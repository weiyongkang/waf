package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// ErrUnsupportedEncoding 表示请求体使用了未启用/不支持的 Content-Encoding，
// 且配置的 unsupported_action = block。
//
// 为什么用哨兵错误：调用方（pipeline）只需要区分「不能检测所以拒绝」与其它读取失败，
// 前者对外返回 400 并给出明确原因，后者按通用读取错误处理。
var ErrUnsupportedEncoding = errors.New("请求体使用了不支持的压缩编码")

// Decode 依据 Content-Encoding 把「已缓冲的原始请求体」解压为明文请求体。
//
// 为什么必须在检测之前完成：
//
//	代理会把 Content-Encoding: gzip 的请求体原样转交给 WAF。若不进行解压，
//	请求体内容对检测引擎完全不可见——攻击者只需加一个压缩头就能绕过体检测。
//	因此解压是「请求体检测能力」的必要组成部分，而不是可选优化。
//
// 返回值语义：
//   - (source, nil)                    未启用解压 / 无编码 / 内容为空 / 策略为 pass：直接用原始缓冲；
//   - (decoded, nil)                   解压成功：返回解压后的可重复读取流；
//   - (nil, ErrUnsupportedEncoding)    编码不受支持且策略为 block：调用方应返回 400。
//
// 安全约束（需求 R13）：
//   - 解压读取受 cfg.MaxBytes 限制（多读 1 字节以区分「恰好超限」与「超过上限」）；
//   - 解压结果放入内存前先完成限额检查，绝不把未受限的解压数据放进内存；
//   - 解压过程本身也用受限读取，避免 zip bomb 在解压阶段就吃掉内存。
func Decode(source *Spool, encoding string, cfg config.DecompressConfig, opts Options) (core.BodyStream, error) {
	if source == nil {
		return nil, nil
	}
	// 未启用解压：完全不做任何处理（零开销），此时压缩体不会被检测，
	// 该状态在启动日志与文档中都会明确提示。
	if !cfg.Enabled {
		return source, nil
	}

	normalised := normaliseEncoding(encoding)
	if normalised == "" {
		// 没有 Content-Encoding：请求体本来就是明文，无需处理。
		return source, nil
	}

	if !containsEncoding(cfg.Encodings, normalised) {
		if cfg.UnsupportedAction == config.DecompressActionPass {
			// 显式选择「放过」：必须留 WARN，否则「被绕过的请求体」在日志里毫无痕迹。
			logf(opts, slog.LevelWarn, "请求体编码不受支持，按配置放过（该请求体不参与内容检测）",
				"encoding", normalised)
			return source, nil
		}
		return nil, fmt.Errorf("%w：Content-Encoding=%s（可用编码：%s；如需放过请将 "+
			"ingress.body.decompress.unsupported_action 设为 pass）",
			ErrUnsupportedEncoding, normalised, strings.Join(cfg.Encodings, ","))
	}

	// 读入原始内容（受限额保护：请求体缓冲阶段已经截断到 max_bytes，这里不会二次膨胀）。
	raw, err := readAll(source, source.Meta().Bytes)
	if err != nil {
		return nil, fmt.Errorf("读取待解压请求体失败：%w", err)
	}
	if len(raw) == 0 {
		return source, nil
	}

	plain, err := decompress(raw, normalised, cfg.MaxBytes)
	if err != nil {
		return nil, err
	}

	logf(opts, slog.LevelDebug, "请求体已解压，解压结果将参与内容检测",
		"encoding", normalised, "compressed_bytes", len(raw), "plain_bytes", len(plain))

	return newDecoded(source, plain), nil
}

// decompress 按编码解压内容，并强制应用解压后上限。
func decompress(raw []byte, encoding string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("解压后上限 max_bytes 必须大于 0（当前 %d）", maxBytes)
	}

	reader, closer, err := newDecompressor(raw, encoding)
	if err != nil {
		return nil, err
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	// 多读 1 字节：只有这样才能区分「恰好等于上限」与「超过上限」。
	plain, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		// 解压中途失败（数据损坏）属于客户端请求本身不合法，按 400 处理。
		return nil, fmt.Errorf("请求体解压失败（数据可能已损坏或不是 %s 格式）：%w", encoding, err)
	}
	if int64(len(plain)) > maxBytes {
		// 超限一律拒绝，而不是截断：截断后的明文请求体是「不完整内容」，
		// 用它做检测会产生「检测过了但没检出」的假安全感（与 ingress.body.on_exceed
		// 的 truncate 语义不同——那里的截断是「代理侧的硬边界」，这里是我们主动设的防线）。
		return nil, fmt.Errorf(
			"%w：解压后大小超过 ingress.body.decompress.max_bytes=%d 字节（疑似压缩炸弹）",
			ErrUnsupportedEncoding, maxBytes,
		)
	}
	return plain, nil
}

// newDecompressor 依据编码构造解压读取器。
func newDecompressor(raw []byte, encoding string) (io.Reader, io.Closer, error) {
	switch encoding {
	case config.DecompressEncodingGzip:
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, nil, fmt.Errorf("请求体解压失败（gzip 头非法）：%w", err)
		}
		return reader, reader, nil
	case config.DecompressEncodingDeflate:
		// 先按 zlib 尝试（HTTP 规范里 deflate 应带 zlib 头），失败再按裸 deflate 兜底。
		//
		// 之所以需要兜底：历史上存在大量「Content-Encoding: deflate 但实际发裸 deflate 流」
		// 的实现（部分老客户端与中间件），只支持 zlib 会让这些请求被误判为「数据损坏」。
		zlibReader, err := zlib.NewReader(bytes.NewReader(raw))
		if err == nil {
			return zlibReader, zlibReader, nil
		}
		return flate.NewReader(bytes.NewReader(raw)), nil, nil
	default:
		return nil, nil, fmt.Errorf("%w：%s", ErrUnsupportedEncoding, encoding)
	}
}

// normaliseEncoding 归一化 Content-Encoding 取值。
//
// 只取第一个编码：多重编码（例如 "gzip, br"）需要按顺序逐层解压，
// 各层都受同一份限额约束，属于「多层解压」的完整能力；
// 当前实现只处理单层编码，遇到多重编码会在 containsEncoding 判定时被拒绝（fail closed），
// 而不是悄悄只解压一层——后者会让攻击者用「多层压缩」绕过检测。
func normaliseEncoding(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, ",") {
		return trimmed // 含逗号表示多重编码，原样返回以便上层判定为「不支持」
	}
	return strings.ToLower(trimmed)
}

// containsEncoding 判断编码是否在启用列表中（大小写不敏感）。
func containsEncoding(encodings []string, target string) bool {
	for _, encoding := range encodings {
		if strings.EqualFold(strings.TrimSpace(encoding), target) {
			return true
		}
	}
	return false
}

// readAll 从可重复读取的流中读入全部内容并复位游标。
//
// 之所以读取后复位：解压完成后，原始缓冲仍可能在日志/取证场景被再次读取，
// 保持「读完后游标回到起点」的不变量可以避免下游读到半截内容。
func readAll(stream core.BodyStream, size int64) ([]byte, error) {
	buffer := make([]byte, 0, size)
	chunk := make([]byte, 32*1024)
	for {
		read, err := stream.Read(chunk)
		if read > 0 {
			buffer = append(buffer, chunk[:read]...)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if err := stream.Rewind(); err != nil {
		return nil, err
	}
	return buffer, nil
}

// decoded 是解压后的请求体流，实现 core.BodyStream。
//
// 之所以把解压结果整体放在内存：解压后的内容需要被多个体阶段单元重复读取，
// 落盘会引入额外的临时文件管理成本；而它的规模已经被 max_bytes 硬限制
// （默认 4MiB），属于可接受的内存占用。
type decoded struct {
	// source 是底层的原始请求体缓冲，Close 时与其一并释放。
	source core.BodyStream
	// data 是解压后的明文内容。
	data []byte
	// reader 是当前读取游标。
	reader *bytes.Reader
	// meta 是解压后的请求体元信息。
	meta core.BodyMeta
}

// newDecoded 构造解压后的请求体流。
func newDecoded(source core.BodyStream, data []byte) *decoded {
	meta := source.Meta()
	meta.Bytes = int64(len(data))
	meta.Spooled = false
	meta.Digest = ""
	// 解压后内容类型仍是原始声明（Content-Type 描述的是明文格式，不受压缩影响）。
	return &decoded{
		source: source,
		data:   data,
		reader: bytes.NewReader(data),
		meta:   meta,
	}
}

// Read 实现 io.Reader。
func (d *decoded) Read(p []byte) (int, error) { return d.reader.Read(p) }

// Rewind 把读取游标复位到起点。
func (d *decoded) Rewind() error {
	_, err := d.reader.Seek(0, io.SeekStart)
	return err
}

// Meta 返回解压后的请求体元信息。
func (d *decoded) Meta() core.BodyMeta { return d.meta }

// Close 释放解压流与底层缓冲（底层缓冲负责删除落盘的临时文件）。
func (d *decoded) Close() error { return d.source.Close() }

// logf 写系统日志；未注入日志器时静默。
func logf(opts Options, level slog.Level, message string, args ...any) {
	if opts.Logger == nil {
		return
	}
	opts.Logger.Log(context.Background(), level, message, args...)
}
