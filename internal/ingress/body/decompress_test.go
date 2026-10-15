package body

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// decompressConfig 返回一份「已启用解压」的测试配置；具体用例在此基础上覆盖字段。
func decompressConfig(encodings ...string) config.DecompressConfig {
	if len(encodings) == 0 {
		encodings = []string{config.DecompressEncodingGzip, config.DecompressEncodingDeflate}
	}
	return config.DecompressConfig{
		Enabled:           true,
		Encodings:         encodings,
		MaxBytes:          4096,
		UnsupportedAction: config.DecompressActionBlock,
	}
}

// gzipBytes 把明文压缩为 gzip 流。
func gzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(plain); err != nil {
		t.Fatalf("构造 gzip 数据失败：%v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 gzip 写入器失败：%v", err)
	}
	return buffer.Bytes()
}

// zlibBytes 把明文压缩为 zlib（带 zlib 头）流，即 HTTP 规范要求的 deflate 形态。
func zlibBytes(t *testing.T, plain []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	if _, err := writer.Write(plain); err != nil {
		t.Fatalf("构造 zlib 数据失败：%v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 zlib 写入器失败：%v", err)
	}
	return buffer.Bytes()
}

// rawDeflateBytes 把明文压缩为裸 deflate 流（无 zlib 头）。
//
// 需要这条路径是因为历史上大量客户端把裸 deflate 标成 Content-Encoding: deflate，
// 只接受 zlib 会让这些请求被误判为「数据损坏」。
func rawDeflateBytes(t *testing.T, plain []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("构造 deflate 写入器失败：%v", err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatalf("构造 deflate 数据失败：%v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 deflate 写入器失败：%v", err)
	}
	return buffer.Bytes()
}

// newFilledSpool 构造并填充一个请求体缓冲器，内容为原始（可能是压缩后的）字节。
func newFilledSpool(t *testing.T, content []byte, contentType string) *Spool {
	t.Helper()

	spool := newSpool(t, baseConfig(t.TempDir()), nil)
	if err := spool.Fill(Source{
		Reader:      bytes.NewReader(content),
		Declared:    int64(len(content)),
		ContentType: contentType,
	}); err != nil {
		t.Fatalf("填充请求体缓冲失败：%v", err)
	}
	return spool
}

// readStream 读取流的全部内容。
func readStream(t *testing.T, stream core.BodyStream) []byte {
	t.Helper()

	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("读取请求体流失败：%v", err)
	}
	return raw
}

// TestDecodeGzipRestoresPlainBody 覆盖：gzip 请求体被解压为明文，且元信息按明文长度更新。
func TestDecodeGzipRestoresPlainBody(t *testing.T) {
	plain := []byte(`{"username":"alice","comment":"<script>alert(1)</script>"}`)
	spool := newFilledSpool(t, gzipBytes(t, plain), "application/json")

	stream, err := Decode(spool, "gzip", decompressConfig(), Options{})
	if err != nil {
		t.Fatalf("解压 gzip 请求体失败：%v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	if got := readStream(t, stream); !bytes.Equal(got, plain) {
		t.Fatalf("解压结果 = %q，期望 %q", got, plain)
	}
	if meta := stream.Meta(); meta.Bytes != int64(len(plain)) {
		t.Fatalf("解压后 Meta().Bytes = %d，期望 %d", meta.Bytes, len(plain))
	}
	if meta := stream.Meta(); meta.Spooled {
		t.Fatalf("解压结果整体在内存中，Meta().Spooled 应为 false")
	}
	if meta := stream.Meta(); meta.ContentType != "application/json" {
		t.Fatalf("解压后 Content-Type = %q，期望沿用原始声明 application/json", meta.ContentType)
	}
}

// TestDecodeDeflateAcceptsZlibAndRawStream 覆盖：deflate 同时接受 zlib 头与裸流两种形态。
func TestDecodeDeflateAcceptsZlibAndRawStream(t *testing.T) {
	plain := []byte("q=<script>alert(1)</script>")

	cases := []struct {
		name  string
		bytes []byte
	}{
		{name: "zlib", bytes: zlibBytes(t, plain)},
		{name: "raw-flate", bytes: rawDeflateBytes(t, plain)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			spool := newFilledSpool(t, testCase.bytes, "application/x-www-form-urlencoded")

			stream, err := Decode(spool, "deflate", decompressConfig(), Options{})
			if err != nil {
				t.Fatalf("解压 deflate(%s) 请求体失败：%v", testCase.name, err)
			}
			t.Cleanup(func() { _ = stream.Close() })

			if got := readStream(t, stream); !bytes.Equal(got, plain) {
				t.Fatalf("解压结果 = %q，期望 %q", got, plain)
			}
		})
	}
}

// TestDecodeIsRepeatableAfterRewind 覆盖：解压结果可被链中多个单元重复读取。
func TestDecodeIsRepeatableAfterRewind(t *testing.T) {
	plain := []byte("id=1%27%20OR%20%271%27%3D%271")
	spool := newFilledSpool(t, gzipBytes(t, plain), "application/x-www-form-urlencoded")

	stream, err := Decode(spool, "gzip", decompressConfig(), Options{})
	if err != nil {
		t.Fatalf("解压 gzip 请求体失败：%v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	first := readStream(t, stream)
	if err := stream.Rewind(); err != nil {
		t.Fatalf("复位解压流失败：%v", err)
	}
	second := readStream(t, stream)

	if !bytes.Equal(first, plain) || !bytes.Equal(second, plain) {
		t.Fatalf("两次读取结果不一致：first=%q second=%q 期望 %q", first, second, plain)
	}
}

// TestDecodeDisabledOrEmptyEncodingReturnsSource 覆盖：未启用解压、无编码、空体三种直通场景。
func TestDecodeDisabledOrEmptyEncodingReturnsSource(t *testing.T) {
	plain := []byte("raw-body")
	spool := newFilledSpool(t, plain, "text/plain")

	// 未启用解压：即使带着 gzip 头也原样返回（该状态下压缩体不参与检测）。
	disabled := decompressConfig()
	disabled.Enabled = false
	stream, err := Decode(spool, "gzip", disabled, Options{})
	if err != nil {
		t.Fatalf("未启用解压时不应报错：%v", err)
	}
	if stream != core.BodyStream(spool) {
		t.Fatalf("未启用解压时应原样返回底层缓冲")
	}

	// 没有 Content-Encoding：请求体本来就是明文。
	stream, err = Decode(spool, "", decompressConfig(), Options{})
	if err != nil {
		t.Fatalf("无编码时不应报错：%v", err)
	}
	if stream != core.BodyStream(spool) {
		t.Fatalf("无编码时应原样返回底层缓冲")
	}
}

// TestDecodeRejectsUnsupportedEncoding 覆盖：编码不在白名单时按失败关闭返回 400 语义的错误。
func TestDecodeRejectsUnsupportedEncoding(t *testing.T) {
	spool := newFilledSpool(t, []byte("whatever"), "application/json")

	_, err := Decode(spool, "br", decompressConfig(), Options{})
	if err == nil {
		t.Fatalf("br 编码不在白名单时应报错")
	}
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("错误应可被 errors.Is 识别为 ErrUnsupportedEncoding，实际：%v", err)
	}
}

// TestDecodePassActionKeepsOriginalBody 覆盖：unsupported_action=pass 时放过原始压缩体。
func TestDecodePassActionKeepsOriginalBody(t *testing.T) {
	compressed := gzipBytes(t, []byte("secret-payload"))
	spool := newFilledSpool(t, compressed, "application/json")

	cfg := decompressConfig()
	cfg.UnsupportedAction = config.DecompressActionPass

	stream, err := Decode(spool, "br", cfg, Options{})
	if err != nil {
		t.Fatalf("策略为 pass 时不应报错：%v", err)
	}
	if stream != core.BodyStream(spool) {
		t.Fatalf("策略为 pass 时应原样返回底层缓冲")
	}
}

// TestDecodeRejectsMultipleEncodings 覆盖：多重编码直接判为不支持，绝不「悄悄只解一层」。
func TestDecodeRejectsMultipleEncodings(t *testing.T) {
	spool := newFilledSpool(t, gzipBytes(t, []byte("nested")), "application/json")

	_, err := Decode(spool, "gzip, deflate", decompressConfig(), Options{})
	if err == nil {
		t.Fatalf("多重编码应被拒绝（fail closed）")
	}
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("多重编码错误应可被识别为 ErrUnsupportedEncoding，实际：%v", err)
	}
}

// TestDecodeEnforcesMaxBytes 覆盖：解压后超过上限时拒绝（防压缩炸弹），且不做截断。
func TestDecodeEnforcesMaxBytes(t *testing.T) {
	// 8KiB 的连续字符压缩后只有几十字节，正好模拟高压缩比载荷。
	plain := bytes.Repeat([]byte("A"), 8192)
	spool := newFilledSpool(t, gzipBytes(t, plain), "text/plain")

	cfg := decompressConfig()
	cfg.MaxBytes = 1024

	_, err := Decode(spool, "gzip", cfg, Options{})
	if err == nil {
		t.Fatalf("解压后超过 max_bytes 时应拒绝")
	}
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("超限错误应可被识别为 ErrUnsupportedEncoding，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "max_bytes") {
		t.Fatalf("错误信息应指出 max_bytes 上限，实际：%v", err)
	}
}

// TestDecodeAcceptsExactlyMaxBytes 覆盖：解压结果恰好等于上限时放行（边界不得误伤）。
func TestDecodeAcceptsExactlyMaxBytes(t *testing.T) {
	plain := bytes.Repeat([]byte("B"), 1024)
	spool := newFilledSpool(t, gzipBytes(t, plain), "text/plain")

	cfg := decompressConfig()
	cfg.MaxBytes = 1024

	stream, err := Decode(spool, "gzip", cfg, Options{})
	if err != nil {
		t.Fatalf("解压结果恰好等于上限时不应报错：%v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	if got := readStream(t, stream); len(got) != 1024 {
		t.Fatalf("解压长度 = %d，期望 1024", len(got))
	}
}

// TestDecodeCorruptedPayloadReportsError 覆盖：压缩数据损坏时给出解压失败错误。
func TestDecodeCorruptedPayloadReportsError(t *testing.T) {
	spool := newFilledSpool(t, []byte("not-a-gzip-stream-at-all"), "text/plain")

	_, err := Decode(spool, "gzip", decompressConfig(), Options{})
	if err == nil {
		t.Fatalf("损坏的 gzip 数据应报错")
	}
	if !strings.Contains(err.Error(), "解压失败") {
		t.Fatalf("错误信息应说明解压失败，实际：%v", err)
	}
}

// TestDecodeEmptyBodyReturnsSource 覆盖：带 gzip 头但请求体为空时不做无意义解压。
func TestDecodeEmptyBodyReturnsSource(t *testing.T) {
	spool := newFilledSpool(t, nil, "application/json")

	stream, err := Decode(spool, "gzip", decompressConfig(), Options{})
	if err != nil {
		t.Fatalf("空请求体不应报错：%v", err)
	}
	if stream != core.BodyStream(spool) {
		t.Fatalf("空请求体时应原样返回底层缓冲")
	}
}

// TestDecodeRejectsNonPositiveMaxBytes 覆盖：解压上限非正数属于配置错误，必须显式报错。
func TestDecodeRejectsNonPositiveMaxBytes(t *testing.T) {
	spool := newFilledSpool(t, gzipBytes(t, []byte("payload")), "text/plain")

	cfg := decompressConfig()
	cfg.MaxBytes = 0

	_, err := Decode(spool, "gzip", cfg, Options{})
	if err == nil {
		t.Fatalf("max_bytes = 0 时应报错，否则限额会静默失效")
	}
}

// TestDecodeEncodingMatchIsCaseInsensitive 覆盖：Content-Encoding 大小写不敏感。
func TestDecodeEncodingMatchIsCaseInsensitive(t *testing.T) {
	plain := []byte("case-insensitive")
	spool := newFilledSpool(t, gzipBytes(t, plain), "text/plain")

	stream, err := Decode(spool, "GZip", decompressConfig(), Options{})
	if err != nil {
		t.Fatalf("大小写不同的编码不应被拒绝：%v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	if got := readStream(t, stream); !bytes.Equal(got, plain) {
		t.Fatalf("解压结果 = %q，期望 %q", got, plain)
	}
}

// TestNormaliseEncoding 覆盖编码归一化规则（多重编码原样返回以便上层判定为不支持）。
func TestNormaliseEncoding(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "   ", want: ""},
		{input: "GZIP", want: "gzip"},
		{input: " gzip ", want: "gzip"},
		{input: "gzip, deflate", want: "gzip, deflate"},
	}
	for _, testCase := range cases {
		if got := normaliseEncoding(testCase.input); got != testCase.want {
			t.Errorf("normaliseEncoding(%q) = %q，期望 %q", testCase.input, got, testCase.want)
		}
	}
}
