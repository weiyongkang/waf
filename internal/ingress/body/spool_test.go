package body

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// recordingMetrics 是带断言的指标实现：内嵌空实现以复用其余方法。
type recordingMetrics struct {
	core.NoopMetrics
	// truncated 记录「请求体被截断」的次数。
	truncated int
	// skipped 记录「请求体被跳过检测」的次数。
	skipped int
	// missing 记录「要求携带请求体但未收到」的次数。
	missing int
	// bytes 记录累计登记的请求体字节数。
	bytes int64
}

// IncBodyTruncated 累加截断次数。
func (m *recordingMetrics) IncBodyTruncated() { m.truncated++ }

// IncBodySkipped 累加跳过次数。
func (m *recordingMetrics) IncBodySkipped() { m.skipped++ }

// IncBodyMissing 累加缺失次数。
func (m *recordingMetrics) IncBodyMissing() { m.missing++ }

// AddBodyBytes 累加字节数。
func (m *recordingMetrics) AddBodyBytes(_ string, n int64) { m.bytes += n }

// baseConfig 返回一份测试用请求体配置；具体用例在其基础上覆盖个别字段。
func baseConfig(dir string) config.BodyConfig {
	return config.BodyConfig{
		Mode:   config.BodyModeOptional,
		Source: "request-body",
		// 与生产默认一致：只有 POST / PUT / PATCH 缺少请求体才算「缺失」。
		MissingMethods:  []string{"POST", "PUT", "PATCH"},
		Lazy:            true,
		MaxBytes:        1024,
		ChunkBytes:      16,
		OnExceed:        config.BodyOnExceedTruncate,
		Spool:           config.SpoolMemory,
		MemoryThreshold: 0,
		SpoolDir:        dir,
		ReadTimeout:     core.Duration(0),
	}
}

// newSpool 在测试中构造缓冲器，失败直接终止用例。
func newSpool(t *testing.T, cfg config.BodyConfig, metrics core.MetricsRecorder) *Spool {
	t.Helper()

	spool, err := New(cfg, Options{Metrics: metrics})
	if err != nil {
		t.Fatalf("构造请求体缓冲失败：%v", err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

// countDirEntries 返回目录内的条目数，用于断言临时文件已被清理。
func countDirEntries(t *testing.T, dir string) int {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败：%v", err)
	}
	return len(entries)
}

// TestFillMemoryKeepsBodyAndRewinds 覆盖：内存缓冲的完整读取与游标复位。
func TestFillMemoryKeepsBodyAndRewinds(t *testing.T) {
	metrics := &recordingMetrics{}
	spool := newSpool(t, baseConfig(""), metrics)

	payload := "hello-waf-body"
	if err := spool.Fill(Source{Reader: strings.NewReader(payload), Declared: int64(len(payload))}); err != nil {
		t.Fatalf("填充请求体失败：%v", err)
	}

	meta := spool.Meta()
	if !meta.Present || meta.Bytes != int64(len(payload)) || meta.Declared != int64(len(payload)) {
		t.Fatalf("元信息不符合预期：%+v", meta)
	}
	if meta.Spooled || meta.Truncated || meta.Skipped || meta.Missing {
		t.Fatalf("内存缓冲不应出现落盘 / 截断 / 跳过 / 缺失：%+v", meta)
	}
	if metrics.bytes != int64(len(payload)) {
		t.Fatalf("登记的请求体字节数应为 %d，实际 %d", len(payload), metrics.bytes)
	}

	first, err := io.ReadAll(spool)
	if err != nil {
		t.Fatalf("读取请求体失败：%v", err)
	}
	if string(first) != payload {
		t.Fatalf("首次读取内容不一致：%q", first)
	}

	// 复位后应能重复读到完全相同的内容（同一请求可能声明多个体检测单元）。
	if err := spool.Rewind(); err != nil {
		t.Fatalf("复位读取位置失败：%v", err)
	}
	second, err := io.ReadAll(spool)
	if err != nil {
		t.Fatalf("复位后读取请求体失败：%v", err)
	}
	if string(second) != payload {
		t.Fatalf("复位后读取内容不一致：%q", second)
	}
}

// TestFillAutoSpillsToDiskAndCleansUp 覆盖：auto 策略越过内存阈值后落盘，且关闭时清理临时文件。
func TestFillAutoSpillsToDiskAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(dir)
	cfg.Spool = config.SpoolAuto
	cfg.MemoryThreshold = 8

	metrics := &recordingMetrics{}
	spool := newSpool(t, cfg, metrics)

	payload := strings.Repeat("x", 64)
	if err := spool.Fill(Source{Reader: strings.NewReader(payload), Declared: int64(len(payload))}); err != nil {
		t.Fatalf("填充请求体失败：%v", err)
	}

	if !spool.Meta().Spooled {
		t.Fatal("越过内存阈值后应落盘（Meta.Spooled 应为 true）")
	}
	if countDirEntries(t, dir) != 1 {
		t.Fatalf("落盘期间临时文件数量应为 1，实际 %d", countDirEntries(t, dir))
	}

	content, err := io.ReadAll(spool)
	if err != nil {
		t.Fatalf("读取落盘请求体失败：%v", err)
	}
	if string(content) != payload {
		t.Fatal("落盘后的内容与原始请求体不一致")
	}

	if err := spool.Close(); err != nil {
		t.Fatalf("关闭请求体缓冲失败：%v", err)
	}
	if countDirEntries(t, dir) != 0 {
		t.Fatalf("关闭后临时文件应被清理，实际剩余 %d 个", countDirEntries(t, dir))
	}
}

// TestFillReadsInChunks 覆盖：请求体必须分块读取，不能一次性读入（需求 R13 / 验收项 A18）。
func TestFillReadsInChunks(t *testing.T) {
	cfg := baseConfig("")
	cfg.ChunkBytes = 8
	cfg.MaxBytes = 4096

	payload := strings.Repeat("a", 200)
	reader := &chunkTrackingReader{reader: strings.NewReader(payload)}

	spool := newSpool(t, cfg, &recordingMetrics{})
	if err := spool.Fill(Source{Reader: reader, Declared: int64(len(payload))}); err != nil {
		t.Fatalf("填充请求体失败：%v", err)
	}

	if reader.maxRead > int(cfg.ChunkBytes) {
		t.Fatalf("单次读取字节数 %d 超过 chunk_bytes %d", reader.maxRead, cfg.ChunkBytes)
	}
	if reader.reads < 3 {
		t.Fatalf("200 字节 / 8 字节块至少应读取 25 次，实际 %d 次", reader.reads)
	}
}

// TestFillExceedTruncate 覆盖：超限策略 truncate 会截断后继续参与检测（验收项 A13）。
func TestFillExceedTruncate(t *testing.T) {
	cfg := baseConfig("")
	cfg.MaxBytes = 4
	cfg.ChunkBytes = 64

	metrics := &recordingMetrics{}
	spool := newSpool(t, cfg, metrics)

	if err := spool.Fill(Source{Reader: strings.NewReader("0123456789"), Declared: 10}); err != nil {
		t.Fatalf("截断策略不应返回错误：%v", err)
	}

	meta := spool.Meta()
	if !meta.Truncated || meta.Bytes != 4 || meta.Skipped {
		t.Fatalf("截断后的元信息不符合预期：%+v", meta)
	}
	content, err := io.ReadAll(spool)
	if err != nil {
		t.Fatalf("读取截断后的请求体失败：%v", err)
	}
	if string(content) != "0123" {
		t.Fatalf("截断后内容应为 %q，实际 %q", "0123", content)
	}
	if metrics.truncated != 1 {
		t.Fatalf("截断指标应累加 1 次，实际 %d", metrics.truncated)
	}
}

// TestFillExceedReject 覆盖：超限策略 reject 返回哨兵错误且不残留临时文件（验收项 A13）。
func TestFillExceedReject(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(dir)
	cfg.Spool = config.SpoolDisk
	cfg.MaxBytes = 4
	cfg.OnExceed = config.BodyOnExceedReject

	metrics := &recordingMetrics{}
	spool := newSpool(t, cfg, metrics)

	err := spool.Fill(Source{Reader: strings.NewReader("0123456789"), Declared: 10})
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("应返回 ErrBodyTooLarge，实际：%v", err)
	}
	if metrics.truncated != 1 {
		t.Fatalf("超限指标应累加 1 次，实际 %d", metrics.truncated)
	}

	// 拒绝路径必须释放资源：关闭后目录内不应残留任何临时文件。
	if err := spool.Close(); err != nil {
		t.Fatalf("关闭请求体缓冲失败：%v", err)
	}
	if countDirEntries(t, dir) != 0 {
		t.Fatalf("拒绝后不应残留临时文件，实际剩余 %d 个", countDirEntries(t, dir))
	}
}

// TestFillExceedSkip 覆盖：超限策略 skip 放弃体检测，读取时立即到达流末尾（验收项 A13）。
func TestFillExceedSkip(t *testing.T) {
	cfg := baseConfig("")
	cfg.MaxBytes = 4
	cfg.OnExceed = config.BodyOnExceedSkip

	metrics := &recordingMetrics{}
	spool := newSpool(t, cfg, metrics)

	if err := spool.Fill(Source{Reader: strings.NewReader("0123456789"), Declared: 10}); err != nil {
		t.Fatalf("跳过策略不应返回错误：%v", err)
	}

	meta := spool.Meta()
	if !meta.Skipped || meta.Bytes != 0 || meta.Present {
		t.Fatalf("跳过后的元信息不符合预期：%+v", meta)
	}
	content, err := io.ReadAll(spool)
	if err != nil {
		t.Fatalf("跳过检测后读取应为空且无错误：%v", err)
	}
	if len(content) != 0 {
		t.Fatalf("跳过检测后不应读到内容，实际 %d 字节", len(content))
	}
	if metrics.skipped != 1 {
		t.Fatalf("跳过指标应累加 1 次，实际 %d", metrics.skipped)
	}
}

// TestFillMissingRequired 覆盖：预期携带请求体却未收到（验收项 A16）。
//
// 语义要点：只有「语义上必定带体」的方法（默认 POST / PUT / PATCH）缺少请求体
// 才算缺失；GET / HEAD 等无体是正常现象，见 TestFillBodylessMethodsAreNotMissing。
// 客户端明确声明空体（Content-Length: 0）同样属于正常，见 TestFillZeroContentLengthIsNotMissing。
func TestFillMissingRequired(t *testing.T) {
	cfg := baseConfig("")
	cfg.Mode = config.BodyModeRequired

	cases := []struct {
		name   string
		method string
		source Source
	}{
		// 声明了非零长度却一个字节都没读到：典型的「代理没有转发请求体」。
		{name: "POST 声明 128 字节但体流为空", method: "POST", source: Source{Reader: strings.NewReader(""), Declared: 128}},
		// 声明长度未知（chunked 编码，或接入通道不转发 Content-Length）：无法证明是空体，按方法计入缺失。
		{name: "POST 长度未知且无体流", method: "POST", source: Source{Reader: nil, Declared: -1}},
		{name: "小写方法名同样生效", method: "post", source: Source{Reader: nil, Declared: -1}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			metrics := &recordingMetrics{}
			spool := newSpool(t, cfg, metrics)

			source := item.source
			source.Method = item.method
			if err := spool.Fill(source); err != nil {
				t.Fatalf("未携带请求体不应返回错误：%v", err)
			}

			meta := spool.Meta()
			if meta.Present || !meta.Missing || meta.Bytes != 0 {
				t.Fatalf("元信息不符合预期：%+v", meta)
			}
			if metrics.missing != 1 {
				t.Fatalf("缺失指标应累加 1 次，实际 %d", metrics.missing)
			}
		})
	}
}

// TestFillZeroContentLengthIsNotMissing 覆盖：客户端明确声明空请求体不算「缺失」。
//
// 需求背景：Content-Length: 0 表示客户端主动声明「本次请求没有请求体」。
// 没有请求体就没有请求参数，「拿不到请求参数」是正常现象，
// 既不应记入 waf_body_missing_total，也不应产生系统日志告警——更不构成拦截理由。
func TestFillZeroContentLengthIsNotMissing(t *testing.T) {
	cfg := baseConfig("")
	cfg.Mode = config.BodyModeRequired

	cases := []struct {
		name   string
		method string
		source Source
	}{
		{name: "POST 空体流", method: "POST", source: Source{Reader: strings.NewReader(""), Declared: 0}},
		{name: "POST 无体流", method: "POST", source: Source{Reader: nil, Declared: 0}},
		{name: "PUT 无体流", method: "PUT", source: Source{Reader: nil, Declared: 0}},
		{name: "PATCH 空体流", method: "PATCH", source: Source{Reader: strings.NewReader(""), Declared: 0}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			metrics := &recordingMetrics{}
			spool := newSpool(t, cfg, metrics)

			source := item.source
			source.Method = item.method
			if err := spool.Fill(source); err != nil {
				t.Fatalf("未携带请求体不应返回错误：%v", err)
			}

			meta := spool.Meta()
			if meta.Present {
				t.Fatalf("空请求体不应被判定为「存在请求体」：%+v", meta)
			}
			if meta.Missing {
				t.Fatalf("Content-Length: 0 属于客户端明确声明空体，不应记为缺失：%+v", meta)
			}
			if metrics.missing != 0 {
				t.Fatalf("Content-Length: 0 不应累加缺失指标，实际 %d", metrics.missing)
			}
		})
	}
}

// TestFillBodylessMethodsAreNotMissing 覆盖：本身不携带请求体的方法不算「缺失」。
//
// 需求背景：GET / HEAD / OPTIONS / DELETE 没有请求体是正常现象。
// 若把它们也计为缺失，系统日志与 waf_body_missing_total 会被正常流量刷屏，
// 真正的问题（代理没有转发请求体）反而看不见。
func TestFillBodylessMethodsAreNotMissing(t *testing.T) {
	cfg := baseConfig("")
	cfg.Mode = config.BodyModeRequired

	// 含空方法名（接入层未能还原原始方法）：无法判断时保守视为「非预期」，不报缺失。
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "DELETE", "TRACE", ""} {
		t.Run(method, func(t *testing.T) {
			metrics := &recordingMetrics{}
			spool := newSpool(t, cfg, metrics)

			// 声明长度未知（-1）：把方法维度单独隔离出来验证，避免被「声明空体」规则掩盖。
			if err := spool.Fill(Source{Method: method, Reader: nil, Declared: -1}); err != nil {
				t.Fatalf("未携带请求体不应返回错误：%v", err)
			}

			if meta := spool.Meta(); meta.Missing {
				t.Fatalf("方法 %q 无请求体属于正常现象，不应记为缺失：%+v", method, meta)
			}
			if metrics.missing != 0 {
				t.Fatalf("方法 %q 不应累加缺失指标，实际 %d", method, metrics.missing)
			}
		})
	}
}

// TestFillChunkedBodyKeepsUnknownDeclared 覆盖：chunked 编码（声明的长度为 -1）。
func TestFillChunkedBodyKeepsUnknownDeclared(t *testing.T) {
	spool := newSpool(t, baseConfig(""), &recordingMetrics{})

	if err := spool.Fill(Source{Reader: strings.NewReader("chunked-body"), Declared: -1}); err != nil {
		t.Fatalf("填充请求体失败：%v", err)
	}

	meta := spool.Meta()
	if !meta.Present || meta.Declared != -1 || meta.Bytes != int64(len("chunked-body")) {
		t.Fatalf("chunked 请求体的元信息不符合预期：%+v", meta)
	}
}

// TestFillSkipsReadingWhenDisabledByConfig 覆盖：mode / source 关闭时不读取请求体。
func TestFillSkipsReadingWhenDisabledByConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.BodyConfig
	}{
		{name: "mode=disabled", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.Mode = config.BodyModeDisabled
			return cfg
		}()},
		{name: "source=none", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.Source = "none"
			return cfg
		}()},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader := &chunkTrackingReader{reader: strings.NewReader("should-not-be-read")}
			spool := newSpool(t, testCase.cfg, &recordingMetrics{})

			if err := spool.Fill(Source{Reader: reader, Declared: 19}); err != nil {
				t.Fatalf("填充请求体失败：%v", err)
			}
			if reader.reads != 0 {
				t.Fatalf("配置关闭读体时不应读取任何字节，实际读取 %d 次", reader.reads)
			}
			if spool.Meta().Present {
				t.Fatal("未读体时不应标记为存在请求体")
			}
		})
	}
}

// TestNewRejectsInvalidConfig 覆盖：构造阶段的参数校验必须 fail fast。
func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.BodyConfig
	}{
		{name: "非法 spool", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.Spool = "unknown"
			return cfg
		}()},
		{name: "非法 on_exceed", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.OnExceed = "unknown"
			return cfg
		}()},
		{name: "max_bytes 非正数", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.MaxBytes = 0
			return cfg
		}()},
		{name: "chunk_bytes 非正数", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.ChunkBytes = 0
			return cfg
		}()},
		{name: "auto 缺少内存阈值", cfg: func() config.BodyConfig {
			cfg := baseConfig("")
			cfg.Spool = config.SpoolAuto
			cfg.MemoryThreshold = 0
			return cfg
		}()},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.cfg, Options{}); err == nil {
				t.Fatal("非法配置应当返回错误")
			}
		})
	}
}

// TestReadAfterCloseReturnsEOF 覆盖：关闭后读取按流末尾处理，不panic也不返回数据。
func TestReadAfterCloseReturnsEOF(t *testing.T) {
	spool := newSpool(t, baseConfig(""), &recordingMetrics{})
	if err := spool.Fill(Source{Reader: bytes.NewBufferString("data"), Declared: 4}); err != nil {
		t.Fatalf("填充请求体失败：%v", err)
	}
	if err := spool.Close(); err != nil {
		t.Fatalf("关闭请求体缓冲失败：%v", err)
	}
	// 重复关闭必须幂等。
	if err := spool.Close(); err != nil {
		t.Fatalf("重复关闭不应返回错误：%v", err)
	}

	if _, err := io.ReadAll(spool); err != nil {
		t.Fatalf("关闭后读取应为空且无错误：%v", err)
	}
	if err := spool.Rewind(); err == nil {
		t.Fatal("关闭后复位读取位置应当报错")
	}
}

// chunkTrackingReader 记录读取次数与单次最大读取字节数，用于验证分块读取。
type chunkTrackingReader struct {
	// reader 是被包装的原始读取器。
	reader io.Reader
	// reads 是 Read 被调用的次数。
	reads int
	// maxRead 是单次读取到的最大字节数。
	maxRead int
}

// Read 转发读取并记录统计信息。
func (r *chunkTrackingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.reads++
	if n > r.maxRead {
		r.maxRead = n
	}
	return n, err
}
