package coraza

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
)

// fakeStream 是测试用的请求体流实现（内存缓冲 + 可复位）。
type fakeStream struct {
	data    []byte
	reader  *bytes.Reader
	content string
}

// newFakeStream 构造一个内存请求体流。
func newFakeStream(body string) *fakeStream {
	return &fakeStream{data: []byte(body), reader: bytes.NewReader([]byte(body))}
}

// Read 实现流式读取。
func (s *fakeStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

// Rewind 把读取位置复位到起点。
func (s *fakeStream) Rewind() error { s.reader = bytes.NewReader(s.data); return nil }

// Meta 返回请求体元信息。
func (s *fakeStream) Meta() core.BodyMeta {
	return core.BodyMeta{Present: len(s.data) > 0, Bytes: int64(len(s.data)), Source: "request-body"}
}

// Close 释放资源。
func (s *fakeStream) Close() error { return nil }

// testDeps 构造检测引擎所需的最小依赖集合（使用内置嵌入的 CRS 规则集）。
func testDeps(t *testing.T) *core.Deps {
	t.Helper()
	return &core.Deps{
		SystemLogger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:      core.NoopMetrics{},
		Clock:        core.SystemClock{},
		Limits: core.Limits{
			MaxRuleFileBytes:   4 << 20,
			MaxRulesTotalBytes: 256 << 20,
			MaxScanTokenBytes:  1 << 20,
			MaxHeaderBytes:     1 << 20,
		},
		Engine: core.EngineSettings{
			Enabled:                true,
			Mode:                   ModeOn,
			ParanoiaLevel:          1,
			RuleDirs:               []string{},
			RuleInclude:            []string{"*.conf"},
			RuleDataInclude:        []string{"*.data"},
			CRSSetup:               "crs-setup.conf",
			BodyAccess:             true,
			BodyLimitBytes:         13 << 20,
			BodyInMemoryLimitBytes: 128 << 10,
			BodyLimitAction:        "reject",
			JSONDepthLimit:         4096,
		},
	}
}

// newCheck 构造一个检测引擎实例。
func newCheck(t *testing.T, deps *core.Deps, name string, phase core.Phase, settings map[string]any) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     name,
		Type:     Type,
		Enabled:  true,
		Order:    10,
		Phase:    phase,
		Settings: settings,
	}, deps)
	if err != nil {
		t.Fatalf("构造检测引擎实例失败：%v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	return check
}

// newRequestContext 构造一次请求的上下文。
func newRequestContext(method, uri, contentType, body string) *core.RequestContext {
	rctx := core.NewRequestContext("test-request", time.Now())
	rctx.Raw.Method = method
	rctx.Raw.URI = uri
	rctx.Raw.Path = uri
	rctx.Raw.Proto = "HTTP/1.1"
	rctx.Raw.Host = "app.example.com"
	rctx.Raw.ClientIP = "198.51.100.7"
	rctx.Raw.Header = http.Header{}
	if contentType != "" {
		rctx.Raw.Header.Set("Content-Type", contentType)
	}
	rctx.Body = core.BodyMeta{ContentType: contentType, Source: "request-body"}
	if body != "" {
		rctx.Body.Present = true
		rctx.Body.Bytes = int64(len(body))
		rctx.Stream = newFakeStream(body)
	}
	rctx.Context = context.Background()
	return rctx
}

// TestJSONDepthScanner 验证嵌套深度扫描器（含字符串内括号不计数）。
func TestJSONDepthScanner(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"空对象", "{}", 1},
		{"两层", `{"a":{"b":1}}`, 2},
		{"四层", `{"a":{"b":{"c":{"d":1}}}}`, 4},
		{"数组嵌套", `[[[[1]]]]`, 4},
		{"字符串内的括号不计数", `{"a":"{{[[{{[[","b":1}`, 1},
		{"转义引号", `{"a":"\"}}{","b":1}`, 1},
		{"无结构", `plain`, 0},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := maxJSONDepth([]byte(item.input)); got != item.want {
				t.Fatalf("maxJSONDepth(%q) = %d，期望 %d", item.input, got, item.want)
			}
		})
	}
}

// TestIsJSONContentType 验证 JSON 内容类型识别。
func TestIsJSONContentType(t *testing.T) {
	cases := map[string]bool{
		"application/json":                  true,
		"application/json; charset=utf-8":   true,
		"APPLICATION/JSON":                  true,
		"application/vnd.api+json":          true,
		"application/x-www-form-urlencoded": false,
		"text/plain":                        false,
		"":                                  false,
	}
	for input, want := range cases {
		if got := isJSONContentType(input); got != want {
			t.Errorf("isJSONContentType(%q) = %t，期望 %t", input, got, want)
		}
	}
}

// TestRequestPhaseBlocksSQLi 验证请求头阶段实例能拦截查询串中的 SQL 注入。
func TestRequestPhaseBlocksSQLi(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{
		"process_body": false,
		"score_key":    "inbound_anomaly_score",
	})

	rctx := newRequestContext("GET", "/api/user?id=1' OR '1'='1", "", "")
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截（block），实际：%+v", result)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("期望至少一条命中明细")
	}
	// 评分由 pipeline 统一汇总（见 pipeline.mergeResult）：插件只负责填写 Result.Score，
	// 因此这里断言的是结果里的评分，而不是请求上下文的累计分。
	if result.Score <= 0 {
		t.Fatalf("期望结果携带异常评分，实际 %d", result.Score)
	}
	if rctx.State("inbound_anomaly_score") == nil {
		t.Fatalf("期望评分写入状态键 inbound_anomaly_score")
	}
}

// TestBodyPhaseBlocksSQLi 验证请求体阶段实例能拦截请求体中的 SQL 注入（需求 R4）。
func TestBodyPhaseBlocksSQLi(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
	})

	const payload = `{"username":"admin","password":"1' OR '1'='1"}`
	rctx := newRequestContext("POST", "/api/login", "application/json", payload)

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("期望请求体检测拦截（block），实际：%+v", result)
	}
}

// TestBodyPhaseBlocksXSS 验证请求体中的 XSS 载荷被拦截。
func TestBodyPhaseBlocksXSS(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
	})

	rctx := newRequestContext("POST", "/api/comment",
		"application/x-www-form-urlencoded", `comment=<script>alert(1)</script>`)

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil || !result.Verdict.IsBlocking() {
		t.Fatalf("期望拦截，实际：%+v", result)
	}
}

// TestBodyPhaseAllowsBenign 验证正常请求体不会被误伤。
func TestBodyPhaseAllowsBenign(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
	})

	rctx := newRequestContext("POST", "/api/profile", "application/json", `{"name":"alice","age":30}`)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result != nil && result.Verdict.IsBlocking() {
		t.Fatalf("正常请求被误拦：%+v", result)
	}
}

// TestJSONDepthLimitBlocks 验证 JSON 嵌套深度超限被拦截为 400（需求 R13 / R4）。
func TestJSONDepthLimitBlocks(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.JSONDepthLimit = 3
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
	})

	rctx := newRequestContext("POST", "/api/deep", "application/json", `{"a":{"b":{"c":{"d":1}}}}`)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBadRequest {
		t.Fatalf("期望 VerdictBadRequest，实际：%+v", result)
	}
	if result.Findings[0].RuleID != jsonDepthExceededRuleID {
		t.Fatalf("期望命中规则 %s，实际 %s", jsonDepthExceededRuleID, result.Findings[0].RuleID)
	}
}

// TestJSONDepthLimitAllowsShallow 验证浅层 JSON 不受深度限制影响。
func TestJSONDepthLimitAllowsShallow(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.JSONDepthLimit = 3
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
	})

	rctx := newRequestContext("POST", "/api/ok", "application/json", `{"a":{"b":1}}`)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result != nil && result.Verdict.IsBlocking() {
		t.Fatalf("浅层 JSON 被误拦：%+v", result)
	}
}

// TestDetectionOnlyObserves 验证 detection_only 模式下只记录不拦截。
func TestDetectionOnlyObserves(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.Mode = ModeDetectionOnly
	check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{
		"process_body": false,
	})

	rctx := newRequestContext("GET", "/api/user?id=1' OR '1'='1", "", "")
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil {
		t.Fatalf("期望返回观察结论，实际为 nil")
	}
	if result.Verdict != core.VerdictObserve {
		t.Fatalf("期望 VerdictObserve，实际 %s", result.Verdict)
	}
	if result.Verdict.IsBlocking() {
		t.Fatalf("观察模式不应产生拦截结论")
	}
}

// TestHTTPVersionOf 验证「协议方案 -> HTTP 版本号」的规范化。
//
// 场景背景：forward-auth 通道下代理转发的是 X-Forwarded-Proto（http / https），
// 若把方案直接当作 HTTP 版本喂给引擎，CRS 的 920430 会拦掉所有请求。
func TestHTTPVersionOf(t *testing.T) {
	cases := map[string]string{
		"":             defaultHTTPVersion,
		"https":        defaultHTTPVersion,
		"http":         defaultHTTPVersion,
		"HTTPS":        defaultHTTPVersion,
		"HTTP/1.1":     "HTTP/1.1",
		"http/2.0":     "HTTP/2.0",
		"  HTTP/2.0  ": "HTTP/2.0",
		"HTTP/1.0":     "HTTP/1.0",
	}
	for input, want := range cases {
		if got := httpVersionOf(input); got != want {
			t.Errorf("httpVersionOf(%q) = %q，期望 %q", input, got, want)
		}
	}
}

// TestPassedResultHasNoInitFindings 验证未产生中断时不会把 CRS 初始化规则当成命中。
func TestPassedResultHasNoInitFindings(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{
		"process_body": false,
	})

	// 完全合法的请求：不应产生任何命中明细。
	rctx := newRequestContext("GET", "/api/user?id=42", "", "")
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil {
		return
	}
	for _, finding := range result.Findings {
		id, convErr := strconv.Atoi(finding.RuleID)
		if convErr == nil && id >= 900000 && id <= 901999 {
			t.Fatalf("CRS 初始化规则不应出现在命中明细中：%+v", finding)
		}
	}
}

// TestBodyProcessorsRouting 验证请求体处理器路由指令的生成与开关语义。
func TestBodyProcessorsRouting(t *testing.T) {
	set, err := rules.Load(rules.Options{
		Source: rules.Source{
			Include:     []string{"*.conf"},
			DataInclude: []string{"*.data"},
			CRSSetup:    "crs-setup.conf",
		},
		MaxFileBytes:  4 << 20,
		MaxTotalBytes: 256 << 20,
	})
	if err != nil {
		t.Fatalf("加载内置规则集失败：%v", err)
	}

	// 显式关闭全部映射：不应生成任何路由规则。
	disabled := testDeps(t).Engine
	disabled.Processors = []core.BodyProcessorSetting{}
	if directive := buildDirectives(set, disabled, true, nil, nil); strings.Contains(directive, "ctl:requestBodyProcessor=") {
		t.Fatalf("processors 显式为空时不应生成路由指令：\n%s", directive)
	}

	// 只启用 JSON：应生成 JSON 路由但不生成 XML 路由。
	jsonOnly := testDeps(t).Engine
	jsonOnly.Processors = []core.BodyProcessorSetting{
		{Name: "json", ContentTypes: []string{`^application/json$`}, Enabled: true},
		{Name: "XML", ContentTypes: []string{`^text/xml$`}, Enabled: false},
	}
	directive := buildDirectives(set, jsonOnly, true, nil, nil)
	if !strings.Contains(directive, "ctl:requestBodyProcessor=JSON") {
		t.Errorf("启用 JSON 映射时应生成 JSON 路由指令：\n%s", directive)
	}
	if strings.Contains(directive, "ctl:requestBodyProcessor=XML") {
		t.Errorf("未启用的 XML 映射不应生成路由指令：\n%s", directive)
	}
}

// TestMultipartSkippedWhenDisabled 验证 parse_multipart=false 时 multipart 请求体不被读取。
func TestMultipartSkippedWhenDisabled(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body":    true,
		"parse_multipart": false,
	})

	rctx := newRequestContext("POST", "/api/upload", "multipart/form-data; boundary=xyz", "payload")
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	// 请求体未进入引擎，因此不应因为请求体内容产生任何拦截结论。
	if result != nil && result.Verdict.IsBlocking() {
		t.Fatalf("multipart 解析关闭时不应因请求体产生拦截，实际：%+v", result)
	}
}

// TestFindingsCapped 验证命中明细条数上限生效（防止日志放大）。
func TestFindingsCapped(t *testing.T) {
	deps := testDeps(t)
	check := newCheck(t, deps, "crs-body", core.PhaseBody, map[string]any{
		"process_body": true,
		"max_findings": 2,
	})

	rctx := newRequestContext("POST", "/api/comment", "application/x-www-form-urlencoded",
		`comment=<script>alert(1)</script>+<script>alert(2)</script>`)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil {
		t.Fatalf("期望产生结论")
	}
	if len(result.Findings) > 2 {
		t.Fatalf("命中明细应被限制为 2 条，实际 %d 条", len(result.Findings))
	}
}

// TestPhaseCoherence 验证 process_body 与阶段的强一致性校验（fail fast）。
func TestPhaseCoherence(t *testing.T) {
	deps := testDeps(t)

	if _, err := New(core.InstanceConfig{
		Name: "bad", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"process_body": true},
	}, deps); err == nil {
		t.Fatalf("request 阶段声明 process_body=true 应当报错")
	}

	if _, err := New(core.InstanceConfig{
		Name: "bad", Type: Type, Enabled: true, Phase: core.PhaseBody,
		Settings: map[string]any{"process_body": false},
	}, deps); err == nil {
		t.Fatalf("body 阶段声明 process_body=false 应当报错")
	}
}

// TestEngineDisabledFails 验证 engine.enabled=false 与启用的 coraza 实例冲突时 fail fast。
func TestEngineDisabledFails(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.Enabled = false

	if _, err := New(core.InstanceConfig{
		Name: "crs", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"process_body": false},
	}, deps); err == nil {
		t.Fatalf("engine.enabled=false 时构造 coraza 实例应当报错")
	}
}

// TestInvalidSettingsRejected 验证非法配置在装配阶段被拒绝（fail fast）。
func TestInvalidSettingsRejected(t *testing.T) {
	deps := testDeps(t)

	if _, err := New(core.InstanceConfig{
		Name: "crs", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"process_body": false, "mode": "nonsense"},
	}, deps); err == nil {
		t.Fatalf("非法 mode 应当报错")
	}
	if _, err := New(core.InstanceConfig{
		Name: "crs", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"process_body": false, "paranoia_level": 9},
	}, deps); err == nil {
		t.Fatalf("非法 paranoia_level 应当报错")
	}
	if _, err := New(core.InstanceConfig{
		Name: "crs", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"process_body": false, "unknown_field": 1},
	}, deps); err == nil {
		t.Fatalf("未知配置字段应当报错（严格模式）")
	}
}

// TestBuildDirectives 验证 SecLang 指令的生成顺序与关键字。
//
// 指令顺序是「配置能否生效」的关键（后写覆盖先写），因此单独断言：
// crs-setup 必须最先、引擎设置必须紧随其后、规则文件最后。
func TestBuildDirectives(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.ParanoiaLevel = 2

	set, err := rules.Load(rules.Options{
		Source: rules.Source{
			Include:     deps.Engine.RuleInclude,
			DataInclude: deps.Engine.RuleDataInclude,
			CRSSetup:    deps.Engine.CRSSetup,
		},
		MaxFileBytes:  deps.Limits.MaxRuleFileBytes,
		MaxTotalBytes: deps.Limits.MaxRulesTotalBytes,
	})
	if err != nil {
		t.Fatalf("加载内置规则集失败：%v", err)
	}

	directive := buildDirectives(set, deps.Engine, false, nil, nil)

	expectations := []string{
		"Include crs-setup.conf",
		"SecRuleEngine On",
		"SecRequestBodyAccess Off",
		"SecAuditEngine Off",
		"tx.blocking_paranoia_level=2",
		// 未配置 engine.body.processors 时应回落到内置的 JSON / XML 路由规则。
		"ctl:requestBodyProcessor=JSON",
		"ctl:requestBodyProcessor=XML",
		"id:900200",
		"Include REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	}
	for _, expected := range expectations {
		if !strings.Contains(directive, expected) {
			t.Errorf("指令缺少 %q", expected)
		}
	}

	if strings.Index(directive, "Include crs-setup.conf") > strings.Index(directive, "SecRuleEngine") {
		t.Errorf("crs-setup.conf 必须在引擎设置之前加载")
	}
	// 请求体处理器路由必须排在规则文件之前：它是 phase 1 的 ctl 动作，
	// 必须在请求体解析之前决定处理器，且要先于 CRS 的初始化规则生效。
	if strings.Index(directive, "ctl:requestBodyProcessor=JSON") > strings.Index(directive, "Include REQUEST-") {
		t.Errorf("请求体处理器路由必须在规则文件之前")
	}
	if strings.Index(directive, "SecRuleEngine") > strings.Index(directive, "Include REQUEST-") {
		t.Errorf("引擎设置必须在规则文件之前（否则会被规则集覆盖）")
	}
}
