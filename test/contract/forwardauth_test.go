package contract

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// authRequest 描述一次 forward-auth 鉴权子请求。
//
// 之所以把「子请求方法」与「原始方法」分开：真实接入中子请求方法与原始方法可能不同
// （OpenResty 在带请求体时用 POST、原生 auth_request 用 GET），
// 而原始方法始终由 X-Forwarded-Method 承载。
type authRequest struct {
	// Method 是**原始请求**方法（通过 X-Forwarded-Method 传递给 WAF）。
	Method string
	// URI 是原始请求 URI（通过 X-Forwarded-Uri 传递）。
	URI string
	// Host 是原始请求 Host。
	Host string
	// Proto 是原始请求协议方案（http / https）。
	Proto string
	// ClientIP 是原始客户端 IP（通过 X-Forwarded-For 传递）。
	ClientIP string
	// ContentType 是请求体类型；为空表示不带请求体。
	ContentType string
	// Body 是请求体内容。
	Body string
}

// forwardAuthRequest 是「代理注入头」的显式构造入口，默认值模拟一次普通的 HTTPS GET。
func forwardAuthRequest(uri string) authRequest {
	return authRequest{
		Method:   http.MethodGet,
		URI:      uri,
		Host:     "app.example.com",
		Proto:    "https",
		ClientIP: "203.0.113.10",
	}
}

// do 发起一次鉴权子请求并返回响应。
//
// 子请求一律使用 POST 发起（真实场景中 OpenResty 与 Traefik 也是以 POST 送交请求体），
// 原始方法由 X-Forwarded-Method 承载。响应体由调用方负责关闭。
func (h *harness) do(t *testing.T, req authRequest) *http.Response {
	t.Helper()

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequest(http.MethodPost, h.auth.URL+"/waf/auth", body)
	if err != nil {
		t.Fatalf("构造鉴权请求失败：%v", err)
	}
	httpReq.Header.Set("X-Forwarded-Uri", req.URI)
	httpReq.Header.Set("X-Forwarded-Method", req.Method)
	httpReq.Header.Set("X-Forwarded-Host", req.Host)
	httpReq.Header.Set("X-Forwarded-Proto", req.Proto)
	httpReq.Header.Set("X-Forwarded-For", req.ClientIP)
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	resp, err := h.auth.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("鉴权请求发送失败：%v", err)
	}
	return resp
}

// readBody 读取并关闭响应体。
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败：%v", err)
	}
	return string(raw)
}

// assertStatus 断言状态码。
func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("状态码 = %d，期望 %d（响应头 %v）", resp.StatusCode, want, resp.Header)
	}
}

// assertHeader 断言响应头取值。
func assertHeader(t *testing.T, resp *http.Response, name, want string) {
	t.Helper()
	if got := resp.Header.Get(name); got != want {
		t.Fatalf("响应头 %s = %q，期望 %q", name, got, want)
	}
}

// assertJSONCode 断言 JSON 错误体中的错误码。
func assertJSONCode(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, `"code":"`+want+`"`) {
		t.Fatalf("JSON 错误体未包含错误码 %s：%s", want, body)
	}
}

// flushLogs 关闭日志装配（触发缓冲落盘），供断言日志内容的用例在读取前调用。
//
// 之所以必须显式调用：日志写入器是带缓冲的，进程正常退出时才会 flush；
// 测试里若直接读文件会看到空内容。
func (h *harness) flushLogs(t *testing.T) {
	t.Helper()
	if err := h.loggers.Close(); err != nil {
		t.Fatalf("关闭日志失败：%v", err)
	}
}

// readAccessLog 读取访问日志文件内容（自动匹配按天轮转的文件名）。
func (h *harness) readAccessLog(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(h.logDir, "waf-access-*.log"))
	if err != nil {
		t.Fatalf("匹配访问日志文件失败：%v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("未找到访问日志文件（目录 %s）", h.logDir)
	}
	var builder strings.Builder
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取访问日志失败：%v", err)
		}
		builder.Write(raw)
	}
	return builder.String()
}

// -----------------------------------------------------------------------------
// 契约 1：Traefik forwardAuth 通道
// -----------------------------------------------------------------------------

// TestTraefikChannelAllowsBenignRequest 验证 Traefik 通道下良性请求被放行。
//
// 契约要点：放行时不写响应体（代理侧只关心状态码），但必须回传请求标识与判定结论。
func TestTraefikChannelAllowsBenignRequest(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	req := forwardAuthRequest("/api/user?id=42")
	req.Method = http.MethodPost
	req.URI = "/api/login"
	req.ContentType = "application/json"
	req.Body = `{"username":"alice","password":"Str0ng!Pass"}`

	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	assertHeader(t, resp, core.HeaderVerdict, core.VerdictAllow.String())
	if resp.Header.Get(core.HeaderRequestID) == "" {
		t.Fatalf("放行响应必须回传 %s", core.HeaderRequestID)
	}
	if body != "" {
		t.Fatalf("放行响应不应携带响应体，实际：%q", body)
	}
}

// TestTraefikChannelBlocksQueryStringSQLi 验证 Traefik 通道下查询串注入被拦截。
//
// 契约要点：拦截时返回 JSON 错误体 + 完整的语义响应头（需求 R20 / R22）。
func TestTraefikChannelBlocksQueryStringSQLi(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	req := forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271")
	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusForbidden)
	assertHeader(t, resp, core.HeaderCode, config.CodeBlocked)
	assertHeader(t, resp, core.HeaderVerdict, core.VerdictBlock.String())
	assertJSONCode(t, body, config.CodeBlocked)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("拦截响应必须是 JSON，实际 Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get(core.HeaderRuleID) == "" {
		t.Fatalf("拦截响应必须回传命中的规则标识 %s", core.HeaderRuleID)
	}
}

// -----------------------------------------------------------------------------
// 契约 2：Nginx(OpenResty) 通道 + 请求体检测（需求 R4）
// -----------------------------------------------------------------------------

// TestOpenRestyChannelDetectsFormBodyXSS 验证表单请求体中的 XSS 被拦截。
func TestOpenRestyChannelDetectsFormBodyXSS(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeNginxOpenResty)})

	req := forwardAuthRequest("/api/comment")
	req.Method = http.MethodPost
	req.ContentType = "application/x-www-form-urlencoded"
	req.Body = "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusForbidden)
	assertJSONCode(t, body, config.CodeBlocked)
	if !strings.Contains(body, `"check":"crs-body"`) {
		t.Fatalf("期望由体阶段实例给出结论，实际：%s", body)
	}
}

// TestOpenRestyChannelDetectsJSONBodySQLi 验证 JSON 请求体中的注入被拦截。
//
// 这是 M1.5 的关键契约：引擎只自动识别 URLENCODED / MULTIPART 请求体，
// JSON 必须显式路由到 JSON 处理器；若路由失效，本例会退化为放行。
func TestOpenRestyChannelDetectsJSONBodySQLi(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeNginxOpenResty)})

	req := forwardAuthRequest("/api/login")
	req.Method = http.MethodPost
	req.ContentType = "application/json"
	req.Body = `{"username":"admin","password":"1' OR '1'='1"}`

	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusForbidden)
	assertJSONCode(t, body, config.CodeBlocked)
	if !strings.Contains(body, `"rule_id":"942`) {
		t.Fatalf("期望命中 942xxx（SQL 注入）规则，实际：%s", body)
	}
}

// TestOpenRestyChannelAllowsBenignJSONBody 验证良性 JSON 请求体不被误拦。
//
// 与上一条用例配对：只证明「能拦」不足以保证可用，还必须证明「不乱拦」。
func TestOpenRestyChannelAllowsBenignJSONBody(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeNginxOpenResty)})

	req := forwardAuthRequest("/api/login")
	req.Method = http.MethodPost
	req.ContentType = "application/json"
	req.Body = `{"username":"alice","password":"Str0ng!Pass","remember":true}`

	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusOK)
	if body != "" {
		t.Fatalf("放行响应不应携带响应体，实际：%q", body)
	}
}

// TestDeeplyNestedJSONBodyRejected 验证深层嵌套 JSON 被请求体守卫拦截（400）。
func TestDeeplyNestedJSONBodyRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeNginxOpenResty) +
		"engine:\n  body:\n    json_depth_limit: 3\n"})

	req := forwardAuthRequest("/api/login")
	req.Method = http.MethodPost
	req.ContentType = "application/json"
	req.Body = `{"a":{"b":{"c":{"d":1}}}}`

	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusBadRequest)
	assertJSONCode(t, body, config.CodeBadRequest)
	if !strings.Contains(body, "json_depth_exceeded") {
		t.Fatalf("期望命中 JSON 深度守卫，实际：%s", body)
	}
}

// -----------------------------------------------------------------------------
// 契约 3：nginx-auth-only 降级通道的状态码收敛
// -----------------------------------------------------------------------------

// TestAuthOnlyChannelCollapsesStatusToForbidden 验证降级通道把真实状态码收敛为 403。
//
// 背景（需求 R22）：Nginx 原生 auth_request 只透传 401 / 403，其它状态码一律改写为 500。
// 因此该通道下 WAF 必须统一返回 403，真实语义由 X-WAF-Code 承载。
func TestAuthOnlyChannelCollapsesStatusToForbidden(t *testing.T) {
	override := ingressOverride(config.IngressTypeNginxAuthOnly) + `
pipeline:
  - name: rl-ip
    type: ratelimit
    enabled: true
    order: 10
    phase: pre
    settings:
      dimensions: [ip]
      window: 60s
      limit: 1
      burst: 0
      action: ratelimit
      store: default
      store_timeout: 200ms
`
	h := newHarness(t, harnessOptions{override: override})

	// 第一次放行。
	first := h.do(t, forwardAuthRequest("/api/items"))
	_ = readBody(t, first)
	assertStatus(t, first, http.StatusOK)

	// 第二次触发限速：真实语义是 429，但该通道必须对外回 403。
	second := h.do(t, forwardAuthRequest("/api/items"))
	body := readBody(t, second)

	assertStatus(t, second, http.StatusForbidden)
	assertHeader(t, second, core.HeaderCode, config.CodeRateLimited)
	assertHeader(t, second, core.HeaderVerdict, core.VerdictRateLimited.String())
	assertJSONCode(t, body, config.CodeRateLimited)
}

// -----------------------------------------------------------------------------
// 契约 4：JSON 错误体渲染端点（Traefik errors 中间件回源）
// -----------------------------------------------------------------------------

// TestDenyEndpointRendersByStatusCode 验证渲染端点既接受错误码字面量，也接受数字状态码。
//
// 之所以必须支持数字状态码：Traefik errors 中间件的 query 模板只能拿到 {status}，
// 无法读取鉴权响应头（需求 R22 的落地偏差记录）。
func TestDenyEndpointRendersByStatusCode(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	cases := []struct {
		name       string
		code       string
		wantStatus int
		wantCode   string
	}{
		{"数字状态码 429", "429", http.StatusTooManyRequests, config.CodeRateLimited},
		{"数字状态码 400", "400", http.StatusBadRequest, config.CodeBadRequest},
		{"数字状态码 403", "403", http.StatusForbidden, config.CodeBlocked},
		{"错误码字面量", config.CodeBlocked, http.StatusForbidden, config.CodeBlocked},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			resp, err := h.auth.Client().Get(h.auth.URL + "/waf/deny?code=" + item.code)
			if err != nil {
				t.Fatalf("请求渲染端点失败：%v", err)
			}
			body := readBody(t, resp)

			assertStatus(t, resp, item.wantStatus)
			assertJSONCode(t, body, item.wantCode)
			assertHeader(t, resp, core.HeaderCode, item.wantCode)
		})
	}
}

// -----------------------------------------------------------------------------
// 契约 5：多实例共享限速计数与封禁名单（需求 R17 / R23）
// -----------------------------------------------------------------------------

// sharedPipelineOverride 是「共享限速 + 封禁名单」用例的校验链覆盖片段。
const sharedPipelineOverride = `
pipeline:
  - name: ban-list
    type: banlist
    enabled: true
    order: 5
    phase: pre
    on_error: pass
  - name: rl-ip
    type: ratelimit
    enabled: true
    order: 10
    phase: pre
    settings:
      dimensions: [ip]
      window: 60s
      limit: 2
      burst: 0
      action: ratelimit
      ban: true
      ban_ttl: 5m
      store: default
      store_timeout: 200ms
`

// TestSharedStoreSharesCountersAcrossInstances 验证两个实例共用同一共享存储时计数是全局累计的。
func TestSharedStoreSharesCountersAcrossInstances(t *testing.T) {
	logDir := t.TempDir()
	first := newHarness(t, harnessOptions{
		override: ingressOverride(config.IngressTypeTraefik) + sharedPipelineOverride,
		logDir:   logDir,
	})
	second := newHarness(t, harnessOptions{
		override:     ingressOverride(config.IngressTypeTraefik) + sharedPipelineOverride,
		sharedStores: first.stores,
		sharedBans:   first.bans,
		logDir:       logDir,
	})

	req := forwardAuthRequest("/api/items")

	// 实例 A 放行第 1 次。
	resp := first.do(t, req)
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusOK)

	// 实例 B 放行第 2 次：若计数不共享，B 会从 0 重新计数。
	resp = second.do(t, req)
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusOK)

	// 第 3 次无论落在哪个实例上都必须被拦：这是「多实例共享」的判定标准。
	resp = second.do(t, req)
	body := readBody(t, resp)
	assertStatus(t, resp, http.StatusTooManyRequests)
	assertJSONCode(t, body, config.CodeRateLimited)
}

// TestIndependentStoresDoNotShareCounters 是上一条用例的对照：不共享存储时不累计。
//
// 之所以要写这个「反例」：它显式固定了 stores[].enabled=false（或未部署 Redis）时的行为，
// 让「为什么生产必须部署 Redis」成为一条可执行的契约而不是文档里的口头约定。
func TestIndependentStoresDoNotShareCounters(t *testing.T) {
	override := ingressOverride(config.IngressTypeTraefik) + sharedPipelineOverride
	first := newHarness(t, harnessOptions{override: override})
	second := newHarness(t, harnessOptions{override: override})

	req := forwardAuthRequest("/api/items")

	for i := 0; i < 2; i++ {
		resp := first.do(t, req)
		_ = readBody(t, resp)
		assertStatus(t, resp, http.StatusOK)
	}
	// 第二个实例自己的计数仍是 0，因此前两次仍然放行。
	for i := 0; i < 2; i++ {
		resp := second.do(t, req)
		_ = readBody(t, resp)
		assertStatus(t, resp, http.StatusOK)
	}
	// 各自到达自己的第 3 次才被拦。
	resp := first.do(t, req)
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusTooManyRequests)
}

// TestSharedStoreSharesBansAcrossInstances 验证内部封禁是全局可见的。
func TestSharedStoreSharesBansAcrossInstances(t *testing.T) {
	override := ingressOverride(config.IngressTypeTraefik) + `
pipeline:
  - name: ban-list
    type: banlist
    enabled: true
    order: 5
    phase: pre
    on_error: pass
`
	logDir := t.TempDir()
	first := newHarness(t, harnessOptions{override: override, logDir: logDir})
	second := newHarness(t, harnessOptions{
		override:     override,
		sharedStores: first.stores,
		sharedBans:   first.bans,
		logDir:       logDir,
	})

	// 通过封禁管理器写入封禁（与 `waf ban add` 走同一条路径）。
	if _, _, err := first.bans.Add(
		context.Background(), "203.0.113.10", "", 5*time.Minute, "契约测试：共享封禁",
	); err != nil {
		t.Fatalf("写入封禁失败：%v", err)
	}

	// 第二个实例必须立即看到该封禁。
	resp := second.do(t, forwardAuthRequest("/api/orders"))
	body := readBody(t, resp)
	assertStatus(t, resp, http.StatusForbidden)
	assertJSONCode(t, body, config.CodeBlocked)
}

// -----------------------------------------------------------------------------
// 契约 6：可观测性（指标 / 探针）与日志
// -----------------------------------------------------------------------------

// TestMetricsAndProbes 验证指标暴露与探针端点。
func TestMetricsAndProbes(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	resp := h.do(t, forwardAuthRequest("/api/items"))
	_ = readBody(t, resp)

	for _, path := range []string{"/healthz", "/readyz", "/version", "/metrics"} {
		probe, err := h.metrics.Client().Get(h.metrics.URL + path)
		if err != nil {
			t.Fatalf("请求 %s 失败：%v", path, err)
		}
		body := readBody(t, probe)
		if probe.StatusCode != http.StatusOK {
			t.Fatalf("%s 状态码 = %d，期望 200", path, probe.StatusCode)
		}
		if path == "/metrics" && !strings.Contains(body, "waf_requests_total") {
			t.Fatalf("指标内容缺少 waf_requests_total：%s", body)
		}
	}
}

// TestAccessLogIsStructuredJSON 验证访问日志是分级 JSON（需求 R21）。
func TestAccessLogIsStructuredJSON(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	resp := h.do(t, forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271"))
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusForbidden)

	h.flushLogs(t)
	content := h.readAccessLog(t)

	if !strings.Contains(content, `"level"`) {
		t.Fatalf("访问日志缺少 level 字段：%s", content)
	}
	if !strings.Contains(content, `"verdict"`) {
		t.Fatalf("访问日志缺少 verdict 字段：%s", content)
	}
	if !strings.Contains(content, `"request_id"`) {
		t.Fatalf("访问日志缺少 request_id 字段：%s", content)
	}
}

// TestAccessLogRecordsAllowedAuthRequests 验证「鉴权请求过与不过都要留痕」（需求 R21）。
//
// 契约要点：默认 logging.access.allow_level=info 时，放行请求必须以 info 级写入访问日志，
// 并携带 action=allow 字段；否则访问日志会出现「无任何记录」的请求，排障与统计都无从下手。
func TestAccessLogRecordsAllowedAuthRequests(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	resp := h.do(t, forwardAuthRequest("/api/user?id=42"))
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusOK)

	h.flushLogs(t)
	content := h.readAccessLog(t)

	if !strings.Contains(content, `"action":"allow"`) {
		t.Fatalf("访问日志未记录放行动作 action=allow：%s", content)
	}
	if !strings.Contains(content, "请求通过") {
		t.Fatalf("访问日志未记录放行消息：%s", content)
	}
}

// TestAccessLogAllowLevelOffSuppressesAllow 验证 allow_level=off 时放行不留痕且不影响拦截。
//
// 契约要点：off 只关闭「放行」记录，拦截 / 观察 / 异常记录必须保持原样，
// 因此关闭后仍能从访问日志看到 action=block。
func TestAccessLogAllowLevelOffSuppressesAllow(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik) + `
logging:
  access:
    allow_level: off
`})

	allowed := h.do(t, forwardAuthRequest("/api/user?id=42"))
	_ = readBody(t, allowed)
	assertStatus(t, allowed, http.StatusOK)

	blocked := h.do(t, forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271"))
	_ = readBody(t, blocked)
	assertStatus(t, blocked, http.StatusForbidden)

	h.flushLogs(t)
	content := h.readAccessLog(t)

	if strings.Contains(content, `"action":"allow"`) {
		t.Fatalf("allow_level=off 时不应记录放行动作：%s", content)
	}
	if !strings.Contains(content, `"action":"block"`) {
		t.Fatalf("allow_level=off 不应影响拦截记录：%s", content)
	}
}

// TestAccessLogAllowLevelDebugLowersChannelLevel 验证 allow_level=debug 会下探通道级别。
//
// 契约要点：通道级别仍是 info 时，debug 级记录会被 slog 直接丢弃；
// 因此 allow_level=debug 必须把访问日志通道级别下探到 debug，否则「放行留痕」会静默失效。
func TestAccessLogAllowLevelDebugLowersChannelLevel(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik) + `
logging:
  access:
    level: info
    allow_level: debug
`})

	resp := h.do(t, forwardAuthRequest("/api/user?id=42"))
	_ = readBody(t, resp)
	assertStatus(t, resp, http.StatusOK)

	h.flushLogs(t)
	content := h.readAccessLog(t)

	if !strings.Contains(content, `"action":"allow"`) {
		t.Fatalf("allow_level=debug 时放行记录必须可见：%s", content)
	}
	if !strings.Contains(content, `"level":"DEBUG"`) {
		t.Fatalf("放行记录应以 debug 级写入：%s", content)
	}
}

// TestRequestWithoutParametersIsNotBlocked 验证「请求未携带参数」不会被误判为攻击。
//
// 契约要点（安全语义）：
//   - 参数类检测（查询串参数 / 表单参数 / JSON 参数）都是「逐变量匹配」：
//     变量不存在时对应的 SecRule 不命中，不存在「参数缺失 -> 记为异常」的路径；
//   - CRS 中唯一按参数「个数」判定的规则是 920380（参数**过多**），
//     没有任何规则以「参数个数为 0」作为拦截条件；
//   - 因此无查询串、无请求体、空 JSON 对象的请求都必须放行。
//
// 固化成用例的原因：一旦后续引入「缺失即异常」的判定，这里会立刻变红。
func TestRequestWithoutParametersIsNotBlocked(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		uri         string
		contentType string
		body        string
	}{
		{name: "GET 无查询串", method: http.MethodGet, uri: "/api/user"},
		{name: "GET 空查询串", method: http.MethodGet, uri: "/api/user?"},
		{name: "POST 无请求体（带 Content-Type）", method: http.MethodPost, uri: "/api/user", contentType: "application/json"},
		{name: "POST 空 JSON 对象", method: http.MethodPost, uri: "/api/user", contentType: "application/json", body: "{}"},
		{name: "POST 无请求体且无 Content-Type", method: http.MethodPost, uri: "/api/user"},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

			req := forwardAuthRequest(item.uri)
			req.Method = item.method
			req.ContentType = item.contentType
			req.Body = item.body

			resp := h.do(t, req)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("无参数请求不应被拦截：状态码 = %d，响应体 = %s", resp.StatusCode, body)
			}

			h.flushLogs(t)
			content := h.readAccessLog(t)
			if !strings.Contains(content, `"action":"allow"`) {
				t.Fatalf("无参数请求应记录为放行：%s", content)
			}
		})
	}
}

// TestUnknownPathReturnsJSONNotFound 验证未知路径返回 JSON 而不是 HTML 错误页。
func TestUnknownPathReturnsJSONNotFound(t *testing.T) {
	h := newHarness(t, harnessOptions{override: ingressOverride(config.IngressTypeTraefik)})

	resp, err := h.auth.Client().Get(h.auth.URL + "/waf/unknown")
	if err != nil {
		t.Fatalf("请求未知路径失败：%v", err)
	}
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusNotFound)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("未知路径必须返回 JSON，实际 Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, `"code"`) {
		t.Fatalf("未知路径响应体缺少 code 字段：%s", body)
	}
}

// metricValue 读取指标端点中指定指标的值；指标不存在时返回 0。
func (h *harness) metricValue(t *testing.T, name string) float64 {
	t.Helper()

	resp, err := h.metrics.Client().Get(h.metrics.URL + "/metrics")
	if err != nil {
		t.Fatalf("请求指标端点失败：%v", err)
	}
	body := readBody(t, resp)

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// 指标名可能带标签（name{...}），因此按「名称 + 可选标签」精确匹配。
		if fields[0] != name && !strings.HasPrefix(fields[0], name+"{") {
			continue
		}
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			t.Fatalf("解析指标行 %q 失败：%v", line, err)
		}
		return value
	}
	return 0
}

// TestBodyMissingMetricOnlyCountsBodyBearingMethods 验证「无参数请求不算异常」。
//
// 契约要点：ingress.body.mode = required 时，「请求体缺失」必须同时满足三个条件，
// 缺一不可：
//  1. 原始方法属于 ingress.body.missing_methods（默认 POST / PUT / PATCH）——
//     GET / HEAD / OPTIONS 本来就不携带请求体，不得计入 waf_body_missing_total；
//  2. 客户端**没有**明确声明空请求体（Content-Length != 0）——
//     Content-Length: 0 表示客户端主动声明「本次请求没有请求体」，没有体就没有参数，
//     「拿不到请求参数」是正常现象，同样不得计入缺失；
//  3. 接入通道确实能送来原始 Content-Length——原生 Nginx 的 auth_request 通道
//     既不转发请求体也不转发 Content-Length，此时「0」只代表未知，
//     无法证明客户端声明了空体，因此仍然计入缺失。
//
// 无论是否缺失，都不影响放行判定（缺失只是可观测信号，不是拦截依据）。
//
// 之所以要固化：把「无体」一律当成异常会让日志与指标被正常流量刷屏，
// 真正的问题（代理没有转发请求体）反而被噪声掩盖。
func TestBodyMissingMetricOnlyCountsBodyBearingMethods(t *testing.T) {
	// 覆盖片段把 ingress 写成单个映射：同一文件里重复声明 ingress 会被严格解析器判为格式错误；
	// 接入类型用常量渲染，避免手写字符串与 config.IngressType* 的取值漂移。
	bodyRequiredOverride := func(ingressType string) string {
		return fmt.Sprintf(`ingress:
  type: %q
  body:
    mode: required
    missing_methods: [POST, PUT, PATCH]
`, ingressType)
	}

	cases := []struct {
		name        string
		ingressType string
		method      string
		wantMissing float64
	}{
		{
			name:        "GET 无请求体不计缺失",
			ingressType: config.IngressTypeTraefik,
			method:      http.MethodGet,
			wantMissing: 0,
		},
		{
			name:        "POST 且 Content-Length: 0 不计缺失",
			ingressType: config.IngressTypeTraefik,
			method:      http.MethodPost,
			wantMissing: 0,
		},
		{
			name:        "POST 且声明长度未知（原生 Nginx 通道）计入缺失",
			ingressType: config.IngressTypeNginxAuthOnly,
			method:      http.MethodPost,
			wantMissing: 1,
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{override: bodyRequiredOverride(item.ingressType)})

			req := forwardAuthRequest("/api/user")
			req.Method = item.method
			req.ContentType = "application/json"

			resp := h.do(t, req)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("缺少请求体不应导致拦截：状态码 = %d，响应体 = %s", resp.StatusCode, body)
			}
			if got := h.metricValue(t, "waf_body_missing_total"); got != item.wantMissing {
				t.Fatalf("waf_body_missing_total = %v，期望 %v", got, item.wantMissing)
			}
		})
	}
}

// doRaw 以「裸 TCP」方式把一条完整 HTTP 报文写到鉴权端点并读回响应。
//
// 存在的意义：http.Client 无法构造「POST 且既没有 Content-Length 也没有
// Transfer-Encoding」的请求（它对 POST/PUT/PATCH 一定会补上 Content-Length: 0），
// 而真实代理在没有转发请求体时恰好会构造出这个形态。
func (h *harness) doRaw(t *testing.T, raw string) *http.Response {
	t.Helper()

	conn, err := net.Dial("tcp", h.auth.Listener.Addr().String())
	if err != nil {
		t.Fatalf("连接鉴权端点失败：%v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("写入鉴权报文失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读取鉴权响应失败：%v", err)
	}
	return resp
}

// rawAuthRequest 拼装一条裸 TCP 鉴权报文（CRLF 行尾）。
func rawAuthRequest(framing []string, body string) string {
	lines := []string{
		"POST /waf/auth HTTP/1.1",
		"Host: waf.internal",
		"X-Forwarded-Uri: /api/constant/selectAll.do",
		"X-Forwarded-Method: POST",
		"X-Forwarded-Host: app.example.com",
		"X-Forwarded-Proto: http",
		"X-Forwarded-For: 203.0.113.10",
	}
	lines = append(lines, framing...)
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

// TestPostWithoutFramingHeadersIsNotBlocked 验证「代理没有转发请求体」的 POST 不被误拦。
//
// 缺陷背景（实测复现）：鉴权子请求的框架头由代理合成，代理没转发请求体时
// （原生 Nginx `auth_request` 的 `proxy_set_header Content-Length ""`、
// Traefik 未开 `forwardBody`、未做体捕获的 OpenResty 配置）两个框架头都不存在，
// 而 net/http 还会把 Transfer-Encoding 从 Header 中剥离。
// 若不还原框架头，CRS 的 920180（POST without Content-Length or Transfer-Encoding）
// 就会把「拿不到请求体」判成协议违规：WARNING = 5 分 = 默认阈值 → 整条 POST 接口被 403。
func TestPostWithoutFramingHeadersIsNotBlocked(t *testing.T) {
	cases := []struct {
		name    string
		framing []string
		body    string
	}{
		{name: "无任何框架头的 POST"},
		{
			name:    "分块传输的 POST",
			framing: []string{"Transfer-Encoding: chunked"},
			body:    "5\r\nhello\r\n0\r\n\r\n",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})

			resp := h.doRaw(t, rawAuthRequest(item.framing, item.body))
			assertStatus(t, resp, http.StatusOK)
			assertHeader(t, resp, "X-WAF-Verdict", "allow")
			_ = readBody(t, resp)
		})
	}
}
