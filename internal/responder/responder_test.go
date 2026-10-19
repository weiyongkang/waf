package responder

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// TestStatusForCode 验证错误码与 HTTP 状态码的映射关系（设计文档 §1.5 契约表）。
func TestStatusForCode(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{config.CodeBlocked, http.StatusForbidden},
		{config.CodeUnauthorized, http.StatusUnauthorized},
		{config.CodeRateLimited, http.StatusTooManyRequests},
		{config.CodeBadRequest, http.StatusBadRequest},
		{config.CodeUnavailable, http.StatusServiceUnavailable},
		// 未知错误码必须落到 403，绝不能因为拼写问题返回 2xx 造成静默放行。
		{"WAF_UNKNOWN", http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := StatusForCode(tc.code); got != tc.want {
			t.Errorf("StatusForCode(%s) = %d，期望 %d", tc.code, got, tc.want)
		}
	}
}

// TestResolveCode 验证渲染端点的 code 参数归一化：
// 既支持错误码字面量，也支持 Traefik errors 中间件传入的数字状态码。
func TestResolveCode(t *testing.T) {
	if got := ResolveCode("429"); got != config.CodeRateLimited {
		t.Errorf("ResolveCode(\"429\") = %s，期望 %s", got, config.CodeRateLimited)
	}
	if got := ResolveCode("503"); got != config.CodeUnavailable {
		t.Errorf("ResolveCode(\"503\") = %s，期望 %s", got, config.CodeUnavailable)
	}
	if got := ResolveCode("WAF_BLOCKED"); got != config.CodeBlocked {
		t.Errorf("ResolveCode(\"WAF_BLOCKED\") = %s，期望 %s", got, config.CodeBlocked)
	}
	if got := ResolveCode(""); got != config.CodeBlocked {
		t.Errorf("ResolveCode(\"\") = %s，期望兜底为 %s", got, config.CodeBlocked)
	}
}

// TestRenderWritesHeadersAndBody 验证 /waf/deny 渲染端点同时满足：
//   - 返回真实语义的 HTTP 状态码（供 Traefik errors 中间件使用）；
//   - 回传 X-WAF-Code 响应头（供 Nginx auth_request_set 读取）；
//   - 响应体为规范 JSON（验收项 A26 / A30）。
func TestRenderWritesHeadersAndBody(t *testing.T) {
	writer, err := New(Config{
		Messages: map[string]string{config.CodeRateLimited: "请求过于频繁"},
		Version:  "test",
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	recorder := httptest.NewRecorder()
	writer.Render(recorder, "01J8Z9Q2K7V4M3N5P6R8T1W0XY", "429")

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("状态码 = %d，期望 %d", recorder.Code, http.StatusTooManyRequests)
	}
	if got := recorder.Header().Get(core.HeaderCode); got != config.CodeRateLimited {
		t.Fatalf("X-WAF-Code = %q，期望 %q", got, config.CodeRateLimited)
	}
	if got := recorder.Header().Get(core.HeaderRequestID); got != "01J8Z9Q2K7V4M3N5P6R8T1W0XY" {
		t.Fatalf("X-WAF-Request-Id = %q，与传入的请求标识不一致", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q，拦截响应必须禁止缓存", got)
	}

	var body ErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是合法 JSON：%v（内容：%s）", err, recorder.Body.String())
	}
	if body.Code != config.CodeRateLimited {
		t.Errorf("响应体 code = %q，期望 %q", body.Code, config.CodeRateLimited)
	}
	if body.Message != "请求过于频繁" {
		t.Errorf("响应体 message = %q，未使用配置的自定义文案", body.Message)
	}
	if body.RequestID != "01J8Z9Q2K7V4M3N5P6R8T1W0XY" {
		t.Errorf("响应体 request_id = %q，与传入值不一致", body.RequestID)
	}
	if body.Timestamp == "" {
		t.Error("响应体 timestamp 为空")
	}
}

// TestRespondCarriesTargetAndBanScope 覆盖：普通拦截响应头与 JSON details
// 都包含触发目标和封禁维度，URI 来自原始请求。
func TestRespondCarriesTargetAndBanScope(t *testing.T) {
	writer, err := New(Config{IncludeDetails: true})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}
	rctx := core.NewRequestContext("REQ-TARGET", core.SystemClock{}.Now())
	rctx.Raw.URI = "/admin?x=1"
	result := core.NewResult("banlist", core.VerdictBlock)
	finding := core.NewFinding("banlist", "internal_banlist", "封禁命中", core.SeverityHigh, 0)
	finding.Data = map[string]string{
		"target":    "client_ip+path",
		"ban_scope": "client_ip+path",
	}
	result.AddFinding(finding)

	recorder := httptest.NewRecorder()
	writer.Respond(recorder, rctx, result)

	if got := recorder.Header().Get(core.HeaderTarget); got != "client_ip+path" {
		t.Fatalf("X-WAF-Target = %q", got)
	}
	if got := recorder.Header().Get(core.HeaderBanScope); got != "client_ip+path" {
		t.Fatalf("X-WAF-Ban-Scope = %q", got)
	}
	var body ErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是合法 JSON：%v", err)
	}
	if body.Details == nil || body.Details.Target != "client_ip+path" ||
		body.Details.BanScope != "client_ip+path" || body.Details.URI != "/admin?x=1" {
		t.Fatalf("响应 details 上下文不完整：%+v", body.Details)
	}
}

// TestRenderMetadataIsAvailableToTemplate 覆盖：渲染端点传入的目标、维度与 URI
// 同时写入响应头和自定义模板。
func TestRenderMetadataIsAvailableToTemplate(t *testing.T) {
	writer, err := New(Config{
		Template: `{"target":{{ .Target | json }},"ban_scope":{{ .BanScope | json }},` +
			`"uri":{{ .URI | json }}}`,
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}
	recorder := httptest.NewRecorder()
	writer.Render(recorder, "REQ-META", config.CodeBlocked, RenderMetadata{
		Target:   "ARGS:id",
		BanScope: "client_ip",
		URI:      "/api/user?id=1",
	})

	if got := recorder.Header().Get(core.HeaderTarget); got != "ARGS:id" {
		t.Fatalf("X-WAF-Target = %q", got)
	}
	if got := recorder.Header().Get(core.HeaderBanScope); got != "client_ip" {
		t.Fatalf("X-WAF-Ban-Scope = %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("模板输出不是合法 JSON：%v（%s）", err, recorder.Body.String())
	}
	if body["target"] != "ARGS:id" || body["ban_scope"] != "client_ip" || body["uri"] != "/api/user?id=1" {
		t.Fatalf("模板元数据不符：%#v", body)
	}
}

// TestRespondForceHTTPStatus 验证 Nginx 原生 auth_request 通道下统一回 403 的行为。
//
// 原因（需求 R22）：auth_request 只透传 401/403，其它状态码会被改写成 500，
// 因此该通道下必须统一回 403，真实语义由 X-WAF-Code 承载。
func TestRespondForceHTTPStatus(t *testing.T) {
	writer, err := New(Config{
		ForceHTTPStatus: http.StatusForbidden,
		Version:         "test",
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	recorder := httptest.NewRecorder()
	rctx := core.NewRequestContext("REQ-1", core.SystemClock{}.Now())
	writer.Respond(recorder, rctx, &core.Result{
		Verdict: core.VerdictRateLimited,
		Check:   "ratelimit",
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望统一为 403", recorder.Code)
	}
	if got := recorder.Header().Get(core.HeaderCode); got != config.CodeRateLimited {
		t.Fatalf("X-WAF-Code = %q，期望 %q（真实语义必须由响应头承载）", got, config.CodeRateLimited)
	}
	if got := recorder.Header().Get(core.HeaderVerdict); got != "ratelimit" {
		t.Fatalf("X-WAF-Verdict = %q，期望 ratelimit", got)
	}
}

// TestRespondHidesDetailsByDefault 验证默认不向攻击者泄露检测细节。
func TestRespondHidesDetailsByDefault(t *testing.T) {
	writer, err := New(Config{Version: "test"})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	recorder := httptest.NewRecorder()
	result := &core.Result{Verdict: core.VerdictBlock, Check: "crs-header"}
	result.AddFinding(core.Finding{RuleID: "942100", Message: "SQL 注入", Score: 5})

	writer.Respond(recorder, core.NewRequestContext("REQ-2", core.SystemClock{}.Now()), result)

	var body ErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是合法 JSON：%v", err)
	}
	if body.Details != nil {
		t.Fatalf("include_details 默认关闭时不应输出检测细节，实际：%+v", body.Details)
	}
	// 但响应头仍应回传规则标识，便于代理侧与运维排障。
	if got := recorder.Header().Get(core.HeaderRuleID); got != "942100" {
		t.Fatalf("X-WAF-Rule-Id = %q，期望 942100", got)
	}
}

// TestRespondOverrideWritesCustomResponse 覆盖蜜罐直接响应：
// 规则自带状态码 / Content-Type / Headers / Body，不能被全局 JSON 模板或
// force_http_status 覆盖，同时仍需回传 WAF 审计头。
func TestRespondOverrideWritesCustomResponse(t *testing.T) {
	writer, err := New(Config{
		ForceHTTPStatus: http.StatusForbidden,
		Template:        `{"code":{{ .Code | json }}}`,
		Version:         "test",
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	rctx := core.NewRequestContext("REQ-HONEYPOT", core.SystemClock{}.Now())
	result := core.NewResult("honeypot", core.VerdictHoneypot).
		AddFinding(core.NewFinding("honeypot", "honeypot:phpinfo", "蜜罐命中", core.SeverityHigh, 0)).
		WithResponse(core.ResponseOverride{
			Status:      http.StatusOK,
			ContentType: "text/html; charset=utf-8",
			Headers:     map[string]string{"Server": "Apache/2.4.59"},
			Body:        "<h1>PHP Version 8.2.17</h1>",
		})

	recorder := httptest.NewRecorder()
	writer.Respond(recorder, rctx, result)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望规则定义的 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Server"); got != "Apache/2.4.59" {
		t.Fatalf("自定义响应头丢失：%q", got)
	}
	if recorder.Body.String() != "<h1>PHP Version 8.2.17</h1>" {
		t.Fatalf("响应体被改写：%q", recorder.Body.String())
	}
	if got := recorder.Header().Get(core.HeaderCode); got != config.CodeHoneypot {
		t.Fatalf("X-WAF-Code = %q，期望 %q", got, config.CodeHoneypot)
	}
	if got := recorder.Header().Get(core.HeaderVerdict); got != core.VerdictHoneypot.String() {
		t.Fatalf("X-WAF-Verdict = %q，期望 honeypot", got)
	}
	if got := recorder.Header().Get(core.HeaderRuleID); got != "honeypot:phpinfo" {
		t.Fatalf("X-WAF-Rule-Id = %q", got)
	}
}
