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
	writer := New(Config{
		Messages: map[string]string{config.CodeRateLimited: "请求过于频繁"},
		Version:  "test",
	})

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

// TestRespondForceHTTPStatus 验证 Nginx 原生 auth_request 通道下统一回 403 的行为。
//
// 原因（需求 R22）：auth_request 只透传 401/403，其它状态码会被改写成 500，
// 因此该通道下必须统一回 403，真实语义由 X-WAF-Code 承载。
func TestRespondForceHTTPStatus(t *testing.T) {
	writer := New(Config{
		ForceHTTPStatus: http.StatusForbidden,
		Version:         "test",
	})

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
	writer := New(Config{Version: "test"})

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
