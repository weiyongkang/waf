package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// newPrefixedServer 构造带统一前缀与自定义响应模板的测试服务。
func newPrefixedServer(t *testing.T, basePath string, ingressPath string) *Server {
	t.Helper()

	cfg := config.Default()
	cfg.Server.BasePath = basePath
	cfg.Ingress.Path = ingressPath
	cfg.Responder.Template = `{"code":{{ .Code | json }},"path":{{ .Path | json }},` +
		`"request_id":{{ .RequestID | json }}}`
	cfg.Responder.MaxBodyBytes = 2048

	srv, err := New(Options{Config: cfg, Version: "test"})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}
	return srv
}

// TestBasePathRoutes 覆盖：所有 WAF 端点统一挂在前缀下，前缀外一律 404。
func TestBasePathRoutes(t *testing.T) {
	srv := newPrefixedServer(t, "/gateway", "/waf/auth")
	handler := srv.Handler()
	metricsHandler := srv.MetricsHandler()

	cases := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		want    int
	}{
		{name: "auth", handler: handler, method: http.MethodGet, path: "/gateway/waf/auth", want: http.StatusOK},
		{name: "deny", handler: handler, method: http.MethodGet, path: "/gateway/waf/deny?code=429", want: http.StatusTooManyRequests},
		{name: "healthz", handler: handler, method: http.MethodGet, path: "/gateway/healthz", want: http.StatusOK},
		{name: "readyz", handler: handler, method: http.MethodGet, path: "/gateway/readyz", want: http.StatusOK},
		{name: "metrics", handler: handler, method: http.MethodGet, path: "/gateway/metrics", want: http.StatusOK},
		{name: "version on metrics listener", handler: metricsHandler, method: http.MethodGet, path: "/gateway/version", want: http.StatusOK},
		{name: "old path outside prefix", handler: handler, method: http.MethodGet, path: "/waf/auth", want: http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tc.handler.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
			if recorder.Code != tc.want {
				t.Fatalf("%s 状态码 = %d，期望 %d；body=%s", tc.path, recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

// TestNotFoundUsesResponderTemplate 覆盖：404 也走统一响应模板并携带实际路径。
func TestNotFoundUsesResponderTemplate(t *testing.T) {
	srv := newPrefixedServer(t, "/gateway", "/waf/auth")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/gateway/unknown", nil))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("状态码 = %d，期望 404", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("404 响应不是合法 JSON：%v（%s）", err, recorder.Body.String())
	}
	if body["code"] != config.CodeNotFound {
		t.Fatalf("404 code = %#v，期望 %s", body["code"], config.CodeNotFound)
	}
	if body["path"] != "/gateway/unknown" {
		t.Fatalf("404 path = %#v，期望实际请求路径", body["path"])
	}
	if body["request_id"] == "" {
		t.Fatal("404 模板响应应包含 request_id")
	}
}

// TestBasePathIsIdempotentForLegacyPaths 覆盖：旧配置中的 /waf/auth 不会被重复加前缀。
func TestBasePathIsIdempotentForLegacyPaths(t *testing.T) {
	srv := newPrefixedServer(t, "/gateway", "/gateway/waf/auth")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/gateway/waf/auth", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("已包含前缀的旧路径应可访问，实际 %d：%s", recorder.Code, recorder.Body.String())
	}
}

// TestAuditRecordsAllowWithSanitizedPath 覆盖：审计入口收到放行结论，且路径不含查询串。
func TestAuditRecordsAllowWithSanitizedPath(t *testing.T) {
	cfg := config.Default()
	cfg.Ingress.Type = config.IngressTypeTraefik
	sink := &recordingAuditSink{}
	srv, err := New(Options{Config: cfg, Audit: sink})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/waf/auth?token=secret", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	req.Header.Set("X-Forwarded-Uri", "/api/user?token=secret")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200：%s", recorder.Code, recorder.Body.String())
	}
	if len(sink.entries) != 1 {
		t.Fatalf("审计记录数 = %d，期望 1", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.Verdict != "allow" || entry.HTTPStatus != http.StatusOK || entry.Action != "allow" {
		t.Fatalf("审计结论不符：%+v", entry)
	}
	if entry.Path != "/waf/auth" {
		t.Fatalf("审计路径 = %q，查询串必须被剥离", entry.Path)
	}
	if entry.ClientIP == "" || entry.Site != "default" {
		t.Fatalf("审计请求字段不符：%+v", entry)
	}
}

// recordingAuditSink 保存审计记录供断言。
type recordingAuditSink struct {
	entries []core.AuditEntry
}

func (s *recordingAuditSink) Record(entry core.AuditEntry) {
	s.entries = append(s.entries, entry)
}

// TestReloadRejectsStaticChange 覆盖：路由/监听相关配置不允许运行期替换。
func TestReloadRejectsStaticChange(t *testing.T) {
	srv := newPrefixedServer(t, "/gateway", "/waf/auth")
	next := config.Default()
	next.Server.BasePath = "/other"
	if err := srv.Reload(ReloadOptions{Config: next}); err == nil {
		t.Fatal("server.base_path 变更应被拒绝")
	}
}

// TestReloadKeepsOldDeciderUntilInflightRequestsFinish 覆盖：
// 重载后旧 decider 必须等在途请求结束后才能关闭。
func TestReloadKeepsOldDeciderUntilInflightRequestsFinish(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	oldDecider := &blockingDecider{name: "old", started: started, unblock: unblock}

	cfg := config.Default()
	srv, err := New(Options{Config: cfg, Decider: oldDecider, Version: "test"})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}
	handler := srv.Handler()

	response := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/waf/auth", nil))
		response <- recorder.Code
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("在途请求未进入旧 decider")
	}

	nextDecider := &blockingDecider{name: "new"}
	if err := srv.Reload(ReloadOptions{Config: config.Default(), Decider: nextDecider}); err != nil {
		t.Fatalf("热重载失败：%v", err)
	}
	if oldDecider.closed.Load() {
		t.Fatal("在途请求结束前不应关闭旧 decider")
	}

	newRecorder := httptest.NewRecorder()
	handler.ServeHTTP(newRecorder, httptest.NewRequest(http.MethodGet, "/waf/auth", nil))
	if newRecorder.Code != http.StatusOK {
		t.Fatalf("重载后请求状态码 = %d，期望 200", newRecorder.Code)
	}
	if nextDecider.calls.Load() != 1 {
		t.Fatalf("重载后请求应使用新 decider，调用次数 = %d", nextDecider.calls.Load())
	}

	close(unblock)
	select {
	case code := <-response:
		if code != http.StatusOK {
			t.Fatalf("在途请求状态码 = %d，期望 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("在途请求未完成")
	}

	deadline := time.Now().Add(2 * time.Second)
	for !oldDecider.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !oldDecider.closed.Load() {
		t.Fatal("在途请求结束后旧 decider 仍未关闭")
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("关闭服务失败：%v", err)
	}
	if !nextDecider.closed.Load() {
		t.Fatal("服务关闭时应关闭当前 decider")
	}
}

// TestAuthHoneypotMetadataResponse 覆盖：蜜罐结论经 /waf/auth 只返回渲染元数据，
// 不再直接携带规则正文；最终响应由 /waf/deny 统一生成。
func TestAuthHoneypotMetadataResponse(t *testing.T) {
	cfg := config.Default()
	srv, err := New(Options{
		Config:  cfg,
		Decider: honeypotDecider{},
		Version: "test",
	})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/waf/auth", nil))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望统一控制码 403：%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("鉴权元数据响应不应携带正文，实际：%q", recorder.Body.String())
	}
	if got := recorder.Header().Get(core.HeaderVerdict); got != core.VerdictHoneypot.String() {
		t.Fatalf("X-WAF-Verdict = %q，期望 honeypot", got)
	}
	if got := recorder.Header().Get(core.HeaderCode); got != config.CodeHoneypot {
		t.Fatalf("X-WAF-Code = %q", got)
	}
	if got := recorder.Header().Get(core.HeaderRuleID); got != "honeypot:phpinfo" {
		t.Fatalf("X-WAF-Rule-Id = %q", got)
	}
}

// TestDenyHoneypotRendersRuleResponse 覆盖：渲染端点按原始请求重新匹配蜜罐规则，
// 并把规则定义的状态码、响应头与正文返回给代理。
func TestDenyHoneypotRendersRuleResponse(t *testing.T) {
	cfg := config.Default()
	srv, err := New(Options{
		Config:    cfg,
		Decider:   honeypotDecider{},
		Extractor: forwardedExtractor{},
		Version:   "test",
	})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	for _, code := range []string{config.CodeHoneypot, "403", "418"} {
		t.Run(code, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/waf/deny?code="+code, nil)
			req.Header.Set("X-Forwarded-Uri", "/phpinfo.php")
			req.Header.Set("X-Forwarded-Method", http.MethodGet)
			req.Header.Set("X-Forwarded-Host", "app.example.com")

			recorder := httptest.NewRecorder()
			srv.Handler().ServeHTTP(recorder, req)

			if recorder.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，期望规则定义的 200：%s", recorder.Code, recorder.Body.String())
			}
			if recorder.Body.String() != "<h1>PHP Version 8.2.17</h1>" {
				t.Fatalf("响应体 = %q", recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("Content-Type = %q", got)
			}
			if got := recorder.Header().Get(core.HeaderVerdict); got != core.VerdictHoneypot.String() {
				t.Fatalf("X-WAF-Verdict = %q，期望 honeypot", got)
			}
			if got := recorder.Header().Get(core.HeaderRuleID); got != "honeypot:phpinfo" {
				t.Fatalf("X-WAF-Rule-Id = %q", got)
			}
		})
	}
}

// TestDenyExplicitBlockCodeDoesNotRenderHoneypot 覆盖：显式 WAF_BLOCKED
// 不应因为路径碰巧命中蜜罐规则而被误渲染成诱饵页面。
func TestDenyExplicitBlockCodeDoesNotRenderHoneypot(t *testing.T) {
	cfg := config.Default()
	srv, err := New(Options{
		Config:    cfg,
		Decider:   honeypotDecider{},
		Extractor: forwardedExtractor{},
		Version:   "test",
	})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/waf/deny?code="+config.CodeBlocked, nil)
	req.Header.Set("X-Forwarded-Uri", "/phpinfo.php")
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	req.Header.Set("X-Forwarded-Host", "app.example.com")

	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), config.CodeBlocked) {
		t.Fatalf("响应体应为 JSON 拦截信息，实际：%q", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "PHP Version") {
		t.Fatalf("显式 WAF_BLOCKED 不应渲染蜜罐页面：%q", recorder.Body.String())
	}
}

// TestBlockResponseCarriesTargetAndAuditContext 覆盖：拒绝响应在响应头标记
// 触发目标与封禁维度，同时审计记录保存完整 URI、查询串与脱敏参数。
func TestBlockResponseCarriesTargetAndAuditContext(t *testing.T) {
	cfg := config.Default()
	cfg.Ingress.Type = config.IngressTypeTraefik
	sink := &recordingAuditSink{}
	srv, err := New(Options{
		Config:    cfg,
		Decider:   banDecisionDecider{},
		Extractor: forwardedExtractor{},
		Audit:     sink,
		Version:   "test",
	})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/waf/auth", nil)
	req.Header.Set("X-Forwarded-Uri", "/admin/export?user=alice&password=query-secret")
	req.Header.Set("X-Forwarded-Method", http.MethodPost)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.20")

	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403；body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(core.HeaderTarget); got != "client_ip+path" {
		t.Fatalf("X-WAF-Target = %q，期望 client_ip+path", got)
	}
	if got := recorder.Header().Get(core.HeaderBanScope); got != "client_ip+path" {
		t.Fatalf("X-WAF-Ban-Scope = %q，期望 client_ip+path", got)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("审计记录数 = %d，期望 1", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.URI != "/admin/export?user=alice&password=query-secret" {
		t.Fatalf("审计 URI = %q", entry.URI)
	}
	if entry.Query != "user=alice&password=query-secret" {
		t.Fatalf("审计 query = %q", entry.Query)
	}
	if entry.Target != "client_ip+path" || entry.BanScope != "client_ip+path" {
		t.Fatalf("审计目标字段不符：target=%q ban_scope=%q", entry.Target, entry.BanScope)
	}
	if !strings.Contains(entry.Params, `"password":"[REDACTED]"`) {
		t.Fatalf("审计参数未脱敏：%s", entry.Params)
	}
	if strings.Contains(entry.Params, "query-secret") {
		t.Fatalf("审计参数泄露敏感值：%s", entry.Params)
	}
}

// TestDenyRendersTargetAndBanScopeMetadata 覆盖：最终渲染端点能从查询参数
// 或代理请求头还原检测目标、封禁维度与 URI，并写入响应头和自定义模板。
func TestDenyRendersTargetAndBanScopeMetadata(t *testing.T) {
	cfg := config.Default()
	cfg.Responder.Template = `{"target":{{ .Target | json }},"ban_scope":{{ .BanScope | json }},` +
		`"uri":{{ .URI | json }}}`
	srv, err := New(Options{Config: cfg, Version: "test"})
	if err != nil {
		t.Fatalf("构造测试服务失败：%v", err)
	}

	const (
		target   = "ARGS:id"
		banScope = "client_ip+path"
		uri      = "/api/user?id=1"
	)
	queryPath := "/waf/deny?code=" + url.QueryEscape(config.CodeBlocked) +
		"&target=" + url.QueryEscape(target) +
		"&ban_scope=" + url.QueryEscape(banScope) +
		"&uri=" + url.QueryEscape(uri)

	cases := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "query",
			req:  httptest.NewRequest(http.MethodGet, queryPath, nil),
		},
		{
			name: "headers",
			req:  httptest.NewRequest(http.MethodGet, "/waf/deny?code="+config.CodeBlocked, nil),
		},
	}
	cases[1].req.Header.Set(core.HeaderTarget, target)
	cases[1].req.Header.Set(core.HeaderBanScope, banScope)
	cases[1].req.Header.Set("X-Forwarded-Uri", uri)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			srv.Handler().ServeHTTP(recorder, tc.req)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("状态码 = %d，期望 403：%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get(core.HeaderTarget); got != target {
				t.Fatalf("X-WAF-Target = %q，期望 %q", got, target)
			}
			if got := recorder.Header().Get(core.HeaderBanScope); got != banScope {
				t.Fatalf("X-WAF-Ban-Scope = %q，期望 %q", got, banScope)
			}
			var body map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("响应不是合法 JSON：%v（%s）", err, recorder.Body.String())
			}
			if body["target"] != target || body["ban_scope"] != banScope || body["uri"] != uri {
				t.Fatalf("模板上下文不符：%#v", body)
			}
		})
	}
}

// banDecisionDecider 返回固定的封禁名单命中结论。
type banDecisionDecider struct{}

func (banDecisionDecider) Decide(context.Context, *core.RequestContext) *core.Result {
	result := core.NewResult("banlist", core.VerdictBlock)
	finding := core.NewFinding("banlist", "internal_banlist", "来源已在封禁名单中",
		core.SeverityHigh, 0)
	finding.Data = map[string]string{
		"target":    "client_ip+path",
		"ban_scope": "client_ip+path",
	}
	result.AddFinding(finding)
	return result
}

func (banDecisionDecider) NeedsBody() bool { return false }
func (banDecisionDecider) Name() string    { return "banlist" }

// honeypotDecider 是返回蜜罐直接响应的测试执行器。
type honeypotDecider struct{}

func (honeypotDecider) Decide(context.Context, *core.RequestContext) *core.Result {
	return honeypotResult()
}

func (honeypotDecider) MatchHoneypot(*core.RequestContext) *core.Result {
	return honeypotResult()
}

func honeypotResult() *core.Result {
	return core.NewResult("honeypot", core.VerdictHoneypot).
		AddFinding(core.NewFinding("honeypot", "honeypot:phpinfo", "蜜罐命中", core.SeverityHigh, 0)).
		WithResponse(core.ResponseOverride{
			Status:      http.StatusOK,
			ContentType: "text/html; charset=utf-8",
			Body:        "<h1>PHP Version 8.2.17</h1>",
		})
}

func (honeypotDecider) NeedsBody() bool { return false }
func (honeypotDecider) Name() string    { return "honeypot" }

// forwardedExtractor 是测试用原始请求还原器：直接读取 X-Forwarded-* 头。
type forwardedExtractor struct{}

func (forwardedExtractor) IngressType() string { return config.IngressTypeTraefik }

func (forwardedExtractor) Extract(r *http.Request) (*core.RawRequest, error) {
	uri := r.Header.Get("X-Forwarded-Uri")
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, err
	}
	method := r.Header.Get("X-Forwarded-Method")
	if method == "" {
		method = r.Method
	}
	return &core.RawRequest{
		Method:   method,
		URI:      uri,
		Path:     parsed.Path,
		RawQuery: parsed.RawQuery,
		Host:     r.Header.Get("X-Forwarded-Host"),
		Header:   r.Header.Clone(),
	}, nil
}

// blockingDecider 是用于验证热重载生命周期的测试执行器。
type blockingDecider struct {
	name    string
	started chan struct{}
	unblock chan struct{}
	closed  atomic.Bool
	calls   atomic.Int64
}

func (d *blockingDecider) Decide(context.Context, *core.RequestContext) *core.Result {
	d.calls.Add(1)
	if d.started != nil {
		select {
		case <-d.started:
		default:
			close(d.started)
		}
	}
	if d.unblock != nil {
		<-d.unblock
	}
	return &core.Result{Verdict: core.VerdictAllow}
}

func (d *blockingDecider) NeedsBody() bool { return false }
func (d *blockingDecider) Name() string    { return d.name }
func (d *blockingDecider) Close() error {
	d.closed.Store(true)
	return nil
}
