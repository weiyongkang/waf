// Package server 负责 forward-auth 鉴权端点的 HTTP 服务与路由装配。
//
// 本包的职责边界（严格遵循需求 R1 / R2，不做反向代理）：
//   - 只暴露鉴权子请求端点、JSON 错误体渲染端点、健康检查与指标端点；
//   - 不接管业务流量、不做 TLS 卸载、不做路由转发、不建立到业务后端的连接。
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/responder"
)

// Options 是 HTTP 服务的构建参数。
type Options struct {
	// Config 是生效配置。
	Config *config.Config
	// Decider 是校验链执行器；为 nil 时使用纯放行执行器。
	Decider core.Decider
	// Extractor 是接入适配器；为 nil 时使用直通适配器（仅用于本地自检）。
	Extractor core.RequestExtractor
	// Responder 是 JSON 错误体渲染器；为 nil 时按配置构建一个。
	Responder *responder.Writer
	// Metrics 是指标写入接口；为 nil 时使用 noop 实现。
	Metrics core.MetricsRecorder
	// Alerts 是告警外送入口；为 nil 时使用丢弃全部告警的空实现。
	//
	// 之所以由外部注入而不是在 server 内部构造：告警外送是旁路能力，
	// 且其实现（internal/notify）依赖 HTTP 客户端等资源，
	// 让 server 只依赖 core.AlertSink 接口可以保持 HTTP 处理层零外送知识。
	Alerts core.AlertSink
	// Audit 是请求审计入口；为 nil 时使用丢弃全部记录的空实现。
	Audit core.AuditSink
	// MetricsHandler 是指标暴露处理器（由 internal/observe 提供）；
	// 为 nil 时 handleMetrics 输出「尚未接入」的占位文本。
	MetricsHandler http.Handler
	// MetricsPath 是指标暴露路径；为空时回落为 "/metrics"。
	//
	// 之所以由外部注入而不是写死：路径可配置（metrics.path），
	// 且必须与 observer 的暴露端点保持一致。
	MetricsPath string
	// SystemLogger 是系统运行日志。
	SystemLogger *slog.Logger
	// AccessLogger 是请求访问与拦截日志。
	AccessLogger *slog.Logger
	// Version 是程序版本。
	Version string
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
	// Sites 是站点解析器；为 nil 时回落为「匹配全部 Host 的默认站点」。
	//
	// 之所以由外部注入而不是在 server 内部构建：站点匹配属于策略层，
	// 与 HTTP 处理无关；注入接口后，未来替换匹配策略（按路径、按灰度比例）
	// 不需要改动任何 HTTP 处理代码。
	Sites core.SiteResolver
}

// Server 是 forward-auth HTTP 服务。
type Server struct {
	cfg                *config.Config
	extractor          core.RequestExtractor
	metrics            core.MetricsRecorder
	alerts             core.AlertSink
	audit              core.AuditSink
	metricsHTTPHandler http.Handler
	metricsPath        string
	systemLogger       *slog.Logger
	accessLogger       *slog.Logger
	version            string
	clock              core.Clock
	startedAt          time.Time
	http               *http.Server
	metricsHTTP        *http.Server
	// runtime 是请求处理使用的不可变快照；重载通过原子替换切换。
	runtime atomic.Pointer[runtimeState]
}

// runtimeState 是一次配置加载对应的请求处理快照。
//
// 使用引用计数延迟关闭旧 decider：重载发生时，已经在途的请求可能仍持有旧快照，
// 立即 Close 会让校验单元在请求中途释放资源。最后一个引用释放后才关闭旧 decider。
type runtimeState struct {
	cfg       *config.Config
	decider   core.Decider
	responder *responder.Writer
	sites     core.SiteResolver

	refs      atomic.Int64
	retired   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// ReloadOptions 是运行期热重载的参数。
type ReloadOptions struct {
	// Config 是重新加载并校验后的配置。
	Config *config.Config
	// Decider 是按新 pipeline / engine / ban 装配出的校验链。
	Decider core.Decider
	// Responder 是新的响应渲染器；为 nil 时按 Config 重新构建。
	Responder *responder.Writer
	// Sites 是新的站点解析器。
	Sites core.SiteResolver
}

// New 构造 HTTP 服务并完成路由装配。
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("server: 配置对象不能为空")
	}

	clock := opts.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	decider := opts.Decider
	if decider == nil {
		// 未装配校验链时退化为纯放行：等价于 pipeline 为空数组（需求 R6）。
		decider = core.AllowAllDecider{}
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}
	alerts := opts.Alerts
	if alerts == nil {
		alerts = core.NoopAlertSink{}
	}
	audit := opts.Audit
	if audit == nil {
		audit = core.NoopAuditSink{}
	}

	writer := opts.Responder
	if writer == nil {
		var err error
		writer, err = buildResponder(opts.Config, opts.Version, clock, opts.SystemLogger)
		if err != nil {
			return nil, err
		}
	}

	srv := &Server{
		cfg:                opts.Config,
		extractor:          opts.Extractor,
		metrics:            metrics,
		alerts:             alerts,
		audit:              audit,
		metricsHTTPHandler: opts.MetricsHandler,
		metricsPath:        metricsEndpointPath(opts),
		systemLogger:       opts.SystemLogger,
		accessLogger:       opts.AccessLogger,
		version:            opts.Version,
		clock:              clock,
		startedAt:          clock.Now(),
	}
	srv.runtime.Store(newRuntimeState(opts.Config, decider, writer, opts.Sites))
	return srv, nil
}

// buildResponder 依据配置构建 JSON 响应渲染器。
func buildResponder(cfg *config.Config, version string, clock core.Clock, logger *slog.Logger) (*responder.Writer, error) {
	forceStatus := 0
	// Nginx 原生 auth_request 通道只能透传 401/403，其它状态码会被改写成 500，
	// 因此该通道下统一回 403，真实语义由 X-WAF-Code 响应头承载（需求 R22）。
	if cfg.Ingress.Type == config.IngressTypeNginxAuthOnly {
		forceStatus = http.StatusForbidden
	}
	writer, err := responder.New(responder.Config{
		IncludeDetails:  cfg.Responder.IncludeDetails,
		Messages:        cfg.Responder.Messages,
		Template:        cfg.Responder.Template,
		TemplateFile:    cfg.Responder.TemplateFile,
		MaxBodyBytes:    cfg.Responder.MaxBodyBytes,
		ForceHTTPStatus: forceStatus,
		Version:         version,
		Clock:           clock,
		Logger:          logger,
	})
	if err != nil {
		return nil, fmt.Errorf("构造响应渲染器失败：%w", err)
	}
	return writer, nil
}

// newRuntimeState 创建请求处理快照。
func newRuntimeState(cfg *config.Config, decider core.Decider, writer *responder.Writer, siteResolver core.SiteResolver) *runtimeState {
	if decider == nil {
		decider = core.AllowAllDecider{}
	}
	return &runtimeState{cfg: cfg, decider: decider, responder: writer, sites: siteResolver}
}

// Reload 原子替换请求处理快照；失败时旧配置继续服务。
func (s *Server) Reload(opts ReloadOptions) error {
	if opts.Config == nil {
		return errors.New("server: 重载配置不能为空")
	}
	if err := s.validateReload(opts.Config); err != nil {
		return err
	}

	writer := opts.Responder
	if writer == nil {
		var err error
		writer, err = buildResponder(opts.Config, s.version, s.clock, s.systemLogger)
		if err != nil {
			return err
		}
	}

	next := newRuntimeState(opts.Config, opts.Decider, writer, opts.Sites)
	old := s.runtime.Swap(next)
	if old != nil {
		old.retire()
	}
	return nil
}

// validateReload 防御性检查路由与监听相关字段未被热更新。
//
// 主流程已经用 config.RestartRequiredChanges 做了完整静态段校验；这里再校验
// 与 Handler 已注册路由直接绑定的字段，防止未来调用方绕过完整校验。
func (s *Server) validateReload(next *config.Config) error {
	current := s.cfg
	switch {
	case current.Server.Listen != next.Server.Listen:
		return errors.New("server.listen 变更需要重启")
	case current.Server.MetricsListen != next.Server.MetricsListen:
		return errors.New("server.metrics_listen 变更需要重启")
	case current.Server.BasePath != next.Server.BasePath:
		return errors.New("server.base_path 变更需要重启")
	case current.Ingress.Path != next.Ingress.Path:
		return errors.New("ingress.path 变更需要重启")
	case current.Ingress.DenyPath != next.Ingress.DenyPath:
		return errors.New("ingress.deny_path 变更需要重启")
	case current.Ingress.Type != next.Ingress.Type:
		return errors.New("ingress.type 变更需要重启")
	case current.Metrics.Enabled != next.Metrics.Enabled:
		return errors.New("metrics.enabled 变更需要重启")
	case current.Metrics.Path != next.Metrics.Path:
		return errors.New("metrics.path 变更需要重启")
	}
	return nil
}

// acquireRuntime 获取当前快照并增加引用计数。
func (s *Server) acquireRuntime() *runtimeState {
	for {
		state := s.runtime.Load()
		if state == nil {
			return nil
		}
		state.refs.Add(1)
		if s.runtime.Load() == state && !state.retired.Load() {
			return state
		}
		state.release()
	}
}

// releaseRuntime 释放快照引用；旧快照的最后一个引用负责关闭 decider。
func (s *Server) releaseRuntime(state *runtimeState) {
	if state != nil {
		state.release()
	}
}

// retire 标记快照退役，并在没有在途请求时关闭其 decider。
func (r *runtimeState) retire() {
	r.retired.Store(true)
	if r.refs.Load() == 0 {
		r.close()
	}
}

// release 减少引用计数。
func (r *runtimeState) release() {
	if r.refs.Add(-1) == 0 && r.retired.Load() {
		r.close()
	}
}

// close 幂等关闭 decider。
func (r *runtimeState) close() {
	r.closeOnce.Do(func() {
		if closer, ok := r.decider.(interface{ Close() error }); ok {
			r.closeErr = closer.Close()
		}
	})
}

// Close 释放当前快照持有的资源。
func (s *Server) Close() error {
	state := s.runtime.Swap(nil)
	if state == nil {
		return nil
	}
	state.retire()
	return state.closeErr
}

// Handler 返回鉴权端点的主路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(s.route(s.cfg.Ingress.Path), s.handleAuth)
	mux.HandleFunc(s.route(s.cfg.Ingress.DenyPath), s.handleDeny)
	mux.HandleFunc(s.route("/healthz"), s.handleHealthz)
	mux.HandleFunc(s.route("/readyz"), s.handleReadyz)
	if s.cfg.Metrics.Enabled {
		mux.HandleFunc(s.route(s.metricsPath), s.handleMetrics)
	}

	// 兜底路由：任何未声明的路径都返回 JSON 404，避免暴露 Go 默认的纯文本响应。
	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

// MetricsHandler 返回独立监听端口上的路由（健康检查 + 指标 + 版本信息）。
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.route("/healthz"), s.handleHealthz)
	mux.HandleFunc(s.route("/readyz"), s.handleReadyz)
	mux.HandleFunc(s.route("/version"), s.handleVersion)
	if s.cfg.Metrics.Enabled {
		mux.HandleFunc(s.route(s.metricsPath), s.handleMetrics)
	}
	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

// route 返回端点在当前部署前缀下的最终生效路径。
func (s *Server) route(path string) string {
	return config.JoinBasePath(s.cfg.Server.BasePath, path)
}

// metricsEndpointPath 推导指标暴露路径。
//
// 优先级：Options.MetricsPath > 配置项 metrics.path > "/metrics"。
// 之所以保留三级回落：Options 是程序化装配入口（测试可覆盖），
// 配置项是运维入口，而 "/metrics" 是任何情况下都能工作的兜底值。
func metricsEndpointPath(opts Options) string {
	if path := strings.TrimSpace(opts.MetricsPath); path != "" {
		return path
	}
	if opts.Config != nil {
		if path := strings.TrimSpace(opts.Config.Metrics.Path); path != "" {
			return path
		}
	}
	return "/metrics"
}

// Run 启动服务并阻塞直到上下文取消或发生致命错误。
//
// 启动策略：业务监听与指标监听相互独立（需求：/metrics 与 /healthz 便于网络隔离）；
// 任一监听启动失败都会立即返回错误，避免「半个服务」上线。
func (s *Server) Run(ctx context.Context) error {
	handler := s.Handler()
	state := s.runtime.Load()
	deciderName := ""
	if state != nil && state.decider != nil {
		deciderName = state.decider.Name()
	}

	s.http = &http.Server{
		Addr:              s.cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout.Duration(),
		MaxHeaderBytes:    int(s.cfg.Limits.MaxHeaderBytes),
		ErrorLog:          slog.NewLogLogger(s.logger().Handler(), slog.LevelWarn),
	}

	runErr := make(chan error, 2)
	var started int

	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return fmt.Errorf("鉴权端点监听 %s 失败：%w", s.http.Addr, err)
	}
	started++
	s.logger().Info("鉴权端点已启动", "addr", s.http.Addr,
		"base_path", s.cfg.Server.BasePath,
		"auth_path", s.route(s.cfg.Ingress.Path),
		"deny_path", s.route(s.cfg.Ingress.DenyPath),
		"decider", deciderName, "version", s.version)
	go func() { runErr <- s.serveHTTP(s.http, listener) }()

	if addr := strings.TrimSpace(s.cfg.Server.MetricsListen); addr != "" {
		s.metricsHTTP = &http.Server{
			Addr:              addr,
			Handler:           s.MetricsHandler(),
			ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout.Duration(),
			ErrorLog:          slog.NewLogLogger(s.logger().Handler(), slog.LevelWarn),
		}
		metricsListener, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			_ = listener.Close()
			return fmt.Errorf("指标端点监听 %s 失败：%w", addr, listenErr)
		}
		started++
		s.logger().Info("指标端点已启动", "addr", addr, "metrics_enabled", s.cfg.Metrics.Enabled)
		go func() { runErr <- s.serveHTTP(s.metricsHTTP, metricsListener) }()
	}

	if started == 0 {
		return errors.New("没有启动任何监听端口，请检查 server.listen 配置")
	}

	select {
	case err := <-runErr:
		// 任一监听异常退出即视为致命错误，触发整体关停。
		s.shutdown()
		return err
	case <-ctx.Done():
		s.logger().Info("收到关停信号，开始优雅退出")
		s.shutdown()
		return nil
	}
}

// serveHTTP 在给定监听器上提供服务，并把 http.ErrServerClosed 归一化为 nil。
func (s *Server) serveHTTP(httpServer *http.Server, listener net.Listener) error {
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP 服务 %s 异常退出：%w", httpServer.Addr, err)
	}
	return nil
}

// shutdown 优雅关停全部监听。
//
// 之所以使用 sync.Once 语义（由调用方保证只调用一次）：Run 的两条退出路径
// （错误退出与信号退出）都可能触发关停，重复 Shutdown 会返回无意义的错误。
func (s *Server) shutdown() {
	timeout := s.cfg.Server.ShutdownTimeout.Duration()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, httpServer := range []*http.Server{s.http, s.metricsHTTP} {
		if httpServer == nil {
			continue
		}
		wg.Add(1)
		go func(hs *http.Server) {
			defer wg.Done()
			if err := hs.Shutdown(ctx); err != nil {
				s.logger().Warn("监听关闭超时", "addr", hs.Addr, "错误", err)
			}
		}(httpServer)
	}
	wg.Wait()
}

// handleAuth 处理 forward-auth 鉴权子请求。
//
// 处理流程：还原原始请求 -> 执行校验链 -> 依据结论渲染响应。
// 放行时不写响应体（仅 200 + 回传响应头），拦截时写 JSON 错误体。
func (s *Server) handleAuth(rw http.ResponseWriter, r *http.Request) {
	state := s.acquireRuntime()
	if state == nil {
		http.Error(rw, "服务正在关闭", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRuntime(state)

	startedAt := s.clock.Now()
	requestID := core.NewRequestID(startedAt)

	rctx := core.NewRequestContext(requestID, startedAt)
	defer func() {
		// 请求体流可能持有临时文件，必须确保释放（需求 R13：不做大体积读取）。
		if rctx.Stream != nil {
			_ = rctx.Stream.Close()
		}
	}()

	raw, err := s.extract(r)
	if err != nil {
		// 还原失败属于客户端请求不可信（例如注入头缺失），按 400 处理。
		s.accessLog().Warn("原始请求还原失败",
			"request_id", requestID, "reason", err.Error(), "remote_addr", r.RemoteAddr)
		s.metrics.IncRequest(siteName(rctx), core.VerdictBadRequest.String())
		failed := &core.Result{
			Verdict: core.VerdictBadRequest,
			Message: "无法还原原始请求信息",
			Err:     err,
			Check:   "ingress",
		}
		detail := s.requestDetail(state, rctx, failed)
		s.recordAudit(state, rctx, failed, detail, startedAt)
		state.responder.Respond(rw, rctx, failed)
		return
	}
	rctx.Raw = raw
	// 站点解析（需求 R6）：在还原出真实 Host 之后、进入校验链之前完成，
	// 使校验单元与日志 / 指标 / 封禁键都能拿到正确的站点归属。
	rctx.Site = resolveSite(state, raw.Host)
	if s.extractor != nil {
		rctx.IngressType = s.extractor.IngressType()
	}
	// 站点级校验链可能需要不同的读体策略：必须在站点解析之后再判断。
	// 需要读取请求体时，为连接设置读取超时，防止慢速请求体攻击长期占用连接；
	// 处理结束后立即清除，避免影响同一 keep-alive 连接上的后续请求。
	needsBody := state.decider.NeedsBody()
	if siteBody, ok := state.decider.(core.SiteBodyDecider); ok {
		needsBody = siteBody.NeedsBodyFor(rctx)
	}
	if needsBody && state.cfg.Ingress.Body.ReadTimeout.Duration() > 0 {
		controller := http.NewResponseController(rw)
		if err := controller.SetReadDeadline(startedAt.Add(state.cfg.Ingress.Body.ReadTimeout.Duration())); err != nil {
			// 部分连接类型不支持设置读取超时（例如特定 HTTP/2 场景），仅记录不阻断。
			s.logger().Debug("无法设置请求体读取超时", "request_id", requestID, "错误", err)
		}
		defer func() {
			// 零值表示清除超时，恢复连接默认行为。
			_ = controller.SetReadDeadline(time.Time{})
		}()
	}
	// 原始请求体的关闭责任在 HTTP 处理层（可能对应网络连接或落盘临时文件）。
	if raw.Body != nil {
		defer func() {
			_ = raw.Body.Close()
		}()
	}

	result := state.decider.Decide(r.Context(), rctx)
	if result == nil {
		result = &core.Result{Verdict: core.VerdictAllow}
	}
	rctx.AppendResult(result)

	// 告警外送（需求 P1-7）：把校验链产出的告警投递给外送入口。
	//
	// 位置选择在「结果已定、响应未写」之间，理由有两条：
	//  1. 只投递一次——结果已经收敛（串联链执行完毕），不会重复；
	//  2. 不影响判定——AlertSink.Notify 的契约是「立刻返回、内部排队异步外送」，
	//     因此这里不会引入任何可感知的延迟，也不会因外送失败改变判定结论。
	if len(result.Alerts) > 0 {
		s.alerts.Notify(result.Alerts)
	}

	detail := s.requestDetail(state, rctx, result)
	s.recordAccess(state, rctx, result, detail, startedAt)
	s.metrics.IncRequest(siteName(rctx), result.Verdict.String())
	s.recordAudit(state, rctx, result, detail, startedAt)

	// 蜜罐命中：鉴权端点只回传「需要渲染」的元数据，最终伪造响应由
	// /waf/deny 在三个代理通道上统一生成。这样 Traefik（只能拿到状态码）、
	// Nginx auth_request（丢弃子请求响应体）和 OpenResty 可以共用同一套
	// 规则匹配与响应渲染逻辑，避免每个代理各自维护一份蜜罐正文。
	if result.Verdict == core.VerdictHoneypot {
		s.respondHoneypotMetadata(rw, rctx, result, requestID)
		return
	}

	if (result.Verdict == core.VerdictAllow || result.Verdict == core.VerdictObserve) && result.Response == nil {
		// 放行：显式回 200 并携带回传响应头，代理据此继续转发业务请求。
		for name, value := range result.Headers {
			rw.Header().Set(name, value)
		}
		rw.Header().Set(core.HeaderVerdict, result.Verdict.String())
		rw.Header().Set(core.HeaderRequestID, requestID)
		rw.Header().Set(core.HeaderCode, "WAF_ALLOW")
		if s.version != "" {
			rw.Header().Set(core.HeaderVersion, s.version)
		}
		rw.WriteHeader(http.StatusOK)
		return
	}

	state.responder.Respond(rw, rctx, result)
}

// respondHoneypotMetadata 写出蜜罐命中的控制响应。
//
// 状态码固定 403：这是 Nginx 原生 auth_request 唯一可靠透传的失败状态，
// 同时也能被 Traefik errors 与 OpenResty 直接识别。规则真正要返回的
// 200/404/500 等状态由 /waf/deny 渲染端点决定。
func (s *Server) respondHoneypotMetadata(rw http.ResponseWriter, rctx *core.RequestContext,
	result *core.Result, requestID string) {
	headers := rw.Header()
	headers.Set("Cache-Control", "no-store")
	headers.Set(core.HeaderVerdict, core.VerdictHoneypot.String())
	headers.Set(core.HeaderCode, config.CodeHoneypot)
	headers.Set(core.HeaderRequestID, requestID)
	if s.version != "" {
		headers.Set(core.HeaderVersion, s.version)
	}
	if rctx != nil && rctx.Site != nil {
		headers.Set("X-WAF-Site", rctx.Site.Name)
	}
	if ruleID := firstResultRuleID(result); ruleID != "" {
		headers.Set(core.HeaderRuleID, ruleID)
	}
	if target := core.ResultTarget(result); target != "" {
		headers.Set(core.HeaderTarget, target)
	}
	if scope := core.ResultBanScope(result); scope != "" {
		headers.Set(core.HeaderBanScope, scope)
	}
	rw.WriteHeader(http.StatusForbidden)
}

// handleDeny 是最终响应渲染端点，供 Traefik errors、Nginx error_page 与
// OpenResty /__waf_deny 回源调用。
//
// 普通拦截返回 JSON 错误体；蜜罐命中则按原始请求重新匹配规则，返回规则
// 定义的任意状态码、响应头与正文。该端点幂等且无副作用，便于直接 curl 自检。
func (s *Server) handleDeny(rw http.ResponseWriter, r *http.Request) {
	state := s.acquireRuntime()
	if state == nil {
		http.Error(rw, "服务正在关闭", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRuntime(state)

	s.metrics.IncDenyRender()
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		// Nginx / OpenResty 可以直接回传 X-WAF-Code；Traefik errors 只能
		// 提供数字状态码，因此这里同时接受查询参数与响应头两种来源。
		code = strings.TrimSpace(r.Header.Get(core.HeaderCode))
	}
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		requestID = r.Header.Get(core.HeaderRequestID)
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		target = strings.TrimSpace(r.Header.Get(core.HeaderTarget))
	}
	banScope := strings.TrimSpace(r.URL.Query().Get("ban_scope"))
	if banScope == "" {
		banScope = strings.TrimSpace(r.Header.Get(core.HeaderBanScope))
	}
	uri := strings.TrimSpace(r.URL.Query().Get("uri"))
	if uri == "" {
		uri = strings.TrimSpace(r.Header.Get("X-Forwarded-Uri"))
	}
	if uri == "" {
		uri = strings.TrimSpace(r.Header.Get("X-Original-URI"))
	}
	if s.renderHoneypot(state, rw, r, code, requestID) {
		return
	}
	state.responder.Render(rw, requestID, code, responder.RenderMetadata{
		Target:   target,
		BanScope: banScope,
		URI:      uri,
	})
}

// renderHoneypot 尝试把本次渲染回源识别为蜜罐命中。
//
// 触发条件：
//   - Nginx / OpenResty 明确传入 WAF_HONEYPOT；
//   - Traefik errors 只能传数字状态码，因此 403（以及可选的 418 哨兵）
//     也需要尝试一次蜜罐重匹配；
//   - 其它明确的拦截码（WAF_BLOCKED 等）不再重匹配，避免误把普通拦截
//     渲染成诱饵页面。
func (s *Server) renderHoneypot(state *runtimeState, rw http.ResponseWriter,
	r *http.Request, code, requestID string) bool {
	if !honeypotRenderCode(code) {
		return false
	}
	matcher, ok := state.decider.(core.HoneypotMatcher)
	if !ok {
		return false
	}

	raw, err := s.extract(r)
	if err != nil {
		s.accessLog().Warn("蜜罐渲染端点无法还原原始请求",
			"request_id", requestID, "reason", err.Error())
		return false
	}
	if requestID == "" {
		requestID = core.NewRequestID(s.clock.Now())
	}
	rctx := core.NewRequestContext(requestID, s.clock.Now())
	rctx.Raw = raw
	rctx.Site = resolveSite(state, raw.Host)
	if s.extractor != nil {
		rctx.IngressType = s.extractor.IngressType()
	}

	result := matcher.MatchHoneypot(rctx)
	if result == nil || result.Response == nil {
		return false
	}
	state.responder.Respond(rw, rctx, result)
	return true
}

// honeypotRenderCode 判断渲染端点是否应该尝试蜜罐匹配。
func honeypotRenderCode(code string) bool {
	switch code {
	case "", config.CodeHoneypot, "403", "418":
		return true
	default:
		return false
	}
}

// handleHealthz 是存活探针：只要进程还在服务，就返回 200。
func (s *Server) handleHealthz(rw http.ResponseWriter, _ *http.Request) {
	s.writeJSON(rw, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
	})
}

// handleReadyz 是就绪探针：在存活的基础上附加「已运行时长」等就绪信息。
//
// 当前阶段校验链与共享存储在启动时已完成装配，因此就绪等于存活；
// 后续阶段若引入规则热加载与存储健康检查，将在此处补充判定。
func (s *Server) handleReadyz(rw http.ResponseWriter, _ *http.Request) {
	state := s.acquireRuntime()
	if state == nil {
		http.Error(rw, "服务正在关闭", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRuntime(state)

	s.writeJSON(rw, http.StatusOK, map[string]any{
		"status":     "ready",
		"version":    s.version,
		"uptime":     s.clock.Since(s.startedAt).String(),
		"decider":    state.decider.Name(),
		"needs_body": state.decider.NeedsBody(),
	})
}

// handleVersion 返回版本信息，便于容器编排与运维快速确认构建版本。
func (s *Server) handleVersion(rw http.ResponseWriter, _ *http.Request) {
	state := s.acquireRuntime()
	if state == nil {
		http.Error(rw, "服务正在关闭", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRuntime(state)

	s.writeJSON(rw, http.StatusOK, map[string]any{
		"version": s.version,
		"decider": state.decider.Name(),
	})
}

// handleMetrics 输出指标。
//
// 采集内容由注入的 MetricsHandler（internal/observe 的 Prometheus 处理器）决定；
// 未注入时输出占位文本，说明指标后端尚未装配——返回 200 而非 404，
// 是为了让「路由已注册但后端缺失」这一装配异常在探针上直接可见。
func (s *Server) handleMetrics(rw http.ResponseWriter, r *http.Request) {
	if s.metricsHTTPHandler != nil {
		s.metricsHTTPHandler.ServeHTTP(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("# 指标后端尚未装配（请装配 internal/observe）\n"))
}

// handleNotFound 是兜底路由：未知路径统一返回 JSON 404。
func (s *Server) handleNotFound(rw http.ResponseWriter, r *http.Request) {
	state := s.acquireRuntime()
	if state == nil {
		http.Error(rw, "服务正在关闭", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseRuntime(state)

	now := s.clock.Now()
	rctx := core.NewRequestContext(core.NewRequestID(now), now)
	// 404 也属于对外拦截响应，必须和鉴权拦截共用同一套渲染模板；
	// 把路径放进请求上下文，模板即可通过 {{ .Path }} 输出实际访问的端点。
	rctx.Raw.Path = r.URL.Path
	rctx.Raw.URI = r.URL.RequestURI()
	rctx.Raw.Method = r.Method
	rctx.Raw.Host = r.Host
	rctx.Raw.Proto = r.Proto
	rctx.Raw.ClientIP = remoteIP(r.RemoteAddr)
	rctx.Raw.ContentLength = r.ContentLength
	rctx.Site = resolveSite(state, r.Host)

	state.responder.Respond(rw, rctx, &core.Result{
		Verdict: core.VerdictBlock,
		Code:    config.CodeNotFound,
	})
}

// writeJSON 写出 JSON 响应。
func (s *Server) writeJSON(rw http.ResponseWriter, status int, payload any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	encoder := jsonEncoder(rw)
	_ = encoder.Encode(payload)
}

// extract 调用接入适配器还原原始请求；未注入适配器时使用直通适配器。
func (s *Server) extract(r *http.Request) (*core.RawRequest, error) {
	if s.extractor != nil {
		return s.extractor.Extract(r)
	}
	return directExtract(r)
}

// requestLogDetail 是一次拦截 / 拒绝场景的请求快照。
//
// 只在非放行场景采集请求参数，避免正常流量产生无意义的解析与日志体积。
type requestLogDetail struct {
	Capture  bool
	Target   string
	BanScope string
	URI      string
	Query    string
	Params   string
}

// requestDetail 汇总目标、URI、查询串与脱敏参数；同一次请求只采集一次。
func (s *Server) requestDetail(state *runtimeState, rctx *core.RequestContext,
	result *core.Result) requestLogDetail {
	detail := requestLogDetail{
		Target:   core.ResultTarget(result),
		BanScope: core.ResultBanScope(result),
	}
	if result != nil && detail.Target == "" {
		detail.Target = result.Check
	}
	if rctx == nil || rctx.Raw == nil {
		return detail
	}
	detail.URI = rctx.Raw.URI
	if detail.URI == "" {
		detail.URI = rctx.Raw.Path
		if rctx.Raw.RawQuery != "" {
			detail.URI += "?" + rctx.Raw.RawQuery
		}
	}
	detail.Query = rctx.Raw.RawQuery
	detail.Capture = result != nil && (result.Verdict != core.VerdictAllow || result.WouldBlock || result.Err != nil)
	if !detail.Capture {
		return detail
	}
	maxBytes := int64(0)
	if state != nil && state.cfg != nil {
		maxBytes = state.cfg.Logging.Access.MaxBodySnippetBytes
	}
	detail.Params = core.CaptureRequestParams(rctx, maxBytes).JSON()
	return detail
}

// recordAccess 写访问日志并记录耗时指标。
func (s *Server) recordAccess(state *runtimeState, rctx *core.RequestContext,
	result *core.Result, detail requestLogDetail, startedAt time.Time) {
	elapsed := s.clock.Since(startedAt)
	s.metrics.ObserveCheckDuration(state.decider.Name(), elapsed.Seconds())

	attributes := []any{
		"request_id", rctx.RequestID,
		"verdict", result.Verdict.String(),
		"check", result.Check,
		"site", siteName(rctx),
		"duration_ms", elapsed.Milliseconds(),
	}
	if rctx.Raw != nil {
		attributes = append(attributes,
			"method", rctx.Raw.Method,
			"path", rctx.Raw.Path,
			"host", rctx.Raw.Host,
			"client_ip", rctx.Raw.ClientIP,
		)
	}
	if len(result.Findings) > 0 {
		attributes = append(attributes, "rule_id", result.Findings[0].RuleID)
	}
	if detail.Capture {
		if detail.Target != "" {
			attributes = append(attributes, "target", detail.Target)
		}
		if detail.BanScope != "" {
			attributes = append(attributes, "ban_scope", detail.BanScope)
		}
		if detail.URI != "" {
			attributes = append(attributes, "uri", detail.URI)
		}
		if detail.Query != "" {
			attributes = append(attributes, "query", detail.Query)
		}
		if detail.Params != "" {
			attributes = append(attributes, "params", detail.Params)
		}
	}
	if result.Err != nil {
		attributes = append(attributes, "error", result.Err.Error())
	}
	// 「若拦截」字段（需求 P1-6）：只有真值才写入日志，避免每条放行日志都多一个 false 字段。
	// 该字段是 DetectionOnly 试运行报告的唯一数据来源（migration 到 on 模式的决策依据）。
	if result.WouldBlock {
		attributes = append(attributes, "would_block", true)
		if result.WouldBlockReason != "" {
			attributes = append(attributes, "would_block_reason", result.WouldBlockReason)
		}
	}

	// 判定动作字段（action）：让「放行 / 拦截 / 观察 / 异常」四类记录字段完全对称，
	// 便于按 action 直接检索、聚合与统计（例如放行与拦截的比例、拦截率趋势）。
	// 该字段在分支之前追加，保证每种判定结果都携带，不会出现解析到缺字段的情形。
	attributes = append(attributes, "action", accessAction(result))

	// 日志等级映射（设计文档 §5.3）：观察与错误用 warn、拦截用 info；
	// 放行请求的等级由 logging.access.allow_level 决定（默认 info，即「过与不过都记录」）。
	switch {
	case result.Err != nil:
		// 校验单元异常优先于放行：失败开放虽然放过了请求，但必须留下 warn 级痕迹。
		s.accessLog().Warn("校验单元异常", attributes...)
	case result.Verdict == core.VerdictAllow:
		s.recordAllow(state, attributes)
	case result.Verdict == core.VerdictObserve && result.WouldBlock:
		// 观察模式且「本应拦截」：用 warn 级而不是 info 级。
		// 原因：这份清单会被用来决定「能否切到 on 模式」，属于必须被看到的运营信号。
		s.accessLog().Warn("旁路观察：本次请求本应被拦截", attributes...)
	case result.Verdict == core.VerdictObserve:
		s.accessLog().Info("命中规则（观察模式）", attributes...)
	case result.Verdict == core.VerdictHoneypot:
		s.accessLog().Info("命中蜜罐规则", attributes...)
	default:
		s.accessLog().Info("请求拦截", attributes...)
	}
}

// recordAudit 把请求结论投递给审计入口。
//
// 审计写入实现必须非阻塞；这里不检查返回值，也不能因审计失败改变响应。
func (s *Server) recordAudit(state *runtimeState, rctx *core.RequestContext,
	result *core.Result, detail requestLogDetail, startedAt time.Time) {
	if result == nil || s.audit == nil {
		return
	}
	entry := core.AuditEntry{
		RequestID:  rctx.RequestID,
		ReceivedAt: startedAt,
		Site:       siteName(rctx),
		Verdict:    result.Verdict.String(),
		Action:     accessAction(result),
		HTTPStatus: auditHTTPStatus(state, result),
		Code:       auditCode(result),
		Check:      result.Check,
		Score:      result.Score,
		Duration:   s.clock.Since(startedAt),
		WouldBlock: result.WouldBlock,
		Findings:   append([]core.Finding(nil), result.Findings...),
	}
	if detail.Capture {
		entry.Target = detail.Target
		entry.BanScope = detail.BanScope
		entry.URI = detail.URI
		entry.Query = detail.Query
		entry.Params = detail.Params
	}
	if result.Err != nil {
		entry.Error = result.Err.Error()
	}
	if result.Response != nil {
		entry.HTTPStatus = result.Response.Status
	}
	if len(result.Findings) > 0 {
		entry.RuleID = result.Findings[0].RuleID
	}
	if rctx.Raw != nil {
		entry.ClientIP = rctx.Raw.ClientIP
		entry.Method = rctx.Raw.Method
		entry.Host = rctx.Raw.Host
		entry.Path = auditPath(rctx.Raw.Path)
	}
	s.audit.Record(entry)
}

// auditCode 返回审计记录中的对外错误码。
func auditCode(result *core.Result) string {
	if result == nil {
		return ""
	}
	if result.Code != "" {
		return result.Code
	}
	if result.Verdict == core.VerdictAllow || result.Verdict == core.VerdictObserve {
		return "WAF_ALLOW"
	}
	return responder.CodeForVerdict(result.Verdict)
}

// auditHTTPStatus 计算审计记录中的对外状态码。
func auditHTTPStatus(state *runtimeState, result *core.Result) int {
	if result == nil {
		return http.StatusOK
	}
	if result.Response != nil {
		return result.Response.Status
	}
	if result.Verdict == core.VerdictAllow || result.Verdict == core.VerdictObserve {
		return http.StatusOK
	}
	if result.Verdict == core.VerdictHoneypot {
		return http.StatusForbidden
	}
	if state != nil && state.cfg.Ingress.Type == config.IngressTypeNginxAuthOnly {
		return http.StatusForbidden
	}
	return responder.StatusForCode(auditCode(result))
}

// auditPath 去除查询串，避免敏感参数进入审计数据库。
func auditPath(path string) string {
	if index := strings.IndexByte(path, '?'); index >= 0 {
		return path[:index]
	}
	return path
}

// accessAction 把判定结果归一为稳定的 action 取值（allow / block / observe / honeypot / error）。
//
// 之所以单独输出 action 而不是让消费方根据 verdict 自行推导：
//  1. verdict 的字符串取值未来可能扩展（例如新增 "challenge"），报表侧不应随之改动；
//  2. 观察模式归一为 observe、异常归一为 error，语义比 verdict 更贴近「日志消费方关心什么」；
//  3. 与 notify、report 等下游字段保持一致的「动词」风格，便于统一检索与统计。
func accessAction(result *core.Result) string {
	switch {
	case result == nil:
		return "error"
	case result.Err != nil:
		return "error"
	case result.Verdict == core.VerdictAllow:
		return "allow"
	case result.Verdict == core.VerdictObserve:
		return "observe"
	case result.Verdict == core.VerdictHoneypot:
		return "honeypot"
	default:
		return "block"
	}
}

// recordAllow 依据 logging.access.allow_level 记录「放行」请求。
//
// 需求背景：鉴权请求无论「过」还是「不过」都要落到访问日志，否则访问日志里
// 会出现「完全没有记录」的请求，排障与容量评估都无从下手。
// 三个取值：
//   - info（默认）：放行以 info 级写入，默认可见，即「过与不过都记录」；
//   - debug：放行以 debug 级写入，仅当把通道级别调到 debug 时可见；
//   - off：完全不记录放行，只保留拦截 / 观察 / 异常记录。
//
// 运行期仍做一次兜底：空值或非法值一律按 info 处理，避免出现「静默不留痕」。
func (s *Server) recordAllow(state *runtimeState, attributes []any) {
	switch strings.ToLower(strings.TrimSpace(state.cfg.Logging.Access.AllowLevel)) {
	case config.AccessAllowLevelOff:
		// 显式关闭：跳过放行记录；拦截 / 观察 / 异常的记录不受任何影响。
		return
	case config.AccessAllowLevelDebug:
		s.accessLog().Debug("请求通过", attributes...)
	default:
		s.accessLog().Info("请求通过", attributes...)
	}
}

// firstResultRuleID 返回结论中首个命中的规则标识；无命中时返回空串。
func firstResultRuleID(result *core.Result) string {
	if result == nil || len(result.Findings) == 0 {
		return ""
	}
	return result.Findings[0].RuleID
}

// siteName 返回站点名，未解析时返回默认站点名。
func siteName(rctx *core.RequestContext) string {
	if rctx == nil || rctx.Site == nil {
		return core.DefaultSiteName
	}
	return rctx.Site.Name
}

// resolveSite 依据还原后的 Host 解析站点策略。
//
// 未装配站点解析器时回落到「匹配全部 Host 的默认站点」，
// 保证 rctx.Site 永不为 nil（日志、指标标签与封禁键都依赖站点名）。
func resolveSite(state *runtimeState, host string) *core.Site {
	if state == nil || state.sites == nil {
		return &core.Site{Name: core.DefaultSiteName, Hosts: []string{"*"}}
	}
	return state.sites.Resolve(host)
}

// logger 返回系统日志器；未注入时返回丢弃输出的兜底日志器。
func (s *Server) logger() *slog.Logger {
	if s.systemLogger != nil {
		return s.systemLogger
	}
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// accessLog 返回访问日志器；未注入时返回丢弃输出的兜底日志器。
func (s *Server) accessLog() *slog.Logger {
	if s.accessLogger != nil {
		return s.accessLogger
	}
	return s.logger()
}
