package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/ingress/forwardauth"
	"github.com/weiyongkang/waf/internal/logging"
	"github.com/weiyongkang/waf/internal/observe"
	"github.com/weiyongkang/waf/internal/pipeline"
	"github.com/weiyongkang/waf/internal/server"
	"github.com/weiyongkang/waf/internal/sites"
	"github.com/weiyongkang/waf/internal/version"
)

// runServe 实现 run 子命令：装配并启动 forward-auth 服务。
//
// 装配顺序（与设计文档 §9.2 的 main.go 职责一致）：
//
//	版本信息 -> 配置加载与校验 -> 日志初始化 -> 接入适配器 -> 依赖集合
//	-> 校验链 -> HTTP 服务 -> 等待信号 -> 优雅关停
//
// 当前进度（M1.3）：接入还原（T5）、请求体缓冲（T6）、串联执行器（T7）、
// 共享存储与内部封禁（T10）已接入；检测引擎（T13，M1.5）与
// Prometheus 指标（T16，M1.5）将在后续里程碑在此处继续装配。
func runServe(args []string, stdout, stderr io.Writer) int {
	resolved, _, code := loadResolved(args, stderr, "waf run")
	if code != exitOK {
		return code
	}
	cfg := resolved.Config

	loggers, err := logging.Build(cfg.Logging)
	if err != nil {
		fmt.Fprintf(stderr, "日志初始化失败：%v\n", err)
		return exitConfigError
	}
	defer func() {
		if err := loggers.Close(); err != nil {
			fmt.Fprintf(stderr, "日志关闭失败：%v\n", err)
		}
	}()

	// 指标（T16，需求 R6 / R13）：
	//
	//	metrics.enabled=true  时构造 Prometheus 采集器，并把暴露端点交给 HTTP 服务；
	//	metrics.enabled=false 时 Recorder 为 noop、Handler 固定 404，实现「关闭即零开销」。
	//
	// 之所以在装配共享存储之前构建：存储层也需要指标（store_errors_total），
	// 必须保证「存储装配」与「指标装配」使用的是同一个写入器实例。
	observer := observe.New(observe.Options{
		Enabled:   cfg.Metrics.Enabled,
		Namespace: cfg.Metrics.Namespace,
		Path:      cfg.Metrics.Path,
		Version:   version.Version,
		Commit:    version.Commit,
		Logger:    loggers.System,
	})
	metrics := observer.Recorder()

	// 接入适配器（T5）：把 Nginx / Traefik 注入头还原为原始业务请求。
	// 装配失败属于配置问题（例如类型取值非法、可信代理网段写错），必须 fail fast。
	extractor, err := forwardauth.New(forwardauth.Config{
		Type:       cfg.Ingress.Type,
		Headers:    cfg.Ingress.Headers,
		ClientIP:   cfg.Ingress.ClientIP,
		BodySource: cfg.Ingress.Body.Source,
		Logger:     loggers.System,
	})
	if err != nil {
		fmt.Fprintf(stderr, "接入适配器装配失败：%v\n", err)
		return exitConfigError
	}

	// 共享存储与内部封禁（需求 R17 / R18 / R23 / R25）：
	//
	//	stores[] 声明了限速计数与封禁名单的落地载体（redis / memory / file）；
	//	ban 段声明了封禁键维度与时长策略。两者的装配收敛在 buildStoreStack，
	//	保证 waf run 与 waf ban 使用完全相同的存储实例与键构造规则。
	//
	// 装配失败属于配置问题（例如 Redis 地址写错、拓扑取值非法），必须 fail fast：
	// 「配置里写了限速与封禁、实际没生效」比启动失败危险得多。
	stack, err := buildStoreStack(cfg, loggers.System, metrics, "")
	if err != nil {
		fmt.Fprintf(stderr, "共享存储装配失败：%v\n", err)
		return exitConfigError
	}
	defer func() {
		if err := stack.Close(); err != nil {
			loggers.System.Error("共享存储关闭失败", "error", err.Error())
		}
	}()

	// 站点解析（T14，需求 R6）：把 sites[] 声明编译成可快速匹配的站点表。
	// 装配失败属于配置问题（重名、重复 Host、非法通配模式），必须 fail fast。
	siteResolver, err := sites.New(sites.Options{Declared: cfg.Sites})
	if err != nil {
		fmt.Fprintf(stderr, "站点策略装配失败：%v\n", err)
		return exitConfigError
	}

	// 告警外送（T18，需求 P1-7）：
	//
	//	notify.enabled=false 时得到的是一个「丢弃全部告警」的空管理器，
	//	因此后续代码无需分支判断；enabled=true 时按 notifiers[] 构造通道并启动外送协程。
	//
	// 装配失败属于配置问题（通道类型未注册、通道私有配置非法），必须 fail fast。
	alerts, err := buildNotifier(context.Background(), cfg, loggers.System, metrics)
	if err != nil {
		fmt.Fprintf(stderr, "告警外送装配失败：%v\n", err)
		return exitConfigError
	}
	// 关停顺序：先停服务（不再产生新告警），再排空告警队列，最后关闭日志。
	// 这里的 defer 注册早于「日志关闭」的 defer，因此按 LIFO 顺序正好满足该要求。
	defer closeAlerts(context.Background(), alerts, 3*cfg.Notify.Timeout.Duration(), loggers.System)

	// 依赖集合：校验单元通过它获取日志、共享存储、指标、时间源与站点策略。
	deps := &core.Deps{
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Stores:       stack.stores,
		Bans:         stack.bans,
		Metrics:      metrics,
		Alerts:       alerts,
		Clock:        core.SystemClock{},
		Limits: core.Limits{
			MaxHeaderBytes:     cfg.Limits.MaxHeaderBytes,
			MaxScanTokenBytes:  cfg.Limits.MaxScanTokenBytes,
			MaxIntelFileBytes:  cfg.Limits.MaxIntelFileBytes,
			MaxRuleFileBytes:   cfg.Limits.MaxRuleFileBytes,
			MaxRulesTotalBytes: cfg.Limits.MaxRulesTotalBytes,
		},
		Sites:   siteResolver.Sites(),
		Engine:  engineSettings(cfg),
		Version: version.Short(),
	}

	// 校验链（T7）：enabled=false 的实例会被丢弃；链为空即等价纯放行（需求 R6）。
	decider, err := pipeline.New(pipeline.Config{
		Instances: cfg.Pipeline,
		Body:      cfg.Ingress.Body,
	}, deps)
	if err != nil {
		fmt.Fprintf(stderr, "校验链装配失败：%v\n", err)
		return exitConfigError
	}
	defer func() {
		if err := decider.Close(); err != nil {
			fmt.Fprintf(stderr, "校验链关闭失败：%v\n", err)
		}
	}()

	// HTTP 服务：不传 Responder，由 server 依据 ingress.type 自行构建
	// （nginx-auth-only 通道需要把对外状态码统一收敛为 403，由 response 头承载真实语义）。
	httpServer, err := server.New(server.Options{
		Config:         cfg,
		Decider:        decider,
		Extractor:      extractor,
		Metrics:        deps.Metrics,
		Alerts:         alerts,
		MetricsHandler: observer.Handler(),
		MetricsPath:    cfg.Metrics.Path,
		SystemLogger:   loggers.System,
		AccessLogger:   loggers.Access,
		Version:        version.Short(),
		Clock:          deps.Clock,
		Sites:          siteResolver,
	})
	if err != nil {
		fmt.Fprintf(stderr, "服务装配失败：%v\n", err)
		return exitRuntimeError
	}

	loggers.System.Info("WAF 启动",
		"version", version.Version,
		"commit", version.Commit,
		"build_time", version.BuildTime,
		"listen", cfg.Server.Listen,
		"metrics_listen", cfg.Server.MetricsListen,
		"ingress_type", extractor.IngressType(),
		"auth_path", cfg.Ingress.Path,
		"deny_path", cfg.Ingress.DenyPath,
		"trusted_proxies", extractor.TrustedProxies(),
		"decider", decider.Name(),
		"pipeline_entries", decider.Entries(),
		"needs_body", decider.NeedsBody(),
		"stores", stack.summaries(),
		"metrics_enabled", observer.Enabled(),
		"metrics_path", cfg.Metrics.Path,
		"metrics_namespace", cfg.Metrics.Namespace,
		"ban_key", stack.bans.KeyKind(),
		"ban_keys", strings.Join(stack.bans.Scopes(), ","),
		"ban_default_ttl", stack.bans.DefaultTTL().String(),
		"ban_max_ttl", stack.bans.MaxTTL().String(),
		"sites", siteResolver.Names(),
		"config_files", len(resolved.Files),
	)

	// 接入通道能力清单（设计文档 §3.7）：
	//
	//	为什么必须显式打印：forward-auth 形态下「能不能拿到请求体」「能不能送达 JSON 错误体」
	//	完全取决于代理侧配置，而 WAF 在运行期无法区分「客户端没带请求体」与「代理没转发请求体」。
	//	把能力清单写进启动日志，运维才能在只看到结果的情况下判断部署是否符合预期。
	reportIngressCapabilities(loggers.System, cfg, extractor.IngressType())

	// 信号处理：SIGINT / SIGTERM 触发优雅关停（验收项 A9）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := httpServer.Run(ctx); err != nil {
		loggers.System.Error("服务异常退出", "error", err.Error())
		fmt.Fprintf(stderr, "服务异常退出：%v\n", err)
		return exitRuntimeError
	}

	loggers.System.Info("WAF 已退出")
	return exitOK
}

// reportIngressCapabilities 在启动日志中输出接入通道的能力清单与降级风险（设计文档 §3.7）。
//
// 输出三项能力，它们是 forward-auth 形态下最容易踩坑的地方：
//
//	body_detection        ：能否拿到请求体（决定请求体检测是否真的在生效）；
//	json_error_body       ：能否把 WAF 渲染的 JSON 错误体送达客户端（否则只剩代理默认错误页）；
//	trusted_content_length：子请求携带的 Content-Length 是否等于原始请求声明的长度。
//
// 最后一项与「请求体缺失」的判定强相关：原生 Nginx 的 auth_request 通道既不转发请求体
// 也不转发 Content-Length（子请求的 Content-Length 恒为 0），WAF 侧无法据此区分
// 「客户端声明了空体」与「代理没转发请求体」，因此该通道下会统一按「未知」处理（-1）。
// 若此时把 ingress.body.mode 配成 required，缺失判定将失去意义，必须显式告警。
func reportIngressCapabilities(logger *slog.Logger, cfg *config.Config, ingressType string) {
	if logger == nil {
		return
	}

	// 默认能力：Traefik / OpenResty / 直通形态都具备三项能力。
	bodyDetection, jsonErrorBody, trustedContentLength := true, true, true
	switch ingressType {
	case config.IngressTypeNginxAuthOnly:
		// 原生 Nginx 通道：auth_request 子请求是 header-only 的，且只能透传 401/403。
		bodyDetection, jsonErrorBody, trustedContentLength = false, false, false
	}

	logger.Info("接入通道能力清单",
		"ingress_type", ingressType,
		"body_detection", bodyDetection,
		"json_error_body", jsonErrorBody,
		"trusted_content_length", trustedContentLength,
		"body_mode", cfg.Ingress.Body.Mode,
	)

	// 「配置声明要请求体检测，通道却送不来请求体」属于必须立刻纠正的配置事故：
	// required 语义下 waf_body_missing_total 与缺失告警都不会反映真实情况。
	if !bodyDetection && cfg.Ingress.Body.Mode == config.BodyModeRequired {
		logger.Warn("接入通道不转发请求体，但 ingress.body.mode = required："+
			"「请求体缺失」无法被观测，waf_body_missing_total 不会反映真实情况；"+
			"请改用 OpenResty 通道或 Traefik（forwardBody: true），"+
			"或把 body.mode 调整为 optional / disabled",
			"ingress_type", ingressType, "body_mode", cfg.Ingress.Body.Mode)
	}

	// auto 只用于过渡期：原生 Nginx(auth-only) 与 OpenResty 的注入头完全相同，无法自动区分。
	if ingressType == config.IngressTypeAuto {
		logger.Info("ingress.type = auto 判定结果会随请求变化，且无法区分 nginx-openresty 与 nginx-auth-only；" +
			"生产环境请显式声明 ingress.type")
	}
}

// engineSettings 把配置树的 engine 段映射为 core.EngineSettings。
//
// 之所以做这层映射而不是让插件直接读 config：core 是被依赖的基础包，
// 不允许反向导入 config（会造成循环依赖）。映射集中在此处，
// 新增引擎配置项时只需要改这一个函数。
func engineSettings(cfg *config.Config) core.EngineSettings {
	engine := cfg.Engine
	return core.EngineSettings{
		Enabled:                engine.Enabled,
		Mode:                   engine.Mode,
		ParanoiaLevel:          engine.ParanoiaLevel,
		RuleDirs:               engine.Rules.Dirs,
		CustomRuleDirs:         engine.Rules.CustomDirs,
		RuleInclude:            engine.Rules.Include,
		RuleDataInclude:        engine.Rules.DataInclude,
		CRSSetup:               engine.Rules.CRSSetup,
		InlineDirectives:       engine.InlineDirectives,
		BodyAccess:             engine.Body.Access,
		BodyLimitBytes:         engine.Body.LimitBytes,
		BodyInMemoryLimitBytes: engine.Body.InMemoryLimitBytes,
		BodyLimitAction:        engine.Body.LimitAction,
		JSONDepthLimit:         engine.Body.JSONDepthLimit,
		ParseMultipart:         engine.Body.ParseMultipart,
		Processors:             bodyProcessors(engine.Body.Processors),
		AnomalyScoreThreshold:  engine.AnomalyScoreThreshold,
		Exceptions:             exceptionSettings(engine.Exceptions),
		HotReload: core.HotReloadSetting{
			Enabled:      engine.HotReload.Enabled,
			Debounce:     engine.HotReload.Debounce.Duration(),
			PollInterval: engine.HotReload.PollInterval.Duration(),
			MarkerFile:   engine.HotReload.MarkerFile,
		},
	}
}

// exceptionSettings 把配置层的误报例外映射为引擎层设置。
//
// 映射保留全部条目（含 enabled=false 与被关闭的）：启用开关与过期判定都交给
// internal/rules/exceptions 统一处理，这样「CLI 校验」「rules list 审计报表」
// 与「运行态编译」看到的是同一份判定逻辑与同一种状态口径。
func exceptionSettings(configured []config.ExceptionConfig) []core.ExceptionSetting {
	if len(configured) == 0 {
		return nil
	}
	settings := make([]core.ExceptionSetting, 0, len(configured))
	for _, item := range configured {
		settings = append(settings, core.ExceptionSetting{
			Name:       item.Name,
			Enabled:    item.Enabled,
			Reason:     item.Reason,
			RuleIDs:    item.RuleIDs,
			Tags:       item.Tags,
			Targets:    item.Targets,
			URLPattern: item.URLPattern,
			Methods:    item.Methods,
			ExpiresAt:  parseExpiresAt(item.ExpiresAt),
		})
	}
	if len(settings) == 0 {
		return nil
	}
	return settings
}

// parseExpiresAt 解析例外的失效时间。
//
// 解析失败时返回零值（等价于「永不过期」）而不是让装配失败：
// 配置校验阶段已经对非法时间报错，能走到这里的只有「合法但被手工构造」的极端情况；
// 此时「永不过期」比「整个 WAF 起不来」是更稳妥的降级。
func parseExpiresAt(value string) time.Time {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// bodyProcessors 把配置层的请求体处理器映射转换为引擎层设置。
//
// 之所以保留 nil：nil 表示「未配置」，由 coraza 实现回落到内置默认映射（JSON / XML）；
// 空切片表示运维显式关闭了全部路由映射，语义不同，不能在此处归一化。
func bodyProcessors(configured []config.BodyProcessorConfig) []core.BodyProcessorSetting {
	if configured == nil {
		return nil
	}
	mappings := make([]core.BodyProcessorSetting, 0, len(configured))
	for _, item := range configured {
		mappings = append(mappings, core.BodyProcessorSetting{
			Name:         item.Name,
			ContentTypes: item.ContentTypes,
			Enabled:      item.Enabled,
		})
	}
	return mappings
}
