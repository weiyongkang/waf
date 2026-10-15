// Package contract 是「接入契约测试」：用真实的 HTTP 服务装配验证
// 两种代理接入形态（Traefik forwardAuth / Nginx OpenResty）与 WAF 之间的契约。
//
// 为什么需要独立的契约测试（对应 docs/development-roadmap.md 的 M1.6 与门禁 G1）：
//
//	单元测试只覆盖单个组件的行为；而「代理侧丢弃鉴权响应体、只能靠响应头传递语义」
//	这类问题只有在「接入还原 + 校验链 + 响应渲染 + 状态码策略」全部串起来时才会暴露。
//	本包因此按真实装配路径（config.Load -> store/ban -> pipeline -> server）构建服务，
//	再用 httptest.Server 发真实 HTTP 请求做断言。
//
// 需要真机才能验证的部分（Traefik / OpenResty 自身的行为）不在此处覆盖，
// 由 deploy/forward-auth/ 下的示例配置负责。
package contract

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/ban"
	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/ingress/forwardauth"
	"github.com/weiyongkang/waf/internal/logging"
	"github.com/weiyongkang/waf/internal/notify"
	"github.com/weiyongkang/waf/internal/notifycfg"
	"github.com/weiyongkang/waf/internal/observe"
	"github.com/weiyongkang/waf/internal/pipeline"
	"github.com/weiyongkang/waf/internal/server"
	"github.com/weiyongkang/waf/internal/sites"
	"github.com/weiyongkang/waf/internal/store"
)

// baseConfigTemplate 是契约测试的基础配置模板。
//
// 之所以用「模板 + 覆盖文件」而不是每个用例写一份完整 YAML：
// 契约测试关心的是接入形态与判定结论，完整 YAML 会让差异淹没在噪声里。
// 两个 %s 都会被替换为日志目录；用例的差异化配置由 harnessOptions.override
// 写入独立的覆盖配置文件（多文件按顺序合并，后者覆盖前者）。
const baseConfigTemplate = `
version: 1
server:
  listen: ":0"
  metrics_listen: "127.0.0.1:0"
  read_header_timeout: 3s
  shutdown_timeout: 5s
ingress:
  path: "/waf/auth"
  deny_path: "/waf/deny"
  body:
    mode: optional
    source: request-body
    lazy: true
    max_bytes: 1048576
    chunk_bytes: 32768
    on_exceed: truncate
    spool: auto
    memory_threshold: 65536
    read_timeout: 2s
responder:
  type: json
  include_details: true
engine:
  enabled: true
  mode: on
  paranoia_level: 1
  rules:
    dirs: []
    custom_dirs: []
    include: ["*.conf"]
    data_include: ["*.data"]
    crs_setup: crs-setup.conf
  inline_directives:
    - "SecRequestBodyAccess On"
  body:
    access: true
    limit_bytes: 13107200
    in_memory_limit_bytes: 131072
    limit_action: reject
    json_depth_limit: 4096
    parse_multipart: false
  hot_reload:
    enabled: false
    debounce: 1s
sites:
  - name: default
    hosts: ["*"]
    engine_mode: inherit
    pipeline: default
pipeline:
  - name: crs-header
    type: coraza
    enabled: true
    order: 30
    phase: request
    on_error: block
    settings:
      process_body: false
  - name: crs-body
    type: coraza
    enabled: true
    order: 31
    phase: body
    on_error: block
    settings:
      process_body: true
  - name: threshold
    type: threshold
    enabled: true
    order: 40
    phase: post
    settings:
      action: block
      inbound_threshold: 5
stores:
  - name: default
    type: memory
    enabled: true
    on_error: fallback_local
    settings: {}
ban:
  default_ttl: 30m
  max_ttl: 24h
  ban_key: client_ip
logging:
  system:
    enabled: false
    level: debug
    format: json
    outputs: ["file"]
    dir: "%s"
    file: waf-system
    rotate: daily
    max_file_bytes: 1048576
    keep_days: 1
  access:
    enabled: true
    level: info
    format: json
    outputs: ["file"]
    dir: "%s"
    file: waf-access
    rotate: daily
    max_file_bytes: 1048576
    keep_days: 1
metrics:
  enabled: true
  namespace: waf
  path: /metrics
`

// ingressOverride 生成接入类型的覆盖片段（写入独立的覆盖配置文件）。
//
// 之所以写成独立文件而不是追加到模板末尾：同一个 YAML 文件里出现重复映射键
// （例如两次 ingress:）会被严格解析器直接判为格式错误；
// 而多个配置文件之间按「后者覆盖前者」合并（见 internal/config/load.go），
// 映射递归合并、数组整体替换，正好表达「覆盖某一接入形态」的语义。
func ingressOverride(ingressType string) string {
	return fmt.Sprintf(`ingress:
  type: %q
`, ingressType)
}

// harness 是契约测试的服务装配结果。
type harness struct {
	t *testing.T
	// cfg 是生效配置。
	cfg *config.Config
	// auth 是鉴权端点服务（http://…/waf/auth）。
	auth *httptest.Server
	// metrics 是指标端点服务（/metrics、/healthz、/readyz、/version）。
	metrics *httptest.Server
	// stores 是共享存储解析器（用于跨实例共享用例）。
	stores *store.Resolver
	// bans 是内部封禁管理器。
	bans *ban.Manager
	// decider 是校验链执行器。
	decider core.Decider
	// observer 是指标装配结果。
	observer *observe.Registry
	// loggers 是日志装配结果。
	loggers *logging.Loggers
	// accessLogPath 是访问日志文件路径（含轮转后缀前的完整前缀）。
	accessLogPath string
	// logDir 是日志目录。
	logDir string
}

// harnessOptions 是构建 harness 的可选参数。
type harnessOptions struct {
	// override 是写入独立覆盖配置文件的 YAML 片段（后加载者覆盖先加载者）。
	override string
	// sharedStores 为 nil 时新建存储；非 nil 时复用（用于验证多实例共享）。
	sharedStores *store.Resolver
	// sharedBans 与 sharedStores 配套复用。
	sharedBans *ban.Manager
	// logDir 为空的时使用 t.TempDir()。
	logDir string
}

// newHarness 按真实装配路径构建一套完整服务。
func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	logDir := opts.logDir
	if logDir == "" {
		logDir = t.TempDir()
	}

	dir := t.TempDir()
	basePath := filepath.Join(dir, "waf.yaml")
	// 日志目录会被写进 YAML；Windows 路径含反斜杠，在双引号标量里会被当成转义序列，
	// 因此统一转换为正斜杠后再写入。
	slashLogDir := filepath.ToSlash(logDir)
	content := fmt.Sprintf(baseConfigTemplate, slashLogDir, slashLogDir)
	if err := os.WriteFile(basePath, []byte(content), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}

	// 覆盖片段写入独立文件：多文件按顺序合并（后者覆盖前者），
	// 既能覆盖 ingress / pipeline / engine 等段，又不会触发
	// 「同一文件重复映射键」的 YAML 解析错误。
	files := []string{basePath}
	if opts.override != "" {
		overridePath := filepath.Join(dir, "waf-override.yaml")
		if err := os.WriteFile(overridePath, []byte(opts.override), 0o600); err != nil {
			t.Fatalf("写入测试覆盖配置失败：%v", err)
		}
		files = append(files, overridePath)
	}

	resolved, err := config.Load(config.Options{
		ConfigFiles:           files,
		SkipDefaultConfigPath: true,
	})
	if err != nil {
		t.Fatalf("加载测试配置失败：%v", err)
	}
	cfg := resolved.Config

	loggers, err := logging.Build(cfg.Logging)
	if err != nil {
		t.Fatalf("日志装配失败：%v", err)
	}
	t.Cleanup(func() { _ = loggers.Close() })

	observer := observe.New(observe.Options{
		Enabled:   cfg.Metrics.Enabled,
		Namespace: cfg.Metrics.Namespace,
		Path:      cfg.Metrics.Path,
		Version:   "contract-test",
		Commit:    "test",
		Logger:    loggers.System,
	})

	extractor, err := forwardauth.New(forwardauth.Config{
		Type:       cfg.Ingress.Type,
		Headers:    cfg.Ingress.Headers,
		ClientIP:   cfg.Ingress.ClientIP,
		BodySource: cfg.Ingress.Body.Source,
		Logger:     loggers.System,
	})
	if err != nil {
		t.Fatalf("接入适配器装配失败：%v", err)
	}

	stores := opts.sharedStores
	var bans *ban.Manager
	if stores == nil {
		stores, err = store.Build(store.Options{
			Configs: cfg.Stores,
			Logger:  loggers.System,
			Metrics: observer.Recorder(),
			Clock:   core.SystemClock{},
		})
		if err != nil {
			t.Fatalf("共享存储装配失败：%v", err)
		}
	}
	t.Cleanup(func() { _ = stores.Close() })

	if opts.sharedBans != nil {
		bans = opts.sharedBans
	} else {
		bans, err = ban.New(ban.Options{
			Config:  cfg.Ban,
			Stores:  stores,
			Logger:  loggers.System,
			Metrics: observer.Recorder(),
		})
		if err != nil {
			t.Fatalf("封禁管理器装配失败：%v", err)
		}
	}

	siteResolver, err := sites.New(sites.Options{Declared: cfg.Sites})
	if err != nil {
		t.Fatalf("站点策略装配失败：%v", err)
	}

	// 告警外送（P1-7）：走与 cmd/waf 完全相同的装配入口（internal/notifycfg），
	// 保证「契约测试通过」与「生产可用」不会因为装配路径分叉而失真。
	alerts := buildAlerts(t, cfg, loggers.System, observer.Recorder())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = alerts.Close(ctx)
	})

	deps := &core.Deps{
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Stores:       stores,
		Bans:         bans,
		Metrics:      observer.Recorder(),
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
		Version: "contract-test",
	}

	decider, err := pipeline.New(pipeline.Config{
		Instances: cfg.Pipeline,
		Body:      cfg.Ingress.Body,
	}, deps)
	if err != nil {
		t.Fatalf("校验链装配失败：%v", err)
	}
	t.Cleanup(func() { _ = decider.Close() })

	srv, err := server.New(server.Options{
		Config:         cfg,
		Decider:        decider,
		Extractor:      extractor,
		Metrics:        observer.Recorder(),
		Alerts:         alerts,
		MetricsHandler: observer.Handler(),
		MetricsPath:    cfg.Metrics.Path,
		SystemLogger:   loggers.System,
		AccessLogger:   loggers.Access,
		Version:        "contract-test",
		Clock:          core.SystemClock{},
		Sites:          siteResolver,
	})
	if err != nil {
		t.Fatalf("服务装配失败：%v", err)
	}

	auth := httptest.NewServer(srv.Handler())
	t.Cleanup(auth.Close)
	metrics := httptest.NewServer(srv.MetricsHandler())
	t.Cleanup(metrics.Close)

	return &harness{
		t:             t,
		cfg:           cfg,
		auth:          auth,
		metrics:       metrics,
		stores:        stores,
		bans:          bans,
		decider:       decider,
		observer:      observer,
		loggers:       loggers,
		accessLogPath: filepath.Join(logDir, cfg.Logging.Access.File),
		logDir:        logDir,
	}
}

// buildAlerts 按生产路径装配告警外送管理器。
func buildAlerts(t *testing.T, cfg *config.Config, logger *slog.Logger, metrics core.MetricsRecorder) *notify.Manager {
	t.Helper()
	manager, err := notifycfg.Build(context.Background(), cfg, notifycfg.DefaultDeps(logger, metrics, "contract-test", cfg.Notify.Timeout))
	if err != nil {
		t.Fatalf("告警外送装配失败：%v", err)
	}
	if manager == nil {
		t.Fatal("告警外送装配返回了空管理器")
	}
	return manager
}

// engineSettings 把配置树的 engine 段映射为 core.EngineSettings。
//
// 与 cmd/waf/cmd_run.go 的 engineSettings 保持等价：契约测试必须走与生产
// 完全相同的映射，否则「测试通过、线上不生效」这类问题无法被发现。
func engineSettings(cfg *config.Config) core.EngineSettings {
	engine := cfg.Engine
	processors := make([]core.BodyProcessorSetting, 0, len(engine.Body.Processors))
	for _, item := range engine.Body.Processors {
		processors = append(processors, core.BodyProcessorSetting{
			Name:         item.Name,
			ContentTypes: item.ContentTypes,
			Enabled:      item.Enabled,
		})
	}
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
		Processors:             processors,
	}
}
