package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/ban"
	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/logging"
	"github.com/weiyongkang/waf/internal/pipeline"
	"github.com/weiyongkang/waf/internal/server"
	"github.com/weiyongkang/waf/internal/sites"
	"github.com/weiyongkang/waf/internal/version"
)

// servingRuntime 是一次配置装配出的可替换运行组件。
type servingRuntime struct {
	// sites 是站点解析器快照。
	sites *sites.Resolver
	// bans 是本轮生效的封禁管理器。
	bans *ban.Manager
	// decider 是校验链执行器；关闭责任移交给 server 的运行期快照。
	decider *pipeline.Router
}

// buildServingRuntime 按配置装配站点、封禁策略与校验链。
//
// 启动与热重载共用该函数，避免两条装配路径在封禁键、引擎参数或站点解析上出现偏差。
func buildServingRuntime(
	cfg *config.Config,
	stack *storeStack,
	loggers *logging.Loggers,
	metrics core.MetricsRecorder,
	alerts core.AlertSink,
) (*servingRuntime, error) {
	siteResolver, err := sites.New(sites.Options{Declared: cfg.Sites})
	if err != nil {
		return nil, fmt.Errorf("站点策略装配失败：%w", err)
	}

	bans, err := stack.newBanManager(cfg.Ban, loggers.System, metrics)
	if err != nil {
		return nil, fmt.Errorf("封禁策略装配失败：%w", err)
	}

	deps := &core.Deps{
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Stores:       stack.stores,
		Bans:         bans,
		Metrics:      metrics,
		Alerts:       alerts,
		Clock:        core.SystemClock{},
		Limits: core.Limits{
			MaxHeaderBytes:     cfg.Limits.MaxHeaderBytes,
			MaxScanTokenBytes:  cfg.Limits.MaxScanTokenBytes,
			MaxIntelFileBytes:  cfg.Limits.MaxIntelFileBytes,
			MaxMMDBBytes:       cfg.Limits.MaxMMDBBytes,
			MaxConfigFileBytes: cfg.Limits.MaxConfigFileBytes,
			MaxRuleFileBytes:   cfg.Limits.MaxRuleFileBytes,
			MaxRulesTotalBytes: cfg.Limits.MaxRulesTotalBytes,
		},
		Sites:   siteResolver.Sites(),
		Engine:  engineSettings(cfg),
		Version: version.Short(),
	}

	decider, err := pipeline.NewRouter(pipeline.RouterConfig{
		Default: cfg.Pipeline,
		Named:   cfg.Pipelines,
		Body:    cfg.Ingress.Body,
	}, deps)
	if err != nil {
		return nil, fmt.Errorf("校验链装配失败：%w", err)
	}
	return &servingRuntime{sites: siteResolver, bans: bans, decider: decider}, nil
}

// reloadServedConfig 重新加载配置并尝试原子应用。
//
// 失败时只记录 ERROR 并继续使用旧配置，绝不让一次写坏的配置文件影响正在服务的实例。
func reloadServedConfig(
	flagSet *config.FlagSet,
	current *config.Config,
	stack *storeStack,
	loggers *logging.Loggers,
	metrics core.MetricsRecorder,
	alerts core.AlertSink,
	httpServer *server.Server,
) *config.Config {
	resolved, err := config.Load(config.Options{
		ConfigFiles: flagSet.ConfigFiles(),
		CLI:         flagSet,
	})
	if err != nil {
		loggers.System.Error("配置热重载失败，继续使用旧配置", "error", err.Error())
		return current
	}

	nextConfig, err := stack.effectiveConfig(resolved.Config)
	if err != nil {
		loggers.System.Error("配置热重载失败：数据库策略快照不可用，继续使用旧配置", "error", err.Error())
		return current
	}
	if err := config.Validate(nextConfig); err != nil {
		loggers.System.Error("配置热重载被拒绝：数据库覆盖后的配置校验失败", "error", err.Error())
		return current
	}

	if changes := config.RestartRequiredChanges(current, nextConfig); len(changes) > 0 {
		loggers.System.Error("配置热重载被拒绝：以下配置段变更需要重启",
			"restart_required", strings.Join(changes, ","),
			"config_files", len(resolved.Files))
		return current
	}

	next, err := buildServingRuntime(nextConfig, stack, loggers, metrics, alerts)
	if err != nil {
		loggers.System.Error("配置热重载装配失败，继续使用旧配置", "error", err.Error())
		return current
	}

	if err := httpServer.Reload(server.ReloadOptions{
		Config:  nextConfig,
		Decider: next.decider,
		Sites:   next.sites,
	}); err != nil {
		_ = next.decider.Close()
		loggers.System.Error("配置热重载应用失败，继续使用旧配置", "error", err.Error())
		return current
	}

	loggers.System.Info("配置热重载成功",
		"config_files", len(resolved.Files),
		"pipeline_entries", next.decider.Entries(),
		"needs_body", next.decider.NeedsBody(),
		"sites", next.sites.Names(),
		"pipelines", next.decider.Names(),
		"ban_key", next.bans.KeyKind(),
		"ban_keys", strings.Join(next.bans.Scopes(), ","),
		"ban_default_ttl", next.bans.DefaultTTL().String(),
		"ban_max_ttl", next.bans.MaxTTL().String(),
		"database", stack.database != nil,
	)
	return nextConfig
}

// effectiveConfig 在启用数据库时刷新快照，并返回数据库覆盖后的配置副本。
func (s *storeStack) effectiveConfig(cfg *config.Config) (*config.Config, error) {
	if s == nil || s.database == nil {
		return cfg, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.refreshSnapshot(ctx); err != nil {
		return nil, err
	}
	return s.applyConfig(cfg), nil
}

// reloadDatabasePolicy 在数据库策略版本变化时重建运行期快照。
//
// 与 YAML 热重载共用同一套装配逻辑；版本未变化时直接返回，避免周期性重建引擎。
func reloadDatabasePolicy(
	current *config.Config,
	stack *storeStack,
	loggers *logging.Loggers,
	metrics core.MetricsRecorder,
	alerts core.AlertSink,
	httpServer *server.Server,
) *config.Config {
	if stack == nil || stack.database == nil {
		return current
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	revision, err := stack.policyRevision(ctx)
	if err != nil {
		loggers.System.Error("检查数据库策略版本失败，继续使用旧配置", "error", err.Error())
		return current
	}
	if stack.snapshot != nil && revision == stack.snapshot.Revision {
		return current
	}
	if _, err := stack.refreshSnapshot(ctx); err != nil {
		loggers.System.Error("刷新数据库策略快照失败，继续使用旧配置", "error", err.Error())
		return current
	}

	nextConfig := stack.applyConfig(current)
	if err := config.Validate(nextConfig); err != nil {
		loggers.System.Error("数据库策略校验失败，继续使用旧配置", "error", err.Error())
		return current
	}
	next, err := buildServingRuntime(nextConfig, stack, loggers, metrics, alerts)
	if err != nil {
		loggers.System.Error("数据库策略装配失败，继续使用旧配置", "error", err.Error())
		return current
	}
	if err := httpServer.Reload(server.ReloadOptions{
		Config:  nextConfig,
		Decider: next.decider,
		Sites:   next.sites,
	}); err != nil {
		_ = next.decider.Close()
		loggers.System.Error("数据库策略应用失败，继续使用旧配置", "error", err.Error())
		return current
	}

	loggers.System.Info("数据库策略热重载成功",
		"revision", revision,
		"sites", next.sites.Names(),
		"ban_key", next.bans.KeyKind(),
		"ban_default_ttl", next.bans.DefaultTTL().String(),
	)
	return nextConfig
}
