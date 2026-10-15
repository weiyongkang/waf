// Package notifycfg 负责把配置层的 notify / notifiers 段装配为 internal/notify 的构建参数。
//
// 为什么需要这一层（而不是让 internal/notify 直接读 config）：
//
//	internal/notify 是"通道实现"的被依赖方，通道实现不应该认识配置结构；
//	而 internal/config 是被广泛依赖的基础包，也不应该反向依赖告警实现。
//	把映射集中在一个独立包，两侧都保持干净，且"新增配置字段"只需要改这一处。
//
// 为什么契约测试也走这里：生产装配与测试装配一旦分叉，
// 就会出现"测试通过、线上不生效"的假象。本包的 Build 是唯一的装配入口。
package notifycfg

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// Build 依据配置装配告警外送管理器（需求 P1-7）。
//
// 返回值语义：
//   - 无论是否启用，都会返回一个可用的管理器；未启用或没有启用通道时，
//     它退化为「丢弃全部告警」的空实现，调用方无需做 nil 判断与分支处理；
//   - 仅当配置或装配确有错误（通道类型未注册、通道私有配置非法、
//     级别门槛拼写错误）时返回 error。
//
// 失败必须 fail fast 的原因：告警是运维的「眼睛」，
// 一个配了却发不出告警的通道，会让故障在无人知晓的情况下持续扩大。
func Build(ctx context.Context, cfg *config.Config, deps notify.Deps) (*notify.Manager, error) {
	if cfg == nil {
		return nil, nil
	}

	policy := notify.Policy{
		Enabled:        cfg.Notify.Enabled,
		QueueSize:      cfg.Notify.QueueSize,
		Workers:        cfg.Notify.Workers,
		Timeout:        cfg.Notify.Timeout.Duration(),
		MinLevel:       cfg.Notify.MinLevel,
		SuppressWindow: cfg.Notify.SuppressWindow.Duration(),
		MaxAttempts:    cfg.Notify.MaxAttempts,
		RetryBackoff:   cfg.Notify.RetryBackoff.Duration(),
		MaxTrackedKeys: cfg.Notify.MaxTrackedKeys,
	}

	declared := make([]notify.Channel, 0, len(cfg.Notifiers))
	skipped := 0
	for _, item := range cfg.Notifiers {
		if !item.Enabled {
			skipped++
			continue
		}
		declared = append(declared, notify.Channel{
			Instance: notify.Instance{
				Name:     item.Name,
				Type:     item.Type,
				Settings: item.Settings,
			},
			MinLevel:       item.MinLevel,
			SuppressWindow: item.SuppressWindow.Duration(),
		})
	}

	logger := deps.LoggerOr()

	if !cfg.Notify.Enabled && len(declared) > 0 {
		// 这类配置极易被误读为「已经接了告警」：总开关关着，通道却写得很完整。
		// 因此必须显式提示，并说明有效的开启方式。
		logger.Warn("notify.enabled = false，已配置的告警通道不会生效",
			"enabled_channels", len(declared),
			"hint", "如需启用告警外送，请设置 notify.enabled = true 并确认至少一个 notifiers[].enabled = true")
	}

	if !cfg.Notify.Enabled {
		// 总开关关闭：完全不构造任何通道（零开销），返回空管理器。
		return notify.NewManager(ctx, notify.Options{Policy: policy})
	}

	if deps.Hostname == "" {
		// 主机名只是告警内容的辅助定位信息，取不到不应阻断启动。
		if hostname, err := os.Hostname(); err == nil {
			deps.Hostname = hostname
		}
	}

	manager, err := notify.NewManager(ctx, notify.Options{
		Policy:   policy,
		Channels: declared,
		Deps:     deps,
	})
	if err != nil {
		return nil, err
	}

	logger.Info("告警外送已装配",
		"enabled", cfg.Notify.Enabled,
		"channels", manager.Channels(),
		"disabled_channels", skipped,
		"min_level", cfg.Notify.MinLevel,
		"suppress_window", cfg.Notify.SuppressWindow.Duration().String(),
		"queue_size", cfg.Notify.QueueSize,
		"workers", cfg.Notify.Workers,
		"max_attempts", cfg.Notify.MaxAttempts,
		"registered_types", strings.Join(notify.RegisteredTypes(), ","),
	)
	return manager, nil
}

// DefaultDeps 依据给定组件构造通道依赖。
//
// 单独抽出这个构造函数是为了让「命令行装配」与「契约测试装配」用同一套默认值
// （系统日志器、时间源、送达超时），避免两边对同一个配置项给出不同的解释。
func DefaultDeps(logger *slog.Logger, metrics core.MetricsRecorder, version string, timeout core.Duration) notify.Deps {
	return notify.Deps{
		Logger:  logger,
		Metrics: metrics,
		Clock:   core.SystemClock{},
		Version: version,
		Timeout: timeout.Duration(),
	}
}
