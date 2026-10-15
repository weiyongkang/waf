package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
	"github.com/weiyongkang/waf/internal/notifycfg"
	"github.com/weiyongkang/waf/internal/version"
)

// buildNotifier 是 run 子命令侧的告警外送装配入口。
//
// 真正的映射逻辑在 internal/notifycfg：那里同时被契约测试复用，
// 因此"生产装配"与"测试装配"不可能发生分叉（见该包的包注释）。
func buildNotifier(ctx context.Context, cfg *config.Config, logger *slog.Logger, metrics core.MetricsRecorder) (*notify.Manager, error) {
	return notifycfg.Build(ctx, cfg, notifycfg.DefaultDeps(logger, metrics, version.Short(), cfg.Notify.Timeout))
}

// closeAlerts 在关停时释放告警外送资源。
//
// 超时给得比单次送达宽松（取 notify.timeout 的若干倍）：关停时允许多等一会儿
// 让在途告警发出去——告警的"最后一公里"往往就是"进程退出导致告警丢失"，
// 但不能无限等待，超过上限就取消上下文中断外送。
func closeAlerts(ctx context.Context, manager *notify.Manager, timeout time.Duration, logger *slog.Logger) {
	if manager == nil {
		return
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := manager.Close(shutdownCtx); err != nil {
		logger.Error("告警外送关闭失败", "error", err.Error())
	}
}
