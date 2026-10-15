// 本文件是「共享存储 + 内部封禁」的装配点。
//
// 之所以把装配逻辑从 cmd_run.go 抽出来单独成文件：
//
//	waf run（服务进程）与 waf ban（运维命令）都需要构建同一套存储栈，
//	运维命令行必须与运行期使用完全相同的存储实例、相同的键构造规则、
//	相同的封禁时长策略——否则会出现「命令说封禁了、服务却没拦」这类
//	最难排查的问题。把装配收敛到一处是保证这一点的唯一可靠方式。
package main

import (
	"fmt"
	"log/slog"

	"github.com/weiyongkang/waf/internal/ban"
	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/store"
)

// storeStack 是共享存储与内部封禁的装配结果。
type storeStack struct {
	// stores 是已构建的存储解析器（持有全部 stores[] 实例）。
	stores *store.Resolver
	// bans 是已构建的封禁管理器（封禁键生成与时长裁剪的唯一入口）。
	bans *ban.Manager
	// configs 是生效的存储声明，供启动日志与 CLI 输出拓扑信息。
	configs []config.StoreConfig
}

// Close 关闭全部存储实例；必须幂等。
func (s *storeStack) Close() error {
	if s == nil || s.stores == nil {
		return nil
	}
	return s.stores.Close()
}

// buildStoreStack 依据配置装配共享存储与内部封禁控制器。
//
// 参数：
//   - cfg：生效配置（读取 stores 与 ban 两段）；
//   - logger：系统日志器；可为 nil（此时降级为丢弃输出的兜底日志器）；
//   - metrics：指标写入接口；可为 nil（此时使用 noop 实现）；
//   - storeName：执行封禁写入时使用的存储实例名；为空表示使用默认存储。
//
// 任一环节失败都会回滚已建实例并返回错误（fail fast）：
// 「配置里写了 Redis、实际没连上」必须在启动阶段暴露，而不是等首个请求到达。
func buildStoreStack(cfg *config.Config, logger *slog.Logger, metrics core.MetricsRecorder, storeName string) (*storeStack, error) {
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}

	resolver, err := store.Build(store.Options{
		Configs: cfg.Stores,
		Logger:  logger,
		Metrics: metrics,
		Clock:   core.SystemClock{},
	})
	if err != nil {
		return nil, err
	}

	manager, err := ban.New(ban.Options{
		Config:    cfg.Ban,
		Stores:    resolver,
		StoreName: storeName,
		Logger:    logger,
		Metrics:   metrics,
	})
	if err != nil {
		_ = resolver.Close()
		return nil, err
	}

	return &storeStack{stores: resolver, bans: manager, configs: cfg.Stores}, nil
}

// summaries 生成存储实例的可读摘要，用于启动日志与运维输出。
//
// 摘要刻意包含「是否启用共享后端」与「实际拓扑」两项：
// 这两点决定了限速与封禁是否真正跨实例共享，是排障时最先要确认的信息。
func (s *storeStack) summaries() []string {
	if s == nil {
		return nil
	}
	summaries := make([]string, 0, len(s.configs))
	for _, item := range s.configs {
		description := fmt.Sprintf("%s(type=%s,enabled=%t)", item.Name, item.Type, item.Enabled)
		switch {
		case !item.Enabled:
			description += fmt.Sprintf("(降级本地实现=%s)", fallbackKind(item.Fallback))
		case item.Type == store.TypeRedis:
			description += fmt.Sprintf("(topology=%s)", topologyOf(item.Settings))
		}
		summaries = append(summaries, description)
	}
	return summaries
}

// fallbackKind 返回生效的降级本地实现名；未配置时按 memory 处理（与 store 层一致）。
func fallbackKind(configured string) string {
	if configured == "" {
		return store.TypeMemory
	}
	return configured
}

// topologyOf 从存储私有配置片段中读取 Redis 拓扑；未配置时按 standalone 处理。
func topologyOf(settings map[string]any) string {
	if settings != nil {
		if raw, exists := settings["topology"]; exists {
			if text, ok := raw.(string); ok && text != "" {
				return text
			}
		}
	}
	return "standalone"
}
