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
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/weiyongkang/waf/internal/ban"
	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/db"
	"github.com/weiyongkang/waf/internal/store"
)

// storeStack 是共享存储与内部封禁的装配结果。
type storeStack struct {
	// stores 是已构建的存储解析器（持有全部 stores[] 实例）。
	stores *store.Resolver
	// banStores 是封禁管理器使用的解析器；启用 SQLite 时把封禁操作分流到数据库，
	// 限速与累进计数仍然使用 stores 中的 Redis / memory / file 实例。
	banStores core.StoreResolver
	// bans 是已构建的封禁管理器（封禁键生成与时长裁剪的唯一入口）。
	bans *ban.Manager
	// configs 是生效的存储声明，供启动日志与 CLI 输出拓扑信息。
	configs []config.StoreConfig
	// storeName 是构建封禁管理器时使用的存储名。
	storeName string
	// database 是启用数据库时的 SQLite 句柄；关闭时保持 nil。
	database *db.DB
	// banStore 是 SQLite 封禁存储；关闭时保持 nil。
	banStore *db.BanStore
	// snapshot 是数据库运营策略的内存快照；关闭时保持 nil。
	snapshot *db.Snapshot
}

// Close 关闭全部存储实例；必须幂等。
func (s *storeStack) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.stores != nil {
		if err := s.stores.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.database != nil {
		if err := s.database.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
	if cfg == nil {
		return nil, fmt.Errorf("构建存储栈时配置不能为空")
	}
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

	stack := &storeStack{
		stores:    resolver,
		banStores: resolver,
		configs:   cfg.Stores,
		storeName: storeName,
	}

	if cfg.Database.Enabled {
		if err := stack.openDatabase(cfg); err != nil {
			_ = stack.Close()
			return nil, err
		}
		stack.banStores = newDatabaseBanResolver(resolver, stack.banStore)
	}

	// CLI 命令（waf ban）不会经过 runServe 的配置覆盖流程，因此这里必须
	// 直接使用数据库中的封禁策略；否则数据库里的 default_ttl / ban_key
	// 与实际运行期不一致。
	managerConfig := cfg.Ban
	if stack.snapshot != nil {
		managerConfig = stack.snapshot.Ban
	}
	manager, err := ban.New(ban.Options{
		Config:    managerConfig,
		Stores:    stack.banStores,
		StoreName: storeName,
		Logger:    logger,
		Metrics:   metrics,
	})
	if err != nil {
		_ = stack.Close()
		return nil, err
	}
	stack.bans = manager

	return stack, nil
}

// openDatabase 打开 SQLite、完成首次导入并加载策略快照。
func (s *storeStack) openDatabase(cfg *config.Config) error {
	database, err := db.Open(db.Config{
		Path:        cfg.Database.Path,
		BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		Clock:       core.SystemClock{},
	})
	if err != nil {
		return fmt.Errorf("打开运行期数据库失败：%w", err)
	}
	s.database = database

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := database.Bootstrap(ctx, cfg, false); err != nil {
		return fmt.Errorf("初始化运行期数据库失败：%w", err)
	}
	snapshot, err := database.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("加载数据库策略快照失败：%w", err)
	}
	banStore, err := db.NewBanStore(database)
	if err != nil {
		return fmt.Errorf("构造数据库封禁存储失败：%w", err)
	}
	s.snapshot = snapshot
	s.banStore = banStore
	return nil
}

// applyConfig 返回叠加数据库运营策略后的配置副本。
//
// 数据库未启用时原样返回；启用时站点、IP 名单、封禁策略与关键标量策略
// 以数据库快照为准，部署类配置仍保留配置文件中的值。
func (s *storeStack) applyConfig(cfg *config.Config) *config.Config {
	if s == nil || s.snapshot == nil {
		return cfg
	}
	return s.snapshot.Apply(cfg)
}

// refreshSnapshot 重新读取数据库策略快照，供热加载使用。
func (s *storeStack) refreshSnapshot(ctx context.Context) (*db.Snapshot, error) {
	if s == nil || s.database == nil {
		return nil, nil
	}
	snapshot, err := s.database.LoadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	s.snapshot = snapshot
	return snapshot, nil
}

// policyRevision 返回数据库策略版本；未启用数据库时返回 0。
func (s *storeStack) policyRevision(ctx context.Context) (int64, error) {
	if s == nil || s.database == nil {
		return 0, nil
	}
	return s.database.Revision(ctx)
}

// newBanManager 使用已建立的存储拓扑重建封禁管理器。
//
// 热重载只允许改 ban 策略，不允许改 stores 拓扑；因此这里复用 resolver，
// 让新策略立即作用于现有存储实例，同时避免重新连接 Redis 或打开新的文件句柄。
func (s *storeStack) newBanManager(cfg config.BanConfig, logger *slog.Logger, metrics core.MetricsRecorder) (*ban.Manager, error) {
	if s == nil || s.stores == nil || s.banStores == nil {
		return nil, fmt.Errorf("共享存储尚未装配，无法重建封禁管理器")
	}
	return ban.New(ban.Options{
		Config:    cfg,
		Stores:    s.banStores,
		StoreName: s.storeName,
		Logger:    logger,
		Metrics:   metrics,
	})
}

// databaseBanResolver 把封禁操作分流到 SQLite，把 Incr 保留给限速存储。
type databaseBanResolver struct {
	// base 是 stores[] 构建出的原存储解析器。
	base core.StoreResolver
	// bans 是 SQLite 封禁存储。
	bans core.Store
}

// newDatabaseBanResolver 构造封禁与计数分离的解析器。
func newDatabaseBanResolver(base core.StoreResolver, bans core.Store) core.StoreResolver {
	return &databaseBanResolver{base: base, bans: bans}
}

// Resolve 返回指定名称的分流存储。
func (r *databaseBanResolver) Resolve(name string) (core.Store, error) {
	counters, err := r.base.Resolve(name)
	if err != nil {
		return nil, err
	}
	return &databaseBanStore{counters: counters, bans: r.bans}, nil
}

// Default 返回默认分流存储。
func (r *databaseBanResolver) Default() (core.Store, error) {
	counters, err := r.base.Default()
	if err != nil {
		return nil, err
	}
	return &databaseBanStore{counters: counters, bans: r.bans}, nil
}

// Names 返回底层存储实例名。
func (r *databaseBanResolver) Names() []string { return r.base.Names() }

// databaseBanStore 将同一 Store 接口拆成两条路径：
// Incr 走向 Redis / memory / file，封禁与名单操作走向 SQLite。
type databaseBanStore struct {
	counters core.Store
	bans     core.Store
}

func (s *databaseBanStore) Incr(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	return s.counters.Incr(ctx, key, window)
}

func (s *databaseBanStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	return s.bans.Ban(ctx, key, ttl, reason)
}

func (s *databaseBanStore) BanWithDetail(ctx context.Context, key string, ttl time.Duration,
	reason string, detail core.BanDetail) error {
	detailed, ok := s.bans.(core.BanDetailStore)
	if !ok {
		return s.bans.Ban(ctx, key, ttl, reason)
	}
	return detailed.BanWithDetail(ctx, key, ttl, reason, detail)
}

func (s *databaseBanStore) BanIfAbsent(ctx context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	return s.bans.BanIfAbsent(ctx, key, ttl, reason)
}

func (s *databaseBanStore) BanIfAbsentWithDetail(ctx context.Context, key string, ttl time.Duration,
	reason string, detail core.BanDetail) (bool, error) {
	detailed, ok := s.bans.(core.BanDetailStore)
	if !ok {
		return s.bans.BanIfAbsent(ctx, key, ttl, reason)
	}
	return detailed.BanIfAbsentWithDetail(ctx, key, ttl, reason, detail)
}

func (s *databaseBanStore) IsBanned(ctx context.Context, key string) (bool, time.Duration, error) {
	return s.bans.IsBanned(ctx, key)
}

func (s *databaseBanStore) List(ctx context.Context) ([]core.BanEntry, error) {
	return s.bans.List(ctx)
}

func (s *databaseBanStore) Unban(ctx context.Context, key string) error {
	return s.bans.Unban(ctx, key)
}

// Close 不关闭底层实例：生命周期由 storeStack 统一管理。
func (s *databaseBanStore) Close() error { return nil }

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
