package store

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// 后端类型常量（配置项 stores[].type 与 stores[].fallback）。
const (
	// TypeRedis 表示 Redis 后端（支持 standalone / sentinel / cluster）。
	TypeRedis = "redis"
	// TypeMemory 表示进程内内存后端。
	TypeMemory = "memory"
	// TypeFile 表示单机文件持久化后端。
	TypeFile = "file"
)

// Options 是构建存储集合的参数。
type Options struct {
	// Configs 是存储实例声明（配置文件的 stores 数组）。
	Configs []config.StoreConfig
	// Logger 是系统日志器；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；可为 nil。
	Metrics core.MetricsRecorder
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
}

// Resolver 是 core.StoreResolver 的实现，持有全部已构建的存储实例。
type Resolver struct {
	// stores 是「实例名 -> 存储」索引。
	stores map[string]core.Store
	// order 是构建顺序，关闭时按逆序执行（后建先关）。
	order []string
	// names 是按字典序排列的实例名，供日志与 CLI 输出。
	names []string
}

// Build 依据配置构建全部存储实例。
//
// 构建策略（需求 R23）：
//
//	stores[].enabled=false          -> 不连接共享后端，直接使用 fallback 指定的本地实现，并写 warn 日志；
//	enabled=true 且 type=redis      -> 按 on_error 决定是否包一层降级 / 失败开放包装；
//	enabled=true 且 type=memory|file-> 直接使用本地实现（此时 fallback / on_error 不生效）。
//
// 任一实例构建失败都会整体失败并回滚已建实例（fail fast）。
func Build(opts Options) (*Resolver, error) {
	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}
	clock := opts.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}

	resolver := &Resolver{stores: make(map[string]core.Store, len(opts.Configs))}

	for index, cfg := range opts.Configs {
		if cfg.Name == "" {
			_ = resolver.Close()
			return nil, fmt.Errorf("stores[%d].name 不能为空", index)
		}
		if _, exists := resolver.stores[cfg.Name]; exists {
			_ = resolver.Close()
			return nil, fmt.Errorf("存储实例名 %q 重复，必须唯一", cfg.Name)
		}

		settings, err := decodeSettings(cfg.Name, cfg.Settings)
		if err != nil {
			_ = resolver.Close()
			return nil, err
		}

		built, err := buildStore(cfg, settings, opts.Logger, metrics, clock)
		if err != nil {
			_ = resolver.Close()
			return nil, fmt.Errorf("构建存储 %q(type=%s) 失败：%w", cfg.Name, cfg.Type, err)
		}

		resolver.stores[cfg.Name] = built
		resolver.order = append(resolver.order, cfg.Name)
	}

	resolver.names = make([]string, 0, len(resolver.stores))
	for name := range resolver.stores {
		resolver.names = append(resolver.names, name)
	}
	sort.Strings(resolver.names)
	return resolver, nil
}

// Resolve 返回指定名称的存储（core.StoreResolver 实现）。
func (r *Resolver) Resolve(name string) (core.Store, error) {
	store, exists := r.stores[name]
	if !exists {
		return nil, fmt.Errorf("未找到名为 %q 的存储实例（已构建：%v）", name, r.names)
	}
	return store, nil
}

// Default 返回默认存储（core.StoreResolver 实现）。
func (r *Resolver) Default() (core.Store, error) {
	if store, exists := r.stores["default"]; exists {
		return store, nil
	}
	if len(r.names) == 1 {
		return r.stores[r.names[0]], nil
	}
	if len(r.stores) == 0 {
		return nil, fmt.Errorf("未配置任何存储实例（stores 为空）")
	}
	return nil, fmt.Errorf("存在多个存储实例（%v），请在插件配置中显式指定 store 名称", r.names)
}

// Names 返回全部已构建的存储实例名（core.StoreResolver 实现）。
func (r *Resolver) Names() []string {
	return append([]string(nil), r.names...)
}

// Close 逆序关闭全部存储实例；必须幂等。
func (r *Resolver) Close() error {
	var firstErr error
	for index := len(r.order) - 1; index >= 0; index-- {
		store, exists := r.stores[r.order[index]]
		if !exists {
			continue
		}
		if err := store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(r.stores, r.order[index])
	}
	r.order = nil
	return firstErr
}

// buildStore 依据单个存储声明构建实现。
func buildStore(cfg config.StoreConfig, settings Settings, logger *slog.Logger, metrics core.MetricsRecorder, clock core.Clock) (core.Store, error) {
	// 1) 显式关闭共享后端：直接用本地实现（需求 R23），并明确提示「多实例不共享」。
	if !cfg.Enabled {
		kind := cfg.Fallback
		if kind == "" {
			kind = TypeMemory
		}
		local, err := buildLocal(cfg.Name, kind, settings, logger, metrics, clock)
		if err != nil {
			return nil, err
		}
		if logger != nil {
			logger.Warn("共享存储未启用（stores[].enabled=false），已使用本地存储；"+
				"多实例之间不会共享限速计数与封禁名单",
				"store", cfg.Name, "local", kind, "prefix", settings.Prefix)
		}
		return local, nil
	}

	switch cfg.Type {
	case TypeMemory, TypeFile:
		return buildLocal(cfg.Name, cfg.Type, settings, logger, metrics, clock)

	case TypeRedis:
		primary, err := NewRedisStore(RedisOptions{
			Name:     cfg.Name,
			Settings: settings,
			Logger:   logger,
			Metrics:  metrics,
			Clock:    clock,
		})
		if err != nil {
			return nil, err
		}

		switch cfg.OnError {
		case config.StoreOnErrorFailOpen:
			// 失败开放：后端故障时按「未限速 / 未封禁」处理，可用性优先。
			return newFailOpenStore(cfg.Name, primary, logger, metrics), nil

		case config.StoreOnErrorFailClosed:
			// 失败关闭：不做任何降级，错误原样上抛，由调用方插件的 on_error 决定最终行为。
			// 之所以不在存储层直接拦截：拦截是「判定行为」，必须由校验单元显式声明。
			if logger != nil {
				logger.Info("共享存储运行期故障策略为 fail_closed：Redis 不可用时将由插件按 on_error 处理",
					"store", cfg.Name)
			}
			return primary, nil

		default:
			// fallback_local（默认）：故障时降级到本地实现。
			kind := cfg.Fallback
			if kind == "" {
				kind = TypeMemory
			}
			if kind == TypeRedis {
				return nil, fmt.Errorf("stores[%s].fallback 不能是 redis（会造成递归降级）", cfg.Name)
			}
			local, err := buildLocal(cfg.Name+"-local", kind, settings, logger, metrics, clock)
			if err != nil {
				_ = primary.Close()
				return nil, err
			}
			return newFallbackStore(cfg.Name, primary, local, logger, metrics), nil
		}

	default:
		return nil, fmt.Errorf("未知的存储类型 %q（可选值：redis / memory / file）", cfg.Type)
	}
}

// buildLocal 构造本地实现（memory / file）。
func buildLocal(name, kind string, settings Settings, logger *slog.Logger, metrics core.MetricsRecorder, clock core.Clock) (core.Store, error) {
	switch kind {
	case TypeMemory:
		return NewMemoryStore(MemoryOptions{
			Name:            name,
			Prefix:          settings.Prefix,
			Shards:          settings.Shards,
			MaxEntries:      settings.MaxEntries,
			CleanupInterval: settings.CleanupInterval.Duration(),
			Clock:           clock,
			Logger:          logger,
			Metrics:         metrics,
		})

	case TypeFile:
		return NewFileStore(FileStoreOptions{
			Name:            name,
			Prefix:          settings.Prefix,
			Path:            settings.Path,
			MaxFileBytes:    settings.MaxFileBytes,
			MaxEntries:      settings.MaxEntries,
			CleanupInterval: settings.CleanupInterval.Duration(),
			Clock:           clock,
			Logger:          logger,
			Metrics:         metrics,
		})

	default:
		return nil, fmt.Errorf("未知的本地存储类型 %q（可选值：memory / file）", kind)
	}
}

// degradationTracker 以「状态变化才记录」的方式输出降级与恢复日志。
//
// 之所以需要它：Redis 抖动期间每个请求都会失败，如果每次都写日志，
// 系统日志会被瞬间冲爆，反而掩盖真正的首因错误。
type degradationTracker struct {
	// name 是存储实例名。
	name string
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
	// degraded 标记当前是否处于降级状态。
	degraded atomic.Bool
}

// fail 记录一次后端故障。
func (t *degradationTracker) fail(err error) {
	t.metrics.IncStoreError(t.name)
	if t.degraded.CompareAndSwap(false, true) && t.logger != nil {
		t.logger.Error("共享存储不可用，已进入降级状态", "store", t.name, "error", err.Error())
	}
}

// ok 记录一次后端恢复。
func (t *degradationTracker) ok() {
	if t.degraded.CompareAndSwap(true, false) && t.logger != nil {
		t.logger.Info("共享存储已恢复", "store", t.name)
	}
}

// fallbackStore 在共享后端故障时降级到本地实现（on_error = fallback_local）。
//
// 语义提示：降级期间限速计数退化为「单实例本地计数」，
// 多实例共享暂时失效；这正是 fallback_local 用可用性换一致性的取舍。
type fallbackStore struct {
	// name 是存储实例名。
	name string
	// primary 是共享后端（redis）。
	primary core.Store
	// local 是降级实现（memory / file）。
	local core.Store
	// tracker 负责降级日志与指标。
	tracker *degradationTracker
}

// newFallbackStore 构造降级包装。
func newFallbackStore(name string, primary, local core.Store, logger *slog.Logger, metrics core.MetricsRecorder) *fallbackStore {
	return &fallbackStore{
		name:    name,
		primary: primary,
		local:   local,
		tracker: &degradationTracker{name: name, logger: logger, metrics: metrics},
	}
}

// Name 返回存储实例名。
func (s *fallbackStore) Name() string { return s.name }

// Incr 优先使用共享后端；故障时降级为本地计数。
func (s *fallbackStore) Incr(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	count, ttl, err := s.primary.Incr(ctx, key, window)
	if err == nil {
		s.tracker.ok()
		return count, ttl, nil
	}
	s.tracker.fail(err)
	return s.local.Incr(ctx, key, window)
}

// Ban 优先写入共享后端；故障时降级写入本地（仅本实例生效）。
func (s *fallbackStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	err := s.primary.Ban(ctx, key, ttl, reason)
	if err == nil {
		s.tracker.ok()
		return nil
	}
	s.tracker.fail(err)
	return s.local.Ban(ctx, key, ttl, reason)
}

// IsBanned 优先查共享后端；故障时退化为本地名单查询。
func (s *fallbackStore) IsBanned(ctx context.Context, key string) (bool, time.Duration, error) {
	banned, remaining, err := s.primary.IsBanned(ctx, key)
	if err == nil {
		s.tracker.ok()
		return banned, remaining, nil
	}
	s.tracker.fail(err)

	// 降级期间的判定原则：以本地名单为准。
	//
	// 注意：共享后端中可能仍存在其它实例刚下发、本实例尚未同步的封禁，
	// 这部分在降级期间无法观测——这是 fallback_local 用一致性换可用性的必然代价；
	// 部署时应通过指标（存储错误计数）监控降级持续时长。
	return s.local.IsBanned(ctx, key)
}

// List 优先使用共享后端；故障时返回本地名单（运维需要知道当前实例能看到什么）。
func (s *fallbackStore) List(ctx context.Context) ([]core.BanEntry, error) {
	entries, err := s.primary.List(ctx)
	if err == nil {
		s.tracker.ok()
		return entries, nil
	}
	s.tracker.fail(err)
	return s.local.List(ctx)
}

// Unban 同时解除共享后端与本地名单，避免降级期间的本地残留。
func (s *fallbackStore) Unban(ctx context.Context, key string) error {
	primaryErr := s.primary.Unban(ctx, key)
	localErr := s.local.Unban(ctx, key)
	if primaryErr != nil {
		s.tracker.fail(primaryErr)
	} else {
		s.tracker.ok()
	}
	if primaryErr != nil {
		return primaryErr
	}
	return localErr
}

// Close 关闭共享后端与本地实现。
func (s *fallbackStore) Close() error {
	primaryErr := s.primary.Close()
	localErr := s.local.Close()
	if primaryErr != nil {
		return primaryErr
	}
	return localErr
}

// failOpenStore 在共享后端故障时返回「空结果」（on_error = fail_open）。
//
// 语义：故障期间视为「未触发限速、未被封禁」，请求继续放行。
// 这是可用性优先的取舍，必须以 error 级日志与指标留痕（由 degradationTracker 完成）。
type failOpenStore struct {
	// name 是存储实例名。
	name string
	// primary 是共享后端。
	primary core.Store
	// tracker 负责降级日志与指标。
	tracker *degradationTracker
}

// newFailOpenStore 构造失败开放包装。
func newFailOpenStore(name string, primary core.Store, logger *slog.Logger, metrics core.MetricsRecorder) *failOpenStore {
	return &failOpenStore{
		name:    name,
		primary: primary,
		tracker: &degradationTracker{name: name, logger: logger, metrics: metrics},
	}
}

// Name 返回存储实例名。
func (s *failOpenStore) Name() string { return s.name }

// Incr 故障时返回计数 0（视为未触发限速）。
func (s *failOpenStore) Incr(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	count, ttl, err := s.primary.Incr(ctx, key, window)
	if err != nil {
		s.tracker.fail(err)
		return 0, 0, nil
	}
	s.tracker.ok()
	return count, ttl, nil
}

// Ban 故障时丢弃封禁动作（可用性优先，不阻断业务请求）。
func (s *failOpenStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	if err := s.primary.Ban(ctx, key, ttl, reason); err != nil {
		s.tracker.fail(err)
		return nil
	}
	s.tracker.ok()
	return nil
}

// IsBanned 故障时返回「未封禁」。
func (s *failOpenStore) IsBanned(ctx context.Context, key string) (bool, time.Duration, error) {
	banned, remaining, err := s.primary.IsBanned(ctx, key)
	if err != nil {
		s.tracker.fail(err)
		return false, 0, nil
	}
	s.tracker.ok()
	return banned, remaining, nil
}

// List 是运维命令路径：故障时如实返回错误，便于运维发现后端不可用。
func (s *failOpenStore) List(ctx context.Context) ([]core.BanEntry, error) {
	entries, err := s.primary.List(ctx)
	if err != nil {
		s.tracker.fail(err)
		return nil, err
	}
	s.tracker.ok()
	return entries, nil
}

// Unban 是运维命令路径：故障时如实返回错误。
func (s *failOpenStore) Unban(ctx context.Context, key string) error {
	if err := s.primary.Unban(ctx, key); err != nil {
		s.tracker.fail(err)
		return err
	}
	s.tracker.ok()
	return nil
}

// Close 关闭共享后端。
func (s *failOpenStore) Close() error { return s.primary.Close() }
