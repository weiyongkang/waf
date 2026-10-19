// Package store 实现共享状态存储的三种后端：redis / memory / file（需求 R17 / R23 / R25）。
//
// 为什么需要抽象（core.Store）：限速计数与封禁名单必须能跨实例共享，
// 而部署形态可能是 Redis 单机 / 哨兵 / 集群，也可能是没有 Redis 的单机内存，
// 甚至需要落盘持久化。校验单元只面向 core.Store 编程，因此切换后端不需要改动任何插件。
//
// 键前缀统一由各实现负责拼接（配置项 settings.prefix），
// 调用方（插件）只需要构造「逻辑键」（例如 rl:ip:1.2.3.4:60），无需关心隔离前缀。
//
// 本包只承载实现与构建逻辑，接口定义在 internal/core/store.go（避免 store 与 check 循环依赖）。
package store

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// defaultMemoryShards 是内存存储的默认分片数（配置文件可覆盖）。
//
// 之所以默认分片：限速计数是每次请求都要写的热点，单一互斥锁在
// 高并发下会成为明显瓶颈；按 key 哈希分片后，锁竞争被摊薄到各分片内。
const defaultMemoryShards = 64

// defaultCleanupInterval 是过期项清理的默认周期（配置文件可覆盖）。
const defaultCleanupInterval = time.Minute

// defaultMaxEntries 是内存存储的默认条目上限（配置文件可覆盖）。
//
// 取一个较大的值：正常业务下计数项会随窗口自然过期，
// 该上限只是「异常流量导致键空间爆炸」时的兜底保护（需求 R13：容量必须可配置且有上限）。
const defaultMaxEntries = 1000000

// counterItem 是一个固定窗口计数项。
type counterItem struct {
	// value 是当前窗口内的计数。
	value int64
	// expireAt 是窗口结束时间。
	expireAt time.Time
}

// banItem 是一条封禁记录。
type banItem struct {
	// reason 是封禁原因（写入名单值，便于运维排查）。
	reason string
	// bannedAt 是首次封禁时间。
	bannedAt time.Time
	// expireAt 是封禁到期时间；零值表示永不过期。
	expireAt time.Time
}

// memoryShard 是内存存储的一个分片，持有独立的互斥锁与两张表。
type memoryShard struct {
	// mu 保护 counters 与 bans。
	mu sync.Mutex
	// counters 是限速计数表。
	counters map[string]*counterItem
	// bans 是封禁名单表。
	bans map[string]*banItem
}

// MemoryStore 是进程内存储实现。
//
// 适用场景：
//   - 单机部署且不需要持久化（进程重启后计数与名单清空）；
//   - 作为 Redis 未启用或运行期故障时的降级实现（需求 R23）。
//
// 明确不适用：多实例共享（各实例各持一份内存，计数与封禁不互通）。
type MemoryStore struct {
	// name 是存储实例名（配置中的 stores[].name）。
	name string
	// prefix 是键前缀。
	prefix string
	// clock 是时间源，便于单元测试伪造时间。
	clock core.Clock
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口，用于记录存储错误。
	metrics core.MetricsRecorder

	// shards 是分片表；mask 用于按哈希取模（分片数取 2 的幂）。
	shards []*memoryShard
	mask   uint32

	// totalCounters / totalBans 是两张表的当前条目数（用于容量保护与统计）。
	totalCounters atomic.Int64
	totalBans     atomic.Int64

	// maxEntries 是单张表的条目上限。
	maxEntries int
	// cleanupInterval 是过期项清理周期。
	cleanupInterval time.Duration

	// stop 用于通知清理协程退出。
	stop chan struct{}
	// wg 等待清理协程结束。
	wg sync.WaitGroup
	// closeOnce 保证 Close 幂等。
	closeOnce sync.Once
	// closed 标记是否已关闭。
	closed atomic.Bool
}

// MemoryOptions 是内存存储的构造参数。
type MemoryOptions struct {
	// Name 是存储实例名。
	Name string
	// Prefix 是键前缀。
	Prefix string
	// Shards 是分片数；<=0 时取默认值，且向上取整为 2 的幂。
	Shards int
	// MaxEntries 是条目上限；<=0 时取默认值。
	MaxEntries int
	// CleanupInterval 是清理周期；<=0 时取默认值。
	CleanupInterval time.Duration
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
	// Logger 是系统日志器；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；可为 nil。
	Metrics core.MetricsRecorder
}

// NewMemoryStore 构造内存存储并启动过期项清理协程。
func NewMemoryStore(opts MemoryOptions) (*MemoryStore, error) {
	clock := opts.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}

	shardCount := normalizeShards(opts.Shards)
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	interval := opts.CleanupInterval
	if interval <= 0 {
		interval = defaultCleanupInterval
	}

	memoryStore := &MemoryStore{
		name:            opts.Name,
		prefix:          opts.Prefix,
		clock:           clock,
		logger:          opts.Logger,
		metrics:         metrics,
		shards:          make([]*memoryShard, shardCount),
		mask:            uint32(shardCount - 1),
		maxEntries:      maxEntries,
		cleanupInterval: interval,
		stop:            make(chan struct{}),
	}
	for index := range memoryStore.shards {
		memoryStore.shards[index] = &memoryShard{
			counters: make(map[string]*counterItem),
			bans:     make(map[string]*banItem),
		}
	}

	memoryStore.wg.Add(1)
	go memoryStore.cleanupLoop()
	return memoryStore, nil
}

// Name 返回存储实例名。
func (s *MemoryStore) Name() string { return s.name }

// Incr 在固定窗口内对 key 自增并返回计数与窗口剩余时间（core.Store 实现）。
func (s *MemoryStore) Incr(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if s.closed.Load() {
		return 0, 0, ErrStoreClosed
	}
	if window <= 0 {
		return 0, 0, fmt.Errorf("限速窗口必须大于 0，当前 %s", window)
	}

	now := s.clock.Now()
	fullKey := s.prefix + key
	shard := s.shardFor(fullKey)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	item, exists := shard.counters[fullKey]
	if exists && item.expireAt.After(now) {
		item.value++
		return item.value, item.expireAt.Sub(now), nil
	}

	// 新窗口（首次出现或上一窗口已过期）：重建计数项并设置窗口结束时间。
	// 之所以「仅在窗口建立时设置 TTL」：同一窗口内的后续自增不重置 TTL，
	// 从而形成固定窗口计数——这是多实例共享限速的基础语义。
	if !exists {
		if err := s.reserveCounter(); err != nil {
			return 0, 0, err
		}
	}
	shard.counters[fullKey] = &counterItem{value: 1, expireAt: now.Add(window)}
	return 1, window, nil
}

// Ban 把 key 加入封禁名单，已存在时强制覆盖（core.Store 实现）。
func (s *MemoryStore) Ban(_ context.Context, key string, ttl time.Duration, reason string) error {
	now := s.clock.Now()
	_, err := s.putBan(key, reason, now, expiryFrom(now, ttl), false)
	return err
}

// BanIfAbsent 仅在 key 不存在或已过期时写入封禁记录（core.Store 实现）。
func (s *MemoryStore) BanIfAbsent(_ context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	now := s.clock.Now()
	return s.putBan(key, reason, now, expiryFrom(now, ttl), true)
}

// putBan 是封禁写入的唯一内部入口，保证 TTL 与容量统计逻辑只有一份实现。
//
// onlyIfAbsent=true 时，若记录仍有效则不做任何修改并返回 created=false；
// 已过期记录会先移除再按新时间写入，因此「到期后再次封禁」仍能获得完整 TTL。
func (s *MemoryStore) putBan(key, reason string, bannedAt, expireAt time.Time, onlyIfAbsent bool) (bool, error) {
	if s.closed.Load() {
		return false, ErrStoreClosed
	}

	fullKey := s.prefix + key
	shard := s.shardFor(fullKey)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := s.clock.Now()
	existing, exists := shard.bans[fullKey]
	if exists {
		active := existing.expireAt.IsZero() || existing.expireAt.After(now)
		if onlyIfAbsent && active {
			return false, nil
		}
		if !active {
			delete(shard.bans, fullKey)
			s.totalBans.Add(-1)
			exists = false
		}
	}
	if !exists {
		if err := s.reserveBan(); err != nil {
			return false, err
		}
	}
	shard.bans[fullKey] = &banItem{reason: reason, bannedAt: bannedAt, expireAt: expireAt}
	return true, nil
}

// IsBanned 查询封禁状态与剩余时长（core.Store 实现）。
func (s *MemoryStore) IsBanned(_ context.Context, key string) (bool, time.Duration, error) {
	if s.closed.Load() {
		return false, 0, ErrStoreClosed
	}

	now := s.clock.Now()
	fullKey := s.prefix + key
	shard := s.shardFor(fullKey)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	item, exists := shard.bans[fullKey]
	if !exists {
		return false, 0, nil
	}
	if !item.expireAt.IsZero() && !item.expireAt.After(now) {
		delete(shard.bans, fullKey)
		s.totalBans.Add(-1)
		return false, 0, nil
	}
	return true, remainingFrom(now, item.expireAt), nil
}

// List 列出当前封禁名单（core.Store 实现）。
func (s *MemoryStore) List(_ context.Context) ([]core.BanEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	now := s.clock.Now()
	entries := make([]core.BanEntry, 0, s.totalBans.Load())

	for _, shard := range s.shards {
		shard.mu.Lock()
		for fullKey, item := range shard.bans {
			if !item.expireAt.IsZero() && !item.expireAt.After(now) {
				delete(shard.bans, fullKey)
				s.totalBans.Add(-1)
				continue
			}
			entries = append(entries, core.BanEntry{
				Key:      trimPrefix(fullKey, s.prefix),
				Reason:   item.reason,
				TTL:      remainingFrom(now, item.expireAt),
				BannedAt: item.bannedAt,
				ExpireAt: item.expireAt,
			})
		}
		shard.mu.Unlock()
	}

	// 排序保证输出稳定：多分片遍历顺序不确定，运维对比两次输出时需要可读的顺序。
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

// Unban 解除封禁（core.Store 实现）。
func (s *MemoryStore) Unban(_ context.Context, key string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	fullKey := s.prefix + key
	shard := s.shardFor(fullKey)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if _, exists := shard.bans[fullKey]; exists {
		delete(shard.bans, fullKey)
		s.totalBans.Add(-1)
	}
	return nil
}

// Close 停止清理协程并释放内存；必须幂等。
func (s *MemoryStore) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.stop)
		s.wg.Wait()
	})
	return nil
}

// Stats 返回内存存储的规模统计，供启动日志与排障使用。
func (s *MemoryStore) Stats() (counters int64, bans int64) {
	return s.totalCounters.Load(), s.totalBans.Load()
}

// snapshotBans 返回当前有效封禁记录的副本（逻辑键 -> 记录），并顺带清理过期项。
//
// 之所以提供该内部方法：file 后端在压缩重写时需要「仍然有效的名单 + 精确到期时间」，
// 而复用 List 只能拿到剩余时长，无法重建出与原记录一致的到期时间。
func (s *MemoryStore) snapshotBans(now time.Time) map[string]banItem {
	snapshot := make(map[string]banItem, s.totalBans.Load())
	for _, shard := range s.shards {
		shard.mu.Lock()
		for fullKey, item := range shard.bans {
			if !item.expireAt.IsZero() && !item.expireAt.After(now) {
				delete(shard.bans, fullKey)
				s.totalBans.Add(-1)
				continue
			}
			snapshot[trimPrefix(fullKey, s.prefix)] = *item
		}
		shard.mu.Unlock()
	}
	return snapshot
}

// shardFor 按 FNV-1a 哈希把键映射到分片。
func (s *MemoryStore) shardFor(key string) *memoryShard {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return s.shards[hash.Sum32()&s.mask]
}

// reserveCounter 预留一个计数条目位置，超出上限时返回错误。
//
// 之所以返回错误而不是静默丢弃：容量耗尽说明键空间异常膨胀（可能是攻击行为），
// 此时让调用方按 on_error 处理，比悄悄停止限速安全得多。
func (s *MemoryStore) reserveCounter() error {
	if s.maxEntries <= 0 {
		return nil
	}
	if int(s.totalCounters.Load()) >= s.maxEntries {
		s.metrics.IncStoreError(s.name)
		return fmt.Errorf("%w：限速计数条目已达上限 %d", ErrCapacityExceeded, s.maxEntries)
	}
	s.totalCounters.Add(1)
	return nil
}

// reserveBan 预留一个封禁条目位置，超出上限时返回错误。
func (s *MemoryStore) reserveBan() error {
	if s.maxEntries <= 0 {
		return nil
	}
	if int(s.totalBans.Load()) >= s.maxEntries {
		s.metrics.IncStoreError(s.name)
		return fmt.Errorf("%w：封禁名单条目已达上限 %d", ErrCapacityExceeded, s.maxEntries)
	}
	s.totalBans.Add(1)
	return nil
}

// cleanupLoop 周期性清理过期条目，避免内存随「一次性」键持续增长。
func (s *MemoryStore) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.purgeExpired()
		}
	}
}

// purgeExpired 清理两张表中的过期条目。
func (s *MemoryStore) purgeExpired() {
	now := s.clock.Now()
	var removedCounters, removedBans int64

	for _, shard := range s.shards {
		shard.mu.Lock()
		for key, item := range shard.counters {
			if !item.expireAt.After(now) {
				delete(shard.counters, key)
				removedCounters++
			}
		}
		for key, item := range shard.bans {
			if !item.expireAt.IsZero() && !item.expireAt.After(now) {
				delete(shard.bans, key)
				removedBans++
			}
		}
		shard.mu.Unlock()
	}

	if removedCounters > 0 {
		s.totalCounters.Add(-removedCounters)
	}
	if removedBans > 0 {
		s.totalBans.Add(-removedBans)
	}
	if (removedCounters > 0 || removedBans > 0) && s.logger != nil {
		s.logger.Debug("清理过期存储条目",
			"store", s.name, "counters", removedCounters, "bans", removedBans)
	}
}

// normalizeShards 把分片数归一化为 2 的幂，便于用位与运算取模。
func normalizeShards(shards int) int {
	if shards <= 0 {
		shards = defaultMemoryShards
	}
	value := 1
	for value < shards {
		value <<= 1
	}
	return value
}

// expiryFrom 依据 TTL 计算到期时间；ttl <= 0 表示永不过期（返回零值）。
func expiryFrom(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

// remainingFrom 计算剩余时长；永不过期时返回 0。
func remainingFrom(now, expireAt time.Time) time.Duration {
	if expireAt.IsZero() {
		return 0
	}
	remaining := expireAt.Sub(now)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// trimPrefix 去掉键前缀，返回逻辑键（供 List 输出）。
func trimPrefix(key, prefix string) string {
	if prefix == "" || len(key) < len(prefix) {
		return key
	}
	return key[len(prefix):]
}
