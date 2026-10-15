package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// fakeClock 是可手动推进的时钟。
//
// 之所以必须可推进：固定窗口过期、封禁 TTL 到期、文件回放过滤过期记录
// 这三类行为都依赖时间流逝，用真实时间测试会既慢又不稳定。
type fakeClock struct {
	// mu 保护 now。
	mu sync.Mutex
	// now 是当前时间。
	now time.Time
}

// newFakeClock 构造起始时间固定的时钟。
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now 返回当前时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Since 返回自 t 起经过的时长。
func (c *fakeClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

// Advance 推进时钟。
func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

// newMemoryStore 构造一个用于测试的内存存储。
func newMemoryStore(t *testing.T, clock core.Clock, maxEntries int) *MemoryStore {
	t.Helper()
	built, err := NewMemoryStore(MemoryOptions{
		Name:            "default",
		Prefix:          "test:",
		MaxEntries:      maxEntries,
		Clock:           clock,
		Metrics:         core.NoopMetrics{},
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("构造内存存储失败：%v", err)
	}
	t.Cleanup(func() { _ = built.Close() })
	return built
}

// TestMemoryStoreIncrFixedWindow 覆盖：同一窗口内累加、窗口过期后重新计数。
func TestMemoryStoreIncrFixedWindow(t *testing.T) {
	clock := newFakeClock()
	memoryStore := newMemoryStore(t, clock, 0)
	ctx := context.Background()

	for index := 1; index <= 3; index++ {
		count, ttl, err := memoryStore.Incr(ctx, "rl:ip:1.2.3.4", time.Minute)
		if err != nil {
			t.Fatalf("第 %d 次计数失败：%v", index, err)
		}
		if count != int64(index) {
			t.Fatalf("第 %d 次计数期望 %d，实际 %d", index, index, count)
		}
		if ttl <= 0 || ttl > time.Minute {
			t.Fatalf("窗口剩余时间应在 (0, 1m] 区间，实际 %s", ttl)
		}
	}

	// 窗口内推进不会重置 TTL，也不会清零计数。
	clock.Advance(30 * time.Second)
	if count, _, err := memoryStore.Incr(ctx, "rl:ip:1.2.3.4", time.Minute); err != nil || count != 4 {
		t.Fatalf("窗口内计数应累加到 4，实际 count=%d err=%v", count, err)
	}

	// 越过窗口边界后重新从 1 开始。
	clock.Advance(31 * time.Second)
	if count, _, err := memoryStore.Incr(ctx, "rl:ip:1.2.3.4", time.Minute); err != nil || count != 1 {
		t.Fatalf("新窗口计数应从 1 开始，实际 count=%d err=%v", count, err)
	}
}

// TestMemoryStoreIncrRejectsInvalidWindow 覆盖：非法窗口直接报错。
func TestMemoryStoreIncrRejectsInvalidWindow(t *testing.T) {
	memoryStore := newMemoryStore(t, newFakeClock(), 0)
	if _, _, err := memoryStore.Incr(context.Background(), "k", 0); err == nil {
		t.Fatal("窗口为 0 时应报错")
	}
}

// TestMemoryStoreBanLifecycle 覆盖：封禁、查询、到期自动失效、解封。
func TestMemoryStoreBanLifecycle(t *testing.T) {
	clock := newFakeClock()
	memoryStore := newMemoryStore(t, clock, 0)
	ctx := context.Background()

	if err := memoryStore.Ban(ctx, "ip:1.2.3.4", 30*time.Minute, "暴力破解"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}

	banned, remaining, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if err != nil || !banned {
		t.Fatalf("刚封禁的来源应处于封禁状态，实际 banned=%v err=%v", banned, err)
	}
	if remaining <= 0 || remaining > 30*time.Minute {
		t.Fatalf("剩余时长应在 (0, 30m] 区间，实际 %s", remaining)
	}

	entries, err := memoryStore.List(ctx)
	if err != nil {
		t.Fatalf("读取名单失败：%v", err)
	}
	if len(entries) != 1 || entries[0].Key != "ip:1.2.3.4" || entries[0].Reason != "暴力破解" {
		t.Fatalf("名单内容不符：%+v", entries)
	}

	// TTL 到期后自动失效，无需额外的解封任务。
	clock.Advance(31 * time.Minute)
	if banned, _, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4"); err != nil || banned {
		t.Fatalf("TTL 到期后应自动失效，实际 banned=%v err=%v", banned, err)
	}

	// 解封路径。
	if err := memoryStore.Ban(ctx, "ip:5.6.7.8", time.Hour, "手工封禁"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := memoryStore.Unban(ctx, "ip:5.6.7.8"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if banned, _, _ := memoryStore.IsBanned(ctx, "ip:5.6.7.8"); banned {
		t.Fatal("解封后不应仍处于封禁状态")
	}
}

// TestMemoryStoreCapacityProtection 覆盖：条目达到上限时返回容量错误而不是静默丢弃。
func TestMemoryStoreCapacityProtection(t *testing.T) {
	memoryStore := newMemoryStore(t, newFakeClock(), 2)
	ctx := context.Background()

	if err := memoryStore.Ban(ctx, "ip:1.1.1.1", time.Minute, ""); err != nil {
		t.Fatalf("第 1 条封禁失败：%v", err)
	}
	if err := memoryStore.Ban(ctx, "ip:2.2.2.2", time.Minute, ""); err != nil {
		t.Fatalf("第 2 条封禁失败：%v", err)
	}
	err := memoryStore.Ban(ctx, "ip:3.3.3.3", time.Minute, "")
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("超出容量应返回 ErrCapacityExceeded，实际 %v", err)
	}
}

// TestMemoryStoreClosed 覆盖：关闭后所有操作返回 ErrStoreClosed。
func TestMemoryStoreClosed(t *testing.T) {
	memoryStore := newMemoryStore(t, newFakeClock(), 0)
	if err := memoryStore.Close(); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}
	if err := memoryStore.Close(); err != nil {
		t.Fatalf("重复关闭必须幂等，实际 %v", err)
	}

	ctx := context.Background()
	if _, _, err := memoryStore.Incr(ctx, "k", time.Minute); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("关闭后 Incr 应返回 ErrStoreClosed，实际 %v", err)
	}
	if err := memoryStore.Ban(ctx, "k", time.Minute, ""); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("关闭后 Ban 应返回 ErrStoreClosed，实际 %v", err)
	}
}

// TestFileStoreReplayAndUnban 覆盖：封禁落盘后重启可回放，解封同样持久化。
func TestFileStoreReplayAndUnban(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf-ban.jsonl")
	clock := newFakeClock()
	ctx := context.Background()

	first, err := NewFileStore(FileStoreOptions{Name: "default", Prefix: "test:", Path: path, Clock: clock})
	if err != nil {
		t.Fatalf("构造文件存储失败：%v", err)
	}
	if err := first.Ban(ctx, "ip:1.2.3.4", 30*time.Minute, "暴力破解"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := first.Ban(ctx, "ip:9.9.9.9", 30*time.Minute, "临时封禁"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if err := first.Unban(ctx, "ip:9.9.9.9"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}

	second, err := NewFileStore(FileStoreOptions{Name: "default", Prefix: "test:", Path: path, Clock: clock})
	if err != nil {
		t.Fatalf("重新构造文件存储失败：%v", err)
	}
	defer func() { _ = second.Close() }()

	if banned, _, err := second.IsBanned(ctx, "ip:1.2.3.4"); err != nil || !banned {
		t.Fatalf("回放后应恢复封禁状态，实际 banned=%v err=%v", banned, err)
	}
	if banned, _, _ := second.IsBanned(ctx, "ip:9.9.9.9"); banned {
		t.Fatal("回放后不应恢复已解除的封禁")
	}

	entries, err := second.List(ctx)
	if err != nil {
		t.Fatalf("读取名单失败：%v", err)
	}
	if len(entries) != 1 || entries[0].Reason != "暴力破解" {
		t.Fatalf("回放后的名单不符：%+v", entries)
	}

	// 过期的历史记录不应在回放时被恢复。
	clock.Advance(31 * time.Minute)
	third, err := NewFileStore(FileStoreOptions{Name: "default", Prefix: "test:", Path: path, Clock: clock})
	if err != nil {
		t.Fatalf("第三次构造文件存储失败：%v", err)
	}
	defer func() { _ = third.Close() }()
	if banned, _, _ := third.IsBanned(ctx, "ip:1.2.3.4"); banned {
		t.Fatal("已过期的封禁记录不应在回放时恢复")
	}
}

// TestFileStoreRequiresPath 覆盖：缺少持久化路径时构造失败。
func TestFileStoreRequiresPath(t *testing.T) {
	if _, err := NewFileStore(FileStoreOptions{Name: "default"}); err == nil {
		t.Fatal("缺少 settings.path 时应构造失败")
	}
}

// TestBuildDisabledUsesLocalFallback 覆盖：stores[].enabled=false 时直接使用本地实现。
func TestBuildDisabledUsesLocalFallback(t *testing.T) {
	resolver, err := Build(Options{Configs: []config.StoreConfig{{
		Name:     "default",
		Type:     TypeRedis,
		Enabled:  false,
		Fallback: TypeMemory,
		Settings: map[string]any{"prefix": "test:", "shards": 4},
	}}})
	if err != nil {
		t.Fatalf("构建存储失败：%v", err)
	}
	defer func() { _ = resolver.Close() }()

	resolved, err := resolver.Default()
	if err != nil {
		t.Fatalf("解析默认存储失败：%v", err)
	}
	if _, ok := resolved.(*MemoryStore); !ok {
		t.Fatalf("未启用共享后端时应使用本地内存实现，实际 %T", resolved)
	}

	count, _, err := resolved.Incr(context.Background(), "k", time.Minute)
	if err != nil || count != 1 {
		t.Fatalf("本地实现应可用，实际 count=%d err=%v", count, err)
	}
}

// TestBuildFileStore 覆盖：file 后端可通过配置构建。
func TestBuildFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ban.jsonl")
	resolver, err := Build(Options{Configs: []config.StoreConfig{{
		Name:    "shared",
		Type:    TypeFile,
		Enabled: true,
		Settings: map[string]any{
			"prefix":         "test:",
			"path":           path,
			"max_file_bytes": 1048576,
		},
	}}})
	if err != nil {
		t.Fatalf("构建文件存储失败：%v", err)
	}
	defer func() { _ = resolver.Close() }()

	resolved, err := resolver.Resolve("shared")
	if err != nil {
		t.Fatalf("解析存储失败：%v", err)
	}
	if err := resolved.Ban(context.Background(), "ip:1.1.1.1", time.Minute, "测试"); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
}

// TestBuildUnknownTopologyFails 覆盖：非法的 Redis 拓扑必须在构建阶段失败。
func TestBuildUnknownTopologyFails(t *testing.T) {
	_, err := Build(Options{Configs: []config.StoreConfig{{
		Name:    "default",
		Type:    TypeRedis,
		Enabled: true,
		Settings: map[string]any{
			"topology": "replica-set",
			"addrs":    []any{"127.0.0.1:6379"},
		},
	}}})
	if err == nil {
		t.Fatal("非法拓扑应在构建阶段直接失败")
	}
}

// TestBuildDuplicateNamesFails 覆盖：存储实例名必须唯一。
func TestBuildDuplicateNamesFails(t *testing.T) {
	_, err := Build(Options{Configs: []config.StoreConfig{
		{Name: "default", Type: TypeMemory, Enabled: true},
		{Name: "default", Type: TypeMemory, Enabled: true},
	}})
	if err == nil {
		t.Fatal("重复的存储实例名应在构建阶段直接失败")
	}
}

// TestFallbackStoreDegradesToLocal 覆盖：Redis 不可用时按 on_error=fallback_local 降级。
//
// 之所以用 127.0.0.1:1 作为目标：该端口几乎不可能有服务监听，
// 连接会被立即拒绝（不需要等待超时），从而稳定复现「后端不可用」。
func TestFallbackStoreDegradesToLocal(t *testing.T) {
	resolver, err := Build(Options{Configs: []config.StoreConfig{{
		Name:     "default",
		Type:     TypeRedis,
		Enabled:  true,
		Fallback: TypeMemory,
		OnError:  config.StoreOnErrorFallbackLocal,
		Settings: map[string]any{
			"topology":        "standalone",
			"addrs":           []any{"127.0.0.1:1"},
			"prefix":          "test:",
			"dial_timeout":    "200ms",
			"read_timeout":    "200ms",
			"write_timeout":   "200ms",
			"max_retries":     0,
			"local_cache_ttl": "0s",
		},
	}}})
	if err != nil {
		t.Fatalf("构建存储失败：%v", err)
	}
	defer func() { _ = resolver.Close() }()

	resolved, err := resolver.Default()
	if err != nil {
		t.Fatalf("解析默认存储失败：%v", err)
	}

	ctx := context.Background()
	count, _, err := resolved.Incr(ctx, "rl:ip:1.2.3.4", time.Minute)
	if err != nil {
		t.Fatalf("降级路径不应向上返回错误，实际 %v", err)
	}
	if count != 1 {
		t.Fatalf("降级后应由本地实现计数，实际 count=%d", count)
	}

	if err := resolved.Ban(ctx, "ip:1.2.3.4", time.Minute, "降级封禁"); err != nil {
		t.Fatalf("降级路径的封禁应写入本地名单，实际 %v", err)
	}
	banned, _, err := resolved.IsBanned(ctx, "ip:1.2.3.4")
	if err != nil || !banned {
		t.Fatalf("降级后应能从本地名单查到封禁，实际 banned=%v err=%v", banned, err)
	}
}

// TestResolverNamesAreSorted 覆盖：存储实例名按字典序返回，便于日志与 CLI 输出稳定。
func TestResolverNamesAreSorted(t *testing.T) {
	resolver, err := Build(Options{Configs: []config.StoreConfig{
		{Name: "zulu", Type: TypeMemory, Enabled: true},
		{Name: "alpha", Type: TypeMemory, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("构建存储失败：%v", err)
	}
	defer func() { _ = resolver.Close() }()

	names := resolver.Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "zulu" {
		t.Fatalf("实例名应按字典序排列，实际 %v", names)
	}

	// 多个实例且无 default 时，Default() 必须报错而不是随意挑一个。
	if _, err := resolver.Default(); err == nil {
		t.Fatal("存在多个实例且无 default 时 Default() 应报错")
	}
}
