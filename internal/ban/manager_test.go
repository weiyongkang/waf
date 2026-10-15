package ban

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/store"
)

// fakeClock 是可手动推进的时钟，用于让封禁剩余时长可精确断言。
type fakeClock struct {
	// mu 保护 now。
	mu sync.Mutex
	// now 是当前时间。
	now time.Time
}

// Now 返回当前时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Since 返回自 t 起经过的时长。
func (c *fakeClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

// testResolver 是只承载测试存储实例的解析器。
type testResolver struct {
	// stores 是实例名到存储的映射。
	stores map[string]core.Store
}

// Resolve 返回指定名称的存储。
func (r *testResolver) Resolve(name string) (core.Store, error) {
	if item, exists := r.stores[name]; exists {
		return item, nil
	}
	return nil, fmt.Errorf("未找到存储实例 %q", name)
}

// Default 返回名为 default 的存储。
func (r *testResolver) Default() (core.Store, error) {
	if item, exists := r.stores["default"]; exists {
		return item, nil
	}
	return nil, errors.New("未配置默认存储")
}

// Names 返回实例名（按字典序）。
func (r *testResolver) Names() []string {
	names := make([]string, 0, len(r.stores))
	for name := range r.stores {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// newTestManager 构造注入本地内存存储的封禁管理器。
func newTestManager(t *testing.T, cfg config.BanConfig) (*Manager, core.Store) {
	t.Helper()

	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	memoryStore, err := store.NewMemoryStore(store.MemoryOptions{
		Name:            "default",
		Prefix:          "test:",
		Clock:           clock,
		Metrics:         core.NoopMetrics{},
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("构造内存存储失败：%v", err)
	}
	t.Cleanup(func() { _ = memoryStore.Close() })

	manager, err := New(Options{
		Config:  cfg,
		Stores:  &testResolver{stores: map[string]core.Store{"default": memoryStore}},
		Metrics: core.NoopMetrics{},
	})
	if err != nil {
		t.Fatalf("构造封禁管理器失败：%v", err)
	}
	return manager, memoryStore
}

// defaultBanConfig 返回测试基线配置。
func defaultBanConfig() config.BanConfig {
	return config.BanConfig{
		DefaultTTL:     core.Duration(30 * time.Minute),
		MaxTTL:         core.Duration(24 * time.Hour),
		BanKey:         config.BanKeyClientIP,
		EscalateWindow: core.Duration(24 * time.Hour),
	}
}

// newRequestContext 构造带客户端 IP 的请求上下文。
func newRequestContext(clientIP string) *core.RequestContext {
	rctx := core.NewRequestContext("req-ban", time.Now())
	rctx.Raw.Header = http.Header{}
	rctx.Raw.ClientIP = clientIP
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	return rctx
}

// TestKeyForClientIP 覆盖：两种封禁键维度的键构造。
func TestKeyForClientIP(t *testing.T) {
	cfg := defaultBanConfig()
	manager, _ := newTestManager(t, cfg)

	if got := manager.KeyForClientIP("1.2.3.4", "shop"); got != "ip:1.2.3.4" {
		t.Fatalf("client_ip 维度应只含 IP，实际 %q", got)
	}

	cfg.BanKey = config.BanKeyClientIPSite
	siteManager, _ := newTestManager(t, cfg)

	if got := siteManager.KeyForClientIP("1.2.3.4", "shop"); got != "ip:1.2.3.4|site:shop" {
		t.Fatalf("client_ip+site 维度的键不符，实际 %q", got)
	}
	// 站点名为空时回落到默认站点，避免出现「键里站点段为空」的歧义键。
	if got := siteManager.KeyForClientIP("1.2.3.4", ""); got != "ip:1.2.3.4|site:default" {
		t.Fatalf("站点名为空时应回落到默认站点，实际 %q", got)
	}
	if got := siteManager.KeyForClientIP("  ", "shop"); got != "" {
		t.Fatalf("IP 为空时应返回空键，实际 %q", got)
	}
}

// TestKeyForUsesRequestContext 覆盖：从请求上下文推导封禁键，与 banlist 查询键一致。
func TestKeyForUsesRequestContext(t *testing.T) {
	manager, _ := newTestManager(t, defaultBanConfig())

	if got := manager.KeyFor(newRequestContext("1.2.3.4")); got != "ip:1.2.3.4" {
		t.Fatalf("应推导出 ip:1.2.3.4，实际 %q", got)
	}
	if got := manager.KeyFor(newRequestContext("")); got != "" {
		t.Fatalf("无客户端 IP 时应返回空键，实际 %q", got)
	}
	if got := manager.KeyFor(nil); got != "" {
		t.Fatalf("空上下文应返回空键，实际 %q", got)
	}
}

// TestAddClampsTTL 覆盖：手工封禁的时长受 ban.max_ttl 约束，缺省使用 default_ttl。
func TestAddClampsTTL(t *testing.T) {
	manager, _ := newTestManager(t, defaultBanConfig())
	ctx := context.Background()

	key, applied, err := manager.Add(ctx, "1.2.3.4", "", 48*time.Hour, "")
	if err != nil {
		t.Fatalf("手工封禁失败：%v", err)
	}
	if key != "ip:1.2.3.4" {
		t.Fatalf("键不符，实际 %q", key)
	}
	if applied != 24*time.Hour {
		t.Fatalf("超长时长应被裁剪到 max_ttl=24h，实际 %s", applied)
	}

	_, applied, err = manager.Add(ctx, "5.6.7.8", "", 0, "暴力破解")
	if err != nil {
		t.Fatalf("手工封禁失败：%v", err)
	}
	if applied != 30*time.Minute {
		t.Fatalf("未指定时长时应使用 default_ttl=30m，实际 %s", applied)
	}
}

// TestBanAppliesDefaultTTL 覆盖：未指定时长时按 default_ttl 落地。
func TestBanAppliesDefaultTTL(t *testing.T) {
	manager, memoryStore := newTestManager(t, defaultBanConfig())
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	err := manager.Ban(ctx, rctx, []core.BanRequest{{Reason: "测试封禁", RuleID: "test"}})
	if err != nil {
		t.Fatalf("封禁失败：%v", err)
	}

	banned, remaining, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if err != nil || !banned {
		t.Fatalf("应处于封禁状态，实际 banned=%v err=%v", banned, err)
	}
	if remaining != 30*time.Minute {
		t.Fatalf("剩余时长应为 default_ttl=30m，实际 %s", remaining)
	}
}

// TestBanEscalation 覆盖：启用累进封禁后，同一来源的封禁时长按时长阶梯递增。
func TestBanEscalation(t *testing.T) {
	cfg := defaultBanConfig()
	cfg.Escalate = true
	cfg.EscalateSteps = []core.Duration{
		core.Duration(30 * time.Minute),
		core.Duration(2 * time.Hour),
		core.Duration(24 * time.Hour),
	}

	manager, memoryStore := newTestManager(t, cfg)
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	want := []time.Duration{30 * time.Minute, 2 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for index, expected := range want {
		if err := manager.Ban(ctx, rctx, []core.BanRequest{{
			Reason: "累进封禁测试", RuleID: "test",
		}}); err != nil {
			t.Fatalf("第 %d 次封禁失败：%v", index+1, err)
		}
		_, remaining, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
		if err != nil {
			t.Fatalf("第 %d 次查询失败：%v", index+1, err)
		}
		if remaining != expected {
			t.Fatalf("第 %d 次封禁时长期望 %s，实际 %s", index+1, expected, remaining)
		}
	}
}

// TestBanEscalationDisabled 覆盖：未启用累进时始终使用 default_ttl。
func TestBanEscalationDisabled(t *testing.T) {
	manager, memoryStore := newTestManager(t, defaultBanConfig())
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	for index := 0; index < 3; index++ {
		if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
			t.Fatalf("第 %d 次封禁失败：%v", index+1, err)
		}
	}
	_, remaining, _ := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if remaining != 30*time.Minute {
		t.Fatalf("未启用累进时剩余时长应恒为 30m，实际 %s", remaining)
	}
}

// TestBanPartialFailureDoesNotBlockOthers 覆盖：单条封禁失败不影响其余动作。
func TestBanPartialFailureDoesNotBlockOthers(t *testing.T) {
	manager, memoryStore := newTestManager(t, defaultBanConfig())
	ctx := context.Background()

	// 第一条：显式键，能够落地；第二条：既无显式键、上下文也无客户端 IP，必然失败。
	rctxWithoutIP := newRequestContext("")
	requests := []core.BanRequest{
		{Key: "ip:9.9.9.9", Reason: "显式键", RuleID: "test"},
		{Reason: "无法推导键", RuleID: "test"},
	}

	err := manager.Ban(ctx, rctxWithoutIP, requests)
	if err == nil {
		t.Fatal("存在失败项时应返回错误供日志与指标记录")
	}

	banned, _, err := memoryStore.IsBanned(ctx, "ip:9.9.9.9")
	if err != nil || !banned {
		t.Fatalf("失败项不应影响成功项落地，实际 banned=%v err=%v", banned, err)
	}
}

// TestBanEmptyRequests 覆盖：空动作列表直接返回成功。
func TestBanEmptyRequests(t *testing.T) {
	manager, _ := newTestManager(t, defaultBanConfig())
	if err := manager.Ban(context.Background(), newRequestContext("1.2.3.4"), nil); err != nil {
		t.Fatalf("空动作列表应返回成功，实际 %v", err)
	}
}

// TestCheckMatchesWrittenKey 覆盖：写入的键与查询的键完全一致（封禁真正生效）。
func TestCheckMatchesWrittenKey(t *testing.T) {
	manager, _ := newTestManager(t, defaultBanConfig())
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	if banned, _, _, _, err := manager.CheckScopes(ctx, rctx); err != nil || banned {
		t.Fatalf("封禁前应为未封禁，实际 banned=%v err=%v", banned, err)
	}

	if err := manager.Ban(ctx, rctx, []core.BanRequest{{Reason: "测试", RuleID: "test"}}); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}

	banned, remaining, key, _, err := manager.CheckScopes(ctx, rctx)
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if !banned || key != "ip:1.2.3.4" {
		t.Fatalf("封禁后应命中同一键，实际 banned=%v key=%q", banned, key)
	}
	if remaining != 30*time.Minute {
		t.Fatalf("剩余时长应为 30m，实际 %s", remaining)
	}
}

// TestListAndUnban 覆盖：名单查询与解封（CLI 使用的路径）。
func TestListAndUnban(t *testing.T) {
	manager, _ := newTestManager(t, defaultBanConfig())
	ctx := context.Background()

	if _, _, err := manager.Add(ctx, "1.2.3.4", "", time.Hour, "手工封禁"); err != nil {
		t.Fatalf("手工封禁失败：%v", err)
	}

	entries, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("读取名单失败：%v", err)
	}
	if len(entries) != 1 || entries[0].Key != "ip:1.2.3.4" || entries[0].Reason != "手工封禁" {
		t.Fatalf("名单内容不符：%+v", entries)
	}

	if err := manager.Unban(ctx, "ip:1.2.3.4"); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	entries, err = manager.List(ctx)
	if err != nil {
		t.Fatalf("读取名单失败：%v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("解封后名单应为空，实际 %+v", entries)
	}
}

// TestNewValidation 覆盖：非法配置与缺失依赖在构造阶段直接失败。
func TestNewValidation(t *testing.T) {
	base := defaultBanConfig()

	tooLong := base
	tooLong.MaxTTL = core.Duration(5 * time.Minute)
	if _, err := New(Options{Config: tooLong, Stores: &testResolver{stores: map[string]core.Store{}}}); err == nil {
		t.Fatal("max_ttl 小于 default_ttl 时应构造失败")
	}

	badKey := base
	badKey.BanKey = "client_ip+ua"
	if _, err := New(Options{Config: badKey, Stores: &testResolver{stores: map[string]core.Store{}}}); err == nil {
		t.Fatal("非法 ban_key 应构造失败")
	}

	if _, err := New(Options{Config: base}); err == nil {
		t.Fatal("未注入存储解析器时应构造失败")
	}
}

// TestNewAppliesFallbackDefaults 覆盖：零值配置由实现补齐为既定默认值。
func TestNewAppliesFallbackDefaults(t *testing.T) {
	manager, err := New(Options{
		Config: config.BanConfig{},
		Stores: &testResolver{stores: map[string]core.Store{}},
	})
	if err != nil {
		t.Fatalf("零值配置应可构造，实际 %v", err)
	}
	if manager.DefaultTTL() != 30*time.Minute {
		t.Fatalf("默认封禁时长应为 30m，实际 %s", manager.DefaultTTL())
	}
	if manager.MaxTTL() != 24*time.Hour {
		t.Fatalf("封禁时长上限应为 24h，实际 %s", manager.MaxTTL())
	}
}
