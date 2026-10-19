package ban

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
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

// Advance 推进时钟。
func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

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
	manager, memoryStore, _ := newTestManagerWithClock(t, cfg)
	return manager, memoryStore
}

// newTestManagerWithClock 构造封禁管理器并返回可手动推进的时钟。
func newTestManagerWithClock(t *testing.T, cfg config.BanConfig) (*Manager, core.Store, *fakeClock) {
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
	return manager, memoryStore, clock
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

// detailRecordingStore 记录 BanDetail，用于验证管理器传递完整请求上下文。
type detailRecordingStore struct {
	core.Store
	mu     sync.Mutex
	detail core.BanDetail
	called bool
}

func (s *detailRecordingStore) BanWithDetail(_ context.Context, _ string, _ time.Duration,
	_ string, detail core.BanDetail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.detail = detail
	s.called = true
	return nil
}

func (s *detailRecordingStore) BanIfAbsentWithDetail(_ context.Context, _ string, _ time.Duration,
	_ string, detail core.BanDetail) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.detail = detail
	s.called = true
	return true, nil
}

// TestManagerPassesBanDetail 覆盖：自动封禁写入存储时携带规则、目标、URI 与脱敏参数。
func TestManagerPassesBanDetail(t *testing.T) {
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

	recording := &detailRecordingStore{Store: memoryStore}
	manager, err := New(Options{
		Config:  defaultBanConfig(),
		Stores:  &testResolver{stores: map[string]core.Store{"default": recording}},
		Metrics: core.NoopMetrics{},
	})
	if err != nil {
		t.Fatalf("构造封禁管理器失败：%v", err)
	}

	rctx := newRequestContext("203.0.113.30")
	rctx.Raw.URI = "/login?username=alice&password=secret"
	rctx.Raw.Path = "/login"
	rctx.Raw.RawQuery = "username=alice&password=secret"
	err = manager.Ban(context.Background(), rctx, []core.BanRequest{{
		Key:    "ip:203.0.113.30",
		Scope:  config.BanKeyClientIP,
		RuleID: "internal_banlist",
		Check:  "banlist",
		Target: "client_ip",
		Reason: "测试封禁",
	}})
	if err != nil {
		t.Fatalf("落地封禁失败：%v", err)
	}

	recording.mu.Lock()
	defer recording.mu.Unlock()
	if !recording.called {
		t.Fatal("存储未收到结构化封禁详情")
	}
	if recording.detail.RuleID != "internal_banlist" || recording.detail.Check != "banlist" {
		t.Fatalf("规则上下文不符：%+v", recording.detail)
	}
	if recording.detail.Target != "client_ip" || recording.detail.Scope != config.BanKeyClientIP {
		t.Fatalf("目标 / 维度不符：%+v", recording.detail)
	}
	if recording.detail.URI != rctx.Raw.URI || recording.detail.Query != rctx.Raw.RawQuery {
		t.Fatalf("URI / 查询串不符：%+v", recording.detail)
	}
	if !strings.Contains(recording.detail.ParamsJSON, "[REDACTED]") ||
		strings.Contains(recording.detail.ParamsJSON, "secret") {
		t.Fatalf("参数快照未正确脱敏：%s", recording.detail.ParamsJSON)
	}
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
	// 累进封禁的阶梯体现在「重新封禁时的 TTL」上；默认不续期时第二次封禁
	// 会保持首次到期时间（见 TestBanRepeatKeepsOriginalExpiry），因此这里显式
	// 打开续期，以覆盖累进阶梯本身的语义。
	cfg.RenewOnRepeat = true
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

// TestBanRepeatKeepsOriginalExpiry 覆盖：重复命中不刷新首次封禁的到期时间。
func TestBanRepeatKeepsOriginalExpiry(t *testing.T) {
	manager, memoryStore, clock := newTestManagerWithClock(t, defaultBanConfig())
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
		t.Fatalf("首次封禁失败：%v", err)
	}
	firstEntries, err := memoryStore.List(ctx)
	if err != nil || len(firstEntries) != 1 {
		t.Fatalf("首次封禁后名单不符：entries=%+v err=%v", firstEntries, err)
	}
	originalExpireAt := firstEntries[0].ExpireAt
	originalBannedAt := firstEntries[0].BannedAt

	// 攻击者在封禁有效期内继续请求：不能续期，否则持续攻击会让封禁永不解除。
	clock.Advance(10 * time.Minute)
	if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
		t.Fatalf("重复封禁失败：%v", err)
	}

	banned, remaining, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if err != nil || !banned {
		t.Fatalf("重复封禁后仍应处于封禁状态，实际 banned=%v err=%v", banned, err)
	}
	if remaining != 20*time.Minute {
		t.Fatalf("重复封禁不应刷新 TTL，剩余时长期望 20m，实际 %s", remaining)
	}
	entries, err := memoryStore.List(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("重复封禁后名单不应新增记录：entries=%+v err=%v", entries, err)
	}
	if !entries[0].ExpireAt.Equal(originalExpireAt) || !entries[0].BannedAt.Equal(originalBannedAt) {
		t.Fatalf("重复封禁改写了首次封禁时间：before=(%s,%s) after=(%s,%s)",
			originalBannedAt, originalExpireAt, entries[0].BannedAt, entries[0].ExpireAt)
	}

	// 到期后再次封禁：这是一次全新的封禁，应从当前时刻重新计算完整 TTL。
	clock.Advance(21 * time.Minute)
	if banned, _, _ := memoryStore.IsBanned(ctx, "ip:1.2.3.4"); banned {
		t.Fatal("到期后应自动解除封禁")
	}
	if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
		t.Fatalf("到期后重新封禁失败：%v", err)
	}
	_, remaining, _ = memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if remaining != 30*time.Minute {
		t.Fatalf("到期后重新封禁应获得完整 TTL，实际 %s", remaining)
	}
}

// TestBanRenewOnRepeat 覆盖：显式开启 renew_on_repeat 时恢复旧的续期行为。
func TestBanRenewOnRepeat(t *testing.T) {
	cfg := defaultBanConfig()
	cfg.RenewOnRepeat = true
	manager, memoryStore, clock := newTestManagerWithClock(t, cfg)
	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")

	if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
		t.Fatalf("首次封禁失败：%v", err)
	}
	clock.Advance(10 * time.Minute)
	if err := manager.Ban(ctx, rctx, []core.BanRequest{{RuleID: "test"}}); err != nil {
		t.Fatalf("重复封禁失败：%v", err)
	}

	_, remaining, err := memoryStore.IsBanned(ctx, "ip:1.2.3.4")
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if remaining != 30*time.Minute {
		t.Fatalf("开启续期后剩余时长应重置为 30m，实际 %s", remaining)
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
