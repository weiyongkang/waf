package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// recordingStore 是单元测试用的内存版 core.Store：
// 记录每次 Incr 的键，便于断言「计数键的构造是否稳定、是否包含维度与窗口」。
type recordingStore struct {
	// mu 保护下列字段。
	mu sync.Mutex
	// counts 是键到计数的映射。
	counts map[string]int64
	// incrKeys 按调用顺序记录计数键。
	incrKeys []string
	// incrErr 非空时让 Incr 直接失败，用于覆盖存储故障路径。
	incrErr error
	// bans 记录写入的封禁条目。
	bans []core.BanEntry
}

// newRecordingStore 构造记录型存储。
func newRecordingStore() *recordingStore {
	return &recordingStore{counts: make(map[string]int64)}
}

// Incr 自增计数并记录键。
func (s *recordingStore) Incr(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if s.incrErr != nil {
		return 0, 0, s.incrErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	s.incrKeys = append(s.incrKeys, key)
	return s.counts[key], window, nil
}

// Ban 记录封禁条目。
func (s *recordingStore) Ban(_ context.Context, key string, ttl time.Duration, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans = append(s.bans, core.BanEntry{Key: key, TTL: ttl, Reason: reason})
	return nil
}

// BanIfAbsent 记录封禁条目并报告创建成功。
func (s *recordingStore) BanIfAbsent(_ context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans = append(s.bans, core.BanEntry{Key: key, TTL: ttl, Reason: reason})
	return true, nil
}

// IsBanned 恒返回未封禁（本测试不覆盖查询路径）。
func (s *recordingStore) IsBanned(context.Context, string) (bool, time.Duration, error) {
	return false, 0, nil
}

// List 返回已记录的封禁条目。
func (s *recordingStore) List(context.Context) ([]core.BanEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]core.BanEntry(nil), s.bans...), nil
}

// Unban 不做任何事。
func (s *recordingStore) Unban(context.Context, string) error { return nil }

// Close 不做任何事。
func (s *recordingStore) Close() error { return nil }

// lastKey 返回最后一次使用的计数键。
func (s *recordingStore) lastKey(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.incrKeys) == 0 {
		t.Fatal("未记录到任何计数键")
	}
	return s.incrKeys[len(s.incrKeys)-1]
}

// singleResolver 是只提供一个存储实例的解析器。
type singleResolver struct {
	// store 是被解析的存储实例。
	store core.Store
}

// Resolve 只认识 default 名称。
func (r *singleResolver) Resolve(name string) (core.Store, error) {
	if name == "" || name == "default" {
		return r.store, nil
	}
	return nil, errors.New("未找到存储实例 " + name)
}

// Default 返回唯一实例。
func (r *singleResolver) Default() (core.Store, error) { return r.store, nil }

// Names 返回实例名列表。
func (r *singleResolver) Names() []string { return []string{"default"} }

// newTestDeps 构造注入指定存储的依赖集合。
func newTestDeps(store core.Store) *core.Deps {
	return &core.Deps{
		Stores:  &singleResolver{store: store},
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
		Limits:  core.Limits{MaxScanTokenBytes: 64},
	}
}

// buildCheck 依据配置片段构造校验单元，构造失败直接终止测试。
func buildCheck(t *testing.T, settings map[string]any, deps *core.Deps) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     "rl",
		Type:     Type,
		Enabled:  true,
		Order:    10,
		Phase:    core.PhasePre,
		Settings: settings,
	}, deps)
	if err != nil {
		t.Fatalf("构造 ratelimit 失败：%v", err)
	}
	return check
}

// newRequestContext 构造一个最小可用的请求上下文。
func newRequestContext() *core.RequestContext {
	rctx := core.NewRequestContext("req-1", time.Now())
	rctx.Raw.Header = http.Header{}
	rctx.Raw.Method = "GET"
	rctx.Raw.URI = "/api/user?id=1"
	rctx.Raw.Path = "/api/user"
	rctx.Raw.Host = "app.example.com"
	rctx.Raw.ClientIP = "1.2.3.4"
	rctx.Raw.Header.Set("User-Agent", "curl/8.0")
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	return rctx
}

// TestEvaluateTriggersAfterLimit 覆盖：超过 limit+burst 后触发限速并回传 Retry-After。
func TestEvaluateTriggersAfterLimit(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip", "site"},
		"window":     "60s",
		"limit":      2,
		"burst":      1,
	}, newTestDeps(store))

	rctx := newRequestContext()
	for index := 0; index < 3; index++ {
		result, err := check.Evaluate(rctx)
		if err != nil {
			t.Fatalf("第 %d 次校验返回错误：%v", index+1, err)
		}
		if result != nil {
			t.Fatalf("第 %d 次校验在阈值内不应产生结论，实际 %s", index+1, result.Verdict)
		}
	}

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第 4 次校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictRateLimited {
		t.Fatalf("期望触发限速，实际 %+v", result)
	}
	if result.Code != "WAF_RATE_LIMITED" {
		t.Fatalf("期望错误码 WAF_RATE_LIMITED，实际 %q", result.Code)
	}
	if result.RetryAfter != time.Minute {
		t.Fatalf("期望 Retry-After 为窗口长度 1m，实际 %s", result.RetryAfter)
	}
}

// TestCounterKeyContainsDimensionsAndWindow 覆盖：计数键包含全部维度值与窗口。
func TestCounterKeyContainsDimensionsAndWindow(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip", "site", "host"},
		"window":     "60s",
		"limit":      10,
	}, newTestDeps(store))

	if _, err := check.Evaluate(newRequestContext()); err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}

	want := "rl:ip=1.2.3.4|site=default|host=app.example.com:60"
	if got := store.lastKey(t); got != want {
		t.Fatalf("计数键不符：期望 %q，实际 %q", want, got)
	}
}

// TestUserAgentDimensionIsHashed 覆盖：UA 维度做哈希处理且长度受 limits 约束。
func TestUserAgentDimensionIsHashed(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ua"},
		"window":     "30s",
		"limit":      10,
	}, newTestDeps(store))

	rctx := newRequestContext()
	rctx.Raw.Header.Set("User-Agent", strings.Repeat("x", 4096))
	if _, err := check.Evaluate(rctx); err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}

	key := store.lastKey(t)
	if !strings.HasPrefix(key, "rl:ua=h:") {
		t.Fatalf("UA 维度应以哈希形式入键，实际键为 %q", key)
	}
	// 键长度必须受 limits.max_scan_token_bytes（64）约束，而不是随 UA 无限增长。
	if len(key) > 64+len("rl:ua=h::30") {
		t.Fatalf("UA 维度的键长度失控：%q", key)
	}
}

// TestEvaluateActions 覆盖：三种 action 分别产生 429 / 403 / 观察结论。
func TestEvaluateActions(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		verdict core.Verdict
		code    string
	}{
		{name: "限速", action: ActionRateLimit, verdict: core.VerdictRateLimited, code: "WAF_RATE_LIMITED"},
		{name: "拦截", action: ActionBlock, verdict: core.VerdictBlock, code: "WAF_BLOCKED"},
		{name: "观察", action: ActionObserve, verdict: core.VerdictObserve, code: ""},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			store := newRecordingStore()
			check := buildCheck(t, map[string]any{
				"dimensions": []any{"ip"},
				"window":     "10s",
				"limit":      1,
				"action":     item.action,
			}, newTestDeps(store))

			rctx := newRequestContext()
			if _, err := check.Evaluate(rctx); err != nil {
				t.Fatalf("首次校验返回错误：%v", err)
			}
			result, err := check.Evaluate(rctx)
			if err != nil {
				t.Fatalf("第二次校验返回错误：%v", err)
			}
			if result == nil || result.Verdict != item.verdict {
				t.Fatalf("期望结论 %s，实际 %+v", item.verdict, result)
			}
			if result.Code != item.code {
				t.Fatalf("期望错误码 %q，实际 %q", item.code, result.Code)
			}
		})
	}
}

// TestEvaluateEmitsBanRequest 覆盖：开启 ban 后触发限速会请求内部封禁。
func TestEvaluateEmitsBanRequest(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip"},
		"window":     "10s",
		"limit":      1,
		"action":     "block",
		"ban":        true,
		"ban_ttl":    "15m",
	}, newTestDeps(store))

	rctx := newRequestContext()
	if _, err := check.Evaluate(rctx); err != nil {
		t.Fatalf("首次校验返回错误：%v", err)
	}
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第二次校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 1 {
		t.Fatalf("期望产生 1 条封禁请求，实际 %+v", result)
	}
	if result.Bans[0].TTL != 15*time.Minute {
		t.Fatalf("封禁时长应为 15m，实际 %s", result.Bans[0].TTL)
	}
	if result.Bans[0].Key != "" {
		t.Fatalf("封禁键应由封禁控制器统一推导（此处应为空），实际 %q", result.Bans[0].Key)
	}
}

// TestEvaluatePathFilter 覆盖：path_match 未命中时完全不计数。
func TestEvaluatePathFilter(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip"},
		"path_match": []any{"^/login$"},
		"window":     "10s",
		"limit":      1,
	}, newTestDeps(store))

	rctx := newRequestContext()
	rctx.Raw.Path = "/api/user"
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("未命中 path_match 时不应产生结论，实际 %s", result.Verdict)
	}
	if len(store.incrKeys) != 0 {
		t.Fatalf("未命中 path_match 时不应产生计数，实际计数 %d 次", len(store.incrKeys))
	}

	rctx.Raw.Path = "/login"
	if _, err := check.Evaluate(rctx); err != nil {
		t.Fatalf("命中 path_match 时校验返回错误：%v", err)
	}
	if len(store.incrKeys) != 1 {
		t.Fatalf("命中 path_match 时应计数 1 次，实际 %d 次", len(store.incrKeys))
	}
}

// TestEvaluateStoreErrorIsPropagated 覆盖：计数失败时返回错误交给 on_error 策略处理。
func TestEvaluateStoreErrorIsPropagated(t *testing.T) {
	store := newRecordingStore()
	store.incrErr = errors.New("模拟存储故障")
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip"},
		"window":     "10s",
		"limit":      1,
	}, newTestDeps(store))

	if _, err := check.Evaluate(newRequestContext()); err == nil {
		t.Fatal("存储故障时应返回错误，而不是静默视为未超限")
	}
}

// TestNewValidation 覆盖：非法配置必须在构造阶段失败（fail fast）。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{name: "缺少维度", settings: map[string]any{"limit": 1}},
		{name: "未知维度", settings: map[string]any{"dimensions": []any{"cookie"}, "limit": 1}},
		{name: "重复维度", settings: map[string]any{"dimensions": []any{"ip", "ip"}, "limit": 1}},
		{name: "缺少limit", settings: map[string]any{"dimensions": []any{"ip"}}},
		{name: "非法action", settings: map[string]any{"dimensions": []any{"ip"}, "limit": 1, "action": "drop"}},
		{name: "非法正则", settings: map[string]any{"dimensions": []any{"ip"}, "limit": 1, "path_match": []any{"("}}},
		{name: "未知字段", settings: map[string]any{"dimensions": []any{"ip"}, "limit": 1, "typo": 1}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if _, err := New(core.InstanceConfig{
				Name: "rl", Type: Type, Enabled: true, Phase: core.PhasePre, Settings: item.settings,
			}, newTestDeps(newRecordingStore())); err == nil {
				t.Fatal("非法配置应在构造阶段直接失败")
			}
		})
	}
}

// TestEvaluateSiteParamOverride 覆盖：站点级 params 覆盖实例配置的阈值与窗口。
func TestEvaluateSiteParamOverride(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip"},
		"window":     "60s",
		"limit":      100,
		"burst":      50,
	}, newTestDeps(store))

	rctx := newRequestContext()
	rctx.Site = &core.Site{
		Name:  "strict",
		Hosts: []string{"strict.example.com"},
		Params: map[string]string{
			"ratelimit.limit":  "1",
			"ratelimit.burst":  "0",
			"ratelimit.window": "10s",
		},
	}

	if _, err := check.Evaluate(rctx); err != nil {
		t.Fatalf("首次校验返回错误：%v", err)
	}
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第二次校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictRateLimited {
		t.Fatalf("站点级阈值收紧到 1 后第二次应触发限速，实际 %+v", result)
	}

	// 计数键中的窗口必须使用站点级覆盖值，否则不同窗口会共用同一个计数桶。
	if key := store.lastKey(t); key != "rl:ip=1.2.3.4:10" {
		t.Fatalf("计数键应使用站点级窗口，实际 %q", key)
	}
}

// TestEvaluateInvalidSiteParamFallsBack 覆盖：站点级参数非法时回退到实例配置。
//
// 之所以必须回退而不是「按 0 处理」：把阈值解析失败当成 0 会让限速变成
// 「拦截一切」或「完全不限制」两种极端，都属于静默失效。
func TestEvaluateInvalidSiteParamFallsBack(t *testing.T) {
	store := newRecordingStore()
	check := buildCheck(t, map[string]any{
		"dimensions": []any{"ip"},
		"window":     "60s",
		"limit":      2,
	}, newTestDeps(store))

	rctx := newRequestContext()
	rctx.Site = &core.Site{
		Name:   "broken",
		Hosts:  []string{"broken.example.com"},
		Params: map[string]string{"ratelimit.limit": "abc", "ratelimit.window": "-1s"},
	}

	// 实例配置为 limit=2、window=60s，因此前两次放行、第三次触发。
	for index := 0; index < 2; index++ {
		if result, err := check.Evaluate(rctx); err != nil || result != nil {
			t.Fatalf("第 %d 次应放行，实际 result=%+v err=%v", index+1, result, err)
		}
	}
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictRateLimited {
		t.Fatalf("非法站点参数应回退到实例配置并触发限速，实际 %+v", result)
	}
	if key := store.lastKey(t); key != "rl:ip=1.2.3.4:60" {
		t.Fatalf("回退后应使用实例窗口，实际键 %q", key)
	}
}

// TestNewRequiresStore 覆盖：未注入存储解析器时必须构造失败。
func TestNewRequiresStore(t *testing.T) {
	if _, err := New(core.InstanceConfig{
		Name: "rl", Type: Type, Enabled: true, Phase: core.PhasePre,
		Settings: map[string]any{"dimensions": []any{"ip"}, "limit": 1},
	}, &core.Deps{}); err == nil {
		t.Fatal("未注入共享存储时应构造失败")
	}
}
