package autoban

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// countingStore 是单元测试用的内存版 core.Store，只实现计数与封禁记录。
type countingStore struct {
	// mu 保护下列字段。
	mu sync.Mutex
	// counts 是键到计数的映射。
	counts map[string]int64
	// incrErr 非空时让 Incr 直接失败。
	incrErr error
	// banned 记录被写入的封禁键。
	banned []string
	// bannedKeys 是 IsBanned 判定为「已封禁」的键集合。
	bannedKeys map[string]bool
}

// newCountingStore 构造计数存储。
func newCountingStore() *countingStore {
	return &countingStore{counts: make(map[string]int64)}
}

// Incr 自增计数。
func (s *countingStore) Incr(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if s.incrErr != nil {
		return 0, 0, s.incrErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	return s.counts[key], window, nil
}

// Ban 记录封禁键。
func (s *countingStore) Ban(_ context.Context, key string, _ time.Duration, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned = append(s.banned, key)
	return nil
}

// BanIfAbsent 记录封禁键并报告创建成功。
func (s *countingStore) BanIfAbsent(_ context.Context, key string, _ time.Duration, _ string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned = append(s.banned, key)
	return true, nil
}

// IsBanned 依据 bannedKeys 判定，未登记时表示未封禁。
func (s *countingStore) IsBanned(_ context.Context, key string) (bool, time.Duration, error) {
	return s.bannedKeys[key], 0, nil
}

// List 返回空名单。
func (s *countingStore) List(context.Context) ([]core.BanEntry, error) { return nil, nil }

// Unban 不做任何事。
func (s *countingStore) Unban(context.Context, string) error { return nil }

// Close 不做任何事。
func (s *countingStore) Close() error { return nil }

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

// fakeBans 是记录封禁动作的 core.BanController 实现。
type fakeBans struct {
	// key 是 KeyFor / KeyForScope 的默认返回值。
	key string
	// keys 是按维度预设的键；命中时优先于 key。
	keys map[string]string
	// scopes 是 Scopes 返回的启用维度清单；为空时返回 [client_ip]。
	scopes []string
	// requests 记录落地的封禁请求。
	requests []core.BanRequest
}

// CheckScopes 恒返回未封禁（autoban 只关心键的构造，不关心是否已封禁）。
func (f *fakeBans) CheckScopes(context.Context, *core.RequestContext) (bool, time.Duration, string, string, error) {
	return false, 0, f.key, "client_ip", nil
}

// KeyForScope 返回按维度预设的键，未预设时回落到 key。
func (f *fakeBans) KeyForScope(_ *core.RequestContext, scope string) string {
	if value, ok := f.keys[scope]; ok {
		return value
	}
	return f.key
}

// Scopes 返回预设的启用维度清单。
func (f *fakeBans) Scopes() []string {
	if len(f.scopes) == 0 {
		return []string{"client_ip"}
	}
	return f.scopes
}

// Ban 记录封禁请求。
func (f *fakeBans) Ban(_ context.Context, _ *core.RequestContext, requests []core.BanRequest) error {
	f.requests = append(f.requests, requests...)
	return nil
}

// KeyFor 返回预设的封禁键。
func (f *fakeBans) KeyFor(*core.RequestContext) string { return f.key }

// buildCheck 依据配置片段构造校验单元，构造失败直接终止测试。
func buildCheck(t *testing.T, settings map[string]any, store core.Store, bans core.BanController) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     "autoban",
		Type:     Type,
		Enabled:  true,
		Order:    90,
		Phase:    core.PhasePost,
		Settings: settings,
	}, &core.Deps{
		Stores:  &singleResolver{store: store},
		Bans:    bans,
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
	})
	if err != nil {
		t.Fatalf("构造 autoban 失败：%v", err)
	}
	return check
}

// newVerdictContext 构造一个已产生指定判定结论的请求上下文。
func newVerdictContext(verdict core.Verdict) *core.RequestContext {
	rctx := core.NewRequestContext("req-autoban", time.Now())
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	rctx.Raw.Header = http.Header{}
	rctx.Raw.ClientIP = "1.2.3.4"
	if verdict != core.VerdictContinue {
		rctx.AppendResult(&core.Result{Check: "blocker", Verdict: verdict})
	}
	return rctx
}

// TestEvaluateCountsUntilThreshold 覆盖：累计命中达到阈值时才产生封禁请求。
func TestEvaluateCountsUntilThreshold(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"trigger_on": []any{"block"},
		"threshold":  3,
		"window":     "5m",
		"ttl":        "1h",
	}, store, bans)

	rctx := newVerdictContext(core.VerdictBlock)
	for index := 0; index < 2; index++ {
		result, err := check.Evaluate(rctx)
		if err != nil {
			t.Fatalf("第 %d 次校验返回错误：%v", index+1, err)
		}
		if result != nil {
			t.Fatalf("第 %d 次命中未达阈值时不应产生结论，实际 %+v", index+1, result)
		}
	}

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第 3 次校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 1 {
		t.Fatalf("第 3 次命中达到阈值，应产生 1 条封禁请求，实际 %+v", result)
	}
	if result.Bans[0].Key != "ip:1.2.3.4" {
		t.Fatalf("封禁键应与 banlist 查询键一致，实际 %q", result.Bans[0].Key)
	}
	if result.Bans[0].TTL != time.Hour {
		t.Fatalf("封禁时长应为 1h，实际 %s", result.Bans[0].TTL)
	}
	if result.Verdict != core.VerdictContinue {
		t.Fatalf("autoban 不应改变链结论，实际 %s", result.Verdict)
	}
}

// TestEvaluateObserveDoesNotBan 覆盖：观察模式只告警、不写入名单。
func TestEvaluateObserveDoesNotBan(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"threshold": 1,
		"window":    "1m",
		"action":    "observe",
		"alert":     true,
	}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictBlock))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil {
		t.Fatal("观察模式仍应产生命中记录与告警")
	}
	if len(result.Bans) != 0 {
		t.Fatalf("观察模式不应产生封禁请求，实际 %+v", result.Bans)
	}
	if len(result.Alerts) != 1 {
		t.Fatalf("观察模式应产生 1 条告警，实际 %d 条", len(result.Alerts))
	}
}

// TestEvaluateTriggerFilter 覆盖：未配置在 trigger_on 中的结论不计入触发。
func TestEvaluateTriggerFilter(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"trigger_on": []any{"ratelimit"},
		"threshold":  1,
		"window":     "1m",
	}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictBlock))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("block 不在 trigger_on 中时不应触发封禁，实际 %+v", result)
	}
	if len(store.counts) != 0 {
		t.Fatalf("未命中触发条件时不应计数，实际计数 %d 项", len(store.counts))
	}
}

// TestEvaluateIgnoresAllowVerdict 覆盖：放行类结论即使配置 any 也不触发封禁。
func TestEvaluateIgnoresAllowVerdict(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"trigger_on": []any{"any"},
		"threshold":  1,
		"window":     "1m",
	}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictAllow))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("放行结论不应触发封禁，实际 %+v", result)
	}
}

// TestEvaluateSkipsWhenBanKeyMissing 覆盖：无法推导封禁键时跳过，不做无键封禁。
func TestEvaluateSkipsWhenBanKeyMissing(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: ""}
	check := buildCheck(t, map[string]any{"threshold": 1, "window": "1m"}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictBlock))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("无法推导封禁键时不应产生结论，实际 %+v", result)
	}
}

// TestEvaluateStoreErrorIsPropagated 覆盖：计数失败返回错误，交给 on_error 策略处理。
func TestEvaluateStoreErrorIsPropagated(t *testing.T) {
	store := newCountingStore()
	store.incrErr = errors.New("模拟存储故障")
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{"threshold": 1, "window": "1m"}, store, bans)

	if _, err := check.Evaluate(newVerdictContext(core.VerdictBlock)); err == nil {
		t.Fatal("计数失败时应返回错误，而不是静默跳过封禁")
	}
}

// TestNewValidation 覆盖：非法配置与缺失依赖在构造阶段直接失败。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		deps     *core.Deps
	}{
		{
			name:     "缺少封禁控制器",
			settings: map[string]any{"threshold": 1, "window": "1m"},
			deps:     &core.Deps{Stores: &singleResolver{store: newCountingStore()}},
		},
		{
			name:     "缺少存储",
			settings: map[string]any{"threshold": 1, "window": "1m"},
			deps:     &core.Deps{Bans: &fakeBans{key: "ip:1.2.3.4"}},
		},
		{
			name:     "非法动作",
			settings: map[string]any{"threshold": 1, "window": "1m", "action": "drop"},
			deps:     &core.Deps{Stores: &singleResolver{store: newCountingStore()}, Bans: &fakeBans{}},
		},
		{
			name:     "未知字段",
			settings: map[string]any{"threshold": 1, "window": "1m", "typo": 1},
			deps:     &core.Deps{Stores: &singleResolver{store: newCountingStore()}, Bans: &fakeBans{}},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "autoban", Type: Type, Enabled: true, Phase: core.PhasePost, Settings: item.settings,
			}, item.deps)
			if err == nil {
				t.Fatal("非法配置应在构造阶段直接失败")
			}
		})
	}
}

// TestNewDefaultsTriggerOnBlockAndHoneypot 覆盖：未配置 trigger_on 时默认对拦截与蜜罐命中生效。
func TestNewDefaultsTriggerOnBlockAndHoneypot(t *testing.T) {
	for _, verdict := range []core.Verdict{core.VerdictBlock, core.VerdictHoneypot} {
		t.Run(verdict.String(), func(t *testing.T) {
			check := buildCheck(t, map[string]any{"threshold": 1, "window": "1m"},
				newCountingStore(), &fakeBans{key: "ip:1.2.3.4"})

			result, err := check.Evaluate(newVerdictContext(verdict))
			if err != nil {
				t.Fatalf("校验返回错误：%v", err)
			}
			if result == nil || len(result.Bans) != 1 {
				t.Fatalf("默认配置应对 %s 结论触发封禁，实际 %+v", verdict, result)
			}
		})
	}
}

// TestEvaluateHoneypotCountsUntilThreshold 覆盖：蜜罐命中按窗口累计，达到阈值后封禁。
func TestEvaluateHoneypotCountsUntilThreshold(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"trigger_on": []any{"honeypot"},
		"threshold":  2,
		"window":     "5m",
		"ttl":        "30m",
	}, store, bans)

	rctx := newVerdictContext(core.VerdictHoneypot)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("首次蜜罐命中校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("首次蜜罐命中未达阈值时不应封禁，实际 %+v", result)
	}

	result, err = check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第二次蜜罐命中校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 1 {
		t.Fatalf("窗口内第二次蜜罐命中应触发封禁，实际 %+v", result)
	}
	if result.Bans[0].Key != "ip:1.2.3.4" {
		t.Fatalf("封禁键不符，实际 %q", result.Bans[0].Key)
	}
	if result.Bans[0].TTL != 30*time.Minute {
		t.Fatalf("封禁时长应为 30m，实际 %s", result.Bans[0].TTL)
	}
}

// TestEvaluateMultipleDimensions 覆盖：多个触发维度同时达标时产出多条封禁动作。
//
// 这是本次改造的核心场景——用户反馈「只按单一 IP 统计阈值得以封禁」不够用：
// 同一个来源同时满足「按 IP 累计」与「按 IP+路径 累计」时，两条封禁动作都应产生，
// 由 internal/ban 逐条落地（多个维度串联生效）。
func TestEvaluateMultipleDimensions(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{
		key: "ip:1.2.3.4",
		keys: map[string]string{
			"client_ip":      "ip:1.2.3.4",
			"client_ip+path": "ip:1.2.3.4|path:/api/user",
		},
		scopes: []string{"client_ip", "client_ip+path"},
	}
	check := buildCheck(t, map[string]any{
		"threshold": 2,
		"window":    "5m",
		"dimensions": []any{
			map[string]any{"scope": "client_ip"},
			map[string]any{"scope": "client_ip+path", "ttl": "1h"},
		},
	}, store, bans)

	rctx := newVerdictContext(core.VerdictBlock)
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("首次校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("首次未达阈值时不应产生结论，实际 %+v", result)
	}

	result, err = check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("第二次校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 2 {
		t.Fatalf("两个维度同时达标时应产生 2 条封禁动作，实际 %+v", result)
	}

	byScope := make(map[string]core.BanRequest, len(result.Bans))
	for _, ban := range result.Bans {
		byScope[ban.Scope] = ban
	}
	if got := byScope["client_ip"].Key; got != "ip:1.2.3.4" {
		t.Fatalf("IP 维度的封禁键不符，实际 %q", got)
	}
	if got := byScope["client_ip+path"].Key; got != "ip:1.2.3.4|path:/api/user" {
		t.Fatalf("路径维度的封禁键不符，实际 %q", got)
	}
	if got := byScope["client_ip+path"].TTL; got != time.Hour {
		t.Fatalf("路径维度的封禁时长应取该维度覆盖值 1h，实际 %s", got)
	}
	if got := byScope["client_ip"].TTL; got != 0 {
		t.Fatalf("IP 维度未覆盖时长时应为 0（交由 ban.default_ttl 兜底），实际 %s", got)
	}
}

// TestEvaluateMinSeverityGate 覆盖：未达最低严重度门槛时不计数、不封禁。
func TestEvaluateMinSeverityGate(t *testing.T) {
	store := newCountingStore()
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"threshold": 1, "window": "1m", "min_severity": "high",
	}, store, bans)

	rctx := newVerdictContext(core.VerdictBlock)
	rctx.AppendResult(&core.Result{
		Check:   "blocker",
		Verdict: core.VerdictBlock,
		Findings: []core.Finding{
			core.NewFinding("blocker", "low-only", "低危命中", core.SeverityLow, 0),
		},
	})

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("严重度未达门槛时不应产生结论，实际 %+v", result)
	}
	if len(store.counts) != 0 {
		t.Fatalf("严重度未达门槛时不应计数，实际 %v", store.counts)
	}

	// 同一来源出现 high 命中时应当放行计数并触发封禁。
	rctx.AppendResult(&core.Result{
		Check:   "blocker",
		Verdict: core.VerdictBlock,
		Findings: []core.Finding{
			core.NewFinding("blocker", "high-hit", "高危命中", core.SeverityHigh, 0),
		},
	})
	result, err = check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 1 {
		t.Fatalf("达到门槛后应产生封禁动作，实际 %+v", result)
	}
}

// TestEvaluateSkipsWhenAlreadyBanned 覆盖：来源已在名单中时不再计数（默认行为）。
func TestEvaluateSkipsWhenAlreadyBanned(t *testing.T) {
	store := newCountingStore()
	store.bannedKeys = map[string]bool{"ip:1.2.3.4": true}
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{"threshold": 1, "window": "1m"}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictBlock))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("已封禁时不应重复产出封禁动作，实际 %+v", result)
	}
	if len(store.counts) != 0 {
		t.Fatalf("已封禁时不应继续计数，实际 %v", store.counts)
	}
}

// TestEvaluateKeepsCountingWhenSkipDisabled 覆盖：显式关闭 skip_when_banned 后的续期语义。
func TestEvaluateKeepsCountingWhenSkipDisabled(t *testing.T) {
	store := newCountingStore()
	store.bannedKeys = map[string]bool{"ip:1.2.3.4": true}
	bans := &fakeBans{key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{
		"threshold": 1, "window": "1m", "skip_when_banned": false,
	}, store, bans)

	result, err := check.Evaluate(newVerdictContext(core.VerdictBlock))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || len(result.Bans) != 1 {
		t.Fatalf("关闭 skip_when_banned 后应持续续期封禁，实际 %+v", result)
	}
	if len(store.counts) != 1 {
		t.Fatalf("关闭 skip_when_banned 后应继续计数，实际 %v", store.counts)
	}
}

// TestNewValidationDimensions 覆盖：维度相关的非法配置在构造阶段直接失败。
func TestNewValidationDimensions(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{
			name: "维度取值非法",
			settings: map[string]any{"dimensions": []any{
				map[string]any{"scope": "ip"},
			}},
		},
		{
			name: "维度未在 ban_keys 中启用",
			settings: map[string]any{"dimensions": []any{
				map[string]any{"scope": "client_ip+method"},
			}},
		},
		{
			name: "维度重复声明",
			settings: map[string]any{"dimensions": []any{
				map[string]any{"scope": "client_ip"},
				map[string]any{"scope": "client_ip"},
			}},
		},
		{
			name:     "严重度取值非法",
			settings: map[string]any{"min_severity": "blocker"},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "autoban", Type: Type, Enabled: true, Phase: core.PhasePost,
				Settings: item.settings,
			}, &core.Deps{
				Stores: &singleResolver{store: newCountingStore()},
				Bans:   &fakeBans{key: "ip:1.2.3.4"},
			})
			if err == nil {
				t.Fatal("非法维度配置应在构造阶段直接失败")
			}
		})
	}
}
