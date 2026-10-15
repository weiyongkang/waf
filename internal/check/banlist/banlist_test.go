package banlist

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// fakeBans 是可控的封禁控制器，用于覆盖命中、未命中与故障三条路径。
type fakeBans struct {
	// banned 是 CheckScopes 的返回值。
	banned bool
	// remaining 是 CheckScopes 返回的剩余时长。
	remaining time.Duration
	// key 是 CheckScopes 返回的封禁键。
	key string
	// scope 是 CheckScopes 返回的命中维度；为空时按默认维度 client_ip 返回。
	scope string
	// scopes 是 Scopes 返回的启用维度清单；为空时返回 [client_ip]。
	scopes []string
	// err 非空时让 CheckScopes 直接失败。
	err error
}

// CheckScopes 返回预设的查询结果。
func (f *fakeBans) CheckScopes(context.Context, *core.RequestContext) (bool, time.Duration, string, string, error) {
	scope := f.scope
	if scope == "" {
		scope = "client_ip"
	}
	return f.banned, f.remaining, f.key, scope, f.err
}

// Ban 记录封禁动作（本单元不产生封禁动作，因此恒返回成功）。
func (f *fakeBans) Ban(context.Context, *core.RequestContext, []core.BanRequest) error {
	return nil
}

// KeyFor 返回预设键。
func (f *fakeBans) KeyFor(*core.RequestContext) string { return f.key }

// KeyForScope 返回预设键（测试替身不区分维度）。
func (f *fakeBans) KeyForScope(*core.RequestContext, string) string { return f.key }

// Scopes 返回预设的启用维度清单。
func (f *fakeBans) Scopes() []string {
	if len(f.scopes) == 0 {
		return []string{"client_ip"}
	}
	return f.scopes
}

// buildCheck 依据配置片段构造校验单元。
func buildCheck(t *testing.T, settings map[string]any, bans core.BanController) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     "ban-list",
		Type:     Type,
		Enabled:  true,
		Order:    5,
		Phase:    core.PhasePre,
		Settings: settings,
	}, &core.Deps{
		Bans:    bans,
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
	})
	if err != nil {
		t.Fatalf("构造 banlist 失败：%v", err)
	}
	return check
}

// newRequestContext 构造最小请求上下文。
func newRequestContext() *core.RequestContext {
	rctx := core.NewRequestContext("req-banlist", time.Now())
	rctx.Raw.Header = http.Header{}
	rctx.Raw.ClientIP = "1.2.3.4"
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	return rctx
}

// TestEvaluateNotBanned 覆盖：未封禁时不产生结论。
func TestEvaluateNotBanned(t *testing.T) {
	check := buildCheck(t, nil, &fakeBans{banned: false})

	result, err := check.Evaluate(newRequestContext())
	if err != nil || result != nil {
		t.Fatalf("未封禁应无结论无错误，实际 result=%+v err=%v", result, err)
	}
}

// TestEvaluateBanned 覆盖：命中封禁名单时拦截并回传剩余时长。
func TestEvaluateBanned(t *testing.T) {
	bans := &fakeBans{banned: true, remaining: 12 * time.Minute, key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{"score": 3}, bans)

	result, err := check.Evaluate(newRequestContext())
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %+v", result)
	}
	if result.Code != "WAF_BLOCKED" {
		t.Fatalf("期望错误码 WAF_BLOCKED，实际 %q", result.Code)
	}
	if result.RetryAfter != 12*time.Minute {
		t.Fatalf("应回传剩余封禁时长，实际 %s", result.RetryAfter)
	}
	if result.Score != 3 {
		t.Fatalf("评分应为 3，实际 %d", result.Score)
	}
	if len(result.Findings) != 1 || result.Findings[0].Data["ban_key"] != "ip:1.2.3.4" {
		t.Fatalf("命中明细不符：%+v", result.Findings)
	}
}

// TestEvaluateObserve 覆盖：观察模式下只记录不拦截。
func TestEvaluateObserve(t *testing.T) {
	bans := &fakeBans{banned: true, remaining: time.Minute, key: "ip:1.2.3.4"}
	check := buildCheck(t, map[string]any{"action": "observe"}, bans)

	result, err := check.Evaluate(newRequestContext())
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictObserve {
		t.Fatalf("期望观察结论，实际 %+v", result)
	}
	if result.Code != "" {
		t.Fatalf("观察结论不应携带拦截错误码，实际 %q", result.Code)
	}
}

// TestEvaluateCheckError 覆盖：查询失败时返回错误交给 on_error 策略处理。
func TestEvaluateCheckError(t *testing.T) {
	bans := &fakeBans{err: errors.New("模拟存储故障")}
	check := buildCheck(t, nil, bans)

	if _, err := check.Evaluate(newRequestContext()); err == nil {
		t.Fatal("查询失败时应返回错误，而不是静默视为未封禁")
	}
}

// TestEvaluateNilContext 覆盖：空上下文不产生结论也不报错。
func TestEvaluateNilContext(t *testing.T) {
	check := buildCheck(t, nil, &fakeBans{})

	result, err := check.Evaluate(nil)
	if err != nil || result != nil {
		t.Fatalf("空上下文应无结论无错误，实际 result=%+v err=%v", result, err)
	}
}

// TestNewRequiresBanController 覆盖：未装配封禁控制器时必须构造失败。
func TestNewRequiresBanController(t *testing.T) {
	if _, err := New(core.InstanceConfig{
		Name: "ban-list", Type: Type, Enabled: true, Phase: core.PhasePre,
	}, &core.Deps{}); err == nil {
		t.Fatal("未注入封禁控制器时应构造失败")
	}
}

// TestNewValidation 覆盖：非法配置在构造阶段直接失败。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{name: "非法动作", settings: map[string]any{"action": "drop"}},
		{name: "未知字段", settings: map[string]any{"typo": 1}},
		{name: "非法超时", settings: map[string]any{"store_timeout": "abc"}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "ban-list", Type: Type, Enabled: true, Phase: core.PhasePre, Settings: item.settings,
			}, &core.Deps{Bans: &fakeBans{}})
			if err == nil {
				t.Fatal("非法配置应在构造阶段直接失败")
			}
		})
	}
}

// TestDefaultOnErrorIsPass 覆盖：失败策略默认值必须为失败开放。
func TestDefaultOnErrorIsPass(t *testing.T) {
	check := buildCheck(t, nil, &fakeBans{})
	defaulter, ok := check.(core.OnErrorDefaulter)
	if !ok {
		t.Fatal("banlist 应实现 OnErrorDefaulter 以声明失败策略默认值")
	}
	if defaulter.DefaultOnError() != core.OnErrorPass {
		t.Fatalf("失败策略默认值应为 pass，实际 %q", defaulter.DefaultOnError())
	}
}

// TestEvaluateReportsMatchedScope 覆盖：命中名单时把「命中的维度」写入命中明细。
//
// 之所以需要该信息：一个部署可以同时启用多个封禁维度，
// 排障时必须能一眼看出「这次到底是被哪个维度的名单拦下的」，
// 否则只能靠猜（维度不同，解封方式也不同）。
func TestEvaluateReportsMatchedScope(t *testing.T) {
	bans := &fakeBans{
		banned:    true,
		remaining: time.Minute,
		key:       "ip:1.2.3.4|path:/api/user",
		scope:     "client_ip+path",
	}
	check := buildCheck(t, nil, bans)

	result, err := check.Evaluate(newRequestContext())
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || len(result.Findings) != 1 {
		t.Fatalf("命中名单时应产生 1 条命中明细，实际 %+v", result)
	}
	if got := result.Findings[0].Data["ban_scope"]; got != "client_ip+path" {
		t.Fatalf("命中明细应记录命中维度，实际 %q", got)
	}
	if got := result.Findings[0].Data["ban_key"]; got != "ip:1.2.3.4|path:/api/user" {
		t.Fatalf("命中明细应记录封禁键，实际 %q", got)
	}
}
