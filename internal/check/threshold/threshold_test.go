package threshold

import (
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// buildCheck 依据配置片段构造校验单元，构造失败直接终止测试。
func buildCheck(t *testing.T, settings map[string]any) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     "threshold",
		Type:     Type,
		Enabled:  true,
		Order:    40,
		Phase:    core.PhasePost,
		Settings: settings,
	}, &core.Deps{Metrics: core.NoopMetrics{}, Clock: core.SystemClock{}})
	if err != nil {
		t.Fatalf("构造 threshold 失败：%v", err)
	}
	return check
}

// newScoredContext 构造一个带有评分与命中的请求上下文。
//
// 注意：真实运行期由执行器调用 RequestContext.AddScore 汇总评分，
// 单元测试直接调用同一接口来模拟执行器的行为。
func newScoredContext(score int, findings ...core.Finding) *core.RequestContext {
	rctx := core.NewRequestContext("req-threshold", time.Now())
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	if score != 0 {
		rctx.AddScore(score)
	}
	if len(findings) > 0 {
		result := &core.Result{Check: "engine", Verdict: core.VerdictContinue}
		result.Findings = append(result.Findings, findings...)
		rctx.AppendResult(result)
	}
	return rctx
}

// TestEvaluateBelowThreshold 覆盖：评分未达阈值时不产生结论。
func TestEvaluateBelowThreshold(t *testing.T) {
	check := buildCheck(t, map[string]any{"inbound_threshold": 5})

	result, err := check.Evaluate(newScoredContext(4))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("评分 4 低于阈值 5 时不应产生结论，实际 %s", result.Verdict)
	}
}

// TestEvaluateAtThresholdBlocks 覆盖：评分达到阈值时拦截并给出统一错误码。
func TestEvaluateAtThresholdBlocks(t *testing.T) {
	check := buildCheck(t, map[string]any{"inbound_threshold": 5})

	result, err := check.Evaluate(newScoredContext(5))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %+v", result)
	}
	if result.Code != "WAF_BLOCKED" {
		t.Fatalf("期望错误码 WAF_BLOCKED，实际 %q", result.Code)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != ruleIDThreshold {
		t.Fatalf("命中明细不符：%+v", result.Findings)
	}
}

// TestEvaluateObserveAction 覆盖：观察模式下仅记录，不产生拦截错误码。
func TestEvaluateObserveAction(t *testing.T) {
	check := buildCheck(t, map[string]any{"inbound_threshold": 5, "action": "observe"})

	result, err := check.Evaluate(newScoredContext(9))
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

// TestEvaluateMinSeverityGate 覆盖：只有低危命中时即使评分达标也不拦截。
func TestEvaluateMinSeverityGate(t *testing.T) {
	check := buildCheck(t, map[string]any{"inbound_threshold": 5, "min_severity": "high"})

	lowOnly := newScoredContext(0, core.NewFinding("engine", "low-1", "低危命中", core.SeverityLow, 5))
	lowOnly.AddScore(5)
	if result, err := check.Evaluate(lowOnly); err != nil {
		t.Fatalf("校验返回错误：%v", err)
	} else if result != nil {
		t.Fatalf("无高危命中时不应拦截，实际 %s", result.Verdict)
	}

	withHigh := newScoredContext(0,
		core.NewFinding("engine", "low-1", "低危命中", core.SeverityLow, 4),
		core.NewFinding("engine", "high-1", "高危命中", core.SeverityHigh, 1),
	)
	withHigh.AddScore(5)
	result, err := check.Evaluate(withHigh)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("存在高危命中且评分达标时应拦截，实际 %+v", result)
	}
}

// TestEvaluateReadsEngineScoreKey 覆盖：可以从检测引擎自写的评分键读取总分。
func TestEvaluateReadsEngineScoreKey(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"inbound_threshold": 5,
		"score_key":         "inbound_anomaly_score",
	})

	rctx := core.NewRequestContext("req-engine", time.Now())
	// 检测引擎按自己的键名写入评分；执行器汇总键保持为 0。
	rctx.SetState("inbound_anomaly_score", 7)

	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("应读取引擎评分键并拦截，实际 %+v", result)
	}
}

// TestEvaluateTakesMaxOfScoreSources 覆盖：两个评分来源取较大值，避免同一次命中被计两次。
func TestEvaluateTakesMaxOfScoreSources(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"inbound_threshold": 10,
		"score_key":         "inbound_anomaly_score",
	})

	rctx := core.NewRequestContext("req-both", time.Now())
	rctx.AddScore(6)
	rctx.SetState("inbound_anomaly_score", 7)

	// 若实现为「求和」，总分为 13 会误触发拦截；取较大值时为 7，不应拦截。
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result != nil {
		t.Fatalf("两个评分来源应取较大值（7 < 10），实际触发 %s", result.Verdict)
	}
}

// TestEvaluateNilContext 覆盖：空上下文不产生结论也不报错。
func TestEvaluateNilContext(t *testing.T) {
	check := buildCheck(t, map[string]any{"inbound_threshold": 1})

	result, err := check.Evaluate(nil)
	if err != nil || result != nil {
		t.Fatalf("空上下文应无结论无错误，实际 result=%+v err=%v", result, err)
	}
}

// TestNewValidation 覆盖：非法配置在构造阶段直接失败。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{name: "缺少阈值", settings: map[string]any{}},
		{name: "阈值为负", settings: map[string]any{"inbound_threshold": -1}},
		{name: "非法动作", settings: map[string]any{"inbound_threshold": 5, "action": "drop"}},
		{name: "非法严重级别", settings: map[string]any{"inbound_threshold": 5, "min_severity": "urgent"}},
		{name: "未知字段", settings: map[string]any{"inbound_threshold": 5, "typo": 1}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "threshold", Type: Type, Enabled: true, Phase: core.PhasePost, Settings: item.settings,
			}, &core.Deps{})
			if err == nil {
				t.Fatal("非法配置应在构造阶段直接失败")
			}
		})
	}
}
