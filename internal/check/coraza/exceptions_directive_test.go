package coraza

import (
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
	"github.com/weiyongkang/waf/internal/rules/exceptions"
)

// loadRules 加载内置 CRS 规则集（与生产装配使用同一份加载逻辑）。
func loadRules(t *testing.T, deps *core.Deps) *rules.Set {
	t.Helper()

	set, err := rules.Load(rules.Options{
		Source: rules.Source{
			Include:     deps.Engine.RuleInclude,
			DataInclude: deps.Engine.RuleDataInclude,
			CRSSetup:    deps.Engine.CRSSetup,
		},
		MaxFileBytes:  deps.Limits.MaxRuleFileBytes,
		MaxTotalBytes: deps.Limits.MaxRulesTotalBytes,
	})
	if err != nil {
		t.Fatalf("加载内置规则集失败：%v", err)
	}
	return set
}

// TestBuildDirectivesPlacesExceptionsAroundRuleFiles 验证两类误报例外被放在规则文件的正确一侧。
//
// 这是整个例外机制最容易搞错的地方，也是「例外配了但疑似不生效」的根因：
//
//	作用域例外（ctl）→ 必须在规则文件之前，否则目标规则已经执行过了；
//	全局例外（移除类指令）→ 必须在规则文件之后，否则没有规则可移除。
func TestBuildDirectivesPlacesExceptionsAroundRuleFiles(t *testing.T) {
	deps := testDeps(t)
	set := loadRules(t, deps)

	exceptionSet := &exceptions.Set{
		Pre:  []string{`SecRule REQUEST_URI "@rx ^/api/login$" "id:900300,phase:1,pass,nolog,noauditlog,ctl:ruleRemoveById=942100"`},
		Post: []string{"SecRuleRemoveById 941100"},
	}

	directive := buildDirectives(set, deps.Engine, false, exceptionSet)

	firstRuleFile := strings.Index(directive, "Include REQUEST-")
	if firstRuleFile < 0 {
		t.Fatalf("指令中应包含规则文件：%s", directive)
	}
	lastRuleFile := strings.LastIndex(directive, "Include REQUEST-")

	scopedIndex := strings.Index(directive, "ctl:ruleRemoveById=942100")
	globalIndex := strings.Index(directive, "SecRuleRemoveById 941100")

	if scopedIndex < 0 {
		t.Fatalf("指令中应包含作用域例外的 ctl 规则")
	}
	if globalIndex < 0 {
		t.Fatalf("指令中应包含全局例外的移除指令")
	}
	if scopedIndex > firstRuleFile {
		t.Errorf("作用域例外必须排在规则文件之前（ctl 规则需先于目标规则执行）")
	}
	if globalIndex < lastRuleFile {
		t.Errorf("全局例外必须排在规则文件之后（移除类指令只对已解析的规则生效）")
	}
}

// TestBuildDirectivesInjectsAnomalyScoreThreshold 验证异常评分阈值覆盖指令的生成与位置。
func TestBuildDirectivesInjectsAnomalyScoreThreshold(t *testing.T) {
	deps := testDeps(t)
	set := loadRules(t, deps)

	// 与 CRS 默认值一致时不生成动作，避免无意义的指令。
	deps.Engine.AnomalyScoreThreshold = defaultAnomalyScoreThreshold
	baseline := buildDirectives(set, deps.Engine, false, nil)
	if strings.Contains(baseline, "tx.inbound_anomaly_score_threshold=") {
		t.Errorf("阈值等于 CRS 默认值 %d 时不应注入覆盖指令", defaultAnomalyScoreThreshold)
	}

	deps.Engine.AnomalyScoreThreshold = 12
	directive := buildDirectives(set, deps.Engine, false, nil)
	if !strings.Contains(directive, "tx.inbound_anomaly_score_threshold=12") {
		t.Fatalf("阈值应被注入到指令中：%s", directive)
	}
	if !strings.Contains(directive, "id:900110") {
		t.Errorf("阈值覆盖动作应使用固定规则的 ID 900110，便于在规则清单中识别")
	}
	// 与偏执等级覆盖同理：必须排在规则文件之前，否则 CRS 的阻断判定仍用旧值。
	if strings.Index(directive, "tx.inbound_anomaly_score_threshold=12") > strings.Index(directive, "Include REQUEST-") {
		t.Errorf("阈值覆盖必须排在规则文件之前")
	}
}

// TestDetectionOnlyMarksWouldBlock 验证旁路观察模式会标记「本应拦截」。
//
// 判定口径：观察模式下 CRS 的 deny 被抑制，但异常评分照常累计，
// 因此「评分达到阈值」即等价于「开着拦截就会被拦」。
func TestDetectionOnlyMarksWouldBlock(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.Mode = ModeDetectionOnly
	deps.Engine.AnomalyScoreThreshold = 5
	check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{"process_body": false})

	t.Run("命中攻击载荷", func(t *testing.T) {
		rctx := newRequestContext("GET", "/api/user?id=1' OR '1'='1", "", "")
		result, err := check.Evaluate(rctx)
		if err != nil {
			t.Fatalf("Evaluate 返回错误：%v", err)
		}
		if result == nil {
			t.Fatalf("攻击载荷应产生观察结论")
		}
		if result.Verdict != core.VerdictObserve {
			t.Fatalf("期望 VerdictObserve，实际 %s", result.Verdict)
		}
		if !result.WouldBlock {
			t.Fatalf("评分已达到阈值，应标记 WouldBlock（评分 %d）", result.Score)
		}
		// 原因文案需要同时给出「评分 / 阈值」与「首条命中规则」，
		// 前者用于判断阈值是否合适，后者用于定位是哪条规则把评分顶上来的。
		if !strings.Contains(result.WouldBlockReason, "达到阈值 5") {
			t.Errorf("WouldBlockReason 应给出评分与阈值，实际：%q", result.WouldBlockReason)
		}
		if !strings.Contains(result.WouldBlockReason, "首条命中规则") {
			t.Errorf("WouldBlockReason 应指出首条命中规则，实际：%q", result.WouldBlockReason)
		}
		if len(result.Findings) == 0 {
			t.Errorf("标记 WouldBlock 时应同时保留命中明细")
		}
	})

	t.Run("良性请求", func(t *testing.T) {
		rctx := newRequestContext("GET", "/api/user?id=42", "", "")
		result, err := check.Evaluate(rctx)
		if err != nil {
			t.Fatalf("Evaluate 返回错误：%v", err)
		}
		if result != nil && result.WouldBlock {
			t.Fatalf("良性请求不应被标记为 WouldBlock：%+v", result)
		}
	})
}

// TestDetectionOnlyWouldBlockRespectsThreshold 验证阈值提高后同样的请求不再被判为「本应拦截」。
func TestDetectionOnlyWouldBlockRespectsThreshold(t *testing.T) {
	deps := testDeps(t)
	deps.Engine.Mode = ModeDetectionOnly
	// 抬高到远超单条 CRITICAL 规则的评分，让同一次请求不再越过阈值。
	deps.Engine.AnomalyScoreThreshold = 100
	check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{"process_body": false})

	rctx := newRequestContext("GET", "/api/user?id=1' OR '1'='1", "", "")
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil {
		t.Fatalf("攻击载荷应产生观察结论")
	}
	if result.WouldBlock {
		t.Fatalf("评分未达到抬高后的阈值时不应标记 WouldBlock：score=%d", result.Score)
	}
}

// TestExceptionsSuppressRuleByID 验证两类例外真的能让目标规则停止命中。
//
// 这是对「指令顺序知识」的端到端验证：只要 Pre / Post 放错一侧，
// 下面的断言就会失败（配置语法全部合法，但例外不生效——最难发现的一类问题）。
func TestExceptionsSuppressRuleByID(t *testing.T) {
	payload := "/api/user?id=1' OR '1'='1"

	// 基线：未配置任何例外时，942100 必须命中。
	baselineDeps := testDeps(t)
	baselineCheck := newCheck(t, baselineDeps, "crs-header", core.PhaseRequest, map[string]any{"process_body": false})
	baseline := newRequestContext("GET", payload, "", "")
	baselineResult, err := baselineCheck.Evaluate(baseline)
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if baselineResult == nil || !hasFinding(baselineResult, "942100") {
		t.Fatalf("基线用例应命中 942100，实际：%+v", baselineResult)
	}

	cases := []struct {
		name       string
		exception  core.ExceptionSetting
		expectRule string
	}{
		{
			name: "全局例外（规则文件之后的移除指令）",
			exception: core.ExceptionSetting{
				Name: "全局放行 942100", Enabled: true, Reason: "测试", RuleIDs: []string{"942100"},
			},
		},
		{
			name: "作用域例外（规则文件之前的 ctl 规则）",
			exception: core.ExceptionSetting{
				Name: "GET 请求放行 942100", Enabled: true, Reason: "测试",
				RuleIDs: []string{"942100"}, Methods: []string{"GET"},
			},
		},
		{
			name: "未启用的例外不应生效",
			exception: core.ExceptionSetting{
				Name: "被关闭的例外", Enabled: false, Reason: "测试", RuleIDs: []string{"942100"},
			},
			expectRule: "942100",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			deps := testDeps(t)
			deps.Engine.Exceptions = []core.ExceptionSetting{testCase.exception}
			check := newCheck(t, deps, "crs-header", core.PhaseRequest, map[string]any{"process_body": false})

			rctx := newRequestContext("GET", payload, "", "")
			result, err := check.Evaluate(rctx)
			if err != nil {
				t.Fatalf("Evaluate 返回错误：%v", err)
			}

			hit := result != nil && hasFinding(result, "942100")
			if testCase.expectRule == "" && hit {
				t.Fatalf("例外生效后 942100 不应再命中，实际：%+v", findingsOf(result))
			}
			if testCase.expectRule != "" && !hit {
				t.Fatalf("例外未生效时 942100 应命中，实际：%+v", findingsOf(result))
			}
		})
	}
}

// hasFinding 判断命中明细中是否存在指定规则 ID。
func hasFinding(result *core.Result, ruleID string) bool {
	if result == nil {
		return false
	}
	for _, finding := range result.Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

// findingsOf 提取命中规则的 ID 列表，用于断言失败时排障。
func findingsOf(result *core.Result) []string {
	if result == nil {
		return nil
	}
	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}
