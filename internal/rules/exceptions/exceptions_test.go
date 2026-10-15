package exceptions

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// now 是全部用例共用的「当前时间」，让过期判定完全可复现。
var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// enabled 构造一条启用状态的例外声明，具体用例在其基础上覆盖字段。
func enabled(name string) core.ExceptionSetting {
	return core.ExceptionSetting{
		Name:    name,
		Enabled: true,
		Reason:  "测试用例",
		RuleIDs: []string{"942100"},
	}
}

// contains 判断 slice 中是否存在完全匹配的元素。
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// containsPrefix 判断 slice 中是否存在以指定前缀开头的元素。
func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// TestCompileGlobalExceptionGoesToPost 覆盖：全局例外生成静态移除指令，并落入 Post 段。
//
// 顺序要求的原因：SecRuleRemoveById 这类指令是「配置期指令」，
// 只对已经解析出来的规则生效，因此必须排在规则文件之后。
func TestCompileGlobalExceptionGoesToPost(t *testing.T) {
	item := enabled("关闭登录接口的 SQLi 规则")
	item.RuleIDs = []string{"942100", "942110"}
	item.Tags = []string{"attack-sqli"}
	item.Targets = []string{"ARGS:password"}

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}

	if len(set.Pre) != 0 {
		t.Fatalf("全局例外不应产生 Pre 段指令，实际：%v", set.Pre)
	}
	for _, want := range []string{
		"SecRuleRemoveById 942100",
		"SecRuleRemoveById 942110",
		"SecRuleRemoveByTag attack-sqli",
		`SecRuleUpdateTargetById 942100 "!ARGS:password"`,
		`SecRuleUpdateTargetById 942110 "!ARGS:password"`,
	} {
		if !contains(set.Post, want) {
			t.Errorf("Post 段缺少指令 %q，实际：%v", want, set.Post)
		}
	}
	if set.Applied != 1 {
		t.Fatalf("Applied = %d，期望 1", set.Applied)
	}
	if len(set.Entries) != 1 || set.Entries[0].Status != StatusApplied {
		t.Fatalf("Entries = %+v，期望单条 applied 记录", set.Entries)
	}
	if set.Entries[0].Scope != "全局" {
		t.Fatalf("Scope = %q，期望 全局", set.Entries[0].Scope)
	}
}

// TestCompileScopedExceptionGoesToPre 覆盖：作用域例外生成 phase:1 的 ctl 规则，并落入 Pre 段。
//
// 顺序要求的原因：同一 phase 内规则按出现顺序求值，ctl 必须先执行才能影响目标规则。
func TestCompileScopedExceptionGoesToPre(t *testing.T) {
	item := enabled("登录接口放行 XSS 规则")
	item.RuleIDs = []string{"941100"}
	item.URLPattern = "^/api/login$"

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}

	if len(set.Post) != 0 {
		t.Fatalf("作用域例外不应产生 Post 段指令，实际：%v", set.Post)
	}
	if len(set.Pre) != 1 {
		t.Fatalf("Pre 段指令数量 = %d，期望 1：%v", len(set.Pre), set.Pre)
	}

	directive := set.Pre[0]
	if !strings.HasPrefix(directive, "SecRule REQUEST_URI ") {
		t.Errorf("仅声明 URL 时应以 REQUEST_URI 为变量，实际：%s", directive)
	}
	for _, want := range []string{
		"^/api/login$",
		"id:900300",
		"phase:1",
		"ctl:ruleRemoveById=941100",
	} {
		if !strings.Contains(directive, want) {
			t.Errorf("指令缺少 %q，实际：%s", want, directive)
		}
	}
}

// TestCompileScopedExceptionMethodOnly 覆盖：只声明方法时以 REQUEST_METHOD 为变量。
func TestCompileScopedExceptionMethodOnly(t *testing.T) {
	item := enabled("仅 POST 放行")
	item.Methods = []string{"post", "GET", "get"}

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if len(set.Pre) != 1 {
		t.Fatalf("Pre 段指令数量 = %d，期望 1：%v", len(set.Pre), set.Pre)
	}

	directive := set.Pre[0]
	// 方法需要归一化：去重、转大写、排序，保证同样的配置生成同样的指令文本。
	if !strings.Contains(directive, `@rx ^(?i:GET|POST)$`) {
		t.Errorf("方法正则应为归一化后的 ^(?i:GET|POST)$，实际：%s", directive)
	}
	if set.Entries[0].Scope != "方法=GET,POST" {
		t.Errorf("Scope = %q，期望 方法=GET,POST", set.Entries[0].Scope)
	}
}

// TestCompileScopedExceptionURLAndMethodUsesChain 覆盖：同时声明 URL 与方法时生成链式规则。
func TestCompileScopedExceptionURLAndMethodUsesChain(t *testing.T) {
	item := enabled("登录接口仅 POST 放行")
	item.RuleIDs = []string{"942100"}
	item.URLPattern = "^/api/login"
	item.Methods = []string{"POST"}

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if len(set.Pre) != 1 {
		t.Fatalf("Pre 段指令数量 = %d，期望 1：%v", len(set.Pre), set.Pre)
	}

	directive := set.Pre[0]
	lines := strings.Split(directive, "\n")
	if len(lines) != 2 {
		t.Fatalf("链式规则应包含两条 SecRule（换行分隔），实际：%s", directive)
	}
	// 首条承载全部动作（含 chain），第二条只带目标与算子。
	if !strings.HasPrefix(lines[0], `SecRule REQUEST_METHOD "@rx ^(?i:POST)$"`) {
		t.Errorf("链式规则首条应以 REQUEST_METHOD 开头，实际：%s", lines[0])
	}
	if !strings.Contains(lines[0], ",chain") {
		t.Errorf("链式规则首条应带 chain 动作，实际：%s", lines[0])
	}
	// 链式规则的第二条带缩进（SecLang 的链式写法惯例），断言前先去掉首尾空白。
	if !strings.HasPrefix(strings.TrimSpace(lines[1]), `SecRule REQUEST_URI "@rx ^/api/login"`) {
		t.Errorf("链式规则第二条应以 REQUEST_URI 开头，实际：%s", lines[1])
	}
	if strings.Contains(lines[1], "ctl:") {
		t.Errorf("链式规则的动作只能出现在首条，实际：%s", lines[1])
	}
	if set.Entries[0].Scope != "URL=^/api/login; 方法=POST" {
		t.Errorf("Scope = %q，期望 URL=^/api/login; 方法=POST", set.Entries[0].Scope)
	}
}

// TestCompileScopedExceptionSplitsOneRulePerAction 覆盖：每个动作独立成一条规则，ID 递增。
//
// 逐条拆分的目的：某个 ctl 动作在目标引擎上不被支持时，
// 只影响那一条规则，而不是让承载多个动作的整条规则一起加载失败。
func TestCompileScopedExceptionSplitsOneRulePerAction(t *testing.T) {
	item := enabled("多动作作用域例外")
	item.RuleIDs = []string{"942100", "941100"}
	item.Tags = []string{"attack-xss"}
	item.Targets = []string{"ARGS:comment"}
	item.Methods = []string{"POST"}

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}

	// 动作数量：2 个 rule_ids + 1 个 tag + (2 个 rule_ids × 1 个 target) = 5。
	if len(set.Pre) != 5 {
		t.Fatalf("Pre 段指令数量 = %d，期望 5：%v", len(set.Pre), set.Pre)
	}
	for index, directive := range set.Pre {
		expected := scopeRuleIDBase + index
		if !strings.Contains(directive, "id:"+strconv.Itoa(expected)) {
			t.Errorf("第 %d 条指令的 ID 期望 %d，实际：%s", index, expected, directive)
		}
		if strings.Count(directive, "ctl:") != 1 {
			t.Errorf("每条规则应只承载一个 ctl 动作，实际：%s", directive)
		}
	}
	if !containsPrefix(set.Pre, "SecRule REQUEST_METHOD") {
		t.Errorf("作用域例外的全部指令都应受方法条件约束，实际：%v", set.Pre)
	}
}

// TestCompileExpiredExceptionIsInert 覆盖：已过期的例外不产生指令，状态为 expired。
func TestCompileExpiredExceptionIsInert(t *testing.T) {
	item := enabled("临时放行")
	item.ExpiresAt = now.Add(-time.Hour)

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("过期例外不应导致编译失败：%v", err)
	}
	if len(set.Pre) != 0 || len(set.Post) != 0 {
		t.Fatalf("过期例外不应产生任何指令，实际 Pre=%v Post=%v", set.Pre, set.Post)
	}
	if set.Applied != 0 {
		t.Fatalf("Applied = %d，期望 0", set.Applied)
	}
	if set.Entries[0].Status != StatusExpired {
		t.Fatalf("Status = %q，期望 expired", set.Entries[0].Status)
	}
}

// TestCompileDisabledExceptionIsInert 覆盖：enabled=false 的例外不产生指令，状态为 disabled。
func TestCompileDisabledExceptionIsInert(t *testing.T) {
	item := enabled("被临时关闭的例外")
	item.Enabled = false

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("未启用的例外不应导致编译失败：%v", err)
	}
	if len(set.Pre) != 0 || len(set.Post) != 0 {
		t.Fatalf("未启用的例外不应产生任何指令，实际 Pre=%v Post=%v", set.Pre, set.Post)
	}
	if set.Entries[0].Status != StatusDisabled {
		t.Fatalf("Status = %q，期望 disabled", set.Entries[0].Status)
	}
}

// TestCompileExpiredTakesPriorityOverDisabled 覆盖：既过期又未启用时状态为 expired。
//
// 区分两者的意义：审计报表要能回答「这条是到期自动失效，还是被人为关掉了」。
func TestCompileExpiredTakesPriorityOverDisabled(t *testing.T) {
	item := enabled("过期且被关闭")
	item.Enabled = false
	item.ExpiresAt = now.Add(-time.Minute)

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if set.Entries[0].Status != StatusExpired {
		t.Fatalf("Status = %q，期望 expired（过期判定优先于启用开关）", set.Entries[0].Status)
	}
}

// TestCompileFutureExpiryStaysApplied 覆盖：未到期的例外正常生效。
func TestCompileFutureExpiryStaysApplied(t *testing.T) {
	item := enabled("尚未到期的例外")
	item.ExpiresAt = now.Add(24 * time.Hour)

	set, err := Compile([]core.ExceptionSetting{item}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if set.Entries[0].Status != StatusApplied {
		t.Fatalf("Status = %q，期望 applied", set.Entries[0].Status)
	}
}

// TestCompileRejectsInvalidDeclarations 覆盖各类非法声明：必须报错而不是静默跳过。
func TestCompileRejectsInvalidDeclarations(t *testing.T) {
	cases := []struct {
		name  string
		item  core.ExceptionSetting
		match string
	}{
		{
			name:  "缺少 name",
			item:  core.ExceptionSetting{Enabled: true, Reason: "有原因", RuleIDs: []string{"942100"}},
			match: "name",
		},
		{
			name:  "缺少 reason",
			item:  core.ExceptionSetting{Name: "没有原因", Enabled: true, RuleIDs: []string{"942100"}},
			match: "reason",
		},
		{
			name:  "没有任何作用维度",
			item:  core.ExceptionSetting{Name: "空例外", Enabled: true, Reason: "有原因"},
			match: "rule_ids",
		},
		{
			name: "targets 缺少 rule_ids",
			item: core.ExceptionSetting{
				Name: "摘除目标但没指定规则", Enabled: true, Reason: "有原因",
				Targets: []string{"ARGS:password"},
			},
			match: "rule_ids",
		},
		{
			name: "URL 正则非法",
			item: core.ExceptionSetting{
				Name: "正则写错", Enabled: true, Reason: "有原因",
				RuleIDs: []string{"942100"}, URLPattern: "(?<bad",
			},
			match: "URL 正则",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Compile([]core.ExceptionSetting{testCase.item}, Options{Now: now})
			if err == nil {
				t.Fatalf("非法配置应导致编译失败")
			}
			if !strings.Contains(err.Error(), testCase.match) {
				t.Fatalf("错误信息应包含 %q，实际：%v", testCase.match, err)
			}
		})
	}
}

// TestCompileAssignsSequentialRuleIDsAcrossExceptions 覆盖：多条作用域例外共用同一个 ID 计数。
//
// 之所以要保证全链唯一：ctl 规则本身就是普通规则，ID 重复会让引擎加载失败或互相覆盖。
func TestCompileAssignsSequentialRuleIDsAcrossExceptions(t *testing.T) {
	first := enabled("第一条例外")
	first.Methods = []string{"GET"}
	second := enabled("第二条例外")
	second.Methods = []string{"POST"}

	set, err := Compile([]core.ExceptionSetting{first, second}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if len(set.Pre) != 2 {
		t.Fatalf("Pre 段指令数量 = %d，期望 2：%v", len(set.Pre), set.Pre)
	}
	if !strings.Contains(set.Pre[0], "id:900300") {
		t.Errorf("第一条指令 ID 期望 900300，实际：%s", set.Pre[0])
	}
	if !strings.Contains(set.Pre[1], "id:900301") {
		t.Errorf("第二条指令 ID 期望 900301，实际：%s", set.Pre[1])
	}
	// 无论生效与否，全部声明都要出现在审计清单里。
	if len(set.Entries) != 2 {
		t.Fatalf("Entries 数量 = %d，期望 2", len(set.Entries))
	}
}

// TestCompilePreAndPostAreDisjoint 覆盖：Pre 段全是 ctl 规则，Post 段全是静态移除指令。
//
// 这条不变式是「顺序正确性」的守门人：一旦两类指令串到同一段，
// 轻则例外不生效，重则整份规则集加载失败。
func TestCompilePreAndPostAreDisjoint(t *testing.T) {
	global := enabled("全局例外")
	global.Tags = []string{"attack-sqli"}
	scoped := enabled("作用域例外")
	scoped.Methods = []string{"POST"}

	set, err := Compile([]core.ExceptionSetting{global, scoped}, Options{Now: now})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if len(set.Pre) == 0 || len(set.Post) == 0 {
		t.Fatalf("本用例应同时产生 Pre 与 Post 指令，实际 Pre=%v Post=%v", set.Pre, set.Post)
	}
	for _, directive := range set.Pre {
		if !strings.HasPrefix(directive, "SecRule ") {
			t.Errorf("Pre 段只应包含 ctl 规则，实际：%s", directive)
		}
	}
	for _, directive := range set.Post {
		if !strings.HasPrefix(directive, "SecRuleRemove") && !strings.HasPrefix(directive, "SecRuleUpdateTarget") {
			t.Errorf("Post 段只应包含静态移除指令，实际：%s", directive)
		}
	}
	if set.Applied != 2 {
		t.Fatalf("Applied = %d，期望 2", set.Applied)
	}
}

// TestCompileEmptyInput 覆盖：空清单编译为空集合且不报错。
func TestCompileEmptyInput(t *testing.T) {
	set, err := Compile(nil, Options{Now: now})
	if err != nil {
		t.Fatalf("空清单不应报错：%v", err)
	}
	if len(set.Pre) != 0 || len(set.Post) != 0 || len(set.Entries) != 0 || set.Applied != 0 {
		t.Fatalf("空清单应产生空集合，实际：%+v", set)
	}
}

// TestCompileUsesCurrentTimeWhenNowIsZero 覆盖：未注入基准时间时使用真实时间（零值分支）。
func TestCompileUsesCurrentTimeWhenNowIsZero(t *testing.T) {
	item := enabled("长期例外")
	item.ExpiresAt = time.Now().Add(-time.Hour)

	set, err := Compile([]core.ExceptionSetting{item}, Options{})
	if err != nil {
		t.Fatalf("编译例外失败：%v", err)
	}
	if set.Entries[0].Status != StatusExpired {
		t.Fatalf("Status = %q，期望 expired（应按真实时间判定）", set.Entries[0].Status)
	}
}

// TestValidatePattern 覆盖 URL 正则校验的四种输入。
func TestValidatePattern(t *testing.T) {
	if err := ValidatePattern(""); err != nil {
		t.Errorf("空正则应视为合法，实际：%v", err)
	}
	if err := ValidatePattern("   "); err != nil {
		t.Errorf("空白正则应视为合法，实际：%v", err)
	}
	if err := ValidatePattern("^/api/login$"); err != nil {
		t.Errorf("合法正则不应报错，实际：%v", err)
	}
	if err := ValidatePattern("(?<bad"); err == nil {
		t.Errorf("非法正则应报错")
	}
}
