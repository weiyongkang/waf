// Package exceptions 把「误报例外」声明编译为 SecLang 指令（需求 R6 / P1-4）。
//
// 为什么需要独立的编译步骤，而不是让运维直接写 SecRuleRemoveById：
//
//  1. 直接写 SecLang 没有任何约束：写错一个 ID 就会静默地多关掉一条防护，
//     而且完全没有审计线索（谁、为什么、什么时候关的）。
//     本包强制每条例外带 name 与 reason，并把编译结果输出成可审计的清单。
//
//  2. 作用域例外的正确写法很容易搞错（ctl 规则必须放在规则文件之前，
//     静态移除指令必须放在规则文件之后）。把「顺序」这一层知识固化在编译器里，
//     可以让运维只关心「在哪个 URL 上放行哪条规则」。
//
//  3. 临时例外需要过期机制。用声明式配置 + 编译期判定过期，
//     比让运维手工记得删除规则更可靠。
//
// 两类例外的机制差异（顺序要求完全相反，这是本包最容易踩的坑）：
//
//	全局例外（无 url_pattern 且无 methods）
//	    → SecRuleRemoveById / SecRuleRemoveByTag / SecRuleUpdateTargetById
//	    这些是「配置期指令」，只对**已经解析出来的规则**生效，
//	    因此必须排在全部规则文件之后（Post 段）。
//
//	作用域例外（指定了 url_pattern 或 methods）
//	    → phase:1 的 ctl 规则（ctl:ruleRemoveById / ctl:ruleRemoveByTag /
//	      ctl:ruleRemoveTargetById）
//	    同一 phase 内的规则按出现顺序求值，ctl 必须先执行才能影响目标规则，
//	    因此必须排在全部规则文件之前（Pre 段）。
package exceptions

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// 生成规则 ID 的约定。
//
// 本项目在 CRS 保留段内分配自己的规则 ID，避免与 CRS 冲突：
//
//	900000 / 900001   CRS crs-setup.conf 占用
//	900100            偏执等级覆盖动作（internal/check/coraza）
//	900200 起         请求体处理器路由（internal/check/coraza）
//	900300 起         本包生成的「作用域例外」ctl 规则
const (
	// scopeRuleIDBase 是作用域例外 ctl 规则的起始 ID。
	scopeRuleIDBase = 900300
)

// Status 表示一条例外的编译结果状态。
//
// 之所以把状态显式建模：运维最关心「我写的例外到底生效没有」，
// 而「被 enabled=false 关闭」「已过期」与「语法错误」的处理方式完全不同。
type Status string

const (
	// StatusApplied 表示该例外已编译为指令并生效。
	StatusApplied Status = "applied"
	// StatusDisabled 表示该例外因 enabled=false 未生效（声明被保留，只用于审计输出）。
	//
	// 注意默认值语义：配置文件里不写 enabled 即为 false，也就是「例外默认不生效」。
	// 这是刻意选择的安全默认——例外等于关闭部分防护，必须显式打开。
	StatusDisabled Status = "disabled"
	// StatusExpired 表示该例外已超过 expires_at，自动失效。
	StatusExpired Status = "expired"
)

// Entry 是一条例外的编译结果，用于日志与审计报表。
type Entry struct {
	// Name 是例外的审计标识。
	Name string
	// Reason 是例外原因。
	Reason string
	// Status 是编译结果状态。
	Status Status
	// Scope 是作用范围的可读描述（例如 "全局" 或 "URL=^/api/login; 方法=POST"）。
	Scope string
	// Directives 是该例外编译出的指令（Status != StatusApplied 时为空）。
	Directives []string
}

// Set 是编译完成的例外集合。
type Set struct {
	// Pre 是需要放在规则文件**之前**的指令（作用域例外的 ctl 规则）。
	Pre []string
	// Post 是需要放在规则文件**之后**的指令（全局例外的静态移除指令）。
	Post []string
	// Entries 是全部例外的编译结果（含未生效的），用于审计输出。
	Entries []Entry
	// Applied 是实际生效的例外条数。
	Applied int
}

// Options 是编译参数。
type Options struct {
	// Now 是「判断例外是否过期」的基准时间；为零值时使用 time.Now()。
	//
	// 之所以可注入：过期判定必须能被单元测试稳定复现，
	// 不允许依赖「跑测试时的真实时间」。
	Now time.Time
}

// Compile 把例外声明编译为 SecLang 指令。
//
// 返回值语义：只要配置本身合法就一定返回 (set, nil)；
// 单条例外因「未启用 / 已过期」而失效不算错误（属于预期的配置状态）。
// 配置非法（缺 name、缺 reason、正则错误、无作用维度）会返回错误。
func Compile(items []core.ExceptionSetting, opts Options) (*Set, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	set := &Set{
		Pre:     make([]string, 0, len(items)),
		Post:    make([]string, 0, len(items)),
		Entries: make([]Entry, 0, len(items)),
	}

	nextRuleID := scopeRuleIDBase

	for index, item := range items {
		entry, err := compileOne(item, index, now, &nextRuleID)
		if err != nil {
			return nil, err
		}
		set.Entries = append(set.Entries, entry)

		if entry.Status != StatusApplied {
			continue
		}
		// 依据指令特征分流到 Pre / Post：作用域例外生成的是 SecRule（ctl 规则），
		// 全局例外生成的是 SecRuleRemoveXxx / SecRuleUpdateTargetXxx 静态指令。
		set.Applied++
		for _, directive := range entry.Directives {
			if strings.HasPrefix(directive, "SecRule ") {
				set.Pre = append(set.Pre, directive)
				continue
			}
			set.Post = append(set.Post, directive)
		}
	}

	return set, nil
}

// compileOne 编译单条例外声明。
func compileOne(item core.ExceptionSetting, index int, now time.Time, nextRuleID *int) (Entry, error) {
	name := strings.TrimSpace(item.Name)
	entry := Entry{Name: name, Reason: strings.TrimSpace(item.Reason)}

	// 配置层面的硬约束在此再校验一次：本包可以脱离 config 包单独使用
	// （例如单元测试或未来从 API 写入例外），不能假设调用方已经校验过。
	if name == "" {
		return entry, fmt.Errorf("例外的 name 不能为空（engine.exceptions[%d]）", index)
	}
	if entry.Reason == "" {
		return entry, fmt.Errorf("例外 %q 必须填写 reason，用于审计留档", name)
	}
	if len(item.RuleIDs) == 0 && len(item.Tags) == 0 && len(item.Targets) == 0 {
		return entry, fmt.Errorf("例外 %q 至少要声明 rule_ids / tags / targets 之一", name)
	}
	if len(item.Targets) > 0 && len(item.RuleIDs) == 0 {
		return entry, fmt.Errorf("例外 %q 声明了 targets 但未声明 rule_ids（摘除目标必须指定规则）", name)
	}
	// URL 正则在此处编译校验：本包允许脱离 config 包单独使用，
	// 因此不能假设调用方已经做过配置校验（否则非法正则会一路带到 SecLang 解析阶段，
	// 报错信息里只剩引擎的语法错误，定位成本高得多）。
	if err := ValidatePattern(item.URLPattern); err != nil {
		return entry, fmt.Errorf("例外 %q 配置非法：%w", name, err)
	}

	// 过期判定优先于启用开关：过期的例外无论是否 enabled 都不应生效，
	// 状态区分开是为了让审计报表能看出「这条是过期失效，不是被人为关闭」。
	if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
		entry.Status = StatusExpired
		entry.Scope = scopeLabel(item)
		return entry, nil
	}
	if !item.Enabled {
		entry.Status = StatusDisabled
		entry.Scope = scopeLabel(item)
		return entry, nil
	}

	scoped := strings.TrimSpace(item.URLPattern) != "" || len(item.Methods) > 0
	entry.Scope = scopeLabel(item)

	directives, err := buildDirectives(item, scoped, nextRuleID)
	if err != nil {
		return entry, fmt.Errorf("例外 %q 编译失败：%w", name, err)
	}
	entry.Directives = directives
	entry.Status = StatusApplied
	return entry, nil
}

// buildDirectives 生成单条例外的指令列表。
//
// 生成策略：
//   - 全局例外：每个规则 ID / 标签 / 目标各生成一条静态指令（不使用合并语法，
//     因为合并语法在不同引擎版本的解析细节上不一致，逐条生成最可预期）；
//   - 作用域例外：每个「动作维度 × 取值」生成一条 phase:1 的 ctl 规则，
//     URL 与方法条件通过 chain 组合（链式规则的首条承载全部动作）。
func buildDirectives(item core.ExceptionSetting, scoped bool, nextRuleID *int) ([]string, error) {
	if !scoped {
		return globalDirectives(item)
	}
	return scopedDirectives(item, nextRuleID)
}

// globalDirectives 生成全局例外指令（必须放在规则文件之后）。
func globalDirectives(item core.ExceptionSetting) ([]string, error) {
	directives := make([]string, 0, len(item.RuleIDs)+len(item.Tags))

	for _, id := range item.RuleIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			directives = append(directives, "SecRuleRemoveById "+trimmed)
		}
	}
	for _, tag := range item.Tags {
		if trimmed := strings.TrimSpace(tag); trimmed != "" {
			directives = append(directives, "SecRuleRemoveByTag "+trimmed)
		}
	}
	// 摘除检测目标：每个「规则 × 目标」一条，语义是「规则保留、不再检查该参数」。
	for _, id := range item.RuleIDs {
		ruleID := strings.TrimSpace(id)
		if ruleID == "" {
			continue
		}
		for _, target := range item.Targets {
			if trimmed := strings.TrimSpace(target); trimmed != "" {
				directives = append(directives,
					fmt.Sprintf("SecRuleUpdateTargetById %s \"!%s\"", ruleID, trimmed))
			}
		}
	}
	if len(directives) == 0 {
		return nil, errors.New("没有生成任何指令（规则 ID / 标签均为空）")
	}
	return directives, nil
}

// scopedDirectives 生成作用域例外的 ctl 规则（必须放在规则文件之前）。
func scopedDirectives(item core.ExceptionSetting, nextRuleID *int) ([]string, error) {
	actions := make([]string, 0, len(item.RuleIDs)+len(item.Tags)+len(item.Targets))

	for _, id := range item.RuleIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			actions = append(actions, "ctl:ruleRemoveById="+trimmed)
		}
	}
	for _, tag := range item.Tags {
		if trimmed := strings.TrimSpace(tag); trimmed != "" {
			actions = append(actions, "ctl:ruleRemoveByTag="+trimmed)
		}
	}
	for _, id := range item.RuleIDs {
		ruleID := strings.TrimSpace(id)
		if ruleID == "" {
			continue
		}
		for _, target := range item.Targets {
			if trimmed := strings.TrimSpace(target); trimmed != "" {
				actions = append(actions, fmt.Sprintf("ctl:ruleRemoveTargetById=%s;%s", ruleID, trimmed))
			}
		}
	}
	if len(actions) == 0 {
		return nil, errors.New("没有生成任何 ctl 动作（规则 ID / 标签均为空）")
	}

	directives := make([]string, 0, len(actions))
	for _, action := range actions {
		ruleID := *nextRuleID
		*nextRuleID = ruleID + 1

		// 每条例外用独立规则承载单个 ctl 动作：多条 ctl 写在同一条规则里虽然合法，
		// 但一旦其中某个动作在目标引擎上不被支持，整条规则会加载失败，
		// 逐条拆分可以把影响面收敛到单个动作（并且日志里能精确定位是哪条）。
		header := fmt.Sprintf("id:%d,phase:1,pass,nolog,noauditlog,%s", ruleID, action)
		if directive, ok := scopedRule(item, header); ok {
			directives = append(directives, directive)
		}
	}
	return directives, nil
}

// scopedRule 依据 URL / 方法条件生成一条 phase:1 的 ctl 规则。
//
// 条件组合方式：
//
//	仅 URL   → SecRule REQUEST_URI "@rx <pattern>" "<actions>"
//	仅方法   → SecRule REQUEST_METHOD "@rx ^(?i:GET|POST)$" "<actions>"
//	两者都有 → 首条使用 chain，第二条只带变量与算子（标准链式写法）
func scopedRule(item core.ExceptionSetting, header string) (string, bool) {
	pattern := strings.TrimSpace(item.URLPattern)
	methods := normaliseMethods(item.Methods)

	switch {
	case pattern != "" && len(methods) > 0:
		// 链式规则：首条承载全部动作（含 chain），第二条只有目标与算子。
		return fmt.Sprintf(
			"SecRule REQUEST_METHOD \"@rx %s\" \"%s,chain\"\n    SecRule REQUEST_URI \"@rx %s\" \"t:none\"",
			methodPattern(methods), header, pattern,
		), true
	case pattern != "":
		return fmt.Sprintf("SecRule REQUEST_URI \"@rx %s\" \"%s\"", pattern, header), true
	case len(methods) > 0:
		return fmt.Sprintf("SecRule REQUEST_METHOD \"@rx %s\" \"%s\"", methodPattern(methods), header), true
	default:
		return "", false
	}
}

// methodPattern 生成方法白名单正则。
//
// 使用非捕获组 + 大小写不敏感标志：HTTP 方法按 RFC 是大小写敏感的，
// 但实际中间层常出现小写（例如部分客户端库），这里放宽以免例外「莫名不生效」。
func methodPattern(methods []string) string {
	return "^(?i:" + strings.Join(methods, "|") + ")$"
}

// normaliseMethods 归一化方法列表：去空白、转大写、去重、排序。
//
// 排序的目的不是语义需要，而是让「同样的配置生成同样的指令文本」，
// 从而保证配置哈希、日志 diff 与测试断言都是稳定的。
func normaliseMethods(methods []string) []string {
	seen := make(map[string]struct{}, len(methods))
	cleaned := make([]string, 0, len(methods))
	for _, method := range methods {
		upper := strings.ToUpper(strings.TrimSpace(method))
		if upper == "" {
			continue
		}
		if _, exists := seen[upper]; exists {
			continue
		}
		seen[upper] = struct{}{}
		cleaned = append(cleaned, upper)
	}
	sort.Strings(cleaned)
	return cleaned
}

// scopeLabel 生成作用范围的可读描述。
func scopeLabel(item core.ExceptionSetting) string {
	pattern := strings.TrimSpace(item.URLPattern)
	methods := normaliseMethods(item.Methods)

	parts := make([]string, 0, 2)
	if pattern != "" {
		parts = append(parts, "URL="+pattern)
	}
	if len(methods) > 0 {
		parts = append(parts, "方法="+strings.Join(methods, ","))
	}
	if len(parts) == 0 {
		return "全局"
	}
	return strings.Join(parts, "; ")
}

// ValidatePattern 报告 URL 正则是否可编译。
//
// 单独导出便于配置校验与 CLI 复用，避免两处各写一遍编译逻辑。
func ValidatePattern(pattern string) error {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return nil
	}
	if _, err := regexp.Compile(trimmed); err != nil {
		return fmt.Errorf("URL 正则 %q 非法：%w", trimmed, err)
	}
	return nil
}
