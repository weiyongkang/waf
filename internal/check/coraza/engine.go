package coraza

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
	"github.com/weiyongkang/waf/internal/rules/exceptions"
)

// resolveEngine 把「全局 engine 配置 + 实例级覆盖」合并为最终生效的引擎配置。
//
// 合并规则（全部字段都可选，未配置即继承）：
//
//	字符串 / 整数：为空或 <= 0 时继承（因为这些字段不存在「合法的零值」）；
//	切片：        nil 时继承；显式写 [] 表示「清空」（用于切回内置规则集）；
//	布尔：        用指针区分「未配置」与「显式配置为 false」。
func resolveEngine(engine core.EngineSettings, settings Settings) (core.EngineSettings, error) {
	effective := engine

	if mode := strings.TrimSpace(settings.Mode); mode != "" {
		effective.Mode = mode
	}
	switch effective.Mode {
	case ModeOn, ModeDetectionOnly:
	default:
		return effective, fmt.Errorf(
			"引擎模式 %q 非法，可选值：%s / %s", effective.Mode, ModeOn, ModeDetectionOnly,
		)
	}

	if settings.ParanoiaLevel > 0 {
		effective.ParanoiaLevel = settings.ParanoiaLevel
	}
	if effective.ParanoiaLevel < 1 || effective.ParanoiaLevel > 4 {
		return effective, fmt.Errorf(
			"偏执等级 paranoia_level=%d 非法，可选值：1 / 2 / 3 / 4", effective.ParanoiaLevel,
		)
	}

	if settings.RuleDirs != nil {
		effective.RuleDirs = settings.RuleDirs
	}
	if settings.CustomRuleDirs != nil {
		effective.CustomRuleDirs = settings.CustomRuleDirs
	}
	if settings.InlineDirectives != nil {
		effective.InlineDirectives = settings.InlineDirectives
	}
	if settings.VirtualPatches != nil {
		effective.VirtualPatches = settings.VirtualPatches
	}
	if settings.VirtualPatchFiles != nil {
		effective.VirtualPatchFiles = settings.VirtualPatchFiles
	}
	if settings.BodyAccess != nil {
		effective.BodyAccess = *settings.BodyAccess
	}
	if settings.BodyLimitBytes > 0 {
		effective.BodyLimitBytes = settings.BodyLimitBytes
	}
	if settings.BodyInMemoryLimitBytes > 0 {
		effective.BodyInMemoryLimitBytes = settings.BodyInMemoryLimitBytes
	}
	if settings.ParseMultipart != nil {
		effective.ParseMultipart = *settings.ParseMultipart
	}
	if settings.BodyProcessors != nil {
		effective.Processors = settings.BodyProcessors
	}

	if effective.BodyLimitBytes <= 0 {
		return effective, fmt.Errorf("请求体上限 body_limit_bytes=%d 非法，必须大于 0", effective.BodyLimitBytes)
	}
	if effective.BodyInMemoryLimitBytes <= 0 {
		return effective, fmt.Errorf(
			"请求体内存上限 body_in_memory_limit_bytes=%d 非法，必须大于 0", effective.BodyInMemoryLimitBytes,
		)
	}
	if effective.BodyInMemoryLimitBytes > effective.BodyLimitBytes {
		return effective, fmt.Errorf(
			"请求体内存上限(%d) 不应大于请求体上限(%d)",
			effective.BodyInMemoryLimitBytes, effective.BodyLimitBytes,
		)
	}
	return effective, nil
}

// buildDirectives 生成交给 Coraza 的 SecLang 指令文本。
//
// 指令顺序是本函数的核心，顺序错误会导致「配置写了却不生效」，因此逐段说明：
//
//	第 1 段：CRS 设置文件
//	    必须最先加载。它定义 tx.* 默认值、默认动作与 tx.crs_setup_version，
//	    CRS 的 REQUEST-901-INITIALIZATION.conf 会校验该版本变量是否存在。
//
//	第 2 段：引擎基础设置
//	    必须放在第 1 段之后，因为 crs-setup.conf 里写死了 SecRuleEngine On /
//	    SecRequestBodyAccess On / SecRequestBodyLimit 13107200；
//	    SecLang 是「后写的生效」，因此本段才能真正决定引擎行为（含 detection_only）。
//	    同时显式关闭审计日志与调试日志：日志由本项目自己的 JSON 日志体系负责，
//	    让 Coraza 再往 stdout 写审计日志会造成日志格式混乱与重复。
//
//	第 3 段：运维自定义指令
//	    便于在不改代码的前提下追加 SecRuleRemoveById / SecRuleUpdateTargetById 等，
//	    用于压误报（需求 R6：规则层可按需调优）。
//
//	第 4 段：偏执等级覆盖
//	    CRS 4.x 的偏执等级由 tx.blocking_paranoia_level / tx.detection_paranoia_level 决定，
//	    而 REQUEST-901 只在它们「未设置」时才赋默认值 1。因此在 901 之前注入该动作即可生效。
//	    （crs-setup.conf 里的 tx.paranoia_level 在 CRS 4.x 已不再被读取，故一并设置。）
//
//	第 5 段：规则文件
//	    按文件名字典序加载，保证「同一次构建的规则顺序完全确定」，便于复现问题。
//
//	第 6 段：全局误报例外
//	    必须排在规则文件**之后**：SecRuleRemoveById / SecRuleRemoveByTag /
//	    SecRuleUpdateTargetById 属于「配置期指令」，只对已经解析出来的规则生效。
//	    放在规则文件之前等于什么都没做（这是最典型的「例外配了不生效」）。
//
// 关于 JSON 深度限制：Coraza v3.0.0 不提供对应指令（其 JSON 处理器没有深度保护），
// 因此该限额由本包自行实现（见 jsondepth.go），不在此处生成指令。
func buildDirectives(set *rules.Set, engine core.EngineSettings, bodyAccess bool,
	exceptions *exceptions.Set, sites []*core.Site, extraGroups ...[]string) string {
	var builder strings.Builder

	// 第 1 段：CRS 设置文件。
	if set.Setup != "" {
		fmt.Fprintf(&builder, "Include %s\n", set.Setup)
	}

	// 第 2 段：引擎基础设置（后写覆盖先写）。
	fmt.Fprintf(&builder, "SecRuleEngine %s\n", ruleEngineValue(engine.Mode))
	fmt.Fprintf(&builder, "SecRequestBodyAccess %s\n", onOff(bodyAccess))
	fmt.Fprintf(&builder, "SecRequestBodyLimit %d\n", engine.BodyLimitBytes)
	fmt.Fprintf(&builder, "SecRequestBodyInMemoryLimit %d\n", engine.BodyInMemoryLimitBytes)
	fmt.Fprintf(&builder, "SecRequestBodyLimitAction %s\n", bodyLimitActionValue(engine.BodyLimitAction))
	fmt.Fprintf(&builder, "SecResponseBodyAccess Off\n")
	// 响应体检测不在本方案的范围内（forward-auth 前置校验看不到业务响应体）。
	fmt.Fprintf(&builder, "SecAuditEngine Off\n")
	fmt.Fprintf(&builder, "SecDebugLogLevel 0\n")

	// 第 2.5 段：站点级引擎模式覆盖。
	//
	// Coraza 的 SecRuleEngine 是 WAF 级配置，但 ctl:ruleEngine 是事务级动作。
	// 在 phase 1 最前面按 Host 注入该动作，就能让同一份已编译规则同时服务
	// on / detection_only 两种站点策略，而无需为每个站点重复编译规则集。
	// 规则顺序按「精确 Host -> 较长通配后缀 -> 通配全部」排列，与 sites.Resolver
	// 的匹配优先级一致，避免多个站点规则同时命中时取到较弱的具体性。
	for _, directive := range siteEngineModeDirectives(sites) {
		builder.WriteString(directive)
		builder.WriteString("\n")
	}

	// 第 3 段：运维自定义指令。
	for _, directive := range engine.InlineDirectives {
		trimmed := strings.TrimSpace(directive)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		builder.WriteString(trimmed)
		builder.WriteString("\n")
	}

	// 第 4 段：偏执等级覆盖（仅当等级不为 1 时才注入，等级 1 是 CRS 默认值，无需多余动作）。
	if engine.ParanoiaLevel > 1 {
		fmt.Fprintf(&builder,
			"SecAction \"id:%d,phase:1,pass,nolog,t:none,"+
				"setvar:'tx.paranoia_level=%d',"+
				"setvar:'tx.blocking_paranoia_level=%d',"+
				"setvar:'tx.detection_paranoia_level=%d'\"\n",
			paranoiaOverrideRuleID, engine.ParanoiaLevel, engine.ParanoiaLevel, engine.ParanoiaLevel,
		)
	}

	// 第 4.2 段：异常评分阈值覆盖。
	//
	// CRS 的阻断判定（REQUEST-949）读取 tx.inbound_anomaly_score_threshold，
	// 该变量在 crs-setup.conf 中被赋默认值 5。这里在规则文件之前覆盖它，
	// 使「引擎的阻断判定」与「pipeline 中 threshold 单元的判定」使用同一个数字。
	// 只在与 CRS 默认值不同时才注入，避免生成无意义的动作。
	if engine.AnomalyScoreThreshold > 0 && engine.AnomalyScoreThreshold != defaultAnomalyScoreThreshold {
		fmt.Fprintf(&builder,
			"SecAction \"id:%d,phase:1,pass,nolog,noauditlog,t:none,"+
				"setvar:'tx.inbound_anomaly_score_threshold=%d'\"\n",
			anomalyThresholdRuleID, engine.AnomalyScoreThreshold,
		)
	}

	// 第 4.5 段：作用域误报例外（ctl 规则）。
	//
	// 必须排在规则文件之前：同一 phase 内的规则按出现顺序求值，
	// ctl:ruleRemoveById / ctl:ruleRemoveByTag / ctl:ruleRemoveTargetById
	// 只有先于目标规则执行，目标规则才会被排除。
	if exceptions != nil {
		for _, directive := range exceptions.Pre {
			builder.WriteString(directive)
			builder.WriteString("\n")
		}
	}

	// 第 4.6 段：请求体处理器路由。
	//
	// 必须放在规则文件之前：这些规则是 phase 1 的 ctl 动作，用于在请求体被解析之前
	// 决定使用哪个处理器。Coraza 只按 Content-Type 自动识别
	// application/x-www-form-urlencoded 与 multipart/form-data；JSON 与 XML 若不在此
	// 显式指定，会被当作 URLENCODED 解析，导致 JSON / XML 请求体里的攻击载荷
	// 完全无法命中规则（需求 R4：请求体检测）。
	for _, directive := range bodyProcessorDirectives(engine) {
		builder.WriteString(directive)
		builder.WriteString("\n")
	}

	// 第 5 段：规则文件（不含设置文件，已在第 1 段加载）。
	for _, file := range set.Files {
		fmt.Fprintf(&builder, "Include %s\n", file)
	}

	// 第 5.5 段：虚拟补丁规则。
	// 放在 CRS 规则之后、全局例外之前：补丁规则可以独立命中，同时仍允许
	// 运维通过 exceptions 对具体规则做误报治理。
	for _, group := range extraGroups {
		for _, directive := range group {
			trimmed := strings.TrimSpace(directive)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			builder.WriteString(trimmed)
			builder.WriteString("\n")
		}
	}

	// 第 6 段：全局误报例外（静态移除指令，必须在规则文件之后）。
	if exceptions != nil {
		for _, directive := range exceptions.Post {
			builder.WriteString(directive)
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

// siteEngineModeRuleIDBase 是站点级引擎模式覆盖规则的 ID 起始值。
//
// 取 901900：避开项目已占用的 900100 / 900110 / 900200 / 900300 区间，
// 也避开内置 CRS 在 REQUEST-901 初始化阶段使用的 901001-901500 区间。
// 站点规则按站点数量顺序分配，实际配置中通常只有个位数。
const siteEngineModeRuleIDBase = 901900

// siteEngineModeDirectives 为显式声明 engine_mode 的站点生成事务级切换规则。
func siteEngineModeDirectives(sites []*core.Site) []string {
	type candidate struct {
		site    *core.Site
		pattern string
		rank    int
	}
	candidates := make([]candidate, 0, len(sites))
	for _, site := range sites {
		if site == nil {
			continue
		}
		mode := strings.TrimSpace(site.EngineMode)
		if mode != ModeOn && mode != ModeDetectionOnly {
			continue // inherit 或空值不生成覆盖规则
		}
		for _, host := range site.Hosts {
			pattern, rank := siteHostPattern(host)
			if pattern == "" {
				continue
			}
			candidates = append(candidates, candidate{site: site, pattern: pattern, rank: rank})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank > candidates[j].rank
		}
		return len(candidates[i].pattern) > len(candidates[j].pattern)
	})

	directives := make([]string, 0, len(candidates))
	for index, item := range candidates {
		engineValue := "On"
		if strings.TrimSpace(item.site.EngineMode) == ModeDetectionOnly {
			engineValue = "DetectionOnly"
		}
		directives = append(directives, fmt.Sprintf(
			"SecRule REQUEST_HEADERS:Host \"@rx %s\" "+
				"\"id:%d,phase:1,pass,nolog,noauditlog,ctl:ruleEngine=%s\"",
			item.pattern, siteEngineModeRuleIDBase+index, engineValue,
		))
	}
	return directives
}

// siteHostPattern 把站点 Host 模式转换为锚定正则，并返回匹配具体性排序值。
// 精确 Host 返回 3，*.后缀 返回 2，* 返回 1。
func siteHostPattern(host string) (string, int) {
	trimmed := strings.ToLower(strings.TrimSpace(host))
	if trimmed == "" {
		return "", 0
	}
	if trimmed == "*" {
		return "^.*$", 1
	}
	if strings.HasPrefix(trimmed, "*.") {
		suffix := strings.TrimPrefix(trimmed, "*.")
		if suffix == "" {
			return "", 0
		}
		return "^[^.]+\\.(?:[^.]+\\.)*" + regexp.QuoteMeta(suffix) + "$", 2
	}
	return "^" + regexp.QuoteMeta(trimmed) + "$", 3
}

// 异常评分阈值覆盖动作的规则 ID。
//
// 取 900110：紧邻偏执等级覆盖动作（900100），同属「引擎行为覆盖」类别，
// 便于在日志与规则清单里一眼识别为本项目注入的配置动作。
const anomalyThresholdRuleID = 900110

// defaultAnomalyScoreThreshold 是 CRS 的默认入站异常评分阈值（见 crs-setup.conf）。
const defaultAnomalyScoreThreshold = 5

// 请求体处理器路由规则的规则 ID 起始值。
//
// 取 900200：CRS 自身只占用 900000 / 900001（crs-setup.conf）与 901xxx（初始化），
// 900100 已被本包的偏执等级覆盖动作占用（见 paranoiaOverrideRuleID），
// 因此从 900200 起顺序分配，既不与 CRS 冲突，也便于在日志里一眼识别为本项目注入。
const bodyProcessorRuleIDBase = 900200

// defaultBodyProcessors 是未配置 engine.body.processors 时使用的内置映射。
//
// 只覆盖 JSON 与 XML：URLENCODED 与 MULTIPART 由 Coraza 依据 Content-Type 自动选择，
// 无需额外指令；把这两个自动识别的处理器再写一遍只会增加规则数量而不改变行为。
func defaultBodyProcessors() []core.BodyProcessorSetting {
	return []core.BodyProcessorSetting{
		{
			Name:         "JSON",
			ContentTypes: []string{`^application/(?:[^;,\s]+\+)?json(?:\s*;.*)?$`},
			Enabled:      true,
		},
		{
			Name:         "XML",
			ContentTypes: []string{`^(?:application|text)/(?:[^;,\s]+\+)?xml(?:\s*;.*)?$`},
			Enabled:      true,
		},
	}
}

// bodyProcessorDirectives 生成「请求体处理器路由」指令。
//
// 每个启用且非空的映射生成一条 phase 1 规则：
//
//	SecRule REQUEST_HEADERS:Content-Type "@rx <模式1>|(<模式2>)" \
//	    "id:900200,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=JSON"
//
// 逐项说明：
//   - 用 @rx 而不是 @pm：内容类型需要前缀锚定，逐个子串匹配会把
//     「application/json-patch+json」这类值误判；
//   - 每个模式用 (?:...) 包裹后以 | 拼接：避免用户模式里的 | 破坏整体分组；
//   - nolog + noauditlog：路由规则是内部机制，不应出现在命中明细与审计日志里
//     （命中明细另外还会被 reportableRule 过滤，这里是双保险）；
//   - pass：不中断，仅设置处理器。
func bodyProcessorDirectives(engine core.EngineSettings) []string {
	processors := engine.Processors
	if processors == nil {
		processors = defaultBodyProcessors()
	}

	directives := make([]string, 0, len(processors))
	ruleID := bodyProcessorRuleIDBase
	for _, processor := range processors {
		name := strings.ToUpper(strings.TrimSpace(processor.Name))
		if !processor.Enabled || name == "" || len(processor.ContentTypes) == 0 {
			continue
		}
		parts := make([]string, 0, len(processor.ContentTypes))
		for _, pattern := range processor.ContentTypes {
			if trimmed := strings.TrimSpace(pattern); trimmed != "" {
				parts = append(parts, "(?:"+trimmed+")")
			}
		}
		if len(parts) == 0 {
			continue
		}
		directives = append(directives, fmt.Sprintf(
			"SecRule REQUEST_HEADERS:Content-Type \"@rx %s\" "+
				"\"id:%d,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=%s\"",
			strings.Join(parts, "|"), ruleID, name,
		))
		ruleID++
	}
	return directives
}

// ruleEngineValue 把模式映射为 SecRuleEngine 取值。
func ruleEngineValue(mode string) string {
	if mode == ModeDetectionOnly {
		return "DetectionOnly"
	}
	return "On"
}

// onOff 把布尔值映射为 SecLang 的 On / Off。
func onOff(enabled bool) string {
	if enabled {
		return "On"
	}
	return "Off"
}

// bodyLimitActionValue 把配置取值映射为 SecRequestBodyLimitAction 取值。
func bodyLimitActionValue(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "processpartial":
		return "ProcessPartial"
	default:
		return "Reject"
	}
}
