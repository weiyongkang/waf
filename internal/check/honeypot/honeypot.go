// Package honeypot 实现「蜜罐 / 诱饵端点」校验单元（PhasePre）。
//
// 语义与 reference/honeypot 的 baitroute 规则保持一致：
//   - 规则按声明顺序匹配，首个命中立即短路整条校验链；
//   - 命中后直接返回规则自己的 status / content-type / headers / body；
//   - 未命中不产生任何结论，后续校验单元继续执行。
//
// 在此基础上补充了三项 WAF 侧能力：
//   - 匹配方式可选 exact / prefix / glob / regex，默认 exact；
//   - 支持从目录递归加载 .yaml / .yml 规则文件，便于复用诱饵规则资产；
//   - 命中会生成 Finding、访问日志与可选告警，后续 autoban 可据 verdict=honeypot 联动封禁。
package honeypot

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	stdpath "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/fsx"
	"gopkg.in/yaml.v3"
)

// Type 是本实现的注册类型名。
const Type = "honeypot"

// 路径匹配方式。
const (
	// MatchExact 表示完整路径相等（默认，与 reference/honeypot 一致）。
	MatchExact = "exact"
	// MatchPrefix 表示路径前缀匹配。
	MatchPrefix = "prefix"
	// MatchGlob 表示 path.Match 通配符匹配（'*' 不跨 '/'）。
	MatchGlob = "glob"
	// MatchRegex 表示 Go 正则匹配（不做自动锚定）。
	MatchRegex = "regex"
)

// 匹配目标。
const (
	// TargetPath 表示只匹配 URL Path（不含查询串）。
	TargetPath = "path"
	// TargetURI 表示匹配完整 URI（含查询串）。
	TargetURI = "uri"
)

// 默认值。
const (
	defaultStatus      = http.StatusOK
	defaultContentType = "text/plain; charset=utf-8"
)

// hopByHopHeaders 是不允许在蜜罐响应中配置的头。
//
// 这些头由 HTTP 框架 / 代理根据实际连接与响应体计算，规则里写死会造成
// Content-Length 与实际正文不一致、连接被错误复用等协议问题。
var hopByHopHeaders = map[string]struct{}{
	"Connection":        {},
	"Content-Length":    {},
	"Keep-Alive":        {},
	"Proxy-Connection":  {},
	"Te":                {},
	"Trailer":           {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
}

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 honeypot 的私有配置片段。
type Settings struct {
	// Rules 是内联规则列表，顺序即匹配顺序。
	Rules []Rule `yaml:"rules"`
	// RulesDir 是规则目录；递归读取 .yaml / .yml，按文件路径字典序加载。
	//
	// 目录规则排在 Rules 之后；完全相同的匹配表达式会按重复规则报错，
	// 避免「写了覆盖但实际被第一条吃掉」的隐式行为。
	RulesDir string `yaml:"rules_dir"`
	// Score 是命中时累加的异常评分。
	Score int `yaml:"score"`
	// Alert 控制是否产生告警；缺省为 true（蜜罐命中属于高价值安全事件）。
	Alert *bool `yaml:"alert"`
}

// Rule 是一条蜜罐规则。
//
// YAML 字段与 reference/honeypot 对齐；同时支持 content_type 与 content-type
// 两种写法，方便直接复用既有规则文件。
type Rule struct {
	// Name 是规则名；为空时自动生成（内联规则为 rule-N，目录规则为 相对路径#N）。
	Name string `yaml:"name"`
	// Method 是单个请求方法；为空且 Methods 也为空时匹配任意方法。
	Method string `yaml:"method"`
	// Methods 是多个请求方法，与 Method 合并。
	Methods []string `yaml:"methods"`
	// Path 是匹配表达式。
	Path string `yaml:"path"`
	// Match 是匹配方式：exact / prefix / glob / regex，默认 exact。
	Match string `yaml:"match"`
	// Target 是匹配目标：path / uri，默认 path。
	//
	// 兼容参考规则中带查询串的 path：exact 模式下 Path 含 '?' 且未显式配置
	// Target 时，自动改为匹配完整 URI。
	Target string `yaml:"target"`
	// Status 是返回状态码，默认 200。
	Status int `yaml:"status"`
	// ContentType 是返回的 Content-Type。
	ContentType string `yaml:"content_type"`
	// ContentTypeAlt 兼容 reference/honeypot 的 content-type 写法。
	ContentTypeAlt string `yaml:"content-type"`
	// Headers 是附加响应头。
	Headers map[string]string `yaml:"headers"`
	// Body 是响应正文原文。
	Body string `yaml:"body"`

	// methods 是规范化后的方法集合；包含 "*" 表示任意方法。
	methods map[string]struct{}
	// matchKind 是规范化后的匹配方式。
	matchKind string
	// targetKind 是规范化后的匹配目标。
	targetKind string
	// regex 是 regex 模式预编译结果。
	regex *regexp.Regexp
}

// Check 是蜜罐校验单元实例。
type Check struct {
	name  string
	phase core.Phase
	order int
	score int
	alert bool
	rules []Rule
	// rulesDir 是磁盘规则目录；为空表示只有内联规则（无文件可监听）。
	rulesDir string
}

// New 依据实例配置构造蜜罐校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	if deps == nil {
		deps = &core.Deps{}
	}
	check, err := buildCheck(inst, deps)
	if err != nil {
		return nil, err
	}

	// 只有「全局开启热加载」且「确实配置了 rules_dir」时才启动监听。
	// 内联规则来自配置文件，运行期不会单独变化；为它起轮询协程没有意义。
	if !deps.Engine.HotReload.Enabled {
		if check.rulesDir != "" {
			deps.SystemLoggerOr().Warn(
				"蜜罐已配置 rules_dir，但 engine.hot_reload.enabled=false，规则文件变化不会自动加载",
				"instance", inst.Name,
				"rules_dir", check.rulesDir,
			)
		}
		return check, nil
	}
	if check.rulesDir == "" {
		return check, nil
	}
	return newReloader(inst, deps, check)
}

// buildCheck 按启动路径构建一个蜜罐实例。
//
// 热加载重建会复用同一函数，确保「启动时」与「重载后」的规则解析、
// 去重、限额检查完全一致。
func buildCheck(inst core.InstanceConfig, deps *core.Deps) (*Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &core.Deps{}
	}

	rules := make([]Rule, 0, len(settings.Rules))
	for i := range settings.Rules {
		rules = append(rules, settings.Rules[i])
	}
	if strings.TrimSpace(settings.RulesDir) != "" {
		fromDir, err := loadRulesDir(settings.RulesDir,
			deps.Limits.MaxRuleFileBytes, deps.Limits.MaxRulesTotalBytes)
		if err != nil {
			return nil, err
		}
		rules = append(rules, fromDir...)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("honeypot 至少需要一条规则（配置 settings.rules 或 settings.rules_dir）")
	}

	normalized := make([]Rule, 0, len(rules))
	seenNames := make(map[string]struct{}, len(rules))
	seenRules := make(map[string]struct{}, len(rules))
	for index := range rules {
		rule, err := normalizeRule(rules[index], index)
		if err != nil {
			return nil, fmt.Errorf("honeypot 规则 %d（%s）非法：%w", index+1, rules[index].Name, err)
		}
		if _, exists := seenNames[rule.Name]; exists {
			return nil, fmt.Errorf("honeypot 规则名 %q 重复，规则名必须唯一", rule.Name)
		}
		seenNames[rule.Name] = struct{}{}

		// 完全相同的方法 + 匹配表达式 + 匹配方式必然只有第一条会生效，
		// 重复声明通常意味着复制粘贴失误，直接在启动阶段报错。
		key := strings.Join(sortedMethods(rule.methods), ",") + "|" + rule.matchKind + "|" + rule.targetKind + "|" + rule.Path
		if _, exists := seenRules[key]; exists {
			return nil, fmt.Errorf("honeypot 规则 %q 与已有规则重复（%s）", rule.Name, key)
		}
		seenRules[key] = struct{}{}
		normalized = append(normalized, rule)
	}

	alert := true
	if settings.Alert != nil {
		alert = *settings.Alert
	}
	return &Check{
		name:     inst.Name,
		phase:    inst.Phase,
		order:    inst.Order,
		score:    settings.Score,
		alert:    alert,
		rules:    normalized,
		rulesDir: strings.TrimSpace(settings.RulesDir),
	}, nil
}

// Name 返回实例名。
func (c *Check) Name() string { return c.name }

// Type 返回实现类型。
func (c *Check) Type() string { return Type }

// Phase 返回执行阶段。
func (c *Check) Phase() core.Phase { return c.phase }

// Order 返回同阶段内的执行顺序。
func (c *Check) Order() int { return c.order }

// Evaluate 按声明顺序查找首条命中规则并生成直接响应。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	result, _ := c.match(rctx, c.score, c.alert)
	return result, nil
}

// MatchHoneypot 按原始请求重新匹配规则，供 /waf/deny 渲染端点使用。
//
// 该路径不累加评分、不产生告警：安全事件已在 /waf/auth 阶段记录，
// 渲染阶段重复产生副作用会导致同一次命中被统计两次。
func (c *Check) MatchHoneypot(rctx *core.RequestContext) *core.Result {
	result, _ := c.match(rctx, 0, false)
	return result
}

// match 是 Evaluate 与 MatchHoneypot 共用的规则匹配逻辑。
func (c *Check) match(rctx *core.RequestContext, score int, alert bool) (*core.Result, *Rule) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}

	uri := rctx.Raw.URI
	if uri == "" {
		uri = rctx.Raw.Path
		if rctx.Raw.RawQuery != "" {
			uri += "?" + rctx.Raw.RawQuery
		}
	}

	for index := range c.rules {
		rule := &c.rules[index]
		if !rule.matches(rctx.Raw.Method, rctx.Raw.Path, uri) {
			continue
		}

		ruleID := "honeypot:" + rule.Name
		result := core.NewResult(c.name, core.VerdictHoneypot)
		result.Code = config.CodeHoneypot
		result.Message = "命中蜜罐规则"
		result.Response = &core.ResponseOverride{
			Status:      rule.Status,
			ContentType: rule.ContentType,
			Headers:     cloneHeaders(rule.Headers),
			Body:        rule.Body,
		}
		finding := core.NewFinding(c.name, ruleID,
			"请求命中蜜罐诱饵端点", core.SeverityHigh, score)
		finding.Data = map[string]string{
			"target":        rule.Path,
			"honeypot_rule": rule.Name,
			"match":         rule.matchKind,
			"target_kind":   rule.targetKind,
			"path":          rctx.Raw.Path,
			"method":        rctx.Raw.Method,
		}
		result.AddFinding(finding)

		if alert {
			result.AddAlert(core.Alert{
				Level:     core.AlertLevelWarn,
				Title:     "蜜罐命中",
				Message:   fmt.Sprintf("蜜罐规则 %s 被触发：%s %s", rule.Name, rctx.Raw.Method, rctx.Raw.Path),
				Site:      siteName(rctx),
				ClientIP:  rctx.Raw.ClientIP,
				RequestID: rctx.RequestID,
				Fields: map[string]string{
					"rule_id":   ruleID,
					"rule_name": rule.Name,
					"method":    rctx.Raw.Method,
					"path":      rctx.Raw.Path,
				},
				At: rctx.ReceivedAt,
			})
		}
		return result, rule
	}
	return nil, nil
}

// DefaultOnError 返回失败策略默认值：规则已全部驻留内存，失败开放即可。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：本实现不持有需要释放的资源。
func (c *Check) Close() error { return nil }

// matches 判断一次请求是否命中规则。
func (r *Rule) matches(method, path, uri string) bool {
	if _, any := r.methods["*"]; !any {
		if _, ok := r.methods[strings.ToUpper(strings.TrimSpace(method))]; !ok {
			return false
		}
	}

	target := path
	if r.targetKind == TargetURI {
		target = uri
	}
	switch r.matchKind {
	case MatchPrefix:
		return strings.HasPrefix(target, r.Path)
	case MatchGlob:
		matched, err := stdpath.Match(r.Path, target)
		return err == nil && matched
	case MatchRegex:
		return r.regex != nil && r.regex.MatchString(target)
	default:
		return target == r.Path
	}
}

// normalizeRule 校验并补全单条规则。
func normalizeRule(rule Rule, index int) (Rule, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("rule-%d", index+1)
	}

	rule.Path = strings.TrimSpace(rule.Path)
	if rule.Path == "" {
		return Rule{}, fmt.Errorf("path 不能为空")
	}

	rule.Match = strings.ToLower(strings.TrimSpace(rule.Match))
	if rule.Match == "" {
		rule.Match = MatchExact
	}
	switch rule.Match {
	case MatchExact, MatchPrefix, MatchGlob, MatchRegex:
	default:
		return Rule{}, fmt.Errorf("match = %q 非法，可选值：exact / prefix / glob / regex", rule.Match)
	}
	rule.matchKind = rule.Match

	rule.Target = strings.ToLower(strings.TrimSpace(rule.Target))
	if rule.Target == "" {
		if rule.Match == MatchExact && strings.Contains(rule.Path, "?") {
			rule.Target = TargetURI
		} else {
			rule.Target = TargetPath
		}
	}
	switch rule.Target {
	case TargetPath, TargetURI:
	default:
		return Rule{}, fmt.Errorf("target = %q 非法，可选值：path / uri", rule.Target)
	}
	rule.targetKind = rule.Target

	if rule.Match == MatchGlob {
		if _, err := stdpath.Match(rule.Path, ""); err != nil {
			return Rule{}, fmt.Errorf("glob 表达式 %q 非法：%w", rule.Path, err)
		}
	}
	if rule.Match == MatchRegex {
		compiled, err := regexp.Compile(rule.Path)
		if err != nil {
			return Rule{}, fmt.Errorf("正则表达式 %q 非法：%w", rule.Path, err)
		}
		rule.regex = compiled
	}

	methods := make(map[string]struct{}, len(rule.Methods)+1)
	if method := strings.ToUpper(strings.TrimSpace(rule.Method)); method != "" {
		methods[method] = struct{}{}
	}
	for _, method := range rule.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		methods[method] = struct{}{}
	}
	if len(methods) == 0 {
		methods["*"] = struct{}{}
	}
	rule.methods = methods

	if rule.Status == 0 {
		rule.Status = defaultStatus
	}
	if rule.Status < 200 || rule.Status > 599 {
		return Rule{}, fmt.Errorf("status = %d 非法，必须在 200-599 之间", rule.Status)
	}
	if (rule.Status == http.StatusNoContent || rule.Status == http.StatusNotModified) && rule.Body != "" {
		return Rule{}, fmt.Errorf("status = %d 不允许携带响应体", rule.Status)
	}

	rule.ContentTypeAlt = strings.TrimSpace(rule.ContentTypeAlt)
	rule.ContentType = strings.TrimSpace(rule.ContentType)
	if rule.ContentTypeAlt != "" {
		if rule.ContentType != "" && rule.ContentType != rule.ContentTypeAlt {
			return Rule{}, fmt.Errorf("content_type 与 content-type 不一致：%q / %q",
				rule.ContentType, rule.ContentTypeAlt)
		}
		rule.ContentType = rule.ContentTypeAlt
	}
	if rule.ContentType == "" && len(rule.Headers) > 0 {
		for name, value := range rule.Headers {
			if strings.EqualFold(name, "Content-Type") {
				rule.ContentType = strings.TrimSpace(value)
				break
			}
		}
	}
	if rule.ContentType == "" {
		rule.ContentType = defaultContentType
	}

	headers, err := normalizeHeaders(rule.Headers)
	if err != nil {
		return Rule{}, err
	}
	rule.Headers = headers
	return rule, nil
}

// normalizeHeaders 校验响应头并统一名称大小写。
func normalizeHeaders(headers map[string]string) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		trimmed := strings.TrimSpace(name)
		canonical := http.CanonicalHeaderKey(trimmed)
		if canonical == "" {
			return nil, fmt.Errorf("响应头名称 %q 非法", name)
		}
		if _, denied := hopByHopHeaders[canonical]; denied {
			return nil, fmt.Errorf("响应头 %q 不允许配置（由 HTTP 框架自动管理）", canonical)
		}
		if strings.ContainsAny(value, "\r\n") || strings.ContainsAny(trimmed, "\r\n") {
			return nil, fmt.Errorf("响应头 %q 的值不能包含换行符", canonical)
		}
		normalized[canonical] = value
	}
	return normalized, nil
}

// loadRulesDir 递归加载目录中的规则文件。
func loadRulesDir(dir string, maxFileBytes, maxTotalBytes int64) ([]Rule, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("解析蜜罐规则目录 %q 失败：%w", dir, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("蜜罐规则目录 %q 不存在或不可访问：%w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("蜜罐规则目录 %q 不是目录", dir)
	}

	files := make([]string, 0, 32)
	if err := filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), ".") {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("遍历蜜罐规则目录 %q 失败：%w", dir, err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("蜜罐规则目录 %q 中没有 .yaml / .yml 文件", dir)
	}

	rules := make([]Rule, 0, len(files))
	var totalBytes int64
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			return nil, fmt.Errorf("读取蜜罐规则文件 %q 状态失败：%w", file, err)
		}
		if maxFileBytes > 0 && fileInfo.Size() > maxFileBytes {
			return nil, fmt.Errorf("蜜罐规则文件 %q 为 %d 字节，超过 limits.max_rule_file_bytes=%d",
				file, fileInfo.Size(), maxFileBytes)
		}
		totalBytes += fileInfo.Size()
		if maxTotalBytes > 0 && totalBytes > maxTotalBytes {
			return nil, fmt.Errorf("蜜罐规则总量超过 limits.max_rules_total_bytes=%d", maxTotalBytes)
		}

		data, err := fsx.ReadCapped(file, maxFileBytes)
		if err != nil {
			return nil, fmt.Errorf("读取蜜罐规则文件 %q 失败：%w", file, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		var fileRules []Rule
		if err := decoder.Decode(&fileRules); err != nil {
			return nil, fmt.Errorf("解析蜜罐规则文件 %q 失败：%w", file, err)
		}

		rel, err := filepath.Rel(absolute, file)
		if err != nil {
			rel = file
		}
		rel = strings.TrimSuffix(rel, filepath.Ext(rel))
		rel = strings.ReplaceAll(rel, string(filepath.Separator), "/")
		for index := range fileRules {
			if strings.TrimSpace(fileRules[index].Name) == "" {
				fileRules[index].Name = fmt.Sprintf("%s#%d", rel, index+1)
			}
		}
		rules = append(rules, fileRules...)
	}
	return rules, nil
}

// cloneHeaders 复制响应头，避免多个请求共享同一份 map。
func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(headers))
	for name, value := range headers {
		cloned[name] = value
	}
	return cloned
}

// sortedMethods 返回稳定排序后的方法列表，用于重复规则检测。
func sortedMethods(methods map[string]struct{}) []string {
	items := make([]string, 0, len(methods))
	for method := range methods {
		items = append(items, method)
	}
	sort.Strings(items)
	return items
}

// siteName 返回站点名，未解析时使用默认站点。
func siteName(rctx *core.RequestContext) string {
	if rctx == nil || rctx.Site == nil {
		return core.DefaultSiteName
	}
	return rctx.Site.Name
}
