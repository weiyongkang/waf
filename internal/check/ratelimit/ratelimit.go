// Package ratelimit 实现「多维限速」校验单元（需求 R17）。
//
// 定位：
//
//	按配置的维度组合（客户端 IP / 请求路径 / Host / 站点 / User-Agent）对请求计数，
//	在固定窗口内超过阈值时按 action 拦截（ratelimit / block）或仅观察（observe）。
//
// 为什么必须在共享存储里计数（需求 R17）：
//
//	多实例部署时，如果每个实例各自在本地内存计数，实际放行量会成为
//	「阈值 × 实例数」，限速配置形同虚设。因此计数一律通过 core.Store 完成；
//	未启用 Redis 时由 store 层按配置降级为本地内存，此时限速只在单实例内生效
//	（store 层会写 warn 级系统日志明确提示，避免运维误以为限速已全局生效）。
//
// 计数键的构造约定：
//
//	计数键 = <key_prefix>rl:<维度1>=<值1>|<维度2>=<值2>:<窗口>
//	例如   rl:ip=1.2.3.4|site=default:60
//
//	把「窗口」写进键，使同一维度值在不同限速规则下互不干扰；
//	同一键的 TTL 由 Store 在首次自增时设置为窗口长度，从而形成固定窗口计数
//	（需求 R17 的既定语义，见 internal/core/store.go 的 Incr 说明）。
//
// 关于 User-Agent 维度：
//
//	User-Agent 完全由客户端控制，既可能超长（数十 KB）也可能包含任意字节。
//	直接把它拼进存储键会污染键空间（键长度、Redis 集群槽位与可读性都受影响），
//	因此该维度统一做「长度截断 + FNV-1a 哈希」后再入键，并带 h: 前缀以便识别。
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "ratelimit"

// ruleIDRateLimit 是限速命中使用的内置规则标识。
const ruleIDRateLimit = "rate_limit_exceeded"

// 限速维度常量（配置项 settings.dimensions 的合法取值）。
const (
	// DimensionIP 表示按客户端 IP 计数。
	DimensionIP = "ip"
	// DimensionPath 表示按请求路径计数（路径来自注入头还原出的原始 URI）。
	DimensionPath = "path"
	// DimensionHost 表示按 Host 计数。
	DimensionHost = "host"
	// DimensionSite 表示按命中的站点名计数。
	DimensionSite = "site"
	// DimensionUA 表示按 User-Agent 计数。
	DimensionUA = "ua"
)

// 动作常量（配置项 settings.action）。
const (
	// ActionRateLimit 表示触发后返回 429 并携带 Retry-After（默认）。
	ActionRateLimit = "ratelimit"
	// ActionBlock 表示触发后直接返回 403。
	ActionBlock = "block"
	// ActionObserve 表示触发后只记录（DetectionOnly 灰度验证）。
	ActionObserve = "observe"
)

// 默认值常量。
//
// 之所以集中定义：限速是「按请求路径执行」的热点代码，任何硬编码都会
// 变成无法运维调整的隐性行为（需求 R13）。
const (
	// defaultStoreTimeout 是单次计数访问的默认超时。
	//
	// 必须有超时：限速计数是每个请求都要做的存储写入，若存储抖动
	// （例如 Redis 主从切换）而没有超时，整条请求链路会被拖垮；
	// 宁可本次计数失败（按 on_error 处理），也不要拖慢全站。
	defaultStoreTimeout = 200 * time.Millisecond
	// defaultWindow 是未配置 window 时使用的窗口长度。
	defaultWindow = time.Minute
	// emptyDimensionValue 是维度值为空时的占位符。
	//
	// 之所以用占位符而不是「跳过该维度」：跳过会让「缺少某个头的请求」
	// 与「未配置该维度的规则」产生相同的键，反而更容易造成误伤；
	// 统一占位可以保证键的构成始终与配置的维度列表一一对应。
	emptyDimensionValue = "-"
)

// 站点级参数覆盖的键名（core.Site.Param 的命名约定：<插件类型>.<参数名>）。
//
// 使用场景：同一个限速实例需要「默认较宽松、但对少数敏感站点更严格」时，
// 不必为该站点再声明一个实例，只需在站点 params 中覆盖阈值即可。
const (
	// siteParamLimit 覆盖窗口内的基础放行次数。
	siteParamLimit = "ratelimit.limit"
	// siteParamBurst 覆盖额外允许的突发次数。
	siteParamBurst = "ratelimit.burst"
	// siteParamWindow 覆盖固定窗口长度（人类可读时长，例如 10s / 1m）。
	siteParamWindow = "ratelimit.window"
)

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 ratelimit 的私有配置片段。
type Settings struct {
	// Dimensions 是参与计数的维度列表，至少一项；可选值：ip / path / host / site / ua。
	Dimensions []string `yaml:"dimensions"`
	// PathMatch 是路径正则列表；为空表示对全部路径生效。
	//
	// 之所以用正则而不是前缀匹配：限速目标往往是「一类接口」
	// （例如 ^/api/auth/ 与 ^/login$），前缀匹配无法表达这种并列关系。
	PathMatch []string `yaml:"path_match"`
	// Window 是固定窗口长度。
	Window core.Duration `yaml:"window"`
	// Limit 是窗口内的基础放行次数，必须大于 0。
	Limit int64 `yaml:"limit"`
	// Burst 是额外允许的突发次数；实际阈值为 Limit + Burst。
	//
	// 之所以把「基础限额」与「突发额度」分开：基础额度表达业务容量，
	// 突发额度用于吸收正常用户的页面并发请求，两者语义不同、调优手段也不同。
	Burst int64 `yaml:"burst"`
	// Action 是触发后的动作：ratelimit / block / observe。
	Action string `yaml:"action"`
	// Score 是触发时累加的异常评分（供 threshold 单元聚合判定）。
	Score int `yaml:"score"`
	// Store 是计数使用的存储实例名；为空表示使用默认存储。
	Store string `yaml:"store"`
	// StoreTimeout 是单次计数访问超时；<= 0 时取默认值。
	StoreTimeout core.Duration `yaml:"store_timeout"`
	// KeyPrefix 是计数键额外前缀，用于同一存储被多条规则共用时的人工区分。
	KeyPrefix string `yaml:"key_prefix"`
	// Ban 控制触发时是否同时请求内部封禁（需求 R18 / R19）。
	//
	// 默认 false：限速通常只是「降速」，是否升级为封禁应显式声明，
	// 否则一次流量高峰就可能把整段 NAT 出口封掉。
	Ban bool `yaml:"ban"`
	// BanTTL 是封禁时长；为 0 时由 ban.default_ttl 兜底。
	BanTTL core.Duration `yaml:"ban_ttl"`
	// BanReason 是封禁原因文本；为空时按规则名自动生成。
	BanReason string `yaml:"ban_reason"`
}

// dimensionValue 是一个维度及其本次请求的取值。
type dimensionValue struct {
	// name 是维度名（ip / path / host / site / ua）。
	name string
	// value 是已规范化（截断 / 哈希 / 占位）的维度值。
	value string
}

// Check 是多维限速校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段。
	phase core.Phase
	// order 是执行顺序。
	order int
	// dimensions 是维度列表（已校验、已去重，顺序与配置一致）。
	dimensions []string
	// pathRegexps 是编译后的路径正则；为空表示匹配全部路径。
	pathRegexps []*regexp.Regexp
	// window 是固定窗口长度。
	window time.Duration
	// limit 是窗口内的基础放行次数。
	limit int64
	// burst 是额外允许的突发次数。
	burst int64
	// action 是触发后的动作。
	action string
	// score 是触发时累加的评分。
	score int
	// keyPrefix 是计数键额外前缀。
	keyPrefix string
	// ban 表示触发时是否请求内部封禁。
	ban bool
	// banTTL 是请求封禁时使用的时长（0 表示由 ban.default_ttl 兜底）。
	banTTL core.Duration
	// banReason 是封禁原因文本。
	banReason string
	// store 是计数使用的存储实例（构造期解析完成，运行期直接使用）。
	store core.Store
	// storeTimeout 是单次计数访问超时。
	storeTimeout time.Duration
	// tokenLimit 是单个维度值的长度上限（来自 limits.max_scan_token_bytes）。
	tokenLimit int64
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 ratelimit 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	dimensions, err := normalizeDimensions(settings.Dimensions)
	if err != nil {
		return nil, err
	}

	if settings.Limit <= 0 {
		return nil, fmt.Errorf("ratelimit 必须配置正整数 limit（当前 %d）", settings.Limit)
	}
	if settings.Burst < 0 {
		return nil, fmt.Errorf("ratelimit 的 burst 不能为负数（当前 %d）", settings.Burst)
	}

	window := settings.Window.Duration()
	if window <= 0 {
		window = defaultWindow
	}

	action := settings.Action
	if action == "" {
		action = ActionRateLimit
	}
	switch action {
	case ActionRateLimit, ActionBlock, ActionObserve:
	default:
		return nil, fmt.Errorf("ratelimit 的 action = %q 非法，可选值：ratelimit / block / observe", action)
	}

	regexps := make([]*regexp.Regexp, 0, len(settings.PathMatch))
	for _, pattern := range settings.PathMatch {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("ratelimit 的 path_match 正则 %q 非法：%w", pattern, err)
		}
		regexps = append(regexps, compiled)
	}

	if deps == nil || deps.Stores == nil {
		// 未注入存储解析器说明启动装配漏配；直接失败比「限速不生效」安全得多。
		return nil, errors.New("ratelimit 需要注入共享存储（core.Deps.Stores），请检查启动装配")
	}
	var store core.Store
	if settings.Store == "" {
		store, err = deps.Stores.Default()
	} else {
		store, err = deps.Stores.Resolve(settings.Store)
	}
	if err != nil {
		return nil, fmt.Errorf("解析限速存储失败：%w", err)
	}

	timeout := settings.StoreTimeout.Duration()
	if timeout <= 0 {
		timeout = defaultStoreTimeout
	}

	tokenLimit := int64(0)
	if deps != nil {
		tokenLimit = deps.Limits.MaxScanTokenBytes
	}

	return &Check{
		name:         inst.Name,
		phase:        inst.Phase,
		order:        inst.Order,
		dimensions:   dimensions,
		pathRegexps:  regexps,
		window:       window,
		limit:        settings.Limit,
		burst:        settings.Burst,
		action:       action,
		score:        settings.Score,
		keyPrefix:    settings.KeyPrefix,
		ban:          settings.Ban,
		banTTL:       settings.BanTTL,
		banReason:    settings.BanReason,
		store:        store,
		storeTimeout: timeout,
		tokenLimit:   tokenLimit,
		logger:       deps.SystemLoggerOr(),
	}, nil
}

// Name 返回实例名。
func (c *Check) Name() string { return c.name }

// Type 返回实现类型。
func (c *Check) Type() string { return Type }

// Phase 返回执行阶段。
func (c *Check) Phase() core.Phase { return c.phase }

// Order 返回执行顺序。
func (c *Check) Order() int { return c.order }

// Evaluate 执行一次限速判断。
//
// 返回 nil 表示本次未触发限速（请求继续流经后续校验单元）。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}

	// 1) 路径过滤：配置了 path_match 时只对命中的路径计数。
	//    非目标路径（例如静态资源）既不应占用接口配额，
	//    也不应产生无意义的存储写入。
	if !c.pathMatches(rctx.Raw.Path) {
		return nil, nil
	}

	// 2) 计算本次请求生效的限速参数（站点级覆盖优先于实例配置）。
	limit, burst, window := c.effectiveLimits(rctx)

	// 3) 组装维度值与计数键。
	values := c.dimensionValues(rctx)
	key := c.counterKey(values, window)

	// 4) 计数：单次存储访问必须带超时与请求上下文，避免拖慢或拖死请求链路。
	ctx := rctx.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if c.storeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.storeTimeout)
		defer cancel()
	}

	count, ttl, err := c.store.Incr(ctx, key, window)
	if err != nil {
		// 返回错误而不是「未超限」：由 pipeline 按该实例的 on_error 策略决定放行或拦截，
		// 避免把「存储不可用」静默降级成「没有限速」。
		return nil, fmt.Errorf("限速计数失败（key=%s）：%w", key, err)
	}

	allowed := limit + burst
	if count <= allowed {
		return nil, nil
	}

	// 5) 触发限速：按 action 生成结论。
	result := c.buildResult(rctx, values, count, allowed, window, ttl)

	c.logger.Debug("触发限速",
		"check", c.name,
		"request_id", rctx.RequestID,
		"key", key,
		"count", count,
		"allowed", allowed,
		"action", c.action,
	)
	return result, nil
}

// DefaultOnError 返回失败策略默认值。
//
// 取 pass（失败开放）：限速依赖外部共享存储，存储抖动时不应该让全站流量被拦截；
// 安全优先的部署可在实例上显式配置 on_error: block。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：存储由 internal/store 统一持有与关闭，本单元无需释放。
func (c *Check) Close() error { return nil }

// buildResult 组装触发限速后的结论（含命中明细与可选的封禁请求）。
func (c *Check) buildResult(rctx *core.RequestContext, values []dimensionValue, count, allowed int64, window, ttl time.Duration) *core.Result {
	var (
		verdict core.Verdict
		code    string
	)
	switch c.action {
	case ActionObserve:
		verdict = core.VerdictObserve
	case ActionBlock:
		verdict = core.VerdictBlock
		code = config.CodeBlocked
	default:
		verdict = core.VerdictRateLimited
		code = config.CodeRateLimited
	}

	result := core.NewResult(c.name, verdict)
	result.Code = code
	if verdict == core.VerdictRateLimited && ttl > 0 {
		// 把窗口剩余时间回传给客户端，便于正常客户端正确退避而不是立刻重试。
		result.RetryAfter = ttl
	}

	finding := core.NewFinding(c.name, ruleIDRateLimit,
		"请求频率超过限速阈值", core.SeverityMedium, c.score)
	finding.Data = map[string]string{
		"dimensions": summarizeDimensions(values),
		"count":      strconv.FormatInt(count, 10),
		"allowed":    strconv.FormatInt(allowed, 10),
		"window":     window.String(),
		"action":     c.action,
		"site":       siteName(rctx),
	}
	result.AddFinding(finding)

	if c.ban && verdict != core.VerdictObserve {
		// 键留空：由 internal/ban 按 ban.ban_key 统一推导，
		// 保证「这里写入的键」与「banlist 查询的键」完全一致。
		reason := c.banReason
		if reason == "" {
			reason = fmt.Sprintf("触发限速规则 %s（%s）", c.name, summarizeDimensions(values))
		}
		result.AddBan(core.BanRequest{
			TTL:    c.banTTL.Duration(),
			Reason: reason,
			RuleID: ruleIDRateLimit,
		})
	}

	return result
}

// pathMatches 判断请求路径是否命中参与计数的路径正则。
func (c *Check) pathMatches(path string) bool {
	if len(c.pathRegexps) == 0 {
		return true
	}
	for _, pattern := range c.pathRegexps {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// dimensionValues 按配置顺序提取并规范化各维度值。
func (c *Check) dimensionValues(rctx *core.RequestContext) []dimensionValue {
	raw := rctx.Raw
	values := make([]dimensionValue, 0, len(c.dimensions))
	for _, name := range c.dimensions {
		var value string
		switch name {
		case DimensionIP:
			value = raw.ClientIP
		case DimensionPath:
			value = raw.Path
		case DimensionHost:
			value = raw.Host
		case DimensionSite:
			if rctx.Site != nil {
				value = rctx.Site.Name
			}
		case DimensionUA:
			// User-Agent 先截断再哈希：截断保证内存占用可控（需求 R13），
			// 哈希保证键长恒定且不包含任意字节。
			value = "h:" + hashToken(capString(raw.HeaderValue("User-Agent"), c.tokenLimit))
		default:
			// 构造期已校验取值，此处仅作防御性兜底。
			value = emptyDimensionValue
		}

		value = strings.TrimSpace(value)
		if value == "" {
			value = emptyDimensionValue
		} else if name != DimensionUA {
			value = capString(value, c.tokenLimit)
		}
		values = append(values, dimensionValue{name: name, value: value})
	}
	return values
}

// counterKey 依据维度值与窗口拼装计数键。
func (c *Check) counterKey(values []dimensionValue, window time.Duration) string {
	var builder strings.Builder
	builder.WriteString(c.keyPrefix)
	builder.WriteString("rl:")
	for index, item := range values {
		if index > 0 {
			builder.WriteByte('|')
		}
		builder.WriteString(item.name)
		builder.WriteByte('=')
		builder.WriteString(item.value)
	}
	builder.WriteByte(':')
	builder.WriteString(windowSuffix(window))
	return builder.String()
}

// effectiveLimits 计算本次请求生效的限速参数。
//
// 解析顺序（站点级覆盖优先）：站点 params（`ratelimit.limit` / `ratelimit.burst` /
// `ratelimit.window`）-> 实例配置。**不做实例级 settings 的动态重载**：
// 实例配置在启动阶段解析一次即可，运行期可变的部分只有站点级覆盖。
//
// 非法取值（例如 "abc"、0、负数时长）会被忽略并写 debug 日志：
// 站点参数写错不应让限速变成「完全不限制」（那是静默失效，比报错危险），
// 因此回退到实例配置，同时留下可排查的日志。
func (c *Check) effectiveLimits(rctx *core.RequestContext) (limit, burst int64, window time.Duration) {
	limit, burst, window = c.limit, c.burst, c.window
	if rctx == nil || rctx.Site == nil {
		return limit, burst, window
	}

	if raw, ok := rctx.Site.Param(siteParamLimit); ok {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			limit = parsed
		} else {
			c.logSiteParamInvalid(rctx, siteParamLimit, raw)
		}
	}
	if raw, ok := rctx.Site.Param(siteParamBurst); ok {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed >= 0 {
			burst = parsed
		} else {
			c.logSiteParamInvalid(rctx, siteParamBurst, raw)
		}
	}
	if raw, ok := rctx.Site.Param(siteParamWindow); ok {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			window = parsed
		} else {
			c.logSiteParamInvalid(rctx, siteParamWindow, raw)
		}
	}
	return limit, burst, window
}

// logSiteParamInvalid 记录被忽略的站点级参数。
func (c *Check) logSiteParamInvalid(rctx *core.RequestContext, key, value string) {
	c.logger.Debug("忽略非法的站点级限速参数，已回退到实例配置",
		"check", c.name,
		"request_id", rctx.RequestID,
		"site", siteName(rctx),
		"key", key,
		"value", value,
	)
}

// siteName 返回请求命中的站点名（供命中明细与日志使用）。
func siteName(rctx *core.RequestContext) string {
	if rctx == nil || rctx.Site == nil {
		return core.DefaultSiteName
	}
	return rctx.Site.Name
}

// windowSuffix 把窗口长度渲染为键后缀。
//
// 整秒窗口写作秒数（60 秒 -> "60"），否则退化为毫秒（1500ms -> "1500ms"），
// 既保证可读性，也避免不同窗口长度算出同一个键。
func windowSuffix(window time.Duration) string {
	if window%time.Second == 0 {
		return strconv.FormatInt(int64(window/time.Second), 10)
	}
	return strconv.FormatInt(window.Milliseconds(), 10) + "ms"
}

// summarizeDimensions 把维度取值渲染为「维度=值」的可读串，用于日志与命中明细。
func summarizeDimensions(values []dimensionValue) string {
	parts := make([]string, 0, len(values))
	for _, item := range values {
		parts = append(parts, item.name+"="+item.value)
	}
	return strings.Join(parts, "|")
}

// normalizeDimensions 校验并规范化维度列表。
//
// 校验规则：
//   - 至少配置一个维度：无维度的限速等价于「全站总配额」，几乎不可能是运维本意；
//   - 每个维度必须是已知取值；
//   - 不允许重复：重复维度不会改变计数结果，但会让键里出现无意义的重复段，属于配置笔误。
func normalizeDimensions(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("ratelimit 必须至少配置一个 dimensions 维度")
	}

	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		name := strings.TrimSpace(item)
		switch name {
		case DimensionIP, DimensionPath, DimensionHost, DimensionSite, DimensionUA:
		default:
			return nil, fmt.Errorf("ratelimit 的 dimensions 取值 %q 非法，可选值：ip / path / host / site / ua", item)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("ratelimit 的 dimensions 中维度 %q 重复", name)
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result, nil
}

// capString 按长度上限截断字符串；limit <= 0 表示不截断。
//
// 之所以按字节截断：存储键与后续检测都以字节为计量单位，
// 按字符截断会让多字节字符（中文 UA）的长度上限变得不可预测。
func capString(value string, limit int64) string {
	if limit <= 0 || int64(len(value)) <= limit {
		return value
	}
	return value[:limit]
}

// hashToken 计算 token 的 FNV-1a 64 位哈希并返回十六进制表示。
//
// 选择 FNV-1a 而不是加密哈希：该哈希只用于把可控长度的字符串压缩成定长键，
// 不承担任何安全职责（真正的判定依据是计数，而不是 UA 本身）。
func hashToken(value string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(value))
	return strconv.FormatUint(hasher.Sum64(), 16)
}
