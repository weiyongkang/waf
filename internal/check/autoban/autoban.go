// Package autoban 实现「自动封禁」校验单元（PhasePost）。
//
// 定位（需求 R18 / R19）：
//
//	把本次请求的命中结论转化为内部封禁动作：「谁、封多久、为什么」，
//	由 internal/ban 统一落地到共享存储（多实例共享，需求 R17）。
//	封禁**只在 WAF 内部生效**，不产生任何系统防火墙操作。
//
// 为什么需要「命中次数阈值」而不是「一次命中即封禁」：
//
//	单次命中封禁的误伤率极高——正常用户的一次误操作、扫描器的一个探测请求，
//	都会把整段 NAT 出口封掉。因此默认要求同一来源在窗口内累计命中达到阈值
//	（配置项 settings.threshold）才真正封禁，把误伤概率压到可接受范围。
//
//	计数同样走共享存储：否则多实例部署时每个实例各算一遍，
//	「3 次才封禁」会被放大成「每实例 3 次」，阈值失去意义。
//
// 为什么「按谁计数」是可配置的（配置项 settings.dimensions）：
//
//	只按 IP 统计时，两类风险无法区分：「单一来源集中打某一个接口」（希望快速精准止损）
//	与「NAT 出口里某个用户触发规则」（希望尽量不封）。因此把封禁身份抽成「维度」：
//	client_ip 看整段来源，client_ip+path 只看「这个人访问这个接口」。
//	每个维度独立计数、独立判定，可配置多个；多个同时达标则一并产出封禁动作。
//
//	维度清单必须与部署的 ban.ban_keys 一致（后者决定运行期真的会去查哪些键），
//	否则会出现「封禁写进去了、却没有任何请求会查到它」，因此构造期即校验并 fail fast。
//
// 与其他收尾单元的配合：
//
//	threshold（评分阈值）负责「是否拦截本次请求」，
//	autoban 负责「是否把这个来源加入封禁名单」，两者独立配置、可以只启用其一。
//	执行器对 PhasePost 单元采用「即使链已短路也要全部执行」的收尾语义，
//	因此即使 pre 阶段已经拦截（例如命中 IP 黑名单），本单元依然会执行并记录封禁。
package autoban

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/ban"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "autoban"

// 动作常量（配置项 settings.action）。
const (
	// ActionBan 表示条件满足时执行封禁（默认）。
	ActionBan = "ban"
	// ActionObserve 表示条件满足时只记录与告警，不写入封禁名单。
	//
	// 使用场景：刚上线自动封禁时先观察一段时间，确认阈值合理后再切换为 ban。
	ActionObserve = "observe"
)

// 触发条件常量（配置项 settings.trigger_on）。
const (
	// TriggerAny 表示「任何终态结论」都计入触发条件。
	TriggerAny = "any"
)

// 默认值常量。
const (
	// defaultThreshold 是默认的命中次数阈值。
	defaultThreshold = 3
	// defaultWindow 是默认的命中统计窗口。
	defaultWindow = 5 * time.Minute
	// defaultStoreTimeout 是单次计数访问的默认超时。
	defaultStoreTimeout = 200 * time.Millisecond
	// ruleIDAutoBan 是触发自动封禁使用的内置规则标识。
	ruleIDAutoBan = "auto_ban"
	// counterNamespace 是命中计数键的命名空间。
	counterNamespace = "ab:"
)

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 autoban 的私有配置片段。
type Settings struct {
	// TriggerOn 是计入触发条件的判定结论名称列表，例如 [block, ratelimit]；
	// 特殊取值 any 表示任何终态结论都计入。为空时按 [block] 处理。
	TriggerOn []string `yaml:"trigger_on"`
	// MinSeverity 是计入触发条件的最低命中严重度（info / low / medium / high / critical）。
	//
	// 为什么需要这道门槛：命中次数衡量的是「量」，严重度衡量的是「质」。
	// 不设门槛时，一个来源只要把低危规则刷够次数就会被封，误伤概率远大于收益。
	// 为空表示不设门槛（与旧版本行为一致）。
	MinSeverity string `yaml:"min_severity"`
	// Dimensions 是触发维度列表（可配置多个，任一维度达标即产出封禁动作）。
	//
	// 为空时等价于单一的 client_ip 维度（与旧版本行为一致），因此旧配置无需修改。
	Dimensions []Dimension `yaml:"dimensions"`
	// Threshold 是窗口内累计命中次数阈值（各维度的默认值），必须大于 0。
	Threshold int `yaml:"threshold"`
	// Window 是命中次数统计窗口（各维度的默认值）。
	Window core.Duration `yaml:"window"`
	// TTL 是封禁时长（各维度的默认值）；为 0 时由 ban.default_ttl 兜底（并受 ban.max_ttl 限制）。
	TTL core.Duration `yaml:"ttl"`
	// SkipWhenBanned 控制「来源已被封禁时是否跳过计数」。
	//
	// 默认 true（留空即生效）：封禁生效期间的后续请求都会被 banlist 拦截，
	// 若继续计数并重复写名单，只会带来两项副作用——计数虚高（阈值失去参考意义）
	// 与名单被反复续期（配合累进封禁时表现为「无限加长」）。
	// 需要「持续攻击就持续续期」语义时可显式设为 false。
	SkipWhenBanned *bool `yaml:"skip_when_banned"`
	// Action 是动作：ban / observe。
	Action string `yaml:"action"`
	// Reason 是封禁原因文本；为空时自动生成（包含触发条件与命中次数）。
	Reason string `yaml:"reason"`
	// Score 是触发时累加的额外评分（通常与 threshold 单元配合）。
	Score int `yaml:"score"`
	// Alert 控制触发时是否同时产生告警事件（由后续里程碑的告警通道外送）。
	Alert bool `yaml:"alert"`
	// Store 是命中计数使用的存储实例名；为空表示使用默认存储。
	Store string `yaml:"store"`
	// StoreTimeout 是单次计数访问超时；<= 0 时取默认值。
	StoreTimeout core.Duration `yaml:"store_timeout"`
}

// Dimension 是单个自动封禁触发维度。
//
// 语义说明（用一句话概括）：
//
//	「谁」在 window 内累计触发 waf 拦截达到 threshold 次，就封禁「谁」ttl 时长；
//	而「谁」的粒度由 scope 决定——可以是 IP，也可以是「IP + 路径」。
//
// 之所以允许每个维度独立配置阈值与时长：不同维度的误伤代价完全不同。
// 例如按 IP 封禁的代价最高（可能误伤 NAT 出口后的整片办公网），
// 因此通常阈值更高、时长更短；按「IP + 路径」封禁的代价低得多，可以更激进。
type Dimension struct {
	// Scope 是封禁维度：client_ip / client_ip+site / client_ip+path / client_ip+method。
	Scope string `yaml:"scope"`
	// Threshold 是窗口内累计命中次数阈值；<= 0 时沿用顶层 settings.threshold。
	Threshold int `yaml:"threshold"`
	// Window 是该维度的命中统计窗口；<= 0 时沿用顶层 settings.window。
	Window core.Duration `yaml:"window"`
	// TTL 是该维度的封禁时长；<= 0 时沿用顶层 settings.ttl。
	TTL core.Duration `yaml:"ttl"`
}

// dimension 是补全默认值后的触发维度（运行时使用的内部形态）。
type dimension struct {
	// scope 是封禁维度。
	scope ban.KeyScope
	// threshold 是该维度的命中次数阈值（已补全默认值）。
	threshold int
	// window 是该维度的统计窗口（已补全默认值）。
	window time.Duration
	// ttl 是该维度的封禁时长（0 表示由 ban.default_ttl 兜底）。
	ttl core.Duration
}

// Check 是自动封禁校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段。
	phase core.Phase
	// order 是执行顺序。
	order int
	// triggers 是触发条件集合（判定结论名称，已小写化）。
	triggers map[string]struct{}
	// triggerAny 表示是否把任何终态结论都计入触发条件。
	triggerAny bool
	// dimensions 是解析补全后的触发维度列表（至少一项）。
	dimensions []dimension
	// minRank 是触发所需的最低严重度序号；0 表示不设门槛。
	minRank int
	// skipWhenBanned 表示来源已在该维度被封禁时是否跳过计数与重复写名单。
	skipWhenBanned bool
	// action 是动作。
	action string
	// reason 是封禁原因文本。
	reason string
	// score 是触发时累加的额外评分。
	score int
	// alert 表示是否产生告警事件。
	alert bool
	// store 是命中计数使用的存储实例（构造期解析完成）。
	store core.Store
	// storeTimeout 是单次计数访问超时。
	storeTimeout time.Duration
	// bans 是封禁控制器。
	bans core.BanController
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 autoban 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	if deps == nil || deps.Bans == nil {
		// 未装配封禁控制器说明部署漏配；直接失败比「自动封禁静默失效」安全得多。
		return nil, errors.New("autoban 需要注入封禁控制器（core.Deps.Bans），请检查启动装配")
	}
	if deps.Stores == nil {
		return nil, errors.New("autoban 需要注入共享存储（core.Deps.Stores），请检查启动装配")
	}

	threshold := settings.Threshold
	if threshold <= 0 {
		threshold = defaultThreshold
	}

	window := settings.Window.Duration()
	if window <= 0 {
		window = defaultWindow
	}

	action := settings.Action
	if action == "" {
		action = ActionBan
	}
	switch action {
	case ActionBan, ActionObserve:
	default:
		return nil, fmt.Errorf("autoban 的 action = %q 非法，可选值：ban / observe", action)
	}

	triggers := make(map[string]struct{}, len(settings.TriggerOn))
	triggerAny := false
	for _, item := range settings.TriggerOn {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if name == TriggerAny {
			triggerAny = true
			continue
		}
		triggers[name] = struct{}{}
	}
	if !triggerAny && len(triggers) == 0 {
		// 未配置触发条件时默认只对拦截类结论生效，行为可预期且最保守。
		triggers[core.VerdictBlock.String()] = struct{}{}
	}

	// 最低严重度门槛：与 threshold 单元的 min_severity 语义保持一致，
	// 非法取值必须在装配阶段报错——静默按「不设门槛」处理等于悄悄削弱了防护。
	minRank := 0
	if strings.TrimSpace(settings.MinSeverity) != "" {
		severity, ok := core.ParseSeverity(settings.MinSeverity)
		if !ok {
			return nil, fmt.Errorf("autoban 的 min_severity = %q 非法，可选值：%s",
				settings.MinSeverity, strings.Join(core.SeverityNames(), " / "))
		}
		minRank = severity.Rank()
	}

	// 触发维度：把各维度的阈值 / 窗口 / 时长补全为顶层默认值，
	// 并校验维度确实是运行期会被查询的维度（否则封禁写进去也没人查）。
	dimensions, err := buildDimensions(settings.Dimensions, threshold, window, settings.TTL, deps.Bans.Scopes())
	if err != nil {
		return nil, err
	}

	// 已被封禁时是否跳过计数：默认 true（见 Settings.SkipWhenBanned 的说明）。
	skipWhenBanned := true
	if settings.SkipWhenBanned != nil {
		skipWhenBanned = *settings.SkipWhenBanned
	}

	var store core.Store
	if settings.Store == "" {
		store, err = deps.Stores.Default()
	} else {
		store, err = deps.Stores.Resolve(settings.Store)
	}
	if err != nil {
		return nil, fmt.Errorf("解析 autoban 计数存储失败：%w", err)
	}

	timeout := settings.StoreTimeout.Duration()
	if timeout <= 0 {
		timeout = defaultStoreTimeout
	}

	return &Check{
		name:           inst.Name,
		phase:          inst.Phase,
		order:          inst.Order,
		triggers:       triggers,
		triggerAny:     triggerAny,
		dimensions:     dimensions,
		minRank:        minRank,
		skipWhenBanned: skipWhenBanned,
		action:         action,
		reason:         settings.Reason,
		score:          settings.Score,
		alert:          settings.Alert,
		store:          store,
		storeTimeout:   timeout,
		bans:           deps.Bans,
		logger:         deps.SystemLoggerOr(),
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

// Evaluate 判断本次请求是否应当触发自动封禁。
//
// 处理流程（逐层过滤，越靠前的判断代价越低）：
//
//  1. 请求上下文有效性；
//  2. 链结论是否属于触发条件（trigger_on）；
//  3. 命中严重度是否达到门槛（min_severity）；
//  4. 逐个触发维度计数：达到阈值即产出一条封禁动作。
//
// 多个维度可以同时命中（例如同一来源既满足 client_ip 维度、也满足 client_ip+path 维度），
// 此时会一并产出多条封禁动作，由 internal/ban 逐条落地——
// 这正是「维度可配置多个、多个则串联」的落地形态（需求 R6）。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}

	verdict := effectiveVerdict(rctx.Results())
	if !c.triggered(verdict) {
		return nil, nil
	}
	if !c.meetsSeverity(rctx) {
		// 严重度不足：只记 debug 日志，不计数也不告警，避免污染访问日志与告警通道。
		c.logger.Debug("自动封禁跳过：命中严重度未达门槛",
			"check", c.name, "request_id", rctx.RequestID, "min_severity_rank", c.minRank)
		return nil, nil
	}

	ctx := rctx.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if c.storeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.storeTimeout)
		defer cancel()
	}

	result := &core.Result{Check: c.name, Score: c.score}
	for _, dim := range c.dimensions {
		if err := c.evaluateDimension(ctx, rctx, verdict, dim, result); err != nil {
			// 返回错误而非「不封禁」：由 pipeline 按 on_error 策略处理，
			// 避免把「计数存储故障」静默变成「自动封禁永久失效」。
			return nil, err
		}
	}

	if len(result.Bans) == 0 && len(result.Findings) == 0 {
		// 全部维度都未达阈值：本次只计数，不产生任何结论。
		return nil, nil
	}
	return result, nil
}

// evaluateDimension 对单个维度执行「查状态 -> 计数 -> 判定 -> 记录」的完整流程。
//
// 之所以每个维度独立计数（而不是共用一个计数器）：
// 不同维度的键不同（ip:1.2.3.4 与 ip:1.2.3.4|path:/api），阈值语义也不同，
// 混用同一个计数器会让「IP 维度的 3 次」与「路径维度的 5 次」互相污染。
func (c *Check) evaluateDimension(ctx context.Context, rctx *core.RequestContext,
	verdict core.Verdict, dim dimension, result *core.Result) error {

	// 封禁键必须向 BanController 索取（与 banlist 的查询键同源），禁止自行拼接。
	banKey := c.bans.KeyForScope(rctx, string(dim.scope))
	if banKey == "" {
		// 无法确定该维度下的来源身份（例如客户端 IP 解析失败）时不封禁：
		// 无键的封禁要么落不了地，要么会误伤一整类来源。
		c.logger.Debug("自动封禁跳过维度：无法推导封禁键",
			"check", c.name, "request_id", rctx.RequestID, "scope", string(dim.scope))
		return nil
	}

	if c.skipWhenBanned {
		// 已经封禁过的来源不再重复计数与重复写名单：
		// 封禁生效期间的后续请求本就会被 banlist 拦截，
		// 继续计数会让「命中次数」失去参考意义，重复写名单还会让时长被无限续期。
		banned, _, err := c.store.IsBanned(ctx, banKey)
		if err != nil {
			return fmt.Errorf("查询封禁状态失败（key=%s）：%w", banKey, err)
		}
		if banned {
			c.logger.Debug("自动封禁跳过维度：来源已在该维度的封禁名单中",
				"check", c.name, "request_id", rctx.RequestID,
				"scope", string(dim.scope), "key", banKey)
			return nil
		}
	}

	countKey := counterKeyFor(dim, banKey)
	count, _, err := c.store.Incr(ctx, countKey, dim.window)
	if err != nil {
		return fmt.Errorf("自动封禁计数失败（key=%s）：%w", countKey, err)
	}
	if count < int64(dim.threshold) {
		// 尚未达到阈值：本次只计数，不产生任何结论（避免污染访问日志）。
		c.logger.Debug("自动封禁计数未达阈值",
			"check", c.name, "request_id", rctx.RequestID, "scope", string(dim.scope),
			"key", banKey, "count", count, "threshold", dim.threshold)
		return nil
	}

	c.appendDimensionResult(rctx, verdict, dim, banKey, count, result)
	return nil
}

// DefaultOnError 返回失败策略默认值。
//
// 取 pass（失败开放）：计数存储故障时不应改变本次请求的判定结果
// （本次是否拦截已由前面的校验单元决定），更不应该因为封禁统计失败而拦截全站。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：存储与封禁控制器由 cmd/waf 统一持有与关闭。
func (c *Check) Close() error { return nil }

// appendDimensionResult 把单个维度的判定结果写入结论集。
//
// 说明：结果本身不产生判定结论（Verdict 保持零值 VerdictContinue），
// 是否拦截本次请求是 threshold 等单元的职责；本单元只负责「把这个来源列入名单」。
func (c *Check) appendDimensionResult(rctx *core.RequestContext, verdict core.Verdict,
	dim dimension, banKey string, count int64, result *core.Result) {

	reason := c.reason
	if reason == "" {
		reason = fmt.Sprintf("自动封禁：%s 维度在窗口 %s 内累计命中 %d 次（触发结论 %s）",
			dim.scope, dim.window, count, verdict)
	}

	finding := core.NewFinding(c.name, ruleIDAutoBan, reason, core.SeverityHigh, 0)
	finding.Data = map[string]string{
		"ban_key":   banKey,
		"ban_scope": string(dim.scope),
		"hit_count": fmt.Sprintf("%d", count),
		"threshold": fmt.Sprintf("%d", dim.threshold),
		"window":    dim.window.String(),
		"verdict":   verdict.String(),
		"action":    c.action,
	}
	result.Findings = append(result.Findings, finding)

	if c.action == ActionObserve {
		// 观察模式：只记录与告警，绝不写入封禁名单。
		if c.alert {
			result.Alerts = append(result.Alerts, c.newAlert(rctx, dim.scope, banKey, count, true))
		}
		return
	}

	// 键与维度都显式指定：与刚才计数的键、以及 banlist 的查询键保持同一身份。
	result.Bans = append(result.Bans, core.BanRequest{
		Key:    banKey,
		Scope:  string(dim.scope),
		TTL:    dim.ttl.Duration(),
		Reason: reason,
		RuleID: ruleIDAutoBan,
	})
	if c.alert {
		result.Alerts = append(result.Alerts, c.newAlert(rctx, dim.scope, banKey, count, false))
	}

	c.logger.Warn("触发自动封禁",
		"check", c.name,
		"request_id", rctx.RequestID,
		"ban_scope", string(dim.scope),
		"ban_key", banKey,
		"hit_count", count,
		"threshold", dim.threshold,
		"window", dim.window.String(),
		"enforcement", "仅 WAF 内部生效，不涉及系统防火墙",
	)
}

// newAlert 构造自动封禁告警事件。
func (c *Check) newAlert(rctx *core.RequestContext, scope ban.KeyScope, banKey string,
	count int64, observe bool) core.Alert {
	title := "自动封禁触发"
	mode := "已写入内部封禁名单"
	if observe {
		title = "自动封禁触发（观察模式）"
		mode = "观察模式，未写入封禁名单"
	}

	site := core.DefaultSiteName
	if rctx.Site != nil {
		site = rctx.Site.Name
	}

	return core.Alert{
		Level: core.AlertLevelWarn,
		Title: title,
		Message: fmt.Sprintf("%s：%s 维度下的 %s 在统计窗口内累计命中 %d 次（%s）",
			title, scope, banKey, count, mode),
		Site:      site,
		ClientIP:  rctx.Raw.ClientIP,
		RequestID: rctx.RequestID,
		Fields: map[string]string{
			"ban_key":   banKey,
			"ban_scope": string(scope),
			"hit_count": fmt.Sprintf("%d", count),
			"check":     c.name,
		},
		At: rctx.ReceivedAt,
	}
}

// meetsSeverity 判断本次请求的命中是否达到最低严重度门槛。
//
// 判定口径：只要**任意一条**命中达到门槛即视为通过。
// 之所以不是「全部命中都达标」：攻击者往往同时触发低危与高危规则
// （例如协议异常 + SQL 注入），要求全部达标会让门槛形同虚设。
//
// minRank 为 0（未配置 min_severity）时不做过滤，保持与旧版本一致的行为。
func (c *Check) meetsSeverity(rctx *core.RequestContext) bool {
	if c.minRank <= 0 {
		return true
	}
	for _, finding := range rctx.AllFindings() {
		if finding.Severity.Rank() >= c.minRank {
			return true
		}
	}
	return false
}

// counterKeyFor 构造某个维度在某个键上的命中计数键。
//
// 为什么把维度与窗口都编进键名：
//   - 编入维度：同一来源在不同维度下的计数互不影响；
//   - 编入窗口：窗口长度是阈值语义的一部分（「5 分钟内 3 次」与「1 小时内 3 次」
//     不可共用计数器），避免运维调整窗口后残留旧计数导致阈值瞬间被击穿。
func counterKeyFor(dim dimension, banKey string) string {
	return counterNamespace + string(dim.scope) + "|" + banKey + "|" + dim.window.String()
}

// buildDimensions 解析并补全触发维度列表。
//
// 设计要点（需求 R5 / R6：能力可配置、可多个并存、多个则串联）：
//   - 未配置 dimensions 时退化为单一的 client_ip 维度，旧配置行为完全不变；
//   - 每项可单独覆盖 threshold / window / ttl，未覆盖的沿用顶层取值；
//   - 维度必须在运行期真的会被查询（enabledScopes，即 ban.ban_keys），
//     否则会出现「封禁写进去了、却没人查」的静默失效，因此在这里直接 fail fast。
func buildDimensions(items []Dimension, threshold int, window time.Duration,
	ttl core.Duration, enabledScopes []string) ([]dimension, error) {

	if len(items) == 0 {
		// 默认维度：按客户端 IP 封禁。这是最通用、也最容易解释的一种封禁语义。
		return []dimension{{
			scope:     ban.ScopeClientIP,
			threshold: threshold,
			window:    window,
			ttl:       ttl,
		}}, nil
	}

	enabled := make(map[string]struct{}, len(enabledScopes))
	for _, name := range enabledScopes {
		enabled[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}

	dimensions := make([]dimension, 0, len(items))
	seen := make(map[ban.KeyScope]struct{}, len(items))
	for index, item := range items {
		scope, ok := ban.ParseKeyScope(item.Scope)
		if !ok {
			return nil, fmt.Errorf("autoban 的 dimensions[%d].scope = %q 非法，可选值：%s",
				index, item.Scope, strings.Join(ban.KeyScopeNames(), " / "))
		}
		if _, duplicated := seen[scope]; duplicated {
			return nil, fmt.Errorf("autoban 的 dimensions[%d].scope = %q 重复声明，同一维度只需配置一次",
				index, item.Scope)
		}
		if _, ok := enabled[string(scope)]; !ok {
			return nil, fmt.Errorf("autoban 的 dimensions[%d].scope = %q 未在 ban.ban_keys 中启用（当前：%s），"+
				"该维度写入的封禁名单不会被任何请求查到",
				index, item.Scope, strings.Join(enabledScopes, " / "))
		}
		seen[scope] = struct{}{}

		entry := dimension{scope: scope, threshold: threshold, window: window, ttl: ttl}
		if item.Threshold > 0 {
			entry.threshold = item.Threshold
		}
		if item.Window.Duration() > 0 {
			entry.window = item.Window.Duration()
		}
		if item.TTL.Duration() > 0 {
			entry.ttl = item.TTL
		}
		dimensions = append(dimensions, entry)
	}
	return dimensions, nil
}

// triggered 判断判定结论是否命中触发条件。
func (c *Check) triggered(verdict core.Verdict) bool {
	if verdict == core.VerdictContinue || verdict == core.VerdictAllow {
		// 放行类结论不计入触发条件：把「放行」当作攻击证据是逻辑错误。
		return false
	}
	if c.triggerAny {
		return true
	}
	_, ok := c.triggers[verdict.String()]
	return ok
}

// effectiveVerdict 依据已执行单元的结论集合推导本次请求的最终判定。
//
// 推导规则与执行器的结论合并规则保持一致（见 internal/pipeline 的 mergeResult）：
// 首个「拒绝类」结论胜出，观察结论会被后续的拒绝类结论覆盖。
// 之所以在执行器之外再推导一次：PhasePost 单元拿到的只有 RequestContext，
// 而本单元需要在「链已短路」的情况下依然知道链结论是什么。
func effectiveVerdict(results []*core.Result) core.Verdict {
	merged := core.VerdictContinue
	for _, result := range results {
		if result == nil || result.Verdict == core.VerdictContinue {
			continue
		}
		if merged == core.VerdictContinue || merged == core.VerdictObserve {
			merged = result.Verdict
		}
	}
	return merged
}
