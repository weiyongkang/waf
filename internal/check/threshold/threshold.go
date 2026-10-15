// Package threshold 实现「异常评分阈值」校验单元（PhasePost）。
//
// 定位（需求 R6 / R8）：
//
//	把前面各校验单元累加的异常评分（anomaly score）与配置阈值比较，
//	超过阈值时给出终态结论（block / observe）。
//
// 为什么必须放在收尾阶段：
//
//	异常评分是「多个单元共同累加」的结果，只有在链尾才能真正判定；
//	执行器（internal/pipeline）对 PhasePost 单元采用「即使链已短路也要全部执行」
//	的收尾语义，因此放在 post 阶段能稳定拿到完整评分。
//
// 评分来源（两者取较大值）：
//
//   - RequestContext.Score()：执行器把各单元 Result.Score 统一汇总后的总分，
//     自研插件（ipaccess / ratelimit / banlist ...）走这条路径；
//
//   - settings.score_key 指向的状态键：检测引擎（Coraza/CRS）按
//     inbound_anomaly_score 之类的名字自行写入的评分，走这条路径。
//
//     取较大值而不是求和：两条路径表达的是「同一批命中的不同记账方式」，
//     求和会导致同一命中被计两次而提前触发拦截（误伤）。
package threshold

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "threshold"

// ruleIDThreshold 是阈值命中使用的内置规则标识。
const ruleIDThreshold = "inbound_threshold_exceeded"

// 动作常量（配置项 settings.action）。
const (
	// ActionBlock 表示超过阈值时拦截（默认）。
	ActionBlock = "block"
	// ActionObserve 表示超过阈值时只记录（DetectionOnly 灰度验证）。
	ActionObserve = "observe"
)

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 threshold 的私有配置片段。
type Settings struct {
	// ScoreKey 是评分所在的状态键；为空时使用执行器统一汇总键（anomaly_score）。
	ScoreKey string `yaml:"score_key"`
	// InboundThreshold 是入站评分的拦截阈值，必须大于 0。
	//
	// 采用 CRS 的命名（inbound_*）是为了与检测引擎的字段保持一致，
	// 运维在看 CRS 日志与本配置之间切换时不需要做名称翻译。
	InboundThreshold int `yaml:"inbound_threshold"`
	// Action 是超过阈值后的动作：block / observe。
	Action string `yaml:"action"`
	// Score 是超过阈值时额外累加的评分（通常用于串联到后续 autoban 的判定条件）。
	Score int `yaml:"score"`
	// RuleID 是命中明细使用的规则标识；为空时使用内置标识。
	RuleID string `yaml:"rule_id"`
	// MinSeverity 是拦截门槛：只有存在至少一条该级别及以上的命中时才允许拦截。
	//
	// 使用场景：某个低危规则集合会把评分推高，但运维并不希望仅凭它们拦截请求，
	// 此时把门槛设为 high，要求「总评分达标」且「存在高危命中」两个条件同时成立。
	// 留空表示不设门槛（默认）。
	MinSeverity string `yaml:"min_severity"`
}

// Check 是异常评分阈值校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段。
	phase core.Phase
	// order 是执行顺序。
	order int
	// scoreKey 是评分所在的状态键。
	scoreKey string
	// threshold 是拦截阈值。
	threshold int
	// action 是超过阈值后的动作。
	action string
	// score 是超过阈值时额外累加的评分。
	score int
	// ruleID 是命中明细使用的规则标识。
	ruleID string
	// minSeverity 是拦截门槛的严重级别排序值；0 表示不设门槛。
	minSeverity int
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 threshold 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	// 阈值缺省继承 engine.anomaly_score_threshold。
	//
	// 为什么必须继承而不是各自设默认值：CRS 自身的阻断判定（REQUEST-949）与
	// 本单元的阈值判定表达的是同一件事（「评分累计到多少就该拦」），
	// 两处若取不同数字，就会出现「引擎认为该拦、WAF 却不拦」的割裂现象。
	// 实例级显式配置仍然优先（需求 R8：可覆盖）。
	threshold := settings.InboundThreshold
	if threshold <= 0 {
		threshold = deps.Engine.AnomalyScoreThreshold
	}
	if threshold <= 0 {
		return nil, fmt.Errorf(
			"threshold 的 inbound_threshold 未配置，且 engine.anomaly_score_threshold 也不是正整数（当前 %d）",
			threshold,
		)
	}

	action := settings.Action
	if action == "" {
		action = ActionBlock
	}
	switch action {
	case ActionBlock, ActionObserve:
	default:
		return nil, fmt.Errorf("threshold 的 action = %q 非法，可选值：block / observe", action)
	}

	scoreKey := strings.TrimSpace(settings.ScoreKey)
	if scoreKey == "" {
		scoreKey = core.StateKeyScore
	}

	minSeverity := 0
	if strings.TrimSpace(settings.MinSeverity) != "" {
		severity, ok := core.ParseSeverity(settings.MinSeverity)
		rank := severity.Rank()
		if !ok {
			return nil, fmt.Errorf("threshold 的 min_severity = %q 非法，可选值：info / low / medium / high / critical",
				settings.MinSeverity)
		}
		minSeverity = rank
	}

	ruleID := settings.RuleID
	if ruleID == "" {
		ruleID = ruleIDThreshold
	}

	return &Check{
		name:        inst.Name,
		phase:       inst.Phase,
		order:       inst.Order,
		scoreKey:    scoreKey,
		threshold:   threshold,
		action:      action,
		score:       settings.Score,
		ruleID:      ruleID,
		minSeverity: minSeverity,
		logger:      deps.SystemLoggerOr(),
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

// Evaluate 比较异常评分与阈值。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil {
		return nil, nil
	}

	total := c.effectiveScore(rctx)
	if total < c.threshold {
		return nil, nil
	}

	// 严重级别门槛：要求存在一条足够严重的命中，避免「一堆低危命中凑出高分」导致误拦。
	if c.minSeverity > 0 && !hasFindingAtLeast(rctx.AllFindings(), c.minSeverity) {
		return nil, nil
	}

	verdict := core.VerdictBlock
	code := config.CodeBlocked
	if c.action == ActionObserve {
		verdict = core.VerdictObserve
		code = ""
	}

	result := core.NewResult(c.name, verdict)
	result.Code = code

	finding := core.NewFinding(c.name, c.ruleID,
		fmt.Sprintf("异常评分 %d 达到阈值 %d", total, c.threshold),
		core.SeverityHigh, c.score)
	finding.Data = map[string]string{
		"score":     fmt.Sprintf("%d", total),
		"threshold": fmt.Sprintf("%d", c.threshold),
		"score_key": c.scoreKey,
		"action":    c.action,
	}
	result.AddFinding(finding)

	c.logger.Debug("异常评分达到阈值",
		"check", c.name,
		"request_id", rctx.RequestID,
		"score", total,
		"threshold", c.threshold,
		"action", c.action,
	)
	return result, nil
}

// DefaultOnError 返回失败策略默认值。
//
// 取 pass（失败开放）：本单元是纯内存计算，不存在外部依赖故障，
// 因此「运行失败」只会来自实现缺陷；此时放过请求比拦截全站更可控。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：本单元不持有需要释放的资源。
func (c *Check) Close() error { return nil }

// effectiveScore 返回本次请求的异常评分总量。
//
// 取「执行器统一汇总键」与「配置的评分键」两者较大值，理由见包注释。
func (c *Check) effectiveScore(rctx *core.RequestContext) int {
	total := rctx.Score()
	if c.scoreKey != core.StateKeyScore {
		if value, ok := stateInt(rctx.State(c.scoreKey)); ok && value > total {
			total = value
		}
	}
	return total
}

// stateInt 把状态值转换为整数，兼容不同实现写入的数值类型。
func stateInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case int32:
		return int(typed), true
	case float64:
		return int(typed), true
	default:
		return 0, false
	}
}

// hasFindingAtLeast 判断是否存在严重级别不低于 rank 的命中。
func hasFindingAtLeast(findings []core.Finding, rank int) bool {
	for _, finding := range findings {
		// 未知级别（空值或插件自定义值）按 0 处理，绝不参与「够严重」的判定。
		if current := finding.Severity.Rank(); current > 0 && current >= rank {
			return true
		}
	}
	return false
}
