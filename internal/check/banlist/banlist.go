// Package banlist 实现「内部封禁名单」校验单元（PhasePre）。
//
// 定位（需求 R17 / R18）：
//
//	检查请求来源是否已在**共享存储**的封禁名单中；命中则按 action 拦截或仅观察。
//	名单由本 WAF 自身写入（autoban / ratelimit 触发的封禁、或运维通过 `waf ban add` 手工下发），
//	**不涉及任何系统防火墙操作**。
//
// 之所以放在 PhasePre：封禁是最廉价也最该最先执行的判定——
// 命中即短路，可以完全避免后续的请求头解析、请求体读取与规则匹配开销。
package banlist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "banlist"

// 动作常量。
const (
	// ActionBlock 表示命中封禁名单时直接拦截。
	ActionBlock = "block"
	// ActionObserve 表示命中封禁名单时只记录，不拦截。
	//
	// 使用场景：刚上线自动封禁能力时，先用 observe 观察名单是否会误伤业务来源。
	ActionObserve = "observe"
)

// defaultStoreTimeout 是单次存储查询的默认超时。
//
// 之所以必须有超时：每次请求都要查一次名单，若存储变慢（例如 Redis 主从切换），
// 没有超时会让整个请求链路被拖垮；宁可查询失败（按 on_error 处理）也不要拖慢全站。
const defaultStoreTimeout = 200 * time.Millisecond

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 banlist 的私有配置片段。
type Settings struct {
	// Action 是命中后的动作：block / observe。
	Action string `yaml:"action"`
	// Score 是命中时累加的异常评分。
	Score int `yaml:"score"`
	// StoreTimeout 是单次存储查询超时；<=0 时取默认值。
	StoreTimeout core.Duration `yaml:"store_timeout"`
}

// Check 是内部封禁名单校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段。
	phase core.Phase
	// order 是执行顺序。
	order int
	// action 是命中后的动作。
	action string
	// score 是命中时累加的评分。
	score int
	// storeTimeout 是存储查询超时。
	storeTimeout time.Duration
	// bans 是封禁控制器（由 internal/ban 提供）。
	bans core.BanController
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 banlist 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	if deps.Bans == nil {
		// 未装配封禁控制器说明部署漏配了 ban 相关组件；
		// 直接失败比「静默不拦截」安全得多（否则运维会误以为封禁已生效）。
		return nil, errors.New("banlist 需要注入封禁控制器（core.Deps.Bans），请检查启动装配")
	}

	action := settings.Action
	if action == "" {
		action = ActionBlock
	}
	switch action {
	case ActionBlock, ActionObserve:
	default:
		return nil, fmt.Errorf("banlist 的 action = %q 非法，可选值：block / observe", action)
	}

	timeout := settings.StoreTimeout.Duration()
	if timeout <= 0 {
		timeout = defaultStoreTimeout
	}

	return &Check{
		name:         inst.Name,
		phase:        inst.Phase,
		order:        inst.Order,
		action:       action,
		score:        settings.Score,
		storeTimeout: timeout,
		bans:         deps.Bans,
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

// Evaluate 查询封禁名单并给出结论。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
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

	// 按部署启用的全部封禁维度查询（ban.ban_keys，可配置多个）。
	// 之所以一次查全部维度：名单可能由不同维度的规则写入（例如 autoban 同时按
	// client_ip 与 client_ip+path 触发），只查单一维度会出现「封了却没有生效」。
	banned, remaining, key, scope, err := c.bans.CheckScopes(ctx, rctx)
	if err != nil {
		// 返回错误而不是「未封禁」：让 pipeline 按 on_error 决定放行还是拦截，
		// 避免把「存储不可用」静默降级成「没有封禁」。
		return nil, fmt.Errorf("查询封禁名单失败（key=%s）：%w", key, err)
	}
	if !banned {
		return nil, nil
	}

	result := core.NewResult(c.name, core.VerdictBlock)
	if c.action == ActionObserve {
		result.Verdict = core.VerdictObserve
	} else {
		result.Code = config.CodeBlocked
		// 剩余封禁时长回传给客户端（Retry-After），便于爬虫与自动化脚本正确退避。
		if remaining > 0 {
			result.RetryAfter = remaining
		}
	}

	finding := core.NewFinding(c.name, "internal_banlist", "来源已在内部封禁名单中",
		core.SeverityHigh, c.score)
	finding.Data = map[string]string{
		"target":         scope,
		"ban_key":        key,
		"ban_scope":      scope,
		"remaining":      remaining.String(),
		"ban_key_policy": "见配置项 ban.ban_keys（为空时取 ban.ban_key）",
		"enforcement":    "仅 WAF 内部生效（不涉及系统防火墙）",
	}
	result.AddFinding(finding)

	return result, nil
}

// DefaultOnError 返回失败策略默认值。
//
// 取 pass（失败开放）：存储抖动时不希望因为「查不到名单」而拦截全站流量。
// 安全优先的部署可在实例上显式配置 on_error: block（此时存储故障会返回 503）。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：存储由 internal/store 统一持有与关闭，本单元无需释放。
func (c *Check) Close() error { return nil }
