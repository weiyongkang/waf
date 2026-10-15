// Package passthrough 提供「空校验单元」实现，用于冒烟测试与基线对照。
//
// 用途：
//
//   - 装配冒烟：把 passthrough 放进 pipeline，即可验证「注册 -> 构造 -> 排序 -> 串联 -> 日志」
//     整条链路是否通畅，而不会对业务流量产生任何拦截影响；
//   - 基线对照：压测时作为「零检测开销」的对照项，用于测量串联框架自身的固定成本；
//   - 灰度占位：先用 passthrough 占住某个 phase / order，后续替换为真实实现即可。
//
// 该实现永远返回空结论（nil），因此串联链一定会继续执行后续校验单元。
package passthrough

import (
	"log/slog"

	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名（配置中 pipeline[].type 的取值）。
const Type = "passthrough"

// init 在包初始化阶段完成类型注册（编译期装配，不使用任何动态加载）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 passthrough 的私有配置片段（配置文件中的 pipeline[].settings）。
type Settings struct {
	// Log 为 true 时，每个请求都会写一条 debug 级系统日志，便于确认串联顺序是否生效。
	Log bool `yaml:"log"`
}

// Check 是空校验单元实例，实现 core.Check 与 core.OnErrorDefaulter。
type Check struct {
	// name 是实例名（配置中的 name）。
	name string
	// phase 是执行阶段。
	phase core.Phase
	// order 是同阶段内的执行顺序。
	order int
	// verbose 控制是否输出执行日志。
	verbose bool
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 passthrough 校验单元。
//
// 构造阶段即完成配置解析（严格模式）：settings 中出现未知字段会直接报错，
// 避免「以为开了日志其实字段名写错」这类静默失效。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	return &Check{
		name:    inst.Name,
		phase:   inst.Phase,
		order:   inst.Order,
		verbose: settings.Log,
		logger:  deps.SystemLoggerOr(),
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

// Evaluate 永远返回空结论，表示「本次不产生任何判定」。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || !c.verbose {
		return nil, nil
	}
	c.logger.Debug("passthrough 校验单元已执行",
		"check", c.name, "request_id", rctx.RequestID, "phase", c.phase.String())
	return nil, nil
}

// DefaultOnError 返回失败策略默认值：本实现无检测逻辑，失败开放即可。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：本实现不持有任何资源，直接返回 nil（必须幂等）。
func (c *Check) Close() error { return nil }
