package core

// InstanceConfig 是「校验单元实例」的配置声明，对应配置文件中 pipeline 数组的一项。
//
// 设计要点（需求 R5 / R6 / R8）：
//   - enabled 控制启用，关闭的实例在构建 pipeline 时直接丢弃，运行期零开销；
//   - 同一 type 可以声明多个实例（例如两个 ratelimit，分别限制全站与登录接口）；
//   - 多个实例按 Phase + Order 串联执行，形成有序校验链。
type InstanceConfig struct {
	// Name 是实例名，必须全局唯一；用于日志、指标标签与配置摘要。
	Name string `yaml:"name"`
	// Type 是实现类型，对应注册表中的键（例如 banlist / ipaccess / ratelimit）。
	Type string `yaml:"type"`
	// Enabled 表示是否启用该实例；缺省为 false，即「默认全关，按需开启」。
	Enabled bool `yaml:"enabled"`
	// Order 是同一阶段内的执行顺序，数值小的先执行。
	Order int `yaml:"order"`
	// Phase 是执行阶段。
	Phase Phase `yaml:"phase"`
	// OnError 是本实例自身出错时的处理策略：
	//   pass  = 失败开放（放过请求，仅记录 error 级日志）
	//   block = 失败关闭（拦截请求，返回 WAF_UNAVAILABLE / 503）
	// 为空时按类型默认值处理（引擎类默认 block，其余默认 pass）。
	OnError string `yaml:"on_error"`
	// Settings 是该实例的私有配置片段，由各插件自行解析为强类型结构。
	Settings map[string]any `yaml:"settings"`
}

// Check 是「可插拔校验单元」的统一抽象（需求 R7）。
//
// 一个功能项 = 一个 Check 实现；新增能力只需要新增一个实现并在注册表登记，
// 主流程（pipeline / server / responder）完全不需要改动。
//
// 实现约束：
//   - Evaluate 必须并发安全，同一实例会被多个请求 goroutine 同时调用；
//   - Evaluate 不得修改 RequestContext 中除 State 以外的字段；
//   - Evaluate 内部的所有耗时操作必须受 RequestContext 的上下文控制。
type Check interface {
	// Name 返回实例名（配置中的 name）。
	Name() string
	// Type 返回实现类型（配置中的 type）。
	Type() string
	// Phase 返回执行阶段。
	Phase() Phase
	// Order 返回同阶段内的执行顺序。
	Order() int
	// Evaluate 执行本次校验并返回结论。
	//
	// 返回的 error 表示「本校验单元自身运行失败」（例如共享存储不可用），
	// 与「判定为拦截」是两件事：前者交给 on_error 策略处理，后者通过 Result.Verdict 表达。
	Evaluate(ctx *RequestContext) (*Result, error)
	// Close 释放该实例持有的资源（连接池、临时文件、后台 goroutine 等）。
	// 必须在进程退出前被调用且幂等。
	Close() error
}

// CheckFactory 是校验单元的构造函数，由各插件包在 init 阶段通过 RegisterCheck 登记。
//
// 工厂在启动装配阶段被调用一次（而非每次请求），因此可以在这里完成配置解析、
// 连接池建立、规则加载等昂贵操作；这些错误必须在启动时暴露（fail fast）。
type CheckFactory func(inst InstanceConfig, deps *Deps) (Check, error)

// OnErrorDefaulter 是可选接口，由校验单元实现以声明自身的失败策略默认值。
//
// 之所以需要它：不同能力域对「自身故障」的容忍度完全不同——
// 检测引擎故障时应当失败关闭（宁可拦截也不放过不可检测的流量），
// 而限速、封禁名单这类依赖外部存储的能力故障时应当失败开放（避免存储抖动导致全站不可用）。
// 若实例未显式配置 on_error，则由实现方自报默认值；未实现该接口时统一按 pass（失败开放）处理。
type OnErrorDefaulter interface {
	// DefaultOnError 返回该实现的失败策略默认值，取值为 "pass" 或 "block"。
	DefaultOnError() string
}

// 失败策略取值常量，供配置校验与 pipeline 共用，避免字符串拼写不一致。
const (
	// OnErrorPass 表示失败开放：校验单元自身出错时放过请求，仅记录 error 级日志。
	OnErrorPass = "pass"
	// OnErrorBlock 表示失败关闭：校验单元自身出错时拦截请求（对外 503）。
	OnErrorBlock = "block"
)
