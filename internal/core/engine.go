package core

import "time"

// EngineSettings 是传递给检测引擎校验单元（type=coraza）的全局引擎配置。
//
// 为什么需要它：检测引擎的规则目录、偏执等级、请求体限额属于「全局引擎配置」
// （配置文件中的 engine 段），而不是某个 pipeline 实例的私有配置；
// 但校验单元的构造函数只能拿到 core.InstanceConfig 与 core.Deps。
// 把 engine 段映射为本结构挂在 Deps.Engine 上，插件即可读到全局配置，
// 同时避免 core 反向依赖 config 包（core 是被依赖方，不允许导入 config）。
type EngineSettings struct {
	// Enabled 为 false 时不加载任何规则，检测引擎插件在装配阶段直接失败，
	// 提示「engine.enabled=false 与 pipeline 中的 coraza 实例冲突」，
	// 而不是静默地跑一个没有任何规则的引擎（那会造成「以为有防护」的错觉）。
	Enabled bool
	// Mode 是引擎模式：on / detection_only。
	Mode string
	// ParanoiaLevel 是 CRS 的偏执等级（1–4）。
	ParanoiaLevel int
	// RuleDirs 是规则目录列表；为空表示使用内置（编译期嵌入）的 CRS 规则集。
	RuleDirs []string
	// CustomRuleDirs 是追加的自定义规则目录列表，在内置 / 主规则集之后加载。
	CustomRuleDirs []string
	// RuleInclude 是目录内的文件匹配模式，例如 ["*.conf"]。
	RuleInclude []string
	// RuleDataInclude 是「规则引用的数据文件」匹配模式，例如 ["*.data"]。
	RuleDataInclude []string
	// CRSSetup 是 CRS 设置文件名（相对规则根）。
	CRSSetup string
	// InlineDirectives 是追加的 SecLang 指令，位于引擎基础设置之后、规则文件之前。
	InlineDirectives []string
	// VirtualPatches 是启用的内置虚拟补丁模板标识。
	VirtualPatches []string
	// VirtualPatchFiles 是自定义 SecLang 虚拟补丁文件。
	VirtualPatchFiles []string
	// BodyAccess 对应 SecRequestBodyAccess。
	BodyAccess bool
	// BodyLimitBytes 对应 SecRequestBodyLimit。
	BodyLimitBytes int64
	// BodyInMemoryLimitBytes 对应 SecRequestBodyInMemoryLimit。
	BodyInMemoryLimitBytes int64
	// BodyLimitAction 取值 reject 或 processPartial，对应 SecRequestBodyLimitAction。
	BodyLimitAction string
	// JSONDepthLimit 是 JSON 解析深度上限。
	JSONDepthLimit int
	// ParseMultipart 决定是否解析 multipart 请求体。
	ParseMultipart bool
	// Processors 是「内容类型 -> 请求体处理器」的映射列表。
	//
	// 为什么必须显式配置：Coraza 只会依据 Content-Type 自动选择 URLENCODED 与
	// MULTIPART 处理器，JSON / XML 必须通过 ctl:requestBodyProcessor=<NAME> 显式指定。
	// 若不配置，application/json 的请求体会被当作 URLENCODED 解析，
	// JSON 载荷几乎无法被 CRS 检出（需求 R4：请求体检测）。
	//
	// 语义：nil 表示使用内置默认映射（JSON / XML）；显式写空切片表示不做任何路由映射。
	Processors []BodyProcessorSetting
	// AnomalyScoreThreshold 是 CRS 入站异常评分阈值（tx.inbound_anomaly_score_threshold）。
	//
	// 该值会同时用于两处，保证判定口径一致：
	//  1. 注入 SecRule 动作，覆盖 CRS 自身的阈值（CRS 的阻断判定使用它）；
	//  2. 作为 pipeline 中 threshold 单元的缺省阈值（阈值单元未显式配置时使用）。
	AnomalyScoreThreshold int
	// Exceptions 是误报例外清单，由 internal/rules/exceptions 编译为 SecLang 指令。
	Exceptions []ExceptionSetting
	// HotReload 是规则热加载配置；Enabled 为 false 时引擎完全不做文件监听。
	HotReload HotReloadSetting
}

// ExceptionSetting 是「编译后的误报例外」这一能力的输入视图。
//
// 为什么不让 core 直接引用 config.ExceptionConfig：core 是被依赖方，
// 不允许反向导入 config（会造成循环依赖）。这里用同构的轻量结构承载，
// 由 cmd/waf 在装配阶段完成映射（与 EngineSettings 的其它字段一致）。
type ExceptionSetting struct {
	// Name 是例外的审计标识。
	Name string
	// Enabled 为 false 时该条例外只参与审计输出、不生成任何指令。
	//
	// 之所以把开关一路传到这里而不是在装配阶段过滤：被关闭的例外同样是审计信息
	// （它解释了「为什么这里不再拦截」），过滤掉会让审计报表出现盲区。
	Enabled bool
	// Reason 是例外原因（审计用）。
	Reason string
	// RuleIDs 是要放行的规则 ID 或 ID 区间。
	RuleIDs []string
	// Tags 是要放行的规则标签。
	Tags []string
	// Targets 是要摘除的检测目标（例如 ARGS:password），需配合 RuleIDs 使用。
	Targets []string
	// URLPattern 是例外生效的 URL 正则；为空表示不限 URL。
	URLPattern string
	// Methods 是例外生效的方法列表；为空表示不限方法。
	Methods []string
	// ExpiresAt 是失效时间（零值表示永不过期）。
	ExpiresAt time.Time
}

// HotReloadSetting 是规则热加载配置。
type HotReloadSetting struct {
	// Enabled 控制是否监听磁盘规则文件的变化。
	Enabled bool
	// Debounce 是文件变化去抖动时间。
	Debounce time.Duration
	// PollInterval 是文件指纹的轮询间隔。
	PollInterval time.Duration
	// MarkerFile 是「运维主动触发重载」的标记文件路径；为空表示不支持手动触发。
	MarkerFile string
}

// BodyProcessorSetting 描述「内容类型 -> 请求体处理器」的一条映射。
//
// 之所以做成列表而不是固定两个开关：业务可能使用 JSON 派生类型
// （application/vnd.api+json）或 XML 派生类型，也可能需要临时关闭某一类解析；
// 列表加启用开关即可覆盖这些场景，且完全由配置驱动（需求 R5-R8）。
type BodyProcessorSetting struct {
	// Name 是 Coraza 的请求体处理器名：JSON / XML / MULTIPART / URLENCODED。
	Name string `yaml:"name"`
	// ContentTypes 是匹配 Content-Type 的正则表达式列表，任一匹配即选用该处理器。
	ContentTypes []string `yaml:"content_types"`
	// Enabled 控制该条映射是否生成指令。
	Enabled bool `yaml:"enabled"`
}

// BodyAccessEnabled 报告是否允许读取请求体。
//
// 之所以把 Access 与 LimitAction 的判定收敛到这里：两个开关的取值都必须满足，
// 任一为否则体检测整体失效，插件不应该分别判断（容易漏判其中一项）。
func (e EngineSettings) BodyAccessEnabled() bool {
	return e.Enabled && e.BodyAccess
}
