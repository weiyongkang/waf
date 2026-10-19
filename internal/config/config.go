// Package config 负责 WAF 的全部配置加载：三通道（环境变量 / 配置文件 / CLI）、
// 优先级叠加（CLI > 配置文件 > 环境变量 > 内置默认值）、结构校验与来源摘要。
//
// 为什么优先级是本项目特有的：reference/honeypot 的优先级是「环境变量 > 配置文件 > 默认值」，
// 与本项目要求的「CLI > 配置文件 > 环境变量」相反，因此配置包必须自研，
// 不能照搬参考实现的配置加载逻辑（设计文档 §2.7）。
package config

import "github.com/weiyongkang/waf/internal/core"

// Config 是 WAF 的完整配置树，字段与 configs/waf.example.yaml 一一对应。
//
// 约定：
//   - 所有时长字段使用 core.Duration，配置中写人类可读形式（如 "30m"）；
//   - 所有大小 / 容量 / 阈值项都必须出现在配置树中，禁止在业务代码里硬编码（需求 R13）；
//   - 数组型配置（pipeline / stores / notifiers / sites）只支持配置文件声明，
//     标量项支持三通道覆盖（设计文档 §2.7）。
type Config struct {
	// Version 是配置格式版本，用于后续兼容性判断。
	Version int `yaml:"version"`
	// Server 是 HTTP 服务相关配置。
	Server ServerConfig `yaml:"server"`
	// Ingress 是接入适配配置：原始请求还原与请求体通道。
	Ingress IngressConfig `yaml:"ingress"`
	// Responder 是拦截响应配置（统一 JSON 错误体，不提供拦截页面）。
	Responder ResponderConfig `yaml:"responder"`
	// Engine 是检测引擎配置（Coraza + CRS），可整体关闭。
	Engine EngineConfig `yaml:"engine"`
	// Sites 是站点策略列表，用于多站点差异化。
	Sites []SiteConfig `yaml:"sites"`
	// Pipeline 是校验链，有序数组即串联顺序；enabled 控制单个实例的启停。
	Pipeline []core.InstanceConfig `yaml:"pipeline"`
	// Pipelines 是具名校验链集合，供 sites[].pipeline 引用实现站点级差异化。
	//
	// 设计取舍：保留顶层 pipeline 作为默认链，避免破坏既有配置；需要按站点
	// 使用不同规则集、插件组合或限速策略时，在该数组中声明具名链。
	// 数组中的 name 必须唯一，且不能使用保留名 default。
	Pipelines []PipelineConfig `yaml:"pipelines"`
	// Stores 是共享状态存储列表（限速计数 + 内部封禁名单）。
	Stores []StoreConfig `yaml:"stores"`
	// Ban 是封禁策略（仅 WAF 内部生效，不执行任何系统防火墙操作）。
	Ban BanConfig `yaml:"ban"`
	// Notify 是告警外送的公共策略（队列、超时、抑制、级别门槛）。
	Notify NotifyConfig `yaml:"notify"`
	// Notifiers 是告警外送通道列表（并联，可多个）。
	Notifiers []NotifierConfig `yaml:"notifiers"`
	// Logging 是日志配置：系统日志与访问日志两类。
	Logging LoggingConfig `yaml:"logging"`
	// Metrics 是指标配置。
	Metrics MetricsConfig `yaml:"metrics"`
	// Limits 是资源与容量限额。
	Limits LimitsConfig `yaml:"limits"`
	// Cache 是本地缓存配置。
	Cache CacheConfig `yaml:"cache"`
	// Database 是运行期 SQLite 持久化配置。
	//
	// 只有明确的运营数据（封禁、IP 名单、站点策略、关键标量策略）会写入数据库；
	// 监听地址、存储连接、规则目录、模板路径、密钥等部署配置始终以配置文件为准。
	// 默认关闭，避免不关心持久化的部署被隐式创建数据库文件。
	Database DatabaseConfig `yaml:"database"`
}

// ServerConfig 是 HTTP 服务配置。
type ServerConfig struct {
	// Listen 是 forward-auth 鉴权端点的监听地址，例如 ":9080"。
	Listen string `yaml:"listen"`
	// MetricsListen 是 /metrics 与 /healthz 的独立监听地址，便于网络隔离。
	MetricsListen string `yaml:"metrics_listen"`
	// BasePath 是所有 WAF HTTP 端点的统一前缀（例如 "/gateway"）；为空表示不加前缀。
	//
	// 拼接规则由 config.JoinBasePath 统一实现：前缀与端点路径做幂等拼接，
	// 已包含该前缀的路径不会被重复拼接，从而兼容旧配置中的 "/waf/auth"。
	BasePath string `yaml:"base_path"`
	// ReadHeaderTimeout 是读取请求头的超时，防止慢速攻击占用连接。
	ReadHeaderTimeout core.Duration `yaml:"read_header_timeout"`
	// ShutdownTimeout 是优雅关停的最长等待时间。
	ShutdownTimeout core.Duration `yaml:"shutdown_timeout"`
}

// IngressConfig 是接入适配配置，负责把代理注入的头与体还原成原始请求。
type IngressConfig struct {
	// Type 是接入适配类型：auto / traefik-forwardauth / nginx-auth-only / nginx-openresty。
	// auto 依据注入头的存在性自动判定（设计文档 §1.4）。
	Type string `yaml:"type"`
	// Path 是鉴权子请求的路径，默认 /waf/auth。
	Path string `yaml:"path"`
	// DenyPath 是 JSON 错误体渲染端点路径（Traefik errors 中间件回源使用）。
	DenyPath string `yaml:"deny_path"`
	// Headers 是各类原始请求信息对应的注入头候选列表（按顺序取首个存在的）。
	Headers IngressHeaders `yaml:"headers"`
	// ClientIP 是客户端 IP 推导配置。
	ClientIP ClientIPConfig `yaml:"client_ip"`
	// Body 是请求体通道与限额配置。
	Body BodyConfig `yaml:"body"`
}

// IngressHeaders 是注入头候选列表：按数组顺序取第一个存在的头。
type IngressHeaders struct {
	// URI 是原始 URI 的候选注入头，例如 X-Forwarded-Uri、X-Original-URI。
	URI []string `yaml:"uri"`
	// Method 是原始请求方法的候选注入头。
	Method []string `yaml:"method"`
	// Host 是原始 Host 的候选注入头。
	Host []string `yaml:"host"`
	// Proto 是原始协议的候选注入头。
	Proto []string `yaml:"proto"`
}

// ClientIPConfig 是客户端 IP 推导配置。
type ClientIPConfig struct {
	// Order 是候选头顺序，例如 [X-Forwarded-For, X-Real-IP]。
	Order []string `yaml:"order"`
	// TrustedProxies 是可信代理网段列表。
	//
	// 安全要求（验收项 A10）：只有当直连来源落在该列表内时，才信任其携带的转发头；
	// 解析 X-Forwarded-For 时从右往左取第一个非可信地址，防止客户端伪造。
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// BodyConfig 是请求体通道与限额配置。
type BodyConfig struct {
	// Mode 是请求体要求：required（必须携带）/ optional（可有可无）/ disabled（完全不读）。
	Mode string `yaml:"mode"`
	// Source 是请求体来源通道：request-body（随鉴权子请求送达）/ none。
	Source string `yaml:"source"`
	// Lazy 为 true 时，只有存在启用的 PhaseBody 校验单元才读取请求体（零开销）。
	Lazy bool `yaml:"lazy"`
	// MaxBytes 是单次请求可读取的请求体上限（字节）。
	MaxBytes int64 `yaml:"max_bytes"`
	// ChunkBytes 是流式读取的单块大小（字节）。
	//
	// 之所以可配置：大块读取会放大大请求体的瞬时内存占用，小块读取会增加系统调用次数；
	// 按 R13「不做大体积读取」的要求，该值必须来自配置文件而不是硬编码常量。
	ChunkBytes int64 `yaml:"chunk_bytes"`
	// OnExceed 是超限处理策略：truncate（截断继续检测）/ reject（直接拒绝）/ skip（跳过检测）。
	OnExceed string `yaml:"on_exceed"`
	// Spool 是缓冲位置策略：memory（仅内存）/ disk（仅落盘）/ auto（按阈值自动选择）。
	Spool string `yaml:"spool"`
	// MemoryThreshold 是 auto 策略下切换到落盘的阈值（字节）。
	MemoryThreshold int64 `yaml:"memory_threshold"`
	// SpoolDir 是落盘目录；为空时使用系统临时目录。
	SpoolDir string `yaml:"spool_dir"`
	// ReadTimeout 是读取请求体的超时。
	ReadTimeout core.Duration `yaml:"read_timeout"`
	// MissingMethods 是「预期必须携带请求体」的 HTTP 方法集合。
	//
	// 只有在 ingress.body.mode = required 时才生效：只有这些方法缺少请求体，
	// 才会被计为「请求体缺失」（系统日志告警 + waf_body_missing_total）。
	//
	// 为什么必须按方法区分：GET / HEAD / OPTIONS / DELETE 等请求本来就不携带请求体，
	// 把它们也算作「缺失」会让日志与指标被正常流量淹没，
	// 反而把真正的问题（代理没有转发请求体）掩盖在噪声里。
	// 对应需求 R5「只对确实存在的内容做校验」，而不是「缺少即异常」。
	MissingMethods []string `yaml:"missing_methods"`
	// Decompress 是「压缩请求体解压」配置（需求 R4 的扩展：P1-5）。
	//
	// 为什么解压放在接入层而不是引擎层：解压后得到的「明文请求体」是链中所有
	// PhaseBody 校验单元的共同输入，放在接入层只需解压一次；
	// 若放在每个引擎实例里，同一份请求体会被重复解压多次。
	Decompress DecompressConfig `yaml:"decompress"`
}

// DecompressConfig 是压缩请求体解压配置。
//
// 背景：代理会把 Content-Encoding: gzip / deflate / br 的请求体原样转交给 WAF，
// 不解压就等于「请求体内容对检测引擎不可见」——攻击者只需加一个 gzip 头就能绕过体检测。
// 因此解压是请求体检测能力的必要组成部分，而不是可选优化。
type DecompressConfig struct {
	// Enabled 控制是否启用解压（默认关闭，符合「全部功能配置启用」的要求 R5）。
	Enabled bool `yaml:"enabled"`
	// Encodings 是允许解压的 Content-Encoding 取值列表。
	//
	// 当前实现支持 gzip 与 deflate（Go 标准库能力范围内）。
	// br（brotli）需要第三方依赖，本项目坚持"无额外依赖"的交付约束（R10 / R14），
	// 因此不接受 br：配置里写 br 会在校验阶段直接报错，
	// 实际收到 br 请求时的行为由 UnsupportedAction 决定。
	Encodings []string `yaml:"encodings"`
	// MaxBytes 是解压后请求体的上限（字节）。
	//
	// 必须单独设置：压缩比可以极大（zip bomb），若只限制压缩体大小，
	// 一个 1MB 的 gzip 包可以膨胀到数 GB 并耗尽内存（需求 R13）。
	MaxBytes int64 `yaml:"max_bytes"`
	// UnsupportedAction 是「遇到未启用/不支持的编码」时的动作：block / pass。
	//
	// 默认 block（失败关闭）：无法检测的内容按不可信处理，避免「加个 br 头就绕过」。
	// 业务确有需要时显式改为 pass，并接受「该编码的请求体不被检测」的事实。
	UnsupportedAction string `yaml:"unsupported_action"`
}

// ResponderConfig 是拦截响应配置。
type ResponderConfig struct {
	// Type 是响应渲染实现类型；当前仅实现 json。
	Type string `yaml:"type"`
	// IncludeDetails 决定是否在错误体中暴露 rule_id / check / score。
	// 默认关闭，避免向攻击者泄露检测细节。
	IncludeDetails bool `yaml:"include_details"`
	// Messages 是错误码到中文提示语的自定义映射，便于按业务口径调整文案。
	Messages map[string]string `yaml:"messages"`
	// Template 是内联 JSON 响应模板（Go text/template 语法）。
	//
	// 模板与 TemplateFile 二选一；两者都为空时使用内置 ErrorBody 结构。
	Template string `yaml:"template"`
	// TemplateFile 是外部模板文件路径；与 Template 互斥。
	TemplateFile string `yaml:"template_file"`
	// MaxBodyBytes 是模板渲染结果的字节上限；<=0 时使用默认值。
	// 该限制用于防止模板异常输出过大，避免错误响应本身消耗过多内存。
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

// EngineConfig 是检测引擎（Coraza + CRS）配置。
type EngineConfig struct {
	// Enabled 为 false 时完全不加载引擎，退化为纯前置访问控制。
	Enabled bool `yaml:"enabled"`
	// Mode 是引擎模式：on（正常拦截）/ detection_only（旁路观察，仅记录不拦截）。
	Mode string `yaml:"mode"`
	// ParanoiaLevel 是 CRS 的偏执等级（1–4），等级越高检出率与误报率同时上升。
	ParanoiaLevel int `yaml:"paranoia_level"`
	// Rules 是规则加载配置。
	Rules EngineRulesConfig `yaml:"rules"`
	// InlineDirectives 是追加的 SecLang 指令（例如 SecRequestBodyAccess On）。
	InlineDirectives []string `yaml:"inline_directives"`
	// VirtualPatches 是启用的内置 CVE 虚拟补丁模板 ID 或 CVE 编号。
	VirtualPatches []string `yaml:"virtual_patches"`
	// VirtualPatchFiles 是自定义 SecLang 虚拟补丁文件。
	VirtualPatchFiles []string `yaml:"virtual_patch_files"`
	// Body 是引擎侧的请求体处理配置。
	Body EngineBodyConfig `yaml:"body"`
	// HotReload 是规则热加载配置。
	HotReload HotReloadConfig `yaml:"hot_reload"`
	// AnomalyScoreThreshold 是 CRS 入站异常评分阈值（对应 tx.inbound_anomaly_score_threshold）。
	//
	// 为什么把它提到 engine 段：CRS 自身的「阻断判定」与 pipeline 中 threshold 单元的
	// 「阈值判定」必须用同一个数字，否则会出现「引擎认为该拦、WAF 却不拦」（或反之）
	// 的割裂现象。把阈值放在引擎配置里统一注入 + 作为 threshold 单元的缺省值，
	// 可以保证两者永远一致（需求 R5）。
	AnomalyScoreThreshold int `yaml:"anomaly_score_threshold"`
	// Exceptions 是误报例外清单，在规则文件加载完成后按作用范围生效（需求 R6 / P1-4）。
	Exceptions []ExceptionConfig `yaml:"exceptions"`
}

// ExceptionConfig 是一条误报例外声明。
//
// 设计取舍：例外「按作用范围」分成两类，二者的实现机制完全不同：
//
//	全局例外（url_pattern 与 methods 均为空）
//	    编译为静态指令 SecRuleRemoveById / SecRuleRemoveByTag /
//	    SecRuleUpdateTargetById，必须放在规则文件**之后**才有意义
//	    （SecLang 的移除类指令只对「已经被解析出来的规则」生效）。
//
//	作用域例外（指定了 url_pattern 和/或 methods）
//	    编译为一条 phase:1 的 ctl 规则（ctl:ruleRemoveById / ruleRemoveByTag /
//	    ruleRemoveTargetById），该规则必须放在规则文件**之前**：
//	    phase 1 内部的规则按出现顺序求值，ctl 只有先于目标规则执行才能生效。
//
// 两类例外的「全局 / 作用域」判定由 url_pattern 与 methods 是否为空决定，
// 不需要额外的类型开关（需求 R5：配置即开关）。
type ExceptionConfig struct {
	// Name 是例外的审计标识，必填且建议唯一，用于在日志与审计报表中定位这条例外。
	Name string `yaml:"name"`
	// Enabled 为 false 时该条例外完全不生效（保留声明便于临时关闭而不删配置）。
	Enabled bool `yaml:"enabled"`
	// Reason 是例外原因，必填。
	//
	// 为什么强制填写：例外本质上是在「关闭部分防护」，没有原因记录的例外
	// 会在半年后变成无法解释的防护缺口；强制填写让例外天然可审计（需求 R6）。
	Reason string `yaml:"reason"`
	// RuleIDs 是要放行的规则 ID 列表，支持单个 ID 与区间（例如 "942100" / "941100-941199"）。
	RuleIDs []string `yaml:"rule_ids"`
	// Tags 是要放行的规则标签列表（对应 SecRuleRemoveByTag / ctl:ruleRemoveByTag）。
	Tags []string `yaml:"tags"`
	// Targets 是要从检测目标中摘除的变量列表（例如 "ARGS:password"）。
	//
	// 语义：配合 RuleIDs 使用，生成 SecRuleUpdateTargetById / ctl:ruleRemoveTargetById，
	// 即「规则保留、只不再检查这些参数」，比整条移除规则更精细。
	Targets []string `yaml:"targets"`
	// URLPattern 是例外生效的 URL 正则（对 REQUEST_URI 求值，含查询串）。
	//
	// 是否锚定由使用者决定：写 "^/api/login$" 表示精确匹配，写 "/api/login"
	// 表示部分匹配。WAF 不做任何自动锚定，避免产生「以为精确匹配其实不是」的误解。
	URLPattern string `yaml:"url_pattern"`
	// Methods 是例外生效的请求方法列表（为空表示不限制方法）。
	Methods []string `yaml:"methods"`
	// ExpiresAt 是例外的失效时间（RFC3339，例如 "2026-12-31T00:00:00+08:00"）。
	//
	// 为空表示永不过期。设置后一旦过期，该例外自动不再生效并在启动日志中标记，
	// 避免临时例外长期滞留（需求 R6：例外必须可审计、可收敛）。
	ExpiresAt string `yaml:"expires_at"`
}

// EngineRulesConfig 是规则加载配置。
type EngineRulesConfig struct {
	// Dirs 是主规则目录列表，按顺序确定性加载。
	//
	// 为空（默认）表示使用「内置嵌入的 CRS 规则集」：规则以 go:embed 编入二进制，
	// 运行期不依赖任何外部文件，因此 distroless 镜像只需一个可执行文件（需求 R14）。
	// 非空时完全改用磁盘目录，用于「自带规则集」或运维热更新规则的场景。
	Dirs []string `yaml:"dirs"`
	// CustomDirs 是追加的自定义规则目录，在主规则集之后加载。
	//
	// 加载顺序的意义：自定义规则可以引用 SecRuleUpdateTargetById / SecRuleRemoveById
	// 对前面加载的主规则做修正（压误报），因此必须排在主规则之后。
	CustomDirs []string `yaml:"custom_dirs"`
	// Include 是目录内的文件匹配模式，例如 ["*.conf"]。
	Include []string `yaml:"include"`
	// DataInclude 是「规则引用的数据文件」匹配模式，例如 ["*.data"]。
	//
	// 为什么需要单独一项：CRS 的规则通过 @pmFromFile unix-shell.data 这类相对路径
	// 引用同目录下的数据文件，这些文件必须与规则一起载入规则文件系统，
	// 但它们本身不是规则文件、不能被 Include（Include 会按 SecRule 解析而报错）。
	DataInclude []string `yaml:"data_include"`
	// CRSSetup 是 CRS 主配置文件路径（crs-setup.conf）。
	CRSSetup string `yaml:"crs_setup"`
}

// EngineBodyConfig 是引擎侧请求体配置。
type EngineBodyConfig struct {
	// Access 对应 SecRequestBodyAccess。
	Access bool `yaml:"access"`
	// LimitBytes 对应 SecRequestBodyLimit（超出按 LimitAction 处理）。
	LimitBytes int64 `yaml:"limit_bytes"`
	// InMemoryLimitBytes 对应 SecRequestBodyInMemoryLimit，超出部分落盘。
	InMemoryLimitBytes int64 `yaml:"in_memory_limit_bytes"`
	// LimitAction 取值 reject 或 processPartial。
	LimitAction string `yaml:"limit_action"`
	// JSONDepthLimit 是 JSON 解析深度上限，防止深层嵌套导致的资源耗尽。
	JSONDepthLimit int `yaml:"json_depth_limit"`
	// ParseMultipart 决定是否解析 multipart 上传（步骤 2 能力，默认关闭）。
	ParseMultipart bool `yaml:"parse_multipart"`
	// Processors 是「内容类型 -> 请求体处理器」的映射列表（默认 JSON 与 XML）。
	Processors []BodyProcessorConfig `yaml:"processors"`
}

// BodyProcessorConfig 是单条「内容类型 -> 请求体处理器」映射配置。
//
// 背景：Coraza 只按 Content-Type 自动识别 application/x-www-form-urlencoded 与
// multipart/form-data；application/json 与各类 XML 必须通过 ctl:requestBodyProcessor
// 显式指定处理器，否则会被当成 URLENCODED 解析，请求体里的攻击载荷无法被规则检出。
type BodyProcessorConfig struct {
	// Name 是请求体处理器名，可选 JSON / XML / MULTIPART / URLENCODED。
	Name string `yaml:"name"`
	// ContentTypes 是匹配 Content-Type 的正则表达式列表（对请求头整体匹配）。
	ContentTypes []string `yaml:"content_types"`
	// Enabled 控制该条映射是否生效。
	Enabled bool `yaml:"enabled"`
}

// HotReloadConfig 是规则热加载配置。
type HotReloadConfig struct {
	// Enabled 控制是否监听规则文件变化并自动重载。
	Enabled bool `yaml:"enabled"`
	// Debounce 是文件变化去抖动时间，避免编辑器/打包工具「边写边改」触发多次重载。
	Debounce core.Duration `yaml:"debounce"`
	// PollInterval 是文件指纹的轮询间隔。
	//
	// 为什么采用轮询而不是 inotify/ReadDirectoryChangesW：
	//   - 本项目交付物是 CGO_ENABLED=0 的静态单二进制，引入 fsnotify 会增加依赖面；
	//   - 轮询在「挂载卷 / 网络文件系统 / 容器 overlay」下行为一致，
	//     而 inotify 在部分容器与 NFS 场景下会漏事件；
	//   - 规则目录通常只有几十个文件，指纹比对（大小 + 修改时间）的代价可以忽略。
	// 该设计取舍已记录在 docs/development-roadmap.md §10.9。
	PollInterval core.Duration `yaml:"poll_interval"`
	// MarkerFile 是「手动触发重载」的标记文件路径。
	//
	// 用途：`waf rules reload` 会更新该文件的时间戳，运行中的实例据此立即重载，
	// 从而在不引入管理面 HTTP API 的前提下获得「运维主动重载」能力。
	// 为空表示不支持手动触发（仅依赖文件变化）。
	MarkerFile string `yaml:"marker_file"`
}

// SiteConfig 是单个站点的策略声明。
type SiteConfig struct {
	// Name 是站点名，必须唯一。
	Name string `yaml:"name"`
	// Hosts 是站点匹配的 Host 模式列表，支持 * 与 *.example.com。
	Hosts []string `yaml:"hosts"`
	// EngineMode 是站点级引擎模式覆盖：inherit 表示继承全局配置。
	EngineMode string `yaml:"engine_mode"`
	// Pipeline 是站点级校验链引用名；default 表示使用全局 pipeline。
	Pipeline string `yaml:"pipeline"`
	// Allowlist 是站点级 IP / CIDR 白名单；命中后直接放行该请求。
	Allowlist []string `yaml:"allowlist"`
	// Blocklist 是站点级 IP / CIDR 黑名单；命中后按 access_action 处理。
	Blocklist []string `yaml:"blocklist"`
	// AccessAction 是站点级 IP 黑名单动作：block / observe；为空时按 block。
	AccessAction string `yaml:"access_action"`
	// AccessScore 是站点级 IP 黑名单命中时累加的异常评分。
	AccessScore int `yaml:"access_score"`
	// Params 是站点级参数覆盖（键值对字符串形式）。
	Params map[string]string `yaml:"params"`
}

// PipelineConfig 是一条具名校验链。
type PipelineConfig struct {
	// Name 是链路名，供 sites[].pipeline 引用。
	Name string `yaml:"name"`
	// Instances 是该链的校验单元声明，顺序与全局 pipeline 一致。
	Instances []core.InstanceConfig `yaml:"instances"`
}

// StoreConfig 是单个共享存储实例的声明。
type StoreConfig struct {
	// Name 是存储实例名，必须唯一；校验单元通过该名字引用。
	Name string `yaml:"name"`
	// Type 是实现类型：redis / memory / file。
	Type string `yaml:"type"`
	// Enabled 为 false 时不连接 Redis，直接使用 Fallback 指定的本地实现。
	Enabled bool `yaml:"enabled"`
	// Fallback 是降级实现名：memory / file。
	Fallback string `yaml:"fallback"`
	// OnError 是运行期故障策略：fail_open / fail_closed / fallback_local。
	OnError string `yaml:"on_error"`
	// Settings 是该存储的私有配置片段。
	//
	// Redis 的拓扑（standalone / sentinel / cluster）与地址、认证、TLS、连接池
	// 全部通过该片段声明（需求 R25），从而「Docker 部署 / 直接部署」与
	// 「单机 / 哨兵 / 集群」的切换不需要改动任何代码。
	Settings map[string]any `yaml:"settings"`
}

// BanConfig 是封禁策略配置（需求 R18 / R19）。
type BanConfig struct {
	// DefaultTTL 是默认封禁时长；取 30m 兼顾劝退效果与 NAT 出口误封风险。
	DefaultTTL core.Duration `yaml:"default_ttl"`
	// MaxTTL 是封禁时长上限，防止误配置导致长期封禁。
	MaxTTL core.Duration `yaml:"max_ttl"`
	// BanKey 是「主封禁键维度」：client_ip / client_ip+site / client_ip+path / client_ip+method。
	//
	// 主维度的用途：
	//   - 运维命令 `waf ban add/remove` 未指定维度时的默认维度；
	//   - 启动日志与 `waf ban list` 的表头展示。
	// 运行期实际参与查询的维度集合见 BanKeys。
	BanKey string `yaml:"ban_key"`
	// BanKeys 是运行期生效的封禁键维度集合（可配置多个）。
	//
	// 语义（需求 R5 / R6：能力可自由配置、可多份并存）：
	//   - 为空时回落到单一的 BanKey，保证旧配置零改动升级；
	//   - 配置多个时，banlist 按声明顺序依次查询，命中任一维度即拦截；
	//   - autoban 的触发维度（settings.dimensions[].scope）必须是本集合的子集，
	//     否则「写进去的键运行期查不到」，配置校验会直接报错。
	//
	// 注意：数组无法通过环境变量 / CLI 机械表达（设计文档 §2.7），
	// 因此该配置项只支持配置文件通道。
	BanKeys []string `yaml:"ban_keys"`
	// Escalate 控制是否启用累进封禁。
	Escalate bool `yaml:"escalate"`
	// EscalateSteps 是累进封禁的时长阶梯。
	EscalateSteps []core.Duration `yaml:"escalate_steps"`
	// EscalateWindow 是累进封禁的统计窗口。
	EscalateWindow core.Duration `yaml:"escalate_window"`
	// RenewOnRepeat 控制重复命中时是否刷新已有封禁的到期时间。
	//
	// false（默认）：封禁到期时间在首次封禁时确定，后续命中只计数/告警，不续期；
	// true：恢复旧行为，每次命中都重新计算 TTL（持续攻击会导致封禁不断延长）。
	RenewOnRepeat bool `yaml:"renew_on_repeat"`
}

// NotifyConfig 是告警外送的公共策略配置（需求 P1-7）。
//
// 为什么这些参数放在全局而不是每个通道里：它们定义的是「外送这件事的公共行为」
// （异步程度、失败重试、聚合口径、级别门槛），把公共行为复制到每个通道
// 会让「为什么这个通道没发出去」变成需要逐通道排查的问题。
// 单个通道若确有差异，可用 NotifierConfig 上的 MinLevel / SuppressWindow 覆盖门槛与窗口。
type NotifyConfig struct {
	// Enabled 是告警外送总开关；false 时完全不构造任何通道（零开销）。
	Enabled bool `yaml:"enabled"`
	// QueueSize 是告警队列长度（条）。
	//
	// 为什么必须是「队列 + 异步」：告警外送是旁路行为，绝不能拖慢请求判定。
	// 队列满时按「丢弃并计数」处理（指标 alert_total{result="dropped"}），
	// 宁可丢告警也不阻塞 WAF（需求 R18 的同源取舍：安全判定优先级最高）。
	QueueSize int `yaml:"queue_size"`
	// Workers 是并发外送协程数。大于 1 时同一通道的告警可能并发送达，
	// 因此通道实现必须是并发安全的。
	Workers int `yaml:"workers"`
	// Timeout 是单次送达的超时时间。
	Timeout core.Duration `yaml:"timeout"`
	// MinLevel 是全局最低告警级别：低于该级别的告警不发送（info / warn / error）。
	MinLevel string `yaml:"min_level"`
	// SuppressWindow 是聚合抑制窗口：同一「聚合键」的告警在窗口内只发送一次。
	//
	// 聚合键 = 级别 + 站点 + 标题 + 命中规则，因此「同一站点反复被同一规则拦截」
	// 在窗口内只产生一条告警，避免告警风暴把通道打爆（也避免值班人员忽略告警）。
	// 设为 0 表示不抑制。
	SuppressWindow core.Duration `yaml:"suppress_window"`
	// MaxAttempts 是单条告警的最大外送尝试次数（含首次）。
	MaxAttempts int `yaml:"max_attempts"`
	// RetryBackoff 是两次尝试之间的固定间隔。
	RetryBackoff core.Duration `yaml:"retry_backoff"`
	// MaxTrackedKeys 是聚合抑制表的键上限（内存上限，需求 R13）。
	//
	// 达到上限后按「最早记录」淘汰：抑制表是无界的哈希表，不设上限会在
	// 高基数攻击（每个请求都换规则）下缓慢吃光内存。
	MaxTrackedKeys int `yaml:"max_tracked_keys"`
}

// NotifierConfig 是单个告警通道的声明。
type NotifierConfig struct {
	// Name 是通道实例名，必须唯一。
	Name string `yaml:"name"`
	// Type 是实现类型：webhook / wechat / syslog / smtp。
	Type string `yaml:"type"`
	// Enabled 控制该通道是否启用。
	Enabled bool `yaml:"enabled"`
	// MinLevel 是该通道的最低告警级别，覆盖 notify.min_level；留空表示继承。
	MinLevel string `yaml:"min_level"`
	// SuppressWindow 是该通道的聚合抑制窗口，覆盖 notify.suppress_window。
	//
	// 为 0 表示「继承全局值」。需要「完全不抑制」时把 notify.suppress_window 设为 0
	//（而不是在这里写一个特殊值）：这样「抑制到底开没开」只有一个权威来源，
	// 不需要读者去记住某个哨兵值的含义。
	SuppressWindow core.Duration `yaml:"suppress_window"`
	// Settings 是通道私有配置片段。
	Settings map[string]any `yaml:"settings"`
}

// LoggingConfig 是日志总配置：系统日志与访问日志两类（需求 R21）。
type LoggingConfig struct {
	// System 是系统运行日志配置。
	System LogOutputConfig `yaml:"system"`
	// Access 是请求访问与拦截日志配置。
	Access AccessLogConfig `yaml:"access"`
}

// LogOutputConfig 是单个日志输出通道的配置。
type LogOutputConfig struct {
	// Enabled 控制该日志通道是否启用。
	Enabled bool `yaml:"enabled"`
	// Level 是日志级别：debug / info / warn / error。
	Level string `yaml:"level"`
	// Format 是输出格式；当前仅支持 json。
	Format string `yaml:"format"`
	// Outputs 是输出目标列表：stdout / file。
	Outputs []string `yaml:"outputs"`
	// Dir 是日志目录。
	Dir string `yaml:"dir"`
	// File 是日志文件名前缀（实际文件名会追加日期或序号）。
	File string `yaml:"file"`
	// Rotate 是轮转策略：daily / size / both。
	Rotate string `yaml:"rotate"`
	// MaxFileBytes 是单文件大小上限（字节），rotate 含 size 时生效。
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	// KeepDays 是日志保留天数。
	KeepDays int `yaml:"keep_days"`
	// MaxTotalBytes 是日志总量上限（字节），0 表示不限制。
	MaxTotalBytes int64 `yaml:"max_total_bytes"`
	// Compress 控制轮转后是否压缩历史日志。
	Compress bool `yaml:"compress"`
}

// AccessLogConfig 是访问日志的扩展配置。
type AccessLogConfig struct {
	// LogOutputConfig 内嵌通用输出配置。
	LogOutputConfig `yaml:",inline"`
	// AllowLevel 是「放行请求」的记录策略：info / debug / off。
	//
	// 默认 info：鉴权请求无论「过」还是「不过」都要在访问日志里留痕——
	// 只记录拦截会让日志出现「没有任何记录的请求」这种解释不了的空白
	//（例如排查「某个接口为什么忽快忽慢」时，根本看不到放行流量）。
	//
	// 高流量站点若担心日志体积，可改为 debug（需要时临时调级别）或 off（只留拦截）。
	AllowLevel string `yaml:"allow_level"`
	// IncludeHeaders 控制是否记录请求头（默认关闭，避免泄露敏感信息）。
	IncludeHeaders bool `yaml:"include_headers"`
	// IncludeBody 控制是否记录请求体内容（默认关闭，仅记录体元信息）。
	IncludeBody bool `yaml:"include_body"`
	// MaxBodySnippetBytes 是请求体片段记录上限（字节）。
	MaxBodySnippetBytes int64 `yaml:"max_body_snippet_bytes"`
	// MaskIP 控制是否对日志中的 IP 做掩码处理。
	MaskIP bool `yaml:"mask_ip"`
	// Redact 是需要脱敏的请求头名称列表。
	Redact []string `yaml:"redact"`
}

// MetricsConfig 是指标配置。
type MetricsConfig struct {
	// Enabled 控制是否暴露指标端点。
	Enabled bool `yaml:"enabled"`
	// Namespace 是全部指标名的统一前缀（默认 waf）。
	//
	// 之所以做成配置项（需求 R13：不硬编码）：同一套监控后端上可能跑着多套
	// WAF 实例（例如灰度环境与生产环境共用一个 Prometheus），前缀可区分来源。
	Namespace string `yaml:"namespace"`
	// Path 是指标暴露路径（默认 /metrics）。
	Path string `yaml:"path"`
}

// LimitsConfig 是资源与容量限额（需求 R13：全部可配置，禁止硬编码）。
type LimitsConfig struct {
	// MaxRuleFileBytes 是单个规则文件大小上限（字节）。
	MaxRuleFileBytes int64 `yaml:"max_rule_file_bytes"`
	// MaxRulesTotalBytes 是规则总量上限（字节）。
	MaxRulesTotalBytes int64 `yaml:"max_rules_total_bytes"`
	// MaxScanTokenBytes 是单个待检测 token 的大小上限（字节）。
	MaxScanTokenBytes int64 `yaml:"max_scan_token_bytes"`
	// MaxIntelFileBytes 是威胁情报文件大小上限（字节）。
	MaxIntelFileBytes int64 `yaml:"max_intel_file_bytes"`
	// MaxMMDBBytes 是 GeoIP 数据库文件大小上限（字节）。
	MaxMMDBBytes int64 `yaml:"max_mmdb_bytes"`
	// MaxConfigFileBytes 是单个配置文件大小上限（字节）。
	MaxConfigFileBytes int64 `yaml:"max_config_file_bytes"`
	// MaxHeaderBytes 是请求头总大小上限（字节）。
	MaxHeaderBytes int64 `yaml:"max_header_bytes"`
}

// CacheConfig 是本地缓存配置。
type CacheConfig struct {
	// Enabled 控制是否启用本地缓存。
	Enabled bool `yaml:"enabled"`
	// RuleCacheEntries 是规则相关缓存的条目上限。
	RuleCacheEntries int `yaml:"rule_cache_entries"`
	// BanCacheEntries 是封禁结论缓存的条目上限。
	BanCacheEntries int `yaml:"ban_cache_entries"`
	// MaxBytes 是缓存总内存上限（字节）。
	MaxBytes int64 `yaml:"max_bytes"`
	// TTL 是缓存条目的默认存活时间。
	TTL core.Duration `yaml:"ttl"`
}

// DatabaseConfig 是 SQLite 运行期数据库配置。
type DatabaseConfig struct {
	// Enabled 控制是否启用 SQLite 持久化。
	//
	// 关闭时沿用原有 stores[] 后端（redis / memory / file），名单与站点策略
	// 继续以 YAML 为唯一来源；开启时封禁、IP 名单、站点策略和关键标量策略
	// 在首次启动时导入数据库，之后以数据库为准。
	Enabled bool `yaml:"enabled"`
	// Path 是 SQLite 文件路径；enabled=true 时必填。
	//
	// 该路径本身属于部署配置，不会写入数据库。
	Path string `yaml:"path"`
	// BusyTimeout 是 SQLite 写锁等待时间。
	BusyTimeout core.Duration `yaml:"busy_timeout"`
	// ReloadInterval 是运行实例检查数据库策略版本的轮询间隔。
	ReloadInterval core.Duration `yaml:"reload_interval"`
	// Audit 是请求审计落库配置。
	Audit DatabaseAuditConfig `yaml:"audit"`
}

// DatabaseAuditConfig 是请求审计落库配置。
type DatabaseAuditConfig struct {
	// Mode 是审计范围：off（关闭）/ events（只记录拦截、观察、蜜罐与异常）/ all（记录全部请求）。
	Mode string `yaml:"mode"`
	// Retention 是审计记录保留时长；<=0 表示不自动清理。
	Retention core.Duration `yaml:"retention"`
	// QueueSize 是异步写入队列长度。
	QueueSize int `yaml:"queue_size"`
	// BatchSize 是单次事务写入的最大条数。
	BatchSize int `yaml:"batch_size"`
	// FlushInterval 是队列空闲时的最大等待时间。
	FlushInterval core.Duration `yaml:"flush_interval"`
}
