package config

import (
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// Default 返回内置默认配置（配置优先级的兜底层）。
//
// 默认值的设计原则：
//   - 默认「可跑」：不加载任何配置文件也能启动并健康运行；
//   - 默认「不拦」：pipeline 默认为空数组，等价于纯放行（需求 R6）。
//     真正启用检测能力由 configs/waf.example.yaml 显式声明，避免默认拦截误伤业务；
//   - 默认「可降级」：共享存储默认指向 Redis 但允许降级到本地内存，
//     因此离线环境不部署 Redis 时仍可运行（需求 R23）。
func Default() *Config {
	return &Config{
		Version: 1,
		Server: ServerConfig{
			Listen:            ":9080",
			MetricsListen:     ":9090",
			BasePath:          "",
			ReadHeaderTimeout: dur(3 * time.Second),
			ShutdownTimeout:   dur(10 * time.Second),
		},
		Ingress: IngressConfig{
			Type:     IngressTypeAuto,
			Path:     "/waf/auth",
			DenyPath: "/waf/deny",
			Headers: IngressHeaders{
				URI:    []string{"X-Forwarded-Uri", "X-Original-URI"},
				Method: []string{"X-Forwarded-Method", "X-Original-Method"},
				Host:   []string{"X-Forwarded-Host"},
				Proto:  []string{"X-Forwarded-Proto"},
			},
			ClientIP: ClientIPConfig{
				Order: []string{"X-Forwarded-For", "X-Real-IP"},
				// 默认只信任内网网段；生产环境必须按实际代理地址收敛（验收项 A10）。
				TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"},
			},
			Body: BodyConfig{
				Mode:            BodyModeRequired,
				Source:          "request-body",
				Lazy:            true,
				MaxBytes:        1048576,
				ChunkBytes:      32768,
				OnExceed:        BodyOnExceedTruncate,
				Spool:           SpoolAuto,
				MemoryThreshold: 65536,
				SpoolDir:        "",
				ReadTimeout:     dur(2 * time.Second),
				// 默认只把「语义上必定携带请求体」的方法算作预期携带：POST / PUT / PATCH。
				// GET / HEAD / OPTIONS / DELETE 允许无体，缺失时不计入 waf_body_missing_total。
				MissingMethods: []string{"POST", "PUT", "PATCH"},
				Decompress: DecompressConfig{
					// 默认关闭解压：开启与否属于容量与兼容性决策，需运维显式确认。
					Enabled:   false,
					Encodings: []string{"gzip", "deflate"},
					// 解压后上限默认 4MiB：比压缩体上限（1MiB）放大约 4 倍，
					// 既给正常业务留出余量，又能挡住高压缩比的 zip bomb。
					MaxBytes:          4 * 1024 * 1024,
					UnsupportedAction: DecompressActionBlock,
				},
			},
		},
		Responder: ResponderConfig{
			Type:           "json",
			IncludeDetails: false,
			MaxBodyBytes:   8192,
			Messages: map[string]string{
				CodeBlocked:      "请求被安全策略拦截",
				CodeRateLimited:  "请求过于频繁，请稍后再试",
				CodeUnauthorized: "需要身份认证",
				CodeBadRequest:   "请求不符合安全要求",
				CodeUnavailable:  "安全检测服务暂时不可用",
				CodeNotFound:     "请求的 WAF 端点不存在",
				CodeHoneypot:     "已命中蜜罐规则",
			},
		},
		Engine: EngineConfig{
			Enabled:       true,
			Mode:          EngineModeOn,
			ParanoiaLevel: 1,
			Rules: EngineRulesConfig{
				// 默认不使用外部规则目录：直接使用编译期嵌入的 CRS 规则集。
				Dirs:        []string{},
				CustomDirs:  []string{},
				Include:     []string{"*.conf"},
				DataInclude: []string{"*.data"},
				CRSSetup:    "crs-setup.conf",
			},
			InlineDirectives: []string{"SecRequestBodyAccess On"},
			Body: EngineBodyConfig{
				Access:             true,
				LimitBytes:         13107200,
				InMemoryLimitBytes: 131072,
				LimitAction:        "reject",
				JSONDepthLimit:     4096,
				ParseMultipart:     false,
				// 默认启用 JSON 与 XML 请求体解析。
				//
				// 为什么不依赖 Coraza 的自动识别：它只自动识别 URLENCODED 与 MULTIPART，
				// JSON / XML 必须显式指定处理器；不配置会退化为「JSON 请求体被当作
				// URLENCODED 解析」，请求体检测形同虚设。
				Processors: []BodyProcessorConfig{
					{
						Name: BodyProcessorJSON,
						ContentTypes: []string{
							`^application/(?:[^;,\s]+\+)?json(?:\s*;.*)?$`,
						},
						Enabled: true,
					},
					{
						Name: BodyProcessorXML,
						ContentTypes: []string{
							`^(?:application|text)/(?:[^;,\s]+\+)?xml(?:\s*;.*)?$`,
						},
						Enabled: true,
					},
				},
			},
			HotReload: HotReloadConfig{
				// 默认开启热加载：规则目录变化后自动重载，加载失败保留旧引擎。
				Enabled:  true,
				Debounce: dur(1 * time.Second),
				// 轮询间隔 5s：相对规则变更（人工/流水线）的节奏足够及时，
				// 同时把「几十个文件的 stat 调用」压到可忽略的频率。
				PollInterval: dur(5 * time.Second),
				MarkerFile:   "",
			},
			// CRS 默认异常评分阈值（crs-setup.conf 的默认值同为 5）。
			AnomalyScoreThreshold: 5,
			VirtualPatches:        []string{},
			VirtualPatchFiles:     []string{},
			Exceptions:            []ExceptionConfig{},
		},
		Sites: []SiteConfig{
			{
				Name:         "default",
				Hosts:        []string{"*"},
				EngineMode:   EngineModeInherit,
				Pipeline:     "default",
				AccessAction: "block",
			},
		},
		// 默认为空校验链：未声明任何插件时不产生任何拦截（验收项 A3）。
		Pipeline: []core.InstanceConfig{},
		// 具名校验链默认关闭：只有 sites[].pipeline 显式引用时才装配。
		Pipelines: []PipelineConfig{},
		Stores: []StoreConfig{
			{
				Name:     "default",
				Type:     "redis",
				Enabled:  true,
				Fallback: "memory",
				OnError:  StoreOnErrorFallbackLocal,
				Settings: map[string]any{
					"topology":        "standalone",
					"addrs":           []any{"127.0.0.1:6379"},
					"db":              0,
					"prefix":          "waf:",
					"local_cache_ttl": "5s",
					"dial_timeout":    "500ms",
					"read_timeout":    "300ms",
					"write_timeout":   "300ms",
				},
			},
		},
		Ban: BanConfig{
			DefaultTTL:     dur(30 * time.Minute),
			MaxTTL:         dur(24 * time.Hour),
			BanKey:         BanKeyClientIP,
			Escalate:       false,
			EscalateSteps:  []core.Duration{dur(30 * time.Minute), dur(2 * time.Hour), dur(24 * time.Hour)},
			EscalateWindow: dur(24 * time.Hour),
			RenewOnRepeat:  false,
		},
		Notify: NotifyConfig{
			// 默认关闭：告警外送会向外部系统发送请求，属于「有副作用」的能力，
			// 必须由运维显式开启并配置通道（需求 R5：功能配置即开关）。
			Enabled:   false,
			QueueSize: 1024,
			Workers:   2,
			Timeout:   dur(5 * time.Second),
			// 默认只外送 warn 及以上：info 级告警（观察模式命中）在试运行阶段量级极大，
			// 默认全发会立刻把通道打爆，反而让真正的告警被忽略。
			MinLevel: "warn",
			// 默认抑制窗口 5 分钟：同一站点被同一规则反复命中时只发一次。
			SuppressWindow: dur(5 * time.Minute),
			MaxAttempts:    3,
			RetryBackoff:   dur(2 * time.Second),
			MaxTrackedKeys: 10000,
		},
		Notifiers: []NotifierConfig{},
		Logging: LoggingConfig{
			System: LogOutputConfig{
				Enabled:       true,
				Level:         "info",
				Format:        "json",
				Outputs:       []string{"stdout", "file"},
				Dir:           "logs",
				File:          "waf-system",
				Rotate:        "daily",
				MaxFileBytes:  134217728,
				KeepDays:      30,
				MaxTotalBytes: 0,
				Compress:      false,
			},
			Access: AccessLogConfig{
				LogOutputConfig: LogOutputConfig{
					Enabled:       true,
					Level:         "info",
					Format:        "json",
					Outputs:       []string{"file"},
					Dir:           "logs",
					File:          "waf-access",
					Rotate:        "daily",
					MaxFileBytes:  134217728,
					KeepDays:      90,
					MaxTotalBytes: 0,
					Compress:      false,
				},
				AllowLevel:          AccessAllowLevelInfo,
				IncludeHeaders:      false,
				IncludeBody:         false,
				MaxBodySnippetBytes: 4096,
				MaskIP:              false,
				Redact: []string{
					"Cookie", "Authorization", "Proxy-Authorization",
					"Set-Cookie", "X-Api-Key", "X-Auth-Token",
				},
			},
		},
		Metrics: MetricsConfig{
			Enabled:   true,
			Namespace: "waf",
			Path:      "/metrics",
		},
		Limits: LimitsConfig{
			MaxRuleFileBytes:   2097152,
			MaxRulesTotalBytes: 67108864,
			MaxScanTokenBytes:  1048576,
			MaxIntelFileBytes:  67108864,
			MaxMMDBBytes:       268435456,
			MaxConfigFileBytes: 1048576,
			MaxHeaderBytes:     1048576,
		},
		Cache: CacheConfig{
			Enabled:          true,
			RuleCacheEntries: 10000,
			BanCacheEntries:  100000,
			MaxBytes:         33554432,
			TTL:              dur(5 * time.Minute),
		},
		Database: DatabaseConfig{
			// 默认关闭：未显式启用时保持原有 stores[] / YAML 行为，
			// 也避免本地测试或只读容器因自动建库失败而无法启动。
			Enabled:        false,
			Path:           "data/waf.db",
			BusyTimeout:    dur(5 * time.Second),
			ReloadInterval: dur(10 * time.Second),
			Audit: DatabaseAuditConfig{
				Mode:          DatabaseAuditModeEvents,
				Retention:     dur(30 * 24 * time.Hour),
				QueueSize:     4096,
				BatchSize:     100,
				FlushInterval: dur(1 * time.Second),
			},
		},
	}
}

// 以下是配置枚举值的常量定义。
//
// 之所以集中定义：避免在配置文件解析、校验与运行期三处出现拼写不一致的字符串。
const (
	// IngressTypeAuto 表示按注入头自动判定接入类型。
	IngressTypeAuto = "auto"
	// IngressTypeTraefik 表示 Traefik ForwardAuth 接入。
	IngressTypeTraefik = "traefik-forwardauth"
	// IngressTypeNginxOpenResty 表示 Nginx(OpenResty) 子请求接入（推荐）。
	IngressTypeNginxOpenResty = "nginx-openresty"
	// IngressTypeNginxAuthOnly 表示原生 Nginx auth_request 降级接入。
	IngressTypeNginxAuthOnly = "nginx-auth-only"

	// BodyModeRequired 表示请求必须携带请求体，缺失时按告警处理。
	BodyModeRequired = "required"
	// BodyModeOptional 表示请求体可有可无。
	BodyModeOptional = "optional"
	// BodyModeDisabled 表示完全不读取请求体。
	BodyModeDisabled = "disabled"

	// BodyOnExceedTruncate 表示超限截断后继续检测。
	BodyOnExceedTruncate = "truncate"
	// BodyOnExceedReject 表示超限直接拒绝（400）。
	BodyOnExceedReject = "reject"
	// BodyOnExceedSkip 表示超限跳过体检测（仅做头检测）。
	BodyOnExceedSkip = "skip"

	// SpoolMemory 表示请求体只缓存在内存。
	SpoolMemory = "memory"
	// SpoolDisk 表示请求体一律落盘。
	SpoolDisk = "disk"
	// SpoolAuto 表示按内存阈值自动选择内存或落盘。
	SpoolAuto = "auto"

	// EngineModeOn 表示引擎正常拦截。
	EngineModeOn = "on"
	// EngineModeDetectionOnly 表示引擎只观察不拦截。
	EngineModeDetectionOnly = "detection_only"
	// EngineModeInherit 表示站点继承全局引擎模式。
	EngineModeInherit = "inherit"

	// DecompressEncodingGzip 表示 gzip 压缩编码。
	DecompressEncodingGzip = "gzip"
	// DecompressEncodingDeflate 表示 zlib/deflate 压缩编码。
	DecompressEncodingDeflate = "deflate"
	// DecompressActionBlock 表示遇到不支持的编码时直接拦截（失败关闭）。
	DecompressActionBlock = "block"
	// DecompressActionPass 表示遇到不支持的编码时放行原始请求体（不检测）。
	DecompressActionPass = "pass"

	// ExceptionTargetArgPrefix 是「摘除某个参数」类目标的前缀，例如 ARGS:password。
	ExceptionTargetArgPrefix = "ARGS:"

	// 以下是引擎请求体处理器名常量（与 Coraza 的处理器注册名一致，大小写不敏感）。

	// BodyProcessorJSON 表示 JSON 请求体处理器。
	BodyProcessorJSON = "JSON"
	// BodyProcessorXML 表示 XML 请求体处理器。
	BodyProcessorXML = "XML"
	// BodyProcessorMultipart 表示 multipart/form-data 请求体处理器。
	BodyProcessorMultipart = "MULTIPART"
	// BodyProcessorURLEncoded 表示 application/x-www-form-urlencoded 请求体处理器。
	BodyProcessorURLEncoded = "URLENCODED"

	// StoreOnErrorFailOpen 表示存储故障时放过请求（失败开放）。
	StoreOnErrorFailOpen = "fail_open"
	// StoreOnErrorFailClosed 表示存储故障时拦截请求（失败关闭）。
	StoreOnErrorFailClosed = "fail_closed"
	// StoreOnErrorFallbackLocal 表示存储故障时降级为本地存储。
	StoreOnErrorFallbackLocal = "fallback_local"

	// DatabaseAuditModeOff 表示不把请求审计写入数据库。
	DatabaseAuditModeOff = "off"
	// DatabaseAuditModeEvents 表示只把拦截、观察、蜜罐与异常请求写入数据库。
	DatabaseAuditModeEvents = "events"
	// DatabaseAuditModeAll 表示把全部鉴权请求写入数据库。
	DatabaseAuditModeAll = "all"

	// BanKeyClientIP 表示按客户端 IP 封禁（默认维度）。
	BanKeyClientIP = "client_ip"
	// BanKeyClientIPSite 表示按「客户端 IP + 站点」封禁（多站点隔离）。
	BanKeyClientIPSite = "client_ip+site"
	// BanKeyClientIPPath 表示按「客户端 IP + 请求路径」封禁。
	//
	// 用于「单来源集中打某一个接口」的场景：封禁到路径粒度即可止损，
	// 又不会把该来源的其他正常业务流量一起误伤。
	BanKeyClientIPPath = "client_ip+path"
	// BanKeyClientIPMethod 表示按「客户端 IP + 请求方法」封禁。
	//
	// 用于「只读站点上反复出现写操作探测」的场景。
	BanKeyClientIPMethod = "client_ip+method"

	// 以下为对外错误码常量，与 core.Verdict 一一对应。
	//
	// CodeBlocked 表示被安全策略拦截。
	CodeBlocked = "WAF_BLOCKED"
	// CodeRateLimited 表示触发限速。
	CodeRateLimited = "WAF_RATE_LIMITED"
	// CodeUnauthorized 表示需要身份认证。
	CodeUnauthorized = "WAF_UNAUTHORIZED"
	// CodeBadRequest 表示请求不符合安全要求。
	CodeBadRequest = "WAF_BAD_REQUEST"
	// CodeUnavailable 表示检测服务不可用。
	CodeUnavailable = "WAF_UNAVAILABLE"
	// CodeNotFound 表示 WAF 端点不存在。
	CodeNotFound = "WAF_NOT_FOUND"
	// CodeHoneypot 表示命中蜜罐规则（响应体由规则自身定义）。
	CodeHoneypot = "WAF_HONEYPOT"
)

// 访问日志中「放行请求」的记录策略（配置项 logging.access.allow_level）。
const (
	// AccessAllowLevelInfo 表示放行请求以 info 级记录（默认）。
	//
	// 之所以默认是 info：鉴权请求无论「过」还是「不过」都应当留下可解释的记录，
	// 否则访问日志里会存在「无任何记录」的请求，排障与容量评估都无从下手。
	AccessAllowLevelInfo = "info"
	// AccessAllowLevelDebug 表示放行请求以 debug 级记录。
	//
	// 适用场景：放行流量远大于拦截流量、且日常不关心放行明细；
	// 需要时把 logging.access.level 临时调为 debug 即可看到放行记录。
	AccessAllowLevelDebug = "debug"
	// AccessAllowLevelOff 表示完全不记录放行请求（只保留拦截与观察）。
	//
	// 适用场景：极高频调用链路的鉴权端点，日志体积优先于可解释性。
	AccessAllowLevelOff = "off"
)

// AccessAllowLevels 返回放行记录策略的全部合法取值（按推荐顺序）。
func AccessAllowLevels() []string {
	return []string{AccessAllowLevelInfo, AccessAllowLevelDebug, AccessAllowLevelOff}
}

// BanKeyKinds 返回全部合法的封禁键维度名（按推荐顺序）。
//
// 之所以集中在这里：配置校验的错误提示、封禁管理器的维度解析、
// 文档与测试都引用同一份清单，避免「新增维度后某处漏改」。
func BanKeyKinds() []string {
	return []string{BanKeyClientIP, BanKeyClientIPSite, BanKeyClientIPPath, BanKeyClientIPMethod}
}

// dur 是 core.Duration 的简写构造辅助，仅用于本文件内的默认值声明。
func dur(d time.Duration) core.Duration {
	return core.Duration(d)
}
