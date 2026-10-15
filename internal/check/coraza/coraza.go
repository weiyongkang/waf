// Package coraza 实现基于 OWASP Coraza 的检测引擎校验单元（type=coraza）。
//
// 定位与边界（严格遵循 R1 / R2：只做 forward-auth 前置校验，不做反向代理）：
//
//	本校验单元只做「还原后的原始请求」检测，不做任何转发、不做响应体检测、
//	不建立到业务后端的连接；判定结果通过 Result 交给执行器与 responder。
//
// 为什么拆成「request 阶段」与「body 阶段」两个实例（配置示例中的 crs-header / crs-body）：
//
//	按需读体是硬约束（需求 R13）：请求体只有在「链中确实存在体阶段单元」时才会被读取。
//	把请求头检测与请求体检测拆成两个实例后，运维可以选择只启用 header 实例
//	（此时一个字节的请求体都不会被读），或对登录接口额外启用 body 实例。
//	若合并为一个实例，则必须始终读体，违背按需读体约束。
//
// 关于 Coraza 版本与实现方式（需求 R10）：
//
//	reference/coraza-traefik-WAF 仅作为参考，其规则文件与规则结构已「复制一份」到本仓库
//	（internal/rules/crs），本包自行实现装配、错误处理、评分提取与日志记录，
//	不引用、不 replace 参考工程。
package coraza

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	corazawaf "github.com/corazawaf/coraza/v3"
	corazaexp "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	corazatypes "github.com/corazawaf/coraza/v3/types"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
	"github.com/weiyongkang/waf/internal/rules/exceptions"
)

// Type 是本实现的注册类型名（配置文件中 pipeline[].type）。
const Type = "coraza"

// 引擎模式取值（配置项 settings.mode，缺省继承 engine.mode）。
const (
	// ModeOn 表示正常拦截。
	ModeOn = "on"
	// ModeDetectionOnly 表示旁路观察：命中只记录、不拦截。
	ModeDetectionOnly = "detection_only"
)

// 请求体限额动作取值（对应 SecRequestBodyLimitAction）。
const (
	// LimitActionReject 表示请求体超限直接拒绝。
	LimitActionReject = "reject"
	// LimitActionProcessPartial 表示请求体超限后处理已接收的部分。
	LimitActionProcessPartial = "processPartial"
)

// 默认值。
const (
	// defaultScoreKey 是异常评分写入的状态键默认值。
	defaultScoreKey = "inbound_anomaly_score"
	// defaultMaxFindings 是单次请求最多记录的命中明细条数。
	//
	// 之所以限额：一条构造恶意的请求可以触发成百上千条 CRS 规则，
	// 无上限地把命中明细写进日志会造成日志放大（攻击者可用它打满磁盘）。
	defaultMaxFindings = 16
	// crsInitializationRuleIDMin / crsInitializationRuleIDMax 界定 CRS 的初始化规则编号区间。
	//
	// 之所以需要它：CRS 的初始化规则（900000 / 900001 / 901xxx）负责给 TX 变量赋默认值，
	// 属于引擎内部机制而非攻击命中；其中一部分带 msg（例如 id:901340 的
	// "Enabling body inspection"），只按「是否有 msg」过滤不足以排除它们。
	crsInitializationRuleIDMin = 900000
	// crsInitializationRuleIDMax 是初始化规则区间的上界（含）。
	crsInitializationRuleIDMax = 901999

	// paranoiaOverrideRuleID 是注入「偏执等级覆盖」动作使用的规则 ID。
	//
	// 取 900100：CRS 自身使用 900000 / 900001（见 crs-setup.conf），
	// 该段区间是 CRS 为用户自定义动作保留的，不会与官方规则冲突。
	paranoiaOverrideRuleID = 900100
)

// 异常评分的事务变量名（按顺序尝试读取）。
const (
	// anomalyScoreVarBlocking 是阻断模式下的入站异常评分（CRS 4.x）。
	anomalyScoreVarBlocking = "blocking_inbound_anomaly_score"
	// anomalyScoreVarDetection 是检测模式下的入站异常评分（阻断评分为 0 时回退读取）。
	anomalyScoreVarDetection = "detection_inbound_anomaly_score"
)

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 coraza 实例的私有配置片段。
//
// 全部字段都可选：未配置（或为零值 / nil）时继承全局 engine 配置。
// 之所以允许实例级覆盖：不同站点或不同路径常常需要不同的规则集与偏执等级
// （例如后台接口用 PL2、公开接口用 PL1），而「可以配置多个实例」是本项目的硬需求（R8）。
type Settings struct {
	// ProcessBody 决定本实例是否检测请求体。
	// 必须与实例所在阶段一致：process_body=true 只能声明在 body 阶段，反之亦然。
	ProcessBody bool `yaml:"process_body"`
	// ScoreKey 是异常评分写入 RequestContext 状态时使用的键名；
	// 为空时使用 "inbound_anomaly_score"（与 CRS 的变量名保持一致，便于对照日志）。
	ScoreKey string `yaml:"score_key"`
	// MaxFindings 是单次请求最多记录的命中明细条数；<=0 时取默认值 16。
	MaxFindings int `yaml:"max_findings"`
	// Mode 覆盖全局 engine.mode（on / detection_only）。
	Mode string `yaml:"mode"`
	// ParanoiaLevel 覆盖全局 engine.paranoia_level（1–4）。
	ParanoiaLevel int `yaml:"paranoia_level"`
	// RuleDirs 覆盖全局 engine.rules.dirs。
	// 显式写 rule_dirs: [] 表示「使用内置嵌入式 CRS」，不写该键则继承全局配置。
	RuleDirs []string `yaml:"rule_dirs"`
	// CustomRuleDirs 覆盖全局 engine.rules.custom_dirs。
	CustomRuleDirs []string `yaml:"custom_rule_dirs"`
	// InlineDirectives 覆盖全局 engine.inline_directives。
	InlineDirectives []string `yaml:"inline_directives"`
	// BodyAccess 覆盖全局 engine.body.access。
	BodyAccess *bool `yaml:"body_access"`
	// BodyLimitBytes 覆盖全局 engine.body.limit_bytes；<=0 时继承。
	BodyLimitBytes int64 `yaml:"body_limit_bytes"`
	// BodyInMemoryLimitBytes 覆盖全局 engine.body.in_memory_limit_bytes；<=0 时继承。
	BodyInMemoryLimitBytes int64 `yaml:"body_in_memory_limit_bytes"`
	// ParseMultipart 覆盖全局 engine.body.parse_multipart。
	ParseMultipart *bool `yaml:"parse_multipart"`
	// BodyProcessors 覆盖全局 engine.body.processors；nil 表示继承。
	//
	// 之所以允许实例级覆盖：同一套规则集可能被不同站点以不同方式使用
	//（例如对外开放的接口只接受 JSON，而内部接口还用 XML），
	// 实例级覆盖可以在不改动全局配置的前提下收敛解析范围（需求 R5-R8）。
	BodyProcessors []core.BodyProcessorSetting `yaml:"body_processors"`
}

// Check 是检测引擎校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段（request 或 body）。
	phase core.Phase
	// order 是同一阶段内的执行顺序。
	order int
	// waf 是已编译完成的 Coraza 引擎，并发安全（NewTransaction 可并发调用）。
	waf corazawaf.WAF
	// processBody 表示本实例是否检测请求体。
	processBody bool
	// parseMultipart 决定 multipart/form-data 请求体是否参与检测。
	//
	// 关闭时本实例不把 multipart 请求体交给引擎（引擎只会对不含请求体变量的规则求值），
	// 用于「大文件上传不进入检测链」这类场景；开启后由引擎的 MULTIPART 处理器解析。
	parseMultipart bool
	// bodyAccess 是最终生效的请求体访问开关（写入 SecRequestBodyAccess）。
	bodyAccess bool
	// scoreKey 是异常评分写入的状态键。
	scoreKey string
	// mode 是最终生效的引擎模式。
	mode string
	// maxFindings 是命中明细条数上限。
	maxFindings int
	// jsonDepthLimit 是 JSON 嵌套深度上限；<=0 表示不检查。
	jsonDepthLimit int
	// bodyScanCap 是 JSON 深度扫描的字节上限（防止为大体积请求体做整轮扫描）。
	bodyScanCap int64
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
	// ruleSource 是规则来源描述（启动日志使用）。
	ruleSource string
	// ruleFiles 是加载的规则文件数量。
	ruleFiles int
	// wouldBlockThreshold 是观察模式下「本应拦截」的评分阈值（取自 engine.anomaly_score_threshold）。
	wouldBlockThreshold int
	// watchDirs 是热加载需要监听的规则目录（主目录 + 自定义目录）。
	watchDirs []string
	// watchInclude / watchData 是热加载的匹配模式，与加载时保持一致。
	watchInclude []string
	watchData    []string
}

// New 依据实例配置构造检测引擎校验单元。
//
// 全部昂贵操作（规则读取、规则编译）都在此完成：规则编译失败属于部署事故，
// 必须在启动阶段暴露，而不是等第一个攻击请求到达时才发现引擎是空的。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	check, err := buildCheck(inst, deps)
	if err != nil {
		return nil, err
	}

	// 热加载包装：只有「全局开启热加载」且「本实例确实监听了磁盘目录」时才包装。
	// 内置嵌入的 CRS 编译在二进制里，永远不会变化，为它起一个轮询协程纯属浪费。
	if deps == nil || !deps.Engine.HotReload.Enabled {
		return check, nil
	}
	if len(check.watchDirs) == 0 {
		deps.SystemLoggerOr().Warn(
			"已开启规则热加载，但该实例没有可监听的磁盘规则目录（内置嵌入规则集为只读）；"+
				"如需热更新规则，请配置 engine.rules.dirs 或实例级 rule_dirs",
			"instance", inst.Name,
		)
		return check, nil
	}
	return newReloader(inst, deps, check)
}

// buildCheck 按真实装配路径构建一个检测引擎实例。
//
// 之所以从 New 中拆出：热加载需要在文件变化时用**完全相同的装配逻辑**重建实例，
// 若重建走另一条代码路径，就会出现「启动时正确、热加载后参数丢失」这类隐蔽偏差。
func buildCheck(inst core.InstanceConfig, deps *core.Deps) (*Check, error) {
	if deps == nil {
		deps = &core.Deps{}
	}

	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	phase := inst.Phase
	if settings.ProcessBody {
		if phase != core.PhaseBody {
			return nil, fmt.Errorf(
				"process_body=true 的实例必须声明在 body 阶段（当前 phase=%s）；"+
					"请求头检测与请求体检测请拆成两个实例，以保证「无体阶段单元时不读请求体」",
				phase,
			)
		}
	} else if phase == core.PhaseBody {
		return nil, fmt.Errorf(
			"body 阶段的实例必须设置 process_body=true（当前为 false）；" +
				"否则执行器会为它读取请求体却什么也不检测，白白产生 IO 开销",
		)
	}

	engine := deps.Engine
	if !engine.Enabled {
		return nil, fmt.Errorf(
			"实例 %q 已启用但 engine.enabled=false；请把 engine.enabled 置为 true，或关闭该实例",
			inst.Name,
		)
	}

	effective, err := resolveEngine(engine, settings)
	if err != nil {
		return nil, err
	}
	if settings.ProcessBody && !effective.BodyAccess {
		return nil, fmt.Errorf(
			"process_body=true 与 body_access=false 冲突；" +
				"请求体检测要求 engine.body.access=true（或实例级 body_access=true）",
		)
	}

	set, err := rules.Load(rules.Options{
		Source: rules.Source{
			Dirs:        effective.RuleDirs,
			CustomDirs:  effective.CustomRuleDirs,
			Include:     effective.RuleInclude,
			DataInclude: effective.RuleDataInclude,
			CRSSetup:    effective.CRSSetup,
		},
		MaxFileBytes:  deps.Limits.MaxRuleFileBytes,
		MaxTotalBytes: deps.Limits.MaxRulesTotalBytes,
		Logger:        deps.SystemLogger,
	})
	if err != nil {
		return nil, err
	}

	bodyAccess := effective.BodyAccess && settings.ProcessBody

	// 编译误报例外：这一步同时产出「指令」与「审计条目」。
	// 指令顺序由 exceptions 包按 Pre / Post 分流，本包只负责插入位置正确。
	exceptionSet, err := exceptions.Compile(effective.Exceptions, exceptions.Options{})
	if err != nil {
		return nil, fmt.Errorf("误报例外编译失败：%w", err)
	}

	directives := buildDirectives(set, effective, bodyAccess, exceptionSet)

	wafConfig := corazawaf.NewWAFConfig().
		WithRootFS(set.FS).
		// 刻意不设置 WithErrorCallback：Coraza 的该回调名字叫「错误日志回调」，
		// 但实际是在**每条带 log 动作的规则命中时**触发（见 coraza 源码
		// transaction.go 的 MatchRule：`if ErrorLogCb != nil && r.Log`）。
		// 把它当作错误钩子会把正常命中全部记成「规则报错」，造成严重误导与日志放大。
		// 命中明细由本包通过 tx.MatchedRules() 自行采集；引擎内部诊断日志默认被
		// SecDebugLogLevel 0 关闭，需要排障时可用
		// engine.inline_directives: ["SecDebugLogLevel 3"] 临时打开。
		WithDirectives(directives)

	waf, err := corazawaf.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("检测引擎规则编译失败（来源：%s）：%w", set.Source, err)
	}

	check := &Check{
		name:           inst.Name,
		phase:          phase,
		order:          inst.Order,
		waf:            waf,
		processBody:    settings.ProcessBody,
		parseMultipart: effective.ParseMultipart,
		bodyAccess:     bodyAccess,
		scoreKey:       scoreKeyOf(settings),
		mode:           effective.Mode,
		maxFindings:    maxFindingsOf(settings),
		jsonDepthLimit: effective.JSONDepthLimit,
		bodyScanCap:    bodyScanCapOf(deps, effective),
		logger:         deps.SystemLoggerOr(),
		metrics:        metricsOf(deps),
		ruleSource:     set.Source,
		ruleFiles:      set.FileCount,
		// 观察模式的「若拦截」阈值与 CRS 阻断阈值同源，保证两份口径永远一致。
		wouldBlockThreshold: effective.AnomalyScoreThreshold,
		// 记录生效的规则目录：热加载监听的就是这些目录。
		watchDirs:    append(append([]string{}, effective.RuleDirs...), effective.CustomRuleDirs...),
		watchInclude: append([]string{}, effective.RuleInclude...),
		watchData:    append([]string{}, effective.RuleDataInclude...),
	}

	// 例外审计：每条例外一条日志，逐条说明「生效/关闭/过期」与原因。
	// 之所以打 info 级而不是 debug：例外的存在本身就是「这里有防护被关闭」，
	// 必须能在默认日志级别下被看到（需求 R6 可审计）。
	logExceptionAudit(deps.SystemLoggerOr(), inst.Name, exceptionSet)

	deps.SystemLoggerOr().Info("检测引擎实例装配完成",
		"instance", inst.Name,
		"phase", phase.String(),
		"mode", check.mode,
		"paranoia_level", effective.ParanoiaLevel,
		"process_body", settings.ProcessBody,
		"body_access", bodyAccess,
		"rule_source", set.Source,
		"rule_files", set.FileCount,
		"rule_bytes", set.TotalBytes,
		"json_depth_limit", effective.JSONDepthLimit,
	)
	return check, nil
}

// Name 返回实例名。
func (c *Check) Name() string { return c.name }

// Type 返回实现类型。
func (c *Check) Type() string { return Type }

// Phase 返回执行阶段。
func (c *Check) Phase() core.Phase { return c.phase }

// Order 返回同阶段内的执行顺序。
func (c *Check) Order() int { return c.order }

// DefaultOnError 声明默认失败策略为「失败关闭」。
//
// 依据：检测引擎不可用时，之后的请求全部不可检测；此时放过流量等于关闭防护，
// 因此默认拦截（对外 503）。运维仍可在实例上显式写 on_error: pass 覆盖该默认值。
func (c *Check) DefaultOnError() string { return core.OnErrorBlock }

// Close 释放引擎持有的资源（Coraza 的 WAF 实例无需显式释放）。
func (c *Check) Close() error { return nil }

// logExceptionAudit 把例外编译结果写成可审计的系统日志。
//
// 输出分两类：
//   - 生效的例外：info 级，逐条给出 name / reason / 作用域 / 指令数量；
//   - 未生效的例外（enabled=false 或已过期）：仍然打日志，因为「一条被关闭的例外」
//     同样是审计信息——它解释了「为什么这里不再拦截」。
func logExceptionAudit(logger *slog.Logger, instance string, set *exceptions.Set) {
	if set == nil || len(set.Entries) == 0 {
		return
	}

	for _, entry := range set.Entries {
		level := slog.LevelInfo
		message := "误报例外已生效"
		switch entry.Status {
		case exceptions.StatusDisabled:
			level = slog.LevelWarn
			message = "误报例外已被 enabled=false 关闭"
		case exceptions.StatusExpired:
			level = slog.LevelWarn
			message = "误报例外已过期失效"
		}
		logger.Log(context.Background(), level, message,
			"instance", instance,
			"name", entry.Name,
			"reason", entry.Reason,
			"scope", entry.Scope,
			"status", string(entry.Status),
			"directives", len(entry.Directives),
		)
	}

	logger.Info("误报例外清单汇总",
		"instance", instance,
		"total", len(set.Entries),
		"applied", set.Applied,
		"scoped_rules", len(set.Pre),
		"global_directives", len(set.Post),
	)
}

// Evaluate 执行一次检测并返回结论。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, fmt.Errorf("请求上下文为空，无法执行检测")
	}
	raw := rctx.Raw

	tx := c.waf.NewTransaction()
	defer func() {
		// 先落审计钩子（当前 AuditEngine=Off，属空操作），再释放事务缓冲，
		// 顺序不能颠倒：事务缓冲释放后再读变量会得到空值。
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	serverHost := raw.Host
	if serverHost == "" {
		serverHost = raw.HeaderValue("Host")
	}
	serverPort := 80
	if strings.Contains(strings.ToUpper(raw.Proto), "HTTPS") {
		serverPort = 443
	}

	// 说明：raw.Proto 在 forward-auth 通道下通常是「协议方案」（http / https），
	// 而不是 HTTP 版本号；必须经 httpVersionOf 规范化后再交给引擎。
	tx.ProcessConnection(raw.ClientIP, 0, serverHost, serverPort)
	tx.SetServerName(serverHost)
	tx.ProcessURI(raw.URI, raw.Method, httpVersionOf(raw.Proto))

	for name, values := range raw.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
	// net/http 会把 Host 从 Header 中移除，必须显式补回，否则 CRS 的
	// REQUEST_HEADERS:Host 与 SERVER_NAME 相关规则会失效。
	tx.AddRequestHeader("Host", serverHost)

	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return c.blockedResult(rctx, tx, interruption), nil
	}

	// 无条件执行「请求体阶段」（Coraza phase 2）求值。
	//
	// 之所以「请求头实例也必须执行」：
	//  1. CRS 的攻击规则（942xxx SQL 注入、941xxx XSS 等）注册在请求体阶段，
	//     查询串参数（ARGS / ARGS_GET）也在该阶段被解析；只执行 ProcessRequestHeaders
	//     会漏掉查询串注入（例如 /api/user?id=1' OR '1'='1）。
	//  2. Coraza 的事务状态机要求：只有执行过 ProcessRequestBody，
	//     MatchedRules 与异常评分等变量才会取到最终值。
	//  3. 请求头实例不会读体：evaluateBody 在 process_body=false 时不向引擎写入任何字节，
	//     只触发 phase 2 求值，代价可忽略，也不违背「按需读体」约束（R13）。
	result, err := c.evaluateBody(tx, rctx)
	if err != nil || result != nil {
		return result, err
	}

	return c.passedResult(rctx, tx), nil
}

// evaluateBody 执行请求体阶段求值。
//
// 行为要点：
//   - 只有「体阶段实例」（process_body=true）才会把请求体读入引擎；
//     请求头实例只做 phase 2 求值，用于让查询串参数参与 CRS 攻击检测。
//   - 无论是否写入请求体，最后都必须调用 ProcessRequestBody：
//     Coraza 要求 phase 1 已执行过，且攻击规则与异常评分的最终值在 phase 2 结束时确定。
//
// 返回值语义：result 非 nil 表示已有终态结论（拦截或业务错误），调用方直接返回；
// result 为 nil 且 err 为 nil 表示未产生结论，继续返回放行 / 观察结论。
func (c *Check) evaluateBody(tx corazatypes.Transaction, rctx *core.RequestContext) (*core.Result, error) {
	if c.processBody {
		switch {
		case rctx.Stream == nil:
			// 体通道不可用（例如接入形态不转发请求体，或配置为 disabled）。
			// 这不是错误：接入形态决定了代理是否把请求体转发给鉴权端点。
			c.logger.Debug("体阶段实例未获得请求体通道，跳过请求体读取",
				"instance", c.name, "request_id", rctx.RequestID,
				"body_present", rctx.Body.Present, "body_source", rctx.Body.Source,
			)
			c.metrics.IncBodyMissing()
		case c.skipMultipart(rctx):
			// multipart 解析被关闭：不把请求体交给引擎，仅让其参与不含请求体变量的规则匹配。
			// 之所以仍然继续往下执行：phase 2 的求值必须发生，否则查询串等变量不会被检测。
			c.logger.Debug("multipart 解析已关闭，跳过请求体读取",
				"instance", c.name, "request_id", rctx.RequestID,
				"content_type", rctx.Body.ContentType,
			)
		default:
			if result := c.checkJSONDepth(rctx); result != nil {
				return result, nil
			}

			interruption, written, err := tx.ReadRequestBodyFrom(rctx.Stream)
			if written > 0 {
				c.metrics.AddBodyBytes(c.name, int64(written))
			}
			if err != nil {
				return nil, fmt.Errorf("请求体写入检测引擎失败：%w", err)
			}
			if interruption != nil {
				return c.blockedResult(rctx, tx, interruption), nil
			}
		}
	}

	// 无条件触发 phase 2 求值：查询串参数与请求头规则在该阶段参与攻击检测，
	// 这是「请求头实例也能拦截查询串注入」的关键。
	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, fmt.Errorf("请求体检测失败：%w", err)
	}
	if interruption != nil {
		return c.blockedResult(rctx, tx, interruption), nil
	}
	return nil, nil
}

// defaultHTTPVersion 是「无法从接入信息推断 HTTP 版本」时使用的兜底版本号。
//
// 选 HTTP/1.1 的原因：它是 CRS 默认白名单（tx.allowed_http_versions）中的一员，
// 也是所有代理都必然接受的版本，不会因为兜底值本身触发协议类规则。
const defaultHTTPVersion = "HTTP/1.1"

// httpVersionOf 把接入层还原出的「协议描述」规范化为 Coraza 期望的 HTTP 版本号。
//
// 为什么需要这一步：在 forward-auth 通道下，代理通过 X-Forwarded-Proto 转发的是
// 「协议方案」（http / https），而 Coraza 的 ProcessURI 第三个参数期望的是
// HTTP 版本（HTTP/1.1、HTTP/2.0）。若把 "https" 原样喂给引擎，
// CRS 的 920430（HTTP 协议版本白名单）会命中，导致所有请求被误拦。
func httpVersionOf(proto string) string {
	trimmed := strings.TrimSpace(proto)
	if trimmed == "" {
		return defaultHTTPVersion
	}
	// 版本号统一转大写：CRS 的 tx.allowed_http_versions 是「空格分隔 + 区分大小写」的
	// 集合（HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 ...），传入小写会造成 920430 误判。
	if strings.HasPrefix(strings.ToUpper(trimmed), "HTTP/") {
		return strings.ToUpper(trimmed)
	}
	// 方案（http / https / h2c 等）本身不携带版本信息，只能兜底。
	return defaultHTTPVersion
}

// skipMultipart 报告本次请求是否应当跳过 multipart 请求体读取。
//
// 判定顺序说明：优先取接入层已解析好的 BodyMeta.ContentType（它已经过头部提取与
// 规范化），仅当它为空时才回退读原始请求头，避免在正常情况下重复解析头部。
func (c *Check) skipMultipart(rctx *core.RequestContext) bool {
	if c.parseMultipart {
		return false
	}
	contentType := rctx.Body.ContentType
	if strings.TrimSpace(contentType) == "" {
		contentType = rctx.Raw.HeaderValue("Content-Type")
	}
	return isMultipartContentType(contentType)
}

// blockedResult 把 Coraza 的中断（interruption）转换为校验结论。
//
// HTTP 状态码到判定结论的映射保持忠实：Coraza 的 413（请求体超限）与 429
// 分别对应「不符合安全要求」与「限速」，若一律映射为 403 会让运维无法区分原因。
func (c *Check) blockedResult(rctx *core.RequestContext, tx corazatypes.Transaction, interruption *corazatypes.Interruption) *core.Result {
	verdict := verdictForStatus(interruption.Status)
	ruleID := strconv.Itoa(interruption.RuleID)

	result := &core.Result{
		Verdict:  verdict,
		Check:    c.name,
		Score:    c.anomalyScore(tx),
		Findings: c.findings(tx, ruleID),
	}
	if c.mode == ModeDetectionOnly {
		// 防御性处理：detection_only 下 SecRuleEngine=DetectionOnly 本不应产生中断；
		// 一旦产生（例如实例级 mode 与规则内 ctl 动作冲突），按观察处理而不是拦截，
		// 避免「配置成只观察却真的拦了」。
		result.Verdict = core.VerdictObserve
	}
	result.AddAlert(c.newAlert(rctx, result.Verdict, ruleID, result.Score))
	c.storeScore(rctx, result.Score)
	return result
}

// passedResult 在未产生中断时给出「观察」或「无结论」。
func (c *Check) passedResult(rctx *core.RequestContext, tx corazatypes.Transaction) *core.Result {
	score := c.anomalyScore(tx)
	// 这里刻意不传 fallbackRuleID：未产生中断时，若没有任何「可上报」的命中规则，
	// 就不应该凭空造出一条命中明细。CRS 每次请求都会命中若干初始化规则
	//（id:900000 / 901xxx），把它们当作战果汇报只会污染访问日志与指标。
	findings := c.findings(tx, "")
	if len(findings) == 0 && score == 0 {
		return nil
	}

	result := &core.Result{
		Verdict:  core.VerdictObserve,
		Check:    c.name,
		Score:    score,
		Findings: findings,
	}

	// DetectionOnly 的「若拦截」判定（需求 P1-6）。
	//
	// 判定口径：观察模式下 CRS 的 deny 动作被引擎抑制（tx.Interruption() 为 nil），
	// 但异常评分照常累计。因此「评分越过阈值」就是「如果开着拦截，这次请求会被拦」。
	// 阈值取 engine.anomaly_score_threshold，与 CRS 自身阻断判定、threshold 单元同源。
	if c.mode == ModeDetectionOnly && c.wouldBlockThreshold > 0 && score >= c.wouldBlockThreshold {
		ruleID := firstReportableRuleID(findings)
		c.metrics.IncWouldBlock(c.name, ruleID)
		result.MarkWouldBlock(fmt.Sprintf("评分 %d 达到阈值 %d（首条命中规则 %s）",
			score, c.wouldBlockThreshold, ruleID))

		// 系统日志留痕：试运行阶段运维需要看到「本应拦截」的细节，
		// 但访问日志的 would_block 字段已经承载了结论，这里只补充原因。
		c.logger.Info("旁路观察模式：本次请求本应被拦截",
			"instance", c.name,
			"request_id", rctx.RequestID,
			"score", score,
			"threshold", c.wouldBlockThreshold,
			"rule_id", ruleID,
			"findings", len(findings),
		)
	}
	return result
}

// firstReportableRuleID 返回命中明细中第一条规则的 ID，用于指标与日志定位。
//
// 取第一条而不是全部：指标标签的基数必须可控（见 observe/metrics.go 的标签基数说明），
// 完整命中明细已经在 Result.Findings 与访问日志里，指标只用于「看趋势 + 定位主力规则」。
func firstReportableRuleID(findings []core.Finding) string {
	for _, finding := range findings {
		if finding.RuleID != "" {
			return finding.RuleID
		}
	}
	return "unknown"
}

// findings 把命中规则转换为命中明细。
//
// 严重级别取事务的「最高严重级别」（CRS 会维护该变量）：Coraza 的 MatchedRule
// 不暴露单条规则的严重级别，逐条猜测会造成不一致，因此统一使用事务级最高级别。
func (c *Check) findings(tx corazatypes.Transaction, fallbackRuleID string) []core.Finding {
	matched := tx.MatchedRules()
	severity := c.severity(tx)
	limit := c.maxFindings
	if limit <= 0 {
		limit = defaultMaxFindings
	}

	findings := make([]core.Finding, 0, limit)
	for _, rule := range matched {
		if !reportableRule(rule) {
			continue
		}
		if len(findings) >= limit {
			break
		}
		id := strconv.Itoa(rule.Rule().ID())
		finding := core.NewFinding(c.name, id, rule.Message(), severity, 0)
		finding.Data = map[string]string{
			"rule_id":     id,
			"matched_var": firstMatchedVar(rule),
			"data":        truncate(rule.Data(), 512),
		}
		findings = append(findings, finding)
	}
	if len(findings) > 0 {
		return findings
	}
	if fallbackRuleID == "" {
		return nil
	}
	return []core.Finding{core.NewFinding(
		c.name, fallbackRuleID, "检测引擎命中（无规则明细）", severity, 0,
	)}
}

// reportableRule 判断一条命中规则是否值得写入命中明细。
//
// 之所以需要过滤：CRS 的初始化文件（REQUEST-901 / REQUEST-905）会执行大量
// SecAction / SecRule（id:900000、id:900001、id:9011xx），它们只用于给 TX 变量
// 赋默认值，带 nolog，其中一部分还不带 msg。若不过滤，任何一次拦截都会附带
// 十几条「初始化规则命中」，既淹没真正的攻击规则，也造成日志放大（需求 R13）。
//
// 过滤条件（两项同时满足才算可上报）：
//
//  1. 规则 ID 不在 CRS 初始化区间 [900000, 901999] 内。
//     该区间是 CRS 保留给「设置与初始化」的编号段：900000 / 900001 来自
//     crs-setup.conf，901xxx 来自 REQUEST-901-INITIALIZATION.conf。其中相当一部分
//     规则虽然带 msg（例如 id:901340 的 "Enabling body inspection"），
//     但语义上并不是攻击命中，不应写进命中明细。
//  2. 规则携带非空的 msg。
//     CRS 的攻击规则与异常评分规则（942xxx、941xxx、949110 等）一律带 msg；
//     纯赋值 / 跳过类规则一律不带 msg。
func reportableRule(rule corazatypes.MatchedRule) bool {
	if rule.Rule() == nil {
		return false
	}
	id := rule.Rule().ID()
	if id >= crsInitializationRuleIDMin && id <= crsInitializationRuleIDMax {
		return false
	}
	return strings.TrimSpace(rule.Message()) != ""
}

// newAlert 构造拦截告警（供 M3 的告警通道并联扇出）。
func (c *Check) newAlert(rctx *core.RequestContext, verdict core.Verdict, ruleID string, score int) core.Alert {
	level := core.AlertLevelWarn
	title := "检测引擎拦截请求"
	if verdict == core.VerdictObserve {
		level = core.AlertLevelInfo
		title = "检测引擎命中规则（观察模式）"
	}

	site := core.DefaultSiteName
	if rctx.Site != nil && rctx.Site.Name != "" {
		site = rctx.Site.Name
	}

	return core.Alert{
		Level:     level,
		Title:     title,
		Message:   fmt.Sprintf("检测引擎在 %s 阶段命中规则 %s（异常评分 %d）", c.phase.String(), ruleID, score),
		Site:      site,
		ClientIP:  rctx.Raw.ClientIP,
		RequestID: rctx.RequestID,
		Fields: map[string]string{
			"check":   c.name,
			"rule_id": ruleID,
			"score":   strconv.Itoa(score),
			"uri":     rctx.Raw.URI,
			"method":  rctx.Raw.Method,
			"mode":    c.mode,
			"phase":   c.phase.String(),
			"at":      time.Now().Format(time.RFC3339),
		},
	}
}

// anomalyScore 读取事务的入站异常评分。
//
// 之所以用类型断言访问事务变量：Coraza 的 types.Transaction 接口没有暴露变量读取，
// 只有 experimental/plugins/plugintypes.TransactionState 暴露了 Variables()。
// 这是官方提供的扩展点（action / operator 插件同样依赖它），因此可以安全使用；
// 断言失败时返回 0 而不是报错——评分缺失不应让检测结果失效。
func (c *Check) anomalyScore(tx corazatypes.Transaction) int {
	state, ok := tx.(corazaexp.TransactionState)
	if !ok {
		return 0
	}
	txVars := state.Variables()
	if txVars == nil {
		return 0
	}

	for _, name := range []string{anomalyScoreVarBlocking, anomalyScoreVarDetection} {
		values := txVars.TX().Get(name)
		if len(values) == 0 {
			continue
		}
		if score, err := strconv.Atoi(strings.TrimSpace(values[0])); err == nil && score != 0 {
			return score
		}
	}
	return 0
}

// severity 读取事务的最高严重级别并映射为本项目的严重级别。
func (c *Check) severity(tx corazatypes.Transaction) core.Severity {
	state, ok := tx.(corazaexp.TransactionState)
	if !ok {
		return core.SeverityMedium
	}
	raw := state.Variables().HighestSeverity().Get()
	if strings.TrimSpace(raw) == "" {
		return core.SeverityMedium
	}

	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "emergency", "alert":
		return core.SeverityCritical
	case "critical", "error":
		return core.SeverityHigh
	case "warning":
		return core.SeverityMedium
	case "notice":
		return core.SeverityLow
	case "info", "debug":
		return core.SeverityInfo
	default:
		return core.SeverityMedium
	}
}

// storeScore 把异常评分写入请求上下文的状态，供 PhasePost 的阈值单元读取。
//
// 与 Result.Score 同时写入是刻意的：threshold 单元取「执行器汇总分」与
// 「本键评分」的较大值，两者同源时结果一致，不会重复计分（取较大值而非求和）。
func (c *Check) storeScore(rctx *core.RequestContext, score int) {
	if score == 0 {
		return
	}
	rctx.SetState(c.scoreKey, score)
}

// firstMatchedVar 返回首个命中变量的可读描述，例如 ARGS:username。
func firstMatchedVar(rule corazatypes.MatchedRule) string {
	datas := rule.MatchedDatas()
	if len(datas) == 0 {
		return ""
	}
	matched := datas[0]
	if key := matched.Key(); key != "" {
		return matched.Variable().Name() + ":" + key
	}
	return matched.Variable().Name()
}

// truncate 按「字节」截断字符串，避免超长证据撑大日志。
func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "…(已截断)"
}

// scoreKeyOf 解析评分状态键。
func scoreKeyOf(settings Settings) string {
	if key := strings.TrimSpace(settings.ScoreKey); key != "" {
		return key
	}
	return defaultScoreKey
}

// maxFindingsOf 解析命中明细条数上限。
func maxFindingsOf(settings Settings) int {
	if settings.MaxFindings > 0 {
		return settings.MaxFindings
	}
	return defaultMaxFindings
}

// metricsOf 返回指标写入接口，未注入时使用空实现。
func metricsOf(deps *core.Deps) core.MetricsRecorder {
	if deps == nil || deps.Metrics == nil {
		return core.NoopMetrics{}
	}
	return deps.Metrics
}

// verdictForStatus 把 Coraza 中断的状态码映射为判定结论。
func verdictForStatus(status int) core.Verdict {
	switch status {
	case 400, 413, 414, 431:
		return core.VerdictBadRequest
	case 401:
		return core.VerdictUnauthorized
	case 429:
		return core.VerdictRateLimited
	case 503:
		return core.VerdictUnavailable
	default:
		return core.VerdictBlock
	}
}

// checkJSONDepth 在 JSON 请求体上执行嵌套深度守卫。
//
// 只在「配置了 json_depth_limit」且「内容类型为 JSON」时生效；
// 命中时直接返回 400 结论，并累加异常评分，使 threshold / autoban 也能感知。
//
// 之所以在把请求体交给引擎之前做这一步：深层嵌套的 JSON 会让上游 JSON 处理器
// 递归展开并长时间占用 CPU；提前拦截可以把代价压到「一次线性扫描」。
func (c *Check) checkJSONDepth(rctx *core.RequestContext) *core.Result {
	if c.jsonDepthLimit <= 0 || !isJSONContentType(rctx.Body.ContentType) {
		return nil
	}

	limit := c.bodyScanCap
	if limit <= 0 || (rctx.Body.Bytes > 0 && rctx.Body.Bytes < limit) {
		limit = rctx.Body.Bytes
	}
	if limit <= 0 {
		return nil
	}

	// 多读 1 个字节用于判断「是否被截断」，避免把「刚好等于上限」当成完整内容。
	content, err := io.ReadAll(io.LimitReader(rctx.Stream, limit+1))
	if err != nil {
		c.logger.Warn("JSON 深度检查读取请求体失败，跳过该检查",
			"instance", c.name, "request_id", rctx.RequestID, "error", err.Error())
		return nil
	}
	if len(content) > int(limit) {
		content = content[:limit]
	}
	// 无论是否命中，都必须把读取游标复位：后续 Coraza 需要从头读取同一份请求体。
	if err := rctx.Stream.Rewind(); err != nil {
		c.logger.Warn("JSON 深度检查后复位请求体失败",
			"instance", c.name, "request_id", rctx.RequestID, "error", err.Error())
	}

	depth := maxJSONDepth(content)
	if depth <= c.jsonDepthLimit {
		return nil
	}

	message := fmt.Sprintf("JSON 请求体嵌套深度 %d 超过上限 %d", depth, c.jsonDepthLimit)
	result := &core.Result{
		Verdict: core.VerdictBadRequest,
		Check:   c.name,
		Message: message,
		Findings: []core.Finding{core.NewFinding(
			c.name, jsonDepthExceededRuleID, message, core.SeverityHigh, 0,
		)},
	}
	result.Findings[0].Data = map[string]string{
		"depth": fmt.Sprintf("%d", depth),
		"limit": fmt.Sprintf("%d", c.jsonDepthLimit),
	}
	c.logger.Warn("请求体嵌套深度超限，已拦截",
		"instance", c.name, "request_id", rctx.RequestID, "depth", depth, "limit", c.jsonDepthLimit,
	)
	return result
}

// bodyScanCapOf 计算 JSON 深度扫描的字节上限。
//
// 取「请求体可读字节数」与「limits.max_scan_token_bytes」的较小值：
// 后者是本项目统一的「单个待检测 token 大小上限」，复用它可以避免新增配置项，
// 同时保证扫描代价始终有界（需求 R13：不做大体积读取）。
func bodyScanCapOf(deps *core.Deps, engine core.EngineSettings) int64 {
	cap := engine.BodyLimitBytes
	if deps != nil && deps.Limits.MaxScanTokenBytes > 0 {
		if cap <= 0 || deps.Limits.MaxScanTokenBytes < cap {
			cap = deps.Limits.MaxScanTokenBytes
		}
	}
	return cap
}
