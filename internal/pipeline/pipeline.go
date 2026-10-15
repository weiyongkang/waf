// Package pipeline 实现「串联校验链执行器」（需求 R5 / R6 / R8）。
//
// 执行模型：
//
//	按 Phase（pre -> request -> body -> post）+ Order 升序串联，逐个执行校验单元；
//	遇到终态结论（Verdict.IsShortCircuit）立即短路，后续校验单元不再执行；
//	全部单元均无结论时返回放行（allow）；
//	单元自身的运行错误按该单元的 on_error 策略处理（pass = 失败开放 / block = 失败关闭）。
//
// 按需读体（需求 R13）：只有当链中存在启用的 PhaseBody 校验单元，
// 且请求体通道确实可用时才读取请求体；整个请求只读取一次，
// 缓冲到 ingress/body.Spool 之后，各单元通过 Rewind 反复读取同一份内容。
//
// 本包是 core.Decider 的唯一生产实现；HTTP 层（internal/server）只依赖该接口，
// 因此替换为「站点级校验链」「灰度链」等实现时，server 无需任何改动。
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/ingress/body"
)

// deciderName 是执行器名称，用于启动日志、访问日志与指标标签。
const deciderName = "pipeline"

// Config 是构建校验链所需的配置来源。
type Config struct {
	// Instances 是校验单元实例声明（对应配置文件的 pipeline 数组，顺序即声明顺序）。
	Instances []core.InstanceConfig
	// Body 是请求体通道配置（来自 ingress.body），仅在有 PhaseBody 单元时才会用到。
	Body config.BodyConfig
}

// entry 是校验链中的一项：校验单元实例 + 其失败策略。
type entry struct {
	// check 是已构造完成的校验单元实例。
	check core.Check
	// onError 是该实例的失败策略（已按「实例配置 -> 实现自报默认 -> pass」解析完毕）。
	onError string
}

// Pipeline 是有序校验链执行器，实现 core.Decider。
type Pipeline struct {
	// entries 是排序后的校验链；已剔除 enabled=false 的实例。
	entries []entry
	// bodyCfg 是请求体通道配置。
	bodyCfg config.BodyConfig
	// logger 是系统日志器（执行器自身诊断用，校验单元日志由插件自行输出）。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
	// clock 是时间源，用于统计单个校验单元的耗时。
	clock core.Clock
	// bans 是内部封禁控制器；未注入时封禁动作不会落地（会写 warn 日志）。
	bans core.BanController

	// needsBody 表示链中存在启用的 PhaseBody 校验单元。
	needsBody bool
	// readBody 表示本次运行确实需要读取请求体（存在体阶段单元且体通道可用）。
	readBody bool

	// closeOnce 保证 Close 幂等（进程退出路径与错误回滚路径都可能调用）。
	closeOnce sync.Once
	// closeErr 记录首次 Close 的错误，供重复调用时原样返回。
	closeErr error
}

// New 依据配置与依赖构建校验链。
//
// 装配期（而非请求期）完成全部昂贵操作：类型解析、配置解析、连接池建立、规则加载。
// 任一实例构造失败都会整体失败并回滚已建实例，遵循 fail fast 原则——
// 「配置里写了插件但实现不存在」必须在启动阶段暴露，而不是等首个请求到达。
func New(cfg Config, deps *core.Deps) (*Pipeline, error) {
	if deps == nil {
		deps = &core.Deps{}
	}

	metrics := deps.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}
	clock := deps.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}

	pipeline := &Pipeline{
		bodyCfg: cfg.Body,
		logger:  deps.SystemLoggerOr(),
		metrics: metrics,
		clock:   clock,
		bans:    deps.Bans,
	}

	for _, inst := range cfg.Instances {
		// 关闭的实例直接丢弃：运行期完全不产生任何开销（需求 R6）。
		if !inst.Enabled {
			continue
		}

		check, err := core.NewCheck(inst, deps)
		if err != nil {
			// 回滚已构造实例，避免连接池 / 临时文件 / 后台 goroutine 泄漏。
			_ = pipeline.Close()
			return nil, err
		}

		if check.Phase() == core.PhaseBody {
			pipeline.needsBody = true
		}
		pipeline.entries = append(pipeline.entries, entry{
			check:   check,
			onError: resolveOnError(inst, check),
		})
	}

	// 稳定排序：先按阶段，再按同阶段内的 order；声明顺序作为最后的稳定依据。
	// 之所以用 SliceStable：order 相同的实例不应因为排序而随机交换执行次序，
	// 否则「串联顺序」不可预测，排障时无法复现。
	sort.SliceStable(pipeline.entries, func(i, j int) bool {
		left, right := pipeline.entries[i].check, pipeline.entries[j].check
		if left.Phase() != right.Phase() {
			return left.Phase() < right.Phase()
		}
		return left.Order() < right.Order()
	})

	pipeline.readBody = pipeline.needsBody &&
		cfg.Body.Mode != config.BodyModeDisabled &&
		cfg.Body.Source == "request-body"

	return pipeline, nil
}

// Name 返回执行器名称（core.Decider 实现）。
func (p *Pipeline) Name() string { return deciderName }

// NeedsBody 报告本次运行是否需要读取请求体（core.Decider 实现）。
//
// 该方法是「按需读体」的判定依据：返回 false 时 HTTP 层连读取超时都不设置，
// 请求体一个字节都不会被读取。
func (p *Pipeline) NeedsBody() bool { return p.readBody }

// Entries 返回排序后的校验单元实例名列表，供启动日志与 check-config 摘要输出。
func (p *Pipeline) Entries() []string {
	names := make([]string, 0, len(p.entries))
	for _, item := range p.entries {
		names = append(names, fmt.Sprintf("%s/%s@%s#%d", item.check.Name(), item.check.Type(), item.check.Phase(), item.check.Order()))
	}
	return names
}

// Decide 执行整条校验链并返回最终结论（core.Decider 实现）。
//
// 返回的 Result 永不为 nil：链为空或全部单元均无结论时返回放行（allow）结论。
func (p *Pipeline) Decide(ctx context.Context, rctx *core.RequestContext) *core.Result {
	if rctx == nil {
		return &core.Result{Verdict: core.VerdictAllow, Check: deciderName}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// 把请求上下文交给校验单元：访问共享存储、调用外部服务的单元必须能感知取消与超时。
	rctx.Context = ctx

	// 1) 按需读体：读取失败或超限拒绝时直接返回业务错误，不进入校验链。
	if err := p.prepareBody(rctx); err != nil {
		return p.bodyErrorResult(rctx, err)
	}

	// 2) 串联执行：合并全部结论，遇终态立即短路。
	//
	// 收尾阶段（PhasePost）例外：链一旦短路，后续的中间阶段单元全部跳过，
	// 但收尾阶段单元仍然执行。原因是收尾阶段承担的是「评分聚合、封禁落地、
	// 告警外送」这类事后动作——它们必须在拦截之后依然发生，
	// 否则「命中即拦截」的规则永远不会触发自动封禁与告警。
	merged := &core.Result{Verdict: core.VerdictContinue, Check: deciderName}
	shortCircuited := false
	for _, item := range p.entries {
		if shortCircuited && item.check.Phase() != core.PhasePost {
			continue
		}
		// 体阶段单元执行前统一把读取游标复位：同一份请求体可能被多个体阶段单元检测
		// （例如「编码还原检查」与「引擎体检测」），由执行器统一复位可以保证
		// 每个单元都从起点读取完整内容，插件无需关心自己是第几个体检测单元。
		if rctx.Stream != nil && item.check.Phase() == core.PhaseBody {
			if err := rctx.Stream.Rewind(); err != nil {
				p.logger.Warn("请求体读取位置复位失败",
					"request_id", rctx.RequestID, "check", item.check.Name(), "error", err.Error())
			}
		}

		result := p.runCheck(rctx, item)
		if result == nil {
			continue
		}
		rctx.AppendResult(result)
		mergeResult(rctx, merged, result)

		if result.Verdict.IsBlocking() {
			p.metrics.IncBlocked(result.Check, firstRuleID(result))
		}
		if result.Verdict.IsShortCircuit() {
			shortCircuited = true
		}
	}

	// 3) 收尾：全部无结论等价于放行（零插件时的行为，验收项 A3）。
	if merged.Verdict == core.VerdictContinue {
		merged.Verdict = core.VerdictAllow
	}
	if merged.Check == "" {
		merged.Check = deciderName
	}

	// 4) 封禁落地：把校验单元请求的封禁动作写入共享存储（需求 R18 / R19）。
	//
	// 之所以放在判定之后、且失败不影响返回值：封禁是「后续请求」的事，
	// 写名单失败不应该改变本次请求的结论（本次该拦的已经拦了），
	// 但必须记录错误，以便运维发现名单写入故障。
	p.applyBans(ctx, rctx, merged)
	return merged
}

// applyBans 落地封禁动作。
//
// 说明：未注入 BanController（例如纯冒烟场景）时直接跳过，
// 此时若存在封禁请求会写 warn 日志提示「封禁未生效」，避免安全动作被静默丢弃。
func (p *Pipeline) applyBans(ctx context.Context, rctx *core.RequestContext, result *core.Result) {
	if result == nil || len(result.Bans) == 0 {
		return
	}
	if p.bans == nil {
		p.logger.Warn("校验链请求了封禁动作，但未装配封禁控制器，封禁未生效",
			"request_id", rctx.RequestID, "bans", len(result.Bans))
		return
	}
	if err := p.bans.Ban(ctx, rctx, result.Bans); err != nil {
		p.logger.Error("封禁动作落地失败", "request_id", rctx.RequestID, "error", err.Error())
	}
}

// Close 逆序关闭全部校验单元（core.Decider 之外的资源释放接口）。
//
// 逆序（后建先关）是资源释放的通行惯例：后构造的实例可能持有对先构造实例的引用。
// 该方法幂等：重复调用返回首次调用的错误。
func (p *Pipeline) Close() error {
	p.closeOnce.Do(func() {
		for index := len(p.entries) - 1; index >= 0; index-- {
			if err := p.entries[index].check.Close(); err != nil && p.closeErr == nil {
				p.closeErr = fmt.Errorf("关闭校验单元 %q 失败：%w", p.entries[index].check.Name(), err)
			}
		}
	})
	return p.closeErr
}

// prepareBody 按需读取并缓冲请求体。
//
// 只有同时满足「链中存在启用的 PhaseBody 单元」「请求体通道可用」两个条件时才读体；
// 其余情况（例如纯头检测、nginx 原生通道不转发体）完全不触碰请求体，零开销。
func (p *Pipeline) prepareBody(rctx *core.RequestContext) error {
	if !p.readBody || rctx.Raw == nil {
		return nil
	}

	spool, err := body.New(p.bodyCfg, body.Options{Logger: p.logger, Metrics: p.metrics})
	if err != nil {
		return fmt.Errorf("初始化请求体缓冲失败：%w", err)
	}

	source := body.Source{
		Reader: rctx.Raw.Body,
		// 原始方法决定「本次请求本应携带请求体吗」：
		// GET / HEAD 等无体是正常现象，只有 POST / PUT / PATCH 等缺失才计入 waf_body_missing_total。
		Method: rctx.Raw.Method,
		// 原始请求声明的请求体长度（由接入适配器还原，见 forwardauth.Extractor.pickContentLength）：
		// 0 表示客户端明确声明了空请求体（没有参数是正常现象，不计缺失），
		// -1 表示未知（chunked 编码或接入通道不转发 Content-Length），>0 表示声明了具体长度。
		Declared:    rctx.Raw.ContentLength,
		ContentType: rctx.Raw.HeaderValue("Content-Type"),
	}
	if err := spool.Fill(source); err != nil {
		// Fill 失败时缓冲内部已释放资源，此处只需兜底关闭。
		_ = spool.Close()
		return err
	}

	// 压缩体解压（P1-5）：代理会把 Content-Encoding: gzip 的请求体原样转交，
	// 不解压则请求体内容对检测引擎完全不可见（加个压缩头即可绕过体检测）。
	//
	// 之所以放在接入层统一做一次：解压后的明文是链中所有 PhaseBody 单元的共同输入，
	// 放在引擎实例里会让同一份请求体被重复解压（多实例串联时尤其浪费）。
	decoded, err := body.Decode(spool, rctx.Raw.HeaderValue("Content-Encoding"),
		p.bodyCfg.Decompress, body.Options{Logger: p.logger, Metrics: p.metrics})
	if err != nil {
		_ = spool.Close()
		return err
	}

	// 缓冲（或解压）成功：写入请求上下文，供各 PhaseBody 单元通过 Rewind 反复读取。
	rctx.Stream = decoded
	rctx.Body = decoded.Meta()
	if rctx.Body.Skipped {
		p.logger.Warn("请求体超限且策略为 skip，本次请求跳过体检测",
			"request_id", rctx.RequestID, "max_bytes", p.bodyCfg.MaxBytes)
	}
	return nil
}

// bodyErrorResult 把请求体读取失败映射为对外结论。
//
// 两类失败的区别：
//   - 超过上限且策略为 reject：属于客户端请求本身不合法，返回 400（VerdictBadRequest）；
//   - 其它读取失败（例如客户端中断）：同样按 400 处理，因为 WAF 无法完成必要判断，
//     放行不可信、返回 503 又会把客户端错误升级为服务端故障。
func (p *Pipeline) bodyErrorResult(rctx *core.RequestContext, err error) *core.Result {
	ruleID := "body_read_error"
	message := "无法读取请求体，请求已被拒绝"
	if errors.Is(err, body.ErrBodyTooLarge) {
		ruleID = "body_too_large"
		message = "请求体超过允许的大小上限"
	}
	// 不支持的压缩编码 / 解压后超限：同样属于「请求本身不合法」，返回 400。
	// 之所以与「读取失败」区分 rule_id：运维需要能一眼看出「拦截原因是压缩体」，
	// 进而决定是开启解压、放宽上限，还是把该来源判为恶意。
	if errors.Is(err, body.ErrUnsupportedEncoding) {
		ruleID = "body_unsupported_encoding"
		message = "请求体使用了不受支持的压缩编码"
	}

	p.logger.Warn("请求体处理失败",
		"request_id", rctx.RequestID, "rule_id", ruleID, "error", err.Error())

	return &core.Result{
		Verdict: core.VerdictBadRequest,
		Check:   deciderName,
		Message: message,
		Findings: []core.Finding{core.NewFinding(
			deciderName, ruleID, message, core.SeverityMedium, 0,
		)},
	}
}

// runCheck 执行单个校验单元，并按 on_error 策略处理其运行错误。
//
// 返回值语义：
//   - nil：单元本次不产生任何结论（等价于「未命中」）；
//   - 非 nil：单元的结论，调用方负责合并与短路判断。
func (p *Pipeline) runCheck(rctx *core.RequestContext, item entry) *core.Result {
	startedAt := p.clock.Now()
	result, err := item.check.Evaluate(rctx)
	p.metrics.ObserveCheckDuration(item.check.Name(), p.clock.Since(startedAt).Seconds())

	if err == nil {
		if result == nil {
			return nil
		}
		if result.Check == "" {
			// 兜底填充实例名：避免插件漏填导致日志与指标无法定位来源。
			result.Check = item.check.Name()
		}
		return result
	}

	// 单元自身运行失败：区分「失败关闭」与「失败开放」两种策略。
	p.metrics.IncCheckError(item.check.Name())
	if result == nil {
		result = &core.Result{Check: item.check.Name()}
	}
	if result.Check == "" {
		result.Check = item.check.Name()
	}
	result.Err = err

	common := []any{
		"request_id", rctx.RequestID,
		"check", item.check.Name(),
		"type", item.check.Type(),
		"on_error", item.onError,
		"error", err.Error(),
	}

	if item.onError == core.OnErrorBlock {
		// 失败关闭：宁可拦截，也不放过无法检测的流量（例如检测引擎不可用）。
		result.Verdict = core.VerdictUnavailable
		p.logger.Error("校验单元执行失败，按 on_error=block 拦截请求", common...)
		return result
	}

	// 失败开放：只有当单元没有给出终态结论时才把结论归零。
	// 之所以保留终态结论：单元可能「已判定拦截、随后记录动作又失败」，
	// 此时放行会削弱防护，保留拦截更安全。
	if !result.Verdict.IsShortCircuit() {
		result.Verdict = core.VerdictContinue
	}
	p.logger.Error("校验单元执行失败，按 on_error=pass 放行请求", common...)
	return result
}

// resolveOnError 解析实例的失败策略。
//
// 解析顺序（设计文档 §7.4）：
//  1. 实例显式配置的 on_error；
//  2. 实现通过 OnErrorDefaulter 自报的默认值（引擎类默认 block）；
//  3. 兜底 pass（失败开放）。
func resolveOnError(inst core.InstanceConfig, check core.Check) string {
	switch inst.OnError {
	case core.OnErrorPass, core.OnErrorBlock:
		return inst.OnError
	}
	if defaulter, ok := check.(core.OnErrorDefaulter); ok {
		if defaulter.DefaultOnError() == core.OnErrorBlock {
			return core.OnErrorBlock
		}
	}
	return core.OnErrorPass
}

// mergeResult 把单个校验单元的结论合并进累积结论。
//
// 合并规则（设计文档 §7.4）：
//   - 评分 / 命中明细 / 封禁请求 / 告警请求：全部累加，供阈值判定与后续动作使用；
//   - 判定结论：只有「累积结论仍为无结论或观察」时才被新结论覆盖，
//     保证先出现的拦截结论不会被后续单元的放行结论冲掉。
//
// 评分会被同时累加到 RequestContext 上：PhasePost 的阈值单元（threshold）
// 需要读取「整条链的评分总量」，而它拿到的只有 RequestContext。
// 约定：插件只负责填写 Result.Score，不要自行调用 RequestContext.AddScore，
// 否则同一次命中会被计入两次。
func mergeResult(rctx *core.RequestContext, merged, src *core.Result) {
	if src == nil {
		return
	}

	merged.Score += src.Score
	if src.Score != 0 {
		rctx.AddScore(src.Score)
	}
	if len(src.Findings) > 0 {
		merged.Findings = append(merged.Findings, src.Findings...)
	}
	if len(src.Bans) > 0 {
		merged.Bans = append(merged.Bans, src.Bans...)
	}
	if len(src.Alerts) > 0 {
		merged.Alerts = append(merged.Alerts, src.Alerts...)
	}

	// 保留首个运行期错误：访问日志据此把「失败开放 / 失败关闭」的请求与正常请求区分开，
	// 只记第一个即可，避免同一条访问日志被多个错误堆满。
	if merged.Err == nil && src.Err != nil {
		merged.Err = src.Err
	}

	// 「若拦截」标记（需求 P1-6）：任一单元判定「本应拦截」即为真。
	// 之所以用「或」而不是「首个」：同一个请求可能被多个实例同时判定为本应拦截，
	// 只要有一个成立，试运行报告就应该把它计为一次「若拦截」。
	// 原因文本保留第一条，避免日志被多条原因撑大。
	if src.WouldBlock && !merged.WouldBlock {
		merged.WouldBlock = true
		merged.WouldBlockReason = src.WouldBlockReason
	}

	if src.Verdict == core.VerdictContinue {
		return
	}
	if merged.Verdict == core.VerdictContinue || merged.Verdict == core.VerdictObserve {
		merged.Verdict = src.Verdict
		merged.Code = src.Code
		merged.Message = src.Message
		merged.RetryAfter = src.RetryAfter
		merged.Check = src.Check
	}
}

// firstRuleID 返回结论中首个命中的规则标识；无命中时返回空串。
func firstRuleID(result *core.Result) string {
	if result == nil || len(result.Findings) == 0 {
		return ""
	}
	return result.Findings[0].RuleID
}
