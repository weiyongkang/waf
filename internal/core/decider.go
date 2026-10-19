package core

import "context"

// Decider 是「校验链执行器」的抽象。
//
// 之所以把它抽成接口而不是让 HTTP 层直接依赖 pipeline 包：
//   - server 包只需要「给我一个结论」，不关心链如何排序、如何短路、如何读体；
//   - 单元测试与冒烟测试可以注入 AllowAllDecider，无需装配任何插件；
//   - 后续阶段的站点级校验链、灰度策略都可以通过替换实现来完成。
type Decider interface {
	// Decide 执行校验链并返回最终结论。
	//
	// 返回的 Result 永不为 nil；当链为空或全部单元均无结论时返回放行结论。
	Decide(ctx context.Context, rctx *RequestContext) *Result

	// NeedsBody 报告当前校验链中是否存在启用的 PhaseBody 校验单元。
	//
	// 该方法是「按需读体」的判定依据：返回 false 时 pipeline 完全不读取请求体，
	// 连缓冲都不创建（设计文档 §7.4 第 3 条）。
	NeedsBody() bool

	// Name 返回执行器名称，用于启动日志与指标标签。
	Name() string
}

// SiteBodyDecider 是可选接口：站点级校验链可能在某个站点需要读体、另一个站点不需要。
//
// 未实现该接口时，HTTP 层回退到 Decider.NeedsBody 的全局判断，保持兼容。
type SiteBodyDecider interface {
	// NeedsBodyFor 报告命中站点的校验链是否需要读取请求体。
	NeedsBodyFor(rctx *RequestContext) bool
}

// HoneypotMatcher 是可选接口：由校验链实现，供 /waf/deny 渲染端点
// 在不重复执行整条校验链的前提下，按原始请求重新匹配蜜罐规则。
//
// 之所以放在 core 而不是让 server 直接依赖 honeypot 包：
//   - server 只依赖抽象，不关心规则加载与匹配细节；
//   - 其它入口（例如后续的管理面预览）可以复用同一匹配能力；
//   - 未装配蜜罐时，类型断言失败即可安全降级为普通 JSON 错误体。
type HoneypotMatcher interface {
	// MatchHoneypot 返回首条命中的蜜罐规则响应；未命中返回 nil。
	//
	// 实现不得产生告警、评分或封禁等副作用：命中事件已在 /waf/auth 阶段记录，
	// 渲染阶段只负责重新生成响应，避免同一次请求被重复计数。
	MatchHoneypot(rctx *RequestContext) *Result
}

// AllowAllDecider 是「纯放行」执行器，用于空校验链、冒烟测试与健康检查。
type AllowAllDecider struct{}

// Decide 始终返回放行结论。
func (AllowAllDecider) Decide(context.Context, *RequestContext) *Result {
	return &Result{Verdict: VerdictAllow, Check: "allow-all"}
}

// NeedsBody 返回 false：纯放行执行器不需要请求体。
func (AllowAllDecider) NeedsBody() bool { return false }

// Name 返回执行器名称。
func (AllowAllDecider) Name() string { return "allow-all" }
