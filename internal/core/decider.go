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
