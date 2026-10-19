package pipeline

import (
	"context"
	"fmt"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/netx"
)

// DefaultPipelineName 是默认校验链的保留名。
const DefaultPipelineName = "default"

// RouterConfig 是站点级校验链与站点访问策略的装配参数。
type RouterConfig struct {
	// Default 是顶层 pipeline 的实例声明。
	Default []core.InstanceConfig
	// Named 是 pipelines[] 声明的具名校验链。
	Named []config.PipelineConfig
	// Body 是请求体通道配置。
	Body config.BodyConfig
}

// sitePolicy 是站点级 IP 访问策略。
type sitePolicy struct {
	allow  *netx.Set
	block  *netx.Set
	action string
	score  int
}

// Router 按请求命中的站点选择校验链，并执行站点级 IP 黑白名单。
//
// 设计取舍：
//   - 默认链保持原有行为，未显式配置 sites[].pipeline 时完全等价于旧版本；
//   - 具名链在装配期一次性构建，请求期只做一次 map 查找；
//   - 站点名单命中发生在校验链之前，白名单直接放行，黑名单按动作拦截或观察。
type Router struct {
	defaultPipeline *Pipeline
	pipelines       map[string]*Pipeline
	bySite          map[string]*Pipeline
	policies        map[string]*sitePolicy
	ordered         []*Pipeline
}

// NewRouter 构建站点级校验链路由器。
func NewRouter(cfg RouterConfig, deps *core.Deps) (*Router, error) {
	if deps == nil {
		deps = &core.Deps{}
	}

	router := &Router{
		pipelines: make(map[string]*Pipeline, len(cfg.Named)),
		bySite:    make(map[string]*Pipeline, len(deps.Sites)),
		policies:  make(map[string]*sitePolicy, len(deps.Sites)),
	}

	defaultPipeline, err := New(Config{Instances: cfg.Default, Body: cfg.Body}, deps)
	if err != nil {
		return nil, fmt.Errorf("装配默认校验链失败：%w", err)
	}
	router.defaultPipeline = defaultPipeline
	router.pipelines[DefaultPipelineName] = defaultPipeline
	router.ordered = append(router.ordered, defaultPipeline)

	for _, declared := range cfg.Named {
		name := declared.Name
		if _, exists := router.pipelines[name]; exists {
			_ = router.Close()
			return nil, fmt.Errorf("具名校验链 %q 重复", name)
		}
		built, buildErr := New(Config{Instances: declared.Instances, Body: cfg.Body}, deps)
		if buildErr != nil {
			_ = router.Close()
			return nil, fmt.Errorf("装配具名校验链 %q 失败：%w", name, buildErr)
		}
		router.pipelines[name] = built
		router.ordered = append(router.ordered, built)
	}

	for _, site := range deps.Sites {
		if site == nil {
			continue
		}
		name := site.Pipeline
		if name == "" {
			name = DefaultPipelineName
		}
		selected, exists := router.pipelines[name]
		if !exists {
			_ = router.Close()
			return nil, fmt.Errorf("站点 %q 引用了不存在的校验链 %q", site.Name, name)
		}
		router.bySite[site.Name] = selected

		allow, allowErr := netx.NewSet(site.Allowlist)
		if allowErr != nil {
			_ = router.Close()
			return nil, fmt.Errorf("站点 %q 的 allowlist 非法：%w", site.Name, allowErr)
		}
		block, blockErr := netx.NewSet(site.Blocklist)
		if blockErr != nil {
			_ = router.Close()
			return nil, fmt.Errorf("站点 %q 的 blocklist 非法：%w", site.Name, blockErr)
		}
		if allow.Empty() && block.Empty() {
			continue
		}
		action := site.AccessAction
		if action == "" {
			action = "block"
		}
		router.policies[site.Name] = &sitePolicy{
			allow: allow, block: block, action: action, score: site.AccessScore,
		}
	}

	return router, nil
}

// Name 返回执行器名称。
func (r *Router) Name() string { return "pipeline-router" }

// NeedsBody 返回任一站点校验链是否需要读取请求体。
func (r *Router) NeedsBody() bool {
	for _, pipeline := range r.ordered {
		if pipeline.NeedsBody() {
			return true
		}
	}
	return false
}

// NeedsBodyFor 返回当前命中站点是否需要读取请求体（core.SiteBodyDecider 实现）。
func (r *Router) NeedsBodyFor(rctx *core.RequestContext) bool {
	if r == nil {
		return false
	}
	return r.pipelineFor(rctx).NeedsBody()
}

// Decide 执行站点访问策略与站点校验链。
func (r *Router) Decide(ctx context.Context, rctx *core.RequestContext) *core.Result {
	if rctx == nil {
		return &core.Result{Verdict: core.VerdictAllow, Check: r.Name()}
	}
	if result := r.applySitePolicy(rctx); result != nil {
		return result
	}
	return r.pipelineFor(rctx).Decide(ctx, rctx)
}

// MatchHoneypot 按命中站点的校验链重新匹配蜜罐规则。
func (r *Router) MatchHoneypot(rctx *core.RequestContext) *core.Result {
	if rctx == nil {
		return nil
	}
	return r.pipelineFor(rctx).MatchHoneypot(rctx)
}

// Close 关闭全部唯一校验链。
func (r *Router) Close() error {
	if r == nil {
		return nil
	}
	var firstErr error
	for _, pipeline := range r.ordered {
		if err := pipeline.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Entries 返回全部校验链的实例摘要。
func (r *Router) Entries() []string {
	if r == nil {
		return nil
	}
	entries := make([]string, 0, len(r.ordered))
	for _, pipeline := range r.ordered {
		entries = append(entries, pipeline.Entries()...)
	}
	return entries
}

// Names 返回已装配的校验链名（default 在前）。
func (r *Router) Names() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.pipelines))
	names = append(names, DefaultPipelineName)
	for name := range r.pipelines {
		if name != DefaultPipelineName {
			names = append(names, name)
		}
	}
	return names
}

// pipelineFor 返回请求命中的校验链。
func (r *Router) pipelineFor(rctx *core.RequestContext) *Pipeline {
	if rctx != nil && rctx.Site != nil {
		if selected, ok := r.bySite[rctx.Site.Name]; ok {
			return selected
		}
	}
	return r.defaultPipeline
}

// applySitePolicy 执行站点级 IP 黑白名单。
func (r *Router) applySitePolicy(rctx *core.RequestContext) *core.Result {
	if rctx == nil || rctx.Site == nil || rctx.Raw == nil {
		return nil
	}
	policy, exists := r.policies[rctx.Site.Name]
	if !exists || policy == nil {
		return nil
	}
	clientIP := rctx.Raw.ClientIP
	if clientIP == "" {
		return nil
	}
	if policy.allow.Contains(clientIP) {
		result := core.NewResult(r.Name(), core.VerdictAllow)
		result.Message = "来源命中站点白名单"
		return result
	}
	if !policy.block.Contains(clientIP) {
		return nil
	}

	verdict := core.VerdictBlock
	code := config.CodeBlocked
	if policy.action == "observe" {
		verdict = core.VerdictObserve
		code = ""
	}
	result := core.NewResult(r.Name(), verdict)
	result.Code = code
	finding := core.NewFinding(r.Name(), "site_blocklist", "来源命中站点黑名单",
		core.SeverityHigh, policy.score)
	finding.Data = map[string]string{
		"site":           rctx.Site.Name,
		"client_ip":      clientIP,
		"action":         policy.action,
		"ban_key_policy": "站点名单只影响当前请求，不写入内部封禁名单",
	}
	result.AddFinding(finding)
	if verdict == core.VerdictObserve {
		result.MarkWouldBlock(fmt.Sprintf("来源 %s 命中站点 %s 黑名单", clientIP, rctx.Site.Name))
	}
	return result
}
