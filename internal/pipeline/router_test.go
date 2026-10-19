package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// routerContext 构造带站点与客户端 IP 的请求上下文。
func routerContext(site *core.Site, clientIP string) *core.RequestContext {
	rctx := core.NewRequestContext("router-test", time.Now())
	rctx.Site = site
	rctx.Raw.Host = "app.example.com"
	rctx.Raw.ClientIP = clientIP
	return rctx
}

// routerDeps 构造 Router 测试所需的依赖与站点声明。
func routerDeps(sites ...*core.Site) *core.Deps {
	return &core.Deps{
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
		Sites:   sites,
	}
}

// TestRouterSelectsPipelineBySite 覆盖：不同站点命中不同校验链。
func TestRouterSelectsPipelineBySite(t *testing.T) {
	resetStubs()
	deps := routerDeps(
		&core.Site{Name: "strict", Pipeline: "strict"},
		&core.Site{Name: "loose", Pipeline: DefaultPipelineName},
	)
	router, err := NewRouter(RouterConfig{
		Default: []core.InstanceConfig{
			instance(t, "default-check", "request", 10, true, "", nil),
		},
		Named: []config.PipelineConfig{{
			Name: "strict",
			Instances: []core.InstanceConfig{
				instance(t, "strict-check", "request", 10, true, "", map[string]any{"verdict": "block"}),
			},
		}},
	}, deps)
	if err != nil {
		t.Fatalf("构建站点路由器失败：%v", err)
	}
	t.Cleanup(func() { _ = router.Close() })

	strictResult := router.Decide(context.Background(), routerContext(deps.Sites[0], "198.51.100.10"))
	if strictResult.Verdict != core.VerdictBlock {
		t.Fatalf("strict 站点应命中具名链并拦截，实际 %s", strictResult.Verdict)
	}

	looseResult := router.Decide(context.Background(), routerContext(deps.Sites[1], "198.51.100.11"))
	if looseResult.Verdict != core.VerdictAllow {
		t.Fatalf("loose 站点应使用默认链并放行，实际 %s", looseResult.Verdict)
	}
}

// TestRouterSiteAllowlistShortCircuits 覆盖：站点白名单直接放行且不执行校验链。
func TestRouterSiteAllowlistShortCircuits(t *testing.T) {
	resetStubs()
	site := &core.Site{Name: "allow", Allowlist: []string{"10.0.0.0/8"}}
	deps := routerDeps(site)
	router, err := NewRouter(RouterConfig{
		Default: []core.InstanceConfig{
			instance(t, "would-block", "request", 10, true, "", map[string]any{"verdict": "block"}),
		},
	}, deps)
	if err != nil {
		t.Fatalf("构建站点路由器失败：%v", err)
	}
	t.Cleanup(func() { _ = router.Close() })

	result := router.Decide(context.Background(), routerContext(site, "10.1.2.3"))
	if result.Verdict != core.VerdictAllow {
		t.Fatalf("白名单来源应直接放行，实际 %s", result.Verdict)
	}
	if check := findStub(t, "would-block"); check.evaluated != 0 {
		t.Fatalf("白名单放行后不应执行校验链，实际执行 %d 次", check.evaluated)
	}
}

// TestRouterSiteBlocklistActions 覆盖：站点黑名单支持 block / observe 两种动作。
func TestRouterSiteBlocklistActions(t *testing.T) {
	cases := []struct {
		name      string
		action    string
		want      core.Verdict
		wantCode  string
		wantBlock bool
	}{
		{name: "拦截", action: "block", want: core.VerdictBlock, wantCode: config.CodeBlocked},
		{name: "观察", action: "observe", want: core.VerdictObserve, wantBlock: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetStubs()
			site := &core.Site{
				Name:         "blocked",
				Blocklist:    []string{"203.0.113.0/24"},
				AccessAction: tc.action,
				AccessScore:  7,
			}
			deps := routerDeps(site)
			router, err := NewRouter(RouterConfig{}, deps)
			if err != nil {
				t.Fatalf("构建站点路由器失败：%v", err)
			}
			t.Cleanup(func() { _ = router.Close() })

			result := router.Decide(context.Background(), routerContext(site, "203.0.113.9"))
			if result.Verdict != tc.want {
				t.Fatalf("期望判定 %s，实际 %s", tc.want, result.Verdict)
			}
			if result.Code != tc.wantCode {
				t.Fatalf("期望错误码 %q，实际 %q", tc.wantCode, result.Code)
			}
			if result.Score != 7 {
				t.Fatalf("黑名单命中应累加 access_score=7，实际 %d", result.Score)
			}
			if result.WouldBlock != tc.wantBlock {
				t.Fatalf("WouldBlock 期望 %v，实际 %v", tc.wantBlock, result.WouldBlock)
			}
		})
	}
}

// TestRouterNeedsBodyForSelectedPipeline 覆盖：按命中站点决定是否读取请求体。
func TestRouterNeedsBodyForSelectedPipeline(t *testing.T) {
	resetStubs()
	bodySite := &core.Site{Name: "body", Pipeline: "body_chain"}
	headerSite := &core.Site{Name: "header", Pipeline: DefaultPipelineName}
	deps := routerDeps(bodySite, headerSite)
	router, err := NewRouter(RouterConfig{
		Body: bodyConfig(),
		Default: []core.InstanceConfig{
			instance(t, "header-check", "request", 10, true, "", nil),
		},
		Named: []config.PipelineConfig{{
			Name: "body_chain",
			Instances: []core.InstanceConfig{
				instance(t, "body-check", "body", 10, true, "", nil),
			},
		}},
	}, deps)
	if err != nil {
		t.Fatalf("构建站点路由器失败：%v", err)
	}
	t.Cleanup(func() { _ = router.Close() })

	if !router.NeedsBody() {
		t.Fatal("存在体阶段校验链时 NeedsBody 应为 true")
	}
	if !router.NeedsBodyFor(routerContext(bodySite, "198.51.100.1")) {
		t.Fatal("命中体阶段站点时 NeedsBodyFor 应为 true")
	}
	if router.NeedsBodyFor(routerContext(headerSite, "198.51.100.1")) {
		t.Fatal("命中纯请求头站点时 NeedsBodyFor 应为 false")
	}
}

// TestRouterRejectsInvalidPipelineReferences 覆盖：装配期必须拒绝重复链名与不存在的引用。
func TestRouterRejectsInvalidPipelineReferences(t *testing.T) {
	cases := []struct {
		name string
		cfg  RouterConfig
		site *core.Site
	}{
		{
			name: "链名重复",
			cfg:  RouterConfig{Named: []config.PipelineConfig{{Name: DefaultPipelineName}}},
		},
		{
			name: "引用不存在的链",
			cfg:  RouterConfig{},
			site: &core.Site{Name: "broken", Pipeline: "missing"},
		},
		{
			name: "站点名单非法",
			cfg:  RouterConfig{},
			site: &core.Site{Name: "broken", Allowlist: []string{"not-a-cidr"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := routerDeps()
			if tc.site != nil {
				deps.Sites = []*core.Site{tc.site}
			}
			if _, err := NewRouter(tc.cfg, deps); err == nil {
				t.Fatal("非法站点策略应在装配期直接失败")
			}
		})
	}
}
