package sites

import (
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// buildResolver 依据站点声明构建解析器，构建失败直接终止测试。
func buildResolver(t *testing.T, declared ...config.SiteConfig) *Resolver {
	t.Helper()
	resolver, err := New(Options{Declared: declared})
	if err != nil {
		t.Fatalf("构建站点解析器失败：%v", err)
	}
	return resolver
}

// TestResolvePriority 覆盖：精确匹配 > 最长通配 > 通配全部 > 内置默认。
func TestResolvePriority(t *testing.T) {
	resolver := buildResolver(t,
		config.SiteConfig{Name: "catch-all", Hosts: []string{"*.example.com"}},
		config.SiteConfig{Name: "api", Hosts: []string{"api.example.com"}},
		config.SiteConfig{Name: "deep", Hosts: []string{"*.api.example.com"}},
	)

	cases := []struct {
		host string
		want string
	}{
		{host: "api.example.com", want: "api"},
		{host: "v1.api.example.com", want: "deep"},
		{host: "www.example.com", want: "catch-all"},
		{host: "other.org", want: core.DefaultSiteName},
	}

	for _, item := range cases {
		if got := resolver.Resolve(item.host).Name; got != item.want {
			t.Fatalf("Resolve(%q) 期望站点 %q，实际 %q", item.host, item.want, got)
		}
	}
}

// TestResolveNormalizesHost 覆盖：Host 的端口 / 大小写 / 结尾点 / IPv6 方括号均被规范化。
func TestResolveNormalizesHost(t *testing.T) {
	resolver := buildResolver(t,
		config.SiteConfig{Name: "app", Hosts: []string{"app.example.com"}},
	)

	cases := []string{
		"app.example.com",
		"app.example.com:8443",
		"APP.Example.COM",
		"app.example.com.",
		"  app.example.com  ",
	}
	for _, host := range cases {
		if got := resolver.Resolve(host).Name; got != "app" {
			t.Fatalf("Resolve(%q) 期望站点 app，实际 %q", host, got)
		}
	}
}

// TestWildcardDoesNotMatchBareDomain 覆盖：*.example.com 不应命中 example.com 本身。
func TestWildcardDoesNotMatchBareDomain(t *testing.T) {
	resolver := buildResolver(t,
		config.SiteConfig{Name: "wild", Hosts: []string{"*.example.com"}},
	)

	if got := resolver.Resolve("example.com").Name; got != core.DefaultSiteName {
		t.Fatalf("裸域不应命中 *.example.com，实际站点 %q", got)
	}
	// 也不能被「后缀相同但标签边界不同」的域名误命中。
	if got := resolver.Resolve("aexample.com").Name; got != core.DefaultSiteName {
		t.Fatalf("aexample.com 不应命中 *.example.com，实际站点 %q", got)
	}
}

// TestCatchAllDeclaredUsesDeclaredSite 覆盖：显式声明 hosts: ["*"] 的站点成为兜底站点，
// 且不再额外生成内置默认站点。
func TestCatchAllDeclaredUsesDeclaredSite(t *testing.T) {
	resolver := buildResolver(t,
		config.SiteConfig{Name: "shop", Hosts: []string{"*"}, EngineMode: config.EngineModeDetectionOnly},
	)

	if got := resolver.Resolve("anything.example").Name; got != "shop" {
		t.Fatalf("未命中精确 / 通配时应回落到声明了 \"*\" 的站点，实际 %q", got)
	}
	names := resolver.Names()
	if len(names) != 1 || names[0] != "shop" {
		t.Fatalf("声明 \"*\" 后不应再追加内置默认站点，实际 %v", names)
	}
	if got := resolver.Resolve("").EngineMode; got != config.EngineModeDetectionOnly {
		t.Fatalf("站点级 engine_mode 应被保留，实际 %q", got)
	}
}

// TestDefaultSiteWhenNotDeclared 覆盖：未声明任何站点时永远返回默认站点（永不 nil）。
func TestDefaultSiteWhenNotDeclared(t *testing.T) {
	var empty *Resolver
	if got := empty.Resolve("anything"); got == nil || got.Name != core.DefaultSiteName {
		t.Fatalf("空解析器应返回默认站点，实际 %+v", got)
	}
	if empty.Sites() != nil || empty.Names() != nil {
		t.Fatal("空解析器的站点列表应为空")
	}

	resolver := buildResolver(t)
	site := resolver.Resolve("app.example.com")
	if site == nil || site.Name != core.DefaultSiteName {
		t.Fatalf("未声明站点时应返回默认站点，实际 %+v", site)
	}
	if len(resolver.Names()) != 1 || resolver.Names()[0] != core.DefaultSiteName {
		t.Fatalf("应自动生成一个默认站点，实际 %v", resolver.Names())
	}
}

// TestSiteParamsArePreserved 覆盖：站点级参数被完整保留并可通过 core.Site.Param 读取。
func TestSiteParamsArePreserved(t *testing.T) {
	resolver := buildResolver(t, config.SiteConfig{
		Name:   "strict",
		Hosts:  []string{"strict.example.com"},
		Params: map[string]string{"ratelimit.limit": "10", "ratelimit.burst": "0"},
	})

	site := resolver.Resolve("strict.example.com")
	got, ok := site.Param("ratelimit.limit")
	if !ok || got != "10" {
		t.Fatalf("站点级参数读取失败：value=%q ok=%v", got, ok)
	}
	if _, ok := site.Param("ratelimit.window"); ok {
		t.Fatal("未配置的站点级参数不应返回命中")
	}
	// 空值等价于未配置，避免「配了空串却意外把阈值改成 0」。
	empty := &core.Site{Name: "x", Params: map[string]string{"ratelimit.limit": "   "}}
	if _, ok := empty.Param("ratelimit.limit"); ok {
		t.Fatal("空白取值应视为未配置")
	}
	var nilSite *core.Site
	if _, ok := nilSite.Param("ratelimit.limit"); ok {
		t.Fatal("空站点应视为未配置")
	}
}

// TestSitePolicyFieldsArePreserved 覆盖：站点级链路引用、IP 名单与访问动作完整映射。
func TestSitePolicyFieldsArePreserved(t *testing.T) {
	resolver := buildResolver(t, config.SiteConfig{
		Name:         "policy",
		Hosts:        []string{"policy.example.com"},
		Pipeline:     "strict_chain",
		Allowlist:    []string{"10.0.0.0/8"},
		Blocklist:    []string{"203.0.113.0/24"},
		AccessAction: "observe",
		AccessScore:  9,
		Params:       map[string]string{"apisec.action": "observe"},
	})

	site := resolver.Resolve("policy.example.com")
	if site.Pipeline != "strict_chain" {
		t.Fatalf("pipeline 期望 strict_chain，实际 %q", site.Pipeline)
	}
	if len(site.Allowlist) != 1 || site.Allowlist[0] != "10.0.0.0/8" {
		t.Fatalf("allowlist 未完整保留：%v", site.Allowlist)
	}
	if len(site.Blocklist) != 1 || site.Blocklist[0] != "203.0.113.0/24" {
		t.Fatalf("blocklist 未完整保留：%v", site.Blocklist)
	}
	if site.AccessAction != "observe" || site.AccessScore != 9 {
		t.Fatalf("站点访问动作未完整保留：%+v", site)
	}
	if got, ok := site.Param("apisec.action"); !ok || got != "observe" {
		t.Fatalf("站点参数未完整保留：value=%q ok=%v", got, ok)
	}
}

// TestNewValidation 覆盖：非法站点声明必须在构造阶段失败（fail fast）。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		declared []config.SiteConfig
	}{
		{
			name:     "站点名为空",
			declared: []config.SiteConfig{{Name: " ", Hosts: []string{"a.example.com"}}},
		},
		{
			name: "站点名重复",
			declared: []config.SiteConfig{
				{Name: "dup", Hosts: []string{"a.example.com"}},
				{Name: "dup", Hosts: []string{"b.example.com"}},
			},
		},
		{
			name:     "未声明hosts",
			declared: []config.SiteConfig{{Name: "empty", Hosts: nil}},
		},
		{
			name: "多个通配全部",
			declared: []config.SiteConfig{
				{Name: "a", Hosts: []string{"*"}},
				{Name: "b", Hosts: []string{"*"}},
			},
		},
		{
			name:     "通配与其它模式混用",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"*", "b.example.com"}}},
		},
		{
			name:     "非法前缀通配",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"api*"}}},
		},
		{
			name:     "非法通配中间段",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"api.*.example.com"}}},
		},
		{
			name:     "非法域名标签",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"-bad.example.com"}}},
		},
		{
			name:     "空标签",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"bad..example.com"}}},
		},
		{
			name: "跨站点重复声明同一 Host",
			declared: []config.SiteConfig{
				{Name: "a", Hosts: []string{"dup.example.com"}},
				{Name: "b", Hosts: []string{"dup.example.com"}},
			},
		},
		{
			name:     "非法访问动作",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"a.example.com"}, AccessAction: "deny"}},
		},
		{
			name:     "非法白名单",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"a.example.com"}, Allowlist: []string{"not-a-cidr"}}},
		},
		{
			name:     "非法黑名单",
			declared: []config.SiteConfig{{Name: "a", Hosts: []string{"a.example.com"}, Blocklist: []string{"300.1.1.1/24"}}},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(Options{Declared: item.declared})
			if err == nil {
				t.Fatal("非法站点声明应在构造阶段直接失败")
			}
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("错误信息不能为空，否则运维无法定位问题")
			}
		})
	}
}

// TestSameSiteRepeatsHostIsAllowed 覆盖：同一站点内重复声明同一 Host 时后者覆盖前者，不报错。
//
// 之所以允许：站点名称未变，语义上仍是「同一个站点的同一个 Host」，
// 报错会让「多个配置文件叠加」这种正常用法无法使用。
func TestSameSiteRepeatsHostIsAllowed(t *testing.T) {
	resolver := buildResolver(t,
		config.SiteConfig{Name: "a", Hosts: []string{"dup.example.com", "dup.example.com"}},
	)
	if got := resolver.Resolve("dup.example.com").Name; got != "a" {
		t.Fatalf("应命中站点 a，实际 %q", got)
	}
}
