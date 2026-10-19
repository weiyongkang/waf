// Package sites 实现「站点解析」：把配置里的站点声明编译成可快速匹配的站点策略表（需求 R6）。
//
// 定位：
//
//	按请求 Host 选出站点策略（core.Site），供校验单元读取站点名、引擎模式与站点级参数覆盖。
//	多站点差异化的全部配置都收敛在 sites[] 一段，校验单元无需感知站点数量与匹配规则。
//
// 匹配优先级（从高到低）：
//
//  1. 精确 Host 匹配（含端口会被规范化掉，例如 app.example.com:8080 -> app.example.com）；
//  2. 通配后缀匹配（*.example.com），多个通配命中时取**后缀最长**者
//     （*.api.example.com 优先于 *.example.com，符合「越具体越优先」的直觉）；
//  3. 通配全部（"*"）的站点；
//  4. 内置默认站点（配置未声明任何站点时自动生成，保证 Resolve 永不返回 nil）。
//
// 为什么不使用正则或 glob：站点匹配在每个请求上都会执行，精确匹配必须是 O(1)；
// 通配只允许「*.前缀」一种形态（足够覆盖多子域场景），既避免正则注入风险，
// 也让匹配代价始终是「通配条目数」量级（生产配置中通常只有个位数）。
package sites

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/netx"
)

// catchAll 是匹配全部 Host 的通配模式。
const catchAll = "*"

// wildcardPrefix 是通配模式的前缀（形如 *.example.com）。
const wildcardPrefix = "*."

// Resolver 是 core.SiteResolver 的实现。
type Resolver struct {
	// sites 是全部站点策略（保持声明顺序，含默认站点），用于日志与配置摘要。
	sites []*core.Site
	// exact 是「精确 Host -> 站点」索引。
	exact map[string]*core.Site
	// wildcards 是通配后缀条目，按后缀长度降序排列，保证「越具体越优先」。
	wildcards []wildcardRule
	// fallback 是通配全部（"*"）的站点；为 nil 时使用 defaultSite。
	fallback *core.Site
	// defaultSite 是内置默认站点，永不为 nil，作为最终兜底。
	defaultSite *core.Site
}

// wildcardRule 是一条通配后缀规则。
type wildcardRule struct {
	// suffix 是包含前导点的后缀，例如 ".example.com"。
	//
	// 之所以保留前导点：匹配时按「标签边界」比较，避免 aexample.com 误命中 *.example.com。
	suffix string
	// site 是命中的站点策略。
	site *core.Site
}

// Options 是站点解析器的构造参数。
type Options struct {
	// Declared 是配置文件的 sites 数组。
	Declared []config.SiteConfig
}

// New 依据配置构建站点解析器。
//
// 校验规则（全部在启动阶段 fail fast）：
//   - 站点名非空且唯一；
//   - 每个站点至少声明一个 host 模式；
//   - 通配模式只允许 "*" 与 "*.后缀" 两种形态，且 "*" 至多出现一次；
//   - 精确模式不允许出现非法字符（点分标签、字母数字与连字符）。
func New(opts Options) (*Resolver, error) {
	resolver := &Resolver{
		exact: make(map[string]*core.Site, len(opts.Declared)),
		defaultSite: &core.Site{
			Name:         core.DefaultSiteName,
			Hosts:        []string{catchAll},
			EngineMode:   config.EngineModeInherit,
			Pipeline:     "default",
			AccessAction: "block",
		},
	}

	names := make(map[string]struct{}, len(opts.Declared)+1)
	var catchAllSites []*core.Site

	for index, declared := range opts.Declared {
		name := strings.TrimSpace(declared.Name)
		if name == "" {
			return nil, fmt.Errorf("sites[%d].name 不能为空", index)
		}
		if _, exists := names[name]; exists {
			return nil, fmt.Errorf("站点名 %q 重复，必须唯一", name)
		}
		names[name] = struct{}{}

		if len(declared.Hosts) == 0 {
			return nil, fmt.Errorf("站点 %q 必须至少声明一个 hosts 匹配模式", name)
		}

		site := &core.Site{
			Name:         name,
			Hosts:        append([]string(nil), declared.Hosts...),
			EngineMode:   declared.EngineMode,
			Pipeline:     declared.Pipeline,
			Allowlist:    append([]string(nil), declared.Allowlist...),
			Blocklist:    append([]string(nil), declared.Blocklist...),
			AccessAction: declared.AccessAction,
			AccessScore:  declared.AccessScore,
			Params:       declared.Params,
		}
		if site.EngineMode == "" {
			site.EngineMode = config.EngineModeInherit
		}
		if site.Pipeline == "" {
			site.Pipeline = "default"
		}
		if site.AccessAction == "" {
			site.AccessAction = "block"
		}
		// 名单在站点装配阶段解析一次，非法条目必须 fail fast；运行期由
		// pipeline.Router 持有解析后的集合，避免每个请求重复解析。
		if _, err := netx.NewSet(site.Allowlist); err != nil {
			return nil, fmt.Errorf("站点 %q 的 allowlist 非法：%w", name, err)
		}
		if _, err := netx.NewSet(site.Blocklist); err != nil {
			return nil, fmt.Errorf("站点 %q 的 blocklist 非法：%w", name, err)
		}
		if site.AccessAction != "block" && site.AccessAction != "observe" {
			return nil, fmt.Errorf("站点 %q 的 access_action = %q 非法，可选值：block / observe", name, site.AccessAction)
		}

		// 站点内部的模式之间也按「精确优先、通配次之」登记，
		// 但同一条声明里同时出现 "*" 与精确模式属于明显的配置笔误，直接报错。
		hasCatchAll := false
		for _, pattern := range declared.Hosts {
			normalized, err := normalizePattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("站点 %q 的 host 模式非法：%w", name, err)
			}
			if normalized == catchAll {
				hasCatchAll = true
				continue
			}
			if strings.HasPrefix(normalized, wildcardPrefix) {
				resolver.wildcards = append(resolver.wildcards, wildcardRule{
					suffix: normalized[len(wildcardPrefix)-1:], // 保留前导点
					site:   site,
				})
				continue
			}
			// 精确模式：同名的精确模式后声明者覆盖先声明者（与配置文件「后者覆盖前者」一致），
			// 但不同站点声明同一个 Host 属于配置冲突，必须报错。
			if existing, exists := resolver.exact[normalized]; exists && existing.Name != name {
				return nil, fmt.Errorf("host %q 同时被站点 %q 与 %q 声明，请改为通配或删除其一",
					normalized, existing.Name, name)
			}
			resolver.exact[normalized] = site
		}

		if hasCatchAll {
			if len(declared.Hosts) > 1 {
				return nil, fmt.Errorf("站点 %q 同时声明了 \"*\" 与其它 host 模式：\"*\" 已覆盖全部 Host，属于配置冗余",
					name)
			}
			catchAllSites = append(catchAllSites, site)
		}

		resolver.sites = append(resolver.sites, site)
	}

	if len(catchAllSites) > 1 {
		return nil, fmt.Errorf("最多只能有一个站点声明 hosts: [\"*\"]，当前有 %d 个", len(catchAllSites))
	}
	if len(catchAllSites) == 1 {
		resolver.fallback = catchAllSites[0]
	}

	// 通配后缀按长度降序：越具体（后缀越长）的规则先匹配。
	sort.SliceStable(resolver.wildcards, func(i, j int) bool {
		return len(resolver.wildcards[i].suffix) > len(resolver.wildcards[j].suffix)
	})

	// 保证站点列表里始终存在一个默认站点：没有任何站点声明 "*" 时补一个内置默认站点，
	// 使「未命中任何站点的 Host」也有确定的策略归属（日志 / 指标 / 封禁键都需要站点名）。
	if resolver.fallback == nil {
		resolver.fallback = resolver.defaultSite
		resolver.sites = append(resolver.sites, resolver.defaultSite)
	}

	return resolver, nil
}

// Resolve 返回给定 Host 命中的站点策略（core.SiteResolver 实现）。
//
// 该实现永不返回 nil：未命中任何站点时返回通配站点或内置默认站点。
func (r *Resolver) Resolve(host string) *core.Site {
	if r == nil {
		return &core.Site{Name: core.DefaultSiteName, Hosts: []string{catchAll}}
	}

	normalized := normalizeHost(host)
	if normalized != "" {
		if site, exists := r.exact[normalized]; exists {
			return site
		}
		for _, rule := range r.wildcards {
			// 按标签边界比较：host 必须比后缀多出至少一个字符，
			// 从而 a.example.com 命中 .example.com，而 example.com 本身不命中。
			if len(normalized) > len(rule.suffix) && strings.HasSuffix(normalized, rule.suffix) {
				return rule.site
			}
		}
	}

	if r.fallback != nil {
		return r.fallback
	}
	return r.defaultSite
}

// Sites 返回全部站点策略（core.SiteResolver 实现）。
func (r *Resolver) Sites() []*core.Site {
	if r == nil {
		return nil
	}
	return append([]*core.Site(nil), r.sites...)
}

// Names 返回全部站点名（含默认站点），顺序与声明顺序一致。
func (r *Resolver) Names() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.sites))
	for _, site := range r.sites {
		names = append(names, site.Name)
	}
	return names
}

// normalizeHost 规范化请求 Host：去掉端口、转小写、去掉结尾的点。
//
// 之所以需要规范化：代理注入的 Host 可能带端口（app.example.com:8443）、
// 大小写不一致（App.Example.COM）或带根域结尾点（app.example.com.），
// 这三种写法在 DNS 语义上等价，若不规范化会导致站点匹配失败。
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

// normalizePattern 规范化配置中的 host 模式，并校验其形态。
func normalizePattern(pattern string) (string, error) {
	normalized := normalizeHost(pattern)
	if normalized == "" {
		return "", fmt.Errorf("模式不能为空")
	}
	if normalized == catchAll {
		return catchAll, nil
	}
	if strings.HasPrefix(normalized, "*") && !strings.HasPrefix(normalized, wildcardPrefix) {
		return "", fmt.Errorf("通配模式只支持 \"*.后缀\" 形态（当前 %q），不支持前缀通配或通配中间段", pattern)
	}

	// 去掉通配前缀后按域名标签校验，避免出现 "*.example..com" / "*.-bad.com" 这类无效模式。
	check := strings.TrimPrefix(normalized, wildcardPrefix)
	for _, label := range strings.Split(check, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("主机名标签 %q 非法（只允许字母、数字与连字符，且不能以连字符开头或结尾）", label)
		}
	}
	return normalized, nil
}

// validLabel 判断单个域名标签是否合法。
func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case char == '-':
		default:
			return false
		}
	}
	return true
}
