package core

import "strings"

// DefaultSiteName 是默认站点名。
//
// 之所以集中定义：默认站点名会出现在日志、指标标签、封禁键（client_ip+site）与
// 站点配置的默认值中；多处各写字符串字面量会出现「看起来一样但实际不一致」的问题。
const DefaultSiteName = "default"

// Site 是站点策略，用于多站点差异化。
//
// 当前阶段仅支持单站点（默认站点匹配所有 Host），但结构先行落地，
// 后续阶段新增站点只需补充配置，不需要改动任何校验单元。
type Site struct {
	// Name 是站点名，出现在日志与指标标签中。
	Name string
	// Hosts 是站点匹配的 Host 模式列表，支持通配符（例如 *.example.com）。
	Hosts []string
	// EngineMode 是引擎模式覆盖：inherit 表示继承全局 engine.mode。
	EngineMode string
	// Pipeline 是站点引用的具名校验链名；空值或 default 表示全局 pipeline。
	Pipeline string
	// Allowlist / Blocklist 是站点级 IP / CIDR 名单。
	Allowlist []string
	Blocklist []string
	// AccessAction 是 Blocklist 命中后的动作：block / observe。
	AccessAction string
	// AccessScore 是 Blocklist 命中时累加的异常评分。
	AccessScore int
	// Params 是站点级参数覆盖（例如更严格的限速阈值），键为参数名。
	Params map[string]string
}

// Matches 判断给定 Host 是否命中该站点。
//
// 当前实现支持两种模式：精确匹配与以 "*." 开头的后缀通配。
// 通配匹配按「点分标签」比较，避免 aexample.com 误命中 *.example.com。
func (s *Site) Matches(host string) bool {
	for _, pattern := range s.Hosts {
		if pattern == "*" || pattern == host {
			return true
		}
		if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
			suffix := pattern[1:] // 保留前导点，保证按标签边界匹配
			if len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}

// Param 读取站点级参数覆盖；不存在时返回 ("", false)。
//
// 参数键的命名约定：`<插件类型>.<参数名>`，例如 `ratelimit.limit`。
// 之所以用「插件类型.参数名」而不是嵌套结构：站点级覆盖是一个扁平的小集合，
// 扁平键既便于配置文件书写，也让插件只需知道自己的类型名即可读取
// （插件无需感知该键属于哪个实例——站点级覆盖对所有同类型实例生效）。
//
// 插件的解析顺序约定（config 中记为「实例 settings -> 站点 params -> 内置默认」）：
// 站点级覆盖只在显式配置时生效，缺省时不影响实例级配置，避免出现
// 「改了站点参数却意外改变了未配置该参数的实例」。
func (s *Site) Param(key string) (string, bool) {
	if s == nil || len(s.Params) == 0 {
		return "", false
	}
	value, exists := s.Params[key]
	if !exists {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

// SiteResolver 依据请求 Host 解析命中的站点策略（需求 R6：站点差异化）。
//
// 之所以定义为接口：站点匹配策略未来可能扩展（例如按路径前缀、按 Header、
// 按灰度比例分站点），server 与校验单元只依赖该接口，替换实现无需改动它们。
//
// 实现约束：Resolve 必须并发安全，且**永不返回 nil**——
// 未命中任何站点时必须回落到默认站点，否则下游（日志、指标、封禁键）都要做 nil 判断。
type SiteResolver interface {
	// Resolve 返回给定 Host 命中的站点策略；未命中时返回默认站点。
	Resolve(host string) *Site
	// Sites 返回全部站点策略（含默认站点），顺序稳定，供启动日志与配置摘要使用。
	Sites() []*Site
}
