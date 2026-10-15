// 本文件实现「封禁键维度」的抽象与内置实现。
//
// 为什么需要这一层抽象（需求 R5 / R6：全部能力可配置、可替换）：
//
//	封禁维度最初只有两档硬编码取值（client_ip / client_ip+site），「维度 -> 键」的
//	构造逻辑散落在封禁管理器与运维命令里。每新增一个维度都要同时改动多处，
//	且极易出现「写入用的键」与「查询用的键」不一致，导致封禁静默失效。
//
//	现在把「维度」收敛为一等公民：
//	  - 维度不可变清单集中在 keyScopes（新增维度只需在这里加一行 + 一个分支）；
//	  - 键构造的唯一入口是 ClientIPScopeKey，运行期判定（banlist / autoban）
//	    与运维命令（waf ban add/remove）共用同一个函数，天然保持一致；
//	  - 一个部署可以同时启用多个维度（ban.ban_keys），查询时按声明顺序短路。
package ban

import (
	"fmt"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// KeyScope 是封禁键维度：决定「把谁、在什么范围内」视作同一个封禁身份。
//
// 取值复用 config 包中的常量，保证「配置校验枚举」与「运行期实现」永远同一份真源。
type KeyScope string

// 受支持的封禁键维度。
const (
	// ScopeClientIP 表示按客户端 IP 封禁（默认，最通用）。
	ScopeClientIP KeyScope = config.BanKeyClientIP
	// ScopeClientIPSite 表示按「客户端 IP + 站点」封禁（多站点互不牵连）。
	ScopeClientIPSite KeyScope = config.BanKeyClientIPSite
	// ScopeClientIPPath 表示按「客户端 IP + 请求路径」封禁。
	//
	// 使用场景：同一来源反复打同一个接口（撞库、遍历、注入探测集中在单个地址），
	// 封禁到路径粒度可以精准止损，同时避免把该来源的其他正常业务流量一起误伤。
	ScopeClientIPPath KeyScope = config.BanKeyClientIPPath
	// ScopeClientIPMethod 表示按「客户端 IP + 请求方法」封禁。
	//
	// 使用场景：只读站点上反复出现的 POST/PUT/DELETE 探测。
	ScopeClientIPMethod KeyScope = config.BanKeyClientIPMethod
)

// keyScopes 是全部受支持的维度，声明顺序即默认的查询短路顺序。
//
// 之所以把「最通用、最容易命中」的 client_ip 放在首位：
// 名单查询是每个请求都要走的路径，先命中即可提前结束查询。
var keyScopes = []KeyScope{
	ScopeClientIP,
	ScopeClientIPSite,
	ScopeClientIPPath,
	ScopeClientIPMethod,
}

// KeyScopeNames 返回全部合法维度名（按声明顺序），用于错误提示与文档。
func KeyScopeNames() []string {
	names := make([]string, 0, len(keyScopes))
	for _, scope := range keyScopes {
		names = append(names, string(scope))
	}
	return names
}

// ParseKeyScope 解析维度名：大小写与首尾空白不敏感。
//
// 空串是历史配置的合法取值（等价于默认维度 client_ip），因此解析成功返回默认维度，
// 以保证旧配置文件不需要任何修改即可升级。
func ParseKeyScope(name string) (KeyScope, bool) {
	normalized := KeyScope(strings.ToLower(strings.TrimSpace(name)))
	if normalized == "" {
		return ScopeClientIP, true
	}
	for _, scope := range keyScopes {
		if scope == normalized {
			return scope, true
		}
	}
	return "", false
}

// Valid 判断维度取值是否受支持；空串不算「显式合法取值」。
func (s KeyScope) Valid() bool {
	if strings.TrimSpace(string(s)) == "" {
		return false
	}
	_, ok := ParseKeyScope(string(s))
	return ok
}

// KeyForScope 依据维度从请求上下文构造封禁键。
//
// 返回空串表示「无法构造键」：调用方必须据此跳过封禁动作——
// 无键的封禁要么写不进去，要么会误伤一整类来源，两种后果都比不封禁更糟。
func KeyForScope(scope KeyScope, rctx *core.RequestContext) string {
	if rctx == nil || rctx.Raw == nil {
		return ""
	}
	site := ""
	if rctx.Site != nil {
		site = rctx.Site.Name
	}
	return ClientIPScopeKey(scope, rctx.Raw.ClientIP, site, rctx.Raw.Path, rctx.Raw.Method)
}

// ClientIPScopeKey 依据维度与显式字段构造封禁键。
//
// 该函数是**全部封禁键的唯一构造入口**：运行期判定（banlist / autoban）与
// 运维命令（waf ban add / remove）都必须经过它，否则会出现
// 「CLI 写进去的键、运行期查不到」这类静默失效。
//
// 键格式（必须保持稳定：跨版本兼容，且便于人工阅读与排障）：
//
//	client_ip        -> ip:1.2.3.4
//	client_ip+site   -> ip:1.2.3.4|site:shop
//	client_ip+path   -> ip:1.2.3.4|path:/api/user
//	client_ip+method -> ip:1.2.3.4|method:POST
func ClientIPScopeKey(scope KeyScope, clientIP, site, path, method string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		// 客户端 IP 是所有维度的公共前提：拿不到 IP 就无从谈起「封禁谁」。
		return ""
	}

	parsed, ok := ParseKeyScope(string(scope))
	if !ok {
		// 未知维度一律拒绝构造键：宁可查不到（放行），也不要构造出一个
		// 语义不明的键名污染名单。
		return ""
	}

	switch parsed {
	case ScopeClientIPSite:
		site = strings.TrimSpace(site)
		if site == "" {
			// 站点缺失时兜底为默认站点名：与请求上下文推导的结果保持一致，
			// 避免「同一条流量在不同路径下算出两个键」。
			site = core.DefaultSiteName
		}
		return fmt.Sprintf("ip:%s|site:%s", clientIP, site)
	case ScopeClientIPPath:
		path = strings.TrimSpace(path)
		if path == "" {
			// 路径缺失（理论上被接入层保证存在）时兜底为根路径：
			// 保持键形态始终可解释，不产生「半截键」。
			path = "/"
		}
		return fmt.Sprintf("ip:%s|path:%s", clientIP, path)
	case ScopeClientIPMethod:
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			// 方法缺失时无法构成有意义的键，直接放弃（返回空串由调用方跳过）。
			return ""
		}
		return fmt.Sprintf("ip:%s|method:%s", clientIP, method)
	default:
		return "ip:" + clientIP
	}
}
