package config

import "strings"

// JoinBasePath 把统一前缀与端点路径拼接为最终生效路径。
//
// 规则：
//   - base 为空或 "/" 时原样返回 path；
//   - base 末尾的 "/" 会被去掉；
//   - path 已经以 base 为前缀时不会重复拼接，兼容旧配置中的 "/waf/auth"；
//   - path 为空时返回规范化的 base，便于调用方处理根路径。
func JoinBasePath(base, path string) string {
	base = strings.TrimSpace(base)
	path = strings.TrimSpace(path)

	if base == "" || base == "/" {
		return path
	}
	base = strings.TrimRight(base, "/")
	if base == "" {
		return path
	}
	if path == "" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == base || strings.HasPrefix(path, base+"/") {
		return path
	}
	return base + path
}
