// Package netx 提供网络地址匹配工具（IP 单地址与 CIDR 网段的统一集合）。
//
// 为什么单独成包：IP 黑白名单（ipaccess）、威胁情报（后续里程碑）以及
// 客户端 IP 推导都需要「把配置里的一串 IP / CIDR 变成可快速判断的集合」，
// 分散实现会出现「有的支持 CIDR、有的只支持单 IP」这类不一致。
package netx

import (
	"fmt"
	"net"
	"strings"
)

// Set 是 IP / CIDR 匹配集合。
//
// 设计取舍：单 IP 用哈希集合判等、CIDR 用网段遍历匹配。
// 之所以不把单 IP 展开成 /32 网段：办公网配置里单 IP 数量通常远多于网段，
// 展开会让「精确匹配」退化为线性扫描，在高频请求路径上代价明显。
type Set struct {
	// networks 是 CIDR 网段列表（按配置顺序保留，便于日志回显）。
	networks []*net.IPNet
	// ips 是规范化后的单 IP 集合。
	ips map[string]struct{}
}

// NewSet 依据配置条目构造集合。
//
// 任一条目非法都会返回错误（fail fast）：IP 名单写错会直接导致防护失效，
// 必须在启动阶段暴露，而不是在请求命中时才静默跳过。
func NewSet(entries []string) (*Set, error) {
	set := &Set{ips: make(map[string]struct{}, len(entries))}
	for _, entry := range entries {
		if err := set.Add(entry); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// Add 向集合中加入一个条目（单个 IP 或 CIDR）；空字符串会被忽略。
func (s *Set) Add(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}

	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("非法的 CIDR %q：%w", entry, err)
		}
		s.networks = append(s.networks, network)
		return nil
	}

	ip := ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("非法的 IP %q（应为 IPv4 / IPv6 字面量或 CIDR）", entry)
	}
	s.ips[ip.String()] = struct{}{}
	return nil
}

// Contains 判断给定地址是否命中集合。
//
// 入参兼容 "1.2.3.4"、"1.2.3.4:8080"、"[::1]:8080" 三种写法，
// 便于直接传入 RemoteAddr / X-Forwarded-For 中的原始片段。
func (s *Set) Contains(value string) bool {
	if s == nil || strings.TrimSpace(value) == "" {
		return false
	}

	ip := ParseIP(value)
	if ip == nil {
		return false
	}
	if _, exists := s.ips[ip.String()]; exists {
		return true
	}
	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Len 返回集合中的条目总数（单 IP + 网段），用于启动日志。
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ips) + len(s.networks)
}

// Empty 判断集合是否为空。
func (s *Set) Empty() bool { return s.Len() == 0 }

// ParseIP 解析地址文本，兼容带端口与 IPv6 方括号的写法。
func ParseIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return net.ParseIP(strings.Trim(value, "[]"))
}
