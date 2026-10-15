package forwardauth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ClientIPResolver 依据可信代理列表推导真实客户端 IP。
//
// 安全模型（验收项 A10）：只有当直连来源（TCP 对端）落在 trusted_proxies 内时，
// 才信任其携带的转发头。否则一律使用 TCP 对端地址。
// 这样可以防止客户端直接伪造 X-Forwarded-For 绕过 IP 黑名单、限速与封禁。
type ClientIPResolver struct {
	// order 是转发头候选顺序（规范化为 http.Header 使用的大小写不敏感键名）。
	order []string
	// trusted 是可信代理网段。
	trusted []*net.IPNet
	// trustedRaw 保留原始文本，用于错误信息与日志。
	trustedRaw []string
}

// NewClientIPResolver 构造客户端 IP 推导器。
//
// order 为空时回退为 ["X-Forwarded-For", "X-Real-IP"]；
// trustedProxies 为空表示「不信任任何转发头」，此时一律使用 TCP 对端地址。
func NewClientIPResolver(order, trustedProxies []string) (*ClientIPResolver, error) {
	if len(order) == 0 {
		order = []string{"X-Forwarded-For", "X-Real-IP"}
	}

	trusted := make([]*net.IPNet, 0, len(trustedProxies))
	trustedRaw := make([]string, 0, len(trustedProxies))
	for _, entry := range trustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// 支持写法：单个 IP（自动按 /32 或 /128 处理）与 CIDR。
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("ingress.client_ip.trusted_proxies 中的 %q 不是合法 IP 或 CIDR", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			trusted = append(trusted, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			trustedRaw = append(trustedRaw, entry)
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("ingress.client_ip.trusted_proxies 中的 %q 不是合法 CIDR：%w", entry, err)
		}
		trusted = append(trusted, network)
		trustedRaw = append(trustedRaw, entry)
	}

	return &ClientIPResolver{order: order, trusted: trusted, trustedRaw: trustedRaw}, nil
}

// TrustedProxies 返回可信代理网段的原始文本列表，用于启动日志。
func (r *ClientIPResolver) TrustedProxies() []string {
	return append([]string(nil), r.trustedRaw...)
}

// Resolve 推导真实客户端 IP。
//
// 返回值：
//   - ip：最终采用的客户端 IP；
//   - chain：解析出的转发链（从左到右，可能为空），仅用于日志；
//   - trustedPeer：TCP 对端是否为可信代理。
//
// 之所以返回转发链：当出现「限速误伤 NAT 出口」这类问题时，运维需要看到完整链路才能定位。
func (r *ClientIPResolver) Resolve(peerAddr string, header http.Header) (ip string, chain []string, trustedPeer bool) {
	peerIP := parseIPFromAddr(peerAddr)
	if peerIP == nil {
		// 无法解析对端地址时不做任何信任推断，直接返回原始字符串。
		return peerAddr, nil, false
	}

	if !r.isTrusted(peerIP) {
		// 对端不可信：完全忽略转发头，避免被伪造。
		return peerIP.String(), nil, false
	}

	for _, name := range r.order {
		values := header.Values(name)
		if len(values) == 0 {
			continue
		}

		// X-Forwarded-For 语义：逗号分隔的链路，最右侧由最近的代理追加。
		if strings.EqualFold(name, "X-Forwarded-For") {
			chain = splitXForwardedFor(values)
			if len(chain) == 0 {
				continue
			}
			return r.pickFromChain(chain), chain, true
		}

		// 其它头（例如 X-Real-IP）只承载单个地址。
		for _, value := range values {
			candidate := parseIPString(value)
			if candidate == nil {
				continue
			}
			// 单值头若指向可信网段，说明它记录的是另一层代理，跳过并继续看下一个候选头。
			if r.isTrusted(candidate) {
				continue
			}
			return candidate.String(), []string{candidate.String()}, true
		}
	}

	// 没有任何可用转发头：使用可信对端自身地址（例如代理与 WAF 同机部署的场景）。
	return peerIP.String(), nil, true
}

// pickFromChain 从转发链中按「从右往左取第一个非可信地址」的规则选出客户端 IP。
//
// 之所以从右往左：链的右端由最近的代理追加，可信度最高；
// 越往左越可能是客户端自行伪造的内容，因此必须在遇到第一个不可信地址时停止。
func (r *ClientIPResolver) pickFromChain(chain []string) string {
	for index := len(chain) - 1; index >= 0; index-- {
		candidate := parseIPString(chain[index])
		if candidate == nil {
			// 非法项（例如 "unknown"）直接跳过，继续向左寻找。
			continue
		}
		if r.isTrusted(candidate) {
			continue
		}
		return candidate.String()
	}
	// 整条链都可信或都非法：退化为最左端（最接近客户端的记录）。
	for _, item := range chain {
		if candidate := parseIPString(item); candidate != nil {
			return candidate.String()
		}
	}
	return ""
}

// isTrusted 判断 IP 是否落在可信代理网段内。
func (r *ClientIPResolver) isTrusted(ip net.IP) bool {
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// splitXForwardedFor 把 X-Forwarded-For 的多个头值展开为有序地址列表。
//
// 之所以要展开多个头值：标准允许同一个头出现多次，等价于按出现顺序拼接。
func splitXForwardedFor(values []string) []string {
	var chain []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				chain = append(chain, item)
			}
		}
	}
	return chain
}

// parseIPFromAddr 从 "IP:PORT" 形式中解析出 IP。
func parseIPFromAddr(addr string) net.IP {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return parseIPString(host)
	}
	// 没有端口（或 IPv6 裸地址）时按整体解析。
	return parseIPString(strings.Trim(addr, "[]"))
}

// parseIPString 解析单条地址文本，兼容 "1.2.3.4:5678" 与 IPv6 字面量。
func parseIPString(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return net.ParseIP(strings.Trim(value, "[]"))
}
