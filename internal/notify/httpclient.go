package notify

import (
	"crypto/tls"
	"net/http"
	"time"
)

// NewHTTPClient 构造带超时与可选「跳过 TLS 证书校验」的 HTTP 客户端。
//
// 之所以放在 notify 包而不是各通道内部各写一份：
//   - 连接池复用策略、超时设置、TLS 校验策略属于**外送通道的公共约定**，
//     分散实现会出现「A 通道有超时、B 通道没有」这类难以发现的差异；
//   - 通道实现（webhook / wechat / 未来的钉钉、飞书）只需要描述
//     「我要不要跳过证书校验」，不需要重复 HTTP 客户端的构造细节。
//
// insecureTLS 仅用于自签名证书的内网环境；开启它意味着放弃对端身份校验，
// 必须在配置评审时显式确认（配置项名称为 insecure_tls 即是为了让它在评审中显眼）。
func NewHTTPClient(timeout time.Duration, insecureTLS bool) *http.Client {
	transport := &http.Transport{
		// 复用默认代理解析，兼容内网通过 HTTP_PROXY 出网的环境。
		Proxy: http.ProxyFromEnvironment,
	}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
