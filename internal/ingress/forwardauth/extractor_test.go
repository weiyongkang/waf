package forwardauth

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
)

// testHeaders 返回与默认配置一致的注入头候选列表。
func testHeaders() config.IngressHeaders {
	return config.IngressHeaders{
		URI:    []string{"X-Forwarded-Uri", "X-Original-URI"},
		Method: []string{"X-Forwarded-Method", "X-Original-Method"},
		Host:   []string{"X-Forwarded-Host"},
		Proto:  []string{"X-Forwarded-Proto"},
	}
}

// testClientIP 返回测试用的客户端 IP 推导配置（仅信任 10.0.0.0/8）。
func testClientIP() config.ClientIPConfig {
	return config.ClientIPConfig{
		Order:          []string{"X-Forwarded-For", "X-Real-IP"},
		TrustedProxies: []string{"10.0.0.0/8"},
	}
}

// newExtractor 在测试中构造接入适配器，失败直接终止用例。
func newExtractor(t *testing.T, cfg Config) *Extractor {
	t.Helper()

	if cfg.Headers.URI == nil {
		cfg.Headers = testHeaders()
	}
	if cfg.ClientIP.Order == nil {
		cfg.ClientIP = testClientIP()
	}
	extractor, err := New(cfg)
	if err != nil {
		t.Fatalf("构造接入适配器失败：%v", err)
	}
	return extractor
}

// newAuthRequest 构造一个「鉴权子请求」。
func newAuthRequest(target, remoteAddr string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

// TestExtractRestoresTraefikForwardedRequest 覆盖：Traefik 注入头的完整还原（验收项 A8）。
func TestExtractRestoresTraefikForwardedRequest(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeAuto})

	request := newAuthRequest("/waf/auth", "10.0.0.5:41234", map[string]string{
		"X-Forwarded-Uri":    "/api/user?id=7",
		"X-Forwarded-Method": "post",
		"X-Forwarded-Host":   "example.com",
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-Server": "traefik-1",
		"X-Forwarded-For":    "203.0.113.9",
		"X-Original-URI":     "/attacker-controlled",
		"User-Agent":         "curl/8.0",
	})

	raw, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("还原原始请求失败：%v", err)
	}

	if raw.Method != http.MethodPost {
		t.Fatalf("原始方法应为 POST，实际 %q", raw.Method)
	}
	if raw.URI != "/api/user?id=7" || raw.Path != "/api/user" || raw.RawQuery != "id=7" {
		t.Fatalf("原始 URI 还原不正确：uri=%q path=%q query=%q", raw.URI, raw.Path, raw.RawQuery)
	}
	if raw.Host != "example.com" || raw.Proto != "https" {
		t.Fatalf("原始 Host / 协议还原不正确：host=%q proto=%q", raw.Host, raw.Proto)
	}
	if raw.ClientIP != "203.0.113.9" || !raw.PeerTrusted {
		t.Fatalf("客户端 IP 推导不正确：ip=%q trusted=%v", raw.ClientIP, raw.PeerTrusted)
	}
	if len(raw.ClientIPChain) != 1 || raw.ClientIPChain[0] != "203.0.113.9" {
		t.Fatalf("转发链记录不正确：%v", raw.ClientIPChain)
	}

	// 注入头必须从「供检测使用的请求头」中剔除，否则会被规则引擎误判或被攻击者利用。
	for _, name := range []string{"X-Forwarded-Uri", "X-Original-URI", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Method"} {
		if value := raw.HeaderValue(name); value != "" {
			t.Fatalf("注入头 %s 应被剔除，实际保留 %q", name, value)
		}
	}
	if got := raw.HeaderValue("User-Agent"); got != "curl/8.0" {
		t.Fatalf("业务请求头应被保留，User-Agent 实际为 %q", got)
	}
}

// TestExtractIgnoresForwardedHeadersFromUntrustedPeer 覆盖：不可信对端携带的转发头一律忽略（验收项 A10）。
func TestExtractIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeTraefik})

	request := newAuthRequest("/waf/auth", "198.51.100.7:5000", map[string]string{
		"X-Forwarded-Uri":    "/admin",
		"X-Forwarded-For":    "1.2.3.4",
		"X-Forwarded-Server": "traefik-1",
	})

	raw, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("还原原始请求失败：%v", err)
	}

	if raw.ClientIP != "198.51.100.7" {
		t.Fatalf("不可信对端必须使用 TCP 对端地址，实际 %q", raw.ClientIP)
	}
	if raw.PeerTrusted {
		t.Fatal("不可信对端不应标记为可信")
	}
	if len(raw.ClientIPChain) != 0 {
		t.Fatalf("不可信对端不应产生转发链，实际 %v", raw.ClientIPChain)
	}
}

// TestExtractSkipsTrustedHopsInForwardedChain 覆盖：从右往左跳过可信代理，取第一个不可信地址（验收项 A10）。
func TestExtractSkipsTrustedHopsInForwardedChain(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeTraefik})

	request := newAuthRequest("/waf/auth", "10.0.0.5:41234", map[string]string{
		"X-Forwarded-Uri":    "/",
		"X-Forwarded-Server": "traefik-1",
		"X-Forwarded-For":    "1.2.3.4, 10.0.0.9",
	})

	raw, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("还原原始请求失败：%v", err)
	}

	if raw.ClientIP != "1.2.3.4" {
		t.Fatalf("应跳过可信代理并取 %q，实际 %q", "1.2.3.4", raw.ClientIP)
	}
	if len(raw.ClientIPChain) != 2 {
		t.Fatalf("转发链应保留 2 跳，实际 %v", raw.ClientIPChain)
	}
}

// TestExtractUsesXRealIPForOpenResty 覆盖：OpenResty 通道的 X-Real-IP 推导与显式类型声明。
func TestExtractUsesXRealIPForOpenResty(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeNginxOpenResty})

	request := newAuthRequest("/waf/auth", "10.0.0.5:41234", map[string]string{
		"X-Forwarded-Uri": "/a?b=1",
		"X-Real-IP":       "198.51.100.1",
	})

	raw, err := extractor.Extract(request)
	if err != nil {
		t.Fatalf("还原原始请求失败：%v", err)
	}

	if raw.ClientIP != "198.51.100.1" {
		t.Fatalf("应使用 X-Real-IP，实际 %q", raw.ClientIP)
	}
	if raw.Path != "/a" || raw.RawQuery != "b=1" {
		t.Fatalf("URI 还原不正确：path=%q query=%q", raw.Path, raw.RawQuery)
	}
	// 未注入原始方法时应回退为子请求自身的方法。
	if raw.Method != http.MethodGet {
		t.Fatalf("方法应回退为子请求方法 GET，实际 %q", raw.Method)
	}
	if got := extractor.IngressType(); got != config.IngressTypeNginxOpenResty {
		t.Fatalf("显式声明的接入类型应为 %q，实际 %q", config.IngressTypeNginxOpenResty, got)
	}
}

// TestExtractContentLengthPerIngressType 覆盖：原始请求体长度（Content-Length）的还原规则。
//
// 契约要点（设计文档 §3.7）：
//   - nginx-auth-only 通道不转发请求体也不转发 Content-Length（deploy 配置里是
//     proxy_pass_request_body off + proxy_set_header Content-Length ""），
//     子请求的 Content-Length 恒为 0，必须还原为「未知」(-1)，
//     否则「客户端明确声明空体」与「通道拿不到请求体」会被混为一谈，
//     真实故障（该通道根本没能力做体检测）将被静默掩盖；
//   - 其余通道（Traefik forwardBody / OpenResty 体捕获 / 直通）下子请求的
//     Content-Length 就是原始请求声明的长度，直接采用。
func TestExtractContentLengthPerIngressType(t *testing.T) {
	cases := []struct {
		name        string
		ingressType string
		headers     map[string]string
		contentLen  int64
		want        int64
	}{
		{
			name:        "nginx-auth-only 通道不携带原始长度",
			ingressType: config.IngressTypeNginxAuthOnly,
			headers:     map[string]string{"X-Forwarded-Uri": "/a"},
			contentLen:  0,
			want:        -1,
		},
		{
			name:        "traefik 通道保留原始长度",
			ingressType: config.IngressTypeTraefik,
			headers:     map[string]string{"X-Forwarded-Uri": "/a", "X-Forwarded-Server": "traefik-1"},
			contentLen:  128,
			want:        128,
		},
		{
			name:        "traefik 通道下客户端声明的空体保持为 0",
			ingressType: config.IngressTypeTraefik,
			headers:     map[string]string{"X-Forwarded-Uri": "/a", "X-Forwarded-Server": "traefik-1"},
			contentLen:  0,
			want:        0,
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			extractor := newExtractor(t, Config{Type: item.ingressType})

			request := newAuthRequest("/waf/auth", "10.0.0.5:41234", item.headers)
			request.ContentLength = item.contentLen

			raw, err := extractor.Extract(request)
			if err != nil {
				t.Fatalf("还原原始请求失败：%v", err)
			}
			if raw.ContentLength != item.want {
				t.Fatalf("ContentLength 还原错误：want %d, got %d", item.want, raw.ContentLength)
			}
		})
	}
}

// TestExtractFallsBackToSubrequestLine 覆盖：无任何注入头时退化为「直通形态」。
func TestExtractFallsBackToSubrequestLine(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeAuto})

	raw, err := extractor.Extract(newAuthRequest("/waf/auth?probe=1", "192.0.2.10:3000", nil))
	if err != nil {
		t.Fatalf("还原原始请求失败：%v", err)
	}

	if raw.URI != "/waf/auth?probe=1" || raw.Path != "/waf/auth" {
		t.Fatalf("应回退为子请求自身的请求行，实际 uri=%q path=%q", raw.URI, raw.Path)
	}
	if raw.ClientIP != "192.0.2.10" {
		t.Fatalf("直通形态下客户端 IP 应取 TCP 对端地址，实际 %q", raw.ClientIP)
	}
}

// TestExtractRejectsControlCharactersInInjectedURI 覆盖：注入头含控制字符时拒绝还原。
func TestExtractRejectsControlCharactersInInjectedURI(t *testing.T) {
	extractor := newExtractor(t, Config{Type: config.IngressTypeTraefik})

	request := newAuthRequest("/waf/auth", "10.0.0.5:41234", map[string]string{
		"X-Forwarded-Uri":    "/a\r\nX-Evil: 1",
		"X-Forwarded-Server": "traefik-1",
	})

	if _, err := extractor.Extract(request); err == nil {
		t.Fatal("注入头含控制字符时必须拒绝还原")
	}
}

// TestNewRejectsInvalidConfig 覆盖：构造阶段的参数校验必须 fail fast。
func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "非法接入类型", cfg: Config{Type: "unknown"}},
		{name: "非法可信代理网段", cfg: Config{
			Type:     config.IngressTypeAuto,
			Headers:  testHeaders(),
			ClientIP: config.ClientIPConfig{TrustedProxies: []string{"999.1.1.1"}},
		}},
		{name: "非法 CIDR", cfg: Config{
			Type:     config.IngressTypeAuto,
			Headers:  testHeaders(),
			ClientIP: config.ClientIPConfig{TrustedProxies: []string{"10.0.0.0/33"}},
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.cfg); err == nil {
				t.Fatal("非法配置应当返回错误")
			}
		})
	}
}

// rawSubrequest 拼装一条最小可用的鉴权子请求报文（CRLF 行尾）。
//
// framing 是消息框架头（Content-Length / Transfer-Encoding），为空表示两者皆缺——
// 这正是「代理没有转发请求体」时的真实形态；body 是报文正文（分块传输时需自带分块帧）。
func rawSubrequest(requestLine, originalMethod string, framing []string, body string) string {
	lines := []string{
		requestLine,
		"Host: waf.internal",
		"X-Forwarded-Uri: /api/constant/selectAll.do",
		"X-Forwarded-Method: " + originalMethod,
		"X-Forwarded-Host: app.example.com",
		"X-Forwarded-Proto: http",
		"X-Forwarded-For: 203.0.113.10",
	}
	lines = append(lines, framing...)
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

// readRawSubrequest 按原始报文解析出一个鉴权子请求。
//
// 之所以不直接用 httptest.NewRequest：它构造不出「既没有 Content-Length 也没有
// Transfer-Encoding」的 POST，而 net/http 在解析真实报文时恰恰会把这种形态的
// ContentLength 记为 0、把 Transfer-Encoding 从 Header 中剥离。
func readRawSubrequest(t *testing.T, raw string) *http.Request {
	t.Helper()

	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("解析原始鉴权子请求失败：%v", err)
	}
	request.RemoteAddr = "10.0.0.5:41234"
	return request
}

// TestExtractRestoresFramingHeaders 覆盖：重建请求必须带上可判定的消息框架头。
//
// 缺陷背景（实测复现）：鉴权子请求是代理合成的报文，代理没转发请求体时
// Content-Length 与 Transfer-Encoding 都不存在；而 net/http 会把这种形态的
// ContentLength 记为 0、把 Transfer-Encoding 收进 r.TransferEncoding。
// 若不还原框架头，CRS 的 920180（POST without Content-Length or Transfer-Encoding）
// 会把每一次「拿不到请求体」的 POST 判成协议违规（WARNING = 5 分 = 默认阈值）→ 403。
func TestExtractRestoresFramingHeaders(t *testing.T) {
	cases := []struct {
		name         string
		ingressType  string
		requestLine  string
		method       string
		framing      []string
		body         string
		wantCL       string
		wantTE       string
		wantDeclared int64
	}{
		{
			name:         "POST 无任何框架头（代理未转发请求体）→ 补 Content-Length: 0",
			ingressType:  config.IngressTypeAuto,
			requestLine:  "POST /waf/auth HTTP/1.1",
			method:       http.MethodPost,
			wantCL:       "0",
			wantDeclared: 0,
		},
		{
			name:         "POST 已声明空体 → 原样保留，不重复补头",
			ingressType:  config.IngressTypeAuto,
			requestLine:  "POST /waf/auth HTTP/1.1",
			method:       http.MethodPost,
			framing:      []string{"Content-Length: 0"},
			wantCL:       "0",
			wantDeclared: 0,
		},
		{
			name:         "POST 带真实长度 → 原样保留",
			ingressType:  config.IngressTypeAuto,
			requestLine:  "POST /waf/auth HTTP/1.1",
			method:       http.MethodPost,
			framing:      []string{"Content-Length: 12"},
			body:         `{"id":12345}`,
			wantCL:       "12",
			wantDeclared: 12,
		},
		{
			name:         "POST 分块传输 → 补 Transfer-Encoding: chunked",
			ingressType:  config.IngressTypeAuto,
			requestLine:  "POST /waf/auth HTTP/1.1",
			method:       http.MethodPost,
			framing:      []string{"Transfer-Encoding: chunked"},
			body:         "0\r\n\r\n",
			wantTE:       "chunked",
			wantDeclared: -1,
		},
		{
			name:         "GET 无框架头 → 不补（无体方法的合法形态）",
			ingressType:  config.IngressTypeAuto,
			requestLine:  "GET /waf/auth HTTP/1.1",
			method:       http.MethodGet,
			wantDeclared: 0,
		},
		{
			name:         "auth-only 通道（长度未知）→ 仍补 Content-Length: 0",
			ingressType:  config.IngressTypeNginxAuthOnly,
			requestLine:  "POST /waf/auth HTTP/1.1",
			method:       http.MethodPost,
			wantCL:       "0",
			wantDeclared: -1,
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			extractor := newExtractor(t, Config{Type: item.ingressType})
			request := readRawSubrequest(t, rawSubrequest(item.requestLine, item.method, item.framing, item.body))

			raw, err := extractor.Extract(request)
			if err != nil {
				t.Fatalf("还原原始请求失败：%v", err)
			}

			if got := raw.Header.Get("Content-Length"); got != item.wantCL {
				t.Fatalf("Content-Length 头还原错误：want %q, got %q", item.wantCL, got)
			}
			if got := raw.Header.Get("Transfer-Encoding"); got != item.wantTE {
				t.Fatalf("Transfer-Encoding 头还原错误：want %q, got %q", item.wantTE, got)
			}
			if values := raw.Header.Values("Content-Length"); len(values) > 1 {
				t.Fatalf("Content-Length 头被重复写入：%v", values)
			}
			if raw.ContentLength != item.wantDeclared {
				t.Fatalf("ContentLength 还原错误：want %d, got %d", item.wantDeclared, raw.ContentLength)
			}
		})
	}
}
