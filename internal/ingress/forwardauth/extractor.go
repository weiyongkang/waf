// Package forwardauth 实现 forward-auth 形态下的「原始请求还原」。
//
// 职责（需求 R1 / R3）：
//
//	把代理发出的鉴权子请求（Nginx auth_request / OpenResty 子请求 / Traefik ForwardAuth）
//	还原为「被保护的原始业务请求」，包括方法、URI、Host、协议、客户端 IP 与请求体。
//
// 设计原则：代理差异只存在于本包，上层（pipeline / 各校验单元 / responder）完全无感，
// 因此新增一种入口（例如后续的 APISIX / HAProxy SPOE）只需新增一个还原实现。
package forwardauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// IngressTypeDirect 表示「未识别出任何代理注入头」的直通形态。
//
// 该形态只应出现在本地自检（curl 直接访问鉴权端点）场景；
// 真实流量下出现该值说明代理配置有误或 ingress.type 配置不当，必须告警。
const IngressTypeDirect = "direct"

// Config 是接入适配器的构造参数。
type Config struct {
	// Type 是配置声明的接入类型（auto / traefik-forwardauth / nginx-openresty / nginx-auth-only）。
	Type string
	// Headers 是各原始请求信息的注入头候选列表。
	Headers config.IngressHeaders
	// ClientIP 是客户端 IP 推导配置（候选头顺序 + 可信代理网段）。
	ClientIP config.ClientIPConfig
	// BodySource 是请求体来源通道（request-body / none）。
	BodySource string
	// Logger 是系统日志器，用于记录 auto 判定结果等诊断信息；可为 nil。
	Logger *slog.Logger
}

// Extractor 是 forward-auth 形态的原始请求还原实现。
type Extractor struct {
	cfg      Config
	resolver *ClientIPResolver

	// ingressType 是确定的接入类型；为空表示配置为 auto，需要逐请求判定。
	ingressType string

	// skipHeaders 是需要从「供检测使用的请求头」中剔除的注入头。
	//
	// 之所以要剔除：这些头承载的是代理内部鉴权通道的信息（例如 X-Forwarded-Uri），
	// 如果保留在请求头中参与规则检测，会产生两类问题：
	//   1) 误报：检测规则把代理注入的内部值当作攻击载荷；
	//   2) 绕过：攻击者构造的同名头会被代理的注入值覆盖或混淆，导致判定结果不可预期。
	skipHeaders []string

	// warnDirectOnce 保证「auto 判定为直通形态」的告警只输出一次，避免刷爆系统日志。
	warnDirectOnce sync.Once

	// reportAutoOnce 保证「auto 判定结果」的提示只输出一次。
	//
	// 之所以需要它：ingress.type 的默认值是 auto，而 auto 只用于过渡期
	// （生产环境必须显式声明类型）。把判定结果打印一次，运维才能确认
	// 实际生效的通道是否与预期一致，而不必逐请求翻日志。
	reportAutoOnce sync.Once
}

// New 构造接入适配器。
//
// 构造阶段完成两件容易出错的事情，使运行期无需再做字符串解析：
//   - 可信代理网段预解析（非法 CIDR 在启动阶段即报错）；
//   - 需要剔除的注入头清单预计算。
func New(cfg Config) (*Extractor, error) {
	switch cfg.Type {
	case config.IngressTypeAuto, config.IngressTypeTraefik,
		config.IngressTypeNginxOpenResty, config.IngressTypeNginxAuthOnly:
	default:
		return nil, fmt.Errorf("不支持的 ingress.type：%q", cfg.Type)
	}

	resolver, err := NewClientIPResolver(cfg.ClientIP.Order, cfg.ClientIP.TrustedProxies)
	if err != nil {
		return nil, err
	}

	extractor := &Extractor{cfg: cfg, resolver: resolver}
	if cfg.Type != config.IngressTypeAuto {
		extractor.ingressType = cfg.Type
	}
	extractor.skipHeaders = collectInjectionHeaders(cfg.Headers)
	return extractor, nil
}

// IngressType 返回实际生效的接入类型。
//
// 配置为 auto 时返回 IngressTypeAuto：真实类型由每个请求的注入头决定，
// 具体值可通过 RequestExtractor.Extract 写入 RequestContext.IngressType 后从日志观察。
func (e *Extractor) IngressType() string {
	if e.ingressType != "" {
		return e.ingressType
	}
	return config.IngressTypeAuto
}

// TrustedProxies 返回可信代理网段列表，用于启动日志与 check-config 输出。
func (e *Extractor) TrustedProxies() []string {
	return e.resolver.TrustedProxies()
}

// Extract 把鉴权子请求还原为原始业务请求（core.RequestExtractor 实现）。
func (e *Extractor) Extract(r *http.Request) (*core.RawRequest, error) {
	if r == nil || r.URL == nil {
		return nil, errors.New("鉴权子请求为空或缺少 URL")
	}

	// 1) 确定接入类型：显式配置优先，auto 时按注入头判定。
	ingressType := e.ingressType
	if ingressType == "" {
		ingressType = detectIngressType(r, e.skipHeaders)
		if ingressType == IngressTypeDirect {
			// 直通形态在真实代理流量下属于配置事故，必须留下痕迹（只告警一次）。
			e.warnDirectOnce.Do(func() {
				if e.cfg.Logger != nil {
					e.cfg.Logger.Warn(
						"接入类型判定为直通（未检测到任何代理注入头）；"+
							"若 WAF 部署在代理之后，请显式配置 ingress.type 或检查代理的注入头设置",
						"ingress_type", ingressType,
					)
				}
			})
		} else {
			e.reportAutoOnce.Do(func() {
				if e.cfg.Logger != nil {
					e.cfg.Logger.Info("接入类型由注入头自动判定", "ingress_type", ingressType)
				}
			})
		}
	}

	// 2) 还原方法：优先取注入头，缺失时回退为子请求自身的方法。
	method, err := e.pickMethod(r)
	if err != nil {
		return nil, err
	}

	// 3) 还原原始 URI：优先取注入头，缺失时回退为子请求自身的请求行。
	uri, err := e.pickValue(r.Header, e.cfg.Headers.URI)
	if err != nil {
		return nil, fmt.Errorf("无法还原原始请求 URI：%w", err)
	}
	if uri == "" {
		if r.URL.RequestURI() == "" {
			return nil, errors.New("原始请求 URI 为空，且鉴权子请求未携带请求行")
		}
		uri = r.URL.RequestURI()
	}
	if err := validateRequestURI(uri); err != nil {
		return nil, err
	}
	path, rawQuery := splitURI(uri)

	// 4) 还原 Host 与协议。
	host, err := e.pickValue(r.Header, e.cfg.Headers.Host)
	if err != nil {
		return nil, fmt.Errorf("无法还原原始 Host：%w", err)
	}
	if host == "" {
		host = r.Host
	}
	host = sanitizeHeaderValue(host)

	proto, err := e.pickValue(r.Header, e.cfg.Headers.Proto)
	if err != nil {
		return nil, fmt.Errorf("无法还原原始协议：%w", err)
	}
	if proto == "" {
		proto = r.Proto
	}
	proto = sanitizeHeaderValue(proto)

	// 5) 推导真实客户端 IP（可信代理校验在 resolver 内部完成）。
	clientIP, chain, trustedPeer := e.resolver.Resolve(r.RemoteAddr, r.Header)

	// 6) 构造供检测使用的请求头副本：剔除注入头，避免污染规则检测。
	detectHeaders := r.Header.Clone()
	for _, name := range e.skipHeaders {
		detectHeaders.Del(name)
	}

	// 7) 还原「声明的请求体长度」，并把消息框架头补回重建的请求头；
	//    判定规则见 pickContentLength 与 restoreFramingHeaders。
	contentLength := e.pickContentLength(r, ingressType)
	restoreFramingHeaders(detectHeaders, method, contentLength, len(r.TransferEncoding) > 0)

	return &core.RawRequest{
		Method:        method,
		URI:           uri,
		Path:          path,
		RawQuery:      rawQuery,
		Host:          host,
		Proto:         proto,
		Header:        detectHeaders,
		ClientIP:      clientIP,
		ClientIPChain: chain,
		PeerTrusted:   trustedPeer,
		// 原始请求声明的请求体长度；判定规则见 pickContentLength。
		ContentLength: contentLength,
		// 请求体由 pipeline 按需读取；此处只做传递，不做任何缓冲。
		Body: r.Body,
	}, nil
}

// pickMethod 还原原始请求方法并做合法性校验。
func (e *Extractor) pickMethod(r *http.Request) (string, error) {
	method, err := e.pickValue(r.Header, e.cfg.Headers.Method)
	if err != nil {
		return "", fmt.Errorf("无法还原原始请求方法：%w", err)
	}
	if method == "" {
		method = r.Method
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "", errors.New("原始请求方法为空")
	}
	// 方法必须是纯字母的 HTTP token，防止把非法内容当作方法参与检测与日志输出。
	for _, ch := range method {
		if (ch < 'A' || ch > 'Z') && ch != '-' {
			return "", fmt.Errorf("非法的原始请求方法 %q", method)
		}
	}
	return method, nil
}

// pickContentLength 还原「原始请求声明的请求体长度」（Content-Length）。
//
// 之所以必须按接入类型区分，而不是直接取子请求的 Content-Length：
//   - nginx-auth-only 通道（deploy/forward-auth/nginx-auth-only.conf 中的
//     `proxy_pass_request_body off` + `proxy_set_header Content-Length ""`）
//     **既不转发请求体，也不转发 Content-Length**，子请求的 Content-Length 恒为 0。
//     此时 0 表示「无法得知」，而不是「客户端声明了空请求体」。
//     若把它当成后者，真实故障（部署通道根本没能力做体检测）会被永久掩盖，
//     所以这里统一记为 -1（未知），让上游按「未知」处理。
//   - Traefik 通道（forwardBody: true，v3.2+）会执行
//     `forwardReq.ContentLength = req.ContentLength`，子请求携带的就是原始长度；
//   - OpenResty 通道由 Lua 捕获请求体后再发起子请求，同样会带上原始长度；
//   - 直通形态（direct，本地自检 / 回溯抓包）下子请求就是原始请求本身。
//     以上三种情况下子请求的 Content-Length 就是原始请求声明的长度，直接采用。
//
// 返回值语义（与 core.RawRequest.ContentLength 一致）：
//   - 0  ：客户端明确声明「本次请求没有请求体」（Content-Length: 0）；
//   - >0 ：客户端声明了具体长度；
//   - -1 ：未知（chunked 编码，或接入通道不转发 Content-Length）。
func (e *Extractor) pickContentLength(r *http.Request, ingressType string) int64 {
	if ingressType == config.IngressTypeNginxAuthOnly {
		return -1
	}
	return r.ContentLength
}

// restoreFramingHeaders 把「消息框架头」（Content-Length / Transfer-Encoding）补回重建的请求头。
//
// 为什么必须补（实测复现的误报）：
//   - 鉴权子请求是代理**合成**的报文，它的框架头描述的是「代理 → WAF」这一段链路，
//     而不是客户端与代理之间的原始报文。代理没把请求体转发过来时（原生 Nginx `auth_request`、
//     Traefik 未开 `forwardBody`、未做体捕获的 OpenResty 配置），子请求既没有
//     `Content-Length` 也没有 `Transfer-Encoding`。
//   - Go 的 net/http 还会把 `Transfer-Encoding` 从 Header 中剥离（只留 `r.TransferEncoding`），
//     并在完全没有框架头时把 `ContentLength` 记为 0。
//   - 于是 CRS 的 920180（`POST without Content-Length or Transfer-Encoding headers`）
//     会把每一次「代理没有转发请求体」的 POST 判成协议违规：该规则是 WARNING（5 分），
//     正好等于默认评分阈值 → 整条 POST 接口被 403。实测：不带 `Content-Length` 的 POST
//     经鉴权端点送入时被 `threshold` 以 `920180` 拦截，而它其实只是「拿不到请求体」。
//
// 还原规则（按顺序判定）：
//  1. 代理已经转发了任一框架头 → 原样保留，不做任何改动（Traefik `forwardBody` /
//     OpenResty 体捕获通道属于这一类，框架信息是真实的）；
//  2. 方法本身「以无请求体为常态」（GET / HEAD / OPTIONS / TRACE）→ 不补：
//     这些方法缺框架头是合法形态，CRS 也正用 920170 / 920171 管控它们的请求体；
//  3. 子请求是分块传输（`Transfer-Encoding: chunked`）→ 补 `Transfer-Encoding: chunked`；
//  4. 其余情况（代理完全没有转发请求体与框架头）→ 补 `Content-Length: 0`：
//     对「WAF 实际收到的这条报文」而言它确实不带请求体。这既不是客户端的协议违规，
//     也不会影响「请求体缺失」的告警判定——后者只看 core.RawRequest.ContentLength
//     （见 internal/ingress/body/spool.go 的 markMissingIfRequired），与本函数无关。
//
// 边界：本函数只作用于**重建形态**。直通形态（IngressTypeDirect / internal/server/direct.go）
// 保留客户端原始框架头，真实的协议违规（例如客户端真的发了既无 CL 也无 TE 的 POST）照旧命中。
func restoreFramingHeaders(header http.Header, method string, declared int64, chunkedSubrequest bool) {
	if header.Get("Content-Length") != "" || header.Get("Transfer-Encoding") != "" {
		return
	}
	if !methodMayCarryBody(method) {
		return
	}
	switch {
	case chunkedSubrequest:
		header.Set("Transfer-Encoding", "chunked")
	case declared > 0:
		// 防御性分支：理论上「已知长度」必然伴随 Content-Length 头，
		// 但若某个代理只传了长度而不传头，按已知长度补回来比补 0 更接近事实。
		header.Set("Content-Length", strconv.FormatInt(declared, 10))
	default:
		header.Set("Content-Length", "0")
	}
}

// methodMayCarryBody 报告该方法是否「语义上可以携带请求体」。
//
// 只排除 RFC 9110 中「以无请求体为常态」的 GET / HEAD / OPTIONS / TRACE。
// 方法为空（接入层未能还原原始方法）时保守返回 false：不补框架头，
// 避免给一条来历不明的请求编造框架信息。
func methodMayCarryBody(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

// pickValue 按候选顺序取第一个非空的头值。
//
// 不同代理对同一语义使用不同的头名（例如原始 URI 可能是 X-Forwarded-Uri，
// 也可能是 X-Original-URI），因此统一用「候选列表」表达，由配置决定顺序。
func (e *Extractor) pickValue(header http.Header, candidates []string) (string, error) {
	for _, name := range candidates {
		value := header.Get(name)
		if value == "" {
			continue
		}
		if err := validateHeaderValue(name, value); err != nil {
			return "", err
		}
		return value, nil
	}
	return "", nil
}

// collectInjectionHeaders 汇总所有可能在还原中被消费的注入头名称。
func collectInjectionHeaders(headers config.IngressHeaders) []string {
	seen := make(map[string]struct{})
	var names []string
	appendAll := func(list []string) {
		for _, name := range list {
			key := http.CanonicalHeaderKey(name)
			if key == "" {
				continue
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			names = append(names, key)
		}
	}
	appendAll(headers.URI)
	appendAll(headers.Method)
	appendAll(headers.Host)
	appendAll(headers.Proto)
	// 这两个头是「客户端 IP」的载体，同样不应参与正文检测。
	appendAll([]string{"X-Forwarded-For", "X-Real-IP"})
	return names
}

// detectIngressType 依据注入头的存在性判定接入类型。
//
// 判定依据：
//   - Traefik 的 forwardAuth 会额外注入 X-Forwarded-Server，且不注入 X-Real-IP；
//   - Nginx（本项目的接入配置）会注入 X-Real-IP；
//   - 两者都会注入 X-Forwarded-Uri / X-Forwarded-Method。
//
// 注意（必须在文档中标注）：nginx-openresty 与 nginx-auth-only 的注入头完全相同，
// 无法通过请求内容区分，而两者的对外状态码语义不同（auth-only 必须统一回 403）。
// 因此 auto 只用于过渡期，生产环境必须显式声明 ingress.type；
// 使用 auth-only 通道时禁止依赖 auto 判定。
func detectIngressType(r *http.Request, skipHeaders []string) string {
	hasHeader := func(name string) bool { return r.Header.Get(name) != "" }

	hasRealIP := hasHeader("X-Real-IP")
	hasForwardedServer := hasHeader("X-Forwarded-Server")
	hasOriginalURI := hasHeader("X-Forwarded-Uri") || hasHeader("X-Original-URI")

	switch {
	case hasForwardedServer && !hasRealIP:
		return config.IngressTypeTraefik
	case hasRealIP || hasOriginalURI:
		return config.IngressTypeNginxOpenResty
	default:
		// 完全没有注入头：直通形态（本地自检）。
		_ = skipHeaders
		return IngressTypeDirect
	}
}

// splitURI 把原始 URI 拆分为路径与查询串。
//
// 之所以不直接用 net/url.Parse：注入头里的 URI 可能是 path-only（例如 "/a?b=1"），
// 也可能是绝对形式（例如 "http://host/a?b=1"）。前者用 url.Parse 会把 "a?b=1" 误判为
// 相对路径并做转义处理，导致原始形态被破坏；这里统一采用「按第一个 ? 切分」的保守做法，
// 保证传给检测引擎的路径与查询串与代理看到的完全一致。
func splitURI(uri string) (path, rawQuery string) {
	// 绝对 URI 形态：先剥离 scheme://host 前缀。
	if index := strings.Index(uri, "://"); index >= 0 {
		rest := uri[index+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			uri = rest[slash:]
		} else {
			uri = "/"
		}
	}
	if index := strings.Index(uri, "?"); index >= 0 {
		return uri[:index], uri[index+1:]
	}
	// 兼容 "path#fragment" 写法（片段不应参与检测，但需保证路径完整）。
	if index := strings.Index(uri, "#"); index >= 0 {
		return uri[:index], ""
	}
	return uri, ""
}

// validateRequestURI 校验原始 URI 的合法性。
func validateRequestURI(uri string) error {
	if uri == "" {
		return errors.New("原始请求 URI 为空")
	}
	if len(uri) > 8192 {
		return fmt.Errorf("原始请求 URI 过长（%d 字节），超过 8192 上限", len(uri))
	}
	// 拒绝控制字符：注入头来自代理，正常请求的 URI 不应包含 CR/LF 等控制字符；
	// 出现即说明请求被篡改，属于必须拦截的异常。
	for _, ch := range uri {
		if ch < 0x20 || ch == 0x7f {
			return fmt.Errorf("原始请求 URI 含非法控制字符（0x%02x）", ch)
		}
	}
	// 使用 url.Parse 做一次语法校验，但保留原始字符串作为检测输入（不做规范化）。
	if _, err := url.ParseRequestURI(uri); err != nil && !strings.HasPrefix(uri, "/") {
		return fmt.Errorf("原始请求 URI 语法非法 %q：%w", uri, err)
	}
	return nil
}

// validateHeaderValue 校验参与还原的头值。
func validateHeaderValue(name, value string) error {
	if len(value) > 8192 {
		return fmt.Errorf("注入头 %s 的值过长（%d 字节）", name, len(value))
	}
	for _, ch := range value {
		if ch < 0x20 || ch == 0x7f {
			return fmt.Errorf("注入头 %s 的值含非法控制字符", name)
		}
	}
	return nil
}

// sanitizeHeaderValue 清理非关键头值中的首尾空白。
func sanitizeHeaderValue(value string) string {
	return strings.TrimSpace(value)
}
