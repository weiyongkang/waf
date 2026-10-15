package core

// WAF 对外回传的响应头名称。
//
// 为什么这些响应头是「必需能力」而不是可选装饰（需求 R22）：
// Nginx 与 Traefik 都会丢弃鉴权子请求的响应体，只有响应头能被代理侧读取
// （Nginx 通过 auth_request_set $upstream_http_x_waf_code 取到）。
// 因此「拦截原因」必须完整地编码在响应头里，代理侧才能渲染出正确的对外响应。
const (
	// HeaderRequestID 回传请求标识，用于把代理侧渲染的错误与其后续排障关联到访问日志。
	HeaderRequestID = "X-WAF-Request-Id"
	// HeaderVerdict 回传判定结论（allow / block / ratelimit / ...）。
	HeaderVerdict = "X-WAF-Verdict"
	// HeaderCode 回传对外错误码（WAF_BLOCKED / WAF_RATE_LIMITED / ...）。
	//
	// 该头是「真实语义」的载体：Nginx auth_request 只透传 401/403，
	// 其它状态码会被改写成 500，因此对外状态码由代理侧渲染端点决定，
	// WAF 侧统一回 403 并通过该头表达真实原因。
	HeaderCode = "X-WAF-Code"
	// HeaderRuleID 回传命中的规则标识，便于排障与误报申诉。
	HeaderRuleID = "X-WAF-Rule-Id"
	// HeaderVersion 回传 WAF 版本，便于确认线上运行的构建版本。
	HeaderVersion = "X-WAF-Version"
)
