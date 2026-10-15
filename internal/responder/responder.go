// Package responder 负责把校验结论渲染为对外响应。
//
// 设计约束（需求 R20 / R22）：
//   - 不提供任何拦截 HTML 页面，统一返回 JSON 错误体；
//   - 由于 Nginx 与 Traefik 都会丢弃鉴权子请求的响应体，
//     「拦截原因」必须同时编码到响应头（X-WAF-Code 等），代理侧才能渲染出正确响应；
//   - 提供 /waf/deny 幂等渲染端点，供 Traefik errors 中间件回源取值。
package responder

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// ErrorBody 是对外 JSON 错误响应体。
//
// 字段顺序与设计文档 §4.2 保持一致，便于日志采集侧与前端统一处理。
type ErrorBody struct {
	// Code 是对外错误码，例如 WAF_BLOCKED。
	Code string `json:"code"`
	// Message 是面向调用方的中文提示，不包含任何检测细节。
	Message string `json:"message"`
	// RequestID 是请求标识，用户反馈问题时凭该值即可定位完整日志。
	RequestID string `json:"request_id"`
	// Timestamp 是响应时间，RFC3339 带时区偏移格式。
	Timestamp string `json:"timestamp"`
	// Details 是检测细节；仅当 include_details = true 时输出（默认关闭，防止信息泄露）。
	Details *ErrorDetails `json:"details,omitempty"`
}

// ErrorDetails 是错误体中可选的检测细节。
type ErrorDetails struct {
	// Verdict 是判定结论标识。
	Verdict string `json:"verdict,omitempty"`
	// Check 是产生结论的校验单元实例名。
	Check string `json:"check,omitempty"`
	// RuleID 是命中的规则标识。
	RuleID string `json:"rule_id,omitempty"`
	// Score 是累计异常评分。
	Score int `json:"score,omitempty"`
}

// Config 是响应渲染配置。
type Config struct {
	// IncludeDetails 决定是否在错误体中输出 Details。
	IncludeDetails bool
	// Messages 是错误码到中文文案的映射（来自配置文件 responder.messages）。
	Messages map[string]string
	// ForceHTTPStatus 非零时，所有拦截响应统一使用该状态码。
	//
	// 使用场景（需求 R22 / 验收项 A30）：Nginx 原生 auth_request 只透传 401/403，
	// 其它状态码会被改写成 500，因此该通道下必须统一回 403，
	// 真实语义通过响应头 X-WAF-Code 表达，最终对外状态码由渲染端点决定。
	ForceHTTPStatus int
	// Version 是当前程序版本，写入 X-WAF-Version 响应头。
	Version string
	// Clock 是时间源，为 nil 时使用系统时钟。
	Clock core.Clock
}

// Writer 是 JSON 错误体渲染器。
type Writer struct {
	cfg   Config
	clock core.Clock
}

// New 构造错误体渲染器。
func New(cfg Config) *Writer {
	clock := cfg.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	if cfg.Messages == nil {
		cfg.Messages = map[string]string{}
	}
	return &Writer{cfg: cfg, clock: clock}
}

// Respond 依据校验结论写出完整响应：状态码、回传响应头与 JSON 错误体。
func (w *Writer) Respond(rw http.ResponseWriter, rctx *core.RequestContext, res *core.Result) {
	code := w.resolveCode(res)
	rctx2 := rctx

	headers := rw.Header()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	// 拦截响应禁止被任何中间层缓存。
	headers.Set("Cache-Control", "no-store")
	if w.cfg.Version != "" {
		headers.Set(core.HeaderVersion, w.cfg.Version)
	}

	requestID := ""
	verdict := "allow"
	if rctx2 != nil {
		requestID = rctx2.RequestID
		headers.Set(core.HeaderRequestID, requestID)
		if rctx2.Site != nil {
			headers.Set("X-WAF-Site", rctx2.Site.Name)
		}
	}
	if res != nil {
		verdict = res.Verdict.String()
		headers.Set(core.HeaderVerdict, verdict)
		if ruleID := firstRuleID(res); ruleID != "" {
			headers.Set(core.HeaderRuleID, ruleID)
		}
		// 限速场景回传 Retry-After，便于客户端与代理侧正确退避。
		if res.RetryAfter > 0 {
			headers.Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds()+0.5)))
		}
		// 401 需要携带认证挑战头，否则浏览器不会弹出认证框。
		if res.Verdict == core.VerdictUnauthorized {
			headers.Set("WWW-Authenticate", `Basic realm="waf"`)
		}
	}
	// X-WAF-Code 是响应头方案的核心：代理侧据此渲染对外响应（需求 R22）。
	headers.Set(core.HeaderCode, code)

	rw.WriteHeader(w.statusFor(code, res))
	w.writeBody(rw, code, requestID, res, verdict)
}

// Render 是供 /waf/deny 渲染端点使用的幂等渲染方法。
//
// 该端点被 Traefik 的 errors 中间件回源调用，也可能被运维直接访问用于自检；
// 因此它只依赖请求参数（错误码 + 请求标识），不依赖任何请求上下文。
func (w *Writer) Render(rw http.ResponseWriter, requestID, code string) {
	// 归一化 code：既支持错误码字面量，也支持 Traefik errors 中间件传入的数字状态码。
	code = ResolveCode(code)

	headers := rw.Header()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("Cache-Control", "no-store")
	if w.cfg.Version != "" {
		headers.Set(core.HeaderVersion, w.cfg.Version)
	}
	headers.Set(core.HeaderCode, code)
	headers.Set(core.HeaderVerdict, "block")
	if requestID != "" {
		headers.Set(core.HeaderRequestID, requestID)
	}

	// 渲染端点返回「真实语义」的状态码：Traefik 的 errors 中间件以该响应为准，
	// 从而让调用方看到 403/429 而不是被代理统一改写后的状态码。
	rw.WriteHeader(StatusForCode(code))
	w.writeBody(rw, code, requestID, nil, "block")
}

// statusFor 计算本次响应应使用的 HTTP 状态码。
func (w *Writer) statusFor(code string, res *core.Result) int {
	if w.cfg.ForceHTTPStatus > 0 {
		return w.cfg.ForceHTTPStatus
	}
	if res != nil && res.Verdict == core.VerdictAllow {
		return http.StatusOK
	}
	return StatusForCode(code)
}

// writeBody 序列化并写出 JSON 错误体。
//
// 序列化失败属于程序缺陷（结构体不含任何不可编码类型），此处不再回退文本错误，
// 以避免「错误响应本身又出错」导致的响应体污染。
func (w *Writer) writeBody(rw http.ResponseWriter, code, requestID string, res *core.Result, verdict string) {
	body := ErrorBody{
		Code:      code,
		Message:   w.messageFor(code),
		RequestID: requestID,
		Timestamp: w.clock.Now().Format(time.RFC3339Nano),
	}
	if w.cfg.IncludeDetails && res != nil {
		body.Details = &ErrorDetails{
			Verdict: verdict,
			Check:   res.Check,
			RuleID:  firstRuleID(res),
			Score:   res.Score,
		}
	}
	encoder := json.NewEncoder(rw)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

// messageFor 返回错误码对应的中文文案：优先取配置自定义文案，其次取内置默认文案。
func (w *Writer) messageFor(code string) string {
	if message, ok := w.cfg.Messages[code]; ok && message != "" {
		return message
	}
	if message, ok := config.Default().Responder.Messages[code]; ok {
		return message
	}
	return "请求被安全策略拦截"
}

// resolveCode 解析最终对外错误码：优先使用校验单元显式指定的错误码。
func (w *Writer) resolveCode(res *core.Result) string {
	if res == nil {
		return config.CodeBlocked
	}
	if res.Code != "" {
		return res.Code
	}
	if res.Verdict == core.VerdictAllow {
		return ""
	}
	return CodeForVerdict(res.Verdict)
}

// firstRuleID 返回结论中首个命中的规则标识。
func firstRuleID(res *core.Result) string {
	if res == nil || len(res.Findings) == 0 {
		return ""
	}
	return res.Findings[0].RuleID
}
