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
	"log/slog"
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
	// Target 是触发拦截 / 封禁的检测目标。
	Target string `json:"target,omitempty"`
	// BanScope 是导致本次拦截的封禁维度。
	BanScope string `json:"ban_scope,omitempty"`
	// URI 是触发拦截的完整原始 URI（含查询串）。
	URI string `json:"uri,omitempty"`
	// Score 是累计异常评分。
	Score int `json:"score,omitempty"`
}

// RenderMetadata 是 /waf/deny 渲染端点可回传的拦截上下文。
//
// 代理只能通过查询参数或响应头传递有限信息；缺失字段保持为空，
// 模板仍可正常渲染，不会因为代理版本不同而失败。
type RenderMetadata struct {
	RequestID string
	Code      string
	Target    string
	BanScope  string
	URI       string
}

// Config 是响应渲染配置。
type Config struct {
	// IncludeDetails 决定是否在错误体中输出 Details。
	IncludeDetails bool
	// Messages 是错误码到中文文案的映射（来自配置文件 responder.messages）。
	Messages map[string]string
	// Template 是内联 JSON 响应模板；与 TemplateFile 互斥。
	Template string
	// TemplateFile 是外部模板文件路径；与 Template 互斥。
	TemplateFile string
	// MaxBodyBytes 是模板渲染结果上限；<=0 时使用 DefaultMaxBodyBytes。
	MaxBodyBytes int64
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
	// Logger 用于记录模板渲染失败等运行期问题；可为 nil。
	Logger *slog.Logger
}

// Writer 是 JSON 错误体渲染器。
type Writer struct {
	cfg      Config
	clock    core.Clock
	template *responseTemplate
}

// New 构造错误体渲染器。
func New(cfg Config) (*Writer, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	if cfg.Messages == nil {
		cfg.Messages = map[string]string{}
	}
	template, err := newResponseTemplate(cfg)
	if err != nil {
		return nil, err
	}
	return &Writer{cfg: cfg, clock: clock, template: template}, nil
}

// Respond 依据校验结论写出完整响应：状态码、回传响应头与 JSON 错误体。
func (w *Writer) Respond(rw http.ResponseWriter, rctx *core.RequestContext, res *core.Result) {
	// 蜜罐等需要伪造业务响应的结论直接覆盖响应，不能套用全局 JSON 模板。
	// 该分支仍会补齐 WAF 审计响应头，便于代理与访问日志关联同一次请求。
	if res != nil && res.Response != nil {
		w.respondOverride(rw, rctx, res, res.Response)
		return
	}

	code := w.resolveCode(res)
	rctx2 := rctx

	headers := rw.Header()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	// 拦截响应禁止被任何中间层缓存。
	headers.Set("Cache-Control", "no-store")
	// 校验单元附加头（例如本地挑战的 WWW-Authenticate / Set-Cookie）。
	if res != nil {
		for name, value := range res.Headers {
			headers.Set(name, value)
		}
	}
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
		if target := resultTarget(res); target != "" {
			headers.Set(core.HeaderTarget, target)
		}
		if scope := core.ResultBanScope(res); scope != "" {
			headers.Set(core.HeaderBanScope, scope)
		}
		// 限速场景回传 Retry-After，便于客户端与代理侧正确退避。
		if res.RetryAfter > 0 {
			headers.Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds()+0.5)))
		}
		// 401 需要携带认证挑战头，否则浏览器不会弹出认证框。
		if res.Verdict == core.VerdictUnauthorized && headers.Get("WWW-Authenticate") == "" {
			headers.Set("WWW-Authenticate", `Basic realm="waf"`)
		}
	}
	// X-WAF-Code 是响应头方案的核心：代理侧据此渲染对外响应（需求 R22）。
	headers.Set(core.HeaderCode, code)

	status := w.statusFor(code, res)
	rw.WriteHeader(status)
	metadata := RenderMetadata{RequestID: requestID, Code: code, Target: resultTarget(res),
		BanScope: core.ResultBanScope(res)}
	if rctx2 != nil && rctx2.Raw != nil {
		metadata.URI = rctx2.Raw.URI
	}
	w.writeBody(rw, code, status, requestID, rctx2, res, verdict, metadata)
}

// respondOverride 按校验单元提供的响应覆盖写出最终响应。
//
// 设计要点：
//   - 规则自定义的响应头先写入，WAF 审计头后写入，防止规则意外覆盖 X-WAF-* 语义；
//   - 不应用 responder.force_http_status：该开关是为原生 Nginx auth_request
//     只能透传 401/403 设计的；蜜罐的最终状态码由 /waf/deny 渲染端点直接返回，
//     三个代理通道都通过该端点获得规则定义的状态码；
//   - Content-Type / Cache-Control 缺省时才补默认值，规则显式配置优先。
func (w *Writer) respondOverride(rw http.ResponseWriter, rctx *core.RequestContext,
	res *core.Result, override *core.ResponseOverride) {
	headers := rw.Header()
	for name, value := range override.Headers {
		headers.Set(name, value)
	}
	if override.ContentType != "" {
		headers.Set("Content-Type", override.ContentType)
	} else if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "text/plain; charset=utf-8")
	}
	if headers.Get("Cache-Control") == "" {
		headers.Set("Cache-Control", "no-store")
	}
	if w.cfg.Version != "" {
		headers.Set(core.HeaderVersion, w.cfg.Version)
	}
	if rctx != nil {
		headers.Set(core.HeaderRequestID, rctx.RequestID)
		if rctx.Site != nil {
			headers.Set("X-WAF-Site", rctx.Site.Name)
		}
	}
	if res != nil {
		headers.Set(core.HeaderVerdict, res.Verdict.String())
		if ruleID := firstRuleID(res); ruleID != "" {
			headers.Set(core.HeaderRuleID, ruleID)
		}
		if target := resultTarget(res); target != "" {
			headers.Set(core.HeaderTarget, target)
		}
		if scope := core.ResultBanScope(res); scope != "" {
			headers.Set(core.HeaderBanScope, scope)
		}
	}
	// X-WAF-Code 同时承担「这是蜜罐直接响应」的代理侧协议标记，
	// OpenResty 脚本据此在 2xx 分支之前直接回写响应体。
	headers.Set(core.HeaderCode, config.CodeHoneypot)

	status := override.Status
	if status < 200 || status > 599 {
		status = http.StatusOK
	}
	rw.WriteHeader(status)
	if override.Body != "" && status != http.StatusNoContent && status != http.StatusNotModified {
		_, _ = rw.Write([]byte(override.Body))
	}
}

// Render 是供 /waf/deny 渲染端点使用的幂等渲染方法。
//
// 该端点被 Traefik 的 errors 中间件回源调用，也可能被运维直接访问用于自检；
// 因此它只依赖请求参数（错误码 + 请求标识），不依赖任何请求上下文。
func (w *Writer) Render(rw http.ResponseWriter, requestID, code string, metadata ...RenderMetadata) {
	meta := RenderMetadata{RequestID: requestID, Code: code}
	if len(metadata) > 0 {
		meta = metadata[0]
		if meta.RequestID == "" {
			meta.RequestID = requestID
		}
		if meta.Code == "" {
			meta.Code = code
		}
	}
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
	if meta.Target != "" {
		headers.Set(core.HeaderTarget, meta.Target)
	}
	if meta.BanScope != "" {
		headers.Set(core.HeaderBanScope, meta.BanScope)
	}

	// 渲染端点返回「真实语义」的状态码：Traefik 的 errors 中间件以该响应为准，
	// 从而让调用方看到 403/429 而不是被代理统一改写后的状态码。
	status := StatusForCode(code)
	rw.WriteHeader(status)
	meta.Code = code
	w.writeBody(rw, code, status, requestID, nil, nil, "block", meta)
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
func (w *Writer) writeBody(rw http.ResponseWriter, code string, status int, requestID string,
	rctx *core.RequestContext, res *core.Result, verdict string, metadata RenderMetadata) {
	body := ErrorBody{
		Code:      code,
		Message:   w.messageFor(code),
		RequestID: requestID,
		Timestamp: w.clock.Now().Format(time.RFC3339Nano),
	}
	if w.cfg.IncludeDetails && res != nil {
		body.Details = &ErrorDetails{
			Verdict:  verdict,
			Check:    res.Check,
			RuleID:   firstRuleID(res),
			Target:   metadata.Target,
			BanScope: metadata.BanScope,
			URI:      metadata.URI,
			Score:    res.Score,
		}
	}
	if w.template != nil {
		data := w.templateData(code, status, requestID, rctx, res, verdict, body.Details, metadata)
		if payload, err := w.template.Render(data); err == nil {
			_, _ = rw.Write(payload)
			return
		} else if w.cfg.Logger != nil {
			w.cfg.Logger.Warn("响应模板渲染失败，回退到默认 JSON 结构",
				"code", code, "request_id", requestID, "error", err.Error())
		}
	}
	encoder := json.NewEncoder(rw)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

// templateData 构造模板渲染数据。
func (w *Writer) templateData(code string, status int, requestID string,
	rctx *core.RequestContext, res *core.Result, verdict string, details *ErrorDetails,
	metadata RenderMetadata) TemplateData {
	data := TemplateData{
		Code:       code,
		Status:     status,
		Message:    w.messageFor(code),
		RequestID:  requestID,
		Timestamp:  w.clock.Now().Format(time.RFC3339Nano),
		Verdict:    verdict,
		Target:     metadata.Target,
		BanScope:   metadata.BanScope,
		URI:        metadata.URI,
		Messages:   w.cfg.Messages,
		HasDetails: details != nil,
	}
	if details != nil {
		data.Details = *details
	}
	if rctx != nil {
		if rctx.Site != nil {
			data.Site = rctx.Site.Name
		}
		if rctx.Raw != nil {
			data.Path = rctx.Raw.Path
			data.ClientIP = rctx.Raw.ClientIP
		}
	}
	if res != nil {
		data.Check = res.Check
		data.RuleID = firstRuleID(res)
		data.Score = res.Score
		if res.RetryAfter > 0 {
			data.RetryAfter = int(res.RetryAfter.Seconds() + 0.5)
		}
	}
	return data
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

// resultTarget 返回拦截目标；没有证据字段时回落到校验单元名。
func resultTarget(res *core.Result) string {
	if res == nil {
		return ""
	}
	if target := core.ResultTarget(res); target != "" {
		return target
	}
	return res.Check
}
