package responder

import (
	"net/http"
	"strconv"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// CodeForStatus 依据 HTTP 状态码反推对外错误码。
//
// 使用场景（需求 R22）：Traefik 的 errors 中间件只能把 {status} 占位符传给渲染端点，
// 无法传递鉴权响应头（X-WAF-Code），因此 /waf/deny 需要支持「按状态码反推错误码」。
// 该反推表与 StatusForCode 严格互逆，修改其一时必须同步另一处。
func CodeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return config.CodeUnauthorized
	case http.StatusTooManyRequests:
		return config.CodeRateLimited
	case http.StatusBadRequest:
		return config.CodeBadRequest
	case http.StatusServiceUnavailable:
		return config.CodeUnavailable
	default:
		return config.CodeBlocked
	}
}

// ResolveCode 归一化渲染端点收到的 code 参数。
//
// 支持两种输入：
//   - 错误码字面量（例如 WAF_BLOCKED）：直接使用；
//   - 纯数字状态码（例如 429，来自 Traefik errors 中间件的 {status} 占位符）：反推错误码；
//   - 为空：按 WAF_BLOCKED 兜底。
//
// 之所以放在 responder 包而不是 server 包：调用方（server / 后续管理面）都应共享同一套归一化规则。
func ResolveCode(code string) string {
	if code == "" {
		return config.CodeBlocked
	}
	if status, err := strconv.Atoi(code); err == nil {
		return CodeForStatus(status)
	}
	return code
}

// StatusForCode 返回对外错误码对应的 HTTP 状态码。
//
// 映射关系来自设计文档 §1.5 的契约表：
//
//	WAF_BLOCKED      -> 403
//	WAF_UNAUTHORIZED -> 401
//	WAF_RATE_LIMITED -> 429
//	WAF_BAD_REQUEST  -> 400
//	WAF_UNAVAILABLE  -> 503
//
// 未知错误码统一按 403 处理：宁可少暴露信息，也不要因为错误码拼写问题返回 200 造成「静默放行」。
func StatusForCode(code string) int {
	switch code {
	case config.CodeUnauthorized:
		return http.StatusUnauthorized
	case config.CodeRateLimited:
		return http.StatusTooManyRequests
	case config.CodeBadRequest:
		return http.StatusBadRequest
	case config.CodeUnavailable:
		return http.StatusServiceUnavailable
	case config.CodeBlocked:
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

// CodeForVerdict 把判定结论映射为对外错误码。
//
// 之所以需要该映射：校验单元可以不显式指定错误码（只给 Verdict），
// 此时由 responder 统一补齐，避免每个插件重复实现同一张映射表。
func CodeForVerdict(verdict core.Verdict) string {
	switch verdict {
	case core.VerdictUnauthorized:
		return config.CodeUnauthorized
	case core.VerdictRateLimited:
		return config.CodeRateLimited
	case core.VerdictBadRequest:
		return config.CodeBadRequest
	case core.VerdictUnavailable:
		return config.CodeUnavailable
	default:
		// VerdictBlock / VerdictDrop / VerdictChallenge 统一按「被安全策略拦截」表达。
		return config.CodeBlocked
	}
}
