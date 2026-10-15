package core

import "fmt"

// Verdict 是校验单元给出的判定结论。
//
// 语义约定（串联语义见设计文档 §7.4）：
//   - VerdictContinue / VerdictObserve 不短路，继续执行后续校验单元；
//   - VerdictAllow 短路并放行；
//   - 其余取值短路并返回对应错误响应。
type Verdict int

const (
	// VerdictContinue 表示本校验单元没有结论，交由后续校验单元继续判断。
	VerdictContinue Verdict = iota
	// VerdictAllow 表示显式放行，立即短路整条链（例如命中 IP 白名单）。
	VerdictAllow
	// VerdictObserve 表示命中但仅记录（DetectionOnly 旁路观察模式），不阻断请求。
	VerdictObserve
	// VerdictBlock 表示拦截，对外返回 403 与 JSON 错误体。
	VerdictBlock
	// VerdictDrop 表示丢弃连接。本方案为 forward-auth 前置校验，无法真正断开连接，
	// 因此对外行为与 VerdictBlock 一致（403），差异仅体现在日志与指标上。
	VerdictDrop
	// VerdictUnauthorized 表示需要身份认证，对外返回 401 并可携带 WWW-Authenticate。
	VerdictUnauthorized
	// VerdictRateLimited 表示触发限速，对外返回 429 并携带 Retry-After。
	VerdictRateLimited
	// VerdictBadRequest 表示请求不符合安全要求（例如请求体超限），对外返回 400。
	VerdictBadRequest
	// VerdictChallenge 表示需要人机校验，预留给后续阶段，当前不产生该结论。
	VerdictChallenge
	// VerdictUnavailable 表示检测服务不可用（失败关闭），对外返回 503。
	VerdictUnavailable
)

// verdictName 是判定结论到名称的映射，用于日志、指标与配置摘要。
var verdictName = map[Verdict]string{
	VerdictContinue:     "continue",
	VerdictAllow:        "allow",
	VerdictObserve:      "observe",
	VerdictBlock:        "block",
	VerdictDrop:         "drop",
	VerdictUnauthorized: "unauthorized",
	VerdictRateLimited:  "ratelimit",
	VerdictBadRequest:   "bad_request",
	VerdictChallenge:    "challenge",
	VerdictUnavailable:  "unavailable",
}

// String 返回判定结论的小写名称，用于 JSON 日志字段与 Prometheus 标签。
func (v Verdict) String() string {
	if name, ok := verdictName[v]; ok {
		return name
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}

// IsShortCircuit 判断该判定是否会中断串联链。
//
// 只有 VerdictContinue 与 VerdictObserve 会继续执行后续校验单元，
// 其余判定均视为终态（详见设计文档 §7.4 的合并规则）。
func (v Verdict) IsShortCircuit() bool {
	return v != VerdictContinue && v != VerdictObserve
}

// IsBlocking 判断该判定是否属于「拒绝类」结论，用于指标与封禁触发条件判断。
//
// 注意：VerdictObserve 虽然命中了规则，但不算拒绝类结论。
func (v Verdict) IsBlocking() bool {
	switch v {
	case VerdictBlock, VerdictDrop, VerdictUnauthorized, VerdictRateLimited,
		VerdictBadRequest, VerdictChallenge, VerdictUnavailable:
		return true
	default:
		return false
	}
}
