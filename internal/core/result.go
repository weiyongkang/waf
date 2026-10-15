package core

import "time"

// BanRequest 是校验单元请求写入封禁名单的动作描述。
//
// 注意：按需求 R18，封禁只在 WAF 内部生效（写入共享存储的名单），
// 绝不产生任何系统防火墙操作（不调用 iptables / firewalld / ufw / nftables）。
type BanRequest struct {
	// Key 是封禁键，例如 ip:1.2.3.4 或 ip:1.2.3.4|path:/api/user。
	//
	// 键必须由 internal/ban 的维度构造函数产出（见 ban.KeyForScope），
	// 否则会出现「写入的键与查询的键不一致」的静默失效。
	Key string
	// Scope 是封禁键维度（client_ip / client_ip+site / client_ip+path / client_ip+method）。
	//
	// 该字段只影响日志与指标的口径（按维度统计封禁量），不参与键的构造；
	// 为空时由封禁管理器按主维度 ban.ban_key 兜底。
	Scope string
	// TTL 是封禁时长；为零时由 ban.default_ttl 兜底，并受 ban.max_ttl 限制。
	TTL time.Duration
	// Reason 是封禁原因，写入名单值以便运维排查。
	Reason string
	// RuleID 是触发封禁的规则标识。
	RuleID string
}

// Result 是校验单元的输出结论。
//
// 一个校验单元可能同时做多件事：给出判定、累加评分、记录命中、请求封禁、触发告警。
// 因此 Result 不是单一枚举，而是一个「动作集合」，由 pipeline 统一合并（见设计文档 §7.4）。
type Result struct {
	// Verdict 是判定结论；零值 VerdictContinue 表示不产生结论。
	Verdict Verdict
	// Code 是对外错误码（例如 WAF_BLOCKED）。为空时由 responder 依据 Verdict 推导默认值。
	Code string
	// Message 是对外错误消息（中文）；为空时由 responder 依据 Code 取配置中的默认文案。
	Message string
	// RetryAfter 用于限速场景，非零时写入 Retry-After 响应头。
	RetryAfter time.Duration
	// Score 是本次结论累加的异常评分增量。
	Score int
	// Findings 是本次结论收集到的命中明细。
	Findings []Finding
	// WouldBlock 表示「旁路观察模式下本应拦截」（需求 P1-6）。
	//
	// 语义：仅当引擎处于 detection_only 且命中证据已越过阈值时为 true，
	// 此时 Verdict 仍是放行（不拦截是观察模式的既定行为）。
	// 该字段是「若拦截清单」的唯一数据来源，pipeline 会据此写访问日志与指标。
	WouldBlock bool
	// WouldBlockReason 是本应拦截的原因（例如 "评分 12 >= 阈值 5；规则 942100"）。
	WouldBlockReason string
	// Bans 是本次结论请求写入的封禁动作。
	Bans []BanRequest
	// Alerts 是本次结论请求外送的告警。
	Alerts []Alert
	// Check 是产生该结论的校验单元实例名，用于日志与指标定位。
	Check string
	// Err 是校验单元自身运行期的错误（例如共享存储不可用）。
	// 该字段非空时，pipeline 会按该实例的 on_error 策略处理。
	Err error
}

// NewResult 构造一个携带判定结论的 Result，并统一填充校验单元名。
func NewResult(check string, verdict Verdict) *Result {
	return &Result{Check: check, Verdict: verdict}
}

// WithScore 追加异常评分增量并返回自身，便于链式构造。
func (r *Result) WithScore(score int) *Result {
	r.Score += score
	return r
}

// AddFinding 追加一条命中明细并同步累加其评分。
func (r *Result) AddFinding(f Finding) *Result {
	r.Findings = append(r.Findings, f)
	r.Score += f.Score
	return r
}

// AddBan 追加一个封禁动作请求。
func (r *Result) AddBan(ban BanRequest) *Result {
	r.Bans = append(r.Bans, ban)
	return r
}

// AddAlert 追加一条告警请求。
func (r *Result) AddAlert(alert Alert) *Result {
	r.Alerts = append(r.Alerts, alert)
	return r
}

// IsEmpty 判断该结果是否不含任何有效信息，用于 pipeline 跳过无用合并。
func (r *Result) IsEmpty() bool {
	if r == nil {
		return true
	}
	return r.Verdict == VerdictContinue && r.Score == 0 &&
		len(r.Findings) == 0 && len(r.Bans) == 0 && len(r.Alerts) == 0 && r.Err == nil &&
		!r.WouldBlock
}

// MarkWouldBlock 把结论标记为「旁路观察模式下本应拦截」。
//
// 之所以提供方法而不是让调用方直接赋值：本应拦截的判定必须同时带上原因，
// 否则「若拦截清单」里只有一堆没有解释的记录，运维无法据此压误报。
func (r *Result) MarkWouldBlock(reason string) *Result {
	r.WouldBlock = true
	r.WouldBlockReason = reason
	return r
}
