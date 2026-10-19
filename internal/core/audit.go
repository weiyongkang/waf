package core

import "time"

// AuditEntry 是一条请求审计记录。
//
// 审计是旁路数据：写入失败或队列满不得影响请求判定与响应。
type AuditEntry struct {
	// RequestID 是请求标识。
	RequestID string
	// ReceivedAt 是请求开始处理的时间。
	ReceivedAt time.Time
	// Site / ClientIP / Method / Host / Path 描述原始请求。
	Site     string
	ClientIP string
	Method   string
	Host     string
	Path     string
	// URI / Query 是包含查询串的完整 URI 与原始查询串。
	URI   string
	Query string
	// Verdict 是最终判定；Action 是归一化动作（allow / block / observe / honeypot / error）。
	Verdict string
	Action  string
	// HTTPStatus 是对外返回状态码。
	HTTPStatus int
	// Code 是对外错误码。
	Code string
	// RuleID / Check / Score 是首要命中信息。
	RuleID string
	Check  string
	Score  int
	// Target 是触发拦截 / 封禁的检测目标（例如 ARGS:id、REQUEST_URI、client_ip）。
	Target string
	// BanScope 是导致本次拦截的封禁维度（例如 client_ip、client_ip+path）。
	BanScope string
	// Params 是脱敏后的请求参数快照（JSON）；空串表示未采集到参数。
	Params string
	// Duration 是本次鉴权耗时。
	Duration time.Duration
	// WouldBlock 表示 DetectionOnly 下本应拦截。
	WouldBlock bool
	// Error 是校验或请求还原错误。
	Error string
	// Findings 是完整命中明细。
	Findings []Finding
}

// AuditSink 接收请求审计记录。
//
// 实现必须立即返回，异步写入由实现自行负责。
type AuditSink interface {
	Record(AuditEntry)
}

// NoopAuditSink 丢弃全部审计记录。
type NoopAuditSink struct{}

// Record 不做任何事。
func (NoopAuditSink) Record(AuditEntry) {}
