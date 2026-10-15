package core

import "strings"

// Severity 是命中明细的严重级别，沿用 WAF 领域的通用分级。
type Severity string

const (
	// SeverityInfo 表示提示级（通常仅用于观察与统计）。
	SeverityInfo Severity = "info"
	// SeverityLow 表示低危。
	SeverityLow Severity = "low"
	// SeverityMedium 表示中危。
	SeverityMedium Severity = "medium"
	// SeverityHigh 表示高危。
	SeverityHigh Severity = "high"
	// SeverityCritical 表示严重（通常对应可直接利用的远程执行类攻击）。
	SeverityCritical Severity = "critical"
)

// Finding 是单条命中明细，描述「哪个校验单元、命中哪条规则、为什么命中」。
//
// 该结构同时用于三处：JSON 错误体（可选，默认不暴露细节）、访问日志、
// 以及后续阶段的告警外送与攻击态势统计。
type Finding struct {
	// Check 是产生该命中的校验单元实例名（配置中的 name）。
	Check string
	// RuleID 是规则标识；自研校验单元使用稳定的内置标识（例如 ip_blocklist）。
	RuleID string
	// Message 是人类可读的命中说明，必须为中文。
	Message string
	// Severity 是严重级别。
	Severity Severity
	// Score 是该命中带来的异常评分增量（异常评分模式下用于阈值聚合）。
	Score int
	// Data 是命中的关键证据，例如命中的参数名、匹配片段；
	// 必须经过脱敏，禁止写入完整 Cookie / Authorization 等敏感内容。
	Data map[string]string
}

// NewFinding 构造一条命中明细，统一填充校验单元名并给出默认严重级别。
//
// 之所以提供构造函数：避免各插件漏填 Check 字段，导致日志无法定位来源。
func NewFinding(check, ruleID, message string, severity Severity, score int) Finding {
	if severity == "" {
		severity = SeverityMedium
	}
	return Finding{
		Check:    check,
		RuleID:   ruleID,
		Message:  message,
		Severity: severity,
		Score:    score,
	}
}

// severityRanks 是严重级别到序号的映射（序号越大越严重）。
//
// 之所以集中在 core 而不是各插件自行实现：级别比较是「同一套语言」，
// 一旦两处实现不一致，就会出现「threshold 认为够严重、autoban 认为不够」这类
// 只有线上才能发现的割裂。
var severityRanks = map[Severity]int{
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// Rank 返回严重级别的序号（越大越严重）；未知级别返回 0。
func (s Severity) Rank() int {
	return severityRanks[s]
}

// SeverityNames 返回全部严重级别名称（由轻到重），用于错误提示与文档。
//
// 之所以由 core 统一提供：级别清单是「同一套语言」，
// 各插件自行列举会在新增级别时漏改，最终表现为「配置写对了却报非法」。
func SeverityNames() []string {
	return []string{
		string(SeverityInfo),
		string(SeverityLow),
		string(SeverityMedium),
		string(SeverityHigh),
		string(SeverityCritical),
	}
}

// ParseSeverity 解析配置中的严重级别名称（大小写与首尾空白不敏感）。
//
// 返回值 ok 为 false 表示名称非法，调用方应据此在装配阶段 fail fast，
// 而不是静默按「不设门槛」处理——那会让「写了 min_severity 却不生效」难以发现。
func ParseSeverity(name string) (Severity, bool) {
	normalized := Severity(strings.ToLower(strings.TrimSpace(name)))
	if normalized == "" {
		return "", false
	}
	if _, ok := severityRanks[normalized]; !ok {
		return "", false
	}
	return normalized, true
}
