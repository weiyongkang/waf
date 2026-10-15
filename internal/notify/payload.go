package notify

import (
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// Payload 是告警外送的标准结构化载荷（HTTP / 邮件正文等复用同一份结构）。
//
// 为什么统一载荷而不是让每个通道自己拼字符串：
//
//  1. 采集侧只需要适配一种结构，新增通道不会带来新的解析逻辑；
//  2. 敏感信息约束只需要实现一次——载荷里**不含**原始请求体与请求头，
//     只带 request_id 这类可用于在访问日志中反查的定位信息（见 Fields 的说明）。
type Payload struct {
	// Level 是告警级别：info / warn / error。
	Level string `json:"level"`
	// Title 是告警标题（中文，可直接阅读）。
	Title string `json:"title"`
	// Message 是告警正文（中文）。
	Message string `json:"message"`
	// Site 是站点名。
	Site string `json:"site,omitempty"`
	// ClientIP 是触发告警的客户端 IP。
	ClientIP string `json:"client_ip,omitempty"`
	// RequestID 是关联请求标识，用于在访问日志中反查完整上下文。
	RequestID string `json:"request_id,omitempty"`
	// Fields 是附加结构化字段（规则 ID、封禁时长等）。
	//
	// 约束：字段值由 WAF 内部生成（规则 ID、评分、方法、URI 等），
	// 不含请求体内容，避免把业务敏感数据外送到第三方通道。
	Fields map[string]string `json:"fields,omitempty"`
	// At 是告警发生时间（RFC3339）。
	At string `json:"at,omitempty"`
	// Host 是产生告警的实例主机名，便于多实例环境下定位来源。
	Host string `json:"host,omitempty"`
	// Version 是 WAF 版本，便于确认告警来自哪个构建。
	Version string `json:"version,omitempty"`
}

// BuildPayload 依据告警事件与依赖信息构造标准载荷。
func BuildPayload(alert core.Alert, deps Deps) Payload {
	at := alert.At
	if at.IsZero() {
		at = deps.ClockOr().Now()
	}

	return Payload{
		Level:     string(alert.Level),
		Title:     alert.Title,
		Message:   alert.Message,
		Site:      alert.Site,
		ClientIP:  alert.ClientIP,
		RequestID: alert.RequestID,
		Fields:    alert.Fields,
		At:        at.Format(time.RFC3339),
		Host:      deps.Hostname,
		Version:   deps.Version,
	}
}

// Summary 生成一行可读摘要（用于 syslog / 邮件主题这类「单行场景」）。
func (p Payload) Summary() string {
	parts := make([]string, 0, 6)
	parts = append(parts, "["+strings.ToUpper(defaultString(p.Level, "info"))+"]", defaultString(p.Title, "WAF 告警"))
	if p.Site != "" {
		parts = append(parts, "站点="+p.Site)
	}
	if p.ClientIP != "" {
		parts = append(parts, "客户端="+p.ClientIP)
	}
	if ruleID := p.Fields["rule_id"]; ruleID != "" {
		parts = append(parts, "规则="+ruleID)
	}
	if p.RequestID != "" {
		parts = append(parts, "request_id="+p.RequestID)
	}
	return strings.Join(parts, " ")
}

// defaultString 返回首选值；为空时返回兜底值。
func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
