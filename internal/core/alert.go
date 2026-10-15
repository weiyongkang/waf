package core

import "time"

// AlertLevel 是告警级别，取值与日志级别保持一致，便于采集侧统一处理。
type AlertLevel string

const (
	// AlertLevelInfo 表示提示级告警（例如观察模式下的规则命中）。
	AlertLevelInfo AlertLevel = "info"
	// AlertLevelWarn 表示警告级告警（例如自动封禁触发）。
	AlertLevelWarn AlertLevel = "warn"
	// AlertLevelError 表示错误级告警（例如检测引擎不可用、共享存储故障）。
	AlertLevelError AlertLevel = "error"
)

// AlertSink 是告警外送入口（由 internal/notify.Manager 实现）。
//
// 之所以在 core 定义接口而不是让 server 直接依赖 internal/notify：
// ① 避免 core 反向依赖具体实现（依赖倒置，设计文档 §7.2 的抽象接口约定）；
// ② 让「产生告警」与「外送告警」彻底解耦——校验单元只负责把 Alert 放进 Result，
//
//	外送策略（并联扇出、聚合抑制、重试）全部由实现方决定。
//
// 实现方必须**永不阻塞调用方**：告警外送是旁路行为，绝不能拖慢请求判定，
// 更不能因为告警通道不可用而影响 WAF 的判定结果。
type AlertSink interface {
	// Notify 投递一批告警；实现必须立刻返回（内部排队异步外送）。
	Notify(alerts []Alert)
}

// NoopAlertSink 是 AlertSink 的空实现，用于「未启用告警外送」的部署路径。
type NoopAlertSink struct{}

// Notify 丢弃全部告警。
func (NoopAlertSink) Notify([]Alert) {}

// Alert 是待外送的告警事件。
//
// 告警通道（Notifier 的多种实现）是并联关系：一个 Alert 会扇出给所有启用的通道，
// 任一通道失败不得影响其它通道，也不得影响请求判定结果。
type Alert struct {
	// Level 是告警级别。
	Level AlertLevel
	// Title 是告警标题（中文，便于在即时通讯工具中直接阅读）。
	Title string
	// Message 是告警正文（中文）。
	Message string
	// Site 是站点名（多站点场景下用于区分）。
	Site string
	// ClientIP 是触发告警的客户端 IP。
	ClientIP string
	// RequestID 是关联的请求标识，用于在访问日志中反查完整上下文。
	RequestID string
	// Fields 是附加的结构化字段（例如规则 ID、封禁时长）。
	Fields map[string]string
	// At 是告警发生时间。
	At time.Time
}
