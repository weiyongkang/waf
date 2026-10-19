package core

import (
	"log/slog"
	"time"
)

// Clock 是时间源抽象。
//
// 之所以不直接调用 time.Now()：限速窗口、封禁 TTL、请求耗时统计都需要在
// 单元测试中「伪造时钟」才能稳定复现边界场景（设计文档验收项 A5）。
type Clock interface {
	// Now 返回当前时间。
	Now() time.Time
	// Since 返回自 t 起经过的时长。
	Since(t time.Time) time.Duration
}

// SystemClock 是基于系统时间的默认 Clock 实现。
type SystemClock struct{}

// Now 返回当前系统时间。
func (SystemClock) Now() time.Time { return time.Now() }

// Since 返回自 t 起经过的时长。
func (SystemClock) Since(t time.Time) time.Duration { return time.Since(t) }

// MetricsRecorder 是观测指标写入接口。
//
// 之所以定义接口而不是直接依赖 Prometheus：既便于在测试中使用 noop 实现，
// 也保证「关闭指标」时不引入任何采集开销（需求 R6：全部能力可关闭）。
type MetricsRecorder interface {
	// IncRequest 记录一次请求及其最终判定（标签：站点、判定结论）。
	IncRequest(site, verdict string)
	// ObserveCheckDuration 记录单个校验单元的耗时（秒）。
	ObserveCheckDuration(check string, seconds float64)
	// IncCheckError 记录校验单元自身错误次数。
	IncCheckError(check string)
	// IncBlocked 记录一次拦截（标签：校验单元、规则 ID）。
	IncBlocked(check, ruleID string)
	// AddBodyBytes 记录读取的请求体字节数。
	AddBodyBytes(check string, bytes int64)
	// IncBodyTruncated 记录请求体被截断的次数。
	IncBodyTruncated()
	// IncBodySkipped 记录请求体因超限策略为 skip 而整体跳过体检测的次数。
	//
	// 之所以与「截断」分开计数：截断表示「用部分内容参与检测」，
	// 跳过表示「完全没有参与检测」，两者的安全含义完全不同，不能合并统计。
	IncBodySkipped()
	// IncBodyMissing 记录「要求携带请求体但未收到」的次数。
	IncBodyMissing()
	// IncBan 记录一次内部封禁。
	IncBan(scope string)
	// IncDenyRender 记录一次 JSON 错误体渲染端点调用。
	IncDenyRender()
	// IncStoreError 记录共享存储访问错误次数。
	IncStoreError(store string)
	// IncWouldBlock 记录一次「旁路观察模式下本应拦截」（DetectionOnly 试运行的核心产出）。
	IncWouldBlock(check, ruleID string)
	// IncRuleReload 记录一次规则热加载结果（success / failure）。
	IncRuleReload(result string)
	// IncAlert 记录一次告警外送结果。
	//
	// result 取值：sent（成功送达）/ failed（送达失败）/ suppressed（被聚合抑制）/
	// dropped（队列已满而被丢弃）。之所以把「抑制」与「失败」分开：
	// 抑制是设计内行为、失败是故障信号，两者的告警口径完全不同。
	IncAlert(notifier, result string)
}

// NoopMetrics 是 MetricsRecorder 的空实现，用于禁用指标或单元测试。
type NoopMetrics struct{}

// IncRequest 不做任何事。
func (NoopMetrics) IncRequest(string, string) {}

// ObserveCheckDuration 不做任何事。
func (NoopMetrics) ObserveCheckDuration(string, float64) {}

// IncCheckError 不做任何事。
func (NoopMetrics) IncCheckError(string) {}

// IncBlocked 不做任何事。
func (NoopMetrics) IncBlocked(string, string) {}

// AddBodyBytes 不做任何事。
func (NoopMetrics) AddBodyBytes(string, int64) {}

// IncBodyTruncated 不做任何事。
func (NoopMetrics) IncBodyTruncated() {}

// IncBodySkipped 不做任何事。
func (NoopMetrics) IncBodySkipped() {}

// IncBodyMissing 不做任何事。
func (NoopMetrics) IncBodyMissing() {}

// IncBan 不做任何事。
func (NoopMetrics) IncBan(string) {}

// IncDenyRender 不做任何事。
func (NoopMetrics) IncDenyRender() {}

// IncStoreError 不做任何事。
func (NoopMetrics) IncStoreError(string) {}

// IncWouldBlock 不做任何事。
func (NoopMetrics) IncWouldBlock(string, string) {}

// IncRuleReload 不做任何事。
func (NoopMetrics) IncRuleReload(string) {}

// IncAlert 不做任何事。
func (NoopMetrics) IncAlert(string, string) {}

// Limits 是传递给校验单元的容量限额，全部来自配置文件（需求 R13，禁止硬编码）。
type Limits struct {
	// MaxHeaderBytes 是请求头总大小上限（字节）。
	MaxHeaderBytes int64
	// MaxScanTokenBytes 是单个待检测 token 的大小上限（字节），超出部分不参与检测。
	MaxScanTokenBytes int64
	// MaxIntelFileBytes 是威胁情报文件大小上限（字节）。
	MaxIntelFileBytes int64
	// MaxMMDBBytes 是 GeoIP / ASN MaxMind 数据库文件大小上限（字节）。
	MaxMMDBBytes int64
	// MaxConfigFileBytes 是外部配置 / 契约文件（例如 OpenAPI spec）的大小上限（字节）。
	MaxConfigFileBytes int64
	// MaxRuleFileBytes 是单个规则文件大小上限（字节）。
	MaxRuleFileBytes int64
	// MaxRulesTotalBytes 是规则集总量上限（字节）。
	MaxRulesTotalBytes int64
}

// Deps 是校验单元的依赖集合，在启动装配阶段一次性构建并注入。
//
// 校验单元通过该结构获取日志、共享存储、指标与时间源，
// 因此不需要任何全局单例，单元测试可以按需替换任意一项。
type Deps struct {
	// SystemLogger 是系统运行日志（进程生命周期、配置、组件状态）。
	SystemLogger *slog.Logger
	// AccessLogger 是请求访问与拦截日志。
	AccessLogger *slog.Logger
	// Stores 是共享存储解析器（限速计数与内部封禁名单）。
	Stores StoreResolver
	// Bans 是内部封禁控制器（查询是否被封禁 + 落地封禁动作）。
	//
	// 之所以与 Stores 分开注入：封禁键的构造、时长裁剪与累进策略属于运维策略，
	// 由 internal/ban 统一提供；插件只通过该接口表达「谁该被封禁」。
	Bans BanController
	// Metrics 是指标写入接口。
	Metrics MetricsRecorder
	// Alerts 是告警外送入口（由 internal/notify 实现）。
	//
	// 之所以通过接口注入而不是让校验单元直接调用 notify 包：
	// 校验单元只负责「产生告警」（把 Alert 放进 Result），
	// 外送策略（并联扇出、聚合抑制、重试）由实现方决定；
	// 同时保证「告警外送未启用」时链路完全不引入任何依赖。
	Alerts AlertSink
	// Clock 是时间源。
	Clock Clock
	// Limits 是容量限额。
	Limits Limits
	// Sites 是已解析的站点策略列表（含默认站点）。
	Sites []*Site
	// Engine 是全局检测引擎配置（type=coraza 的实例从这里读取规则与限额）。
	Engine EngineSettings
	// Version 是当前程序版本，用于响应头与启动日志。
	Version string
}

// SystemLoggerOr 返回系统日志器；未注入时返回一个丢弃全部输出的兜底日志器。
//
// 该兜底仅用于单元测试与极端异常路径，正常运行期必须注入真实日志器。
func (d *Deps) SystemLoggerOr() *slog.Logger {
	if d != nil && d.SystemLogger != nil {
		return d.SystemLogger
	}
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// AccessLoggerOr 返回访问日志器；未注入时返回一个丢弃全部输出的兜底日志器。
func (d *Deps) AccessLoggerOr() *slog.Logger {
	if d != nil && d.AccessLogger != nil {
		return d.AccessLogger
	}
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// MetricsOr 返回指标接口；未注入时返回 noop 实现。
func (d *Deps) MetricsOr() MetricsRecorder {
	if d != nil && d.Metrics != nil {
		return d.Metrics
	}
	return NoopMetrics{}
}

// AlertsOr 返回告警外送入口；未注入时返回一个丢弃全部告警的空实现。
//
// 该兜底让「未启用告警外送」的部署路径完全不需要分支判断：
// 校验单元可以无条件调用 AlertsOr().Notify(...)，未启用时自然无副作用。
func (d *Deps) AlertsOr() AlertSink {
	if d != nil && d.Alerts != nil {
		return d.Alerts
	}
	return NoopAlertSink{}
}

// ClockOr 返回时间源；未注入时返回系统时钟。
func (d *Deps) ClockOr() Clock {
	if d != nil && d.Clock != nil {
		return d.Clock
	}
	return SystemClock{}
}

// discardWriter 是丢弃全部写入的 io.Writer，仅用于兜底日志器。
type discardWriter struct{}

// Write 丢弃全部数据并报告写入成功。
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
