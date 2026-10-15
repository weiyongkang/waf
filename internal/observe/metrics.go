package observe

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metrics 是 core.MetricsRecorder 的 Prometheus 实现。
//
// 全部指标名与标签集在本文件中集中定义，业务代码不得直接引用具体指标名——
// 这样未来重命名指标或调整标签时，改动范围被限制在本文件内。
//
// 标签基数说明（重要）：site / check / verdict / scope / store 的取值都来自
// 配置文件或固定枚举，基数有界；rule_id 的取值来自规则库，CRS 全量规则也只有
// 数千条，同样有界。因此这里不需要额外的基数保护。
type metrics struct {
	// requests 按「站点 + 最终结论」统计请求量，是最上层的业务看板指标。
	requests *prometheus.CounterVec
	// checkDuration 按校验单元统计耗时，用于定位「哪个插件拖慢了整条链」。
	checkDuration *prometheus.HistogramVec
	// checkErrors 按校验单元统计自身错误次数。
	// 该值持续增长说明存在「配置错了但被失败开放兜住」的隐患，必须告警。
	checkErrors *prometheus.CounterVec
	// blocked 按「校验单元 + 规则 ID」统计拦截次数，用于识别主力拦截规则。
	blocked *prometheus.CounterVec
	// bodyBytes 按校验单元统计实际读取并参与检测的请求体字节数。
	bodyBytes *prometheus.CounterVec
	// bodyTruncated 统计请求体超限被截断的次数（部分内容仍参与检测）。
	bodyTruncated prometheus.Counter
	// bodySkipped 统计请求体超限被整体跳过的次数（完全没有参与检测）。
	//
	// 与 bodyTruncated 分开计数：截断与跳过的安全含义完全不同，
	// 合并计数会掩盖「体检测整体失效」这种高危状态。
	bodySkipped prometheus.Counter
	// bodyMissing 统计「要求携带请求体但未收到」的次数。
	bodyMissing prometheus.Counter
	// bans 按封禁维度（如 client_ip、client_ip+site）统计内部封禁次数。
	bans *prometheus.CounterVec
	// denyRenders 统计错误体渲染端点被调用的次数（Traefik errors 中间件回源）。
	denyRenders prometheus.Counter
	// storeErrors 按存储实例统计访问错误次数，是判断共享存储健康度的关键指标。
	storeErrors *prometheus.CounterVec
	// wouldBlock 统计「旁路观察模式下本应拦截」的请求次数（需求 P1-6）。
	//
	// 为什么必须单独一个指标：DetectionOnly 阶段的核心产出就是这份「若拦截」清单，
	// 它直接决定「能否切换到 on 模式」。把它混进 blocked_total 会让看板失去意义
	//（blocked_total 在观察模式下恒为 0，运维会误以为「没有攻击」）。
	wouldBlock *prometheus.CounterVec
	// ruleReloads 统计规则热加载结果，标签为 result（success / failure）。
	ruleReloads *prometheus.CounterVec
	// alerts 统计告警外送结果，标签为 notifier（通道实例名）与 result。
	//
	// result 取 sent / failed / suppressed / dropped：抑制是设计内行为、
	// 丢弃说明队列被打满（需要调大 queue_size）、失败才是通道故障信号。
	// 三者混在一起会让「告警通道到底健不健康」无法判断。
	alerts *prometheus.CounterVec
	// buildInfo 暴露构建版本信息，值恒为 1。
	buildInfo *prometheus.GaugeVec
}

// newMetrics 构造全部采集器。
func newMetrics(namespace, version, commit string) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "WAF 处理的鉴权请求总数，按站点与最终判定结果分组。",
		}, []string{"site", "verdict"}),

		checkDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "check_duration_seconds",
			Help:      "单个校验单元的执行耗时（秒），按校验单元名分组。",
			Buckets:   checkDurationBuckets,
		}, []string{"check"}),

		checkErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "check_errors_total",
			Help:      "校验单元自身发生错误的次数（结果为失败开放/关闭之前），按校验单元名分组。",
		}, []string{"check"}),

		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "blocked_total",
			Help:      "被拦截的请求次数，按校验单元名与规则 ID 分组。",
		}, []string{"check", "rule_id"}),

		bodyBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "body_bytes_total",
			Help:      "实际读取并参与检测的请求体字节数，按校验单元名分组。",
		}, []string{"check"}),

		bodyTruncated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "body_truncated_total",
			Help:      "请求体超过 max_bytes 被截断的次数（截断后的部分内容仍参与检测）。",
		}),

		bodySkipped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "body_skipped_total",
			Help:      "请求体超过 max_bytes 且 on_exceed=skip 而整体跳过体检测的次数。",
		}),

		bodyMissing: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "body_missing_total",
			Help:      "要求携带请求体（body.mode=required）但未收到的次数。",
		}),

		bans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bans_total",
			Help:      "WAF 内部封禁名单的新增次数，按封禁维度分组（不含任何系统防火墙操作）。",
		}, []string{"scope"}),

		denyRenders: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "deny_render_total",
			Help:      "JSON 错误体渲染端点被调用的次数。",
		}),

		storeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "store_errors_total",
			Help:      "共享存储访问错误次数，按存储实例名分组。",
		}, []string{"store"}),

		wouldBlock: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "would_block_total",
			Help:      "旁路观察模式下本应被拦截的请求次数，按校验单元名与规则 ID 分组。",
		}, []string{"check", "rule_id"}),

		ruleReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rule_reload_total",
			Help:      "规则热加载次数，按结果分组（success / failure）。",
		}, []string{"result"}),

		alerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "alert_total",
			Help:      "告警外送次数，按通道实例与结果分组（sent / failed / suppressed / dropped）。",
		}, []string{"notifier", "result"}),
	}

	// 构建信息恒为 1，通过 version / commit 标签承载内容。
	// 这是 Prometheus 生态确认「线上跑的是哪个版本」的标准做法：
	// 用值恒为 1 的时间序列 + 标签，而不是把版本号塞进指标值（值无法做区间查询）。
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "WAF 构建信息，值恒为 1；version / commit 标签标识当前构建。",
	}, []string{"version", "commit"})
	buildInfo.WithLabelValues(version, commit).Set(1)

	m.buildInfo = buildInfo
	return m
}

// collectors 返回需要登记的采集器列表。
func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.requests,
		m.checkDuration,
		m.checkErrors,
		m.blocked,
		m.bodyBytes,
		m.bodyTruncated,
		m.bodySkipped,
		m.bodyMissing,
		m.bans,
		m.denyRenders,
		m.storeErrors,
		m.wouldBlock,
		m.ruleReloads,
		m.alerts,
		m.buildInfo,
	}
}

// IncWouldBlock 记录一次「旁路观察模式下本应拦截」。
func (m *metrics) IncWouldBlock(check, ruleID string) {
	m.wouldBlock.WithLabelValues(check, ruleID).Inc()
}

// IncRuleReload 记录一次规则热加载结果。
func (m *metrics) IncRuleReload(result string) {
	m.ruleReloads.WithLabelValues(result).Inc()
}

// IncAlert 记录一次告警外送结果。
func (m *metrics) IncAlert(notifier, result string) {
	m.alerts.WithLabelValues(notifier, result).Inc()
}

// IncRequest 记录一次请求及其最终判定。
func (m *metrics) IncRequest(site, verdict string) {
	m.requests.WithLabelValues(site, verdict).Inc()
}

// ObserveCheckDuration 记录单个校验单元的耗时（秒）。
func (m *metrics) ObserveCheckDuration(check string, seconds float64) {
	m.checkDuration.WithLabelValues(check).Observe(seconds)
}

// IncCheckError 记录校验单元自身错误次数。
func (m *metrics) IncCheckError(check string) {
	m.checkErrors.WithLabelValues(check).Inc()
}

// IncBlocked 记录一次拦截。
func (m *metrics) IncBlocked(check, ruleID string) {
	m.blocked.WithLabelValues(check, ruleID).Inc()
}

// AddBodyBytes 记录读取的请求体字节数。
//
// int64 -> float64 的转换在 2^53 字节（约 8 PiB）以下精确无损，
// 远超单进程生命周期内可能读取的请求体总量，因此精度不构成问题。
func (m *metrics) AddBodyBytes(check string, bytes int64) {
	if bytes <= 0 {
		return
	}
	m.bodyBytes.WithLabelValues(check).Add(float64(bytes))
}

// IncBodyTruncated 记录请求体被截断的次数。
func (m *metrics) IncBodyTruncated() {
	m.bodyTruncated.Inc()
}

// IncBodySkipped 记录请求体被整体跳过的次数。
func (m *metrics) IncBodySkipped() {
	m.bodySkipped.Inc()
}

// IncBodyMissing 记录「要求携带请求体但未收到」的次数。
func (m *metrics) IncBodyMissing() {
	m.bodyMissing.Inc()
}

// IncBan 记录一次内部封禁。
func (m *metrics) IncBan(scope string) {
	m.bans.WithLabelValues(scope).Inc()
}

// IncDenyRender 记录一次 JSON 错误体渲染端点调用。
func (m *metrics) IncDenyRender() {
	m.denyRenders.Inc()
}

// IncStoreError 记录共享存储访问错误次数。
func (m *metrics) IncStoreError(store string) {
	m.storeErrors.WithLabelValues(store).Inc()
}
