// Package observe 提供基于 Prometheus 的指标采集与暴露实现。
//
// 设计要点（对应需求 R6「全部能力可关闭」、R13「限额可配置」与设计文档 §7.4）：
//
//  1. 整体可关闭：metrics.enabled=false 时本包不创建任何采集器、不注册任何路由，
//     并返回 noop 写入器，做到「关闭即零开销」。
//  2. 接口隔离：业务代码只依赖 core.MetricsRecorder，本包是它的其中一个实现。
//     未来若要换成 OpenTelemetry / StatsD，只需新增一个实现并在装配处替换，
//     校验单元与存储层完全不需要改动（需求 R7 抽象接口 + 多实现的同一思路）。
//  3. 独立注册表：使用自建的 prometheus.Registry，而不是全局默认注册表。
//     好处是单元测试可以并行装配、互不污染，也不会与第三方依赖在 init 中
//     调用 MustRegister 的行为互相冲突（重复注册会 panic）。
package observe

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/weiyongkang/waf/internal/core"
)

// DefaultNamespace 是指标名的默认前缀。
const DefaultNamespace = "waf"

// DefaultPath 是指标暴露的默认路径。
const DefaultPath = "/metrics"

// checkDurationBuckets 是「单个校验单元耗时」直方图的分桶边界（单位：秒）。
//
// 之所以不使用 prometheus.DefBuckets：默认分桶从 5ms 起步、上探到 10s，
// 对「单个校验单元」而言粒度过粗——WAF 单次校验绝大多数落在亚毫秒到几十毫秒区间，
// 使用默认分桶会让 P50/P95 全部落进同一个桶，失去观测价值。
var checkDurationBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
}

// Options 是观测组件的装配参数。
type Options struct {
	// Enabled 控制是否真正创建采集器。
	// 为 false 时 Recorder 返回空实现、Handler 返回固定 404。
	Enabled bool
	// Namespace 是全部指标名的统一前缀；为空时取 DefaultNamespace。
	Namespace string
	// Path 是指标暴露路径；为空时取 DefaultPath。
	// 该值只用于日志与自描述，实际路由注册由调用方（server）按同一取值完成。
	Path string
	// Version 与 Commit 写入 waf_build_info 指标，便于确认线上运行的是哪个构建。
	Version string
	Commit  string
	// Logger 是系统日志器，可为 nil。
	Logger *slog.Logger
}

// Registry 是观测组件的装配结果：指标写入器 + 暴露端点。
//
// 之所以把两者打包在一起返回：它们必须成对装配——只有写入器没有端点等于白采集，
// 只有端点没有写入器则会暴露一堆恒为 0 的序列。由一次构造同时产出可以避免错配。
type Registry struct {
	// recorder 是指标写入器；未启用时为空实现。
	recorder core.MetricsRecorder
	// handler 是指标暴露端点；未启用时返回 404。
	handler http.Handler
	// enabled 记录是否真正启用了指标采集，供装配日志使用。
	enabled bool
}

// New 依据装配参数构造观测组件。
//
// 本函数不会返回错误：Prometheus 采集器的构造在自建注册表下不会失败，
// 唯一的失败点是重复注册，而每次 New 都创建全新注册表，因此不存在该情况。
func New(opts Options) *Registry {
	if !opts.Enabled {
		return &Registry{
			recorder: core.NoopMetrics{},
			handler:  disabledHandler(),
			enabled:  false,
		}
	}

	namespace := opts.Namespace
	if namespace == "" {
		namespace = DefaultNamespace
	}

	registry := prometheus.NewRegistry()
	m := newMetrics(namespace, opts.Version, opts.Commit)

	// 运行时指标与进程指标几乎零成本，且是容器环境排障（GC、协程泄漏、FD 耗尽的）
	// 第一手资料，因此随指标能力一起开启，不单独提供开关。
	register(registry, collectors.NewGoCollector(), opts.Logger)
	register(registry, collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), opts.Logger)
	for _, collector := range m.collectors() {
		register(registry, collector, opts.Logger)
	}

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		// ContinueOnError：个别采集器出错时仍输出其余指标，
		// 避免一个坏采集器让整个 /metrics 变成 500，影响监控告警链路。
		ErrorHandling: promhttp.ContinueOnError,
		Registry:      registry,
	})

	return &Registry{recorder: m, handler: handler, enabled: true}
}

// Recorder 返回指标写入器（未启用时为空实现，可直接使用，无需判空）。
func (r *Registry) Recorder() core.MetricsRecorder {
	if r == nil || r.recorder == nil {
		return core.NoopMetrics{}
	}
	return r.recorder
}

// Handler 返回指标暴露端点（未启用时返回固定 404）。
//
// 返回 404 而不是 200 空体：让探针与抓取器能明确区分「指标未启用」与
// 「指标启用但当前没有任何数据」，避免把配置错误当成正常状态。
func (r *Registry) Handler() http.Handler {
	if r == nil || r.handler == nil {
		return disabledHandler()
	}
	return r.handler
}

// Enabled 报告指标采集是否真正启用。
func (r *Registry) Enabled() bool {
	return r != nil && r.enabled
}

// register 把采集器登记到注册表；失败只记录警告，不影响整体装配。
//
// 之所以容错而不是 fail fast：指标属于可观测性能力，不应因为一个采集器
// 注册冲突就让整个 WAF 启动失败（业务防护的可用性优先于观测数据的完整性）。
func register(registry *prometheus.Registry, collector prometheus.Collector, logger *slog.Logger) {
	if err := registry.Register(collector); err != nil {
		if logger != nil {
			logger.Warn("指标采集器注册失败，已跳过该采集器", "error", err.Error())
		}
	}
}

// disabledHandler 返回「指标未启用」的 404 处理器。
func disabledHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.WriteHeader(http.StatusNotFound)
		_, _ = rw.Write([]byte(`{"code":"WAF_METRICS_DISABLED","message":"指标端点未启用（metrics.enabled=false）"}` + "\n"))
	})
}
