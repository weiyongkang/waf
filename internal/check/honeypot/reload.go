package honeypot

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
)

// ruleFilePatterns 是蜜罐规则目录的监听范围，与 loadRulesDir 的扩展名过滤保持一致。
var ruleFilePatterns = []string{"*.yaml", "*.yml"}

// reloader 是支持规则目录热加载的蜜罐校验单元。
//
// 设计要点与 coraza 的 reloader 保持一致：
//  1. 原子替换：先完整构建新实例，成功后才切换 atomic.Pointer；
//  2. 失败保留旧规则：规则发布出错时线上仍使用上一版诱饵规则；
//  3. 监听目录递归：与 loadRulesDir 的递归加载语义一致，子目录变更也能发现。
type reloader struct {
	name  string
	phase core.Phase
	order int

	current atomic.Pointer[Check]
	inst    core.InstanceConfig
	deps    *core.Deps

	logger  *slog.Logger
	metrics core.MetricsRecorder
	watcher *rules.Watcher
	reloads atomic.Int64
}

// newReloader 包装已构建完成的蜜罐实例并启动文件监听。
func newReloader(inst core.InstanceConfig, deps *core.Deps, check *Check) (core.Check, error) {
	hot := deps.Engine.HotReload
	watcher, err := rules.NewWatcher(rules.WatchConfig{
		Dirs:       []string{check.rulesDir},
		Include:    ruleFilePatterns,
		Interval:   hot.PollInterval,
		Debounce:   hot.Debounce,
		MarkerFile: hot.MarkerFile,
		Recursive:  true,
		Logger:     deps.SystemLoggerOr(),
	})
	if err != nil {
		return nil, fmt.Errorf("实例 %q 的蜜罐规则热加载监听器构造失败：%w", inst.Name, err)
	}

	loader := &reloader{
		name:    check.name,
		phase:   check.phase,
		order:   check.order,
		inst:    inst,
		deps:    deps,
		logger:  deps.SystemLoggerOr(),
		metrics: deps.MetricsOr(),
		watcher: watcher,
	}
	loader.current.Store(check)

	loader.logger.Info("蜜罐规则热加载已启用",
		"instance", check.name,
		"rules_dir", check.rulesDir,
		"poll_interval", hot.PollInterval.String(),
		"debounce", hot.Debounce.String(),
		"marker_file", hot.MarkerFile,
	)
	watcher.Start(context.Background(), loader.reload)
	return loader, nil
}

// reload 重建蜜罐实例并原子替换。
func (r *reloader) reload() {
	r.reloads.Add(1)

	rebuilt, err := buildCheck(r.inst, r.deps)
	if err != nil {
		// 与 CRS 热加载一致：失败保留旧规则，避免规则发布事故扩大为防护中断。
		r.metrics.IncRuleReload("failure")
		r.logger.Error("蜜罐规则热加载失败，继续使用旧规则",
			"instance", r.name,
			"error", err.Error(),
			"reloads", r.reloads.Load(),
		)
		return
	}

	previous := r.current.Swap(rebuilt)
	if previous != nil {
		if err := previous.Close(); err != nil {
			r.logger.Warn("旧蜜罐规则实例释放失败", "instance", r.name, "error", err.Error())
		}
	}

	r.metrics.IncRuleReload("success")
	r.logger.Info("蜜罐规则热加载成功，规则已原子替换",
		"instance", r.name,
		"rules", len(rebuilt.rules),
		"rules_dir", rebuilt.rulesDir,
		"reloads", r.reloads.Load(),
	)
}

// Name 返回实例名。
func (r *reloader) Name() string { return r.name }

// Type 返回实现类型。
func (r *reloader) Type() string { return Type }

// Phase 返回执行阶段。
func (r *reloader) Phase() core.Phase { return r.phase }

// Order 返回同阶段内的执行顺序。
func (r *reloader) Order() int { return r.order }

// DefaultOnError 返回蜜罐的失败策略默认值。
func (r *reloader) DefaultOnError() string { return core.OnErrorPass }

// Evaluate 用当前生效的规则执行校验。
func (r *reloader) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	check := r.current.Load()
	if check == nil {
		return nil, fmt.Errorf("蜜罐实例 %q 尚未就绪", r.name)
	}
	return check.Evaluate(rctx)
}

// MatchHoneypot 用当前生效的规则执行渲染阶段重匹配。
func (r *reloader) MatchHoneypot(rctx *core.RequestContext) *core.Result {
	check := r.current.Load()
	if check == nil {
		return nil
	}
	return check.MatchHoneypot(rctx)
}

// Close 停止文件监听并释放当前实例。
func (r *reloader) Close() error {
	r.watcher.Stop()
	check := r.current.Load()
	if check == nil {
		return nil
	}
	return check.Close()
}
