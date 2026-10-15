package coraza

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/rules"
)

// reloader 是「支持热加载的检测引擎实例」。
//
// 设计要点：
//
//  1. **原子替换**：内部持有 atomic.Pointer[Check]，重载时先完整构建新实例，
//     构建成功才切换指针。任意时刻正在处理的请求都能拿到「完整可用」的引擎，
//     不会读到半个实例（需求 P1-2：加载失败保留旧引擎）。
//
//  2. **失败保留旧引擎**：重建失败只记录错误日志与失败指标，不改变当前引擎。
//     规则发布出错时线上防护不会中断——这是「热加载」与「重启换规则」的本质区别。
//
//  3. **去抖动与串行**：监听器自身带去抖动（见 rules.Watcher），
//     且重载在同一协程内顺序执行，天然不会并发重建（重建会读磁盘并编译规则，较重）。
type reloader struct {
	// name / phase / order 与底层实例一致，热加载不改变这些「结构性属性」。
	name  string
	phase core.Phase
	order int

	// current 是当前生效的引擎实例。
	current atomic.Pointer[Check]
	// inst / deps 是重建所需的输入，重建走与启动完全相同的装配路径。
	inst core.InstanceConfig
	deps *core.Deps
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
	// watcher 是文件监听器。
	watcher *rules.Watcher
	// reloads 记录累计重载次数（含失败），用于日志与排障。
	reloads atomic.Int64
}

// newReloader 包装一个已构建完成的实例并启动文件监听。
func newReloader(inst core.InstanceConfig, deps *core.Deps, check *Check) (core.Check, error) {
	hot := deps.Engine.HotReload

	watcher, err := rules.NewWatcher(rules.WatchConfig{
		Dirs:        check.watchDirs,
		Include:     check.watchInclude,
		DataInclude: check.watchData,
		Interval:    hot.PollInterval,
		Debounce:    hot.Debounce,
		MarkerFile:  hot.MarkerFile,
		Logger:      deps.SystemLoggerOr(),
	})
	if err != nil {
		return nil, fmt.Errorf("实例 %q 的规则热加载监听器构造失败：%w", inst.Name, err)
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

	loader.logger.Info("规则热加载已启用",
		"instance", check.name,
		"dirs", check.watchDirs,
		"poll_interval", hot.PollInterval.String(),
		"debounce", hot.Debounce.String(),
		"marker_file", hot.MarkerFile,
	)
	watcher.Start(context.Background(), loader.reload)
	return loader, nil
}

// reload 重建引擎并原子替换。
func (r *reloader) reload() {
	r.reloads.Add(1)

	rebuilt, err := buildCheck(r.inst, r.deps)
	if err != nil {
		// 失败保留旧引擎：绝不允许「规则发布出错导致线上失去防护」。
		r.metrics.IncRuleReload("failure")
		r.logger.Error("规则热加载失败，继续使用旧的检测引擎",
			"instance", r.name,
			"error", err.Error(),
			"reloads", r.reloads.Load(),
		)
		return
	}

	previous := r.current.Swap(rebuilt)
	// 旧实例的释放必须是「替换之后」：先释放再替换会让并发中的请求读到已关闭的实例。
	// Coraza 的 WAF 实例本身无需显式释放，这里仍然调用 Close 以保持「资源由创建者释放」的约定。
	if previous != nil {
		if err := previous.Close(); err != nil {
			r.logger.Warn("旧检测引擎实例释放失败", "instance", r.name, "error", err.Error())
		}
	}

	r.metrics.IncRuleReload("success")
	r.logger.Info("规则热加载成功，检测引擎已原子替换",
		"instance", r.name,
		"rule_source", rebuilt.ruleSource,
		"rule_files", rebuilt.ruleFiles,
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

// DefaultOnError 转发底层实例的默认失败策略。
func (r *reloader) DefaultOnError() string {
	if check := r.current.Load(); check != nil {
		return check.DefaultOnError()
	}
	return core.OnErrorBlock
}

// Evaluate 用当前生效的引擎实例执行检测。
func (r *reloader) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	check := r.current.Load()
	if check == nil {
		// 理论上不可达（构造后立即 Store）。这里按失败关闭处理：
		// 没有引擎就等于没有任何检测能力，放行等于关闭防护。
		return nil, fmt.Errorf("检测引擎实例 %q 尚未就绪", r.name)
	}
	return check.Evaluate(rctx)
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
