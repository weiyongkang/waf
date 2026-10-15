// Package notify 实现告警外送（需求 P1-7）：抽象接口 + 多实现并联扇出 + 聚合抑制。
//
// 为什么把告警外送做成独立包而不是塞进 server：
//
//  1. **旁路属性**：告警外送是「观察与通知」，绝不能影响请求判定。放在独立包里，
//     可以用队列 + 工作协程把「投递」与「送达」彻底隔离（见 manager.go）。
//
//  2. **可替换性**：通道实现差异极大（HTTP、syslog、SMTP），但它们对上游只有
//     一个契约：`Sender.Send(ctx, alert)`。新增通道不需要改动任何既有代码，
//     只需注册一个新的实现类型（需求 R5：抽象接口 + 多实现 + 可配置）。
//
//  3. **并联语义**：多个通道之间是并联（扇出）关系，一个通道失败不得影响其它通道，
//     也不得影响告警的其余处理路径。这一语义由 Manager 统一保证，
//     而不是指望每个通道实现自己小心处理。
//
// 与 core 的关系：core 只定义 `Alert`（事件）与 `AlertSink`（入口接口），
// 本包提供 `AlertSink` 的实现，因此 core 不会反向依赖本包（依赖倒置）。
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// Sender 是「把一条告警送进某个通道」的实现接口。
//
// 实现方必须遵守的约定：
//   - Send 必须在 ctx 超时后立即返回（不允许无限等待外部系统）；
//   - Send 必须并发安全（Workers > 1 时同一通道可能被并发调用）；
//   - Send 返回错误表示本条告警送达失败，Manager 会按 notify.max_attempts 重试；
//   - Close 必须幂等，且不得阻塞（Manager 在关停时会对它加超时）。
type Sender interface {
	// Name 返回通道实例名（用于日志与指标标签）。
	Name() string
	// Type 返回实现类型名（用于日志与排障）。
	Type() string
	// Send 送达一条告警。
	Send(ctx context.Context, alert core.Alert) error
	// Close 释放通道持有的资源（连接、文件描述符等）。
	Close() error
}

// Instance 是通道声明的实现视图。
//
// 为什么不直接传 config.NotifierConfig：本包是被依赖方，让通道实现依赖 config
// 会把「配置结构」与「通道实现」绑死。这里用最小视图承载必要字段，
// 由 cmd/waf 在装配阶段完成映射（与 core.EngineSettings 的做法一致）。
type Instance struct {
	// Name 是通道实例名，必须唯一。
	Name string
	// Type 是实现类型名。
	Type string
	// Settings 是通道私有配置片段（各实现用 core.DecodeSettings 解析）。
	Settings map[string]any
}

// Deps 是通道实现的依赖集合。
type Deps struct {
	// Logger 是系统日志器，用于记录通道自身的连接失败等信息；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标接口，供通道实现记录自身指标；为 nil 时使用空实现。
	Metrics core.MetricsRecorder
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
	// Hostname 是当前实例的主机名，写入告警内容便于区分多实例。
	Hostname string
	// Version 是当前构建版本，写入告警内容。
	Version string
	// Timeout 是 notify.timeout（单次送达超时），通道可以在自己的 settings 里覆盖。
	Timeout time.Duration
}

// LoggerOr 返回日志器；未注入时返回一个丢弃全部输出的兜底日志器。
func (d Deps) LoggerOr() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// MetricsOr 返回指标接口；未注入时返回空实现。
func (d Deps) MetricsOr() core.MetricsRecorder {
	if d.Metrics != nil {
		return d.Metrics
	}
	return core.NoopMetrics{}
}

// ClockOr 返回时间源；未注入时返回系统时钟。
func (d Deps) ClockOr() core.Clock {
	if d.Clock != nil {
		return d.Clock
	}
	return core.SystemClock{}
}

// TimeoutOr 返回单次送达超时；未配置时回落到 5 秒。
func (d Deps) TimeoutOr() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return defaultSendTimeout
}

// defaultSendTimeout 是未配置超时时的兜底值。
//
// 必须有兜底：没有超时的外送会让工作协程永久卡死在一个不可达的外部系统上，
// 表现为「告警通道静默失效」（队列逐渐堆积直到开始丢弃）。
const defaultSendTimeout = 5 * time.Second

// discardWriter 是丢弃全部写入的 io.Writer，仅用于兜底日志器。
type discardWriter struct{}

// Write 丢弃全部写入并报告成功。
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Factory 依据通道声明构造实现。
type Factory func(inst Instance, deps Deps) (Sender, error)

// 注册表：实现类型 -> 构造函数（编译期装配，不使用 Go plugin 包，
// 以保证 CGO_ENABLED=0 下的静态单二进制交付，与 core.RegisterCheck 同一思路）。
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Factory)
)

// Register 登记一种告警通道实现。
//
// 只应在通道包的 init 函数中调用；重复登记会 panic（编译期装配错误必须立刻暴露）。
func Register(typeName string, factory Factory) {
	if typeName == "" {
		panic("notify: Register 的类型名不能为空")
	}
	if factory == nil {
		panic(fmt.Sprintf("notify: Register(%q) 的构造函数不能为 nil", typeName))
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[typeName]; exists {
		panic(fmt.Sprintf("notify: 通道类型 %q 被重复注册", typeName))
	}
	registry[typeName] = factory
}

// New 依据通道声明构造实现。
//
// 未注册的类型直接返回错误（fail fast）：配置里写了 type 却没有对应实现，
// 属于部署事故（例如忘记在 cmd/waf/plugins.go 里空白导入），
// 必须在启动阶段暴露，而不是等第一条告警需要外送时才发现。
func New(inst Instance, deps Deps) (Sender, error) {
	registryMu.RLock()
	factory, ok := registry[inst.Type]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("告警通道类型 %q 未注册（可用类型：%v）", inst.Type, RegisteredTypes())
	}
	sender, err := factory(inst, deps)
	if err != nil {
		return nil, fmt.Errorf("构造告警通道 %q(type=%s) 失败：%w", inst.Name, inst.Type, err)
	}
	if sender == nil {
		return nil, fmt.Errorf("告警通道 %q(type=%s) 的构造函数返回了空实例", inst.Name, inst.Type)
	}
	return sender, nil
}

// RegisteredTypes 返回已注册的全部通道类型名，按字典序排列。
//
// 用于配置错误提示与 `check-config` 输出，帮助运维发现类型名拼写错误。
func RegisteredTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]string, 0, len(registry))
	for name := range registry {
		types = append(types, name)
	}
	sort.Strings(types)
	return types
}
