package notify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// Policy 是告警外送的公共策略（由配置层的 notify 段映射而来）。
//
// 之所以在本包定义独立结构而不是直接引用 config.NotifyConfig：
// 本包是「通道实现」的被依赖方，通道实现不应该认识配置结构；
// 由 cmd/waf 在装配阶段完成 config -> Policy 的映射，
// 这样「配置新增字段」不会牵动任何一个通道实现（与 core.EngineSettings 同一思路）。
type Policy struct {
	// Enabled 是总开关。关闭时调用方不应构造 Manager，此处仅用于启动日志。
	Enabled bool
	// QueueSize 是告警队列长度（条）。队列把「产生告警」与「送达告警」解耦，
	// 使请求判定路径永远不会等待外部系统。
	QueueSize int
	// Workers 是并发外送协程数。
	Workers int
	// Timeout 是单次送达的超时时间；<=0 时回落到本包默认值。
	Timeout time.Duration
	// MinLevel 是全局最低告警级别（info / warn / error）；留空表示 info。
	MinLevel string
	// SuppressWindow 是全局聚合抑制窗口；0 表示不抑制。
	SuppressWindow time.Duration
	// MaxAttempts 是单条告警的最大尝试次数（含首次）；<=0 时按 1 次处理。
	MaxAttempts int
	// RetryBackoff 是两次尝试之间的固定间隔；0 表示立即重试。
	RetryBackoff time.Duration
	// MaxTrackedKeys 是单个通道抑制表的键上限；<=0 表示不设上限（仅靠窗口过期）。
	//
	// 之所以以「通道」为单位而不是全局一张表：不同通道的门槛与窗口可以不同，
	// 共用一张表会让「A 通道发过了」导致「B 通道不发」，与并联扇出语义矛盾。
	MaxTrackedKeys int
}

// Channel 是一个告警通道的运行声明。
type Channel struct {
	// Instance 是通道声明（名称 / 类型 / 私有配置）。
	Instance Instance
	// MinLevel 是通道级最低告警级别；留空表示继承 Policy.MinLevel。
	MinLevel string
	// SuppressWindow 是通道级抑制窗口；0 表示继承 Policy.SuppressWindow。
	SuppressWindow time.Duration
}

// Options 是 Manager 的构建参数。
type Options struct {
	// Policy 是公共外送策略。
	Policy Policy
	// Channels 是已启用的通道（enabled=false 的通道由调用方在此处过滤掉）。
	Channels []Channel
	// Deps 是通道依赖（日志 / 指标 / 时间源 / 超时）。
	Deps Deps
}

// Result 外送结果的指标标签取值，集中定义避免各处拼写漂移。
const (
	// resultSent 表示成功送达。
	resultSent = "sent"
	// resultFailed 表示重试耗尽后仍失败。
	resultFailed = "failed"
	// resultSuppressed 表示被聚合抑制窗口拦下。
	resultSuppressed = "suppressed"
	// resultDropped 表示队列已满而被丢弃。
	resultDropped = "dropped"
)

// 内部常量。
const (
	// keySeparator 是聚合键的分隔符。选用 ASCII 单元分隔符（US）而不是 '|' 之类：
	// 站点名与标题都可能包含可打印符号，只有不可打印控制字符能保证不会与字段值冲突。
	keySeparator = "\x1f"
	// pruneInterval 是「无上限抑制表」的惰性清理间隔（按写入次数计）。
	//
	// 只在 max_tracked_keys <= 0（运维显式声明不设上限）时使用：
	// 每累计这么多次写入做一次全表扫描，删除已过期条目。取 1024 是
	// 「扫描开销摊薄到可忽略」与「内存回收足够及时」之间的折中。
	pruneInterval = 1024
	// dropLogInterval 是「队列已满」系统日志的最小间隔。
	//
	// 队列打满时告警会产生风暴式丢弃，逐条打日志会把系统日志本身变成压垮磁盘的元凶；
	// 因此丢弃计数交给指标（alert_total{result="dropped"}），日志只做节流提示。
	dropLogInterval = time.Second
)

// Manager 是 AlertSink 的默认实现：并联扇出 + 聚合抑制 + 异步重试。
//
// 并发模型（这是本文件的核心，改动前请先读完）：
//
//		请求协程                队列（有缓冲）           工作协程（Workers 个）
//		Notify(alerts)  --扇出-->  job{alert, channel}  -->  Sender.Send
//		     |                          |                        |
//		  门槛/抑制判定             满则丢弃并计数            失败则按策略重试
//
//	  - 门槛与抑制判定**同步**完成：两者都只是内存比较与哈希查找，代价极低；
//	    同步完成的收益是「被抑制的告警不会占用队列」，队列容量留给真正要发的告警。
//	  - 真正的网络 / 磁盘写入**异步**完成：这是「告警绝不能拖慢请求判定」的落点。
//	  - 扇出是**并联**语义：一个通道失败、变慢甚至阻塞，都不影响其它通道，
//	    因为每个通道的送达都是队列里的独立任务，由不同工作协程并行消费。
type Manager struct {
	policy Policy
	deps   Deps

	channels []*channelState

	// queue 是待送达任务队列；job 已绑定具体通道，因此工作协程无需再做门槛判定。
	queue chan job
	// wg 用于等待全部工作协程退出。
	wg sync.WaitGroup
	// cancel 取消工作协程的上下文（关停时中断在途外送）。
	cancel context.CancelFunc

	// mu 保护 closed 与 queue 的发送，确保「关停与投递」之间不会出现
	// 「向已关闭的 channel 发送」这一致命竞态。
	mu     sync.Mutex
	closed bool
	// closeOnce 保证队列只关闭一次（Close 允许被重复调用）。
	closeOnce sync.Once
	// sendersClosed 保证通道实例只释放一次（通道的 Close 必须幂等，此处再加一道保险）。
	sendersClosed bool

	// dropMu / lastDropLogAt 用于节流「队列已满」的系统日志。
	dropMu        sync.Mutex
	lastDropLogAt time.Time
}

// job 是一次「把某条告警送到某个通道」的任务。
type job struct {
	channel *channelState
	alert   core.Alert
}

// channelState 是通道的运行时状态。
type channelState struct {
	// name 是通道实例名（用于日志与指标标签）。
	name string
	// typ 是实现类型名（用于日志）。
	typ string
	// sender 是通道实现。
	sender Sender
	// minLevel 是门槛解析后的最终取值。
	minLevel core.AlertLevel
	// suppress 是该通道独立的聚合抑制表。
	suppress *suppressStore
}

// NewManager 构造告警外送管理器并按需启动工作协程。
//
// 返回错误意味着「配置或装配有问题」（通道类型未注册、通道自身配置非法、
// 级别门槛拼写错误）。这类问题必须在启动阶段暴露：一个配了却发不出告警的通道，
// 比进程启动失败危险得多。
func NewManager(ctx context.Context, opts Options) (*Manager, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	globalLevel, ok, err := ParseLevel(opts.Policy.MinLevel)
	if err != nil {
		return nil, err
	}
	if !ok {
		// 未配置全局门槛时回落到 info：门槛越低越安全，
		// 「多发一条告警」永远优于「静默丢掉一条告警」。
		globalLevel = core.AlertLevelInfo
	}

	manager := &Manager{
		policy:   opts.Policy,
		deps:     opts.Deps,
		channels: make([]*channelState, 0, len(opts.Channels)),
	}

	for _, declared := range opts.Channels {
		state, err := newChannelState(declared, manager.policy, globalLevel, manager.deps)
		if err != nil {
			// 装配失败时释放已构造的通道，避免泄漏连接 / 文件描述符。
			_ = manager.closeSenders()
			return nil, err
		}
		manager.channels = append(manager.channels, state)
	}

	// 没有通道时退化为「什么都不做」：不启动队列与协程，避免空转。
	if len(manager.channels) == 0 {
		return manager, nil
	}

	queueSize := manager.policy.QueueSize
	if queueSize <= 0 {
		// 队列长度为 0 会让每次投递都直接丢弃（非阻塞发送必然失败），
		// 这是「配了告警却一条发不出」的典型事故，此处强制抬到通道数量级的下限。
		queueSize = len(manager.channels)
	}
	manager.queue = make(chan job, queueSize)

	workers := manager.policy.Workers
	if workers <= 0 {
		workers = 1
	}

	workerCtx, cancel := context.WithCancel(ctx)
	manager.cancel = cancel

	manager.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go manager.runWorker(workerCtx)
	}
	return manager, nil
}

// newChannelState 构造单个通道的运行时状态并完成门槛解析。
func newChannelState(declared Channel, policy Policy, globalLevel core.AlertLevel, deps Deps) (*channelState, error) {
	if strings.TrimSpace(declared.Instance.Name) == "" {
		return nil, errors.New("告警通道实例名不能为空")
	}
	if strings.TrimSpace(declared.Instance.Type) == "" {
		return nil, errors.New("告警通道 " + declared.Instance.Name + " 的实现类型不能为空")
	}

	sender, err := New(declared.Instance, deps)
	if err != nil {
		return nil, err
	}

	minLevel := globalLevel
	if level, set, err := ParseLevel(declared.MinLevel); err != nil {
		_ = sender.Close()
		return nil, err
	} else if set {
		minLevel = level
	}

	window := declared.SuppressWindow
	if window == 0 {
		window = policy.SuppressWindow
	}

	return &channelState{
		name:     declared.Instance.Name,
		typ:      declared.Instance.Type,
		sender:   sender,
		minLevel: minLevel,
		suppress: newSuppressStore(window, policy.MaxTrackedKeys, deps.ClockOr()),
	}, nil
}

// Notify 实现 core.AlertSink：投递一批告警，立即返回，绝不阻塞调用方。
func (m *Manager) Notify(alerts []core.Alert) {
	if m == nil || len(alerts) == 0 || len(m.channels) == 0 {
		return
	}
	for _, alert := range alerts {
		m.dispatch(alert)
	}
}

// dispatch 把一条告警扇出到全部满足条件的通道。
func (m *Manager) dispatch(alert core.Alert) {
	if alert.Level == "" {
		// 未标注级别的告警按 info 处理：级别缺失不应该变成「不发」。
		alert.Level = core.AlertLevelInfo
	}
	now := m.deps.ClockOr().Now()
	if alert.At.IsZero() {
		alert.At = now
	}

	for _, channel := range m.channels {
		if !MeetsLevel(alert.Level, channel.minLevel) {
			continue
		}
		if !channel.suppress.admit(alert, now) {
			m.deps.MetricsOr().IncAlert(channel.name, resultSuppressed)
			continue
		}
		m.enqueue(job{channel: channel, alert: alert})
	}
}

// enqueue 把任务放入队列；队列已满时丢弃并计数，绝不阻塞。
func (m *Manager) enqueue(task job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		// 正在关停：静默丢弃，避免向已关闭的 channel 发送导致 panic。
		m.deps.MetricsOr().IncAlert(task.channel.name, resultDropped)
		return
	}
	select {
	case m.queue <- task:
	default:
		m.deps.MetricsOr().IncAlert(task.channel.name, resultDropped)
		m.logDrop(task.channel.name)
	}
}

// logDrop 以节流方式记录一次「队列已满」的系统日志。
func (m *Manager) logDrop(channelName string) {
	now := m.deps.ClockOr().Now()
	m.dropMu.Lock()
	if !m.lastDropLogAt.IsZero() && now.Sub(m.lastDropLogAt) < dropLogInterval {
		m.dropMu.Unlock()
		return
	}
	m.lastDropLogAt = now
	m.dropMu.Unlock()

	// 注意措辞：这里说明的是「WAF 自身的处理能力」不足，
	// 而不是配置错误，运维的处置动作是上调 notify.queue_size 或削减告警量。
	m.deps.LoggerOr().Warn("告警队列已满，本条告警被丢弃",
		"channel", channelName,
		"queue_size", m.policy.QueueSize,
		"hint", "可上调 notify.queue_size / notify.workers，或提高 notify.min_level 减少告警量")
}

// runWorker 是单个外送协程的主循环。
func (m *Manager) runWorker(ctx context.Context) {
	defer m.wg.Done()
	for task := range m.queue {
		if ctx.Err() != nil {
			// 上下文已取消：剩余任务不再外送，但仍然把队列消费干净，
			// 否则关闭队列后本循环无法退出。
			continue
		}
		m.deliver(ctx, task)
	}
}

// deliver 把一条告警送到一个通道，并按策略重试。
func (m *Manager) deliver(ctx context.Context, task job) {
	attempts := m.policy.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && m.policy.RetryBackoff > 0 {
			if !sleepContext(ctx, m.policy.RetryBackoff) {
				break
			}
		}

		// 每次尝试都单独计时：不共享超时意味着「重试」拿到的是完整的新预算，
		// 这与「外部系统短暂抖动后恢复」的典型场景一致。
		sendCtx, cancel := context.WithTimeout(ctx, m.deps.TimeoutOr())
		err := task.channel.sender.Send(sendCtx, task.alert)
		cancel()

		if err == nil {
			m.deps.MetricsOr().IncAlert(task.channel.name, resultSent)
			return
		}
		lastErr = err

		if ctx.Err() != nil {
			// 进程正在关停：不再重试，直接结束。
			break
		}
	}

	m.deps.MetricsOr().IncAlert(task.channel.name, resultFailed)
	m.deps.LoggerOr().Error("告警外送失败",
		"channel", task.channel.name,
		"type", task.channel.typ,
		"attempts", attempts,
		"alert_title", task.alert.Title,
		"alert_level", string(task.alert.Level),
		"request_id", task.alert.RequestID,
		"error", errorString(lastErr))
}

// Channels 返回启用的通道名列表（用于启动日志与自检）。
func (m *Manager) Channels() []string {
	if m == nil {
		return nil
	}
	names := make([]string, 0, len(m.channels))
	for _, channel := range m.channels {
		names = append(names, channel.name+"("+channel.typ+")")
	}
	return names
}

// ChannelTypes 返回启用通道的实现类型列表（按通道声明顺序，用于自检与排障）。
func (m *Manager) ChannelTypes() []string {
	if m == nil {
		return nil
	}
	types := make([]string, 0, len(m.channels))
	for _, channel := range m.channels {
		types = append(types, channel.typ)
	}
	return types
}

// Close 关闭管理器：停止接收新告警、等待在途任务结束、释放全部通道。
//
// 关停顺序是关键：
//  1. 先置位 closed 并关闭队列 —— 此后 Notify 只会静默丢弃，不会再入队；
//  2. 等待工作协程把队列剩余任务消费完（带超时，超时则取消上下文中断在途外送）；
//  3. 最后释放通道资源 —— 必须确保没有任何协程仍在调用 Sender.Send。
//
// Close 可以重复调用；ctx 为 nil 时使用 Background。
func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		if m.queue != nil {
			close(m.queue)
		}
		m.mu.Unlock()
	})

	if m.queue != nil {
		done := make(chan struct{})
		go func() {
			m.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			// 超时：取消上下文让在途外送立即返回错误，然后等待协程退出。
			// 这一步不会无限等待——Sender 的契约要求「ctx 结束后必须立即返回」。
			if m.cancel != nil {
				m.cancel()
			}
			<-done
		}
	}
	if m.cancel != nil {
		m.cancel()
	}
	return m.closeSenders()
}

// closeSenders 释放全部通道资源（幂等）。
func (m *Manager) closeSenders() error {
	m.mu.Lock()
	if m.sendersClosed {
		m.mu.Unlock()
		return nil
	}
	m.sendersClosed = true
	channels := m.channels
	m.mu.Unlock()

	var firstErr error
	for _, channel := range channels {
		if channel == nil || channel.sender == nil {
			continue
		}
		if err := channel.sender.Close(); err != nil {
			m.deps.LoggerOr().Error("告警通道释放失败",
				"channel", channel.name, "type", channel.typ, "error", err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// sleepContext 睡眠指定时长；上下文取消时提前返回 false。
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// errorString 把可能为 nil 的错误转成可安全写入日志的字符串。
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
