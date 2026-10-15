package notify

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// 本文件提供测试替身：可编程行为的告警通道、可拨动的时钟、可观察的指标写入器。
//
// 之所以集中在一个文件：多个测试文件（manager_test.go / suppress_test.go）
// 都要用到这些替身，集中定义可以避免「同一个替身写两份、行为逐渐漂移」。

// stubSender 是可编程行为的告警通道替身。
type stubSender struct {
	// name 是实例名。
	name string
	// typ 是实现类型名。
	typ string
	// mu 保护全部可变字段（Manager 会并发调用 Send）。
	mu sync.Mutex
	// received 记录已成功接收的告警。
	received []core.Alert
	// calls 记录 Send 被调用的总次数（含失败尝试）。
	calls int
	// failTimes 表示前 N 次调用返回错误（用于验证重试）。
	failTimes int
	// alwaysFail 为 true 时全部调用都失败。
	alwaysFail bool
	// blockUntil 非 nil 时 Send 会阻塞到该通道被关闭（用于验证队列满丢弃）。
	blockUntil chan struct{}
	// closeCount 记录 Close 被调用的次数（用于验证幂等）。
	closeCount int
}

// Send 记录一次调用并按配置决定成功或失败。
func (s *stubSender) Send(ctx context.Context, alert core.Alert) error {
	s.mu.Lock()
	s.calls++
	shouldFail := s.alwaysFail || s.calls <= s.failTimes
	block := s.blockUntil
	s.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if shouldFail {
		return errors.New("stub 通道故障")
	}

	s.mu.Lock()
	s.received = append(s.received, alert)
	s.mu.Unlock()
	return nil
}

// Name 返回实例名。
func (s *stubSender) Name() string { return s.name }

// Type 返回实现类型名。
func (s *stubSender) Type() string { return s.typ }

// Close 记录一次关闭。
func (s *stubSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	return nil
}

// snapshot 返回已接收告警的副本与调用次数。
func (s *stubSender) snapshot() ([]core.Alert, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	received := make([]core.Alert, len(s.received))
	copy(received, s.received)
	return received, s.calls
}

// 测试替身通道的类型名与工厂注册表。
const (
	// stubType 是行为可编程的通道类型名。
	stubType = "stub"
	// stubFailType 是「构造即失败」的通道类型名。
	stubFailType = "stub-fail"
)

var (
	// stubRegistry 保存按实例名索引的替身，便于测试在构造后取得句柄。
	stubRegistryMu sync.Mutex
	stubRegistry   = map[string]*stubSender{}
)

func init() {
	Register(stubType, func(inst Instance, deps Deps) (Sender, error) {
		sender := &stubSender{name: inst.Name, typ: stubType}
		stubRegistryMu.Lock()
		stubRegistry[inst.Name] = sender
		stubRegistryMu.Unlock()
		return sender, nil
	})
	Register(stubFailType, func(inst Instance, deps Deps) (Sender, error) {
		return nil, errors.New("构造函数故意失败")
	})
}

// stubFor 返回指定实例名的替身。
func stubFor(name string) *stubSender {
	stubRegistryMu.Lock()
	defer stubRegistryMu.Unlock()
	return stubRegistry[name]
}

// resetStubs 清空替身注册表（每个测试开始前调用，避免测试间相互干扰）。
func resetStubs() {
	stubRegistryMu.Lock()
	defer stubRegistryMu.Unlock()
	stubRegistry = map[string]*stubSender{}
}

// stubClock 是可拨动的时钟替身。
type stubClock struct {
	// mu 保护 now。
	mu sync.Mutex
	// now 是当前时间。
	now time.Time
}

// newStubClock 构造一个从固定时刻开始的时钟。
func newStubClock() *stubClock {
	return &stubClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// Now 返回当前（可被测试改写）的时间。
func (c *stubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Since 返回自 t 起经过的时间。
func (c *stubClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

// advance 向前拨动时钟。
func (c *stubClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// stubMetrics 是可观察的指标替身。
type stubMetrics struct {
	// NoopMetrics 提供其余方法，保证接口完整。
	core.NoopMetrics
	// mu 保护 alerts。
	mu sync.Mutex
	// alerts 统计 alert_total 的 (通道, 结果) 计数。
	alerts map[string]int
}

// newStubMetrics 构造指标替身。
func newStubMetrics() *stubMetrics {
	return &stubMetrics{alerts: map[string]int{}}
}

// IncAlert 记录一次告警外送结果。
func (m *stubMetrics) IncAlert(notifier, result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts[notifier+"|"+result]++
}

// countOf 返回指定通道与结果的计数。
func (m *stubMetrics) countOf(notifier, result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alerts[notifier+"|"+result]
}

// totalOf 返回指定结果在全部通道上的计数总和。
func (m *stubMetrics) totalOf(result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for key, value := range m.alerts {
		if len(key) >= len(result) && key[len(key)-len(result):] == result {
			total += value
		}
	}
	return total
}

// waitFor 轮询等待条件成立；超时则返回 false。
//
// 之所以需要它：告警外送是异步的（队列 + 工作协程），
// 测试必须等待协程完成投递，而不能依赖「函数返回即已完成」。
func waitFor(condition func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return condition()
}

// testAlert 构造一条测试告警。
func testAlert(level core.AlertLevel, site, title, ruleID string) core.Alert {
	fields := map[string]string{}
	if ruleID != "" {
		fields["rule_id"] = ruleID
	}
	return core.Alert{
		Level:   level,
		Title:   title,
		Message: title + " 的详情",
		Site:    site,
		Fields:  fields,
	}
}
