package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// newTestManager 构造被测管理器，并在测试结束时关闭它。
func newTestManager(t *testing.T, policy Policy, channels []Channel, deps Deps) *Manager {
	t.Helper()
	manager, err := NewManager(context.Background(), Options{Policy: policy, Channels: channels, Deps: deps})
	if err != nil {
		t.Fatalf("构造告警管理器失败：%v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			t.Logf("关闭告警管理器返回错误：%v", err)
		}
	})
	return manager
}

// stubChannel 构造一个使用测试替身实现的通道声明。
func stubChannel(name string) Channel {
	return Channel{Instance: Instance{Name: name, Type: stubType}}
}

// TestManagerFansOutToEveryChannel 验证并联扇出：一条告警送达全部启用的通道。
func TestManagerFansOutToEveryChannel(t *testing.T) {
	resetStubs()
	metrics := newStubMetrics()
	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 2, MaxAttempts: 1},
		[]Channel{stubChannel("a"), stubChannel("b")},
		Deps{Metrics: metrics},
	)

	manager.Notify([]core.Alert{testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942100")})

	if !waitFor(func() bool {
		receivedA, _ := stubFor("a").snapshot()
		receivedB, _ := stubFor("b").snapshot()
		return len(receivedA) == 1 && len(receivedB) == 1
	}, 2*time.Second) {
		t.Fatalf("告警未送达全部通道：a=%v b=%v", len(mustSnapshot(t, "a")), len(mustSnapshot(t, "b")))
	}
	if metrics.countOf("a", resultSent) != 1 || metrics.countOf("b", resultSent) != 1 {
		t.Fatalf("sent 指标不符合预期：%+v", metrics.alerts)
	}
}

// TestManagerAppliesLevelThreshold 验证级别门槛：全局门槛生效，通道级门槛可覆盖。
func TestManagerAppliesLevelThreshold(t *testing.T) {
	resetStubs()
	inherit := stubChannel("inherit")
	override := Channel{
		Instance: Instance{Name: "override", Type: stubType},
		MinLevel: "info",
	}
	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 1, MaxAttempts: 1, MinLevel: "warn"},
		[]Channel{inherit, override},
		Deps{},
	)

	manager.Notify([]core.Alert{
		testAlert(core.AlertLevelInfo, "shop", "观察模式命中", "942100"),
		testAlert(core.AlertLevelWarn, "shop", "自动封禁", "900100"),
	})

	if !waitFor(func() bool {
		received, _ := stubFor("override").snapshot()
		return len(received) == 2
	}, 2*time.Second) {
		t.Fatalf("覆盖门槛的通道应收到的告警条数不符：%v", len(mustSnapshot(t, "override")))
	}
	inherited, _ := stubFor("inherit").snapshot()
	if len(inherited) != 1 {
		t.Fatalf("继承全局门槛的通道应只收到 warn 及以上告警，实际 %d 条", len(inherited))
	}
	if inherited[0].Level != core.AlertLevelWarn {
		t.Fatalf("继承通道收到的告警级别不符：%s", inherited[0].Level)
	}
}

// TestManagerSuppressesRepeatedAlertsPerChannel 验证聚合抑制按通道独立生效。
//
// 构造方式：全局窗口 5 分钟，override 通道单独把窗口设为 1 毫秒并向前拨动时钟。
// 期望结果是 override 重新收到告警、inherit 仍被抑制——这证明了抑制表是「每通道一张」。
func TestManagerSuppressesRepeatedAlertsPerChannel(t *testing.T) {
	resetStubs()
	clock := newStubClock()
	metrics := newStubMetrics()

	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 1, MaxAttempts: 1, SuppressWindow: 5 * time.Minute},
		[]Channel{
			stubChannel("inherit"),
			{
				Instance:       Instance{Name: "short", Type: stubType},
				SuppressWindow: time.Millisecond,
			},
		},
		Deps{Clock: clock, Metrics: metrics},
	)

	alert := testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942100")
	manager.Notify([]core.Alert{alert})
	if !waitFor(func() bool {
		a, _ := stubFor("inherit").snapshot()
		b, _ := stubFor("short").snapshot()
		return len(a) == 1 && len(b) == 1
	}, 2*time.Second) {
		t.Fatal("首条告警未送达")
	}

	// 窗口内重复：两个通道都应当被抑制。
	manager.Notify([]core.Alert{alert})
	time.Sleep(30 * time.Millisecond)
	if _, calls := stubFor("inherit").snapshot(); calls != 1 {
		t.Fatalf("inherit 通道在抑制窗口内不应重复外送，实际调用 %d 次", calls)
	}
	if metrics.countOf("inherit", resultSuppressed) != 1 || metrics.countOf("short", resultSuppressed) != 1 {
		t.Fatalf("suppressed 指标不符合预期：%+v", metrics.alerts)
	}

	// 越过 override 通道的短窗口后重复：只有 override 重新外送。
	clock.advance(10 * time.Millisecond)
	manager.Notify([]core.Alert{alert})
	if !waitFor(func() bool { return len(mustSnapshot(t, "short")) == 2 }, 2*time.Second) {
		t.Fatal("窗口过期后 override 通道应重新外送")
	}
	if received, _ := stubFor("inherit").snapshot(); len(received) != 1 {
		t.Fatalf("inherit 通道仍应处于抑制窗口内，实际收到 %d 条", len(received))
	}
}

// TestManagerAggregatesByRuleAndSite 验证聚合键包含规则 ID：换规则即视为新事件。
func TestManagerAggregatesByRuleAndSite(t *testing.T) {
	resetStubs()
	clock := newStubClock()
	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 1, MaxAttempts: 1, SuppressWindow: time.Hour},
		[]Channel{stubChannel("a")},
		Deps{Clock: clock},
	)

	manager.Notify([]core.Alert{
		testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942100"),
		testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942110"),
		testAlert(core.AlertLevelWarn, "blog", "命中 SQL 注入", "942100"),
	})

	if !waitFor(func() bool { return len(mustSnapshot(t, "a")) == 3 }, 2*time.Second) {
		t.Fatalf("不同规则 / 不同站点的告警不应相互抑制，实际 %d 条", len(mustSnapshot(t, "a")))
	}
}

// TestManagerRetriesUntilSuccess 验证失败重试：按策略重试并在成功后停止。
func TestManagerRetriesUntilSuccess(t *testing.T) {
	resetStubs()
	metrics := newStubMetrics()
	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 1, MaxAttempts: 3, RetryBackoff: time.Millisecond},
		[]Channel{stubChannel("a")},
		Deps{Metrics: metrics},
	)
	stubFor("a").failTimes = 2

	manager.Notify([]core.Alert{testAlert(core.AlertLevelError, "shop", "存储故障", "")})

	if !waitFor(func() bool { return len(mustSnapshot(t, "a")) == 1 }, 2*time.Second) {
		t.Fatal("重试后应成功送达")
	}
	if _, calls := stubFor("a").snapshot(); calls != 3 {
		t.Fatalf("期望调用 3 次（2 次失败 + 1 次成功），实际 %d 次", calls)
	}
	if metrics.countOf("a", resultSent) != 1 || metrics.countOf("a", resultFailed) != 0 {
		t.Fatalf("sent / failed 指标不符合预期：%+v", metrics.alerts)
	}
}

// TestManagerMarksFailedAfterExhaustingAttempts 验证重试耗尽后的失败计数。
func TestManagerMarksFailedAfterExhaustingAttempts(t *testing.T) {
	resetStubs()
	metrics := newStubMetrics()
	manager := newTestManager(t,
		Policy{QueueSize: 8, Workers: 1, MaxAttempts: 2, RetryBackoff: time.Millisecond},
		[]Channel{stubChannel("a")},
		Deps{Metrics: metrics},
	)
	stubFor("a").alwaysFail = true

	manager.Notify([]core.Alert{testAlert(core.AlertLevelError, "shop", "存储故障", "")})

	if !waitFor(func() bool { return metrics.countOf("a", resultFailed) == 1 }, 2*time.Second) {
		t.Fatalf("期望 failed 计数为 1，实际指标：%+v", metrics.alerts)
	}
	if _, calls := stubFor("a").snapshot(); calls != 2 {
		t.Fatalf("期望调用 2 次，实际 %d 次", calls)
	}
	if metrics.countOf("a", resultSent) != 0 {
		t.Fatalf("不应有 sent 计数：%+v", metrics.alerts)
	}
}

// TestManagerDropsWhenQueueFull 验证队列满时丢弃并计数，且绝不阻塞调用方。
func TestManagerDropsWhenQueueFull(t *testing.T) {
	resetStubs()
	metrics := newStubMetrics()
	manager := newTestManager(t,
		Policy{QueueSize: 1, Workers: 1, MaxAttempts: 1},
		[]Channel{stubChannel("a")},
		Deps{Metrics: metrics},
	)

	release := make(chan struct{})
	stubFor("a").blockUntil = release

	alerts := make([]core.Alert, 0, 20)
	for i := 0; i < 20; i++ {
		alerts = append(alerts, testAlert(core.AlertLevelWarn, "shop", "告警-"+itoa(i), ""))
	}

	start := time.Now()
	manager.Notify(alerts)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Notify 不应阻塞调用方，实际耗时 %s", elapsed)
	}

	if !waitFor(func() bool { return metrics.totalOf(resultDropped) > 0 }, 2*time.Second) {
		t.Fatalf("队列满时应产生 dropped 计数，实际指标：%+v", metrics.alerts)
	}
	close(release)
}

// TestManagerCloseIsIdempotent 验证 Close 可以重复调用且返回 nil。
func TestManagerCloseIsIdempotent(t *testing.T) {
	resetStubs()
	manager, err := NewManager(context.Background(), Options{
		Policy:   Policy{QueueSize: 4, Workers: 1, MaxAttempts: 1},
		Channels: []Channel{stubChannel("a")},
	})
	if err != nil {
		t.Fatalf("构造告警管理器失败：%v", err)
	}

	for i := 0; i < 3; i++ {
		if err := manager.Close(context.Background()); err != nil {
			t.Fatalf("第 %d 次 Close 返回错误：%v", i+1, err)
		}
	}
	if stubFor("a").closeCount != 1 {
		t.Fatalf("通道 Close 应只被调用一次，实际 %d 次", stubFor("a").closeCount)
	}

	// 关闭后继续投递不应 panic（静默丢弃）。
	manager.Notify([]core.Alert{testAlert(core.AlertLevelWarn, "shop", "关闭后投递", "")})
}

// TestManagerWithoutChannelsIsNoop 验证没有启用通道时管理器退化为空实现。
func TestManagerWithoutChannelsIsNoop(t *testing.T) {
	manager, err := NewManager(context.Background(), Options{Policy: Policy{Enabled: false}})
	if err != nil {
		t.Fatalf("构造空告警管理器失败：%v", err)
	}
	manager.Notify([]core.Alert{testAlert(core.AlertLevelError, "shop", "故障", "")})
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("空管理器 Close 返回错误：%v", err)
	}
	if len(manager.Channels()) != 0 {
		t.Fatalf("空管理器不应有任何通道：%v", manager.Channels())
	}
}

// TestManagerRejectsUnknownChannelType 验证未注册类型在构造期失败（fail fast）。
func TestManagerRejectsUnknownChannelType(t *testing.T) {
	_, err := NewManager(context.Background(), Options{
		Policy:   Policy{QueueSize: 4, Workers: 1},
		Channels: []Channel{{Instance: Instance{Name: "x", Type: "not-registered"}}},
	})
	if err == nil {
		t.Fatal("未注册的通道类型应当返回错误")
	}
	if !strings.Contains(err.Error(), "未注册") {
		t.Fatalf("错误信息应说明类型未注册，实际：%v", err)
	}
}

// TestManagerReleasesSendersOnConstructionFailure 验证构造中途失败时已建通道被释放。
func TestManagerReleasesSendersOnConstructionFailure(t *testing.T) {
	resetStubs()
	_, err := NewManager(context.Background(), Options{
		Policy: Policy{QueueSize: 4, Workers: 1},
		Channels: []Channel{
			stubChannel("ok"),
			{Instance: Instance{Name: "bad", Type: stubFailType}},
		},
	})
	if err == nil {
		t.Fatal("通道构造失败时应当返回错误")
	}
	if stubFor("ok").closeCount != 1 {
		t.Fatalf("构造失败时应释放已构造的通道，closeCount=%d", stubFor("ok").closeCount)
	}
}

// TestManagerRejectsInvalidLevel 验证非法的级别门槛在构造期被发现。
func TestManagerRejectsInvalidLevel(t *testing.T) {
	_, err := NewManager(context.Background(), Options{
		Policy:   Policy{QueueSize: 4, Workers: 1, MinLevel: "fatal"},
		Channels: []Channel{stubChannel("a")},
	})
	if err == nil {
		t.Fatal("非法级别应当返回错误")
	}
}

// mustSnapshot 返回指定通道已接收的告警（取不到替身时返回 nil）。
func mustSnapshot(t *testing.T, name string) []core.Alert {
	t.Helper()
	sender := stubFor(name)
	if sender == nil {
		return nil
	}
	received, _ := sender.snapshot()
	return received
}

// itoa 把整数转换为十进制字符串（测试内部使用，避免引入额外依赖）。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
