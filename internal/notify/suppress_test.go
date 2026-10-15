package notify

import (
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// TestAggregateKeyDistinguishesFields 验证聚合键对四个维度都敏感。
//
// 之所以逐个字段验证：聚合键是「哪些告警算同一件事」的唯一定义，
// 任何一个字段被漏掉，都会造成「不同事件被错误地互相抑制」——
// 这类缺陷在生产上表现为「告警漏发」，且极难通过观察发现。
func TestAggregateKeyDistinguishesFields(t *testing.T) {
	base := testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942100")
	baseline := AggregateKey(base)

	cases := map[string]core.Alert{
		"级别不同":     testAlert(core.AlertLevelError, "shop", "命中 SQL 注入", "942100"),
		"站点不同":     testAlert(core.AlertLevelWarn, "blog", "命中 SQL 注入", "942100"),
		"标题不同":     testAlert(core.AlertLevelWarn, "shop", "命中 XSS", "942100"),
		"规则 ID 不同": testAlert(core.AlertLevelWarn, "shop", "命中 SQL 注入", "942110"),
	}
	for name, alert := range cases {
		if AggregateKey(alert) == baseline {
			t.Fatalf("%s 时聚合键应当不同（说明该维度未参与聚合键计算）", name)
		}
	}

	if AggregateKey(base) != baseline {
		t.Fatal("相同告警的聚合键必须稳定")
	}
	// 缺失 Fields 时不应 panic。
	if got := AggregateKey(core.Alert{Level: core.AlertLevelInfo}); got == "" {
		t.Fatal("缺少附加字段时聚合键也应当可计算")
	}
}

// TestSuppressStoreDisabledWhenWindowZero 验证窗口为 0 时完全不抑制也不记录状态。
func TestSuppressStoreDisabledWhenWindowZero(t *testing.T) {
	store := newSuppressStore(0, 100, newStubClock())
	alert := testAlert(core.AlertLevelWarn, "shop", "标题", "1")
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !store.admit(alert, now) {
			t.Fatalf("窗口为 0 时第 %d 次也应放行", i+1)
		}
	}
	if store.size() != 0 {
		t.Fatalf("窗口为 0 时不应写入任何状态，实际 %d 条", store.size())
	}
}

// TestSuppressStoreReAdmitsAfterWindowExpiry 验证窗口过期后重新放行。
func TestSuppressStoreReAdmitsAfterWindowExpiry(t *testing.T) {
	store := newSuppressStore(time.Minute, 100, newStubClock())
	alert := testAlert(core.AlertLevelWarn, "shop", "标题", "1")
	now := time.Now()

	if !store.admit(alert, now) {
		t.Fatal("首次应当放行")
	}
	if store.admit(alert, now.Add(30*time.Second)) {
		t.Fatal("窗口内应当被抑制")
	}
	if !store.admit(alert, now.Add(61*time.Second)) {
		t.Fatal("窗口过期后应当重新放行")
	}
}

// TestSuppressStoreEvictsOldestWhenOverLimit 验证超上限时淘汰最早写入的键。
func TestSuppressStoreEvictsOldestWhenOverLimit(t *testing.T) {
	store := newSuppressStore(time.Hour, 2, newStubClock())
	now := time.Now()

	first := testAlert(core.AlertLevelWarn, "shop", "标题", "1")
	second := testAlert(core.AlertLevelWarn, "shop", "标题", "2")
	third := testAlert(core.AlertLevelWarn, "shop", "标题", "3")

	for _, alert := range []core.Alert{first, second, third} {
		if !store.admit(alert, now) {
			t.Fatal("不同聚合键首次都应放行")
		}
	}
	if store.size() != 2 {
		t.Fatalf("超过上限后应淘汰到 2 条，实际 %d 条", store.size())
	}
	// 最早的键已被淘汰，因此再次出现时会被当作新事件放行。
	if !store.admit(first, now) {
		t.Fatal("被淘汰的键再次出现时应当放行")
	}
	// 未被淘汰的键仍在窗口内，应当被抑制。
	if store.admit(third, now) {
		t.Fatal("未被淘汰且仍在窗口内的键应当被抑制")
	}
}

// TestSuppressStorePrunesExpiredWhenUnlimited 验证「不设上限」模式下的周期性清理。
//
// 该模式的语义是：运维显式声明 max_tracked_keys <= 0，不再做容量淘汰，
// 由周期性全表清理回收过期条目。测试通过制造 1024 次写入（清理周期）
// 并让全部历史条目过期来验证清理确实发生。
func TestSuppressStorePrunesExpiredWhenUnlimited(t *testing.T) {
	store := newSuppressStore(time.Second, 0, newStubClock())
	start := time.Now()

	for i := 0; i < pruneInterval; i++ {
		alert := testAlert(core.AlertLevelWarn, "shop", "标题", itoa(i))
		// 每次写入都把时间推过一个窗口，让此前全部条目都成为过期项。
		if !store.admit(alert, start.Add(time.Duration(i+1)*2*time.Second)) {
			t.Fatalf("第 %d 次写入应当放行", i)
		}
	}

	if size := store.size(); size > 2 {
		t.Fatalf("周期清理后应只剩最近写入的少量条目，实际 %d 条", size)
	}
}

// TestSuppressStoreKeepsSingleOrderEntryPerKey 验证同一键不会在顺序队列中重复插入。
func TestSuppressStoreKeepsSingleOrderEntryPerKey(t *testing.T) {
	store := newSuppressStore(time.Hour, 100, newStubClock())
	alert := testAlert(core.AlertLevelWarn, "shop", "标题", "1")
	now := time.Now()

	for i := 0; i < 5; i++ {
		store.admit(alert, now)
	}
	if len(store.order) != 1 {
		t.Fatalf("同一聚合键在顺序队列中应只有一条记录，实际 %d 条", len(store.order))
	}
	if store.size() != 1 {
		t.Fatalf("同一聚合键在抑制表中应只占一条记录，实际 %d 条", store.size())
	}
}
