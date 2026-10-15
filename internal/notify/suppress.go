package notify

import (
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// suppressStore 是单个告警通道的聚合抑制表。
//
// 为什么必须「每通道一张表」而不是全局一张：通道之间是并联扇出关系，
// 共用一张表会出现「A 通道刚发过同类告警，导致 B 通道被抑制」的错误行为——
// B 通道根本没收到过这条告警。因此抑制状态必须与通道一一对应。
//
// 数据结构与容量控制（对应需求 R13：缓存大小必须可配置）：
//
//	entries 是「聚合键 -> 最近一次放行时间」的哈希表；
//	order   是按写入顺序排列的键队列，用于在达到上限时做 O(1) 淘汰。
//
// 两个边界都要处理，缺一不可：
//   - max_tracked_keys > 0：达到上限后淘汰「最早写入」的键。高基数攻击
//     （每个请求换一条规则）会让聚合键数量线性增长，不设上限会缓慢吃光内存。
//   - max_tracked_keys <= 0：运维显式声明不设上限，此时改为按写入次数
//     周期性全表清理已过期条目，避免表无限增长（清理代价被摊薄到可忽略）。
type suppressStore struct {
	// mu 保护全部字段；admit 在请求处理路径上被调用，因此临界区必须极短
	//（只有哈希查找与切片追加，没有任何 I/O）。
	mu sync.Mutex
	// window 是抑制窗口；<=0 表示不抑制（此时本表完全不参与工作，零开销）。
	window time.Duration
	// limit 是键上限；<=0 表示不设上限（改用周期性清理）。
	limit int
	// clock 是时间源，仅用于测试与日志（当前实现由调用方传入 now，此字段保留给未来扩展）。
	clock core.Clock
	// entries 记录每个聚合键最近一次「被放行」的时间。
	entries map[string]time.Time
	// order 是按写入顺序排列的键队列，用于淘汰最早写入的键。
	order []string
	// writes 统计写入次数，用于驱动「无上限」模式下的周期性清理。
	writes int
}

// newSuppressStore 构造聚合抑制表。
func newSuppressStore(window time.Duration, limit int, clock core.Clock) *suppressStore {
	if clock == nil {
		clock = core.SystemClock{}
	}
	return &suppressStore{
		window:  window,
		limit:   limit,
		clock:   clock,
		entries: make(map[string]time.Time),
	}
}

// admit 判断一条告警是否应当放行外送。
//
// 语义：同一聚合键在窗口内**只放行一次**（首次放行，其余抑制）。
// 首次放行时记录时间戳，因此窗口是「滑动」的——只有当某键在窗口内**再次**出现
// 才会被抑制，长时间没有复现的键会被清理掉，不会永久压制。
func (s *suppressStore) admit(alert core.Alert, now time.Time) bool {
	if s == nil || s.window <= 0 {
		// 未开启抑制：直接放行，且不写任何状态（零内存开销）。
		return true
	}

	key := AggregateKey(alert)

	s.mu.Lock()
	defer s.mu.Unlock()

	if last, exists := s.entries[key]; exists && now.Sub(last) < s.window {
		return false
	}

	if _, exists := s.entries[key]; !exists {
		s.order = append(s.order, key)
	}
	s.entries[key] = now
	s.writes++

	if s.limit > 0 {
		s.evictOverLimit()
	} else if s.writes%pruneInterval == 0 {
		s.pruneExpired(now)
	}
	return true
}

// evictOverLimit 在上限模式下淘汰最早写入的键。
//
// 说明：这里**不做**「先清理过期条目」的全表扫描。上限模式一定运行在高基数场景，
// 此时每次新键都做一次 O(n) 扫描会把抑制表变成热点；而顺序淘汰本身是 O(1) 的，
// 代价是「偶尔淘汰一个其实还没过期的键」，其后果仅仅是「同类告警多发一条」，
// 这是可以接受的降级方向（宁可多发，不可漏发）。
func (s *suppressStore) evictOverLimit() {
	for len(s.entries) > s.limit && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, oldest)
	}
	s.compactOrder()
}

// pruneExpired 删除全部已过期条目（仅在「不设上限」模式下周期性调用）。
func (s *suppressStore) pruneExpired(now time.Time) {
	original := s.order
	kept := original[:0]
	for _, key := range original {
		last, exists := s.entries[key]
		if !exists {
			continue
		}
		if now.Sub(last) >= s.window {
			delete(s.entries, key)
			continue
		}
		kept = append(kept, key)
	}
	// 清空被裁掉位置的字符串引用，避免底层数组继续持有已删除的键。
	for i := len(kept); i < len(original); i++ {
		original[i] = ""
	}
	s.order = kept
}

// compactOrder 在「切片前移导致底层数组浪费过半」时做一次搬移。
//
// 为什么需要：order 通过 s.order[1:] 前移，底层数组会越来越大却永远不释放，
// 长期运行下等价于内存泄漏。这里用摊销方式重建，均摊代价为 O(1)。
func (s *suppressStore) compactOrder() {
	if len(s.order) == 0 {
		s.order = nil
		return
	}
	if cap(s.order) <= 2*len(s.order) {
		return
	}
	compacted := make([]string, len(s.order))
	copy(compacted, s.order)
	s.order = compacted
}

// size 返回当前抑制表条目数（用于测试与自检）。
func (s *suppressStore) size() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// AggregateKey 计算告警的聚合键：级别 + 站点 + 标题 + 命中规则。
//
// 这四个字段的组合刻画了「同一类事件」：同一站点上被同一条规则以同一级别拦下，
// 对值班人员来说就是「同一件事又发生了」，只有首次需要提醒。
// 之所以带上级别：error 级（例如存储故障）与 info 级（观察模式命中）
// 是完全不同的处置动作，不能被同一个窗口压制。
//
// 分隔符使用 ASCII 单元分隔符（US，0x1F）：站点名与标题都可能包含
// 常见可打印符号，只有控制字符能保证不会与字段值冲突（避免「a|b」与「a」+「|b」撞键）。
func AggregateKey(alert core.Alert) string {
	var builder strings.Builder
	builder.Grow(len(alert.Site) + len(alert.Title) + len(alert.Level) + 8)
	builder.WriteString(string(alert.Level))
	builder.WriteString(keySeparator)
	builder.WriteString(alert.Site)
	builder.WriteString(keySeparator)
	builder.WriteString(alert.Title)
	builder.WriteString(keySeparator)
	builder.WriteString(alert.Fields["rule_id"])
	return builder.String()
}
