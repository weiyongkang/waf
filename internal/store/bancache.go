package store

import (
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// banCache 是「已封禁结论」的本地短 TTL 缓存。
//
// 定位（需求 R17）：封禁查询是每个请求都要做的判断，如果每次都打 Redis，
// 在大流量下会形成明显的往返开销；而封禁结论具有「一旦为真、短时间内不会变假」的特点，
// 因此只缓存「已封禁」这一侧，命中缓存即可直接拦截。
//
// 之所以不缓存「未封禁」结论：那会让新下发的封禁在一段时间内对其它实例不可见，
// 直接削弱多实例共享的意义；漏判的成本远高于多一次 Redis 往返。
type banCache struct {
	// mu 保护 entries。
	mu sync.Mutex
	// entries 记录「已封禁」的键及其缓存到期时间。
	entries map[string]time.Time
	// ttl 是缓存存活时间（配置项 settings.local_cache_ttl）。
	ttl time.Duration
	// maxEntries 是缓存条目上限（配置项 settings.local_cache_entries）。
	maxEntries int
	// clock 是时间源。
	clock core.Clock
}

// newBanCache 构造本地封禁缓存；ttl <= 0 表示不缓存（直接返回 nil 以便调用方快速判断）。
func newBanCache(ttl time.Duration, maxEntries int, clock core.Clock) *banCache {
	if ttl <= 0 {
		return nil
	}
	if maxEntries <= 0 {
		maxEntries = defaultLocalCacheEntries
	}
	if clock == nil {
		clock = core.SystemClock{}
	}
	return &banCache{
		entries:    make(map[string]time.Time),
		ttl:        ttl,
		maxEntries: maxEntries,
		clock:      clock,
	}
}

// defaultLocalCacheEntries 是本地封禁缓存的默认条目上限。
const defaultLocalCacheEntries = 100000

// has 判断键是否命中本地缓存。
func (c *banCache) has(key string) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	expireAt, exists := c.entries[key]
	if !exists {
		return false
	}
	if !expireAt.After(c.clock.Now()) {
		delete(c.entries, key)
		return false
	}
	return true
}

// set 记录一个「已封禁」结论。
func (c *banCache) set(key string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxEntries {
		c.purgeExpiredLocked()
	}
	c.entries[key] = c.clock.Now().Add(c.ttl)
}

// remove 移除一条缓存（解封后必须调用，否则本实例会继续拦截已解封来源）。
func (c *banCache) remove(key string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}

// purgeExpiredLocked 清理过期条目；调用方必须持锁。
func (c *banCache) purgeExpiredLocked() {
	now := c.clock.Now()
	for key, expireAt := range c.entries {
		if !expireAt.After(now) {
			delete(c.entries, key)
		}
	}
}
