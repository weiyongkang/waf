package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// ErrUnsupported 表示当前实现不支持某类操作。
var ErrUnsupported = errors.New("SQLite 封禁存储不支持该操作")

// BanStore 使用 SQLite 持久化封禁名单，并在内存中维护非持久化计数窗口。
//
// 设计取舍：
//   - 封禁记录必须跨重启保留，写入 SQLite；
//   - 限速/累进封禁计数是高频易失数据，只放内存，避免把每个请求都变成磁盘写；
//   - BanIfAbsent 通过「先删过期行、再 INSERT ON CONFLICT DO NOTHING」保证
//     同一封禁键只按首次写入时间计时，后续命中不刷新到期时间。
type BanStore struct {
	db   *DB
	now  func() time.Time
	mu   sync.Mutex
	incs map[string]counterItem
}

// counterItem 是一个固定窗口计数项。
type counterItem struct {
	value    int64
	expireAt time.Time
}

// NewBanStore 构造 SQLite 封禁存储。
func NewBanStore(database *DB) (*BanStore, error) {
	if database == nil {
		return nil, fmt.Errorf("封禁存储必须注入数据库")
	}
	return &BanStore{
		db:   database,
		now:  database.Now,
		incs: make(map[string]counterItem),
	}, nil
}

// Incr 在内存中执行固定窗口计数（core.Store 实现）。
//
// 计数故意不落 SQLite：它属于短周期易失状态，持久化既没有安全收益，
// 还会把高频请求路径变成数据库写热点。
func (s *BanStore) Incr(_ context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if s == nil {
		return 0, 0, ErrUnsupported
	}
	if window <= 0 {
		window = time.Minute
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	item, exists := s.incs[key]
	if !exists || !item.expireAt.After(now) {
		item = counterItem{value: 0, expireAt: now.Add(window)}
	}
	item.value++
	s.incs[key] = item
	return item.value, item.expireAt.Sub(now), nil
}

// Ban 强制写入或续期封禁（core.Store 实现）。
func (s *BanStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	now := s.now()
	return s.upsert(ctx, key, ttl, reason, "manual", core.BanDetail{}, now)
}

// BanWithDetail 强制写入或续期封禁，并保存触发时的请求上下文。
func (s *BanStore) BanWithDetail(ctx context.Context, key string, ttl time.Duration,
	reason string, detail core.BanDetail) error {
	return s.upsert(ctx, key, ttl, reason, "auto", detail, s.now())
}

// BanIfAbsent 仅在键不存在或已过期时写入，返回是否实际创建（core.Store 实现）。
func (s *BanStore) BanIfAbsent(ctx context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	return s.banIfAbsentWithDetail(ctx, key, ttl, reason, core.BanDetail{})
}

// BanIfAbsentWithDetail 仅在键不存在或已过期时写入，并保存请求上下文快照。
func (s *BanStore) BanIfAbsentWithDetail(ctx context.Context, key string, ttl time.Duration,
	reason string, detail core.BanDetail) (bool, error) {
	return s.banIfAbsentWithDetail(ctx, key, ttl, reason, detail)
}

// banIfAbsentWithDetail 是自动封禁的唯一写入实现。
func (s *BanStore) banIfAbsentWithDetail(ctx context.Context, key string, ttl time.Duration,
	reason string, detail core.BanDetail) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	nowMillis := now.UnixMilli()
	expireValue := expiryMillis(now, ttl)

	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("开启封禁事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 先删除已过期记录：到期后再次封禁应当获得新的完整 TTL。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM bans WHERE key = ? AND expire_at IS NOT NULL AND expire_at <= ?`,
		key, nowMillis); err != nil {
		return false, fmt.Errorf("清理过期封禁失败：%w", err)
	}

	meta := parseBanKey(key)
	result, err := tx.ExecContext(ctx,
		`INSERT INTO bans(key, client_ip, scope, site, path, method, reason, rule_id,
		                  check_name, target, request_id, uri, query_text, params_json, source,
		                  banned_at, expire_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'auto', ?, ?, ?, ?)
		 ON CONFLICT(key) DO NOTHING`,
		key, meta.clientIP, meta.scope, meta.site, meta.path, meta.method, reason,
		detail.RuleID, detail.Check, detail.Target, detail.RequestID, detail.URI,
		detail.Query, detail.ParamsJSON, nowMillis, expireValue, nowMillis, nowMillis)
	if err != nil {
		return false, fmt.Errorf("写入封禁记录失败：%w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("读取封禁写入结果失败：%w", err)
	}
	if affected == 0 {
		return false, nil
	}
	if err := insertBanEvent(ctx, tx, "ban", key, reason, "auto", detail, meta.scope, nowMillis); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("提交封禁事务失败：%w", err)
	}
	return true, nil
}

// IsBanned 查询封禁状态与剩余时长（core.Store 实现）。
func (s *BanStore) IsBanned(ctx context.Context, key string) (bool, time.Duration, error) {
	nowMillis := s.now().UnixMilli()
	var expireAt sql.NullInt64
	err := s.db.sql.QueryRowContext(ctx,
		`SELECT expire_at FROM bans WHERE key = ?`, key).Scan(&expireAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("查询封禁记录失败：%w", err)
	}
	if !expireAt.Valid {
		return true, 0, nil
	}
	remaining := time.Duration(expireAt.Int64-nowMillis) * time.Millisecond
	if remaining <= 0 {
		// 惰性清理：不要求后台定时任务，查询路径即可保证到期自动解封。
		_, _ = s.db.sql.ExecContext(ctx, `DELETE FROM bans WHERE key = ? AND expire_at <= ?`, key, nowMillis)
		return false, 0, nil
	}
	return true, remaining, nil
}

// List 列出当前有效封禁（core.Store 实现）。
func (s *BanStore) List(ctx context.Context) ([]core.BanEntry, error) {
	nowMillis := s.now().UnixMilli()
	rows, err := s.db.sql.QueryContext(ctx,
		`SELECT key, reason, scope, rule_id, check_name, target, uri, query_text, params_json,
		        COALESCE(expire_at, 0), banned_at
		   FROM bans
		  WHERE expire_at IS NULL OR expire_at > ?
		  ORDER BY key`, nowMillis)
	if err != nil {
		return nil, fmt.Errorf("读取封禁名单失败：%w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := make([]core.BanEntry, 0)
	for rows.Next() {
		var (
			key, reason, scope, ruleID, check, target string
			uri, query, paramsJSON                    string
			expireAt, bannedAt                        int64
		)
		if err := rows.Scan(&key, &reason, &scope, &ruleID, &check, &target,
			&uri, &query, &paramsJSON, &expireAt, &bannedAt); err != nil {
			return nil, fmt.Errorf("读取封禁记录失败：%w", err)
		}
		entry := core.BanEntry{
			Key:        key,
			Reason:     reason,
			Scope:      scope,
			RuleID:     ruleID,
			Check:      check,
			Target:     target,
			URI:        uri,
			Query:      query,
			ParamsJSON: paramsJSON,
			BannedAt:   time.UnixMilli(bannedAt),
		}
		if expireAt > 0 {
			entry.ExpireAt = time.UnixMilli(expireAt)
			entry.TTL = time.Duration(expireAt-nowMillis) * time.Millisecond
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历封禁名单失败：%w", err)
	}
	return entries, nil
}

// Unban 删除封禁记录（core.Store 实现）。
func (s *BanStore) Unban(ctx context.Context, key string) error {
	nowMillis := s.now().UnixMilli()
	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启解封事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM bans WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("删除封禁记录失败：%w", err)
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		if err := insertBanEvent(ctx, tx, "unban", key, "", "manual", core.BanDetail{}, "", nowMillis); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交解封事务失败：%w", err)
	}
	return nil
}

// Close 释放内存计数；数据库由 DB 统一关闭。
func (s *BanStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.incs = make(map[string]counterItem)
	s.mu.Unlock()
	return nil
}

// upsert 是强制封禁（人工续期）的唯一内部入口。
func (s *BanStore) upsert(ctx context.Context, key string, ttl time.Duration, reason, source string,
	detail core.BanDetail, now time.Time) error {
	nowMillis := now.UnixMilli()
	expireValue := expiryMillis(now, ttl)
	meta := parseBanKey(key)

	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启封禁事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO bans(key, client_ip, scope, site, path, method, reason, rule_id,
		                  check_name, target, request_id, uri, query_text, params_json, source,
		                  banned_at, expire_at, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET
		     client_ip = excluded.client_ip,
		     scope = excluded.scope,
		     site = excluded.site,
		     path = excluded.path,
		     method = excluded.method,
		     reason = excluded.reason,
		     rule_id = excluded.rule_id,
		     check_name = excluded.check_name,
		     target = excluded.target,
		     request_id = excluded.request_id,
		     uri = excluded.uri,
		     query_text = excluded.query_text,
		     params_json = excluded.params_json,
		     source = excluded.source,
		     banned_at = excluded.banned_at,
		     expire_at = excluded.expire_at,
		     updated_at = excluded.updated_at`,
		key, meta.clientIP, meta.scope, meta.site, meta.path, meta.method, reason,
		detail.RuleID, detail.Check, detail.Target, detail.RequestID, detail.URI,
		detail.Query, detail.ParamsJSON, source, nowMillis, expireValue, nowMillis, nowMillis)
	if err != nil {
		return fmt.Errorf("写入封禁记录失败：%w", err)
	}
	if err := insertBanEvent(ctx, tx, "ban", key, reason, source, detail, meta.scope, nowMillis); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交封禁事务失败：%w", err)
	}
	return nil
}

// expiryMillis 把 TTL 转换为绝对到期时间；ttl <= 0 表示永不过期。
func expiryMillis(now time.Time, ttl time.Duration) any {
	if ttl <= 0 {
		return nil
	}
	return now.Add(ttl).UnixMilli()
}

// insertBanEvent 写入封禁历史事件。
func insertBanEvent(ctx context.Context, tx *sql.Tx, event, key, reason, source string,
	detail core.BanDetail, scope string, now int64) error {
	if detail.Scope == "" {
		detail.Scope = scope
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO ban_events(event, ban_key, reason, source, rule_id, check_name,
		                       ban_scope, target, request_id, uri, query_text, params_json, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event, key, reason, source, detail.RuleID, detail.Check, detail.Scope,
		detail.Target, detail.RequestID, detail.URI, detail.Query, detail.ParamsJSON, now)
	if err != nil {
		return fmt.Errorf("写入封禁事件失败：%w", err)
	}
	return nil
}

// banKeyMeta 是从稳定封禁键中解析出的可查询字段。
type banKeyMeta struct {
	clientIP string
	scope    string
	site     string
	path     string
	method   string
}

// parseBanKey 解析 internal/ban 的稳定键格式。
//
// 键格式是跨版本契约（见 internal/ban/keys.go），解析失败时只保留原始键，
// 不阻断封禁写入；查询与解封仍然以 key 为准。
func parseBanKey(key string) banKeyMeta {
	meta := banKeyMeta{scope: "client_ip"}
	parts := strings.Split(key, "|")
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "ip:"):
			meta.clientIP = strings.TrimPrefix(part, "ip:")
		case strings.HasPrefix(part, "site:"):
			meta.site = strings.TrimPrefix(part, "site:")
			meta.scope = "client_ip+site"
		case strings.HasPrefix(part, "path:"):
			meta.path = strings.TrimPrefix(part, "path:")
			meta.scope = "client_ip+path"
		case strings.HasPrefix(part, "method:"):
			meta.method = strings.TrimPrefix(part, "method:")
			meta.scope = "client_ip+method"
		}
	}
	return meta
}
