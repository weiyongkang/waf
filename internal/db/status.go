package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Status 是数据库运行状态与运营数据规模的只读摘要。
type Status struct {
	// Path 是数据库文件路径。
	Path string
	// Initialized 表示 YAML 运营数据是否已经完成首次导入。
	Initialized bool
	// InitializedAt 是首次导入时间；未初始化时为零值。
	InitializedAt time.Time
	// Revision 是当前策略版本。
	Revision int64
	// Bans 是封禁表总行数（含尚未惰性清理的过期行）。
	Bans int64
	// ActiveBans 是当前仍然有效的封禁数。
	ActiveBans int64
	// BanEvents 是封禁与解封历史事件数。
	BanEvents int64
	// IPLists 是 IP 名单条目数。
	IPLists int64
	// Sites 是站点策略数。
	Sites int64
	// AuditRequests 是请求审计记录数。
	AuditRequests int64
	// ConfigImports 是配置导入快照数。
	ConfigImports int64
}

// Status 读取数据库状态；只执行 COUNT 查询，不修改运营数据。
func (d *DB) Status(ctx context.Context) (Status, error) {
	if d == nil || d.sql == nil {
		return Status{}, errors.New("数据库尚未打开")
	}
	status := Status{Path: d.Path()}

	var initializedAt sql.NullInt64
	err := d.sql.QueryRowContext(ctx,
		`SELECT initialized_at FROM bootstrap_state WHERE id = 1`).Scan(&initializedAt)
	switch {
	case err == nil:
		status.Initialized = true
		if initializedAt.Valid {
			status.InitializedAt = time.UnixMilli(initializedAt.Int64)
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return Status{}, fmt.Errorf("读取数据库初始化状态失败：%w", err)
	}

	if status.Revision, err = d.Revision(ctx); err != nil {
		return Status{}, err
	}
	nowMillis := d.Now().UnixMilli()
	counts := []struct {
		query       string
		dest        *int64
		usesNowTime bool
	}{
		{`SELECT COUNT(*) FROM bans`, &status.Bans, false},
		{`SELECT COUNT(*) FROM bans WHERE expire_at IS NULL OR expire_at > ?`, &status.ActiveBans, true},
		{`SELECT COUNT(*) FROM ban_events`, &status.BanEvents, false},
		{`SELECT COUNT(*) FROM ip_lists`, &status.IPLists, false},
		{`SELECT COUNT(*) FROM site_policies`, &status.Sites, false},
		{`SELECT COUNT(*) FROM audit_requests`, &status.AuditRequests, false},
		{`SELECT COUNT(*) FROM config_imports`, &status.ConfigImports, false},
	}
	for _, item := range counts {
		var err error
		if item.usesNowTime {
			err = d.sql.QueryRowContext(ctx, item.query, nowMillis).Scan(item.dest)
		} else {
			err = d.sql.QueryRowContext(ctx, item.query).Scan(item.dest)
		}
		if err != nil {
			return Status{}, fmt.Errorf("读取数据库统计失败：%w", err)
		}
	}
	return status, nil
}
