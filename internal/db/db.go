// Package db 实现 WAF 运行期数据的 SQLite 持久化。
//
// 边界约定：
//   - 数据库只保存运营数据（封禁、IP 名单、站点策略、关键标量策略与可选审计）；
//   - 监听地址、Redis 连接、规则/模板/MMDB 路径、密钥等部署配置永远不写数据库；
//   - 首次启动时从 YAML 导入运营数据，之后以数据库为权威来源。
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"

	_ "modernc.org/sqlite"
)

// Config 是打开 SQLite 数据库的参数。
type Config struct {
	// Path 是数据库文件路径；":memory:" 用于测试。
	Path string
	// BusyTimeout 是写锁等待时间；<=0 时使用 5 秒。
	BusyTimeout time.Duration
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
}

// DB 是 SQLite 数据库句柄与仓储入口。
type DB struct {
	// sql 是底层连接池。
	sql *sql.DB
	// path 是数据库文件路径，供启动日志与运维命令输出。
	path string
	// clock 是时间源。
	clock core.Clock
}

// Open 打开数据库、设置 PRAGMA 并执行迁移。
func Open(cfg Config) (*DB, error) {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil, fmt.Errorf("database.path 不能为空")
	}
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("创建数据库目录失败：%w", err)
			}
		}
	}

	busyTimeout := cfg.BusyTimeout
	if busyTimeout <= 0 {
		busyTimeout = 5 * time.Second
	}
	clock := cfg.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}

	dsn := path
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		dsn = "file:" + filepath.ToSlash(path)
	}
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败：%w", err)
	}
	// SQLite 同一时刻只允许一个写事务；单连接可以避免 database/sql 内部
	// 多连接互相抢锁，也保证 PRAGMA 对全部操作生效。
	handle.SetMaxOpenConns(1)
	handle.SetMaxIdleConns(1)
	handle.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := handle.PingContext(ctx); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("连接 SQLite 数据库失败：%w", err)
	}
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeout.Milliseconds()),
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	}
	for _, statement := range pragmas {
		if _, err := handle.ExecContext(ctx, statement); err != nil {
			_ = handle.Close()
			return nil, fmt.Errorf("设置 SQLite PRAGMA 失败（%s）：%w", statement, err)
		}
	}

	database := &DB{sql: handle, path: path, clock: clock}
	if err := database.migrate(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return database, nil
}

// Close 关闭数据库；必须幂等。
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	err := d.sql.Close()
	d.sql = nil
	return err
}

// Path 返回数据库文件路径。
func (d *DB) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Now 返回当前时间。
func (d *DB) Now() time.Time {
	return d.clock.Now()
}

// migrate 执行 schema 迁移。
func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.sql.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("初始化数据库 schema 失败：%w", err)
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO policy_revision(id, revision, updated_at) VALUES(1, 1, ?)`,
		time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("初始化策略版本失败：%w", err)
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`,
		time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("记录 schema 版本失败：%w", err)
	}
	// CREATE TABLE IF NOT EXISTS 不会为旧库补列；必须显式执行增量迁移。
	if err := d.ensureColumns(ctx); err != nil {
		return err
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`,
		time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("记录 schema v2 版本失败：%w", err)
	}
	return nil
}

// columnMigration 描述一个需要补充的列。
type columnMigration struct {
	name       string
	definition string
}

// ensureColumns 为升级前的数据库补充结构化审计所需的列。
//
// SQLite 的 ALTER TABLE ADD COLUMN 无法在列已存在时幂等执行，因此先读取
// PRAGMA table_info 判断。由于连接池固定为单连接，查询 rows 必须显式关闭后
// 才能执行后续 ALTER，否则会等待自己持有的唯一连接。
func (d *DB) ensureColumns(ctx context.Context) error {
	migrations := []struct {
		table   string
		columns []columnMigration
	}{
		{
			table: "bans",
			columns: []columnMigration{
				{name: "request_id", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "check_name", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "target", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "uri", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "query_text", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "params_json", definition: "TEXT NOT NULL DEFAULT ''"},
			},
		},
		{
			table: "ban_events",
			columns: []columnMigration{
				{name: "request_id", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "check_name", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "ban_scope", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "target", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "uri", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "query_text", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "params_json", definition: "TEXT NOT NULL DEFAULT ''"},
			},
		},
		{
			table: "audit_requests",
			columns: []columnMigration{
				{name: "uri", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "query_text", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "target", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "ban_scope", definition: "TEXT NOT NULL DEFAULT ''"},
				{name: "params_json", definition: "TEXT NOT NULL DEFAULT ''"},
			},
		},
	}

	for _, migration := range migrations {
		existing, err := d.tableColumns(ctx, migration.table)
		if err != nil {
			return err
		}
		for _, column := range migration.columns {
			if existing[column.name] {
				continue
			}
			statement := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s",
				migration.table, column.name, column.definition)
			if _, err := d.sql.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("升级数据库表 %s 字段 %s 失败：%w",
					migration.table, column.name, err)
			}
		}
	}
	return nil
}

// tableColumns 返回表的已有列集合。
func (d *DB) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := d.sql.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, fmt.Errorf("读取数据库表 %s 结构失败：%w", table, err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var (
			cid       int
			name      string
			columnTyp string
			notNull   int
			defaultV  sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &columnTyp, &notNull, &defaultV, &pk); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("解析数据库表 %s 结构失败：%w", table, err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("遍历数据库表 %s 结构失败：%w", table, err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("关闭数据库表 %s 结构查询失败：%w", table, err)
	}
	return columns, nil
}

// schemaSQL 是数据库的完整初始 schema。
//
// 所有时间字段统一使用 Unix 毫秒（UTC 绝对时间），避免时区与本地时间影响封禁到期判定。
const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bootstrap_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    initialized_at INTEGER NOT NULL,
    config_hash    TEXT NOT NULL DEFAULT '',
    config_version INTEGER NOT NULL DEFAULT 1,
    source         TEXT NOT NULL DEFAULT '',
    imported_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS config_imports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    source      TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_revision (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    revision   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    key        TEXT PRIMARY KEY,
    client_ip  TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL DEFAULT '',
    site       TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    rule_id    TEXT NOT NULL DEFAULT '',
    check_name TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    uri        TEXT NOT NULL DEFAULT '',
    query_text TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    banned_at  INTEGER NOT NULL,
    expire_at  INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bans_expire_at ON bans(expire_at);
CREATE INDEX IF NOT EXISTS idx_bans_client_ip ON bans(client_ip);

CREATE TABLE IF NOT EXISTS ban_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event      TEXT NOT NULL,
    ban_key    TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    rule_id    TEXT NOT NULL DEFAULT '',
    check_name TEXT NOT NULL DEFAULT '',
    ban_scope  TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    uri        TEXT NOT NULL DEFAULT '',
    query_text TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ban_events_key ON ban_events(ban_key);
CREATE INDEX IF NOT EXISTS idx_ban_events_created_at ON ban_events(created_at);

CREATE TABLE IF NOT EXISTS ip_lists (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    list_type  TEXT NOT NULL CHECK (list_type IN ('allow', 'block')),
    scope      TEXT NOT NULL CHECK (scope IN ('global', 'site', 'check')),
    site       TEXT NOT NULL DEFAULT '',
    pipeline   TEXT NOT NULL DEFAULT '',
    check_name TEXT NOT NULL DEFAULT '',
    value      TEXT NOT NULL,
    action     TEXT NOT NULL DEFAULT '',
    score      INTEGER NOT NULL DEFAULT 0,
    enabled    INTEGER NOT NULL DEFAULT 1,
    reason     TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    expire_at  INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_lists_identity
    ON ip_lists(list_type, scope, site, pipeline, check_name, value);
CREATE INDEX IF NOT EXISTS idx_ip_lists_scope ON ip_lists(scope, site, check_name);

CREATE TABLE IF NOT EXISTS site_policies (
    site          TEXT PRIMARY KEY,
    hosts_json    TEXT NOT NULL,
    engine_mode   TEXT NOT NULL DEFAULT '',
    pipeline      TEXT NOT NULL DEFAULT 'default',
    access_action TEXT NOT NULL DEFAULT 'block',
    access_score  INTEGER NOT NULL DEFAULT 0,
    params_json   TEXT NOT NULL DEFAULT '{}',
    enabled       INTEGER NOT NULL DEFAULT 1,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_settings (
    scope      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, name, key)
);

CREATE TABLE IF NOT EXISTS audit_requests (
    request_id    TEXT PRIMARY KEY,
    received_at   INTEGER NOT NULL,
    site          TEXT NOT NULL DEFAULT '',
    client_ip     TEXT NOT NULL DEFAULT '',
    method        TEXT NOT NULL DEFAULT '',
    host          TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    uri           TEXT NOT NULL DEFAULT '',
    query_text    TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    ban_scope     TEXT NOT NULL DEFAULT '',
    params_json   TEXT NOT NULL DEFAULT '',
    verdict       TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    http_status   INTEGER NOT NULL DEFAULT 0,
    code          TEXT NOT NULL DEFAULT '',
    rule_id       TEXT NOT NULL DEFAULT '',
    check_name    TEXT NOT NULL DEFAULT '',
    score         INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    would_block   INTEGER NOT NULL DEFAULT 0,
    error_text    TEXT NOT NULL DEFAULT '',
    findings_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_audit_requests_received_at ON audit_requests(received_at);
CREATE INDEX IF NOT EXISTS idx_audit_requests_client_ip ON audit_requests(client_ip);
CREATE INDEX IF NOT EXISTS idx_audit_requests_rule_id ON audit_requests(rule_id);

-- 运营策略变更触发器：外部工具直接修改数据库时自动递增版本，
-- 运行实例无需手工执行 UPDATE policy_revision，按 reload_interval 即可热加载。
CREATE TRIGGER IF NOT EXISTS trg_site_policies_revision_insert
AFTER INSERT ON site_policies BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_site_policies_revision_update
AFTER UPDATE ON site_policies BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_site_policies_revision_delete
AFTER DELETE ON site_policies BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS trg_ip_lists_revision_insert
AFTER INSERT ON ip_lists BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_ip_lists_revision_update
AFTER UPDATE ON ip_lists BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_ip_lists_revision_delete
AFTER DELETE ON ip_lists BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS trg_policy_settings_revision_insert
AFTER INSERT ON policy_settings BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_policy_settings_revision_update
AFTER UPDATE ON policy_settings BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_policy_settings_revision_delete
AFTER DELETE ON policy_settings BEGIN
    UPDATE policy_revision SET revision = revision + 1,
           updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000 WHERE id = 1;
END;
`

// bumpRevision 在事务内递增策略版本。
func bumpRevision(ctx context.Context, tx *sql.Tx, now int64) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE policy_revision SET revision = revision + 1, updated_at = ? WHERE id = 1`, now)
	if err != nil {
		return fmt.Errorf("递增策略版本失败：%w", err)
	}
	return nil
}

// Revision 返回当前策略版本。
func (d *DB) Revision(ctx context.Context) (int64, error) {
	var revision int64
	err := d.sql.QueryRowContext(ctx, `SELECT revision FROM policy_revision WHERE id = 1`).Scan(&revision)
	if err != nil {
		return 0, fmt.Errorf("读取策略版本失败：%w", err)
	}
	return revision, nil
}
