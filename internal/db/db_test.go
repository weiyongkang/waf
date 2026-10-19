package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// testClock 是可控时间源，避免封禁测试依赖真实等待。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}

func (c *testClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

// newTestDatabase 打开临时目录中的 SQLite，并返回固定时钟。
func newTestDatabase(t *testing.T) (*DB, *testClock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "waf.db")
	clock := &testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	database, err := Open(Config{Path: path, Clock: clock})
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, clock, path
}

// testConfig 返回带站点与 ipaccess 名单的最小运营配置。
func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Stores = []config.StoreConfig{{Name: "default", Type: "memory", Enabled: true}}
	cfg.Sites = []config.SiteConfig{{
		Name:         "default",
		Hosts:        []string{"*"},
		Pipeline:     "default",
		AccessAction: "block",
		AccessScore:  5,
		Allowlist:    []string{"192.0.2.10"},
		Blocklist:    []string{"198.51.100.0/24"},
	}}
	cfg.Pipeline = []core.InstanceConfig{{
		Name:    "ip-access",
		Type:    "ipaccess",
		Enabled: true,
		Settings: map[string]any{
			"allowlist": []string{"203.0.113.5"},
			"blocklist": []string{"203.0.113.6"},
			"action":    "block",
		},
	}}
	cfg.Ban.DefaultTTL = core.Duration(30 * time.Minute)
	cfg.Ban.MaxTTL = core.Duration(24 * time.Hour)
	return cfg
}

// TestBootstrapImportsOnlyOnce 覆盖首次导入、重复启动不覆盖与外部导入源失效。
func TestBootstrapImportsOnlyOnce(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	cfg := testConfig()

	first, err := database.Bootstrap(ctx, cfg, false)
	if err != nil {
		t.Fatalf("首次导入失败：%v", err)
	}
	if !first.Imported || first.Initialized {
		t.Fatalf("首次导入结果不符：%+v", first)
	}

	// 首次导入完成后，YAML 中的站点名单不应再覆盖数据库。
	cfg.Sites[0].Blocklist = []string{"203.0.113.200/32"}
	second, err := database.Bootstrap(ctx, cfg, false)
	if err != nil {
		t.Fatalf("二次启动不应失败：%v", err)
	}
	if second.Imported || !second.Initialized {
		t.Fatalf("二次启动结果不符：%+v", second)
	}
	if second.ConfigHash == "" {
		t.Fatal("二次启动应返回首次导入摘要")
	}

	snapshot, err := database.LoadSnapshot(ctx)
	if err != nil {
		t.Fatalf("加载快照失败：%v", err)
	}
	if len(snapshot.Sites) != 1 {
		t.Fatalf("站点数 = %d，期望 1", len(snapshot.Sites))
	}
	if contains(snapshot.Sites[0].Blocklist, "203.0.113.200/32") {
		t.Fatal("数据库初始化后不应被 YAML 二次覆盖")
	}
	if !contains(snapshot.Sites[0].Blocklist, "198.51.100.0/24") {
		t.Fatal("首次导入的站点黑名单丢失")
	}
}

// TestBootstrapDoesNotRequireImportFileAfterInitialization 覆盖 blocklist_file 只用于首次导入。
func TestBootstrapDoesNotRequireImportFileAfterInitialization(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	cfg := testConfig()
	importFile := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(importFile, []byte("203.0.113.9\n"), 0o600); err != nil {
		t.Fatalf("写入导入文件失败：%v", err)
	}
	cfg.Pipeline[0].Settings["blocklist_file"] = importFile
	if _, err := database.Bootstrap(ctx, cfg, false); err != nil {
		t.Fatalf("首次导入失败：%v", err)
	}
	if err := os.Remove(importFile); err != nil {
		t.Fatalf("删除导入文件失败：%v", err)
	}
	if _, err := database.Bootstrap(ctx, cfg, false); err != nil {
		t.Fatalf("初始化后不应继续依赖 blocklist_file：%v", err)
	}
}

// TestBanIfAbsentDoesNotRenew 覆盖同一封禁键重复命中不刷新到期时间。
func TestBanIfAbsentDoesNotRenew(t *testing.T) {
	database, clock, _ := newTestDatabase(t)
	store, err := NewBanStore(database)
	if err != nil {
		t.Fatalf("构造封禁存储失败：%v", err)
	}
	ctx := context.Background()
	key := "client_ip:192.0.2.1"

	created, err := store.BanIfAbsent(ctx, key, time.Hour, "首次触发")
	if err != nil || !created {
		t.Fatalf("首次封禁失败：created=%t err=%v", created, err)
	}
	clock.Advance(30 * time.Minute)
	created, err = store.BanIfAbsent(ctx, key, 2*time.Hour, "重复触发")
	if err != nil {
		t.Fatalf("重复封禁失败：%v", err)
	}
	if created {
		t.Fatal("重复命中不应重新创建封禁记录")
	}
	banned, remaining, err := store.IsBanned(ctx, key)
	if err != nil || !banned {
		t.Fatalf("应处于封禁状态：banned=%t err=%v", banned, err)
	}
	if remaining < 29*time.Minute || remaining > 30*time.Minute {
		t.Fatalf("剩余时长 = %s，期望约 30m（首次封禁的到期时间）", remaining)
	}

	clock.Advance(31 * time.Minute)
	banned, _, err = store.IsBanned(ctx, key)
	if err != nil {
		t.Fatalf("查询过期封禁失败：%v", err)
	}
	if banned {
		t.Fatal("到期后必须自动解封")
	}
	created, err = store.BanIfAbsent(ctx, key, 5*time.Minute, "到期后再次触发")
	if err != nil || !created {
		t.Fatalf("到期后应重新封禁：created=%t err=%v", created, err)
	}
	if _, remaining, _ := store.IsBanned(ctx, key); remaining < 4*time.Minute || remaining > 5*time.Minute {
		t.Fatalf("重新封禁后的剩余时长 = %s，期望约 5m", remaining)
	}
}

// TestBanPersistenceAndUnban 覆盖关闭重开后的封禁持久化与手工解封。
func TestBanPersistenceAndUnban(t *testing.T) {
	database, clock, path := newTestDatabase(t)
	store, err := NewBanStore(database)
	if err != nil {
		t.Fatalf("构造封禁存储失败：%v", err)
	}
	ctx := context.Background()
	key := "client_ip:192.0.2.2"
	if err := store.Ban(ctx, key, time.Hour, "手工封禁"); err != nil {
		t.Fatalf("写入封禁失败：%v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("关闭数据库失败：%v", err)
	}

	reopened, err := Open(Config{Path: path, Clock: clock})
	if err != nil {
		t.Fatalf("重新打开数据库失败：%v", err)
	}
	defer func() { _ = reopened.Close() }()
	reopenedStore, err := NewBanStore(reopened)
	if err != nil {
		t.Fatalf("重新构造封禁存储失败：%v", err)
	}
	banned, _, err := reopenedStore.IsBanned(ctx, key)
	if err != nil || !banned {
		t.Fatalf("重启后封禁记录丢失：banned=%t err=%v", banned, err)
	}
	entries, err := reopenedStore.List(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("封禁列表不符：len=%d err=%v", len(entries), err)
	}
	if entries[0].BannedAt.IsZero() || entries[0].ExpireAt.IsZero() {
		t.Fatal("封禁时间字段必须持久化")
	}
	if err := reopenedStore.Unban(ctx, key); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if banned, _, _ := reopenedStore.IsBanned(ctx, key); banned {
		t.Fatal("解封后不应再命中")
	}
}

// TestBanWithDetailPersistsRequestContext 覆盖：封禁表、事件表与 List 均保留
// 规则、检测目标、URI、查询串和脱敏参数。
func TestBanWithDetailPersistsRequestContext(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	store, err := NewBanStore(database)
	if err != nil {
		t.Fatalf("构造封禁存储失败：%v", err)
	}
	ctx := context.Background()
	key := "ip:203.0.113.40|path:/login"
	detail := core.BanDetail{
		RequestID:  "req-detail",
		Check:      "banlist",
		RuleID:     "internal_banlist",
		Target:     "client_ip+path",
		Scope:      "client_ip+path",
		URI:        "/login?user=alice&password=secret",
		Query:      "user=alice&password=secret",
		ParamsJSON: `{"query":{"user":"alice","password":"[REDACTED]"}}`,
	}
	created, err := store.BanIfAbsentWithDetail(ctx, key, time.Hour, "测试封禁", detail)
	if err != nil || !created {
		t.Fatalf("写入结构化封禁失败：created=%t err=%v", created, err)
	}

	entries, err := store.List(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("读取封禁列表失败：len=%d err=%v", len(entries), err)
	}
	entry := entries[0]
	if entry.RuleID != detail.RuleID || entry.Check != detail.Check ||
		entry.Target != detail.Target || entry.Scope != detail.Scope ||
		entry.URI != detail.URI || entry.Query != detail.Query ||
		entry.ParamsJSON != detail.ParamsJSON {
		t.Fatalf("封禁列表上下文不完整：%+v", entry)
	}

	var (
		eventRule, eventCheck, eventScope, eventTarget  string
		eventURI, eventQuery, eventParams, eventRequest string
	)
	err = database.sql.QueryRowContext(ctx,
		`SELECT rule_id, check_name, ban_scope, target, uri, query_text, params_json, request_id
		   FROM ban_events WHERE ban_key = ? AND event = 'ban'`, key).
		Scan(&eventRule, &eventCheck, &eventScope, &eventTarget,
			&eventURI, &eventQuery, &eventParams, &eventRequest)
	if err != nil {
		t.Fatalf("读取封禁事件失败：%v", err)
	}
	if eventRule != detail.RuleID || eventCheck != detail.Check || eventScope != detail.Scope ||
		eventTarget != detail.Target || eventURI != detail.URI || eventQuery != detail.Query ||
		eventParams != detail.ParamsJSON || eventRequest != detail.RequestID {
		t.Fatalf("封禁事件上下文不完整：rule=%q check=%q scope=%q target=%q uri=%q query=%q params=%q request=%q",
			eventRule, eventCheck, eventScope, eventTarget, eventURI, eventQuery, eventParams, eventRequest)
	}
}

// TestOpenMigratesLegacySchema 覆盖：旧数据库启动时自动补齐结构化审计列。
func TestOpenMigratesLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("打开旧库失败：%v", err)
	}
	legacySchema := `
CREATE TABLE bans (
    key TEXT PRIMARY KEY, client_ip TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT '',
    site TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '', rule_id TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
    banned_at INTEGER NOT NULL, expire_at INTEGER, created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE ban_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, ban_key TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
);
CREATE TABLE audit_requests (
    request_id TEXT PRIMARY KEY, received_at INTEGER NOT NULL, site TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '', verdict TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
    http_status INTEGER NOT NULL DEFAULT 0, code TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '', check_name TEXT NOT NULL DEFAULT '',
    score INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0,
    would_block INTEGER NOT NULL DEFAULT 0, error_text TEXT NOT NULL DEFAULT '',
    findings_json TEXT NOT NULL DEFAULT '[]'
);`
	if _, err := raw.Exec(legacySchema); err != nil {
		_ = raw.Close()
		t.Fatalf("创建旧库 schema 失败：%v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭旧库失败：%v", err)
	}

	database, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("打开并迁移旧库失败：%v", err)
	}
	defer func() { _ = database.Close() }()

	expected := map[string][]string{
		"bans":           {"request_id", "check_name", "target", "uri", "query_text", "params_json"},
		"ban_events":     {"request_id", "check_name", "ban_scope", "target", "uri", "query_text", "params_json"},
		"audit_requests": {"uri", "query_text", "target", "ban_scope", "params_json"},
	}
	for table, columns := range expected {
		existing, err := database.tableColumns(context.Background(), table)
		if err != nil {
			t.Fatalf("读取 %s 列失败：%v", table, err)
		}
		for _, column := range columns {
			if !existing[column] {
				t.Fatalf("旧库迁移后 %s 缺少列 %s", table, column)
			}
		}
	}
}

// TestInsertAuditEntryPersistsContext 覆盖：审计表保存 URI、查询串、目标、
// 封禁维度与脱敏参数，而不只是路径和规则号。
func TestInsertAuditEntryPersistsContext(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	entry := core.AuditEntry{
		RequestID:  "req-audit-detail",
		ReceivedAt: database.Now(),
		Site:       "shop",
		ClientIP:   "203.0.113.50",
		Method:     "POST",
		Host:       "app.example.com",
		Path:       "/login",
		URI:        "/login?user=alice&password=secret",
		Query:      "user=alice&password=secret",
		Verdict:    core.VerdictBlock.String(),
		Action:     "block",
		HTTPStatus: 403,
		Code:       config.CodeBlocked,
		RuleID:     "internal_banlist",
		Check:      "banlist",
		Target:     "client_ip+path",
		BanScope:   "client_ip+path",
		Params:     `{"query":{"user":"alice","password":"[REDACTED]"}}`,
	}
	tx, err := database.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开启审计事务失败：%v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertAuditEntry(ctx, tx, entry); err != nil {
		t.Fatalf("写入审计记录失败：%v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交审计事务失败：%v", err)
	}

	var uri, query, target, banScope, params string
	err = database.sql.QueryRowContext(ctx,
		`SELECT uri, query_text, target, ban_scope, params_json
		   FROM audit_requests WHERE request_id = ?`, entry.RequestID).
		Scan(&uri, &query, &target, &banScope, &params)
	if err != nil {
		t.Fatalf("读取审计记录失败：%v", err)
	}
	if uri != entry.URI || query != entry.Query || target != entry.Target ||
		banScope != entry.BanScope || params != entry.Params {
		t.Fatalf("审计上下文不完整：uri=%q query=%q target=%q scope=%q params=%q",
			uri, query, target, banScope, params)
	}
}

// TestSnapshotApplyMergesGlobalAndCheckLists 覆盖全局名单对所有 ipaccess 实例生效。
func TestSnapshotApplyMergesGlobalAndCheckLists(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	cfg := testConfig()
	if _, err := database.Bootstrap(ctx, cfg, false); err != nil {
		t.Fatalf("导入失败：%v", err)
	}
	now := database.Now().UnixMilli()
	if _, err := database.sql.ExecContext(ctx,
		`INSERT INTO ip_lists(list_type, scope, value, source, created_at, updated_at)
		 VALUES('allow', 'global', '10.0.0.1', 'test', ?, ?)`,
		now, now); err != nil {
		t.Fatalf("写入全局白名单失败：%v", err)
	}
	if _, err := database.sql.ExecContext(ctx,
		`INSERT INTO ip_lists(list_type, scope, value, source, created_at, updated_at)
		 VALUES('block', 'global', '10.0.0.2', 'test', ?, ?)`,
		now, now); err != nil {
		t.Fatalf("写入全局黑名单失败：%v", err)
	}

	snapshot, err := database.LoadSnapshot(ctx)
	if err != nil {
		t.Fatalf("加载快照失败：%v", err)
	}
	effective := snapshot.Apply(cfg)
	settings := effective.Pipeline[0].Settings
	allow, _ := settings["allowlist"].([]string)
	block, _ := settings["blocklist"].([]string)
	if !contains(allow, "10.0.0.1") || !contains(allow, "203.0.113.5") {
		t.Fatalf("ipaccess allowlist 未合并全局与实例名单：%v", allow)
	}
	if !contains(block, "10.0.0.2") || !contains(block, "203.0.113.6") {
		t.Fatalf("ipaccess blocklist 未合并全局与实例名单：%v", block)
	}
	if !contains(effective.Sites[0].Allowlist, "10.0.0.1") {
		t.Fatalf("站点白名单未合并全局名单：%v", effective.Sites[0].Allowlist)
	}
}

// TestStatusReportsCounts 覆盖数据库状态摘要。
func TestStatusReportsCounts(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	if _, err := database.Bootstrap(ctx, testConfig(), false); err != nil {
		t.Fatalf("导入失败：%v", err)
	}
	store, _ := NewBanStore(database)
	if _, err := store.BanIfAbsent(ctx, "client_ip:192.0.2.3", time.Hour, "测试"); err != nil {
		t.Fatalf("写入封禁失败：%v", err)
	}
	status, err := database.Status(ctx)
	if err != nil {
		t.Fatalf("读取状态失败：%v", err)
	}
	if !status.Initialized || status.Bans != 1 || status.ActiveBans != 1 || status.Sites != 1 {
		t.Fatalf("状态数据不符：%+v", status)
	}
	if status.BanEvents != 1 || status.ConfigImports != 1 {
		t.Fatalf("事件或导入记录数不符：%+v", status)
	}
}

// TestPolicyMutationTriggersRevision 覆盖外部直接修改运营策略时自动递增热加载版本。
func TestPolicyMutationTriggersRevision(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	if _, err := database.Bootstrap(ctx, testConfig(), false); err != nil {
		t.Fatalf("导入失败：%v", err)
	}
	now := database.Now().UnixMilli()

	assertRevisionBumped := func(action string, exec func() error) {
		t.Helper()
		before, err := database.Revision(ctx)
		if err != nil {
			t.Fatalf("读取变更前版本失败：%v", err)
		}
		if err := exec(); err != nil {
			t.Fatalf("%s失败：%v", action, err)
		}
		after, err := database.Revision(ctx)
		if err != nil {
			t.Fatalf("读取变更后版本失败：%v", err)
		}
		if after <= before {
			t.Fatalf("%s后策略版本未增长：before=%d after=%d", action, before, after)
		}
	}

	assertRevisionBumped("直接更新站点策略", func() error {
		_, err := database.sql.ExecContext(ctx,
			`UPDATE site_policies SET access_score = access_score + 1, updated_at = ? WHERE site = 'default'`,
			now)
		return err
	})
	assertRevisionBumped("直接插入 IP 名单", func() error {
		_, err := database.sql.ExecContext(ctx,
			`INSERT INTO ip_lists(list_type, scope, value, source, created_at, updated_at)
			 VALUES('block', 'global', '198.18.0.1', 'test', ?, ?)`,
			now, now)
		return err
	})
	assertRevisionBumped("直接更新策略项", func() error {
		_, err := database.sql.ExecContext(ctx,
			`UPDATE policy_settings SET updated_at = ? WHERE scope = 'global' AND name = ''`,
			now)
		return err
	})
}

// TestAuditWriterModes 覆盖审计全量 / 事件模式与异步落库。
func TestAuditWriterModes(t *testing.T) {
	database, _, _ := newTestDatabase(t)
	ctx := context.Background()
	if _, err := database.Bootstrap(ctx, testConfig(), false); err != nil {
		t.Fatalf("导入失败：%v", err)
	}

	all, err := NewAuditWriter(database, config.DatabaseAuditConfig{
		Mode:          config.DatabaseAuditModeAll,
		QueueSize:     8,
		BatchSize:     1,
		FlushInterval: core.Duration(time.Second),
	}, nil)
	if err != nil {
		t.Fatalf("构造审计写入器失败：%v", err)
	}
	all.Record(core.AuditEntry{RequestID: "req-1", Verdict: "allow", Action: "allow", HTTPStatus: 200})
	all.Record(core.AuditEntry{
		RequestID: "req-2", Verdict: "block", Action: "block", HTTPStatus: 403,
		Findings: []core.Finding{{Check: "coraza", RuleID: "942100"}},
	})
	if err := all.Close(); err != nil {
		t.Fatalf("关闭审计写入器失败：%v", err)
	}
	status, err := database.Status(ctx)
	if err != nil {
		t.Fatalf("读取状态失败：%v", err)
	}
	if status.AuditRequests != 2 {
		t.Fatalf("all 模式审计记录数 = %d，期望 2", status.AuditRequests)
	}

	events, err := NewAuditWriter(database, config.DatabaseAuditConfig{
		Mode:          config.DatabaseAuditModeEvents,
		QueueSize:     8,
		BatchSize:     8,
		FlushInterval: core.Duration(time.Second),
	}, nil)
	if err != nil {
		t.Fatalf("构造事件审计写入器失败：%v", err)
	}
	events.Record(core.AuditEntry{RequestID: "req-3", Verdict: "allow", Action: "allow"})
	events.Record(core.AuditEntry{RequestID: "req-4", Verdict: "observe", Action: "observe"})
	if err := events.Close(); err != nil {
		t.Fatalf("关闭事件审计写入器失败：%v", err)
	}
	status, err = database.Status(ctx)
	if err != nil {
		t.Fatalf("读取状态失败：%v", err)
	}
	if status.AuditRequests != 3 {
		t.Fatalf("events 模式审计记录数 = %d，期望 3（仅新增 observe）", status.AuditRequests)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
