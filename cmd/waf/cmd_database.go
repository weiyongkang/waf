package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/db"
)

// runDB 实现运行期数据库运维命令。
//
// 命令形态：
//
//	waf db status  [-c 配置]
//	waf db import-config [-c 配置] [--force]
func runDB(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "缺少 db 子命令，可用：status / import-config")
		return exitConfigError
	}
	switch args[0] {
	case "status":
		return runDBStatus(args[1:], stdout, stderr)
	case "import-config":
		return runDBImportConfig(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知的 db 子命令 %q，可用：status / import-config\n", args[0])
		return exitConfigError
	}
}

// runDBStatus 输出数据库路径、初始化状态、策略版本与运营数据规模。
func runDBStatus(args []string, stdout, stderr io.Writer) int {
	resolved, _, code := loadResolved(args, stderr, "waf db status")
	if code != exitOK {
		return code
	}
	cfg := resolved.Config
	fmt.Fprintf(stdout, "database.enabled: %t\n", cfg.Database.Enabled)
	fmt.Fprintf(stdout, "database.path: %s\n", cfg.Database.Path)
	if !cfg.Database.Enabled {
		fmt.Fprintln(stdout, "状态：未启用（运行期沿用 stores[] 与 YAML 配置）")
		return exitOK
	}
	if !databaseFileExists(cfg.Database.Path) {
		fmt.Fprintln(stdout, "状态：数据库文件不存在（首次启动 waf run 时自动创建并导入）")
		return exitOK
	}

	database, err := openConfigDatabase(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "打开数据库失败：%v\n", err)
		return exitRuntimeError
	}
	defer func() { _ = database.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), banCommandTimeout)
	defer cancel()
	status, err := database.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "读取数据库状态失败：%v\n", err)
		return exitRuntimeError
	}
	fmt.Fprintf(stdout, "database.initialized: %t\n", status.Initialized)
	if status.Initialized {
		fmt.Fprintf(stdout, "database.initialized_at: %s\n", status.InitializedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(stdout, "policy.revision: %d\n", status.Revision)
	fmt.Fprintf(stdout, "bans.total: %d\n", status.Bans)
	fmt.Fprintf(stdout, "bans.active: %d\n", status.ActiveBans)
	fmt.Fprintf(stdout, "ban_events: %d\n", status.BanEvents)
	fmt.Fprintf(stdout, "ip_lists: %d\n", status.IPLists)
	fmt.Fprintf(stdout, "site_policies: %d\n", status.Sites)
	fmt.Fprintf(stdout, "audit_requests: %d\n", status.AuditRequests)
	fmt.Fprintf(stdout, "config_imports: %d\n", status.ConfigImports)
	return exitOK
}

// runDBImportConfig 从当前 YAML / CLI 配置重新导入运营数据。
//
// 默认只在数据库尚未初始化时导入；--force 会覆盖数据库拥有的策略数据，
// 但始终保留封禁记录、封禁事件与请求审计记录。
func runDBImportConfig(args []string, stdout, stderr io.Writer) int {
	force := false
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--force", "-force":
			force = true
		default:
			filtered = append(filtered, arg)
		}
	}

	resolved, _, code := loadResolved(filtered, stderr, "waf db import-config")
	if code != exitOK {
		return code
	}
	cfg := resolved.Config
	if !cfg.Database.Enabled {
		fmt.Fprintln(stderr, "database.enabled = false，未启用运行期数据库")
		return exitConfigError
	}

	database, err := openConfigDatabase(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "打开数据库失败：%v\n", err)
		return exitRuntimeError
	}
	defer func() { _ = database.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := database.Bootstrap(ctx, cfg, force)
	if err != nil {
		fmt.Fprintf(stderr, "导入配置失败：%v\n", err)
		return exitRuntimeError
	}
	if !result.Imported {
		fmt.Fprintf(stdout, "数据库已初始化（revision=%d），本次未覆盖；如需重新导入请加 --force\n", result.Revision)
		return exitOK
	}
	fmt.Fprintf(stdout, "配置导入完成（revision=%d，hash=%s）\n", result.Revision, result.ConfigHash)
	fmt.Fprintln(stdout, "封禁记录、封禁事件与请求审计记录已保留。")
	return exitOK
}

// applyDatabaseConfig 在数据库已初始化时把运营策略叠加到配置。
//
// 数据库文件不存在或尚未完成首次导入时保持 YAML 配置原样，
// 从而保证 `waf config print` 不会因为只读查看而隐式创建数据库。
func applyDatabaseConfig(ctx context.Context, cfg *config.Config) (*config.Config, bool, error) {
	if cfg == nil || !cfg.Database.Enabled || !databaseFileExists(cfg.Database.Path) {
		return cfg, false, nil
	}
	database, err := openConfigDatabase(cfg)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = database.Close() }()

	initialized, err := database.Initialized(ctx)
	if err != nil {
		return nil, false, err
	}
	if !initialized {
		return cfg, false, nil
	}
	snapshot, err := database.LoadSnapshot(ctx)
	if err != nil {
		return nil, false, err
	}
	effective := snapshot.Apply(cfg)
	if err := config.Validate(effective); err != nil {
		return nil, true, fmt.Errorf("数据库运营策略校验失败：%w", err)
	}
	return effective, true, nil
}

// openConfigDatabase 按配置打开 SQLite；调用方负责 Close。
func openConfigDatabase(cfg *config.Config) (*db.DB, error) {
	return db.Open(db.Config{
		Path:        cfg.Database.Path,
		BusyTimeout: cfg.Database.BusyTimeout.Duration(),
		Clock:       core.SystemClock{},
	})
}

// databaseFileExists 判断数据库文件是否已经存在；":memory:" 视为存在。
func databaseFileExists(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if path == ":memory:" {
		return true
	}
	if strings.HasPrefix(path, "file:") {
		path = strings.TrimPrefix(path, "file:")
		if index := strings.IndexByte(path, '?'); index >= 0 {
			query := path[index+1:]
			path = path[:index]
			if strings.Contains(query, "mode=memory") {
				return true
			}
		}
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
