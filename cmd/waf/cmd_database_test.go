package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
	"gopkg.in/yaml.v3"
)

// TestDatabaseCLIAndConfigPrintPrecedence 覆盖 db status/import-config 与 config print 的数据库优先级。
func TestDatabaseCLIAndConfigPrintPrecedence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "waf.db")
	configPath := filepath.Join(dir, "waf.yaml")
	writeDatabaseTestConfig(t, configPath, dbPath, 5)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "status", "-c", configPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db status 退出码 = %d；stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "数据库文件不存在") {
		t.Fatalf("首次 status 应提示文件不存在：%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"db", "import-config", "-c", configPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db import-config 退出码 = %d；stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "配置导入完成") {
		t.Fatalf("导入输出不符：%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"db", "status", "-c", configPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("db status 退出码 = %d；stderr=%s", code, stderr.String())
	}
	for _, field := range []string{"database.initialized: true", "site_policies: 1", "bans.active: 0"} {
		if !strings.Contains(stdout.String(), field) {
			t.Fatalf("status 输出缺少 %q：%s", field, stdout.String())
		}
	}

	// 修改 YAML 后不重新导入：config print 必须继续输出数据库中的旧值。
	writeDatabaseTestConfig(t, configPath, dbPath, 9)
	effective := runConfigPrintConfig(t, configPath)
	if got := effective.Sites[0].AccessScore; got != 5 {
		t.Fatalf("config print 的 access_score = %d，期望数据库值 5", got)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"db", "import-config", "-c", configPath, "--force"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("强制导入退出码 = %d；stderr=%s", code, stderr.String())
	}
	effective = runConfigPrintConfig(t, configPath)
	if got := effective.Sites[0].AccessScore; got != 9 {
		t.Fatalf("强制导入后 access_score = %d，期望 9", got)
	}
}

// TestBanCLIUsesSQLiteWhenDatabaseEnabled 覆盖 ban 命令与服务共享 SQLite 封禁名单。
func TestBanCLIUsesSQLiteWhenDatabaseEnabled(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "waf.yaml")
	writeDatabaseTestConfig(t, configPath, filepath.Join(dir, "waf.db"), 5)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"ban", "add", "-c", configPath,
		"--ip", "203.0.113.77", "--ttl", "10m", "--reason", "CLI 测试"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("ban add 退出码 = %d；stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "已封禁 203.0.113.77") {
		t.Fatalf("ban add 输出不符：%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"ban", "list", "-c", configPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("ban list 退出码 = %d；stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "203.0.113.77") || !strings.Contains(stdout.String(), "CLI 测试") {
		t.Fatalf("ban list 未读到 SQLite 记录：%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"ban", "remove", "-c", configPath, "--ip", "203.0.113.77"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("ban remove 退出码 = %d；stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"ban", "list", "-c", configPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("ban list 退出码 = %d；stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "封禁名单为空") {
		t.Fatalf("解封后名单应为空：%s", stdout.String())
	}
}

// runConfigPrintConfig 执行 config print 并解析输出。
func runConfigPrintConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "print", "-c", path}, &stdout, &stderr); code != exitOK {
		t.Fatalf("config print 退出码 = %d；stderr=%s", code, stderr.String())
	}
	cfg := &config.Config{}
	if err := yaml.Unmarshal(stdout.Bytes(), cfg); err != nil {
		t.Fatalf("config print 输出不是合法 YAML：%v\n%s", err, stdout.String())
	}
	return cfg
}

// writeDatabaseTestConfig 写入启用 SQLite 的最小配置。
func writeDatabaseTestConfig(t *testing.T, path, databasePath string, accessScore int) {
	t.Helper()
	content := fmt.Sprintf(`server:
  listen: ":9080"
  metrics_listen: ""
stores:
  - name: default
    type: memory
    enabled: true
database:
  enabled: true
  path: %q
  reload_interval: 2s
sites:
  - name: default
    hosts: ["*"]
    pipeline: default
    access_action: block
    access_score: %d
`, filepath.ToSlash(databasePath), accessScore)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入数据库测试配置失败：%v", err)
	}
}
