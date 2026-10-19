package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/logging"
	"github.com/weiyongkang/waf/internal/server"
)

// TestDatabasePolicyGovernsReload 覆盖：数据库初始化后 YAML 不覆盖数据库字段，
// 数据库策略版本变化后则由 reloadDatabasePolicy 热重载新值。
func TestDatabasePolicyGovernsReload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "waf.db")
	path := filepath.Join(dir, "10-base.yaml")
	writeRuntimeDatabaseConfig(t, path, dbPath, 5)

	flagSet, err := config.NewFlagSet("test", io.Discard)
	if err != nil {
		t.Fatalf("构造参数集合失败：%v", err)
	}
	if err := flagSet.Parse([]string{"-c", dir}); err != nil {
		t.Fatalf("解析参数失败：%v", err)
	}
	resolved, err := config.Load(config.Options{ConfigFiles: flagSet.ConfigFiles(), CLI: flagSet})
	if err != nil {
		t.Fatalf("初始加载失败：%v", err)
	}
	loggers, err := logging.Build(resolved.Config.Logging)
	if err != nil {
		t.Fatalf("构造日志器失败：%v", err)
	}
	defer func() { _ = loggers.Close() }()

	metrics := core.NoopMetrics{}
	stack, err := buildStoreStack(resolved.Config, loggers.System, metrics, "")
	if err != nil {
		t.Fatalf("构造存储栈失败：%v", err)
	}
	defer func() { _ = stack.Close() }()
	current := stack.applyConfig(resolved.Config)
	if got := current.Sites[0].AccessScore; got != 5 {
		t.Fatalf("初始数据库站点评分 = %d，期望 5", got)
	}

	alerts := core.NoopAlertSink{}
	initialRuntime, err := buildServingRuntime(current, stack, loggers, metrics, alerts)
	if err != nil {
		t.Fatalf("初始装配失败：%v", err)
	}
	httpServer, err := server.New(server.Options{
		Config:       current,
		Decider:      initialRuntime.decider,
		Metrics:      metrics,
		Alerts:       alerts,
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Sites:        initialRuntime.sites,
	})
	if err != nil {
		t.Fatalf("构造服务失败：%v", err)
	}
	defer func() { _ = httpServer.Close() }()

	// 只改 YAML：数据库拥有该字段，热重载后仍应保持数据库值。
	writeRuntimeDatabaseConfig(t, path, dbPath, 42)
	current = reloadServedConfig(flagSet, current, stack, loggers, metrics, alerts, httpServer)
	if got := current.Sites[0].AccessScore; got != 5 {
		t.Fatalf("YAML 热重载后 access_score = %d，期望数据库值 5", got)
	}

	// 显式导入数据库后，版本轮询应把新值应用到运行期配置。
	reloaded, err := config.Load(config.Options{ConfigFiles: flagSet.ConfigFiles(), CLI: flagSet})
	if err != nil {
		t.Fatalf("重新加载配置失败：%v", err)
	}
	if _, err := stack.database.Bootstrap(context.Background(), reloaded.Config, true); err != nil {
		t.Fatalf("强制导入数据库失败：%v", err)
	}
	current = reloadDatabasePolicy(current, stack, loggers, metrics, alerts, httpServer)
	if got := current.Sites[0].AccessScore; got != 42 {
		t.Fatalf("数据库热重载后 access_score = %d，期望 42", got)
	}
}

// TestReloadServedConfigDirectory 覆盖目录配置的完整重载路径：
// 动态段成功替换、非法配置保留旧值、静态段变更整次拒绝。
func TestReloadServedConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "10-base.yaml")
	writeRuntimeConfig(t, path, runtimeTestConfig("20m", ":9080"))

	flagSet, err := config.NewFlagSet("test", io.Discard)
	if err != nil {
		t.Fatalf("构造参数集合失败：%v", err)
	}
	if err := flagSet.Parse([]string{"-c", dir}); err != nil {
		t.Fatalf("解析参数失败：%v", err)
	}
	resolved, err := config.Load(config.Options{ConfigFiles: flagSet.ConfigFiles(), CLI: flagSet})
	if err != nil {
		t.Fatalf("初始加载失败：%v", err)
	}

	loggers, err := logging.Build(resolved.Config.Logging)
	if err != nil {
		t.Fatalf("构造日志器失败：%v", err)
	}
	defer func() { _ = loggers.Close() }()

	metrics := core.NoopMetrics{}
	stack, err := buildStoreStack(resolved.Config, loggers.System, metrics, "")
	if err != nil {
		t.Fatalf("构造存储栈失败：%v", err)
	}
	defer func() { _ = stack.Close() }()

	alerts := core.NoopAlertSink{}
	initialRuntime, err := buildServingRuntime(resolved.Config, stack, loggers, metrics, alerts)
	if err != nil {
		t.Fatalf("初始装配失败：%v", err)
	}
	httpServer, err := server.New(server.Options{
		Config:       resolved.Config,
		Decider:      initialRuntime.decider,
		Metrics:      metrics,
		Alerts:       alerts,
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Sites:        initialRuntime.sites,
	})
	if err != nil {
		t.Fatalf("构造服务失败：%v", err)
	}
	defer func() { _ = httpServer.Close() }()

	current := resolved.Config
	writeRuntimeConfig(t, path, runtimeTestConfig("25m", ":9080"))
	current = reloadServedConfig(flagSet, current, stack, loggers, metrics, alerts, httpServer)
	if got := current.Ban.DefaultTTL.Duration(); got != 25*time.Minute {
		t.Fatalf("动态重载后 ban.default_ttl = %s，期望 25m", got)
	}

	// 静态段变更必须整次拒绝，返回值应保持重载前的配置指针。
	writeRuntimeConfig(t, path, runtimeTestConfig("35m", ":9999"))
	retained := reloadServedConfig(flagSet, current, stack, loggers, metrics, alerts, httpServer)
	if retained != current {
		t.Fatal("静态段变更时不应替换当前配置")
	}

	// 写坏 YAML 时同样保留旧配置。
	if err := os.WriteFile(path, []byte("ban: [invalid\n"), 0o600); err != nil {
		t.Fatalf("写入非法配置失败：%v", err)
	}
	retained = reloadServedConfig(flagSet, current, stack, loggers, metrics, alerts, httpServer)
	if retained != current {
		t.Fatal("非法配置时不应替换当前配置")
	}
}

// runtimeTestConfig 生成最小可运行的目录配置。
func runtimeTestConfig(banTTL string, listen string) string {
	return "server:\n  listen: " + listen + "\n" +
		"stores:\n  - name: default\n    type: memory\n    enabled: true\n" +
		"logging:\n" +
		"  system:\n    enabled: false\n    outputs: []\n" +
		"  access:\n    enabled: false\n    outputs: []\n" +
		"ban:\n  default_ttl: " + banTTL + "\n"
}

// writeRuntimeConfig 覆盖写入测试配置。
func writeRuntimeConfig(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}
}

// writeRuntimeDatabaseConfig 写入启用 SQLite 的目录配置。
func writeRuntimeDatabaseConfig(t *testing.T, path, databasePath string, accessScore int) {
	t.Helper()
	content := "server:\n  listen: \":9080\"\n  metrics_listen: \"\"\n" +
		"stores:\n  - name: default\n    type: memory\n    enabled: true\n" +
		"database:\n  enabled: true\n  path: \"" + filepath.ToSlash(databasePath) + "\"\n  reload_interval: 1s\n" +
		"logging:\n  system:\n    enabled: false\n    outputs: []\n" +
		"  access:\n    enabled: false\n    outputs: []\n" +
		"sites:\n  - name: default\n    hosts: [\"*\"]\n    pipeline: default\n    access_action: block\n" +
		"    access_score: " + fmt.Sprintf("%d", accessScore) + "\n"
	writeRuntimeConfig(t, path, content)
}
