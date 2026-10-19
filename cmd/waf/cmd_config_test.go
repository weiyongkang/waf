package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"gopkg.in/yaml.v3"
)

// TestConfigPrintOutputsAllDefaults 覆盖：config print 不依赖配置文件即可输出完整默认配置。
// 环境变量存在时会在默认值之上叠加，这属于命令的预期语义。
func TestConfigPrintOutputsAllDefaults(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "print"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("config print 退出码 = %d，期望 0；stderr=%s", code, stderr.String())
	}

	var cfg config.Config
	if err := yaml.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatalf("config print 输出不是合法 YAML：%v\n%s", err, stdout.String())
	}
	if cfg.Server.BasePath != "" {
		t.Fatalf("默认 base_path 应为空，实际 %q", cfg.Server.BasePath)
	}
	if cfg.Ingress.Path != "/waf/auth" || cfg.Ingress.DenyPath != "/waf/deny" {
		t.Fatalf("默认端点路径不符：auth=%q deny=%q", cfg.Ingress.Path, cfg.Ingress.DenyPath)
	}
	if cfg.Ban.RenewOnRepeat {
		t.Fatal("默认 renew_on_repeat 必须为 false（重复命中不续期）")
	}
	if cfg.Responder.MaxBodyBytes != 8192 {
		t.Fatalf("默认 responder.max_body_bytes 应为 8192，实际 %d", cfg.Responder.MaxBodyBytes)
	}
	if cfg.Responder.Messages[config.CodeNotFound] == "" {
		t.Fatal("默认配置必须包含 WAF_NOT_FOUND 文案")
	}

	text := stdout.String()
	for _, field := range []string{
		"base_path:", "renew_on_repeat:", "template:", "template_file:", "max_body_bytes:",
		"database:", "reload_interval:", "audit:", "retention:", "queue_size:",
	} {
		if !strings.Contains(text, field) {
			t.Errorf("默认配置输出缺少字段 %q", field)
		}
	}
}

// TestConfigPrintAppliesDirectoryEnvAndCLI 覆盖：config print 输出目录配置、环境变量与 CLI 的最终叠加结果。
func TestConfigPrintAppliesDirectoryEnvAndCLI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "10-base.yaml"), []byte(
		"ban:\n  default_ttl: 20m\nlogging:\n  access:\n    level: warn\n",
	), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}
	// t.Setenv 会在用例结束后恢复，避免污染其它测试。
	t.Setenv("WAF_RESPONDER_INCLUDE_DETAILS", "true")

	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"config", "print", "-c", dir, "--ban-default-ttl", "2h",
	}, &stdout, &stderr); code != exitOK {
		t.Fatalf("config print 退出码 = %d，期望 0；stderr=%s", code, stderr.String())
	}

	var cfg config.Config
	if err := yaml.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatalf("config print 输出不是合法 YAML：%v\n%s", err, stdout.String())
	}
	if cfg.Ban.DefaultTTL.Duration() != 2*time.Hour {
		t.Fatalf("ban.default_ttl = %s，期望 CLI 覆盖值 2h", cfg.Ban.DefaultTTL)
	}
	if cfg.Logging.Access.Level != "warn" {
		t.Fatalf("logging.access.level = %q，期望目录配置值 warn", cfg.Logging.Access.Level)
	}
	if !cfg.Responder.IncludeDetails {
		t.Fatal("responder.include_details 应体现环境变量 WAF_RESPONDER_INCLUDE_DETAILS=true")
	}
}

// TestConfigPrintHelp 覆盖：-h 只输出帮助，不再访问 nil 配置对象。
func TestConfigPrintHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "print", "-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("config print -h 退出码 = %d，期望 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("-h 不应输出配置，实际：%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage") && !strings.Contains(stderr.String(), "用法") {
		t.Fatalf("-h 未输出帮助信息：%s", stderr.String())
	}
}
