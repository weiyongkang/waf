package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadPriority 验证三通道优先级：CLI > 配置文件 > 环境变量 > 内置默认值（需求 R16）。
//
// 该测试是验收项 A17 的核心用例：一旦优先级被写反，本用例会立即失败。
func TestLoadPriority(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "waf.yaml")
	fileContent := "ban:\n  default_ttl: 45m\nlogging:\n  access:\n    level: warn\n"
	if err := os.WriteFile(configPath, []byte(fileContent), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}

	// 环境变量把 ban.default_ttl 设为 10m，把 logging.access.level 设为 debug。
	env := map[string]string{
		"WAF_BAN_DEFAULT_TTL":      "10m",
		"WAF_LOGGING_ACCESS_LEVEL": "debug",
	}
	lookup := func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}

	t.Run("仅环境变量时以环境变量为准", func(t *testing.T) {
		resolved, err := Load(Options{LookupEnv: lookup, SkipDefaultConfigPath: true})
		if err != nil {
			t.Fatalf("加载配置失败：%v", err)
		}
		if got := resolved.Config.Ban.DefaultTTL.String(); got != "10m0s" {
			t.Fatalf("ban.default_ttl = %s，期望 10m0s", got)
		}
		if got := resolved.OriginOf("ban.default_ttl"); got != OriginEnv {
			t.Fatalf("ban.default_ttl 来源 = %s，期望 env", got)
		}
	})

	t.Run("配置文件覆盖环境变量", func(t *testing.T) {
		resolved, err := Load(Options{
			ConfigFiles:           []string{configPath},
			LookupEnv:             lookup,
			SkipDefaultConfigPath: true,
		})
		if err != nil {
			t.Fatalf("加载配置失败：%v", err)
		}
		if got := resolved.Config.Ban.DefaultTTL.String(); got != "45m0s" {
			t.Fatalf("ban.default_ttl = %s，期望 45m0s（文件应覆盖环境变量）", got)
		}
		if got := resolved.Config.Logging.Access.Level; got != "warn" {
			t.Fatalf("logging.access.level = %s，期望 warn（文件应覆盖环境变量）", got)
		}
		if got := resolved.OriginOf("logging.access.level"); got != OriginFile {
			t.Fatalf("logging.access.level 来源 = %s，期望 file", got)
		}
	})

	t.Run("CLI 覆盖配置文件与环境变量", func(t *testing.T) {
		flagSet, err := NewFlagSet("test", os.Stderr)
		if err != nil {
			t.Fatalf("构造参数集合失败：%v", err)
		}
		if err := flagSet.Parse([]string{"--ban-default-ttl", "2h"}); err != nil {
			t.Fatalf("解析参数失败：%v", err)
		}

		resolved, err := Load(Options{
			ConfigFiles:           []string{configPath},
			CLI:                   flagSet,
			LookupEnv:             lookup,
			SkipDefaultConfigPath: true,
		})
		if err != nil {
			t.Fatalf("加载配置失败：%v", err)
		}
		if got := resolved.Config.Ban.DefaultTTL.String(); got != "2h0m0s" {
			t.Fatalf("ban.default_ttl = %s，期望 2h0m0s（CLI 优先级最高）", got)
		}
		if got := resolved.OriginOf("ban.default_ttl"); got != OriginCLI {
			t.Fatalf("ban.default_ttl 来源 = %s，期望 cli", got)
		}
		// 未被 CLI 覆盖的项仍应保持文件值。
		if got := resolved.Config.Logging.Access.Level; got != "warn" {
			t.Fatalf("logging.access.level = %s，期望 warn", got)
		}
	})
}

// TestLoadRejectsUnknownKey 验证未知配置项会被拒绝，并从错误信息中定位到具体路径。
//
// 之所以必须有该检查：拼错的配置项被静默忽略，会表现为「以为开了防护其实没开」。
func TestLoadRejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(configPath, []byte("ban:\n  default_ttl_x: 30m\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}

	_, err := Load(Options{ConfigFiles: []string{configPath}, SkipDefaultConfigPath: true})
	if err == nil {
		t.Fatal("期望因未知配置项而报错，实际加载成功")
	}
	if !strings.Contains(err.Error(), "ban.default_ttl_x") {
		t.Fatalf("错误信息未指出具体配置项：%v", err)
	}
}

// TestLoadRejectsNonScalarCLIOverride 验证数组类配置项不能被 CLI 覆盖。
//
// 设计约定：结构化列表（pipeline / stores 等）只能写在配置文件里。
func TestLoadRejectsNonScalarCLIOverride(t *testing.T) {
	flagSet, err := NewFlagSet("test", os.Stderr)
	if err != nil {
		t.Fatalf("构造参数集合失败：%v", err)
	}
	err = flagSet.Parse([]string{"--set", "pipeline=[]"})
	if err == nil {
		t.Fatal("期望 --set 覆盖数组配置项时报错，实际通过")
	}
	if !strings.Contains(err.Error(), "不是标量") {
		t.Fatalf("错误信息未说明原因：%v", err)
	}
}

// TestLoadRejectsInvalidValue 验证取值范围校验会阻止危险配置。
func TestLoadRejectsInvalidValue(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "waf.yaml")
	// 0 会让限额静默失效，属于必须拦截的危险配置。
	if err := os.WriteFile(configPath, []byte("limits:\n  max_config_file_bytes: 0\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}

	_, err := Load(Options{ConfigFiles: []string{configPath}, SkipDefaultConfigPath: true})
	if err == nil {
		t.Fatal("期望因限额为 0 而报错，实际加载成功")
	}
	if !strings.Contains(err.Error(), "max_config_file_bytes") {
		t.Fatalf("错误信息未指出具体配置项：%v", err)
	}
}

// TestSchemaNamingIsMechanical 验证环境变量与 CLI 参数命名可由配置路径机械推导。
func TestSchemaNamingIsMechanical(t *testing.T) {
	sch, err := buildSchema()
	if err != nil {
		t.Fatalf("构建 schema 失败：%v", err)
	}

	if path, ok := sch.envNames["WAF_BAN_DEFAULT_TTL"]; !ok || path != "ban.default_ttl" {
		t.Fatalf("WAF_BAN_DEFAULT_TTL 应映射到 ban.default_ttl，实际 %q（存在=%v）", path, ok)
	}
	if path, ok := sch.flagNames["ban-default-ttl"]; !ok || path != "ban.default_ttl" {
		t.Fatalf("--ban-default-ttl 应映射到 ban.default_ttl，实际 %q（存在=%v）", path, ok)
	}
	// responder.messages 的键由用户自定义，不应参与环境变量推导。
	if _, ok := sch.envNames["WAF_RESPONDER_MESSAGES_WAF_BLOCKED"]; ok {
		t.Fatal("responder.messages 的子键不应参与环境变量推导")
	}
}
