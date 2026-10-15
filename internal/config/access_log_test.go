package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAccessAllowLevel 覆盖 logging.access.allow_level 的默认值与取值校验。
//
// 之所以该配置必须有强校验：写错时会退化成「放行请求完全不留痕」，
// 而这类静默失效只有在事后翻日志时才会被发现（需求：鉴权请求过与不过都要留痕）。
func TestAccessAllowLevel(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
		problem string
	}{
		{name: "默认值为 info", content: "version: 1\n", want: AccessAllowLevelInfo},
		{name: "显式 info", content: "logging:\n  access:\n    allow_level: info\n", want: AccessAllowLevelInfo},
		{name: "显式 debug", content: "logging:\n  access:\n    allow_level: debug\n", want: AccessAllowLevelDebug},
		{name: "显式 off", content: "logging:\n  access:\n    allow_level: off\n", want: AccessAllowLevelOff},
		{
			name:    "非法取值",
			content: "logging:\n  access:\n    allow_level: always\n",
			problem: "logging.access.allow_level",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "waf.yaml")
			if err := os.WriteFile(configPath, []byte(item.content), 0o600); err != nil {
				t.Fatalf("写入测试配置失败：%v", err)
			}

			resolved, err := Load(Options{ConfigFiles: []string{configPath}, SkipDefaultConfigPath: true})
			if item.problem != "" {
				if err == nil {
					t.Fatalf("期望报错（%s），实际加载成功", item.problem)
				}
				if !strings.Contains(err.Error(), item.problem) {
					t.Fatalf("错误信息应包含 %q，实际：%v", item.problem, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望配置合法，实际报错：%v", err)
			}
			// 省略该项时必须回落到默认 info，保证「过与不过都留痕」。
			if got := resolved.Config.Logging.Access.AllowLevel; got != item.want {
				t.Fatalf("allow_level = %q，期望 %q", got, item.want)
			}
		})
	}
}
