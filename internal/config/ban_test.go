package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateBanKeys 覆盖：ban_keys 的取值校验与「必须包含主维度」的约束。
//
// 之所以这些约束必须由配置校验兜住：
//   - 维度取值写错 -> banlist 永远不会去查这个键，封禁形同虚设；
//   - ban_keys 不含 ban_key -> 运维命令写进去的名单永远不会被查询到；
//   - 两者都属于「配置写错了但服务照常启动」的静默失效，必须在加载阶段直接报错。
func TestValidateBanKeys(t *testing.T) {
	cases := []struct {
		name    string
		content string
		problem string
	}{
		{
			name:    "合法的多维度配置",
			content: "ban:\n  ban_key: client_ip\n  ban_keys: [client_ip, client_ip+path]\n",
		},
		{
			name:    "维度取值非法",
			content: "ban:\n  ban_keys: [client_ip, ip]\n",
			problem: "ban.ban_keys[1]",
		},
		{
			name:    "主维度未包含在查询维度中",
			content: "ban:\n  ban_key: client_ip\n  ban_keys: [client_ip+path]\n",
			problem: "必须包含 ban.ban_key",
		},
		{
			name:    "维度重复声明",
			content: "ban:\n  ban_keys: [client_ip, client_ip]\n",
			problem: "重复出现",
		},
		{
			name:    "主维度取值非法",
			content: "ban:\n  ban_key: ip\n",
			problem: "ban.ban_key",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "waf.yaml")
			if err := os.WriteFile(configPath, []byte(item.content), 0o600); err != nil {
				t.Fatalf("写入测试配置失败：%v", err)
			}

			_, err := Load(Options{ConfigFiles: []string{configPath}, SkipDefaultConfigPath: true})
			if item.problem == "" {
				if err != nil {
					t.Fatalf("期望配置合法，实际报错：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望报错（%s），实际加载成功", item.problem)
			}
			if !strings.Contains(err.Error(), item.problem) {
				t.Fatalf("错误信息应包含 %q，实际：%v", item.problem, err)
			}
		})
	}
}
