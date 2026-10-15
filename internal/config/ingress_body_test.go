package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIngressBodyMissingMethods 覆盖 ingress.body.missing_methods 的默认值与校验。
//
// 该列表决定「哪些方法缺少请求体才算异常」：
//   - 默认只包含 POST / PUT / PATCH（语义上必定携带请求体的方法）；
//   - GET / HEAD / OPTIONS 等无体是正常现象，不能被算成「缺失」，
//     否则系统日志与 waf_body_missing_total 会被正常流量刷屏；
//   - 写得非法或重复属于静默失效配置，必须在加载阶段直接报错。
func TestIngressBodyMissingMethods(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
		problem string
	}{
		{name: "默认值只含带体方法", content: "version: 1\n", want: []string{"POST", "PUT", "PATCH"}},
		{
			name:    "可自定义方法集合",
			content: "ingress:\n  body:\n    missing_methods: [POST, PUT, PATCH, DELETE]\n",
			want:    []string{"POST", "PUT", "PATCH", "DELETE"},
		},
		{
			name:    "required 模式下空列表属于静默失效",
			content: "ingress:\n  body:\n    mode: required\n    missing_methods: []\n",
			problem: "missing_methods",
		},
		{
			name:    "空字符串项非法",
			content: "ingress:\n  body:\n    missing_methods: [\"POST\", \"\"]\n",
			problem: "missing_methods[1]",
		},
		{
			name:    "含空白字符的方法名非法",
			content: "ingress:\n  body:\n    missing_methods: [\"PO ST\"]\n",
			problem: "missing_methods[0]",
		},
		{
			name:    "重复声明非法（大小写不敏感）",
			content: "ingress:\n  body:\n    missing_methods: [POST, post]\n",
			problem: "重复出现",
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
			got := resolved.Config.Ingress.Body.MissingMethods
			if len(got) != len(item.want) {
				t.Fatalf("missing_methods = %v，期望 %v", got, item.want)
			}
			for i := range item.want {
				if got[i] != item.want[i] {
					t.Fatalf("missing_methods = %v，期望 %v", got, item.want)
				}
			}
		})
	}
}
