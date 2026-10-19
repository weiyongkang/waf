package config

import (
	"strings"
	"testing"
)

// TestValidateRouteCollisions 覆盖：前缀叠加后路径相同必须在启动前拦截。
func TestValidateRouteCollisions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "默认配置无冲突",
			mutate: func(*Config) {
			},
		},
		{
			name: "前缀叠加后 auth 与 deny 冲突",
			mutate: func(cfg *Config) {
				cfg.Server.BasePath = "/waf"
				cfg.Ingress.Path = "/auth"
				cfg.Ingress.DenyPath = "/waf/auth"
			},
			want: "ingress.deny_path 与 ingress.path 的最终路径冲突",
		},
		{
			name: "auth 与内置健康检查冲突",
			mutate: func(cfg *Config) {
				cfg.Ingress.Path = "/healthz"
			},
			want: "内置端点 /healthz 与 ingress.path 的最终路径冲突",
		},
		{
			name: "metrics 与 deny 冲突",
			mutate: func(cfg *Config) {
				cfg.Metrics.Path = cfg.Ingress.DenyPath
			},
			want: "metrics.path 与 ingress.deny_path 的最终路径冲突",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(cfg)
			err := Validate(cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("合法配置不应校验失败：%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际 %v", tc.want, err)
			}
		})
	}
}
