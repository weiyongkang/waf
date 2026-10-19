package config

import (
	"strings"
	"testing"
)

// TestValidateSitesAndPipelines 覆盖多站点策略的交叉校验。
func TestValidateSitesAndPipelines(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "合法具名链与站点引用",
			mutate: func(cfg *Config) {
				cfg.Pipelines = []PipelineConfig{{Name: "strict_chain"}}
				cfg.Sites = []SiteConfig{{
					Name:     "shop",
					Hosts:    []string{"shop.example.com"},
					Pipeline: "strict_chain",
				}}
			},
		},
		{
			name: "站点引用不存在的链",
			mutate: func(cfg *Config) {
				cfg.Sites = []SiteConfig{{
					Name:     "shop",
					Hosts:    []string{"shop.example.com"},
					Pipeline: "missing_chain",
				}}
			},
			want: "不存在",
		},
		{
			name: "具名链占用保留名",
			mutate: func(cfg *Config) {
				cfg.Pipelines = []PipelineConfig{{Name: "default"}}
			},
			want: "保留名",
		},
		{
			name: "具名链重名",
			mutate: func(cfg *Config) {
				cfg.Pipelines = []PipelineConfig{{Name: "strict_chain"}, {Name: "strict_chain"}}
			},
			want: "重复",
		},
		{
			name: "非法访问动作",
			mutate: func(cfg *Config) {
				cfg.Sites = []SiteConfig{{
					Name:         "shop",
					Hosts:        []string{"shop.example.com"},
					AccessAction: "deny",
				}}
			},
			want: "access_action",
		},
		{
			name: "非法白名单",
			mutate: func(cfg *Config) {
				cfg.Sites = []SiteConfig{{
					Name:      "shop",
					Hosts:     []string{"shop.example.com"},
					Allowlist: []string{"not-a-cidr"},
				}}
			},
			want: "allowlist",
		},
		{
			name: "非法黑名单",
			mutate: func(cfg *Config) {
				cfg.Sites = []SiteConfig{{
					Name:      "shop",
					Hosts:     []string{"shop.example.com"},
					Blocklist: []string{"300.1.1.1/24"},
				}}
			},
			want: "blocklist",
		},
		{
			name: "负数访问评分",
			mutate: func(cfg *Config) {
				cfg.Sites = []SiteConfig{{
					Name:        "shop",
					Hosts:       []string{"shop.example.com"},
					AccessScore: -1,
				}}
			},
			want: "access_score",
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
