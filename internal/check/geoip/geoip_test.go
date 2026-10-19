package geoip

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/core"
)

// TestGeoIPValidation 覆盖装配期的配置错误，全部应在打开数据库之前失败。
func TestGeoIPValidation(t *testing.T) {
	missingDB := filepath.Join(t.TempDir(), "missing.mmdb")
	cases := []struct {
		name     string
		settings map[string]any
		want     string
	}{
		{name: "缺少数据库路径", settings: map[string]any{}, want: "database 不能为空"},
		{name: "非法动作", settings: map[string]any{
			"database": missingDB, "action": "deny", "block_countries": []string{"KP"},
		}, want: "action"},
		{name: "空名单", settings: map[string]any{
			"database": missingDB, "allow_countries": []string{}, "block_countries": []string{},
		}, want: "未配置任何"},
		{name: "非法国家代码", settings: map[string]any{
			"database": missingDB, "block_countries": []string{"CHINA"},
		}, want: "长度非法"},
		{name: "数据库不可访问", settings: map[string]any{
			"database": missingDB, "block_countries": []string{"KP"},
		}, want: "不可访问"},
	}

	deps := &core.Deps{Limits: core.Limits{MaxMMDBBytes: 1 << 20}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "geoip", Type: Type, Enabled: true, Phase: core.PhaseRequest, Settings: tc.settings,
			}, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际 %v", tc.want, err)
			}
		})
	}
}

// TestNormalizeCodes 验证国家/洲代码的规范化与去重。
func TestNormalizeCodes(t *testing.T) {
	set, err := normalizeCodes([]string{" cn ", "CN", "AS", ""})
	if err != nil {
		t.Fatalf("normalizeCodes: %v", err)
	}
	for _, code := range []string{"CN", "AS"} {
		if _, ok := set[code]; !ok {
			t.Fatalf("缺少代码 %s：%v", code, set)
		}
	}
	if len(set) != 2 {
		t.Fatalf("应去重并忽略空值，实际 %v", set)
	}
}
