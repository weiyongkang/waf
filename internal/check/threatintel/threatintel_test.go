package threatintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// newIntelFile 写入一份测试情报文件并返回路径。
func newIntelFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newThreatIntelCheck 构造一个关闭热更新的威胁情报实例。
func newThreatIntelCheck(t *testing.T, settings map[string]any) *Check {
	t.Helper()
	deps := &core.Deps{
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
		Limits:  core.Limits{MaxIntelFileBytes: 1 << 20},
	}
	check, err := New(core.InstanceConfig{
		Name:     "intel",
		Type:     Type,
		Enabled:  true,
		Phase:    core.PhaseRequest,
		Settings: settings,
	}, deps)
	if err != nil {
		t.Fatalf("构造威胁情报实例失败：%v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	return check.(*Check)
}

// TestThreatIntelMatchesIPAndDomain 覆盖：IP/CIDR 与带端口 Host 的域名匹配。
func TestThreatIntelMatchesIPAndDomain(t *testing.T) {
	path := newIntelFile(t, "1.2.3.0/24\nevil.example.com\n")
	check := newThreatIntelCheck(t, map[string]any{
		"files":      []string{path},
		"hot_reload": false,
		"score":      10,
	})

	ipContext := core.NewRequestContext("intel-ip", time.Now())
	ipContext.Raw.ClientIP = "1.2.3.9"
	result, err := check.Evaluate(ipContext)
	if err != nil {
		t.Fatalf("IP 情报匹配失败：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock || result.Score != 10 {
		t.Fatalf("IP 命中结果不符合预期：%+v", result)
	}

	domainContext := core.NewRequestContext("intel-domain", time.Now())
	domainContext.Raw.Host = "evil.example.com:8443"
	result, err = check.Evaluate(domainContext)
	if err != nil {
		t.Fatalf("域名情报匹配失败：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("带端口域名应命中情报：%+v", result)
	}
}

// TestThreatIntelSiteParamOverride 覆盖：站点参数可把实例配置切换为观察模式。
func TestThreatIntelSiteParamOverride(t *testing.T) {
	path := newIntelFile(t, "203.0.113.0/24\n")
	check := newThreatIntelCheck(t, map[string]any{
		"files":      []string{path},
		"hot_reload": false,
		"action":     "block",
		"score":      5,
	})

	rctx := core.NewRequestContext("intel-observe", time.Now())
	rctx.Raw.ClientIP = "203.0.113.10"
	rctx.Site = &core.Site{Name: "shop", Params: map[string]string{
		"threatintel.action": "observe",
		"threatintel.score":  "12",
	}}
	result, err := check.Evaluate(rctx)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result == nil || result.Verdict != core.VerdictObserve || !result.WouldBlock {
		t.Fatalf("站点参数应切换为观察模式：%+v", result)
	}
	if result.Code != "" || result.Score != 12 {
		t.Fatalf("观察模式错误码/评分不符合预期：%+v", result)
	}
}

// TestThreatIntelValidation 覆盖：缺少情报源、非法动作与 ASN 缺库必须在装配期失败。
func TestThreatIntelValidation(t *testing.T) {
	asnFile := newIntelFile(t, "AS13335\n")
	cases := []struct {
		name     string
		settings map[string]any
		want     string
	}{
		{name: "缺少情报源", settings: map[string]any{}, want: "files 或 dirs"},
		{name: "非法动作", settings: map[string]any{
			"files": []string{asnFile}, "action": "deny",
		}, want: "action"},
		{name: "ASN 缺少数据库", settings: map[string]any{
			"files": []string{asnFile},
		}, want: "asn_database"},
	}

	deps := &core.Deps{Limits: core.Limits{MaxIntelFileBytes: 1 << 20}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "intel", Type: Type, Enabled: true, Phase: core.PhaseRequest, Settings: tc.settings,
			}, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际 %v", tc.want, err)
			}
		})
	}
}
