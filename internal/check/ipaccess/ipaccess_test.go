package ipaccess

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// buildCheck 依据配置片段构造校验单元，构造失败直接终止测试。
func buildCheck(t *testing.T, settings map[string]any, maxIntelBytes int64) core.Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name:     "ip-access",
		Type:     Type,
		Enabled:  true,
		Order:    10,
		Phase:    core.PhasePre,
		Settings: settings,
	}, &core.Deps{
		Metrics: core.NoopMetrics{},
		Clock:   core.SystemClock{},
		Limits:  core.Limits{MaxIntelFileBytes: maxIntelBytes},
	})
	if err != nil {
		t.Fatalf("构造 ipaccess 失败：%v", err)
	}
	return check
}

// newRequestContext 构造带指定客户端 IP 的请求上下文。
func newRequestContext(clientIP string) *core.RequestContext {
	rctx := core.NewRequestContext("req-ip", time.Now())
	rctx.Raw.Header = http.Header{}
	rctx.Raw.ClientIP = clientIP
	rctx.Site = &core.Site{Name: core.DefaultSiteName}
	return rctx
}

// TestAllowlistShortCircuits 覆盖：白名单命中直接放行（短路整条链）。
func TestAllowlistShortCircuits(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"allowlist": []any{"192.168.0.0/16"},
		"blocklist": []any{"192.168.1.1"},
	}, 0)

	result, err := check.Evaluate(newRequestContext("192.168.1.1"))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictAllow {
		t.Fatalf("白名单优先级最高，应显式放行，实际 %+v", result)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "ip_allowlist" {
		t.Fatalf("命中明细不符：%+v", result.Findings)
	}
}

// TestBlocklistBlocks 覆盖：黑名单命中产生拦截结论。
func TestBlocklistBlocks(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"blocklist": []any{"203.0.113.0/24"},
		"score":     5,
	}, 0)

	result, err := check.Evaluate(newRequestContext("203.0.113.9"))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %+v", result)
	}
	if result.Score != 5 {
		t.Fatalf("评分应为 5，实际 %d", result.Score)
	}
}

// TestBlocklistObserve 覆盖：观察模式下只记录不拦截。
func TestBlocklistObserve(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"blocklist": []any{"203.0.113.9"},
		"action":    "observe",
	}, 0)

	result, err := check.Evaluate(newRequestContext("203.0.113.9"))
	if err != nil {
		t.Fatalf("校验返回错误：%v", err)
	}
	if result == nil || result.Verdict != core.VerdictObserve {
		t.Fatalf("期望观察结论，实际 %+v", result)
	}
}

// TestNoMatchNoConclusion 覆盖：名单都不命中时不产生结论。
func TestNoMatchNoConclusion(t *testing.T) {
	check := buildCheck(t, map[string]any{"blocklist": []any{"203.0.113.9"}}, 0)

	result, err := check.Evaluate(newRequestContext("198.51.100.1"))
	if err != nil || result != nil {
		t.Fatalf("未命中应无结论无错误，实际 result=%+v err=%v", result, err)
	}
}

// TestUnknownClientIP 覆盖：无法确定来源地址时不产生结论。
func TestUnknownClientIP(t *testing.T) {
	check := buildCheck(t, map[string]any{
		"allowlist": []any{"0.0.0.0/0"},
	}, 0)

	result, err := check.Evaluate(newRequestContext(""))
	if err != nil || result != nil {
		t.Fatalf("无法确定来源地址时不应产生结论，实际 result=%+v err=%v", result, err)
	}
}

// TestBlocklistFile 覆盖：从文件加载黑名单（支持注释、空行与首尾空白）。
func TestBlocklistFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	content := "# 这是注释\n\n203.0.113.7\n  198.51.100.0/24  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入名单文件失败：%v", err)
	}

	check := buildCheck(t, map[string]any{"blocklist_file": path}, 0)

	if result, err := check.Evaluate(newRequestContext("203.0.113.7")); err != nil {
		t.Fatalf("校验返回错误：%v", err)
	} else if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("文件中的单 IP 应命中黑名单，实际 %+v", result)
	}
	if result, err := check.Evaluate(newRequestContext("198.51.100.55")); err != nil {
		t.Fatalf("校验返回错误：%v", err)
	} else if result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("文件中的网段应命中黑名单，实际 %+v", result)
	}
}

// TestBlocklistFileTooLarge 覆盖：名单文件超过限额时构造失败（需求 R13）。
func TestBlocklistFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("203.0.113.7\n198.51.100.8\n"), 0o600); err != nil {
		t.Fatalf("写入名单文件失败：%v", err)
	}

	if _, err := New(core.InstanceConfig{
		Name: "ip-access", Type: Type, Enabled: true, Phase: core.PhasePre,
		Settings: map[string]any{"blocklist_file": path},
	}, &core.Deps{Limits: core.Limits{MaxIntelFileBytes: 4}}); err == nil {
		t.Fatal("名单文件超过 limits.max_intel_file_bytes 时应构造失败")
	}
}

// TestNewValidation 覆盖：非法配置在构造阶段直接失败。
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{name: "非法IP", settings: map[string]any{"blocklist": []any{"999.1.1.1"}}},
		{name: "非法CIDR", settings: map[string]any{"allowlist": []any{"10.0.0.0/40"}}},
		{name: "非法动作", settings: map[string]any{"action": "drop"}},
		{name: "未知字段", settings: map[string]any{"typo": 1}},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := New(core.InstanceConfig{
				Name: "ip-access", Type: Type, Enabled: true, Phase: core.PhasePre, Settings: item.settings,
			}, &core.Deps{})
			if err == nil {
				t.Fatal("非法配置应在构造阶段直接失败")
			}
		})
	}
}
