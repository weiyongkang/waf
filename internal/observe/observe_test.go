package observe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDisabledRegistry 验证「指标关闭」时既不暴露数据、写入器也可安全调用。
//
// 对应需求 R6：任何能力关闭后都必须零副作用，且调用方无需判空。
func TestDisabledRegistry(t *testing.T) {
	registry := New(Options{Enabled: false})

	if registry.Enabled() {
		t.Fatalf("Enabled() = true，期望 false")
	}

	recorder := registry.Recorder()
	if recorder == nil {
		t.Fatalf("Recorder() 返回 nil，期望空实现")
	}
	// 空实现必须可安全调用（否则调用方到处都要判空）。
	recorder.IncRequest("default", "allow")
	recorder.ObserveCheckDuration("demo", 0.001)
	recorder.IncBlocked("demo", "1")
	recorder.AddBodyBytes("demo", 128)
	recorder.IncBodyTruncated()
	recorder.IncBodySkipped()
	recorder.IncBodyMissing()
	recorder.IncBan("client_ip")
	recorder.IncDenyRender()
	recorder.IncStoreError("default")
	recorder.IncCheckError("demo")

	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, DefaultPath, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("关闭指标时状态码 = %d，期望 404", response.Code)
	}
	if !strings.Contains(response.Body.String(), "WAF_METRICS_DISABLED") {
		t.Fatalf("关闭指标时响应体缺少错误码标记：%s", response.Body.String())
	}
}

// TestEnabledRegistryExposesMetrics 验证启用后每个写入方法都能产出对应的指标序列。
func TestEnabledRegistryExposesMetrics(t *testing.T) {
	registry := New(Options{
		Enabled:   true,
		Namespace: "waf",
		Version:   "1.2.3",
		Commit:    "abc123",
	})
	if !registry.Enabled() {
		t.Fatalf("Enabled() = false，期望 true")
	}

	recorder := registry.Recorder()
	recorder.IncRequest("shop", "block")
	recorder.ObserveCheckDuration("coraza", 0.002)
	recorder.IncCheckError("coraza")
	recorder.IncBlocked("coraza", "942100")
	recorder.AddBodyBytes("coraza", 2048)
	recorder.IncBodyTruncated()
	recorder.IncBodySkipped()
	recorder.IncBodyMissing()
	recorder.IncBan("client_ip+site")
	recorder.IncDenyRender()
	recorder.IncStoreError("default")
	recorder.IncRequest("shop", "allow")

	body := scrape(t, registry)

	expectations := []string{
		`waf_requests_total{site="shop",verdict="block"} 1`,
		`waf_requests_total{site="shop",verdict="allow"} 1`,
		`waf_check_errors_total{check="coraza"} 1`,
		`waf_blocked_total{check="coraza",rule_id="942100"} 1`,
		`waf_body_bytes_total{check="coraza"} 2048`,
		`waf_body_truncated_total 1`,
		`waf_body_skipped_total 1`,
		`waf_body_missing_total 1`,
		`waf_bans_total{scope="client_ip+site"} 1`,
		`waf_deny_render_total 1`,
		`waf_store_errors_total{store="default"} 1`,
		`waf_build_info{commit="abc123",version="1.2.3"} 1`,
		`waf_check_duration_seconds_count{check="coraza"} 1`,
	}
	for _, expected := range expectations {
		if !strings.Contains(body, expected) {
			t.Errorf("指标输出缺少 %q\n实际输出：\n%s", expected, body)
		}
	}

	// 运行时与进程指标应当随指标能力一并暴露（容器排障的第一手资料）。
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("指标输出缺少 go_goroutines")
	}
}

// TestCustomNamespace 验证指标名前缀可配置（需求 R13：不硬编码）。
func TestCustomNamespace(t *testing.T) {
	registry := New(Options{Enabled: true, Namespace: "wafcanary"})
	registry.Recorder().IncRequest("default", "allow")

	body := scrape(t, registry)
	if !strings.Contains(body, `wafcanary_requests_total{site="default",verdict="allow"} 1`) {
		t.Fatalf("自定义前缀未生效，实际输出：\n%s", body)
	}
}

// TestDefaultNamespaceFallback 验证前缀为空时回落为默认值。
func TestDefaultNamespaceFallback(t *testing.T) {
	registry := New(Options{Enabled: true, Namespace: ""})
	registry.Recorder().IncRequest("default", "allow")

	body := scrape(t, registry)
	if !strings.Contains(body, "waf_requests_total{") {
		t.Fatalf("默认前缀未生效，实际输出：\n%s", body)
	}
}

// scrape 通过暴露端点抓取一次指标文本。
//
// 之所以走完整的 HTTP 端点而不是直接调用 Gather()：
// 这样同时覆盖了「处理器装配是否正确」这一层，避免出现「采集器对了但端点错了」。
func scrape(t *testing.T, registry *Registry) string {
	t.Helper()

	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, DefaultPath, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("抓取指标状态码 = %d，期望 200", response.Code)
	}

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("读取指标响应失败：%v", err)
	}
	return string(raw)
}
