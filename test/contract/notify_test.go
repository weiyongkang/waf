package contract

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// 本文件覆盖「告警外送」的接入契约（需求 P1-7）：
//
//	校验链产出告警 -> server 投递 -> notify.Manager 扇出 -> 通道真实送达
//
// 为什么必须放在契约测试而不是 notify 包的单元测试里：
// notify 的单元测试用的是替身通道，验证的是「扇出/抑制/重试」这些内部语义；
// 而这里要验证的是**接线是否正确**——配置里的 notifiers 段能否被真正装配起来，
// server 是否真的把 Result.Alerts 交给了外送入口。
// 少了这一层，「告警管理器测试全绿、线上一条也发不出去」是完全可能的。

// webhookRecorder 是一个收集告警载荷的假接收端。
type webhookRecorder struct {
	// server 是接收端点。
	server *httptest.Server
	// mu 保护 payloads。
	mu sync.Mutex
	// payloads 记录收到的全部载荷。
	payloads []map[string]any
}

// newWebhookRecorder 启动假接收端。
func newWebhookRecorder() *webhookRecorder {
	recorder := &webhookRecorder{}
	recorder.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err == nil {
			recorder.mu.Lock()
			recorder.payloads = append(recorder.payloads, payload)
			recorder.mu.Unlock()
		}
		rw.WriteHeader(http.StatusOK)
	}))
	return recorder
}

// Close 关闭假接收端。
func (r *webhookRecorder) Close() { r.server.Close() }

// URL 返回接收地址。
func (r *webhookRecorder) URL() string { return r.server.URL + "/hook" }

// count 返回已收到的载荷数量。
func (r *webhookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.payloads)
}

// first 返回第一条载荷。
func (r *webhookRecorder) first() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.payloads) == 0 {
		return nil
	}
	return r.payloads[0]
}

// waitForPayload 等待至少收到一条载荷。
//
// 告警外送是异步的（队列 + 工作协程），因此必须轮询等待，
// 不能假设「HTTP 响应返回时告警已经送达」。
func (r *webhookRecorder) waitForPayload(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if r.count() > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return r.count() > 0
}

// notifyOverride 构造启用告警外送的覆盖配置。
func notifyOverride(url string) string {
	return fmt.Sprintf(`notify:
  enabled: true
  queue_size: 64
  workers: 2
  timeout: 3s
  min_level: info
  suppress_window: 0
  max_attempts: 2
  retry_backoff: 50ms
  max_tracked_keys: 100
notifiers:
  - name: contract-hook
    type: webhook
    enabled: true
    settings:
      url: %q
      timeout: 3s
`, url)
}

// TestAlertIsDeliveredToWebhookChannel 验证「拦截请求产生告警并真实外送」的完整链路。
func TestAlertIsDeliveredToWebhookChannel(t *testing.T) {
	recorder := newWebhookRecorder()
	defer recorder.Close()

	h := newHarness(t, harnessOptions{override: notifyOverride(recorder.URL())})

	req := forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271")
	resp := h.do(t, req)
	body := readBody(t, resp)

	assertStatus(t, resp, http.StatusForbidden)
	assertJSONCode(t, body, config.CodeBlocked)

	if !recorder.waitForPayload(5 * time.Second) {
		t.Fatalf("拦截后未收到任何告警外送（说明告警没有真正投递到通道）")
	}

	payload := recorder.first()
	if payload == nil {
		t.Fatal("告警载荷为空")
	}
	if payload["level"] == "" || payload["level"] == nil {
		t.Errorf("载荷缺少级别字段：%+v", payload)
	}
	if title, _ := payload["title"].(string); title == "" {
		t.Errorf("载荷缺少标题：%+v", payload)
	}
	if site, _ := payload["site"].(string); site != "default" {
		t.Errorf("载荷站点应为 default，实际 %v", payload["site"])
	}
	if requestID, _ := payload["request_id"].(string); requestID == "" {
		t.Errorf("载荷缺少 request_id（无法反查完整上下文）：%+v", payload)
	}

	// 需求 P1-7 的安全约束：不得把原始请求体 / 请求头外送到第三方通道。
	for _, forbidden := range []string{"body", "headers", "raw_request"} {
		if _, exists := payload[forbidden]; exists {
			t.Errorf("载荷不应包含字段 %q：%+v", forbidden, payload)
		}
	}
}

// TestNotifyDisabledByDefault 验证未启用告警外送时不会产生任何外送动作。
func TestNotifyDisabledByDefault(t *testing.T) {
	recorder := newWebhookRecorder()
	defer recorder.Close()

	// 注意：这里**故意**把通道写成 enabled: true，但总开关保持默认的 false。
	// 这是最容易误读为「已经接了告警」的配置形态，必须不产生任何外送。
	override := fmt.Sprintf(`notifiers:
  - name: contract-hook
    type: webhook
    enabled: true
    settings:
      url: %q
`, recorder.URL())

	h := newHarness(t, harnessOptions{override: override})

	req := forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271")
	resp := h.do(t, req)
	_ = readBody(t, resp)

	time.Sleep(300 * time.Millisecond)
	if recorder.count() != 0 {
		t.Fatalf("notify.enabled = false 时不应有任何外送，实际收到 %d 条", recorder.count())
	}
}

// TestAlertFanOutToMultipleChannels 验证并联扇出：一条告警送达全部启用通道。
func TestAlertFanOutToMultipleChannels(t *testing.T) {
	first := newWebhookRecorder()
	defer first.Close()
	second := newWebhookRecorder()
	defer second.Close()

	override := fmt.Sprintf(`notify:
  enabled: true
  queue_size: 64
  workers: 2
  timeout: 3s
  min_level: info
  suppress_window: 0
  max_attempts: 2
  retry_backoff: 50ms
notifiers:
  - name: hook-a
    type: webhook
    enabled: true
    settings:
      url: %q
  - name: hook-b
    type: webhook
    enabled: true
    settings:
      url: %q
`, first.URL(), second.URL())

	h := newHarness(t, harnessOptions{override: override})

	req := forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271")
	resp := h.do(t, req)
	_ = readBody(t, resp)

	if !first.waitForPayload(5*time.Second) || !second.waitForPayload(5*time.Second) {
		t.Fatalf("并联扇出失败：hook-a=%d 条，hook-b=%d 条", first.count(), second.count())
	}
}

// TestAlertSuppressionDeduplicatesRepeats 验证聚合抑制：窗口内同类告警只发一次。
func TestAlertSuppressionDeduplicatesRepeats(t *testing.T) {
	recorder := newWebhookRecorder()
	defer recorder.Close()

	override := fmt.Sprintf(`notify:
  enabled: true
  queue_size: 64
  workers: 2
  timeout: 3s
  min_level: info
  suppress_window: 5m
  max_attempts: 2
  retry_backoff: 50ms
notifiers:
  - name: hook
    type: webhook
    enabled: true
    settings:
      url: %q
`, recorder.URL())

	h := newHarness(t, harnessOptions{override: override})

	for i := 0; i < 3; i++ {
		resp := h.do(t, forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271"))
		body := readBody(t, resp)
		if !strings.Contains(body, config.CodeBlocked) {
			t.Fatalf("第 %d 次请求应被拦截，实际：%s", i+1, body)
		}
	}

	if !recorder.waitForPayload(5 * time.Second) {
		t.Fatal("未收到任何告警")
	}
	// 给扇出与抑制判定留出余量，确认后续请求没有产生新的外送。
	time.Sleep(300 * time.Millisecond)
	if count := recorder.count(); count != 1 {
		t.Fatalf("聚合抑制窗口内应只外送 1 条，实际 %d 条", count)
	}
}

// TestAlertMetricsCounted 验证告警外送结果被计入指标。
func TestAlertMetricsCounted(t *testing.T) {
	recorder := newWebhookRecorder()
	defer recorder.Close()

	h := newHarness(t, harnessOptions{override: notifyOverride(recorder.URL())})

	resp := h.do(t, forwardAuthRequest("/api/user?id=1%27%20OR%20%271%27%3D%271"))
	_ = readBody(t, resp)

	if !recorder.waitForPayload(5 * time.Second) {
		t.Fatal("未收到告警")
	}

	metricsResp, err := http.Get(h.metrics.URL + h.cfg.Metrics.Path)
	if err != nil {
		t.Fatalf("拉取指标失败：%v", err)
	}
	defer func() { _ = metricsResp.Body.Close() }()
	raw, _ := io.ReadAll(metricsResp.Body)

	if !strings.Contains(string(raw), `waf_alert_total{notifier="contract-hook",result="sent"}`) {
		t.Fatalf("指标中应包含 alert_total 的 sent 计数，实际：\n%s", firstLines(string(raw), 60))
	}

}

// firstLines 返回文本的前 n 行（用于错误信息）。
func firstLines(text string, n int) string {
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
