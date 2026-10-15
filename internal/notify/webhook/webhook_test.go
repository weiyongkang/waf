package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// testAlert 构造一条用于外送的测试告警。
func testAlert() core.Alert {
	return core.Alert{
		Level:     core.AlertLevelWarn,
		Title:     "自动封禁已触发",
		Message:   "客户端在 60 秒内命中 20 次",
		Site:      "shop",
		ClientIP:  "203.0.113.10",
		RequestID: "req-1",
		Fields:    map[string]string{"rule_id": "900100"},
		At:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// newInstance 构造指向给定地址的通道声明。
func newInstance(name string, settings map[string]any) notify.Instance {
	return notify.Instance{Name: name, Type: Type, Settings: settings}
}

// TestRegistered 验证包在被导入时完成了类型注册（fail fast 依赖该注册）。
func TestRegistered(t *testing.T) {
	found := false
	for _, name := range notify.RegisteredTypes() {
		if name == Type {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("类型 %q 未注册，已注册类型：%v", Type, notify.RegisteredTypes())
	}
}

// TestNewRejectsInvalidSettings 验证构造期的配置校验（fail fast）。
func TestNewRejectsInvalidSettings(t *testing.T) {
	cases := map[string]map[string]any{
		"缺少 url": {},
		"协议不支持":  {"url": "ftp://example.com/hook"},
		"方法不支持":  {"url": "https://example.com/hook", "method": "DELETE"},
		"存在未知字段": {"url": "https://example.com/hook", "unknown_field": 1},
	}
	for name, settings := range cases {
		if _, err := New(newInstance("t", settings), notify.Deps{}); err == nil {
			t.Fatalf("%s：应当返回错误", name)
		}
	}
}

// TestSendPostsStructuredPayload 验证成功投递的请求形态与载荷字段。
func TestSendPostsStructuredPayload(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotAuth        string
		gotBody        map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{
		"url":     server.URL,
		"headers": map[string]any{"Authorization": "Bearer token-1"},
	}), notify.Deps{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("外送失败：%v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("默认方法应为 POST，实际 %s", gotMethod)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Fatalf("Content-Type 不符：%s", gotContentType)
	}
	if gotAuth != "Bearer token-1" {
		t.Fatalf("自定义请求头未生效：%q", gotAuth)
	}
	if gotBody["level"] != "warn" || gotBody["title"] != "自动封禁已触发" {
		t.Fatalf("载荷字段不符：%+v", gotBody)
	}
	if gotBody["client_ip"] != "203.0.113.10" || gotBody["request_id"] != "req-1" {
		t.Fatalf("载荷缺少定位字段：%+v", gotBody)
	}
	if gotBody["at"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("时间字段应为 RFC3339，实际 %v", gotBody["at"])
	}
	// 约束（需求 P1-7）：载荷不得包含原始请求体 / 请求头。
	for _, forbidden := range []string{"body", "headers", "raw_request"} {
		if _, exists := gotBody[forbidden]; exists {
			t.Fatalf("载荷不应包含字段 %q：%+v", forbidden, gotBody)
		}
	}
}

// TestSendFailsOnNon2xx 验证非 2xx 视为失败，并把响应片段带回错误信息。
func TestSendFailsOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte("网关内部错误"))
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	err = sender.Send(context.Background(), testAlert())
	if err == nil {
		t.Fatal("非 2xx 状态应当返回错误")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "网关内部错误") {
		t.Fatalf("错误信息应包含状态码与响应片段，实际：%v", err)
	}
}

// TestSendRespectsContextCancellation 验证上下文取消时立即返回（不拖慢工作协程）。
func TestSendRespectsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := sender.Send(ctx, testAlert()); err == nil {
		t.Fatal("上下文取消时应当返回错误")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("上下文取消后应立即返回，实际耗时 %s", elapsed)
	}
}

// TestNameAndType 验证实例名与类型名的返回。
func TestNameAndType(t *testing.T) {
	sender, err := New(newInstance("hook-a", map[string]any{"url": "https://example.com/hook"}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()
	if sender.Name() != "hook-a" || sender.Type() != Type {
		t.Fatalf("Name/Type 不符：%q / %q", sender.Name(), sender.Type())
	}
}
