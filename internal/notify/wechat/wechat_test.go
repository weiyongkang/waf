package wechat

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
		Message:   "客户端在 60 秒内命中 20 次\n（第二行用于验证换行被压平）",
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

// TestRegistered 验证包在被导入时完成了类型注册。
func TestRegistered(t *testing.T) {
	for _, name := range notify.RegisteredTypes() {
		if name == Type {
			return
		}
	}
	t.Fatalf("类型 %q 未注册，已注册类型：%v", Type, notify.RegisteredTypes())
}

// TestNewRejectsInvalidSettings 验证构造期的配置校验。
func TestNewRejectsInvalidSettings(t *testing.T) {
	cases := map[string]map[string]any{
		"缺少 url": {},
		"格式不支持":  {"url": "https://example.com/hook", "format": "card"},
		"存在未知字段": {"url": "https://example.com/hook", "token": "x"},
	}
	for name, settings := range cases {
		if _, err := New(newInstance("t", settings), notify.Deps{}); err == nil {
			t.Fatalf("%s：应当返回错误", name)
		}
	}
}

// TestSendMarkdownMessage 验证默认按 markdown 报文发送，且包含关键定位信息。
func TestSendMarkdownMessage(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = rw.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("外送失败：%v", err)
	}

	if got["msgtype"] != formatMarkdown {
		t.Fatalf("默认应为 markdown 报文，实际 %v", got["msgtype"])
	}
	markdown, ok := got["markdown"].(map[string]any)
	if !ok {
		t.Fatalf("报文缺少 markdown 容器：%+v", got)
	}
	content, _ := markdown["content"].(string)
	for _, expected := range []string{"警告", "自动封禁已触发", "shop", "203.0.113.10", "900100", "req-1"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("正文缺少 %q：\n%s", expected, content)
		}
	}
	if strings.Contains(content, "\n（第二行") {
		t.Fatalf("正文换行应被压平，实际：\n%s", content)
	}
}

// TestSendTextMessage 验证 format=text 时使用纯文本报文。
func TestSendTextMessage(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = rw.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL, "format": "text"}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("外送失败：%v", err)
	}
	if got["msgtype"] != formatText {
		t.Fatalf("应为 text 报文，实际 %v", got["msgtype"])
	}
	text, ok := got["text"].(map[string]any)
	if !ok {
		t.Fatalf("报文缺少 text 容器：%+v", got)
	}
	if content, _ := text["content"].(string); !strings.Contains(content, "自动封禁已触发") {
		t.Fatalf("正文缺少标题：%v", content)
	}
}

// TestSendFailsOnBusinessErrorCode 验证 HTTP 200 但 errcode != 0 时视为失败。
//
// 这是企业微信通道与通用 webhook 的关键差异：只看状态码会把
// 「机器人 key 已失效」误判为「已经告警成功」。
func TestSendFailsOnBusinessErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	err = sender.Send(context.Background(), testAlert())
	if err == nil {
		t.Fatal("errcode != 0 应当返回错误")
	}
	if !strings.Contains(err.Error(), "93000") {
		t.Fatalf("错误信息应包含业务错误码，实际：%v", err)
	}
}

// TestSendFailsOnNonJSONResponse 验证响应体不是 JSON 时视为失败。
func TestSendFailsOnNonJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("<html>bad gateway</html>"))
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err == nil {
		t.Fatal("响应体非 JSON 应当返回错误")
	}
}

// TestSendFailsOnNon2xx 验证非 2xx 状态视为失败。
func TestSendFailsOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	sender, err := New(newInstance("t", map[string]any{"url": server.URL}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err == nil {
		t.Fatal("非 2xx 应当返回错误")
	}
}
