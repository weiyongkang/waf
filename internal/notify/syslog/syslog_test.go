package syslog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// testAlert 构造一条用于渲染的测试告警。
func testAlert() core.Alert {
	return core.Alert{
		Level:     core.AlertLevelError,
		Title:     "共享存储不可用",
		Message:   "Redis 连接被拒绝",
		Site:      "shop",
		ClientIP:  "203.0.113.10",
		RequestID: "req-1",
		Fields:    map[string]string{"rule_id": "900200"},
		At:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// newInstance 构造通道声明。
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
//
// 注意：这里只覆盖「配置本身非法」的分支，它们的判断发生在建立连接之前，
// 因此在任何平台上的行为都是一致的（不受 log/syslog 平台差异影响）。
func TestNewRejectsInvalidSettings(t *testing.T) {
	cases := map[string]map[string]any{
		"网络协议非法": {"network": "http", "address": "127.0.0.1:514"},
		"有网络无地址": {"network": "tcp"},
		"设施名非法":  {"facility": "local9"},
		"格式非法":   {"format": "xml"},
		"存在未知字段": {"tag_name": "x"},
	}
	for name, settings := range cases {
		if _, err := New(newInstance("t", settings), notify.Deps{}); err == nil {
			t.Fatalf("%s：应当返回错误", name)
		}
	}
}

// TestRenderSummary 验证 summary 格式输出一行可读摘要。
func TestRenderSummary(t *testing.T) {
	instance := &notifier{name: "t", format: formatSummary}
	line, err := instance.render(testAlert())
	if err != nil {
		t.Fatalf("渲染失败：%v", err)
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("summary 格式应为单行：%q", line)
	}
	for _, expected := range []string{"ERROR", "共享存储不可用", "shop", "203.0.113.10", "900200", "req-1"} {
		if !strings.Contains(line, expected) {
			t.Fatalf("摘要缺少 %q：%s", expected, line)
		}
	}
}

// TestRenderJSON 验证 json 格式输出完整结构化载荷。
func TestRenderJSON(t *testing.T) {
	instance := &notifier{name: "t", format: formatJSON}
	line, err := instance.render(testAlert())
	if err != nil {
		t.Fatalf("渲染失败：%v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("json 格式应可被解析：%v", err)
	}
	if decoded["level"] != "error" || decoded["title"] != "共享存储不可用" {
		t.Fatalf("字段不符：%+v", decoded)
	}
	// 约束（需求 P1-7）：不得外送原始请求体 / 请求头。
	for _, forbidden := range []string{"body", "headers"} {
		if _, exists := decoded[forbidden]; exists {
			t.Fatalf("载荷不应包含字段 %q", forbidden)
		}
	}
}

// TestSeverityFor 验证告警级别到 syslog 严重级别的映射。
func TestSeverityFor(t *testing.T) {
	cases := map[core.AlertLevel]severity{
		core.AlertLevelError: severityErr,
		core.AlertLevelWarn:  severityWarning,
		core.AlertLevelInfo:  severityInfo,
		"":                   severityInfo,
		"unknown":            severityInfo,
	}
	for level, expected := range cases {
		if got := severityFor(level); got != expected {
			t.Fatalf("级别 %q 应映射为 %d，实际 %d", level, expected, got)
		}
	}
}

// TestFacilityNames 验证设施名映射覆盖常用取值且默认值为 local0。
func TestFacilityNames(t *testing.T) {
	for _, name := range []string{"kern", "user", "daemon", "auth", "authpriv", "cron", "local0", "local7"} {
		if _, ok := facilityNames[name]; !ok {
			t.Fatalf("设施名 %q 应当被支持", name)
		}
	}
	if facilityNames["local0"] != facilityLocal0 {
		t.Fatalf("local0 应映射为 %d", facilityLocal0)
	}
}
