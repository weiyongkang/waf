package responder

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// TestResponderTemplateRendersConfiguredFields 覆盖：自定义模板可使用请求与判定字段。
func TestResponderTemplateRendersConfiguredFields(t *testing.T) {
	writer, err := New(Config{
		IncludeDetails: true,
		Messages:       map[string]string{config.CodeRateLimited: "访问太频繁"},
		Template: `{"code":{{ .Code | json }},"status":{{ .Status }},"message":{{ .Message | json }},` +
			`"request_id":{{ .RequestID | json }},"path":{{ .Path | json }},"client_ip":{{ .ClientIP | json }},` +
			`"site":{{ .Site | json }},"rule_id":{{ .RuleID | json }},"score":{{ .Score }},` +
			`"retry_after":{{ .RetryAfter }}}`,
		MaxBodyBytes: 2048,
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	rctx := core.NewRequestContext("REQ-TEMPLATE", core.SystemClock{}.Now())
	rctx.Site = &core.Site{Name: "shop"}
	rctx.Raw.Path = "/api/user"
	rctx.Raw.ClientIP = "203.0.113.10"
	result := &core.Result{
		Verdict:    core.VerdictRateLimited,
		Code:       config.CodeRateLimited,
		Check:      "ratelimit",
		RetryAfter: 30 * time.Second,
	}
	result.AddFinding(core.Finding{RuleID: "942100", Score: 5})

	recorder := httptest.NewRecorder()
	writer.Respond(recorder, rctx, result)

	if recorder.Code != 429 {
		t.Fatalf("状态码 = %d，期望 429", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("模板输出不是合法 JSON：%v（%s）", err, recorder.Body.String())
	}
	wants := map[string]any{
		"code":        config.CodeRateLimited,
		"status":      float64(429),
		"message":     "访问太频繁",
		"request_id":  "REQ-TEMPLATE",
		"path":        "/api/user",
		"client_ip":   "203.0.113.10",
		"site":        "shop",
		"rule_id":     "942100",
		"score":       float64(5),
		"retry_after": float64(30),
	}
	for key, want := range wants {
		if got := body[key]; got != want {
			t.Errorf("模板字段 %s = %#v，期望 %#v", key, got, want)
		}
	}
}

// TestResponderTemplateRespectsIncludeDetails 覆盖：模板中的 HasDetails 与配置一致。
func TestResponderTemplateRespectsIncludeDetails(t *testing.T) {
	writer, err := New(Config{
		IncludeDetails: false,
		Template: `{"code":{{ .Code | json }},"has_details":{{ .HasDetails }}` +
			`{{ if .HasDetails }},"rule_id":{{ .RuleID | json }}{{ end }}}`,
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	result := &core.Result{Verdict: core.VerdictBlock, Check: "crs"}
	result.AddFinding(core.Finding{RuleID: "942100", Score: 5})
	recorder := httptest.NewRecorder()
	writer.Respond(recorder, core.NewRequestContext("REQ-DETAILS", core.SystemClock{}.Now()), result)

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("模板输出不是合法 JSON：%v（%s）", err, recorder.Body.String())
	}
	if body["has_details"] != false {
		t.Fatalf("include_details=false 时 HasDetails 应为 false，实际 %#v", body["has_details"])
	}
	if _, exists := body["rule_id"]; exists {
		t.Fatal("include_details=false 时模板不应输出检测细节")
	}
}

// TestResponderTemplateFile 覆盖：模板可从外部文件加载。
func TestResponderTemplateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.tmpl")
	if err := os.WriteFile(path, []byte(`{"from_file":{{ .Code | json }}}`), 0o600); err != nil {
		t.Fatalf("写入模板文件失败：%v", err)
	}

	writer, err := New(Config{TemplateFile: path})
	if err != nil {
		t.Fatalf("加载外部模板失败：%v", err)
	}
	recorder := httptest.NewRecorder()
	writer.Render(recorder, "REQ-FILE", config.CodeBadRequest)
	if !strings.Contains(recorder.Body.String(), `"from_file":"WAF_BAD_REQUEST"`) {
		t.Fatalf("外部模板未生效：%s", recorder.Body.String())
	}
}

// TestResponderTemplateCanReferenceCustomMessage 覆盖：样例数据包含自定义文案键。
func TestResponderTemplateCanReferenceCustomMessage(t *testing.T) {
	if _, err := New(Config{
		Messages: map[string]string{"WAF_CUSTOM": "自定义提示"},
		Template: `{"message":{{ .Messages.WAF_CUSTOM | json }}}`,
	}); err != nil {
		t.Fatalf("引用自定义错误码文案的模板应通过启动校验：%v", err)
	}
}

// TestResponderTemplateValidation 覆盖：非法模板与互斥配置在构造阶段失败。
func TestResponderTemplateValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "语法错误", cfg: Config{Template: `{"code":`}},
		{name: "输出不是合法 JSON", cfg: Config{Template: `{"code":{{ .Code }}}`}},
		{name: "内联与文件互斥", cfg: Config{Template: `{}`, TemplateFile: "response.tmpl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("非法模板配置应在构造阶段失败")
			}
		})
	}
}

// TestResponderTemplateRuntimeFailureFallsBack 覆盖：运行期模板渲染失败回退默认 JSON。
func TestResponderTemplateRuntimeFailureFallsBack(t *testing.T) {
	writer, err := New(Config{
		MaxBodyBytes: 64,
		Template: `{{ if eq .Code "WAF_BLOCKED" }}{"ok":true}{{ else }}` +
			`{"code":{{ .Code | json }},"padding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}{{ end }}`,
	})
	if err != nil {
		t.Fatalf("构造响应渲染器失败：%v", err)
	}

	recorder := httptest.NewRecorder()
	writer.Render(recorder, "REQ-FALLBACK", config.CodeRateLimited)

	var body ErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("回退响应不是合法 JSON：%v（%s）", err, recorder.Body.String())
	}
	if body.Code != config.CodeRateLimited {
		t.Fatalf("模板超限后应回退默认结构，实际 code=%q", body.Code)
	}
	if strings.Contains(recorder.Body.String(), "padding") {
		t.Fatal("模板超限后不应输出模板内容")
	}
}
