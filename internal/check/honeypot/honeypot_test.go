package honeypot

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"gopkg.in/yaml.v3"
)

// newCheckFromYAML 构造测试用蜜罐实例；settings 由 YAML 片段提供，便于覆盖真实配置写法。
func newCheckFromYAML(t *testing.T, raw string) *Check {
	t.Helper()

	var settings map[string]any
	if err := yaml.Unmarshal([]byte(raw), &settings); err != nil {
		t.Fatalf("解析测试配置失败：%v", err)
	}
	check, err := New(core.InstanceConfig{
		Name:     "honeypot",
		Type:     Type,
		Phase:    core.PhasePre,
		Settings: settings,
	}, &core.Deps{})
	if err != nil {
		t.Fatalf("构造蜜罐实例失败：%v", err)
	}
	return check.(*Check)
}

// newHoneypotContext 构造带原始请求信息的请求上下文。
func newHoneypotContext(t *testing.T, method, target string) *core.RequestContext {
	t.Helper()

	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("解析测试 URL 失败：%v", err)
	}
	rctx := core.NewRequestContext("REQ-HP", time.Now())
	rctx.Raw = &core.RawRequest{
		Method:     method,
		URI:        parsed.RequestURI(),
		Path:       parsed.Path,
		RawQuery:   parsed.RawQuery,
		ClientIP:   "192.0.2.10",
		ReceivedAt: time.Now(),
	}
	return rctx
}

// TestEvaluateReturnsRuleResponse 覆盖参考实现的核心语义：method + path 精确命中后直接返回规则响应。
func TestEvaluateReturnsRuleResponse(t *testing.T) {
	check := newCheckFromYAML(t, `
rules:
  - name: phpinfo
    method: GET
    path: /phpinfo.php
    status: 200
    content_type: text/html
    headers:
      Server: Apache/2.4.59
    body: '<h1>PHP Version 8.2.17</h1>'
score: 7
`)

	result, err := check.Evaluate(newHoneypotContext(t, "GET", "/phpinfo.php"))
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result == nil {
		t.Fatal("命中规则时不应返回 nil")
	}
	if result.Verdict != core.VerdictHoneypot {
		t.Fatalf("verdict = %s，期望 honeypot", result.Verdict)
	}
	if result.Response == nil {
		t.Fatal("蜜罐命中必须携带 ResponseOverride")
	}
	if result.Response.Status != 200 || result.Response.ContentType != "text/html" {
		t.Fatalf("响应覆盖 = %+v", result.Response)
	}
	if result.Response.Headers["Server"] != "Apache/2.4.59" {
		t.Fatalf("自定义响应头未保留：%+v", result.Response.Headers)
	}
	if !strings.Contains(result.Response.Body, "PHP Version") {
		t.Fatalf("响应正文不符：%q", result.Response.Body)
	}
	if result.Score != 7 {
		t.Fatalf("score = %d，期望 7", result.Score)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "honeypot:phpinfo" {
		t.Fatalf("finding 不符：%+v", result.Findings)
	}
	if len(result.Alerts) != 1 {
		t.Fatalf("默认应产生一条告警，实际 %d", len(result.Alerts))
	}
}

// TestMatchHoneypotHasNoSideEffects 覆盖渲染端点复用匹配逻辑时
// 不重复累加评分、不产生告警，但仍返回完整响应覆盖。
func TestMatchHoneypotHasNoSideEffects(t *testing.T) {
	check := newCheckFromYAML(t, `
rules:
  - name: phpinfo
    method: GET
    path: /phpinfo.php
    status: 200
    content_type: text/html
    body: '<h1>PHP Version 8.2.17</h1>'
score: 7
`)

	result := check.MatchHoneypot(newHoneypotContext(t, "GET", "/phpinfo.php"))
	if result == nil || result.Response == nil {
		t.Fatal("渲染匹配必须返回 ResponseOverride")
	}
	if result.Verdict != core.VerdictHoneypot {
		t.Fatalf("verdict = %s，期望 honeypot", result.Verdict)
	}
	if result.Score != 0 {
		t.Fatalf("渲染匹配不应重复累加评分，实际 %d", result.Score)
	}
	if len(result.Alerts) != 0 {
		t.Fatalf("渲染匹配不应重复产生告警，实际 %d 条", len(result.Alerts))
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "honeypot:phpinfo" {
		t.Fatalf("finding 不符：%+v", result.Findings)
	}
}

// TestEvaluateMissAndMethodIsolation 覆盖：未命中与方法不匹配时继续执行后续校验单元。
func TestEvaluateMissAndMethodIsolation(t *testing.T) {
	check := newCheckFromYAML(t, `
rules:
  - method: GET
    path: /.env
    status: 200
    body: SECRET=1
`)

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{name: "路径不匹配", method: "GET", target: "/.git/HEAD"},
		{name: "方法不匹配", method: "POST", target: "/.env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := check.Evaluate(newHoneypotContext(t, tc.method, tc.target))
			if err != nil {
				t.Fatalf("Evaluate 返回错误：%v", err)
			}
			if result != nil {
				t.Fatalf("未命中时应返回 nil，实际 %+v", result)
			}
		})
	}
}

// TestFirstMatchWins 覆盖：多条规则命中时只使用第一条。
func TestFirstMatchWins(t *testing.T) {
	check := newCheckFromYAML(t, `
rules:
  - name: first
    method: GET
    match: prefix
    path: /admin
    status: 201
    body: first
  - name: second
    method: GET
    path: /admin
    status: 202
    body: second
`)
	result, err := check.Evaluate(newHoneypotContext(t, "GET", "/admin"))
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if result.Response.Status != 201 || result.Response.Body != "first" {
		t.Fatalf("应使用第一条规则，实际 %+v", result.Response)
	}
}

// TestMatchModesAndQuery 覆盖 prefix / glob / regex / 带查询串的 URI 匹配。
func TestMatchModesAndQuery(t *testing.T) {
	check := newCheckFromYAML(t, `
rules:
  - name: prefix
    method: GET
    match: prefix
    path: /api/internal/
    body: prefix
  - name: glob
    method: GET
    match: glob
    path: '/backup/*.sql'
    body: glob
  - name: regex
    method: GET
    match: regex
    path: '^/debug/[0-9]+$'
    body: regex
  - name: query
    method: GET
    path: '/index.php?option=com_users'
    body: query
`)

	cases := []struct {
		target string
		body   string
	}{
		{target: "/api/internal/users", body: "prefix"},
		{target: "/backup/db.sql", body: "glob"},
		{target: "/debug/123", body: "regex"},
		{target: "/index.php?option=com_users", body: "query"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			result, err := check.Evaluate(newHoneypotContext(t, "GET", tc.target))
			if err != nil {
				t.Fatalf("Evaluate 返回错误：%v", err)
			}
			if result == nil || result.Response.Body != tc.body {
				t.Fatalf("target=%s 命中结果 = %+v，期望 body=%s", tc.target, result, tc.body)
			}
		})
	}
}

// TestAlertCanBeDisabled 覆盖：告警默认开启，但可以按实例关闭。
func TestAlertCanBeDisabled(t *testing.T) {
	check := newCheckFromYAML(t, `
alert: false
rules:
  - method: GET
    path: /trap
    body: ok
`)
	result, err := check.Evaluate(newHoneypotContext(t, "GET", "/trap"))
	if err != nil {
		t.Fatalf("Evaluate 返回错误：%v", err)
	}
	if len(result.Alerts) != 0 {
		t.Fatalf("alert=false 时不应产生告警，实际 %d 条", len(result.Alerts))
	}
}

// TestLoadRulesDir 覆盖：目录规则按文件路径稳定排序，并兼容 content-type 写法。
func TestLoadRulesDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("创建规则子目录失败：%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-a.yaml"), []byte(`
- method: GET
  path: /a
  status: 201
  content-type: text/plain
  body: A
`), 0o600); err != nil {
		t.Fatalf("写入规则文件失败：%v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "20-b.yml"), []byte(`
- method: GET
  path: /b
  status: 202
  body: B
`), 0o600); err != nil {
		t.Fatalf("写入规则文件失败：%v", err)
	}

	check, err := New(core.InstanceConfig{
		Name:  "honeypot",
		Type:  Type,
		Phase: core.PhasePre,
		Settings: map[string]any{
			"rules_dir": dir,
		},
	}, &core.Deps{})
	if err != nil {
		t.Fatalf("从目录构造蜜罐实例失败：%v", err)
	}
	typed := check.(*Check)
	if len(typed.rules) != 2 {
		t.Fatalf("规则数 = %d，期望 2", len(typed.rules))
	}
	if typed.rules[0].Name != "10-a#1" {
		t.Fatalf("首个规则名 = %q，期望 10-a#1", typed.rules[0].Name)
	}
	if typed.rules[0].ContentType != "text/plain" {
		t.Fatalf("content-type 兼容字段未生效：%q", typed.rules[0].ContentType)
	}

	result, err := typed.Evaluate(newHoneypotContext(t, "GET", "/b"))
	if err != nil || result == nil || result.Response.Status != 202 {
		t.Fatalf("目录规则未生效：result=%+v err=%v", result, err)
	}
}

// TestHotReloadRulesDir 覆盖：rules_dir 中的规则变化后自动重建并原子替换，
// 且渲染阶段的 MatchHoneypot 也使用新规则。
func TestHotReloadRulesDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("创建规则子目录失败：%v", err)
	}
	ruleFile := filepath.Join(nested, "bait.yaml")
	if err := os.WriteFile(ruleFile, []byte(`
- method: GET
  path: /old-bait
  status: 201
  body: old
`), 0o600); err != nil {
		t.Fatalf("写入规则文件失败：%v", err)
	}

	check, err := New(core.InstanceConfig{
		Name:  "honeypot",
		Type:  Type,
		Phase: core.PhasePre,
		Settings: map[string]any{
			"rules_dir": dir,
		},
	}, &core.Deps{Engine: core.EngineSettings{
		HotReload: core.HotReloadSetting{
			Enabled:      true,
			PollInterval: 20 * time.Millisecond,
			Debounce:     10 * time.Millisecond,
		},
	}})
	if err != nil {
		t.Fatalf("构造带热加载的蜜罐实例失败：%v", err)
	}
	t.Cleanup(func() { _ = check.Close() })

	if _, ok := check.(*reloader); !ok {
		t.Fatalf("配置 rules_dir 且开启热加载时应返回 reloader，实际 %T", check)
	}

	result, err := check.Evaluate(newHoneypotContext(t, "GET", "/old-bait"))
	if err != nil || result == nil || result.Response == nil || result.Response.Body != "old" {
		t.Fatalf("热加载前规则未生效：result=%+v err=%v", result, err)
	}

	if err := os.WriteFile(ruleFile, []byte(`
- method: GET
  path: /new-bait
  status: 202
  body: new
`), 0o600); err != nil {
		t.Fatalf("更新规则文件失败：%v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		result, err = check.Evaluate(newHoneypotContext(t, "GET", "/new-bait"))
		if err == nil && result != nil && result.Response != nil && result.Response.Body == "new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待规则热加载超时：result=%+v err=%v", result, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 渲染端点走 HoneypotMatcher 接口，必须同样看到新规则。
	rendered := check.(core.HoneypotMatcher).MatchHoneypot(newHoneypotContext(t, "GET", "/new-bait"))
	if rendered == nil || rendered.Response == nil || rendered.Response.Status != 202 {
		t.Fatalf("热加载后 MatchHoneypot 未使用新规则：%+v", rendered)
	}

	old, err := check.Evaluate(newHoneypotContext(t, "GET", "/old-bait"))
	if err != nil || old != nil {
		t.Fatalf("旧规则应已被替换，result=%+v err=%v", old, err)
	}
}

// TestHotReloadFailureKeepsOldRules 覆盖：新规则解析失败时继续使用旧规则。
func TestHotReloadFailureKeepsOldRules(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "bait.yaml")
	if err := os.WriteFile(ruleFile, []byte(`
- method: GET
  path: /stable-bait
  status: 200
  body: stable
`), 0o600); err != nil {
		t.Fatalf("写入规则文件失败：%v", err)
	}

	check, err := New(core.InstanceConfig{
		Name:  "honeypot",
		Type:  Type,
		Phase: core.PhasePre,
		Settings: map[string]any{
			"rules_dir": dir,
		},
	}, &core.Deps{Engine: core.EngineSettings{
		HotReload: core.HotReloadSetting{
			Enabled:      true,
			PollInterval: 20 * time.Millisecond,
			Debounce:     10 * time.Millisecond,
		},
	}})
	if err != nil {
		t.Fatalf("构造带热加载的蜜罐实例失败：%v", err)
	}
	t.Cleanup(func() { _ = check.Close() })

	if err := os.WriteFile(ruleFile, []byte("not: [valid"), 0o600); err != nil {
		t.Fatalf("写入非法规则文件失败：%v", err)
	}

	// 给监听器至少两轮轮询与一次去抖的时间。
	time.Sleep(200 * time.Millisecond)

	result, err := check.Evaluate(newHoneypotContext(t, "GET", "/stable-bait"))
	if err != nil || result == nil || result.Response == nil || result.Response.Body != "stable" {
		t.Fatalf("热加载失败后应保留旧规则：result=%+v err=%v", result, err)
	}
}

// TestInvalidRulesFailFast 覆盖：非法规则必须在启动阶段报错，而不是静默跳过。
func TestInvalidRulesFailFast(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{name: "空规则集", yaml: "{}"},
		{name: "非法正则", yaml: "rules:\n  - path: '['\n    match: regex\n"},
		{name: "非法状态码", yaml: "rules:\n  - path: /x\n    status: 199\n"},
		{name: "禁止逐跳头", yaml: "rules:\n  - path: /x\n    headers:\n      Content-Length: '10'\n"},
		{name: "重复规则名", yaml: "rules:\n  - name: same\n    path: /a\n  - name: same\n    path: /b\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var settings map[string]any
			if err := yaml.Unmarshal([]byte(tc.yaml), &settings); err != nil {
				t.Fatalf("解析测试配置失败：%v", err)
			}
			if _, err := New(core.InstanceConfig{
				Name:     "honeypot",
				Type:     Type,
				Phase:    core.PhasePre,
				Settings: settings,
			}, &core.Deps{}); err == nil {
				t.Fatal("非法规则应导致构造失败")
			}
		})
	}
}
