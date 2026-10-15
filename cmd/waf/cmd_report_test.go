package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// accessLogLine 生成一行访问日志（JSON Lines 格式，字段与 internal/server 的记录一致）。
//
// 时间字段使用 RFC3339：它是唯一权威的时间来源（报表按记录时间过滤，而不是按文件名）。
func accessLogLine(when time.Time, verdict, ruleID, path, clientIP string, wouldBlock bool) string {
	return fmt.Sprintf(
		`{"time":%q,"level":"info","msg":"请求拦截","request_id":"req-1","verdict":%q,`+
			`"check":"crs-header","site":"default","method":"GET","path":%q,"host":"app.example.com",`+
			`"client_ip":%q,"rule_id":%q,"would_block":%t,"score":5,"status":403,"duration_ms":3}`,
		when.Format(time.RFC3339), verdict, path, clientIP, ruleID, wouldBlock,
	)
}

// writeAccessLog 在目录中写入访问日志文件（文件名遵循 <prefix>-<日期>.log 约定）。
func writeAccessLog(t *testing.T, dir, content string) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建日志目录失败：%v", err)
	}
	path := filepath.Join(dir, "waf-access-"+time.Now().Format("2006-01-02")+".log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入访问日志失败：%v", err)
	}
	return path
}

// runReportCommand 执行 report 子命令并返回退出码与两路输出。
func runReportCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	code := runReport(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestReportDispatchRejectsUnknownAction 覆盖：缺少子命令与未知子命令都返回配置错误码。
func TestReportDispatchRejectsUnknownAction(t *testing.T) {
	if code, _, _ := runReportCommand(t); code != exitConfigError {
		t.Errorf("缺少子命令时退出码 = %d，期望 %d", code, exitConfigError)
	}
	if code, _, _ := runReportCommand(t, "no-such-action"); code != exitConfigError {
		t.Errorf("未知子命令时退出码 = %d，期望 %d", code, exitConfigError)
	}
}

// TestReportDetectionAggregatesWouldBlock 覆盖：detection 报表按「若拦截」筛出记录并给出排行。
func TestReportDetectionAggregatesWouldBlock(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := strings.Join([]string{
		accessLogLine(now.Add(-time.Minute), "observe", "942100", "/api/login", "203.0.113.10", true),
		accessLogLine(now.Add(-2*time.Minute), "observe", "942100", "/api/login", "203.0.113.10", true),
		accessLogLine(now.Add(-3*time.Minute), "observe", "941100", "/search", "203.0.113.11", true),
		// 未标记 would_block 的观察记录不应进入「若拦截」统计。
		accessLogLine(now.Add(-4*time.Minute), "observe", "920100", "/index.html", "203.0.113.12", false),
		// 拦截记录不属于「若拦截」统计（它已经被拦了）。
		accessLogLine(now.Add(-5*time.Minute), "block", "942100", "/api/login", "203.0.113.13", false),
	}, "\n") + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "detection", "--dir", dir, "--top", "5")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	for _, want := range []string{"942100", "941100", "/api/login", "203.0.113.10", "942"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("报表输出应包含 %q，实际：\n%s", want, stdout)
		}
	}
	// 未标记 would_block 的规则 ID 不应出现在排行里。
	if strings.Contains(stdout, "920100") {
		t.Errorf("未标记 would_block 的记录不应进入若拦截排行，实际：\n%s", stdout)
	}
}

// TestReportAttackCountsBlockedAndObserved 覆盖：attack 报表区分拦截与观察两种处置。
func TestReportAttackCountsBlockedAndObserved(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := strings.Join([]string{
		accessLogLine(now.Add(-time.Minute), "block", "942100", "/api/login", "203.0.113.10", false),
		accessLogLine(now.Add(-2*time.Minute), "block", "941100", "/search", "203.0.113.10", false),
		accessLogLine(now.Add(-3*time.Minute), "observe", "942100", "/api/login", "203.0.113.11", false),
		// 放行记录不参与攻击统计。
		accessLogLine(now.Add(-4*time.Minute), "allow", "", "/index.html", "203.0.113.12", false),
	}, "\n") + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "attack", "--dir", dir, "--top", "5")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	for _, want := range []string{"2", "1", "942100", "941100"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("报表输出应包含 %q，实际：\n%s", want, stdout)
		}
	}
}

// TestReportDetectionSinceFilter 覆盖：--since 按记录时间过滤，而不是按日志文件名。
func TestReportDetectionSinceFilter(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := strings.Join([]string{
		accessLogLine(now.Add(-time.Minute), "observe", "942100", "/recent", "203.0.113.10", true),
		accessLogLine(now.Add(-48*time.Hour), "observe", "942100", "/old", "203.0.113.10", true),
	}, "\n") + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "detection", "--dir", dir, "--since", "1h")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "/recent") {
		t.Errorf("窗口内的记录应被统计，实际：\n%s", stdout)
	}
	if strings.Contains(stdout, "/old") {
		t.Errorf("窗口外的记录不应被统计，实际：\n%s", stdout)
	}
}

// TestReportDetectionRejectsBrokenLine 覆盖：日志中存在坏行时必须报错并指出文件与行号。
//
// 之所以不静默跳过坏行：一旦静默跳过，「统计结果偏小」这类问题在生产里极难发现，
// 报表也就失去了「可复现的事实来源」这一价值。
func TestReportDetectionRejectsBrokenLine(t *testing.T) {
	dir := t.TempDir()
	content := accessLogLine(time.Now(), "observe", "942100", "/ok", "203.0.113.10", true) + "\n" +
		"这不是 JSON\n"
	path := writeAccessLog(t, dir, content)

	code, _, stderr := runReportCommand(t, "detection", "--dir", dir)
	if code == exitOK {
		t.Fatalf("存在坏行时不应返回成功")
	}
	if !strings.Contains(stderr, filepath.Base(path)) {
		t.Errorf("错误信息应指出文件名，实际：%s", stderr)
	}
	if !strings.Contains(stderr, "第 2 行") {
		t.Errorf("错误信息应指出行号，实际：%s", stderr)
	}
}

// TestReportDetectionMissingDirectory 覆盖：日志目录为空或不存在时给出明确错误。
func TestReportDetectionMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	if code, _, stderr := runReportCommand(t, "detection", "--dir", dir); code == exitOK {
		t.Errorf("目录中没有日志文件时应失败，实际：%s", stderr)
	}

	missing := filepath.Join(t.TempDir(), "not-exist")
	code, _, stderr := runReportCommand(t, "detection", "--dir", missing)
	if code == exitOK {
		t.Errorf("目录不存在时应失败")
	}
	if !strings.Contains(stderr, "读取访问日志失败") {
		t.Errorf("错误信息应说明读取失败，实际：%s", stderr)
	}
}

// TestReportDetectionJSONOutput 覆盖：--json 输出的字段名与访问日志字段保持一致（便于流水线消费）。
func TestReportDetectionJSONOutput(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeAccessLog(t, dir, accessLogLine(now.Add(-time.Minute), "observe", "942100", "/api/login", "203.0.113.10", true)+"\n")

	code, stdout, stderr := runReportCommand(t, "detection", "--dir", dir, "--json")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	for _, want := range []string{`"would_block"`, `"top_rules"`, `"samples"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("JSON 输出应包含字段 %s，实际：\n%s", want, stdout)
		}
	}
}

// TestTopNStableOrdering 覆盖：排行在计数相同时按键名升序，保证输出可复现。
func TestTopNStableOrdering(t *testing.T) {
	counter := map[string]int{"b": 1, "a": 1, "c": 2}
	pairs := topN(counter, 3)
	if len(pairs) != 3 {
		t.Fatalf("条目数 = %d，期望 3", len(pairs))
	}
	if pairs[0].Key != "c" {
		t.Errorf("首位应为计数最高的 c，实际 %q", pairs[0].Key)
	}
	if pairs[1].Key != "a" || pairs[2].Key != "b" {
		t.Errorf("计数相同时应按键名升序，实际 %q, %q", pairs[1].Key, pairs[2].Key)
	}

	// 截断到前 n 项。
	if truncated := topN(counter, 1); len(truncated) != 1 {
		t.Errorf("topN(1) 应只返回 1 项，实际 %d 项", len(truncated))
	}
}

// TestMaxLineBytesOfFallsBackWhenUnset 覆盖：单行上限非法时回落到 0（表示不限制）。
func TestMaxLineBytesOfFallsBackWhenUnset(t *testing.T) {
	cases := []struct {
		name  string
		limit int64
		want  int
	}{
		{name: "正数限额", limit: 1024, want: 1024},
		{name: "零值回落", limit: 0, want: 0},
		{name: "负数回落", limit: -1, want: 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// 直接使用内置默认值，避免让用例依赖机器上是否存在 /etc/waf/waf.yaml。
			resolved, err := config.Load(config.Options{SkipDefaultConfigPath: true})
			if err != nil {
				t.Fatalf("构造配置失败：%v", err)
			}
			cfg := resolved.Config
			cfg.Limits.MaxScanTokenBytes = testCase.limit
			if got := maxLineBytesOf(cfg); got != testCase.want {
				t.Fatalf("maxLineBytesOf = %d，期望 %d", got, testCase.want)
			}
		})
	}
}
