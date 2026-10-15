package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accessLogLineWithCheck 生成一行访问日志，允许指定校验单元名（check）。
//
// 之所以单独一个构造函数而不是改动 accessLogLine 的签名：
// ban 报表的判定依据就是 check 字段，需要精确控制它；
// 而其余报表测试的 check 取值与断言无关，保持原签名可以让它们不被牵连。
func accessLogLineWithCheck(when time.Time, verdict, check, ruleID, path, clientIP, site string) string {
	return fmt.Sprintf(
		`{"time":%q,"level":"info","msg":"请求拦截","request_id":"req-1","verdict":%q,`+
			`"check":%q,"site":%q,"method":"GET","path":%q,"host":"app.example.com",`+
			`"client_ip":%q,"rule_id":%q,"score":5,"status":403,"duration_ms":3}`,
		when.Format(time.RFC3339), verdict, check, site, path, clientIP, ruleID,
	)
}

// TestReportBanAggregatesBanHits 覆盖：只统计封禁相关校验单元的记录，并按小时给出时间线。
func TestReportBanAggregatesBanHits(t *testing.T) {
	now := time.Now().Truncate(time.Hour).Add(30 * time.Minute)
	dir := t.TempDir()
	content := strings.Join([]string{
		// 封禁名单命中：应当计入。
		accessLogLineWithCheck(now.Add(-time.Minute), "block", "banlist", "", "/api/orders", "203.0.113.10", "shop"),
		accessLogLineWithCheck(now.Add(-2*time.Minute), "block", "banlist", "", "/api/orders", "203.0.113.10", "shop"),
		// 自动封禁命中：check 名同样包含 ban，应当计入。
		accessLogLineWithCheck(now.Add(-90*time.Minute), "block", "autoban", "900100", "/api/pay", "203.0.113.11", "shop"),
		// 非封禁校验单元：不应计入。
		accessLogLineWithCheck(now.Add(-3*time.Minute), "block", "crs-header", "942100", "/api/login", "203.0.113.12", "shop"),
		// 放行记录：不应计入。
		accessLogLineWithCheck(now.Add(-4*time.Minute), "allow", "banlist", "", "/index.html", "203.0.113.13", "shop"),
	}, "\n") + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "ban", "--dir", dir, "--top", "5", "--since", "24h")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}

	for _, want := range []string{"封禁运维报表", "封禁命中：3 条", "203.0.113.10", "203.0.113.11", "时间线"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("报表输出应包含 %q，实际：\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "203.0.113.12") {
		t.Errorf("非封禁校验单元的来源 IP 不应出现在封禁报表中：\n%s", stdout)
	}
	if strings.Contains(stdout, "203.0.113.13") {
		t.Errorf("放行记录不应计入封禁报表：\n%s", stdout)
	}
}

// TestReportBanJSONOutput 覆盖：ban 报表的 JSON 输出结构。
func TestReportBanJSONOutput(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := accessLogLineWithCheck(now.Add(-time.Minute), "block", "banlist", "", "/api/orders", "203.0.113.10", "shop") + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "ban", "--dir", dir, "--json")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	for _, want := range []string{`"ban_hits": 1`, `"top_clients"`, `"timeline"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("JSON 输出应包含 %q，实际：\n%s", want, stdout)
		}
	}
}

// TestReportCSVExport 覆盖：--format csv --out 生成可用的 CSV 文件。
func TestReportCSVExport(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := accessLogLine(now.Add(-time.Minute), "block", "942100", "/api/login", "203.0.113.10", false) + "\n"
	writeAccessLog(t, dir, content)

	target := filepath.Join(t.TempDir(), "out", "attack.csv")
	code, stdout, stderr := runReportCommand(t, "attack", "--dir", dir, "--format", "csv", "--out", target)
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "已导出报表") {
		t.Errorf("应在标准输出给出导出提示，实际：\n%s", stdout)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取导出文件失败：%v", err)
	}
	// BOM + 中文表头 + 关键数据。
	if !bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		t.Error("CSV 应以 UTF-8 BOM 开头")
	}
	text := string(data)
	for _, want := range []string{"# 汇总", "# Top 攻击源 IP", "203.0.113.10", "942100"} {
		if !strings.Contains(text, want) {
			t.Errorf("CSV 应包含 %q，实际：\n%s", want, text)
		}
	}
}

// TestReportXLSXExportInfersFormat 覆盖：只给 --out 的 *.xlsx 时按扩展名推断格式。
func TestReportXLSXExportInfersFormat(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := strings.Join([]string{
		accessLogLine(now.Add(-time.Minute), "block", "942100", "/api/login", "203.0.113.10", false),
		accessLogLine(now.Add(-2*time.Minute), "observe", "942100", "/api/login", "203.0.113.11", true),
	}, "\n") + "\n"
	writeAccessLog(t, dir, content)

	target := filepath.Join(t.TempDir(), "detection.xlsx")
	code, _, stderr := runReportCommand(t, "detection", "--dir", dir, "--out", target)
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取导出文件失败：%v", err)
	}
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		t.Fatalf("xlsx 应为 zip 容器（PK 魔数），实际前 4 字节：%v", data[:min(4, len(data))])
	}
	if !bytes.Contains(data, []byte("xl/worksheets/sheet1.xml")) {
		t.Error("xlsx 应包含工作表部件")
	}
}

// TestReportExportToStdout 覆盖：只给 --format 时导出内容写到标准输出。
func TestReportExportToStdout(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	content := accessLogLine(now.Add(-time.Minute), "block", "942100", "/api/login", "203.0.113.10", false) + "\n"
	writeAccessLog(t, dir, content)

	code, stdout, stderr := runReportCommand(t, "attack", "--dir", dir, "--format", "csv")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.HasPrefix(stdout, "\xEF\xBB\xBF") {
		t.Error("导出到标准输出时也应带 UTF-8 BOM")
	}
	if strings.Contains(stdout, "攻击态势报表\n日志目录") {
		t.Error("导出模式下不应再输出人读表格")
	}
}

// TestReportExportRejectsUnknownFormat 覆盖：非法格式与无法推断的扩展名都返回配置错误码。
func TestReportExportRejectsUnknownFormat(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeAccessLog(t, dir, accessLogLine(now, "block", "942100", "/api/login", "203.0.113.10", false)+"\n")

	if code, _, _ := runReportCommand(t, "attack", "--dir", dir, "--format", "pdf"); code != exitConfigError {
		t.Errorf("非法格式时退出码 = %d，期望 %d", code, exitConfigError)
	}
	if code, _, _ := runReportCommand(t, "attack", "--dir", dir, "--out", filepath.Join(t.TempDir(), "a.pdf")); code != exitConfigError {
		t.Errorf("无法推断格式时退出码 = %d，期望 %d", code, exitConfigError)
	}
}

// TestReportTableFormatKeepsHumanOutput 覆盖：--format table（默认）仍输出人读表格。
func TestReportTableFormatKeepsHumanOutput(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	writeAccessLog(t, dir, accessLogLine(now, "block", "942100", "/api/login", "203.0.113.10", false)+"\n")

	code, stdout, stderr := runReportCommand(t, "attack", "--dir", dir, "--format", "table")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "攻击态势报表") || !strings.Contains(stdout, "Top 攻击源 IP") {
		t.Errorf("table 格式应输出人读表格，实际：\n%s", stdout)
	}
}

// min 返回两个整数中的较小值（Go 1.21 起标准库提供 min，这里保留本地实现以便表达意图）。
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
