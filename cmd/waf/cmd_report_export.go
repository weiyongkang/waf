package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/observe/report"
)

// 本文件是 report 子命令的「导出后端」（需求 P1-9）。
//
// 职责边界：
//
//	cmd_report.go        负责读取访问日志、聚合统计、生成人读表格；
//	cmd_report_export.go 负责把统计结果转换为可导出的二维表并写文件。
//
// 这样划分的好处是「新增一种导出格式」不会触碰任何统计口径代码，
// 而统计口径的修改也不会影响导出实现（internal/observe/report 只认二维表）。

// reportFormatTable 是 --format 的默认取值：输出人读表格（不导出文件）。
const reportFormatTable = "table"

// tryExportReport 依据 --format / --out 决定是否走导出路径。
//
// 返回值语义：
//   - handled = false：调用方应继续自己的「人读表格」输出；
//   - handled = true：导出已完成（或已报错），调用方直接返回 code。
//
// 格式推断规则（对运维最省事、同时保持可预测）：
//   - 显式 --format csv|xlsx 优先；
//   - 只给 --out 时按扩展名推断（.csv / .xlsx）；
//   - 两者都没给，或 --format=table 时不导出。
func tryExportReport(loader *reportFlagSet, cfg *config.Config, stdout, stderr io.Writer, document report.Document) (bool, int) {
	formatValue := strings.ToLower(loader.stringFlag("format"))
	outPath := loader.stringFlag("out")

	var format report.Format
	switch formatValue {
	case "", reportFormatTable:
		if outPath == "" {
			return false, exitOK
		}
		guessed, ok := report.FormatFromPath(outPath)
		if !ok {
			fmt.Fprintf(stderr, "无法从 --out 的扩展名推断导出格式，请显式指定 --format csv 或 --format xlsx\n")
			return true, exitConfigError
		}
		format = guessed
	default:
		parsed, err := report.ParseFormat(formatValue)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return true, exitConfigError
		}
		format = parsed
	}

	options := reportOptions(cfg)
	if outPath == "" {
		if err := report.Write(stdout, format, document, options); err != nil {
			fmt.Fprintf(stderr, "导出报表失败：%v\n", err)
			return true, exitRuntimeError
		}
		return true, exitOK
	}

	if err := report.WriteFile(outPath, format, document, options); err != nil {
		fmt.Fprintf(stderr, "导出报表失败：%v\n", err)
		return true, exitRuntimeError
	}
	fmt.Fprintf(stdout, "已导出报表：%s（格式 %s，工作表 %d 张）\n", outPath, format, len(document.Sheets))
	return true, exitOK
}

// reportOptions 依据配置构造导出限额。
//
// 限额复用已有的配置项而不是新增开关（需求 R13 的推论）：
//   - 单元格长度沿用 limits.max_scan_token_bytes：单元格内容就是一条被截断的 token；
//   - 行数沿用 report 子命令的 --top：报表本身就是「Top N」语义，
//     导出更多行既没有统计意义，也会让 Excel 打不开。
func reportOptions(cfg *config.Config) report.Options {
	return report.Options{
		MaxCellBytes: maxLineBytesOf(cfg),
	}
}

// summarySheet 构造「汇总」表：一张表里给出本次报表的关键指标。
func summarySheet(title string, notes []string, metrics []counterPair) report.Sheet {
	rows := make([][]string, 0, len(metrics))
	for _, metric := range metrics {
		rows = append(rows, []string{metric.Key, strconv.Itoa(metric.Count)})
	}
	return report.Sheet{
		Name:           title,
		Title:          title,
		Notes:          notes,
		Headers:        []string{"指标", "数值"},
		Rows:           rows,
		NumericColumns: []int{1},
	}
}

// counterSheet 构造排行表：排名 + 维度值 + 次数。
//
// 复用同一构造函数可以让三种报表（detection / attack / ban）的导出结构完全一致，
// 汇聚到数据仓库后可以用同一条 SQL 处理。
func counterSheet(title string, keyHeader string, pairs []counterPair) report.Sheet {
	rows := make([][]string, 0, len(pairs))
	for index, pair := range pairs {
		rows = append(rows, []string{strconv.Itoa(index + 1), pair.Key, strconv.Itoa(pair.Count)})
	}
	return report.Sheet{
		Name:           title,
		Title:          title,
		Headers:        []string{"排名", keyHeader, "次数"},
		Rows:           rows,
		NumericColumns: []int{0, 2},
	}
}

// reportNotes 构造报表附注（生成时间、数据来源、时间范围）。
func reportNotes(dir, since, generatedAt string) []string {
	return []string{
		"日志目录：" + dir,
		"时间范围：" + since,
		"生成时间：" + generatedAt,
		"说明：数据来源为 WAF 访问日志（JSON Lines），报表可离线复现",
	}
}

// detectionDocument 把 DetectionOnly 报表转换为导出文档。
func detectionDocument(payload detectionReportPayload) report.Document {
	samples := make([][]string, 0, len(payload.Samples))
	for _, sample := range payload.Samples {
		samples = append(samples, []string{
			sample.Time.Format(time.RFC3339),
			displayOrDash(sample.Method),
			displayOrDash(sample.Path),
			displayOrDash(sample.RuleID),
			sample.RequestID,
			displayOrDash(sample.ClientIP),
			displayOrDash(sample.Site),
		})
	}

	return report.Document{Sheets: []report.Sheet{
		summarySheet("汇总", reportNotes(payload.LogDir, payload.Since, payload.GeneratedAt), []counterPair{
			{Key: "窗口内访问记录", Count: payload.TotalRecords},
			{Key: "本应拦截", Count: payload.WouldBlock},
		}),
		counterSheet("Top 规则", "规则 ID", payload.TopRules),
		counterSheet("Top 路径", "路径", payload.TopPaths),
		counterSheet("Top 来源 IP", "客户端 IP", payload.TopClients),
		{
			Name:    "样例",
			Title:   "本应拦截样例（供人工复核）",
			Headers: []string{"时间", "方法", "路径", "规则", "request_id", "客户端 IP", "站点"},
			Rows:    samples,
		},
	}}
}

// attackDocument 把攻击态势报表转换为导出文档。
func attackDocument(payload attackReportPayload) report.Document {
	return report.Document{Sheets: []report.Sheet{
		summarySheet("汇总", reportNotes(payload.LogDir, payload.Since, payload.GeneratedAt), []counterPair{
			{Key: "窗口内访问记录", Count: payload.TotalRecords},
			{Key: "拦截", Count: payload.Blocked},
			{Key: "观察命中", Count: payload.Observed},
		}),
		counterSheet("Top 命中规则", "规则 ID", payload.TopRules),
		counterSheet("Top 攻击源 IP", "客户端 IP", payload.TopClients),
		counterSheet("Top 被攻击路径", "路径", payload.TopPaths),
		counterSheet("Top 校验单元", "校验单元", payload.TopChecks),
	}}
}

// banDocument 把封禁运维报表转换为导出文档。
func banDocument(payload banReportPayload) report.Document {
	timelineRows := make([][]string, 0, len(payload.Timeline))
	for _, bucket := range payload.Timeline {
		timelineRows = append(timelineRows, []string{bucket.Key, strconv.Itoa(bucket.Count)})
	}

	return report.Document{Sheets: []report.Sheet{
		summarySheet("汇总", reportNotes(payload.LogDir, payload.Since, payload.GeneratedAt), []counterPair{
			{Key: "窗口内访问记录", Count: payload.TotalRecords},
			{Key: "封禁命中", Count: payload.BanHits},
		}),
		counterSheet("Top 封禁来源 IP", "客户端 IP", payload.TopClients),
		{
			Name:           "时间线",
			Title:          "封禁命中时间线（按小时聚合）",
			Headers:        []string{"时间（小时）", "命中次数"},
			Rows:           timelineRows,
			NumericColumns: []int{1},
		},
		counterSheet("Top 站点", "站点", payload.TopSites),
		counterSheet("Top 规则", "规则 ID", payload.TopRules),
	}}
}
