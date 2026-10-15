// Package report 提供审计报表的导出能力（需求 P1-9）。
//
// 设计取向：**零第三方依赖**。
// 导出格式只有两种，且都只需要标准库：
//
//	csv   encoding/csv —— 通用、可被 Excel / 数据库 / 脚本直接消费；
//	xlsx  archive/zip + 手写 OOXML —— 真正的 Excel 工作簿，可被 Excel 直接打开。
//
// 为什么不用 Excel 的 SpreadsheetML 2003（单文件 XML）：
// 该格式在新版 Excel 中会触发「格式与扩展名不匹配」的警告，
// 而 xlsx 是 OOXML 标准包（一个 zip + 若干 XML），标准库 archive/zip 已经足够生成，
// 因此没有必要让运维在「能打开但有警告」和「需要装库」之间做取舍。
//
// 关于「报表从哪来」：本包只负责**把已经算好的二维数据写成文件**，
// 不做任何日志解析与聚合。原因见 docs/development-roadmap.md §10.11：
// 聚合逻辑属于 cmd/waf 的 report 子命令，导出只是它的一个输出后端，
// 两者分开可以让「新增一种导出格式」完全不影响统计口径。
package report

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Format 是导出格式。
type Format string

const (
	// FormatCSV 是逗号分隔文本（UTF-8，带 BOM 以便 Excel 正确识别中文）。
	FormatCSV Format = "csv"
	// FormatXLSX 是 OOXML 工作簿。
	FormatXLSX Format = "xlsx"
)

// Options 是导出选项。
//
// 两个上限都来自配置文件（需求 R13：缓存与体积上限必须可配置，
// 禁止在实现里硬编码），0 表示不限制。
type Options struct {
	// MaxRows 是单张表最大导出行数；超出部分被截断并在表中追加说明行。
	//
	// 为什么需要：一次导出几百万行会让文件不可用（Excel 也打不开），
	// 运维真正需要的是「先看 Top 汇总，再按需缩小时间范围」。
	MaxRows int
	// MaxCellBytes 是单个单元格的最大字节数；超出部分被截断。
	//
	// 为什么需要：单元格内容来自访问日志（路径、User-Agent 等外部输入），
	// 不限制会让一条异常长的记录把整份导出变得不可用。
	MaxCellBytes int
}

// Document 是待导出的文档，可包含一张或多张表。
type Document struct {
	// Sheets 是全部工作表，按顺序导出。
	Sheets []Sheet
}

// Sheet 是一张二维表。
type Sheet struct {
	// Name 是工作表名。Excel 对工作表名有限制（长度、非法字符、重名），
	// 写入时会被规范化；为空时自动命名为 Sheet1、Sheet2……
	Name string
	// Title 是表标题，作为第一行写入（便于人工阅读与打印）。
	Title string
	// Notes 是附注行（生成时间、日志目录、时间范围等），写在标题之后、表头之前。
	Notes []string
	// Headers 是列名。
	Headers []string
	// Rows 是数据行。列数少于 Headers 时补空串，多于时被忽略。
	Rows [][]string
	// NumericColumns 是需要按数字写入的列下标（从 0 开始）。
	//
	// 为什么显式声明而不是自动嗅探：规则 ID、客户端 IP 这类「看起来像数字」的
	// 列被自动转成数字后，在 Excel 里会丢失前导零、被科学计数法改写，
	// 反而破坏可读性。显式声明让语义由报表作者决定。
	NumericColumns []int
}

// ParseFormat 解析导出格式字符串。
func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(FormatCSV), "text":
		return FormatCSV, nil
	case string(FormatXLSX), "excel", "xls":
		return FormatXLSX, nil
	default:
		return "", fmt.Errorf("未知的导出格式 %q，可选：csv / xlsx", value)
	}
}

// FormatFromPath 依据文件扩展名推断导出格式。
func FormatFromPath(path string) (Format, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		return FormatCSV, true
	case ".xlsx":
		return FormatXLSX, true
	default:
		return "", false
	}
}

// Write 把文档写入 w。
func Write(w io.Writer, format Format, document Document, options Options) error {
	if w == nil {
		return errors.New("report: 输出目标不能为空")
	}
	if len(document.Sheets) == 0 {
		return errors.New("report: 文档中没有任何工作表")
	}
	switch format {
	case FormatCSV:
		return writeCSV(w, document, options)
	case FormatXLSX:
		return writeXLSX(w, document, options)
	default:
		return fmt.Errorf("report: 不支持的导出格式 %q", format)
	}
}

// WriteFile 把文档写入文件；父目录不存在时自动创建。
func WriteFile(path string, format Format, document Document, options Options) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("report: 导出路径不能为空")
	}
	if dir := filepath.Dir(trimmed); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建导出目录 %s 失败：%w", dir, err)
		}
	}

	file, err := os.Create(trimmed)
	if err != nil {
		return fmt.Errorf("创建导出文件 %s 失败：%w", trimmed, err)
	}
	if err := Write(file, format, document, options); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭导出文件 %s 失败：%w", trimmed, err)
	}
	return nil
}

// normalizeSheet 把工作表规范化为「列数固定、单元格已截断」的形态。
//
// 返回值中的 truncated 表示是否因为行数上限被截断。
func normalizeSheet(sheet Sheet, options Options) (headers []string, rows [][]string, truncated bool) {
	headers = make([]string, len(sheet.Headers))
	for i, header := range sheet.Headers {
		headers[i] = clampCell(header, options.MaxCellBytes)
	}

	rows = make([][]string, 0, len(sheet.Rows))
	for index, row := range sheet.Rows {
		if options.MaxRows > 0 && index >= options.MaxRows {
			truncated = true
			break
		}
		normalized := make([]string, len(headers))
		for column := range headers {
			if column < len(row) {
				normalized[column] = clampCell(row[column], options.MaxCellBytes)
			}
		}
		rows = append(rows, normalized)
	}
	return headers, rows, truncated
}

// clampCell 按字节上限截断单元格内容。
func clampCell(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	truncated := value[:limit]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated + "…(已截断)"
}

// numericColumnSet 把列下标列表转换为集合，便于写入时快速判断。
func numericColumnSet(columns []int) map[int]struct{} {
	if len(columns) == 0 {
		return nil
	}
	set := make(map[int]struct{}, len(columns))
	for _, column := range columns {
		set[column] = struct{}{}
	}
	return set
}
