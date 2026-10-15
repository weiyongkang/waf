package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// csvBOM 是 UTF-8 字节顺序标记。
//
// 为什么必须写 BOM：Excel 打开不带 BOM 的 UTF-8 CSV 时会按系统本地编码
// （简体中文环境为 GBK）解码，中文列名与站点名会变成乱码。
// 这一个字节是「导出文件能被 Excel 直接打开」的最低成本方案。
var csvBOM = []byte{0xEF, 0xBB, 0xBF}

// writeCSV 把文档写为 CSV。
//
// 多工作表处理：CSV 本身没有工作表概念，因此按顺序拼接，
// 表与表之间空一行分隔，并在每张表前写入 `# 标题 / 附注` 注释行。
// 需要严格「一表一文件」时请分别导出（report 子命令支持多次调用）。
func writeCSV(w io.Writer, document Document, options Options) error {
	if _, err := w.Write(csvBOM); err != nil {
		return fmt.Errorf("写入 CSV 字节顺序标记失败：%w", err)
	}

	writer := csv.NewWriter(w)
	for index, sheet := range document.Sheets {
		if index > 0 {
			// 空行分隔多张表。
			if err := writer.Write(nil); err != nil {
				return fmt.Errorf("写入 CSV 分隔行失败：%w", err)
			}
		}
		if err := writeCSVSheet(writer, sheet, options); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("写入 CSV 失败：%w", err)
	}
	return nil
}

// writeCSVSheet 写出一张表的注释、表头与数据行。
func writeCSVSheet(writer *csv.Writer, sheet Sheet, options Options) error {
	headers, rows, truncated := normalizeSheet(sheet, options)

	if title := strings.TrimSpace(sheet.Title); title != "" {
		if err := writer.Write([]string{"# " + title}); err != nil {
			return fmt.Errorf("写入 CSV 标题失败：%w", err)
		}
	}
	for _, note := range sheet.Notes {
		if err := writer.Write([]string{"# " + note}); err != nil {
			return fmt.Errorf("写入 CSV 附注失败：%w", err)
		}
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入 CSV 表头失败：%w", err)
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入 CSV 数据行失败：%w", err)
		}
	}
	if truncated {
		// 明确告知被截断，避免使用者误以为「就只有这么多数据」。
		note := make([]string, len(headers))
		if len(note) > 0 {
			note[0] = fmt.Sprintf("# 已达到导出上限（%d 行），后续数据被截断；请缩小时间范围或使用 --top 限制条数", options.MaxRows)
		}
		if err := writer.Write(note); err != nil {
			return fmt.Errorf("写入 CSV 截断说明失败：%w", err)
		}
	}
	return nil
}
