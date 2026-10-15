package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 本文件生成「最小可用」的 OOXML 工作簿。
//
// 一个能被 Excel 正常打开的 xlsx 包至少需要 5 个部件：
//
//	[Content_Types].xml              声明各扩展名与部件的类型
//	_rels/.rels                      包级关系：指向 xl/workbook.xml
//	xl/workbook.xml                  工作簿：工作表清单
//	xl/_rels/workbook.xml.rels       工作簿关系：指向各工作表部件
//	xl/worksheets/sheetN.xml         工作表本体（行 / 单元格）
//
// 这里刻意不生成 xl/styles.xml 与 docProps/*：它们只影响观感与元数据，
// 不是「能被 Excel 打开」的必要条件，而每多一个部件就多一份出错的可能。
// 未来若要加粗表头或设置列宽，再引入 styles.xml 即可（属于纯增量改动）。

// xmlDeclaration 是所有 XML 部件的公共声明。
const xmlDeclaration = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

// 各部件的根命名空间。
const (
	// nsSpreadsheet 是工作表主命名空间。
	nsSpreadsheet = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
	// nsRelationships 是关系部件命名空间。
	nsRelationships = "http://schemas.openxmlformats.org/package/2006/relationships"
	// nsContentTypes 是内容类型命名空间。
	nsContentTypes = "http://schemas.openxmlformats.org/package/2006/content-types"
	// nsOfficeRelationships 是 officeDocument 关系类型前缀。
	nsOfficeRelationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)

// maxSheetNameRunes 是 Excel 允许的工作表名长度上限（字符数）。
const maxSheetNameRunes = 31

// writeXLSX 把文档写为 OOXML 工作簿。
func writeXLSX(w io.Writer, document Document, options Options) error {
	archive := zip.NewWriter(w)

	names := buildSheetNames(document)

	if err := addXLSXPart(archive, "[Content_Types].xml", contentTypesXML(len(names))); err != nil {
		return err
	}
	if err := addXLSXPart(archive, "_rels/.rels", rootRelationshipsXML()); err != nil {
		return err
	}
	if err := addXLSXPart(archive, "xl/workbook.xml", workbookXML(names)); err != nil {
		return err
	}
	if err := addXLSXPart(archive, "xl/_rels/workbook.xml.rels", workbookRelationshipsXML(len(names))); err != nil {
		return err
	}
	for index, sheet := range document.Sheets {
		content := worksheetXML(sheet, options)
		part := fmt.Sprintf("xl/worksheets/sheet%d.xml", index+1)
		if err := addXLSXPart(archive, part, content); err != nil {
			return err
		}
	}

	if err := archive.Close(); err != nil {
		return fmt.Errorf("生成 xlsx 归档失败：%w", err)
	}
	return nil
}

// addXLSXPart 向归档中写入一个文本部件。
func addXLSXPart(archive *zip.Writer, name string, content string) error {
	writer, err := archive.Create(name)
	if err != nil {
		return fmt.Errorf("创建 xlsx 部件 %s 失败：%w", name, err)
	}
	if _, err := io.WriteString(writer, content); err != nil {
		return fmt.Errorf("写入 xlsx 部件 %s 失败：%w", name, err)
	}
	return nil
}

// contentTypesXML 生成 [Content_Types].xml。
func contentTypesXML(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(xmlDeclaration)
	builder.WriteString(`<Types xmlns="` + nsContentTypes + `">`)
	builder.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	builder.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	builder.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	for index := 0; index < sheetCount; index++ {
		builder.WriteString(`<Override PartName="/xl/worksheets/sheet`)
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(`.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`)
	}
	builder.WriteString(`</Types>`)
	return builder.String()
}

// rootRelationshipsXML 生成 _rels/.rels。
func rootRelationshipsXML() string {
	var builder strings.Builder
	builder.WriteString(xmlDeclaration)
	builder.WriteString(`<Relationships xmlns="` + nsRelationships + `">`)
	builder.WriteString(`<Relationship Id="rId1" Type="` + nsOfficeRelationships + `/officeDocument" Target="xl/workbook.xml"/>`)
	builder.WriteString(`</Relationships>`)
	return builder.String()
}

// workbookXML 生成 xl/workbook.xml。
func workbookXML(names []string) string {
	var builder strings.Builder
	builder.WriteString(xmlDeclaration)
	builder.WriteString(`<workbook xmlns="` + nsSpreadsheet + `" xmlns:r="` + nsOfficeRelationships + `">`)
	builder.WriteString(`<sheets>`)
	for index, name := range names {
		builder.WriteString(`<sheet name="`)
		builder.WriteString(escapeXMLText(name))
		builder.WriteString(`" sheetId="`)
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(`" r:id="rId`)
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(`"/>`)
	}
	builder.WriteString(`</sheets>`)
	builder.WriteString(`</workbook>`)
	return builder.String()
}

// workbookRelationshipsXML 生成 xl/_rels/workbook.xml.rels。
func workbookRelationshipsXML(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(xmlDeclaration)
	builder.WriteString(`<Relationships xmlns="` + nsRelationships + `">`)
	for index := 0; index < sheetCount; index++ {
		builder.WriteString(`<Relationship Id="rId`)
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(`" Type="` + nsOfficeRelationships + `/worksheet" Target="worksheets/sheet`)
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString(`.xml"/>`)
	}
	builder.WriteString(`</Relationships>`)
	return builder.String()
}

// worksheetXML 生成单张工作表的内容。
//
// 单元格一律使用 inlineStr（内联字符串）而不是共享字符串表（sharedStrings.xml）：
// 共享字符串表的价值在于「大量重复文本压缩存储」，而我们的报表以计数与 IP 为主，
// 重复率低，为此多维护一个部件与一套索引映射不划算。
func worksheetXML(sheet Sheet, options Options) string {
	headers, rows, truncated := normalizeSheet(sheet, options)
	numeric := numericColumnSet(sheet.NumericColumns)

	var builder strings.Builder
	builder.WriteString(xmlDeclaration)
	builder.WriteString(`<worksheet xmlns="` + nsSpreadsheet + `">`)
	builder.WriteString(`<sheetData>`)

	rowIndex := 0
	writeRow := func(cells []string, forceText bool) {
		rowIndex++
		builder.WriteString(`<row r="`)
		builder.WriteString(strconv.Itoa(rowIndex))
		builder.WriteString(`">`)
		for column, value := range cells {
			writeCell(&builder, column, rowIndex, value, !forceText && isNumericColumn(numeric, column))
		}
		builder.WriteString(`</row>`)
	}

	if title := strings.TrimSpace(sheet.Title); title != "" {
		writeRow([]string{title}, true)
	}
	for _, note := range sheet.Notes {
		writeRow([]string{note}, true)
	}
	if len(headers) > 0 {
		writeRow(headers, true)
	}
	for _, row := range rows {
		writeRow(row, false)
	}
	if truncated {
		writeRow([]string{fmt.Sprintf("已达到导出上限（%d 行），后续数据被截断；请缩小时间范围或使用 --top 限制条数", options.MaxRows)}, true)
	}

	builder.WriteString(`</sheetData>`)
	builder.WriteString(`</worksheet>`)
	return builder.String()
}

// writeCell 写出一个单元格。
func writeCell(builder *strings.Builder, column, row int, value string, numericColumn bool) {
	reference := columnName(column) + strconv.Itoa(row)
	builder.WriteString(`<c r="`)
	builder.WriteString(reference)
	builder.WriteString(`"`)

	if numericColumn && isPlainNumber(value) {
		builder.WriteString(`><v>`)
		builder.WriteString(strings.TrimSpace(value))
		builder.WriteString(`</v></c>`)
		return
	}

	builder.WriteString(` t="inlineStr"><is><t xml:space="preserve">`)
	builder.WriteString(escapeXMLText(value))
	builder.WriteString(`</t></is></c>`)
}

// isNumericColumn 判断列是否被声明为数字列。
func isNumericColumn(columns map[int]struct{}, column int) bool {
	if len(columns) == 0 {
		return false
	}
	_, exists := columns[column]
	return exists
}

// isPlainNumber 判断字符串是否是「可以安全写入 <v> 的数字字面量」。
//
// 之所以先做字符白名单再交给 ParseFloat：
// strconv.ParseFloat 会接受 "Inf" / "NaN" 这类写法，
// 而它们并不是合法的 XML Schema 数值（应为 "INF"），写进工作簿会让 Excel 报错或显示异常。
func isPlainNumber(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	for _, char := range trimmed {
		switch {
		case char >= '0' && char <= '9', char == '-', char == '+', char == '.', char == 'e', char == 'E':
		default:
			return false
		}
	}
	_, err := strconv.ParseFloat(trimmed, 64)
	return err == nil
}

// escapeXMLText 转义 XML 文本内容。
//
// 使用标准库 xml.EscapeText 而不是手写替换：它同时处理了
// 「非法 XML 字符（如控制字符、非法 UTF-8）」替换为 U+FFFD 的规则，
// 手写实现极易漏掉这一层，导致生成的工作簿被 Excel 判定为损坏。
func escapeXMLText(value string) string {
	var buffer bytes.Buffer
	if err := xml.EscapeText(&buffer, []byte(value)); err != nil {
		// bytes.Buffer 的写入不会失败；此处仅做防御。
		return ""
	}
	return buffer.String()
}

// columnName 把 0 起始的列下标转换为 Excel 列名（A、B……Z、AA、AB……）。
func columnName(index int) string {
	name := make([]byte, 0, 4)
	for index >= 0 {
		name = append([]byte{byte('A' + index%26)}, name...)
		index = index/26 - 1
	}
	return string(name)
}

// buildSheetNames 规范化全部工作表名，保证唯一且符合 Excel 限制。
func buildSheetNames(document Document) []string {
	used := make(map[string]struct{}, len(document.Sheets))
	names := make([]string, 0, len(document.Sheets))
	for index, sheet := range document.Sheets {
		names = append(names, uniqueSheetName(sheet.Name, index, used))
	}
	return names
}

// uniqueSheetName 生成合法且唯一的工作表名。
//
// Excel 的约束（任一不满足都会导致打开时报错或静默改名字）：
//   - 长度不超过 31 个字符；
//   - 不能包含 : \ / ? * [ ]；
//   - 同一工作簿内不能重名；
//   - 不能为空。
func uniqueSheetName(name string, index int, used map[string]struct{}) string {
	cleaned := strings.Map(func(char rune) rune {
		switch char {
		case ':', '\\', '/', '?', '*', '[', ']':
			return '_'
		}
		if char < 0x20 {
			return -1
		}
		return char
	}, name)
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		cleaned = "Sheet" + strconv.Itoa(index+1)
	}
	cleaned = truncateRunes(cleaned, maxSheetNameRunes)

	candidate := cleaned
	for suffix := 2; ; suffix++ {
		if _, exists := used[candidate]; !exists {
			break
		}
		suffixText := "_" + strconv.Itoa(suffix)
		base := truncateRunes(cleaned, maxSheetNameRunes-utf8.RuneCountInString(suffixText))
		candidate = base + suffixText
	}
	used[candidate] = struct{}{}
	return candidate
}

// truncateRunes 按字符数截断字符串。
func truncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index]
		}
		count++
	}
	return value
}
