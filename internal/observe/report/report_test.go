package report

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleDocument 构造一份包含一张汇总表与一张明细表的测试文档。
func sampleDocument() Document {
	return Document{Sheets: []Sheet{
		{
			Name:    "Top 攻击源",
			Title:   "攻击态势报表",
			Notes:   []string{"日志目录：/var/log/waf", "时间范围：最近 24h"},
			Headers: []string{"排名", "客户端 IP", "次数"},
			Rows: [][]string{
				{"1", "203.0.113.10", "128"},
				{"2", "203.0.113.11", "64"},
			},
			NumericColumns: []int{0, 2},
		},
		{
			Name:    "明细",
			Headers: []string{"request_id", "路径"},
			Rows:    [][]string{{"req-1", "/api/login"}},
		},
	}}
}

// TestParseFormat 验证格式解析与别名。
func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"csv":   FormatCSV,
		"CSV":   FormatCSV,
		" text": FormatCSV,
		"xlsx":  FormatXLSX,
		"Excel": FormatXLSX,
		"xls":   FormatXLSX,
	}
	for input, expected := range cases {
		got, err := ParseFormat(input)
		if err != nil {
			t.Fatalf("解析 %q 失败：%v", input, err)
		}
		if got != expected {
			t.Fatalf("解析 %q 期望 %q，实际 %q", input, expected, got)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Fatal("未知格式应当返回错误")
	}
}

// TestFormatFromPath 验证按扩展名推断格式。
func TestFormatFromPath(t *testing.T) {
	if format, ok := FormatFromPath("out/attack.CSV"); !ok || format != FormatCSV {
		t.Fatalf("应识别为 csv：%v %v", format, ok)
	}
	if format, ok := FormatFromPath("out/attack.xlsx"); !ok || format != FormatXLSX {
		t.Fatalf("应识别为 xlsx：%v %v", format, ok)
	}
	if _, ok := FormatFromPath("out/attack.json"); ok {
		t.Fatal("未知扩展名不应被识别")
	}
}

// TestWriteCSV 验证 CSV 输出包含 BOM、注释行、表头与数据行。
func TestWriteCSV(t *testing.T) {
	var buffer bytes.Buffer
	if err := Write(&buffer, FormatCSV, sampleDocument(), Options{}); err != nil {
		t.Fatalf("导出失败：%v", err)
	}

	data := buffer.Bytes()
	if !bytes.HasPrefix(data, csvBOM) {
		t.Fatal("CSV 应以 UTF-8 BOM 开头（否则 Excel 打开中文会乱码）")
	}

	reader := csv.NewReader(bytes.NewReader(data[len(csvBOM):]))
	// 注释行只有一列，因此必须关闭「每行列数一致」的校验。
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失败：%v", err)
	}

	flat := make([]string, 0, len(records))
	for _, record := range records {
		flat = append(flat, strings.Join(record, "|"))
	}
	joined := strings.Join(flat, "\n")

	for _, expected := range []string{
		"# 攻击态势报表",
		"# 日志目录：/var/log/waf",
		"排名|客户端 IP|次数",
		"1|203.0.113.10|128",
		"request_id|路径",
		"req-1|/api/login",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("CSV 缺少 %q：\n%s", expected, joined)
		}
	}
}

// TestWriteCSVTruncatesAtMaxRows 验证行数上限生效并给出明确说明。
func TestWriteCSVTruncatesAtMaxRows(t *testing.T) {
	document := Document{Sheets: []Sheet{{
		Title:   "截断测试",
		Headers: []string{"序号"},
		Rows:    [][]string{{"1"}, {"2"}, {"3"}, {"4"}},
	}}}

	var buffer bytes.Buffer
	if err := Write(&buffer, FormatCSV, document, Options{MaxRows: 2}); err != nil {
		t.Fatalf("导出失败：%v", err)
	}

	content := buffer.String()
	if strings.Contains(content, "\n3\n") {
		t.Fatalf("超出上限的数据行不应出现：\n%s", content)
	}
	if !strings.Contains(content, "已达到导出上限") {
		t.Fatalf("应给出截断说明：\n%s", content)
	}
}

// TestWriteCSVClampsCellBytes 验证单元格长度上限与 UTF-8 边界保护。
func TestWriteCSVClampsCellBytes(t *testing.T) {
	document := Document{Sheets: []Sheet{{
		Headers: []string{"路径"},
		Rows:    [][]string{{strings.Repeat("路径", 50)}},
	}}}

	var buffer bytes.Buffer
	if err := Write(&buffer, FormatCSV, document, Options{MaxCellBytes: 10}); err != nil {
		t.Fatalf("导出失败：%v", err)
	}
	if !strings.Contains(buffer.String(), "已截断") {
		t.Fatalf("应标注截断：%s", buffer.String())
	}
	if bytes.ContainsRune(buffer.Bytes(), 0xFFFD) {
		t.Fatal("截断不应产生非法的 UTF-8 字符")
	}
}

// TestWriteXLSXStructure 验证生成的工作簿包含必要部件，且内容正确转义。
func TestWriteXLSXStructure(t *testing.T) {
	var buffer bytes.Buffer
	if err := Write(&buffer, FormatXLSX, sampleDocument(), Options{}); err != nil {
		t.Fatalf("导出失败：%v", err)
	}

	parts := readZipParts(t, buffer.Bytes())
	for _, required := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"xl/workbook.xml",
		"xl/_rels/workbook.xml.rels",
		"xl/worksheets/sheet1.xml",
		"xl/worksheets/sheet2.xml",
	} {
		if _, exists := parts[required]; !exists {
			t.Fatalf("工作簿缺少部件 %s（实际部件：%v）", required, keysOf(parts))
		}
	}

	workbook := parts["xl/workbook.xml"]
	if !strings.Contains(workbook, `name="Top 攻击源"`) {
		t.Fatalf("工作簿未包含工作表名：%s", workbook)
	}

	sheet := parts["xl/worksheets/sheet1.xml"]
	if !strings.Contains(sheet, `<c r="B5" t="inlineStr">`) {
		t.Fatalf("明细单元格应为内联字符串：%s", sheet)
	}
	if !strings.Contains(sheet, `<v>128</v>`) {
		t.Fatalf("声明为数字的列应写成数值单元格：%s", sheet)
	}
	if !strings.Contains(sheet, "攻击态势报表") || !strings.Contains(sheet, "203.0.113.10") {
		t.Fatalf("工作表缺少内容：%s", sheet)
	}
}

// TestWriteXLSXEscapesSpecialCharacters 验证特殊字符被正确转义。
func TestWriteXLSXEscapesSpecialCharacters(t *testing.T) {
	document := Document{Sheets: []Sheet{{
		Headers: []string{"路径"},
		Rows: [][]string{
			{"/search?q=<script>&x='y'"},
			{"控制字符：\x00\x01"},
		},
	}}}

	var buffer bytes.Buffer
	if err := Write(&buffer, FormatXLSX, document, Options{}); err != nil {
		t.Fatalf("导出失败：%v", err)
	}
	sheet := readZipParts(t, buffer.Bytes())["xl/worksheets/sheet1.xml"]

	if strings.Contains(sheet, "<script>") {
		t.Fatalf("未转义的标记会破坏 XML：%s", sheet)
	}
	if !strings.Contains(sheet, "&lt;script&gt;") || !strings.Contains(sheet, "&amp;") {
		t.Fatalf("尖括号与 & 应被转义：%s", sheet)
	}
	if strings.ContainsRune(sheet, 0x00) || strings.ContainsRune(sheet, 0x01) {
		t.Fatalf("非法 XML 字符应被替换：%s", sheet)
	}
}

// TestUniqueSheetName 验证工作表名合法化（非法字符、超长、重名）。
func TestUniqueSheetName(t *testing.T) {
	used := map[string]struct{}{}

	if got := uniqueSheetName("a:b/c?d*e[f]g", 0, used); got != "a_b_c_d_e_f_g" {
		t.Fatalf("非法字符应被替换为下划线，实际 %q", got)
	}
	if got := uniqueSheetName("", 1, used); got != "Sheet2" {
		t.Fatalf("空名应回落到 SheetN，实际 %q", got)
	}

	long := strings.Repeat("表", 40)
	if got := uniqueSheetName(long, 2, used); len([]rune(got)) > maxSheetNameRunes {
		t.Fatalf("工作表名不应超过 %d 个字符，实际 %d", maxSheetNameRunes, len([]rune(got)))
	}

	first := uniqueSheetName("重复", 3, used)
	second := uniqueSheetName("重复", 4, used)
	if first == second {
		t.Fatalf("重名应被自动去重：%q / %q", first, second)
	}
}

// TestColumnName 验证列名换算。
func TestColumnName(t *testing.T) {
	cases := map[int]string{0: "A", 1: "B", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"}
	for index, expected := range cases {
		if got := columnName(index); got != expected {
			t.Fatalf("列 %d 期望 %q，实际 %q", index, expected, got)
		}
	}
}

// TestIsPlainNumber 验证数字字面量判定。
func TestIsPlainNumber(t *testing.T) {
	for _, value := range []string{"0", "128", "-5", "+5", "3.14", "1e5"} {
		if !isPlainNumber(value) {
			t.Fatalf("%q 应被判定为数字", value)
		}
	}
	for _, value := range []string{"", " ", "abc", "203.0.113.10", "Inf", "NaN", "1,5", "0x10"} {
		if isPlainNumber(value) {
			t.Fatalf("%q 不应被判定为数字", value)
		}
	}
}

// TestWriteRejectsInvalidInput 验证空文档与未知格式被拒绝。
func TestWriteRejectsInvalidInput(t *testing.T) {
	var buffer bytes.Buffer
	if err := Write(&buffer, Format("pdf"), sampleDocument(), Options{}); err == nil {
		t.Fatal("未知格式应当返回错误")
	}
	if err := Write(&buffer, FormatCSV, Document{}, Options{}); err == nil {
		t.Fatal("空文档应当返回错误")
	}
}

// TestWriteFileCreatesParentDirectory 验证导出文件时自动创建父目录。
func TestWriteFileCreatesParentDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "deep", "report.csv")
	if err := WriteFile(target, FormatCSV, sampleDocument(), Options{}); err != nil {
		t.Fatalf("导出文件失败：%v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("导出文件不存在：%v", err)
	}
	if info.Size() == 0 {
		t.Fatal("导出文件不应为空")
	}

	if err := WriteFile("  ", FormatCSV, sampleDocument(), Options{}); err == nil {
		t.Fatal("空路径应当返回错误")
	}
}

// readZipParts 读取 zip 归档中的全部文本部件。
func readZipParts(t *testing.T, data []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("生成的工作簿不是合法 zip：%v", err)
	}
	parts := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		handle, err := file.Open()
		if err != nil {
			t.Fatalf("打开部件 %s 失败：%v", file.Name, err)
		}
		content, err := io.ReadAll(handle)
		_ = handle.Close()
		if err != nil {
			t.Fatalf("读取部件 %s 失败：%v", file.Name, err)
		}
		parts[file.Name] = string(content)
	}
	return parts
}

// keysOf 返回映射的键列表（用于错误信息）。
func keysOf(parts map[string]string) []string {
	keys := make([]string, 0, len(parts))
	for key := range parts {
		keys = append(keys, key)
	}
	return keys
}
