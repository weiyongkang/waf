package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile 在临时目录写入测试文件并返回路径。
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}
	return path
}

// TestScanLinesSkipsCommentsAndBlanks 覆盖：注释与空行被跳过，条目去首尾空白。
func TestScanLinesSkipsCommentsAndBlanks(t *testing.T) {
	path := writeFile(t, "list.txt", "# 注释行\n\n1.2.3.4\n   10.0.0.0/8   \n#尾部注释\n")

	var lines []string
	_, err := ScanLines(path, 0, 0, func(line string, _ int) error {
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatalf("扫描失败：%v", err)
	}

	want := []string{"1.2.3.4", "10.0.0.0/8"}
	if len(lines) != len(want) {
		t.Fatalf("条目数不符：期望 %v，实际 %v", want, lines)
	}
	for index := range want {
		if lines[index] != want[index] {
			t.Fatalf("第 %d 条不符：期望 %q，实际 %q", index, want[index], lines[index])
		}
	}
}

// TestScanLinesReportsLineNumbers 覆盖：回调收到的是文件中的真实行号（含被跳过的行）。
func TestScanLinesReportsLineNumbers(t *testing.T) {
	path := writeFile(t, "list.txt", "# 注释\n\n1.2.3.4\n")

	var gotLineNo int
	_, err := ScanLines(path, 0, 0, func(_ string, lineNo int) error {
		gotLineNo = lineNo
		return nil
	})
	if err != nil {
		t.Fatalf("扫描失败：%v", err)
	}
	if gotLineNo != 3 {
		t.Fatalf("条目位于第 3 行，实际报告第 %d 行", gotLineNo)
	}
}

// TestScanLinesRejectsOversizedFile 覆盖：文件超过总量上限时直接拒绝（需求 R13）。
func TestScanLinesRejectsOversizedFile(t *testing.T) {
	path := writeFile(t, "list.txt", "1.2.3.4\n5.6.7.8\n")

	_, err := ScanLines(path, 4, 0, func(string, int) error { return nil })
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("超限文件应返回 ErrFileTooLarge，实际 %v", err)
	}
}

// TestScanLinesPropagatesCallbackError 覆盖：回调错误被原样返回，便于定位非法行。
func TestScanLinesPropagatesCallbackError(t *testing.T) {
	path := writeFile(t, "list.txt", "1.2.3.4\nbad-entry\n")

	sentinel := errors.New("非法条目")
	_, err := ScanLines(path, 0, 0, func(line string, _ int) error {
		if line == "bad-entry" {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("应原样返回回调错误，实际 %v", err)
	}
}

// TestScanLinesLimitsLineLength 覆盖：单行超长时中止扫描（避免单行把内存打爆）。
func TestScanLinesLimitsLineLength(t *testing.T) {
	path := writeFile(t, "list.txt", strings.Repeat("a", 4096)+"\n")

	_, err := ScanLines(path, 0, 128, func(string, int) error { return nil })
	if err == nil {
		t.Fatal("单行超过上限时应返回错误")
	}
}

// TestScanLinesEmptyPath 覆盖：空路径直接报错。
func TestScanLinesEmptyPath(t *testing.T) {
	if _, err := ScanLines("  ", 0, 0, func(string, int) error { return nil }); err == nil {
		t.Fatal("空路径应报错")
	}
}

// TestReadCapped 覆盖：整体读取的限额校验。
func TestReadCapped(t *testing.T) {
	path := writeFile(t, "data.txt", "hello")

	content, err := ReadCapped(path, 16)
	if err != nil {
		t.Fatalf("读取失败：%v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("内容不符：%q", content)
	}

	if _, err := ReadCapped(path, 2); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("超限读取应返回 ErrFileTooLarge，实际 %v", err)
	}
}
