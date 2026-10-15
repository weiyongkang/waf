package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/rules"
)

// rulesTestDir 构造一个「带清单的合法规则包」目录。
func rulesTestDir(t *testing.T, version string) string {
	t.Helper()

	dir := t.TempDir()
	writeRulesTestFile(t, dir, "a.conf", "SecRule ARGS \"@rx (?i:union.*select)\" \"id:942100,phase:2,block\"")
	writeRulesTestFile(t, dir, "rules.data", "payload")

	manifest, err := rules.BuildManifest(dir, nil, nil, "", 1<<20,
		rules.ManifestMeta{Name: "test-crs", Version: version, Source: "cli-test"})
	if err != nil {
		t.Fatalf("生成清单失败：%v", err)
	}
	if _, err := rules.WriteManifest(dir, manifest); err != nil {
		t.Fatalf("写入清单失败：%v", err)
	}
	return dir
}

// writeRulesTestFile 在目录中写入文件。
func writeRulesTestFile(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建目录失败：%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("写入文件失败：%v", err)
	}
}

// runRulesCommand 执行 rules 子命令并返回退出码与两路输出。
func runRulesCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	code := runRules(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestRulesDispatchRejectsUnknownAction 覆盖：缺少子命令与未知子命令都返回配置错误码。
func TestRulesDispatchRejectsUnknownAction(t *testing.T) {
	if code, _, _ := runRulesCommand(t); code != exitConfigError {
		t.Errorf("缺少子命令时退出码 = %d，期望 %d", code, exitConfigError)
	}
	if code, _, _ := runRulesCommand(t, "no-such-action"); code != exitConfigError {
		t.Errorf("未知子命令时退出码 = %d，期望 %d", code, exitConfigError)
	}
}

// TestRulesVerifyExitCodes 覆盖：校验通过 / 内容不一致 / 有多余文件 三种退出码。
//
// 三种结果分开表达是刻意的：流水线需要区分「包坏了（重新拷贝）」与
// 「包多了文件（人工清理）」，用同一个失败码会让自动化无法判断处置动作。
func TestRulesVerifyExitCodes(t *testing.T) {
	t.Run("校验通过", func(t *testing.T) {
		dir := rulesTestDir(t, "1.0.0")
		code, stdout, stderr := runRulesCommand(t, "verify", "--dir", dir)
		if code != exitOK {
			t.Fatalf("退出码 = %d，期望 %d；stdout=%s stderr=%s", code, exitOK, stdout, stderr)
		}
		if !strings.Contains(stdout, "校验结果：通过") {
			t.Errorf("输出应包含校验结论，实际：%s", stdout)
		}
	})

	t.Run("存在多余文件", func(t *testing.T) {
		dir := rulesTestDir(t, "1.0.0")
		writeRulesTestFile(t, dir, "leftover.conf", "SecRule ARGS \"@rx x\" \"id:999999,phase:2,block\"")

		code, stdout, stderr := runRulesCommand(t, "verify", "--dir", dir)
		if code != exitUnexpectedFiles {
			t.Fatalf("退出码 = %d，期望 %d；stdout=%s stderr=%s", code, exitUnexpectedFiles, stdout, stderr)
		}
		if !strings.Contains(stdout, "leftover.conf") {
			t.Errorf("输出应列出多余文件，实际：%s", stdout)
		}
	})

	t.Run("摘要不一致", func(t *testing.T) {
		dir := rulesTestDir(t, "1.0.0")
		writeRulesTestFile(t, dir, "a.conf", "SecRule ARGS \"@rx (?i:union.*select)\" \"id:942100,phase:2,block\" # 被改动")

		code, stdout, _ := runRulesCommand(t, "verify", "--dir", dir)
		if code != exitConfigError {
			t.Fatalf("退出码 = %d，期望 %d；stdout=%s", code, exitConfigError, stdout)
		}
		if !strings.Contains(stdout, "校验结果：未通过") {
			t.Errorf("输出应给出未通过结论，实际：%s", stdout)
		}
	})

	t.Run("缺少目录参数", func(t *testing.T) {
		code, _, stderr := runRulesCommand(t, "verify")
		if code != exitConfigError {
			t.Fatalf("退出码 = %d，期望 %d", code, exitConfigError)
		}
		if !strings.Contains(stderr, "--dir") {
			t.Errorf("提示信息应指出缺少 --dir，实际：%s", stderr)
		}
	})

	t.Run("目录中没有清单", func(t *testing.T) {
		dir := t.TempDir()
		writeRulesTestFile(t, dir, "a.conf", "rule")
		code, _, stderr := runRulesCommand(t, "verify", "--dir", dir)
		if code != exitConfigError {
			t.Fatalf("退出码 = %d，期望 %d", code, exitConfigError)
		}
		if !strings.Contains(stderr, "规则包校验失败") {
			t.Errorf("提示信息应说明校验失败，实际：%s", stderr)
		}
	})
}

// TestRulesVerifyJSONOutput 覆盖：--json 输出可直接被流水线解析。
func TestRulesVerifyJSONOutput(t *testing.T) {
	dir := rulesTestDir(t, "2.1.0")

	code, stdout, stderr := runRulesCommand(t, "verify", "--dir", dir, "--json")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, `"manifest"`) || !strings.Contains(stdout, `"2.1.0"`) {
		t.Errorf("JSON 输出应包含清单信息，实际：%s", stdout)
	}
}

// TestRulesManifestCreatesManifest 覆盖：manifest 子命令生成可被严格模式读回的清单。
func TestRulesManifestCreatesManifest(t *testing.T) {
	dir := t.TempDir()
	writeRulesTestFile(t, dir, "a.conf", "rule-a")
	writeRulesTestFile(t, dir, "rules.data", "bin/sh")

	code, stdout, stderr := runRulesCommand(t, "manifest",
		"--dir", dir, "--name", "my-crs", "--package-version", "3.0.0", "--source-url", "https://example.com/rules")
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "manifest.yaml") {
		t.Errorf("输出应指出清单文件路径，实际：%s", stdout)
	}

	manifest, err := rules.LoadManifest(dir, 1<<20)
	if err != nil {
		t.Fatalf("读回清单失败：%v", err)
	}
	if manifest.Name != "my-crs" || manifest.Version != "3.0.0" || manifest.Source != "https://example.com/rules" {
		t.Fatalf("清单元信息不符：%+v", manifest)
	}
	if len(manifest.Files) != 2 {
		t.Fatalf("清单文件数量 = %d，期望 2", len(manifest.Files))
	}
}

// TestRulesManifestRequiresNameAndVersion 覆盖：缺少必填参数时报错。
func TestRulesManifestRequiresNameAndVersion(t *testing.T) {
	dir := t.TempDir()
	writeRulesTestFile(t, dir, "a.conf", "rule-a")

	cases := [][]string{
		{"manifest", "--dir", dir, "--package-version", "1.0.0"},
		{"manifest", "--dir", dir, "--name", "crs"},
		{"manifest", "--name", "crs", "--package-version", "1.0.0"},
	}
	for _, args := range cases {
		if code, _, _ := runRulesCommand(t, args...); code != exitConfigError {
			t.Errorf("参数不全时 %v 的退出码应为 %d，实际 %d", args, exitConfigError, code)
		}
	}
}

// TestRulesInstallAndRollback 覆盖：安装子命令保留上一版本，回滚子命令可恢复。
func TestRulesInstallAndRollback(t *testing.T) {
	target := filepath.Join(t.TempDir(), "crs")

	sourceV1 := t.TempDir()
	writeRulesTestFile(t, sourceV1, "a.conf", "rule-v1")

	if code, _, stderr := runRulesCommand(t, "install", "--source", sourceV1, "--target", target); code != exitOK {
		t.Fatalf("首次安装退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}

	sourceV2 := t.TempDir()
	writeRulesTestFile(t, sourceV2, "a.conf", "rule-v2")
	if code, _, stderr := runRulesCommand(t, "install", "--source", sourceV2, "--target", target); code != exitOK {
		t.Fatalf("升级安装退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}

	content, err := os.ReadFile(filepath.Join(target, "a.conf"))
	if err != nil {
		t.Fatalf("读取目标文件失败：%v", err)
	}
	if string(content) != "rule-v2" {
		t.Fatalf("升级后内容 = %q，期望 rule-v2", content)
	}

	if code, stdout, stderr := runRulesCommand(t, "rollback", "--target", target); code != exitOK {
		t.Fatalf("回滚退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	} else if !strings.Contains(stdout, "已回滚") {
		t.Errorf("回滚输出应说明已完成，实际：%s", stdout)
	}

	content, err = os.ReadFile(filepath.Join(target, "a.conf"))
	if err != nil {
		t.Fatalf("读取目标文件失败：%v", err)
	}
	if string(content) != "rule-v1" {
		t.Fatalf("回滚后内容 = %q，期望 rule-v1", content)
	}
}

// TestRulesInstallRejectsSamePath 覆盖：源与目标相同时拒绝执行（避免自毁规则目录）。
func TestRulesInstallRejectsSamePath(t *testing.T) {
	dir := t.TempDir()
	writeRulesTestFile(t, dir, "a.conf", "rule")

	// 库层无法区分「用法错误」与「运行期错误」，统一按运行期错误上报；
	// 这里只断言「必须失败」并检查失败原因，避免把具体退出码焊死。
	if code, _, stderr := runRulesCommand(t, "install", "--source", dir, "--target", dir); code == exitOK {
		t.Errorf("源与目标相同时必须失败，实际退出码 %d", code)
	} else if !strings.Contains(stderr, "安装失败") {
		t.Errorf("失败时应说明原因，实际：%s", stderr)
	}
}

// TestRulesRollbackWithoutPrevious 覆盖：没有可回滚版本时报错。
func TestRulesRollbackWithoutPrevious(t *testing.T) {
	target := t.TempDir()
	writeRulesTestFile(t, target, "a.conf", "rule")

	if code, _, stderr := runRulesCommand(t, "rollback", "--target", target); code == exitOK {
		t.Errorf("无可回滚版本时必须失败，实际退出码 %d", code)
	} else if !strings.Contains(stderr, "回滚") {
		t.Errorf("失败时应给出原因，实际：%s", stderr)
	}
}

// TestRulesReloadWithoutMarkerFile 覆盖：未配置标记文件时给出可操作的提示。
//
// 这里刻意不依赖「运行中的实例」：reload 的设计目标就是「不引入管理面 API」，
// 因此它只能通过文件系统表达，缺少配置时必须明确告知运维两条替代路径。
func TestRulesReloadWithoutMarkerFile(t *testing.T) {
	code, _, stderr := runRulesCommand(t, "reload")
	if code != exitConfigError {
		t.Fatalf("未配置 marker_file 时退出码 = %d，期望 %d", code, exitConfigError)
	}
	if !strings.Contains(stderr, "marker_file") && !strings.Contains(stderr, "hot_reload") {
		t.Errorf("提示信息应指出相关配置项，实际：%s", stderr)
	}
}

// TestRulesReloadTouchesMarkerFile 覆盖：配置了标记文件时 reload 会更新其时间戳。
func TestRulesReloadTouchesMarkerFile(t *testing.T) {
	configDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "reload.marker")
	configPath := filepath.Join(configDir, "waf.yaml")

	body := "version: 1\nengine:\n  hot_reload:\n    enabled: true\n    poll_interval: 1s\n    marker_file: " +
		quoteYAML(filepath.ToSlash(marker)) + "\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}

	code, stdout, stderr := runRulesCommand(t, "reload", "-c", configPath)
	if code != exitOK {
		t.Fatalf("退出码 = %d，期望 %d；stderr=%s", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, marker) && !strings.Contains(stdout, filepath.ToSlash(marker)) {
		t.Errorf("输出应指出被更新的标记文件，实际：%s", stdout)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("标记文件应被创建：%v", err)
	}
}

// quoteYAML 把路径渲染为双引号 YAML 标量（Windows 路径含冒号，必须加引号）。
func quoteYAML(value string) string {
	return "\"" + strings.ReplaceAll(value, "\\", "\\\\") + "\""
}
