package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testMaxFileBytes 是规则包测试使用的单文件上限（足以覆盖测试数据，又不至于失去约束意义）。
const testMaxFileBytes = 1 << 20

// writeFile 在指定目录写入文件（会自动创建目录）。
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建目录 %s 失败：%v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入文件 %s 失败：%v", path, err)
	}
	return path
}

// newRulePackage 构造一个最小但结构完整的规则包（规则文件 + 数据文件 + 设置文件）。
func newRulePackage(t *testing.T, dir string) {
	t.Helper()

	writeFile(t, dir, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"SecRule ARGS \"@rx (?i:union.*select)\" \"id:942100,phase:2,block\"")
	writeFile(t, dir, "unix-shell.data", "bin/sh\nbin/bash\n")
	writeFile(t, dir, "crs-setup.conf", "SecAction \"id:900000,phase:1,pass\"")
}

// findEntry 在清单中按文件名查找记录。
func findEntry(manifest *Manifest, name string) (FileEntry, bool) {
	for _, entry := range manifest.Files {
		if entry.Name == name {
			return entry, true
		}
	}
	return FileEntry{}, false
}

// TestBuildManifestClassifiesFiles 覆盖：清单按 kind 正确分类，并跳过不匹配的文件。
func TestBuildManifestClassifiesFiles(t *testing.T) {
	dir := t.TempDir()
	newRulePackage(t, dir)
	// 不匹配 include / data_include 的文件不进入清单（例如随包附带的说明文档）。
	writeFile(t, dir, "README.md", "本地说明文件")

	created := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	manifest, err := BuildManifest(dir, []string{"*.conf"}, []string{"*.data"}, "crs-setup.conf",
		testMaxFileBytes, ManifestMeta{Name: "owasp-crs", Version: "4.17.0", Source: "local", Now: created})
	if err != nil {
		t.Fatalf("生成清单失败：%v", err)
	}

	if manifest.Name != "owasp-crs" || manifest.Version != "4.17.0" || manifest.Source != "local" {
		t.Fatalf("清单元信息错误：%+v", manifest)
	}
	if manifest.Created != created.Format(time.RFC3339) {
		t.Fatalf("Created = %q，期望 %q", manifest.Created, created.Format(time.RFC3339))
	}
	if len(manifest.Files) != 3 {
		t.Fatalf("清单文件数量 = %d，期望 3（README.md 不应进入清单）：%+v", len(manifest.Files), manifest.Files)
	}

	// 清单按文件名排序，保证「同样的输入生成同样的清单」。
	expectedOrder := []string{
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"crs-setup.conf",
		"unix-shell.data",
	}
	for index, name := range expectedOrder {
		if manifest.Files[index].Name != name {
			t.Fatalf("第 %d 条记录 = %q，期望 %q（应按文件名排序）",
				index, manifest.Files[index].Name, name)
		}
	}

	kinds := map[string]string{
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": KindRules,
		"unix-shell.data":                          KindData,
		"crs-setup.conf":                           KindSetup,
	}
	for name, kind := range kinds {
		entry, ok := findEntry(manifest, name)
		if !ok {
			t.Fatalf("清单缺少 %s", name)
		}
		if entry.Kind != kind {
			t.Errorf("%s 的 kind = %q，期望 %q", name, entry.Kind, kind)
		}
		if len(entry.SHA256) != 64 {
			t.Errorf("%s 的 SHA256 长度 = %d，期望 64", name, len(entry.SHA256))
		}
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("读取 %s 失败：%v", name, err)
		}
		if entry.Size != int64(len(content)) {
			t.Errorf("%s 的 Size = %d，期望 %d", name, entry.Size, len(content))
		}
	}
}

// TestBuildManifestRejectsInvalidInput 覆盖：非法参数与空目录必须报错。
func TestBuildManifestRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	newRulePackage(t, dir)

	if _, err := BuildManifest(dir, nil, nil, "", 0, ManifestMeta{Name: "x", Version: "1"}); err == nil {
		t.Errorf("max_file_bytes <= 0 时应报错（限额不允许静默失效）")
	}

	empty := t.TempDir()
	if _, err := BuildManifest(empty, nil, nil, "", testMaxFileBytes, ManifestMeta{Name: "x", Version: "1"}); err == nil {
		t.Errorf("空目录应报错")
	}
}

// TestBuildManifestRejectsOversizedFile 覆盖：单个文件超过上限时报错。
func TestBuildManifestRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.conf", strings.Repeat("A", 2048))

	if _, err := BuildManifest(dir, []string{"*.conf"}, nil, "", 1024, ManifestMeta{Name: "x", Version: "1"}); err == nil {
		t.Fatalf("超过单文件上限时应报错")
	}
}

// TestManifestRoundTrip 覆盖：清单写入磁盘后可被严格模式重新读回。
func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	newRulePackage(t, dir)

	manifest, err := BuildManifest(dir, nil, nil, "crs-setup.conf", testMaxFileBytes,
		ManifestMeta{Name: "owasp-crs", Version: "4.17.0", Source: "local"})
	if err != nil {
		t.Fatalf("生成清单失败：%v", err)
	}
	path, err := WriteManifest(dir, manifest)
	if err != nil {
		t.Fatalf("写入清单失败：%v", err)
	}
	if filepath.Base(path) != ManifestName {
		t.Fatalf("清单文件名 = %q，期望 %q", filepath.Base(path), ManifestName)
	}

	loaded, err := LoadManifest(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("读取清单失败：%v", err)
	}
	if loaded.Name != manifest.Name || loaded.Version != manifest.Version || len(loaded.Files) != len(manifest.Files) {
		t.Fatalf("读回的清单与写入内容不一致：%+v vs %+v", loaded, manifest)
	}
}

// TestLoadManifestRejectsBadInput 覆盖：清单缺失、缺字段、含未知字段都必须报错。
func TestLoadManifestRejectsBadInput(t *testing.T) {
	t.Run("清单不存在", func(t *testing.T) {
		if _, err := LoadManifest(t.TempDir(), testMaxFileBytes); err == nil {
			t.Fatalf("清单不存在时应报错")
		}
	})

	t.Run("缺少 name", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, ManifestName, "version: \"1.0\"\nfiles: []\n")
		if _, err := LoadManifest(dir, testMaxFileBytes); err == nil {
			t.Fatalf("缺少 name 时应报错")
		}
	})

	t.Run("缺少 version", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, ManifestName, "name: \"crs\"\nfiles: []\n")
		if _, err := LoadManifest(dir, testMaxFileBytes); err == nil {
			t.Fatalf("缺少 version 时应报错")
		}
	})

	t.Run("含未知字段", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, ManifestName, "name: \"crs\"\nversion: \"1.0\"\nunknown: true\n")
		if _, err := LoadManifest(dir, testMaxFileBytes); err == nil {
			t.Fatalf("严格模式下未知字段应报错（否则「以为校验了、其实没有」）")
		}
	})
}

// TestVerifyReportsThreeStates 覆盖：缺失 / 变更 / 多余三种异常都能被分别识别。
func TestVerifyReportsThreeStates(t *testing.T) {
	dir := t.TempDir()
	newRulePackage(t, dir)

	manifest, err := BuildManifest(dir, nil, nil, "crs-setup.conf", testMaxFileBytes,
		ManifestMeta{Name: "owasp-crs", Version: "4.17.0"})
	if err != nil {
		t.Fatalf("生成清单失败：%v", err)
	}
	if _, err := WriteManifest(dir, manifest); err != nil {
		t.Fatalf("写入清单失败：%v", err)
	}

	// 基线：内容与清单一致时校验通过。
	report, err := Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if !report.OK() {
		t.Fatalf("基线校验应通过，实际：%+v", report)
	}
	if len(report.Unexpected) != 0 {
		t.Fatalf("基线不应有多余文件，实际：%v", report.Unexpected)
	}

	// 场景一：文件被改写（内容长度变化）。
	writeFile(t, dir, "crs-setup.conf", "SecAction \"id:900000,phase:1,pass\" # 被改动")
	report, err = Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if len(report.Mismatched) != 1 || report.Mismatched[0] != "crs-setup.conf" {
		t.Fatalf("应识别出 crs-setup.conf 被改动，实际：%+v", report.Mismatched)
	}
	if report.OK() {
		t.Fatalf("存在改动时 OK() 应为 false")
	}

	// 场景二：清单声明了但目录中缺失的文件。
	if err := os.Remove(filepath.Join(dir, "unix-shell.data")); err != nil {
		t.Fatalf("删除文件失败：%v", err)
	}
	report, err = Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if len(report.Missing) != 1 || report.Missing[0] != "unix-shell.data" {
		t.Fatalf("应识别出 unix-shell.data 缺失，实际：%+v", report.Missing)
	}

	// 场景三：目录里存在清单未声明的文件（升级残留）。
	writeFile(t, dir, "leftover.conf", "SecRule ARGS \"@rx x\" \"id:999999,phase:2,block\"")
	report, err = Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if len(report.Unexpected) != 1 || report.Unexpected[0] != "leftover.conf" {
		t.Fatalf("应识别出多余文件 leftover.conf，实际：%+v", report.Unexpected)
	}
	// 注意：此处 OK() 仍为 false —— 前两个场景造成的缺失与摘要不一致尚未修复。
	if report.OK() {
		t.Fatalf("存在缺失与摘要不一致时 OK() 必须为 false")
	}

	// 场景四：清单外的说明文档同样被判为多余文件。
	//
	// 这是刻意保留的约定：规则目录是「规则包交付物目录」，只应存放清单声明的文件。
	// 只有这样，「目录里还有什么是会被加载/参与检测的」才不存在盲区。
	writeFile(t, dir, "README.md", "说明文档")
	report, err = Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if len(report.Unexpected) != 2 {
		t.Fatalf("说明文档也应被判为多余文件，实际：%+v", report.Unexpected)
	}
}

// TestVerifyUnexpectedFilesDoNotFailVerification 覆盖：仅有「多余文件」时 OK() 仍为 true。
//
// 语义说明：多余文件由 CLI 单独处置（退出码 3），它表达的是「目录不干净」，
// 而不是「规则包损坏」——两者的处置动作完全不同（清理 vs 重新拷贝）。
func TestVerifyUnexpectedFilesDoNotFailVerification(t *testing.T) {
	dir := t.TempDir()
	newRulePackage(t, dir)
	addManifest(t, dir, "1.0.0")

	report, err := Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if !report.OK() || len(report.Unexpected) != 0 {
		t.Fatalf("干净目录应通过校验，实际：%+v", report)
	}

	writeFile(t, dir, "leftover.conf", "SecRule ARGS \"@rx x\" \"id:999999,phase:2,block\"")
	report, err = Verify(dir, testMaxFileBytes)
	if err != nil {
		t.Fatalf("校验失败：%v", err)
	}
	if !report.OK() {
		t.Fatalf("仅有多余文件时 OK() 应为 true：%+v", report)
	}
	if len(report.Unexpected) != 1 || report.Unexpected[0] != "leftover.conf" {
		t.Fatalf("应识别出 leftover.conf，实际：%+v", report.Unexpected)
	}
}

// TestInstallCreatesTargetAndKeepsPrevious 覆盖：首次安装建立目标目录，升级时保留上一版本。
func TestInstallCreatesTargetAndKeepsPrevious(t *testing.T) {
	sourceV1 := t.TempDir()
	writeFile(t, sourceV1, "a.conf", "rule-v1")
	addManifest(t, sourceV1, "1.0.0")

	target := filepath.Join(t.TempDir(), "crs")

	first, err := Install(sourceV1, target, InstallOptions{MaxFileBytes: testMaxFileBytes})
	if err != nil {
		t.Fatalf("首次安装失败：%v", err)
	}
	if first.Previous != "" {
		t.Fatalf("首次安装不应有上一版本，实际：%q", first.Previous)
	}
	if first.Files != 2 {
		t.Fatalf("安装文件数 = %d，期望 2（a.conf + manifest.yaml）", first.Files)
	}
	if got := readFile(t, filepath.Join(target, "a.conf")); got != "rule-v1" {
		t.Fatalf("目标目录内容 = %q，期望 rule-v1", got)
	}

	// 升级：源目录换了内容与版本号。
	sourceV2 := t.TempDir()
	writeFile(t, sourceV2, "a.conf", "rule-v2")
	writeFile(t, sourceV2, "b.conf", "rule-v2-b")
	addManifest(t, sourceV2, "2.0.0")

	second, err := Install(sourceV2, target, InstallOptions{MaxFileBytes: testMaxFileBytes})
	if err != nil {
		t.Fatalf("升级安装失败：%v", err)
	}
	if second.Previous == "" {
		t.Fatalf("升级安装应保留上一版本目录")
	}
	if got := readFile(t, filepath.Join(target, "a.conf")); got != "rule-v2" {
		t.Fatalf("升级后目标目录内容 = %q，期望 rule-v2", got)
	}
	if !fileExists(filepath.Join(target, "b.conf")) {
		t.Fatalf("升级后应包含新文件 b.conf")
	}
	if got := readFile(t, filepath.Join(second.Previous, "a.conf")); got != "rule-v1" {
		t.Fatalf("上一版本目录内容 = %q，期望 rule-v1", got)
	}
	// 暂存目录不应残留。
	if fileExists(target + ".new") {
		t.Fatalf("安装完成后不应残留暂存目录 %s.new", target)
	}
}

// TestInstallRejectsSamePathAndBadSource 覆盖：源与目标相同、源不是目录、源路径不存在都必须报错。
func TestInstallRejectsSamePathAndBadSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.conf", "rule")

	if _, err := Install(dir, dir, InstallOptions{}); err == nil {
		t.Errorf("源目录与目标目录相同时应报错")
	}

	filePath := writeFile(t, t.TempDir(), "not-a-dir.conf", "rule")
	if _, err := Install(filePath, filepath.Join(t.TempDir(), "target"), InstallOptions{}); err == nil {
		t.Errorf("源路径不是目录时应报错")
	}

	if _, err := Install(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "target"), InstallOptions{}); err == nil {
		t.Errorf("源目录不存在时应报错")
	}

	if _, err := Install("  ", filepath.Join(t.TempDir(), "target"), InstallOptions{}); err == nil {
		t.Errorf("源目录为空串时应报错")
	}
	if _, err := Install(dir, "  ", InstallOptions{}); err == nil {
		t.Errorf("目标目录为空串时应报错")
	}
}

// TestInstallRejectsPackageFailingVerification 覆盖：源包校验不通过时拒绝安装。
func TestInstallRejectsPackageFailingVerification(t *testing.T) {
	source := t.TempDir()
	writeFile(t, source, "a.conf", "rule")
	addManifest(t, source, "1.0.0")

	// 篡改文件内容，使清单摘要不再匹配。
	writeFile(t, source, "a.conf", "rule-tampered")

	target := filepath.Join(t.TempDir(), "crs")
	if _, err := Install(source, target, InstallOptions{MaxFileBytes: testMaxFileBytes}); err == nil {
		t.Fatalf("源包摘要不一致时应拒绝安装")
	}
	if fileExists(target) {
		t.Fatalf("安装被拒绝时不应创建目标目录")
	}
}

// TestInstallFailureKeepsExistingTarget 覆盖：安装失败不破坏现有规则目录（核心安全属性）。
func TestInstallFailureKeepsExistingTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "crs")
	writeFile(t, target, "a.conf", "existing")

	// 源目录中包含子目录：当前实现明确不支持，复制阶段必然失败。
	source := t.TempDir()
	writeFile(t, source, "a.conf", "new")
	writeFile(t, filepath.Join(source, "sub"), "b.conf", "nested")

	if _, err := Install(source, target, InstallOptions{MaxFileBytes: testMaxFileBytes}); err == nil {
		t.Fatalf("含子目录的规则包应被拒绝")
	}

	if got := readFile(t, filepath.Join(target, "a.conf")); got != "existing" {
		t.Fatalf("安装失败后目标目录内容 = %q，期望保留 existing", got)
	}
	if fileExists(target + ".new") {
		t.Fatalf("安装失败后不应残留暂存目录")
	}
}

// TestInstallEnforcesTotalSizeLimit 覆盖：规则包总大小超过上限时拒绝安装。
func TestInstallEnforcesTotalSizeLimit(t *testing.T) {
	source := t.TempDir()
	writeFile(t, source, "a.conf", strings.Repeat("A", 512))
	writeFile(t, source, "b.conf", strings.Repeat("B", 512))

	target := filepath.Join(t.TempDir(), "crs")
	_, err := Install(source, target, InstallOptions{MaxFileBytes: testMaxFileBytes, MaxTotalBytes: 600})
	if err == nil {
		t.Fatalf("总大小超限时应拒绝安装")
	}
	if !strings.Contains(err.Error(), "max_rules_total_bytes") {
		t.Fatalf("错误信息应指出对应的配置项，实际：%v", err)
	}
}

// TestInstallEnforcesSingleFileLimit 覆盖：单个文件超过上限时拒绝安装。
func TestInstallEnforcesSingleFileLimit(t *testing.T) {
	source := t.TempDir()
	writeFile(t, source, "a.conf", strings.Repeat("A", 2048))

	target := filepath.Join(t.TempDir(), "crs")
	_, err := Install(source, target, InstallOptions{MaxFileBytes: 1024})
	if err == nil {
		t.Fatalf("单文件超限时应拒绝安装")
	}
	if !strings.Contains(err.Error(), "max_rule_file_bytes") {
		t.Fatalf("错误信息应指出对应的配置项，实际：%v", err)
	}
}

// TestRollbackRestoresPreviousVersion 覆盖：回滚把上一版本恢复为当前版本，并保留失败版本供排障。
func TestRollbackRestoresPreviousVersion(t *testing.T) {
	target := filepath.Join(t.TempDir(), "crs")

	sourceV1 := t.TempDir()
	writeFile(t, sourceV1, "a.conf", "rule-v1")
	if _, err := Install(sourceV1, target, InstallOptions{MaxFileBytes: testMaxFileBytes}); err != nil {
		t.Fatalf("首次安装失败：%v", err)
	}

	sourceV2 := t.TempDir()
	writeFile(t, sourceV2, "a.conf", "rule-v2")
	if _, err := Install(sourceV2, target, InstallOptions{MaxFileBytes: testMaxFileBytes}); err != nil {
		t.Fatalf("升级安装失败：%v", err)
	}

	failedDir, err := Rollback(target, InstallOptions{MaxFileBytes: testMaxFileBytes})
	if err != nil {
		t.Fatalf("回滚失败：%v", err)
	}
	if got := readFile(t, filepath.Join(target, "a.conf")); got != "rule-v1" {
		t.Fatalf("回滚后目标目录内容 = %q，期望 rule-v1", got)
	}
	if got := readFile(t, filepath.Join(failedDir, "a.conf")); got != "rule-v2" {
		t.Fatalf("失败版本目录内容 = %q，期望保留 rule-v2", got)
	}
}

// TestRollbackWithoutPreviousFails 覆盖：没有上一版本可回滚时明确报错。
func TestRollbackWithoutPreviousFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "crs")
	writeFile(t, target, "a.conf", "rule")

	if _, err := Rollback(target, InstallOptions{}); err == nil {
		t.Fatalf("没有上一版本时应报错")
	}
}

// TestInstallSupportsCustomPreviousSuffix 覆盖：回滚目录后缀可配置。
func TestInstallSupportsCustomPreviousSuffix(t *testing.T) {
	target := filepath.Join(t.TempDir(), "crs")

	first := t.TempDir()
	writeFile(t, first, "a.conf", "rule-v1")
	if _, err := Install(first, target, InstallOptions{MaxFileBytes: testMaxFileBytes, PreviousSuffix: ".bak"}); err != nil {
		t.Fatalf("首次安装失败：%v", err)
	}

	second := t.TempDir()
	writeFile(t, second, "a.conf", "rule-v2")
	result, err := Install(second, target, InstallOptions{MaxFileBytes: testMaxFileBytes, PreviousSuffix: ".bak"})
	if err != nil {
		t.Fatalf("升级安装失败：%v", err)
	}
	if !strings.HasSuffix(result.Previous, ".bak") {
		t.Fatalf("上一版本目录 = %q，期望以 .bak 结尾", result.Previous)
	}
	if _, err := Rollback(target, InstallOptions{PreviousSuffix: ".bak"}); err != nil {
		t.Fatalf("使用自定义后缀回滚失败：%v", err)
	}
	if got := readFile(t, filepath.Join(target, "a.conf")); got != "rule-v1" {
		t.Fatalf("回滚后内容 = %q，期望 rule-v1", got)
	}
}

// addManifest 为目录生成并写入清单（模拟「带清单的规则包」）。
func addManifest(t *testing.T, dir, version string) {
	t.Helper()

	manifest, err := BuildManifest(dir, nil, nil, "", testMaxFileBytes,
		ManifestMeta{Name: "test-crs", Version: version, Source: "test"})
	if err != nil {
		t.Fatalf("生成清单失败：%v", err)
	}
	if _, err := WriteManifest(dir, manifest); err != nil {
		t.Fatalf("写入清单失败：%v", err)
	}
}

// readFile 读取文件内容，失败直接终止用例。
func readFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取文件 %s 失败：%v", path, err)
	}
	return string(content)
}

// fileExists 判断路径是否存在。
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
