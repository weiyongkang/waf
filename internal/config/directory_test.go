package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadExpandsConfigDirectoryInOrder 覆盖：目录内按文件名字典序合并，并过滤非配置/隐藏文件。
func TestLoadExpandsConfigDirectoryInOrder(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "10-ban.yaml", "ban:\n  default_ttl: 10m\n")
	writeConfig(t, dir, "20-ban.yaml", "ban:\n  default_ttl: 45m\n")
	writeConfig(t, dir, ".hidden.yaml", "ban:\n  default_ttl: 99m\n")
	writeConfig(t, dir, "notes.txt", "ban:\n  default_ttl: 88m\n")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("创建子目录失败：%v", err)
	}
	writeConfig(t, filepath.Join(dir, "sub"), "30-ban.yaml", "ban:\n  default_ttl: 77m\n")

	resolved, err := Load(Options{ConfigFiles: []string{dir}, SkipDefaultConfigPath: true})
	if err != nil {
		t.Fatalf("加载配置目录失败：%v", err)
	}
	if got := resolved.Config.Ban.DefaultTTL.String(); got != "45m0s" {
		t.Fatalf("ban.default_ttl = %s，期望 45m0s（20-ban.yaml 最后生效）", got)
	}
	wantFiles := []string{
		filepath.Join(dir, "10-ban.yaml"),
		filepath.Join(dir, "20-ban.yaml"),
	}
	if len(resolved.Files) != len(wantFiles) {
		t.Fatalf("加载文件数 = %d，期望 %d：%v", len(resolved.Files), len(wantFiles), resolved.Files)
	}
	for index, want := range wantFiles {
		if resolved.Files[index] != want {
			t.Fatalf("Files[%d] = %s，期望 %s", index, resolved.Files[index], want)
		}
	}
	if len(resolved.ConfigDirs) != 1 || resolved.ConfigDirs[0] != dir {
		t.Fatalf("ConfigDirs = %v，期望 [%s]", resolved.ConfigDirs, dir)
	}
}

// TestLoadMixesFileAndDirectoryOrder 覆盖：文件与目录混用时按 -c 出现顺序覆盖。
func TestLoadMixesFileAndDirectoryOrder(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("创建配置目录失败：%v", err)
	}
	writeConfig(t, configDir, "10-server.yaml", "server:\n  listen: \":9081\"\n")
	extra := filepath.Join(dir, "99-extra.yaml")
	if err := os.WriteFile(extra, []byte("server:\n  listen: \":9082\"\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败：%v", err)
	}

	resolved, err := Load(Options{ConfigFiles: []string{configDir, extra}, SkipDefaultConfigPath: true})
	if err != nil {
		t.Fatalf("加载混合配置失败：%v", err)
	}
	if got := resolved.Config.Server.Listen; got != ":9082" {
		t.Fatalf("server.listen = %s，期望后出现的文件 :9082", got)
	}

	resolved, err = Load(Options{ConfigFiles: []string{extra, configDir}, SkipDefaultConfigPath: true})
	if err != nil {
		t.Fatalf("加载混合配置失败：%v", err)
	}
	if got := resolved.Config.Server.Listen; got != ":9081" {
		t.Fatalf("server.listen = %s，期望后出现的目录 :9081", got)
	}
}

// TestLoadRejectsEmptyConfigDirectory 覆盖：空目录不能静默退化为默认配置。
func TestLoadRejectsEmptyConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(Options{ConfigFiles: []string{dir}, SkipDefaultConfigPath: true})
	if err == nil {
		t.Fatal("空配置目录应返回错误")
	}
	if !strings.Contains(err.Error(), "没有可加载的配置文件") {
		t.Fatalf("错误信息未说明空目录：%v", err)
	}
}

// TestConfigFingerprintDetectsChanges 覆盖：目录内容变化会改变监听指纹。
func TestConfigFingerprintDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "10-waf.yaml")
	writeConfig(t, dir, "10-waf.yaml", "server:\n  listen: \":9080\"\n")

	first, err := configFingerprint([]string{dir})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9081\"\n"), 0o600); err != nil {
		t.Fatalf("更新配置失败：%v", err)
	}
	stamp := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("更新修改时间失败：%v", err)
	}
	second, err := configFingerprint([]string{dir})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if first == second {
		t.Fatal("配置文件变化后指纹不应相同")
	}
}

// TestRestartRequiredChanges 覆盖：只有可热加载段允许运行期替换。
func TestRestartRequiredChanges(t *testing.T) {
	base := Default()
	dynamic := Default()
	dynamic.Pipeline = nil
	dynamic.Sites = nil
	dynamic.Ban.DefaultTTL = dur(10 * time.Minute)
	dynamic.Responder.IncludeDetails = true
	dynamic.Engine.Mode = EngineModeDetectionOnly
	if changes := RestartRequiredChanges(base, dynamic); len(changes) != 0 {
		t.Fatalf("动态配置不应要求重启，实际：%v", changes)
	}

	static := Default()
	static.Server.Listen = ":9999"
	static.Logging.Access.Level = "debug"
	changes := RestartRequiredChanges(base, static)
	if len(changes) != 2 || changes[0] != "server" || changes[1] != "logging" {
		t.Fatalf("静态配置变更 = %v，期望 [server logging]", changes)
	}
}

// writeConfig 写入测试配置文件并自动创建目录。
func writeConfig(t *testing.T, dir string, name string, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败：%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}
}
