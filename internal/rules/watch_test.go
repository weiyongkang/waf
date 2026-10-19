package rules

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeRuleFile 在目录中写入一个规则文件。
func writeRuleFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入规则文件 %s 失败：%v", path, err)
	}
	return path
}

// silentLogger 返回一个只写日志级别以上消息、但输出被丢弃的日志器。
//
// 之所以仍然传入日志器而不是 nil：让热加载路径的日志调用都被真实执行一遍
// （nil 分支与真实分支的代码路径不同，测试要用更接近生产的那条）。
func silentLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestFingerprintIsStableAndSorted 覆盖：同一目录多次计算结果一致，且与文件遍历顺序无关。
func TestFingerprintIsStableAndSorted(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "b.conf", "SecRule ARGS \"@rx b\" \"id:100001,phase:1,pass\"")
	writeRuleFile(t, dir, "a.conf", "SecRule ARGS \"@rx a\" \"id:100002,phase:1,pass\"")
	writeRuleFile(t, dir, "rules.data", "payload")

	first, err := Fingerprint([]string{dir}, []string{"*.conf"}, []string{"*.data"})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	second, err := Fingerprint([]string{dir}, []string{"*.conf"}, []string{"*.data"})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if first != second {
		t.Fatalf("同一目录两次计算的指纹应一致：%s vs %s", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("指纹应为 SHA-256 十六进制摘要（64 字符），实际长度 %d", len(first))
	}
}

// TestFingerprintDetectsEqualLengthReplacement 覆盖：等长内容替换也能被检出。
//
// 这是「指纹要包含修改时间」的直接原因：只比文件大小会漏掉这类变更，
// 而它恰恰是「把规则阈值从 5 改成 8」的典型形态。
func TestFingerprintDetectsEqualLengthReplacement(t *testing.T) {
	dir := t.TempDir()
	path := writeRuleFile(t, dir, "a.conf", `SecRule ARGS "@rx a" "id:100001,phase:1,pass"`)

	before, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}

	// 写入等长的另一份内容，并显式把修改时间推后，避免依赖文件系统时间戳精度。
	if err := os.WriteFile(path, []byte(`SecRule ARGS "@rx b" "id:100001,phase:1,pass"`), 0o600); err != nil {
		t.Fatalf("改写规则文件失败：%v", err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatalf("调整文件时间失败：%v", err)
	}

	after, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if before == after {
		t.Fatalf("等长内容替换后指纹应发生变化")
	}
}

// TestFingerprintDetectsAddedAndRemovedFiles 覆盖：新增与删除文件都会改变指纹。
func TestFingerprintDetectsAddedAndRemovedFiles(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	withOne, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}

	added := writeRuleFile(t, dir, "b.conf", "rule-b")
	withTwo, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if withOne == withTwo {
		t.Fatalf("新增文件后指纹应发生变化")
	}

	if err := os.Remove(added); err != nil {
		t.Fatalf("删除文件失败：%v", err)
	}
	backToOne, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if backToOne == withTwo {
		t.Fatalf("删除文件后指纹应发生变化")
	}
}

// TestFingerprintEmptyDirectoryIsStable 覆盖：空目录与「从空变为非空」都能被稳定表达。
func TestFingerprintEmptyDirectoryIsStable(t *testing.T) {
	dir := t.TempDir()

	empty, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if empty != hashOf("<empty>") {
		t.Fatalf("空目录应使用固定占位指纹，实际：%s", empty)
	}

	writeRuleFile(t, dir, "a.conf", "rule-a")
	nonEmpty, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if nonEmpty == empty {
		t.Fatalf("目录从空变为非空时指纹必须变化")
	}
}

// TestFingerprintIgnoresUnmatchedFiles 覆盖：不匹配模式的文件不影响指纹。
//
// 监听范围必须与加载范围一致，否则会出现「指纹变了但规则没变」的无效重载。
func TestFingerprintIgnoresUnmatchedFiles(t *testing.T) {
	dir := t.TempDir()

	baseline, err := Fingerprint([]string{dir}, []string{"*.conf"}, []string{"*.data"})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}

	writeRuleFile(t, dir, "README.md", "说明文件")
	after, err := Fingerprint([]string{dir}, []string{"*.conf"}, []string{"*.data"})
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if after != baseline {
		t.Fatalf("不匹配模式的文件不应影响指纹")
	}
}

// TestFingerprintRecursiveDetectsNestedChanges 覆盖：递归模式能发现子目录中的规则变更。
func TestFingerprintRecursiveDetectsNestedChanges(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "deeper")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("创建子目录失败：%v", err)
	}
	path := writeRuleFile(t, nested, "a.yaml", "- path: /old\n")

	before, err := FingerprintRecursive([]string{dir}, []string{"*.yaml"}, nil)
	if err != nil {
		t.Fatalf("计算递归指纹失败：%v", err)
	}

	if err := os.WriteFile(path, []byte("- path: /new-rule\n"), 0o600); err != nil {
		t.Fatalf("改写子目录规则失败：%v", err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatalf("调整文件时间失败：%v", err)
	}

	after, err := FingerprintRecursive([]string{dir}, []string{"*.yaml"}, nil)
	if err != nil {
		t.Fatalf("计算递归指纹失败：%v", err)
	}
	if before == after {
		t.Fatalf("子目录规则变化后递归指纹应发生变化")
	}
}

// TestFingerprintNonRecursiveIgnoresNestedFiles 覆盖：默认模式保持原有语义，
// 不会因为子目录文件变化而触发无关重载。
func TestFingerprintNonRecursiveIgnoresNestedFiles(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "top.conf", "top")
	before, err := Fingerprint([]string{dir}, []string{"*.conf"}, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}

	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("创建子目录失败：%v", err)
	}
	writeRuleFile(t, nested, "nested.conf", "nested")

	after, err := Fingerprint([]string{dir}, []string{"*.conf"}, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	if before != after {
		t.Fatalf("非递归模式不应感知子目录文件变化")
	}
}

// TestFingerprintRejectsInvalidPattern 覆盖：非法匹配模式必须报错而不是静默忽略。
func TestFingerprintRejectsInvalidPattern(t *testing.T) {
	dir := t.TempDir()

	if _, err := Fingerprint([]string{dir}, []string{"["}, nil); err == nil {
		t.Fatalf("非法匹配模式应报错")
	}
}

// TestFingerprintSkipsEmptyDirEntries 覆盖：目录列表中的空串被忽略，不会构造出非法路径。
func TestFingerprintSkipsEmptyDirEntries(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	only, err := Fingerprint([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("计算指纹失败：%v", err)
	}
	mixed, err := Fingerprint([]string{"", dir, "  "}, nil, nil)
	if err != nil {
		t.Fatalf("含空目录项时不应报错：%v", err)
	}
	if only != mixed {
		t.Fatalf("空目录项应被忽略：%s vs %s", only, mixed)
	}
}

// TestNewWatcherValidatesConfig 覆盖：构造阶段的参数校验。
func TestNewWatcherValidatesConfig(t *testing.T) {
	if _, err := NewWatcher(WatchConfig{Interval: time.Second}); err == nil {
		t.Errorf("未提供监听目录时应报错")
	}
	if _, err := NewWatcher(WatchConfig{Dirs: []string{t.TempDir()}, Interval: 0}); err == nil {
		t.Errorf("轮询间隔为 0 时应报错")
	}
	if _, err := NewWatcher(WatchConfig{Dirs: []string{t.TempDir()}, Interval: -time.Second}); err == nil {
		t.Errorf("轮询间隔为负时应报错")
	}
}

// TestWatcherTriggersOnFileChange 覆盖：文件内容变化触发回调，且回调只在一轮内触发一次。
func TestWatcherTriggersOnFileChange(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	watcher, err := NewWatcher(WatchConfig{
		Dirs:     []string{dir},
		Interval: 20 * time.Millisecond,
		Logger:   silentLogger(),
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}

	notifications := make(chan struct{}, 8)
	watcher.Start(context.Background(), func() { notifications <- struct{}{} })
	t.Cleanup(watcher.Stop)

	// 启动后先确认「没有变化不会误报」：留出几个轮询周期。
	select {
	case <-notifications:
		t.Fatalf("未发生变化时不应触发重载")
	case <-time.After(150 * time.Millisecond):
	}

	writeRuleFile(t, dir, "b.conf", "rule-b")

	select {
	case <-notifications:
	case <-time.After(5 * time.Second):
		t.Fatalf("文件变化后应在超时前触发重载")
	}
}

// TestWatcherTriggersOnMarkerFile 覆盖：标记文件被 touch 时触发重载。
//
// 该机制用于「不重启进程、也不改规则文件」的手动重载入口（waf rules reload）。
func TestWatcherTriggersOnMarkerFile(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	marker := filepath.Join(t.TempDir(), "reload.marker")
	if err := os.WriteFile(marker, []byte("initial"), 0o600); err != nil {
		t.Fatalf("创建标记文件失败：%v", err)
	}

	watcher, err := NewWatcher(WatchConfig{
		Dirs:       []string{dir},
		Interval:   20 * time.Millisecond,
		MarkerFile: marker,
		Logger:     silentLogger(),
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}

	notifications := make(chan struct{}, 8)
	watcher.Start(context.Background(), func() { notifications <- struct{}{} })
	t.Cleanup(watcher.Stop)

	select {
	case <-notifications:
		t.Fatalf("标记文件未变化时不应触发重载")
	case <-time.After(150 * time.Millisecond):
	}

	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(marker, later, later); err != nil {
		t.Fatalf("更新时间戳失败：%v", err)
	}

	select {
	case <-notifications:
	case <-time.After(5 * time.Second):
		t.Fatalf("标记文件变化后应在超时前触发重载")
	}
}

// TestWatcherDebounceStillTriggers 覆盖：开启去抖动后仍然会触发（只是延迟一拍）。
func TestWatcherDebounceStillTriggers(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	watcher, err := NewWatcher(WatchConfig{
		Dirs:     []string{dir},
		Interval: 20 * time.Millisecond,
		Debounce: 30 * time.Millisecond,
		Logger:   silentLogger(),
	})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}

	notifications := make(chan struct{}, 8)
	watcher.Start(context.Background(), func() { notifications <- struct{}{} })
	t.Cleanup(watcher.Stop)

	writeRuleFile(t, dir, "c.conf", "rule-c")

	select {
	case <-notifications:
	case <-time.After(5 * time.Second):
		t.Fatalf("开启去抖动后仍应在超时前触发重载")
	}
}

// TestWatcherStopIsIdempotent 覆盖：Stop 可重复调用，且未 Start 时调用不阻塞。
func TestWatcherStopIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	watcher, err := NewWatcher(WatchConfig{Dirs: []string{dir}, Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}

	// 未调用 Start：Stop 必须是安全空操作。
	watcher.Stop()

	watcher.Start(context.Background(), func() {})
	watcher.Stop()
	watcher.Stop()
}

// TestWatcherStopsWhenContextCancelled 覆盖：上下文取消后轮询协程退出，不再触发回调。
func TestWatcherStopsWhenContextCancelled(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.conf", "rule-a")

	watcher, err := NewWatcher(WatchConfig{Dirs: []string{dir}, Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("构造监听器失败：%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	notifications := make(chan struct{}, 8)
	watcher.Start(ctx, func() { notifications <- struct{}{} })

	cancel()
	// 等待协程真正退出：Stop 内部会等待 done。
	watcher.Stop()

	writeRuleFile(t, dir, "d.conf", "rule-d")

	select {
	case <-notifications:
		t.Fatalf("上下文取消后不应再触发回调")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDirFilesListsMatchedFilesSorted 覆盖：DirFiles 与加载逻辑使用同一套模式归一化规则。
func TestDirFilesListsMatchedFilesSorted(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "b.conf", "rule-b")
	writeRuleFile(t, dir, "a.conf", "rule-a")
	writeRuleFile(t, dir, "rules.data", "payload")
	writeRuleFile(t, dir, "README.md", "说明")

	names, err := DirFiles(dir, nil, nil)
	if err != nil {
		t.Fatalf("列出规则文件失败：%v", err)
	}

	expected := []string{"a.conf", "b.conf", "rules.data"}
	if len(names) != len(expected) {
		t.Fatalf("文件数量 = %d，期望 %d：%v", len(names), len(expected), names)
	}
	for index, name := range expected {
		if names[index] != name {
			t.Fatalf("第 %d 个文件 = %q，期望 %q（应按字典序）", index, names[index], name)
		}
	}
}
