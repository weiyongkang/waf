package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 配置目录监听的默认节奏。
//
// 采用轮询而不是 fsnotify：项目交付物是 CGO_ENABLED=0 的单二进制，
// 且容器绑定挂载与 NFS 下文件系统事件并不可靠。配置目录通常只有十几个文件，
// 每轮仅 stat 一遍，开销可以忽略。
const (
	DefaultWatchInterval = 2 * time.Second
	DefaultWatchDebounce = 500 * time.Millisecond
)

// WatchOptions 是配置目录监听的构造参数。
type WatchOptions struct {
	// Inputs 是 -c 指定的原始文件/目录列表。
	Inputs []string
	// Interval 是轮询间隔；<=0 时使用 DefaultWatchInterval。
	Interval time.Duration
	// Debounce 是变化后的稳定等待时间；<=0 时使用 DefaultWatchDebounce。
	Debounce time.Duration
	// Logger 用于记录监听自身的异常；可为 nil。
	Logger *slog.Logger
}

// Watcher 轮询配置文件/目录指纹，发现稳定变化后回调。
type Watcher struct {
	cfg       WatchOptions
	cancel    context.CancelFunc
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// NewWatcher 构造配置监听器。
func NewWatcher(opts WatchOptions) (*Watcher, error) {
	if len(opts.Inputs) == 0 {
		return nil, fmt.Errorf("配置监听至少需要一个文件或目录")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultWatchInterval
	}
	if opts.Debounce <= 0 {
		opts.Debounce = DefaultWatchDebounce
	}
	return &Watcher{cfg: opts, done: make(chan struct{})}, nil
}

// Start 启动后台监听；onChange 在指纹稳定变化后同步调用。
func (w *Watcher) Start(ctx context.Context, onChange func()) {
	if w == nil || onChange == nil {
		return
	}
	w.startOnce.Do(func() {
		watchCtx, cancel := context.WithCancel(ctx)
		w.cancel = cancel
		go w.loop(watchCtx, onChange)
	})
}

// Stop 停止监听并等待后台协程退出；可重复调用。
func (w *Watcher) Stop() {
	if w == nil || w.cancel == nil {
		return
	}
	w.stopOnce.Do(func() {
		w.cancel()
		<-w.done
	})
}

// loop 执行轮询、去抖与回调。
func (w *Watcher) loop(ctx context.Context, onChange func()) {
	defer close(w.done)

	fingerprint, err := configFingerprint(w.cfg.Inputs)
	if err != nil {
		w.logf("WARN", "配置目录指纹计算失败，将在下一轮重试", "error", err.Error())
	}

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		next, err := configFingerprint(w.cfg.Inputs)
		if err != nil {
			w.logf("WARN", "配置目录指纹计算失败，跳过本轮检查", "error", err.Error())
			continue
		}
		if next == fingerprint {
			continue
		}

		// 文件可能正在被写入：等待一个去抖周期后复核，确认指纹稳定再重载。
		if !w.waitDebounce(ctx) {
			return
		}
		confirmed, err := configFingerprint(w.cfg.Inputs)
		if err != nil {
			w.logf("WARN", "配置目录指纹复核失败，跳过本轮检查", "error", err.Error())
			continue
		}

		fingerprint = confirmed
		w.logf("INFO", "检测到配置文件变化，开始热重载", "fingerprint", shortDigest(confirmed))
		onChange()
	}
}

// waitDebounce 等待去抖周期；上下文取消时返回 false。
func (w *Watcher) waitDebounce(ctx context.Context) bool {
	timer := time.NewTimer(w.cfg.Debounce)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// configFingerprint 计算配置文件/目录的稳定指纹。
//
// 指纹包含路径、大小与修改时间；目录输入会包含其下所有将被加载的配置文件。
// 文件缺失也记录为一种状态，保证「删除后重新创建」同样能触发重载尝试。
func configFingerprint(inputs []string) (string, error) {
	entries := make([]string, 0, len(inputs))
	for _, input := range inputs {
		path := strings.TrimSpace(input)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			entries = append(entries, "missing|"+filepath.Clean(path))
			continue
		}
		if info.IsDir() {
			files, err := configFilesInDir(path)
			if err != nil {
				return "", err
			}
			if len(files) == 0 {
				entries = append(entries, "dir|"+filepath.Clean(path)+"|<empty>")
				continue
			}
			for _, file := range files {
				fileInfo, err := os.Stat(file)
				if err != nil {
					entries = append(entries, "missing|"+filepath.Clean(file))
					continue
				}
				entries = append(entries, fmt.Sprintf(
					"file|%s|%d|%d", filepath.Clean(file), fileInfo.Size(), fileInfo.ModTime().UnixNano(),
				))
			}
			continue
		}
		entries = append(entries, fmt.Sprintf(
			"file|%s|%d|%d", filepath.Clean(path), info.Size(), info.ModTime().UnixNano(),
		))
	}
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

// shortDigest 截取摘要前 12 位，仅用于日志展示。
func shortDigest(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

// logf 写系统日志；logger 为 nil 时静默。
func (w *Watcher) logf(level string, message string, args ...any) {
	if w.cfg.Logger == nil {
		return
	}
	switch level {
	case "WARN":
		w.cfg.Logger.Warn(message, args...)
	case "ERROR":
		w.cfg.Logger.Error(message, args...)
	default:
		w.cfg.Logger.Info(message, args...)
	}
}
