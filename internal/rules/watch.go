package rules

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

// WatchConfig 是规则文件监听的配置。
//
// 为什么用「轮询指纹」而不是 inotify / ReadDirectoryChangesW（设计取舍）：
//
//  1. 依赖面：本项目交付物是 CGO_ENABLED=0 的静态单二进制（需求 R14），
//     引入 fsnotify 会新增第三方依赖，而本项目坚持「无额外运行时依赖」。
//  2. 环境一致性：容器的绑定挂载、overlayfs 与部分 NFS 场景下，
//     文件系统事件会丢失或行为不一致；轮询在这三种环境下表现完全相同。
//  3. 代价可控：规则目录通常只有几十个文件，每轮只做 stat（不读内容），
//     PollInterval 默认 5s，开销可以忽略。
//
// 该取舍已记录在 docs/development-roadmap.md §10.9。
type WatchConfig struct {
	// Dirs 是需要监听的规则目录（主规则目录 + 自定义规则目录）。
	Dirs []string
	// Include 是规则文件的匹配模式（与加载时保持一致，避免监听范围与加载范围不一致）。
	Include []string
	// DataInclude 是数据文件的匹配模式。
	DataInclude []string
	// Interval 是轮询间隔。
	Interval time.Duration
	// Debounce 是变化后的去抖动时间：确认「指纹稳定下来」再回调，
	// 避免打包/解包过程中文件仍在变化时触发半成品重载。
	Debounce time.Duration
	// MarkerFile 是可选的「手动触发」标记文件：其修改时间变化也会触发回调。
	MarkerFile string
	// Logger 是系统日志器，可为 nil。
	Logger *slog.Logger
}

// Watcher 周期性比对规则目录指纹，发现变化时回调通知。
//
// 并发约定：Start 只应调用一次；Stop 可安全重复调用。
type Watcher struct {
	// cfg 是监听配置。
	cfg WatchConfig
	// logger 是系统日志器。
	logger *slog.Logger
	// fingerprint 是上一轮的指纹。
	fingerprint string
	// markerStamp 是上一轮的标记文件修改时间。
	markerStamp time.Time

	// cancel 停止轮询。
	cancel context.CancelFunc
	// done 在轮询协程退出后关闭。
	done chan struct{}
	// stopOnce 保证 Stop 幂等。
	stopOnce sync.Once
}

// NewWatcher 构造规则文件监听器并计算初始指纹。
//
// 初始指纹的作用是避免「启动时立刻误报一次变化」：只有指纹相对启动时刻发生变化，
// 才认为是真正的文件变更。
func NewWatcher(cfg WatchConfig) (*Watcher, error) {
	if len(cfg.Dirs) == 0 {
		return nil, fmt.Errorf("规则热加载需要至少一个监听目录")
	}
	if cfg.Interval <= 0 {
		return nil, fmt.Errorf("规则热加载的轮询间隔必须大于 0，当前为 %s", cfg.Interval)
	}

	watcher := &Watcher{
		cfg:    cfg,
		logger: cfg.Logger,
	}

	fingerprint, err := Fingerprint(cfg.Dirs, cfg.Include, cfg.DataInclude)
	if err != nil {
		return nil, err
	}
	watcher.fingerprint = fingerprint
	watcher.markerStamp = markerStampOf(cfg.MarkerFile)
	return watcher, nil
}

// Start 启动轮询协程。onChange 在检测到变化时被调用（同一协程内顺序调用）。
func (w *Watcher) Start(ctx context.Context, onChange func()) {
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})

	go func() {
		defer close(w.done)

		ticker := time.NewTicker(w.cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.poll(onChange)
			}
		}
	}()
}

// Stop 停止轮询协程并等待其退出（幂等）。
func (w *Watcher) Stop() {
	if w.cancel == nil {
		return
	}
	w.stopOnce.Do(func() {
		w.cancel()
		<-w.done
	})
}

// poll 执行一轮指纹比对。
func (w *Watcher) poll(onChange func()) {
	fingerprint, err := Fingerprint(w.cfg.Dirs, w.cfg.Include, w.cfg.DataInclude)
	if err != nil {
		// 目录暂时不可访问（例如正在被原子替换）不视为错误：
		// 下一轮轮询会重新计算，避免因一次瞬时状态就刷屏告警。
		w.logf("WARN", "规则目录指纹计算失败，跳过本轮检查", "error", err.Error())
		return
	}

	stamp := markerStampOf(w.cfg.MarkerFile)
	changed := fingerprint != w.fingerprint || (!stamp.IsZero() && !stamp.Equal(w.markerStamp))

	if !changed {
		return
	}

	// 去抖动：等待一个去抖动周期后重新计算，指纹仍变化才真正触发，
	// 避免「文件正在被写入」的中间状态触发一次注定失败的重载。
	if w.cfg.Debounce > 0 {
		time.Sleep(w.cfg.Debounce)
		confirmed, err := Fingerprint(w.cfg.Dirs, w.cfg.Include, w.cfg.DataInclude)
		if err != nil {
			w.logf("WARN", "规则目录指纹复核失败，跳过本轮检查", "error", err.Error())
			return
		}
		fingerprint = confirmed
		stamp = markerStampOf(w.cfg.MarkerFile)
	}

	w.fingerprint = fingerprint
	w.markerStamp = stamp

	w.logf("INFO", "检测到规则文件变化，开始重载", "fingerprint", shortHash(fingerprint))
	onChange()
}

// logf 写系统日志；logger 为 nil 时静默。
func (w *Watcher) logf(level string, message string, args ...any) {
	if w.logger == nil {
		return
	}
	switch level {
	case "WARN":
		w.logger.Warn(message, args...)
	case "ERROR":
		w.logger.Error(message, args...)
	default:
		w.logger.Info(message, args...)
	}
}

// markerStampOf 读取标记文件的修改时间；文件不存在时返回零值。
func markerStampOf(path string) time.Time {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return time.Time{}
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// Fingerprint 计算一组规则目录的内容指纹。
//
// 指纹构成：对每个匹配文件取「相对路径 + 大小 + 修改时间（纳秒）」，
// 按路径排序后拼接并做 SHA-256。
//
// 为什么包含修改时间而不只包含大小：只比大小的话，「等长内容替换」这类变更
// 会被漏掉（例如把一条规则的阈值从 5 改成 8），而修改时间能捕捉到它。
// 为什么不直接哈希文件内容：那需要把全部规则读进内存（违反 R13 的不大体积读取约束），
// 而规则集在规模上是「几十个文件、几百 KB」级别，指纹机制已经足够可靠。
func Fingerprint(dirs []string, include []string, dataInclude []string) (string, error) {
	patterns := append(append([]string{}, include...), dataInclude...)
	if len(patterns) == 0 {
		patterns = append(append([]string{}, defaultIncludePatterns...), defaultDataPatterns...)
	}

	var entries []string
	for _, dir := range dirs {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		for _, pattern := range patterns {
			matches, err := filepath.Glob(filepath.Join(trimmed, pattern))
			if err != nil {
				return "", fmt.Errorf("规则目录 %s 的模式 %q 非法：%w", trimmed, pattern, err)
			}
			for _, match := range matches {
				info, err := os.Stat(match)
				if err != nil || info.IsDir() {
					continue
				}
				entries = append(entries, fmt.Sprintf("%s|%d|%d",
					filepath.ToSlash(match), info.Size(), info.ModTime().UnixNano()))
			}
		}
	}

	if len(entries) == 0 {
		// 没有任何规则文件也是有效状态（例如规则目录暂时为空），
		// 用固定串表示，保证「从空变成非空」也能被检测到。
		return hashOf("<empty>"), nil
	}

	sort.Strings(entries)
	return hashOf(strings.Join(entries, "\n")), nil
}

// hashOf 计算字符串的 SHA-256 十六进制摘要。
func hashOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// shortHash 截取摘要前 12 位，仅用于日志展示。
func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

// DirFiles 列出目录中匹配模式的文件（相对路径），按字典序排序。
//
// 供 `waf rules list` 展示「运行态会加载哪些文件」，
// 与加载逻辑共用同一套模式归一化规则，避免 CLI 与运行态口径不一致。
func DirFiles(dir string, include []string, dataInclude []string) ([]string, error) {
	fsys := os.DirFS(dir)
	patterns := append(append([]string{}, normaliseInclude(include)...),
		normalisePatterns(dataInclude, defaultDataPatterns)...)
	names, err := globRuleFiles(fsys, patterns)
	if err != nil {
		return nil, err
	}
	return names, nil
}
