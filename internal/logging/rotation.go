package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// rotationWriter 是「按天 / 按大小」轮转的日志文件写入器。
//
// 实现约束（需求 R13：不做大体积读取）：
//   - 始终只持有单个文件句柄，写入采用追加模式，不读取历史文件内容；
//   - 体积统计只累加本次进程写入的字节数，启动时不扫描文件已有大小；
//   - 保留策略清理按文件名排序后删除最旧的文件，同样不读取内容。
//
// 之所以自研而不引入第三方轮转库：离线交付环境下依赖越少越好，
// 且本项目需要的策略（daily / size / both）逻辑简单、易于审计。
type rotationWriter struct {
	mu sync.Mutex

	// dir 是日志目录。
	dir string
	// prefix 是文件名前缀，最终形如 <prefix>-2026-10-15.log。
	prefix string
	// rotate 是轮转策略：daily / size / both。
	rotate string
	// maxFileBytes 是单文件大小上限（rotate 含 size 时生效）。
	maxFileBytes int64
	// keepDays 是保留天数，<= 0 表示不做清理。
	keepDays int
	// maxTotalBytes 是日志总量上限，<= 0 表示不限制。
	maxTotalBytes int64
	// compress 预留：是否压缩历史文件（当前版本未实现压缩，仅为配置兼容保留）。
	compress bool

	// file 是当前打开的文件句柄。
	file *os.File
	// currentDate 是当前文件对应的日期（用于按天轮转判断）。
	currentDate string
	// currentIndex 是同日内的分片序号（用于按大小轮转）。
	currentIndex int
	// writtenBytes 是当前文件已写入的字节数。
	writtenBytes int64
}

// newRotationWriter 创建轮转写入器。
func newRotationWriter(dir, prefix, rotate string, maxFileBytes int64, keepDays int, maxTotalBytes int64, compress bool) (*rotationWriter, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("日志目录不能为空")
	}
	if strings.TrimSpace(prefix) == "" {
		return nil, fmt.Errorf("日志文件名前缀不能为空")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建日志目录 %s 失败：%w", dir, err)
	}
	return &rotationWriter{
		dir:           dir,
		prefix:        prefix,
		rotate:        rotate,
		maxFileBytes:  maxFileBytes,
		keepDays:      keepDays,
		maxTotalBytes: maxTotalBytes,
		compress:      compress,
		currentDate:   time.Now().Format("2006-01-02"),
	}, nil
}

// Write 写入日志内容，必要时先完成轮转。
func (w *rotationWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureFile(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.file.Write(p)
	w.writtenBytes += int64(n)
	return n, err
}

// Close 关闭当前文件句柄。
func (w *rotationWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// ensureFile 确保存在可写的目标文件；需要时执行轮转。
func (w *rotationWriter) ensureFile(incomingBytes int64) error {
	today := time.Now().Format("2006-01-02")

	needRotate := false
	dateChanged := today != w.currentDate
	// 按天轮转：日期变化时切换到新文件。
	if (w.rotate == "daily" || w.rotate == "both") && dateChanged {
		needRotate = true
	}
	// 按大小轮转：当前文件写满时切换到新分片。
	if w.rotate == "size" || w.rotate == "both" {
		if w.maxFileBytes > 0 && w.file != nil && w.writtenBytes+incomingBytes > w.maxFileBytes {
			needRotate = true
		}
		// 纯 size 策略下日期变化不触发轮转，但仍需更新日期标记以免后续判断混乱。
		if dateChanged && w.rotate == "size" {
			w.currentDate = today
		}
	}

	if w.file != nil && needRotate {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("关闭旧日志文件失败：%w", err)
		}
		w.file = nil
	}

	if w.file == nil {
		if dateChanged {
			// 日期变化时重置分片序号与体积统计。
			w.currentDate = today
			w.currentIndex = 0
			w.writtenBytes = 0
		} else if needRotate {
			w.currentIndex++
			w.writtenBytes = 0
		}

		path := w.filePath()
		// 进程重启后追加写入既有文件，因此这里需要修正体积统计基线，
		// 否则 size 策略会在重启后立即触发一次无意义轮转。
		if info, err := os.Stat(path); err == nil {
			w.writtenBytes = info.Size()
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return fmt.Errorf("打开日志文件 %s 失败：%w", path, err)
		}
		w.file = file
	}

	w.cleanupIfNeeded()
	return nil
}

// filePath 返回当前应写入的文件路径。
//
// 命名规则：<prefix>-<YYYY-MM-DD>.log；同日分片追加 .<序号> 后缀。
func (w *rotationWriter) filePath() string {
	name := fmt.Sprintf("%s-%s", w.prefix, w.currentDate)
	if w.currentIndex > 0 {
		name = fmt.Sprintf("%s.%d", name, w.currentIndex)
	}
	return filepath.Join(w.dir, name+".log")
}

// cleanupIfNeeded 按保留天数与总量上限清理历史日志。
//
// 清理是「尽力而为」：失败只影响磁盘占用，不影响日志写入，因此不向上返回错误。
func (w *rotationWriter) cleanupIfNeeded() {
	if w.keepDays <= 0 && w.maxTotalBytes <= 0 {
		return
	}

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	type logFile struct {
		path    string
		modTime time.Time
		size    int64
	}
	var files []logFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), w.prefix) || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, logFile{
			path:    filepath.Join(w.dir, entry.Name()),
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}

	// 按修改时间升序（最旧的在前），便于依次删除。
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })

	var remaining []logFile
	if w.keepDays > 0 {
		threshold := time.Now().AddDate(0, 0, -w.keepDays)
		for _, file := range files {
			if file.modTime.Before(threshold) {
				_ = os.Remove(file.path)
				continue
			}
			remaining = append(remaining, file)
		}
	} else {
		remaining = files
	}

	if w.maxTotalBytes <= 0 {
		return
	}

	var total int64
	for _, file := range remaining {
		total += file.size
	}
	for _, file := range remaining {
		if total <= w.maxTotalBytes {
			break
		}
		_ = os.Remove(file.path)
		total -= file.size
	}
}
