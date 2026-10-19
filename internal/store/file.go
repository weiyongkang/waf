package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// fileRecordMaxBytes 是单条持久化记录的行长度上限（字节）。
//
// 之所以需要上限：持久化文件属于「外部输入」，被人工编辑或损坏时不能无限读入内存
// （需求 R13）。超过该长度的行会被跳过并告警，而不是让进程 OOM。
const fileRecordMaxBytes = 64 * 1024

// defaultBanFileBytes 是封禁持久化文件的默认大小上限（配置文件可覆盖）。
//
// 超过该上限会触发一次「压缩重写」（只保留仍然有效的封禁记录），
// 从而让文件大小与「实际封禁数量」成正比，而不是与「历史操作次数」成正比。
const defaultBanFileBytes = 8 * 1024 * 1024

// banRecord 是一条持久化的封禁变更记录（JSON Lines 格式）。
//
// 之所以采用「追加写 + 压缩重写」而不是「每次全量重写」：
// 封禁是写多读少的高频动作，追加写是 O(1) 且不阻塞其它操作；
// 而全量重写会让每次封禁都产生一次全文件 IO，在名单较大时不可接受。
type banRecord struct {
	// Op 是操作类型：ban（加入） | unban（移除）。
	Op string `json:"op"`
	// Key 是逻辑键（不含前缀）。
	Key string `json:"key"`
	// Reason 是封禁原因，仅 op=ban 时有效。
	Reason string `json:"reason,omitempty"`
	// BannedAt 是首次封禁时间；省略表示旧版本记录未提供。
	BannedAt *time.Time `json:"banned_at,omitempty"`
	// ExpireAt 是封禁到期时间；省略表示永不过期。
	ExpireAt *time.Time `json:"expire_at,omitempty"`
}

// 操作类型常量。
const (
	fileOpBan   = "ban"
	fileOpUnban = "unban"
)

// FileStore 是「单机持久化」存储实现。
//
// 组成：
//   - 限速计数：仅存内存（计数是短周期状态，跨重启恢复没有意义，且会放大误限速）；
//   - 封禁名单：内存 + JSON Lines 文件持久化（进程重启后封禁依然生效）。
//
// 明确不适用：多实例共享。file 后端只解决「单机重启不丢封禁」，
// 多实例共享必须使用 redis 后端（需求 R23）。
type FileStore struct {
	// MemoryStore 提供计数与名单的内存实现，本类型在其之上增加持久化。
	*MemoryStore
	// path 是持久化文件路径。
	path string
	// maxFileBytes 是触发压缩重写的文件大小上限。
	maxFileBytes int64

	// mu 串行化文件追加与压缩重写，避免并发写导致记录交错。
	mu sync.Mutex
	// file 是当前打开的追加写句柄。
	file *os.File
	// fileBytes 是当前文件的近似大小（字节）。
	fileBytes int64
	// closed 标记是否已关闭。
	closed bool
}

// FileStoreOptions 是文件存储的构造参数。
type FileStoreOptions struct {
	// Name 是存储实例名。
	Name string
	// Prefix 是键前缀。
	Prefix string
	// Path 是持久化文件路径；必填。
	Path string
	// MaxFileBytes 是文件大小上限；<=0 时取默认值。
	MaxFileBytes int64
	// MaxEntries 是内存条目上限；<=0 时取默认值。
	MaxEntries int
	// CleanupInterval 是过期项清理周期；<=0 时取默认值。
	CleanupInterval time.Duration
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
	// Logger 是系统日志器；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；可为 nil。
	Metrics core.MetricsRecorder
}

// NewFileStore 构造文件存储：先回放已有记录重建内存名单，再打开追加写句柄。
func NewFileStore(opts FileStoreOptions) (*FileStore, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("file 存储必须配置 settings.path（封禁持久化文件路径）")
	}
	maxFileBytes := opts.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = defaultBanFileBytes
	}

	memoryStore, err := NewMemoryStore(MemoryOptions{
		Name:            opts.Name,
		Prefix:          opts.Prefix,
		MaxEntries:      opts.MaxEntries,
		CleanupInterval: opts.CleanupInterval,
		Clock:           opts.Clock,
		Logger:          opts.Logger,
		Metrics:         opts.Metrics,
	})
	if err != nil {
		return nil, err
	}

	fileStore := &FileStore{
		MemoryStore:  memoryStore,
		path:         opts.Path,
		maxFileBytes: maxFileBytes,
	}

	if err := fileStore.replay(); err != nil {
		_ = memoryStore.Close()
		return nil, err
	}
	if err := fileStore.openForAppend(); err != nil {
		_ = memoryStore.Close()
		return nil, err
	}
	return fileStore, nil
}

// Ban 追加一条封禁记录并写入内存名单，已存在时强制覆盖（core.Store 实现）。
func (s *FileStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	now := s.clock.Now()
	expireAt := expiryFrom(now, ttl)
	if _, err := s.MemoryStore.putBan(key, reason, now, expireAt, false); err != nil {
		return err
	}
	return s.appendBanRecord(key, reason, now, expireAt)
}

// BanIfAbsent 仅在 key 不存在或已过期时写入封禁记录（core.Store 实现）。
//
// 只有实际创建封禁时才追加持久化记录，避免重复命中把文件撑大。
func (s *FileStore) BanIfAbsent(ctx context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	now := s.clock.Now()
	expireAt := expiryFrom(now, ttl)
	created, err := s.MemoryStore.putBan(key, reason, now, expireAt, true)
	if err != nil || !created {
		return created, err
	}
	if err := s.appendBanRecord(key, reason, now, expireAt); err != nil {
		return false, err
	}
	return true, nil
}

// appendBanRecord 持久化一条封禁记录。
func (s *FileStore) appendBanRecord(key, reason string, bannedAt, expireAt time.Time) error {
	record := banRecord{Op: fileOpBan, Key: key, Reason: reason}
	if !bannedAt.IsZero() {
		value := bannedAt
		record.BannedAt = &value
	}
	if !expireAt.IsZero() {
		value := expireAt
		record.ExpireAt = &value
	}
	return s.append(record)
}

// Unban 追加一条解除记录并从内存名单移除（core.Store 实现）。
func (s *FileStore) Unban(ctx context.Context, key string) error {
	if err := s.MemoryStore.Unban(ctx, key); err != nil {
		return err
	}
	return s.append(banRecord{Op: fileOpUnban, Key: key})
}

// Close 压缩重写持久化文件并关闭句柄；必须幂等。
func (s *FileStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	compactErr := s.compactLocked()
	if s.file != nil {
		if err := s.file.Close(); err != nil && compactErr == nil {
			compactErr = err
		}
		s.file = nil
	}
	s.mu.Unlock()

	// 先关文件再关内存存储，保证「压缩失败」不会阻断内存资源释放。
	if err := s.MemoryStore.Close(); err != nil && compactErr == nil {
		compactErr = err
	}
	return compactErr
}

// append 追加一条记录，必要时触发压缩重写。
func (s *FileStore) append(record banRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("封禁记录序列化失败：%w", err)
	}
	payload = append(payload, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}
	if s.file == nil {
		return ErrStoreClosed
	}
	if _, err := s.file.Write(payload); err != nil {
		s.metrics.IncStoreError(s.name)
		return fmt.Errorf("写入封禁持久化文件失败：%w", err)
	}
	s.fileBytes += int64(len(payload))

	if s.maxFileBytes > 0 && s.fileBytes >= s.maxFileBytes {
		if err := s.compactLocked(); err != nil {
			// 压缩失败不影响本次封禁（记录已落盘），仅告警。
			if s.logger != nil {
				s.logger.Warn("封禁文件压缩失败，将在下次写入时重试", "store", s.name, "error", err.Error())
			}
		}
	}
	return nil
}

// replay 回放持久化文件，重建内存中的封禁名单。
func (s *FileStore) replay() error {
	file, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			// 首次运行：文件尚不存在，属于正常情况。
			return nil
		}
		return fmt.Errorf("打开封禁持久化文件失败：%w", err)
	}
	defer func() { _ = file.Close() }()

	now := s.clock.Now()
	replayed, skipped := 0, 0

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), fileRecordMaxBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record banRecord
		if err := json.Unmarshal(line, &record); err != nil {
			// 单条损坏不应导致整体不可用：跳过并计数，由启动日志暴露。
			skipped++
			continue
		}

		switch record.Op {
		case fileOpBan:
			if record.ExpireAt != nil && !record.ExpireAt.After(now) {
				// 已过期的历史记录直接忽略，不进入内存。
				continue
			}
			bannedAt := now
			if record.BannedAt != nil {
				bannedAt = *record.BannedAt
			}
			expireAt := time.Time{}
			if record.ExpireAt != nil {
				expireAt = *record.ExpireAt
			}
			// 回放使用记录中的绝对时间，保证重启后到期时间与首次封禁时间不变。
			if _, err := s.MemoryStore.putBan(record.Key, record.Reason, bannedAt, expireAt, false); err != nil {
				skipped++
				continue
			}
			replayed++
		case fileOpUnban:
			if err := s.MemoryStore.Unban(context.Background(), record.Key); err != nil {
				skipped++
				continue
			}
		default:
			skipped++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取封禁持久化文件失败：%w", err)
	}

	if s.logger != nil {
		s.logger.Info("回放封禁持久化文件完成",
			"store", s.name, "path", s.path, "bans", replayed, "skipped", skipped)
	}
	return nil
}

// openForAppend 打开追加写句柄。
func (s *FileStore) openForAppend() error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("创建封禁持久化目录失败：%w", err)
		}
	}

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开封禁持久化文件失败：%w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("读取封禁持久化文件状态失败：%w", err)
	}

	s.file = file
	s.fileBytes = info.Size()
	return nil
}

// compactLocked 以「写临时文件 + 原子改名」的方式重写持久化文件。
//
// 调用方必须已持有 s.mu。
func (s *FileStore) compactLocked() error {
	if s.path == "" {
		return nil
	}

	live := s.snapshotBans(s.clock.Now())

	tempPath := s.path + ".compact"
	tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建压缩临时文件失败：%w", err)
	}

	writer := bufio.NewWriter(tempFile)
	for key, item := range live {
		record := banRecord{Op: fileOpBan, Key: key, Reason: item.reason}
		if !item.bannedAt.IsZero() {
			bannedAt := item.bannedAt
			record.BannedAt = &bannedAt
		}
		if !item.expireAt.IsZero() {
			expireAt := item.expireAt
			record.ExpireAt = &expireAt
		}
		payload, err := json.Marshal(record)
		if err != nil {
			_ = tempFile.Close()
			return fmt.Errorf("封禁记录序列化失败：%w", err)
		}
		if _, err := writer.Write(append(payload, '\n')); err != nil {
			_ = tempFile.Close()
			return fmt.Errorf("写入压缩临时文件失败：%w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("刷新压缩临时文件失败：%w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("关闭压缩临时文件失败：%w", err)
	}

	// Windows 下无法对已打开的文件执行改名，因此必须先关闭追加写句柄。
	wasOpen := s.file != nil
	if wasOpen {
		if err := s.file.Close(); err != nil {
			s.file = nil
			return fmt.Errorf("压缩前关闭持久化文件失败：%w", err)
		}
		s.file = nil
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		// 改名失败时尽量恢复追加写句柄，避免后续封禁全部失败。
		if wasOpen {
			_ = s.openForAppend()
		}
		return fmt.Errorf("替换封禁持久化文件失败：%w", err)
	}
	if wasOpen {
		if err := s.openForAppend(); err != nil {
			return err
		}
	}

	if s.logger != nil {
		s.logger.Debug("封禁持久化文件已压缩重写",
			"store", s.name, "path", s.path, "bans", len(live), "bytes", s.fileBytes)
	}
	return nil
}
