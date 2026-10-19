package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// AuditWriter 异步把请求审计记录批量写入 SQLite。
//
// 性能边界：审计是旁路数据，队列满时直接丢弃并计数，绝不让磁盘写阻塞请求处理。
type AuditWriter struct {
	db       *DB
	cfg      config.DatabaseAuditConfig
	logger   *slog.Logger
	queue    chan core.AuditEntry
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	dropOnce sync.Once
}

// NewAuditWriter 构造并启动审计写入协程；mode=off 时返回 nil。
func NewAuditWriter(database *DB, cfg config.DatabaseAuditConfig, logger *slog.Logger) (*AuditWriter, error) {
	if database == nil {
		return nil, fmt.Errorf("审计写入器必须注入数据库")
	}
	if cfg.Mode == config.DatabaseAuditModeOff {
		return nil, nil
	}
	if cfg.Mode != config.DatabaseAuditModeEvents && cfg.Mode != config.DatabaseAuditModeAll {
		return nil, fmt.Errorf("database.audit.mode = %q 非法", cfg.Mode)
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval.Duration() <= 0 {
		cfg.FlushInterval = core.Duration(time.Second)
	}
	writer := &AuditWriter{
		db:     database,
		cfg:    cfg,
		logger: logger,
		queue:  make(chan core.AuditEntry, cfg.QueueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go writer.run()
	return writer, nil
}

// Record 投递一条审计记录；队列满时丢弃，保证请求路径不被阻塞。
func (w *AuditWriter) Record(entry core.AuditEntry) {
	if w == nil || !w.enabled(entry) {
		return
	}
	select {
	case <-w.stop:
		return
	default:
	}
	select {
	case w.queue <- entry:
	default:
		w.dropOnce.Do(func() {
			if w.logger != nil {
				w.logger.Warn("审计队列已满，后续记录将被丢弃", "queue_size", w.cfg.QueueSize)
			}
		})
	}
}

// Close 停止接收记录、排空队列并等待最后一批写入完成；必须幂等。
func (w *AuditWriter) Close() error {
	if w == nil {
		return nil
	}
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
	return nil
}

// enabled 判断当前审计模式是否记录该条目。
func (w *AuditWriter) enabled(entry core.AuditEntry) bool {
	switch w.cfg.Mode {
	case config.DatabaseAuditModeAll:
		return true
	case config.DatabaseAuditModeEvents:
		// allow 不是事件；observe / block / honeypot / error 以及 would_block 都要保留。
		return entry.Verdict != core.VerdictAllow.String() || entry.WouldBlock || entry.Error != ""
	default:
		return false
	}
}

// run 是唯一的后台写入协程。
func (w *AuditWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.FlushInterval.Duration())
	defer ticker.Stop()
	pruneTicker := time.NewTicker(time.Hour)
	defer pruneTicker.Stop()

	batch := make([]core.AuditEntry, 0, w.cfg.BatchSize)
	w.prune()
	for {
		select {
		case entry := <-w.queue:
			batch = append(batch, entry)
			if len(batch) >= w.cfg.BatchSize {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-pruneTicker.C:
			w.prune()
		case <-w.stop:
			for {
				select {
				case entry := <-w.queue:
					batch = append(batch, entry)
				default:
					if len(batch) > 0 {
						w.flush(batch)
					}
					return
				}
			}
		}
	}
}

// flush 在单个事务中写入一批记录。
func (w *AuditWriter) flush(entries []core.AuditEntry) {
	if len(entries) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := w.db.sql.BeginTx(ctx, nil)
	if err != nil {
		w.logError("开启审计写入事务失败", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	for _, entry := range entries {
		if err := insertAuditEntry(ctx, tx, entry); err != nil {
			w.logError("写入审计记录失败", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		w.logError("提交审计事务失败", err)
	}
}

// insertAuditEntry 写入单条审计记录。
func insertAuditEntry(ctx context.Context, tx *sql.Tx, entry core.AuditEntry) error {
	receivedAt := entry.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	findings := entry.Findings
	if findings == nil {
		findings = []core.Finding{}
	}
	rawFindings, err := json.Marshal(findings)
	if err != nil {
		rawFindings = []byte("[]")
	}
	ruleID, check := entry.RuleID, entry.Check
	target, banScope := entry.Target, entry.BanScope
	if len(findings) > 0 {
		if ruleID == "" {
			ruleID = findings[0].RuleID
		}
		if check == "" {
			check = findings[0].Check
		}
		if target == "" {
			target = core.FindingTarget(findings[0])
		}
		if banScope == "" {
			banScope = findings[0].Data["ban_scope"]
		}
	}
	wouldBlock := 0
	if entry.WouldBlock {
		wouldBlock = 1
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_requests(request_id, received_at, site, client_ip, method, host, path,
		                           uri, query_text, target, ban_scope, params_json,
		                           verdict, action, http_status, code, rule_id, check_name, score,
		                           duration_ms, would_block, error_text, findings_json)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(request_id) DO UPDATE SET
		     received_at = excluded.received_at,
		     site = excluded.site,
		     client_ip = excluded.client_ip,
		     method = excluded.method,
		     host = excluded.host,
		     path = excluded.path,
		     uri = excluded.uri,
		     query_text = excluded.query_text,
		     target = excluded.target,
		     ban_scope = excluded.ban_scope,
		     params_json = excluded.params_json,
		     verdict = excluded.verdict,
		     action = excluded.action,
		     http_status = excluded.http_status,
		     code = excluded.code,
		     rule_id = excluded.rule_id,
		     check_name = excluded.check_name,
		     score = excluded.score,
		     duration_ms = excluded.duration_ms,
		     would_block = excluded.would_block,
		     error_text = excluded.error_text,
		     findings_json = excluded.findings_json`,
		entry.RequestID, receivedAt.UnixMilli(), entry.Site, entry.ClientIP, entry.Method,
		entry.Host, entry.Path, entry.URI, entry.Query, target, banScope, entry.Params,
		entry.Verdict, entry.Action, entry.HTTPStatus, entry.Code,
		ruleID, check, entry.Score, entry.Duration.Milliseconds(), wouldBlock,
		entry.Error, string(rawFindings))
	if err != nil {
		return fmt.Errorf("写入审计记录失败：%w", err)
	}
	return nil
}

// prune 按保留时长清理历史审计记录。
func (w *AuditWriter) prune() {
	retention := w.cfg.Retention.Duration()
	if retention <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cutoff := w.db.Now().Add(-retention).UnixMilli()
	if _, err := w.db.sql.ExecContext(ctx,
		`DELETE FROM audit_requests WHERE received_at < ?`, cutoff); err != nil {
		w.logError("清理过期审计记录失败", err)
	}
}

// logError 统一记录审计协程错误；审计失败不影响主请求链路。
func (w *AuditWriter) logError(message string, err error) {
	if w.logger != nil {
		w.logger.Warn(message, "error", err.Error())
	}
}
