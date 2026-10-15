// Package body 实现「按需读取 + 流式缓冲 + 限额截断」的请求体缓冲器（需求 R4 / R13）。
//
// 为什么需要独立的请求体缓冲层：
//
//  1. forward-auth 形态下，请求体随鉴权子请求一次性送达，底层流只能被消费一次；
//  2. 串联链中可能存在多个 PhaseBody 校验单元（例如「编码还原检查」与「引擎体检测」），
//     每个单元都需要从头读取同一份请求体，因此必须先把请求体缓冲到「可重复读取」的载体；
//  3. 需求 R13 明确禁止「大体积读取」，因此读取必须分块进行，并受 max_bytes 与
//     on_exceed 策略约束，超出内存阈值时自动落盘，避免大请求体长期占用堆内存。
//
// 本包只做缓冲，不做任何安全判定：是否读体由 pipeline 依据「是否存在启用的 PhaseBody
// 校验单元」决定，因此「不需要体检测」的场景下本包完全不参与，零开销。
package body

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// ErrBodyTooLarge 表示请求体超过 ingress.body.max_bytes，且超限策略为 reject。
//
// pipeline 依据该哨兵错误返回 400（VerdictBadRequest）。之所以用哨兵错误而不是自定义
// 错误类型：调用方只需要区分「超限拒绝」与「其它读取失败」两种情况。
var ErrBodyTooLarge = errors.New("请求体超过允许的大小上限")

// metricsLabel 是本包写入指标时使用的固定标签值。
//
// 之所以固定为 "ingress.body"：请求体缓冲属于接入层能力而非某个校验单元，
// 用固定标签可以把它与「各校验单元自身的耗时 / 错误」清晰区分开。
const metricsLabel = "ingress.body"

// Options 是请求体缓冲器的可选依赖。
type Options struct {
	// Logger 是系统日志器，用于告警「要求携带请求体但未收到」等异常；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；为 nil 时使用空实现。
	Metrics core.MetricsRecorder
}

// Source 描述待缓冲的请求体来源。
//
// 之所以把三个字段打包成结构体：调用方（pipeline）从原始请求里一次性取出这些信息，
// 打包传递可以避免「参数顺序写错」这类低级错误。
type Source struct {
	// Reader 是原始请求体流；为 nil 表示本次请求未携带请求体。
	Reader io.Reader
	// Declared 是**原始请求**声明的内容长度（Content-Length）。
	//
	// 取值语义（与 core.RawRequest.ContentLength 一致）：
	//   - 0  ：客户端明确声明「本次请求没有请求体」，属于正常空体；
	//   - >0 ：客户端声明了具体长度；
	//   - -1 ：未知（chunked 编码，或接入通道不转发 Content-Length）。
	Declared int64
	// ContentType 是请求体的内容类型（Content-Type），仅用于日志与元信息展示。
	ContentType string
	// Method 是**原始请求**的 HTTP 方法（如 GET / POST）。
	//
	// 之所以必须显式传入：方法决定了「本次请求本应携带请求体吗」——
	// GET / HEAD / OPTIONS / DELETE 没有请求体是正常现象，
	// 只有 POST / PUT / PATCH 等才应计入「请求体缺失」。
	Method string
}

// Spool 是请求体缓冲器，实现 core.BodyStream 接口。
//
// 缓冲位置策略（ingress.body.spool）：
//   - memory：全部缓存在内存；
//   - disk  ：一律落盘到临时文件；
//   - auto  ：先缓存在内存，累计字节数超过 memory_threshold 后整体迁移到临时文件。
//
// 生命周期：由 pipeline 在需要体检测时创建，Fill 只被调用一次；
// 之后 Read / Rewind / Meta 可能被串联链中的多个校验单元先后调用，
// 最终由 HTTP 处理层统一 Close（删除落盘的临时文件）。
type Spool struct {
	// cfg 是生效的请求体配置（构造时已做归一化）。
	cfg config.BodyConfig
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder

	// mu 保护全部可变状态：校验单元可能被并发调用（例如 PhasePost 的异步动作）。
	mu sync.Mutex
	// closed 表示 Close 已执行，用于保证幂等。
	closed bool

	// memory 是内存缓冲；与 file 互斥（二者最多只有一个非 nil）。
	memory *bytes.Buffer
	// file 是落盘的临时文件；与 memory 互斥。
	file *os.File
	// path 是临时文件路径，Close 时用于删除。
	path string
	// dataBytes 是已缓冲的有效字节数（截断后即为上限值）。
	dataBytes int64
	// reader 是当前读取游标：内存模式指向 bytes.Reader，落盘模式指向临时文件。
	reader io.Reader

	// present 表示本次请求实际携带了请求体（以实际读到的字节数为准）。
	present bool
	// missing 表示配置要求携带请求体（mode = required）但实际未收到。
	missing bool
	// truncated 表示请求体因超过 max_bytes 被截断（仅部分内容参与检测）。
	truncated bool
	// skipDetection 表示因超限策略为 skip 而整体放弃体检测。
	skipDetection bool
	// spilled 表示请求体已落盘到临时文件。
	spilled bool
	// declared 是原始请求声明的内容长度（-1 表示未知，0 表示明确声明空体）。
	declared int64
	// contentType 是请求体的内容类型，仅用于元信息展示。
	contentType string
	// method 是原始请求方法（大写），用于判断「本应携带请求体但缺失」。
	method string
}

// New 构造请求体缓冲器。
//
// 构造阶段完成参数归一化与合法性检查（fail fast）：
// spool / on_exceed 取值非法、max_bytes 非正数、chunk_bytes 非正数都会在此报错，
// 避免运行期出现「限额静默失效」这类危险行为。
func New(cfg config.BodyConfig, opts Options) (*Spool, error) {
	switch cfg.Spool {
	case config.SpoolMemory, config.SpoolDisk, config.SpoolAuto:
	default:
		return nil, fmt.Errorf("ingress.body.spool = %q 非法，可选值：memory / disk / auto", cfg.Spool)
	}

	switch cfg.OnExceed {
	case config.BodyOnExceedTruncate, config.BodyOnExceedReject, config.BodyOnExceedSkip:
	default:
		return nil, fmt.Errorf("ingress.body.on_exceed = %q 非法，可选值：truncate / reject / skip", cfg.OnExceed)
	}

	if cfg.MaxBytes <= 0 {
		return nil, fmt.Errorf("ingress.body.max_bytes = %d 非法，必须大于 0（0 会让限额静默失效）", cfg.MaxBytes)
	}
	if cfg.ChunkBytes <= 0 {
		return nil, fmt.Errorf("ingress.body.chunk_bytes = %d 非法，必须大于 0", cfg.ChunkBytes)
	}
	if cfg.Spool == config.SpoolAuto && cfg.MemoryThreshold <= 0 {
		return nil, fmt.Errorf("ingress.body.spool = \"auto\" 时 memory_threshold 必须大于 0，当前 %d", cfg.MemoryThreshold)
	}

	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}

	return &Spool{cfg: cfg, logger: opts.Logger, metrics: metrics}, nil
}

// Fill 从请求体流中分块读取并缓冲请求体。
//
// 返回值语义：
//   - nil：缓冲完成；是否被截断 / 是否跳过检测通过 Meta 观察；
//   - ErrBodyTooLarge：超限且策略为 reject，调用方应返回 400；
//   - 其它错误：读取底部流失败（例如客户端中断连接）。
//
// 该方法只应被调用一次；重复调用会导致重复写入缓冲。
func (s *Spool) Fill(src Source) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("请求体缓冲已关闭，不能再写入")
	}

	s.declared = src.Declared
	s.contentType = src.ContentType
	// 归一化方法名：仅在「预期携带请求体」的方法上才把无体视为缺失，
	// 因此这里统一转大写，避免大小写差异导致判定失效。
	s.method = strings.ToUpper(strings.TrimSpace(src.Method))

	// 1) 依据配置判定是否读体：mode = disabled 或 source != request-body 时一律不读。
	if s.cfg.Mode == config.BodyModeDisabled || s.cfg.Source != "request-body" {
		return nil
	}

	// 2) 未携带请求体：mode = required 时记录 Missing（验收项 A16）。
	if src.Reader == nil {
		s.markMissingIfRequired()
		s.prepareReader()
		return nil
	}

	// 3) 分块读取：每块大小由 chunk_bytes 决定，禁止一次性读入整个请求体（需求 R13）。
	buf := make([]byte, s.chunkSize())
	for {
		n, err := src.Reader.Read(buf)
		if n > 0 {
			if consumeErr := s.consume(buf[:n]); consumeErr != nil {
				s.releaseBuffers()
				return consumeErr
			}
			// 超限已按策略处理完毕：不再继续读取剩余字节。
			// 之所以直接停止读取而不是排空：剩余内容不会参与检测，排空只会浪费带宽。
			if s.truncated || s.skipDetection {
				break
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.releaseBuffers()
			return fmt.Errorf("读取请求体失败：%w", err)
		}
	}

	// 4) 收尾：判定是否存在请求体、记录 Missing 与字节数指标。
	if s.dataBytes == 0 && !s.skipDetection {
		s.markMissingIfRequired()
	}
	s.present = s.dataBytes > 0
	if s.present {
		s.metrics.AddBodyBytes(metricsLabel, s.dataBytes)
	}
	if err := s.prepareReader(); err != nil {
		return err
	}
	return nil
}

// Read 实现 io.Reader：从当前游标位置顺序读取缓冲内容。
func (s *Spool) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.reader == nil {
		// 无请求体 / 已跳过检测 / 已关闭：统一按「读到结尾」处理，
		// 使调用方无需区分「空缓冲」与「已消费完」两种情况。
		return 0, io.EOF
	}
	return s.reader.Read(p)
}

// Rewind 把读取游标重置到起点，供下一个 PhaseBody 校验单元从头读取同一份请求体。
//
// 之所以零拷贝：缓冲内容要么在内存（bytes.Reader）要么在临时文件（*os.File），
// 重置读取位置只是改变游标，不涉及数据搬运。
func (s *Spool) Rewind() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("请求体缓冲已关闭，不能重置读取位置")
	}
	return s.prepareReader()
}

// Meta 返回请求体元信息。
//
// 设计意义（需求 R13）：多数校验单元只需要元信息（是否存在、多大、是否被截断），
// 不需要体内容本身；提供该视图可以让「轻量判断」与「内容检测」彻底解耦。
func (s *Spool) Meta() core.BodyMeta {
	s.mu.Lock()
	defer s.mu.Unlock()

	return core.BodyMeta{
		Present:     s.present,
		Bytes:       s.dataBytes,
		Declared:    s.declared,
		Truncated:   s.truncated,
		Skipped:     s.skipDetection,
		Missing:     s.missing,
		Spooled:     s.spilled,
		ContentType: s.contentType,
		Source:      s.cfg.Source,
	}
}

// Close 释放底层资源：关闭并删除落盘的临时文件。
//
// 必须幂等：HTTP 处理层与 pipeline 都可能触发关闭，重复关闭不得报错。
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	s.reader = nil

	var firstErr error
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			firstErr = fmt.Errorf("关闭请求体临时文件失败：%w", err)
		}
	}
	if s.path != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = fmt.Errorf("删除请求体临时文件失败：%w", err)
		}
	}
	s.file = nil
	s.path = ""
	s.memory = nil
	return firstErr
}

// consume 依据剩余额度决定「正常写入」还是「按超限策略处理」。
func (s *Spool) consume(chunk []byte) error {
	remaining := s.cfg.MaxBytes - s.dataBytes
	if int64(len(chunk)) <= remaining {
		return s.write(chunk)
	}
	return s.handleExceed(chunk, remaining)
}

// handleExceed 处理「本次读取的字节数超过剩余额度」的情况。
//
// 三种策略的语义差异（设计文档 §7.4）：
//   - truncate：保留上限内的内容继续检测，标记 Truncated；
//   - reject  ：直接拒绝，返回 ErrBodyTooLarge（调用方回 400）；
//   - skip    ：放弃体检测，标记 Skipped（头 / URI 检测仍然生效）。
func (s *Spool) handleExceed(chunk []byte, remaining int64) error {
	switch s.cfg.OnExceed {
	case config.BodyOnExceedReject:
		s.truncated = true
		s.metrics.IncBodyTruncated()
		return ErrBodyTooLarge
	case config.BodyOnExceedSkip:
		s.skipDetection = true
		// 放弃体检测：已缓冲的内容不再需要，立即释放，避免残留内容被后续 Read 读到。
		s.releaseBuffers()
		s.metrics.IncBodySkipped()
		if s.logger != nil {
			s.logger.Warn("请求体超过上限且策略为 skip，本次请求跳过体检测",
				"max_bytes", s.cfg.MaxBytes, "declared", s.declared)
		}
		return nil
	default:
		s.truncated = true
		if remaining > 0 {
			if err := s.write(chunk[:remaining]); err != nil {
				return err
			}
		}
		s.metrics.IncBodyTruncated()
		if s.logger != nil {
			s.logger.Warn("请求体超过上限，已按 truncate 策略截断后继续检测",
				"max_bytes", s.cfg.MaxBytes, "declared", s.declared)
		}
		return nil
	}
}

// write 把一段数据写入当前缓冲目标（内存或临时文件）。
func (s *Spool) write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if err := s.ensureTarget(int64(len(p))); err != nil {
		return err
	}

	if s.file != nil {
		if _, err := s.file.Write(p); err != nil {
			return fmt.Errorf("写入请求体临时文件失败：%w", err)
		}
	} else {
		if s.memory == nil {
			s.memory = &bytes.Buffer{}
		}
		s.memory.Write(p)
	}
	s.dataBytes += int64(len(p))
	return nil
}

// ensureTarget 依据 spool 策略选择缓冲目标，必要时把内存缓冲迁移到临时文件。
func (s *Spool) ensureTarget(incoming int64) error {
	if s.file != nil {
		return nil
	}

	needDisk := s.cfg.Spool == config.SpoolDisk
	if s.cfg.Spool == config.SpoolAuto && s.dataBytes+incoming > s.cfg.MemoryThreshold {
		// auto 策略：即将越过内存阈值，提前迁移，避免「先整段读入内存再落盘」。
		needDisk = true
	}
	if !needDisk {
		return nil
	}
	return s.spillToDisk()
}

// spillToDisk 把已缓冲的内存内容迁移到临时文件，并切换后续写入目标。
//
// 迁移只发生一次：完成之后 file 非 nil，后续写入直接落盘。
func (s *Spool) spillToDisk() error {
	file, err := os.CreateTemp(s.cfg.SpoolDir, "waf-body-*.tmp")
	if err != nil {
		return fmt.Errorf("创建请求体临时文件失败（spool_dir=%q）：%w", s.cfg.SpoolDir, err)
	}

	if s.memory != nil && s.memory.Len() > 0 {
		if _, err := file.Write(s.memory.Bytes()); err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			return fmt.Errorf("迁移内存缓冲到临时文件失败：%w", err)
		}
	}

	s.memory = nil
	s.file = file
	s.path = file.Name()
	s.spilled = true

	if s.logger != nil {
		s.logger.Debug("请求体已迁移到临时文件",
			"path", s.path, "bytes", s.dataBytes, "memory_threshold", s.cfg.MemoryThreshold)
	}
	return nil
}

// prepareReader 依据当前缓冲位置把读取游标重置到起点。
func (s *Spool) prepareReader() error {
	if s.file != nil {
		if _, err := s.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("重置请求体临时文件读取位置失败：%w", err)
		}
		s.reader = s.file
		return nil
	}
	if s.memory == nil {
		s.memory = &bytes.Buffer{}
	}
	s.reader = bytes.NewReader(s.memory.Bytes())
	return nil
}

// releaseBuffers 释放已占用的缓冲资源（超限拒绝或跳过检测时调用）。
//
// 之所以要主动释放：超限说明请求体体积不可信，继续在内存或磁盘上保留它
// 只会放大资源风险，而内容本身已经不会再参与检测。
func (s *Spool) releaseBuffers() {
	if s.file != nil {
		_ = s.file.Close()
		if s.path != "" {
			_ = os.Remove(s.path)
		}
		s.file = nil
		s.path = ""
	}
	s.memory = nil
	s.dataBytes = 0
	s.spilled = false
	s.reader = nil
}

// markMissingIfRequired 在「预期携带请求体但未收到」时记录告警与指标。
//
// 判定口径（与设计文档 §3.7 一致）：必须**同时**满足以下三个条件才算「请求体缺失」：
//
//  1. ingress.body.mode = required（本部署预期能拿到请求体）；
//  2. **原始请求方法**属于 ingress.body.missing_methods（默认 POST / PUT / PATCH）；
//  3. 原始请求**没有明确声明空请求体**（即声明的 Content-Length != 0）。
//
// 条件 2 的必要性：GET / HEAD / OPTIONS 等请求本来就不携带请求体，
// 把它们也计为「缺失」会让系统日志与 waf_body_missing_total 被正常流量刷屏，
// 真正的问题（代理没有转发请求体）反而被噪声掩盖。
//
// 条件 3 的必要性：Content-Length: 0 是客户端主动声明「本次请求没有请求体」，
// 没有请求体自然就没有请求参数——「拿不到请求参数」属于正常现象，
// 既不是异常、更不构成拦截理由。本项目的原则是「只对确实存在的内容做校验」，
// 而不是「缺少即异常」。
//
// 注意 declared == -1 表示**未知**（chunked 编码，或接入通道不转发 Content-Length，
// 例如原生 Nginx 的 auth_request 通道）。未知不等于空体：既然无法证明客户端声明了空体，
// 就仍然按方法维度计入缺失，避免「代理没转发请求体」这类真实故障被静默掩盖。
func (s *Spool) markMissingIfRequired() {
	if s.cfg.Mode != config.BodyModeRequired {
		return
	}
	if !s.expectsBody() {
		return
	}
	if s.declared == 0 {
		// 客户端明确声明了空请求体：没有内容就没有可校验的参数，静默通过。
		return
	}
	s.missing = true
	s.metrics.IncBodyMissing()
	if s.logger != nil {
		s.logger.Warn("配置要求携带请求体（ingress.body.mode = required），但本次请求未携带请求体",
			"source", s.cfg.Source, "method", s.method, "declared", s.declared)
	}
}

// expectsBody 报告本次请求方法是否「语义上应当携带请求体」（方法维度）。
//
// 命中 ingress.body.missing_methods 中的任意一项即视为预期携带（大小写不敏感）。
// 该方法只负责方法维度；「客户端是否声明了空体」由 markMissingIfRequired 的条件 3 判定，
// 两者必须同时成立才计入缺失。
// 方法为空（接入层未能还原原始方法）时保守返回 false：
// 宁可漏报「缺失」，也不要把一个「无法判断」的请求当成配置错误持续刷屏。
func (s *Spool) expectsBody() bool {
	if s.method == "" {
		return false
	}
	for _, candidate := range s.cfg.MissingMethods {
		if strings.EqualFold(strings.TrimSpace(candidate), s.method) {
			return true
		}
	}
	return false
}

// chunkSize 返回单块读取大小。
//
// 归一化规则：块大小不得超过 max_bytes（块比上限还大属于配置浪费），
// 且至少为 1 字节；两个约束都保证循环一定会推进。
func (s *Spool) chunkSize() int {
	size := s.cfg.ChunkBytes
	if size <= 0 || size > s.cfg.MaxBytes {
		size = s.cfg.MaxBytes
	}
	if size <= 0 {
		size = 1
	}
	return int(size)
}
