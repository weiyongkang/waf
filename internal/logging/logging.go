// Package logging 提供 WAF 的两类日志：系统运行日志与请求访问日志（需求 R21）。
//
// 两类日志的定位：
//   - 系统日志（system）：进程生命周期、配置生效、组件状态、热加载、存储故障等；
//   - 访问日志（access）：每一个经过鉴权端点的请求的判定结果、命中规则、耗时。
//
// 共同要求：分级（debug/info/warn/error）、JSON 格式、可输出到 stdout 与文件。
// 之所以统一使用标准库 log/slog：零第三方依赖、JsonHandler 原生支持结构化字段，
// 且与内部其它组件（http.Server.ErrorLog 等）天然兼容。
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
)

// Loggers 是构建完成的两类日志器及其需要关闭的资源。
type Loggers struct {
	// System 是系统运行日志器。
	System *slog.Logger
	// Access 是请求访问与拦截日志器。
	Access *slog.Logger
	// closers 是需要随进程退出一并关闭的写入器（例如日志文件句柄）。
	closers []io.Closer
}

// Close 关闭全部日志文件句柄；必须幂等。
func (l *Loggers) Close() error {
	var firstErr error
	for _, closer := range l.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.closers = nil
	return firstErr
}

// Build 依据配置构建两类日志器。
//
// 说明：日志级别只影响记录量，不影响安全判定；因此任一通道禁用（enabled=false）时
// 统一替换为丢弃输出的日志器，保证调用方无需做 nil 判断。
func Build(cfg config.LoggingConfig) (*Loggers, error) {
	loggers := &Loggers{}

	system, systemCloser, err := buildOne("系统日志", cfg.System, "")
	if err != nil {
		return nil, err
	}
	loggers.System = system
	if systemCloser != nil {
		loggers.closers = append(loggers.closers, systemCloser)
	}

	// 访问日志通道额外叠加「放行记录策略」（logging.access.allow_level）：
	// allow_level=debug 时必须把通道级别下探到 debug，否则放行记录会被通道级别过滤掉，
	// 「放行留痕」这个需求会静默失效；allow_level=off 由 server 层直接跳过写入，这里不处理。
	access, accessCloser, err := buildOne("访问日志", cfg.Access.LogOutputConfig, cfg.Access.AllowLevel)
	if err != nil {
		// 系统日志已建好，需要回滚以避免文件句柄泄漏。
		_ = loggers.Close()
		return nil, err
	}
	loggers.Access = access
	if accessCloser != nil {
		loggers.closers = append(loggers.closers, accessCloser)
	}

	return loggers, nil
}

// buildOne 构建单个日志通道，返回日志器与需要关闭的写入器（可能为 nil）。
//
// allowLevel 是「放行记录策略」覆盖值，只有访问日志通道会传入（系统日志传空串）：
// 它只影响通道的最低级别，不改变拦截 / 观察 / 异常记录的等级语义。
func buildOne(label string, cfg config.LogOutputConfig, allowLevel string) (*slog.Logger, io.Closer, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, fmt.Errorf("%s级别配置非法：%w", label, err)
	}
	// 按放行策略决定是否需要下探通道级别，保证「放行留痕」不会静默失效。
	level, err = applyAllowLevel(level, allowLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("%s配置非法：%w", label, err)
	}
	options := &slog.HandlerOptions{Level: level}

	if !cfg.Enabled || len(cfg.Outputs) == 0 {
		// 通道关闭：返回丢弃全部输出的日志器，避免调用方到处写 nil 判断。
		return slog.New(slog.NewJSONHandler(io.Discard, options)), nil, nil
	}

	writers := make([]io.Writer, 0, len(cfg.Outputs))
	var closer io.Closer

	for _, output := range cfg.Outputs {
		switch output {
		case "stdout":
			writers = append(writers, os.Stdout)
		case "file":
			rotation, err := newRotationWriter(
				cfg.Dir, cfg.File, cfg.Rotate, cfg.MaxFileBytes, cfg.KeepDays, cfg.MaxTotalBytes, cfg.Compress,
			)
			if err != nil {
				if closer != nil {
					_ = closer.Close()
				}
				return nil, nil, fmt.Errorf("%s文件输出初始化失败：%w", label, err)
			}
			writers = append(writers, rotation)
			// 两类日志各自独立轮转，因此这里只保留最后一个文件写入器的关闭句柄；
			// 实际场景中同一通道不会同时声明两个 file 输出（配置校验已确保 outputs 去重语义）。
			closer = rotation
		default:
			return nil, nil, fmt.Errorf("%s输出目标 %q 非法，可选值：stdout / file", label, output)
		}
	}

	return slog.New(slog.NewJSONHandler(io.MultiWriter(writers...), options)), closer, nil
}

// parseLevel 把配置中的级别字符串转换为 slog 级别。
//
// 映射关系（设计文档 §5.2）：debug/info/warn/error 分别对应 slog 的四级；
// fatal 在本项目中不用于日志输出（进程退出由 main 统一处理）。
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("未知日志级别 %q，可选值：debug / info / warn / error", level)
	}
}

// applyAllowLevel 依据「放行记录策略」决定访问日志通道的最低级别。
//
// 背景：放行记录若以 debug 级写入，而通道级别仍是 info，slog 会直接把它丢弃，
// 于是「鉴权请求过与不过都留痕」这个需求会静默失效。因此策略要求更细时把级别下探。
// 三个取值：
//   - info（默认）：不改变通道级别，放行记录以 info 级写入，默认可见；
//   - debug：把通道级别下探到 debug，使放行记录可见；
//   - off：不改变通道级别（放行由 server 层直接跳过，拦截 / 观察记录保持原级别）；
//   - 空串：系统日志通道，不做任何处理。
func applyAllowLevel(base slog.Level, allowLevel string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(allowLevel)) {
	case "", config.AccessAllowLevelInfo, config.AccessAllowLevelOff:
		return base, nil
	case config.AccessAllowLevelDebug:
		// 已比 debug 更细时保持原级别，避免把级别「调粗」导致其它记录丢失。
		if base > slog.LevelDebug {
			return slog.LevelDebug, nil
		}
		return base, nil
	default:
		return base, fmt.Errorf("未知放行记录策略 %q，可选值：%s", allowLevel, strings.Join(config.AccessAllowLevels(), " / "))
	}
}
