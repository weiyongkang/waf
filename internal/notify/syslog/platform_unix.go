//go:build !windows && !plan9

package syslog

import (
	stdsyslog "log/syslog"
)

// openSink 在类 Unix 平台建立 syslog 连接。
//
// network 与 address 同时为空时使用本机 syslog 套接字（/dev/log 等），
// 这是「WAF 与 syslog 守护进程同机部署」的最常见形态。
func openSink(network, address string, fac facility, tag string) (sink, error) {
	// 传给 Dial 的优先级只用于确定 facility（严重级别由每次写入时指定，
	// 见 log/syslog 的 writeAndRetry：`(w.priority & facilityMask) | (p & severityMask)`）。
	writer, err := stdsyslog.Dial(network, address, stdsyslog.Priority(priority(fac, severityInfo)), tag)
	if err != nil {
		return nil, err
	}
	return &unixSink{writer: writer}, nil
}

// unixSink 基于标准库 log/syslog 实现 sink。
//
// log/syslog.Writer 内部有互斥锁，因此并发写入是安全的；
// 写入失败时它会自动关闭并按需重连（writeAndRetry），无需我们额外处理。
type unixSink struct {
	// writer 是标准库的 syslog 写入器。
	writer *stdsyslog.Writer
}

// write 以指定严重级别写入一条消息。
func (s *unixSink) write(level severity, message string) error {
	switch level {
	case severityErr:
		return s.writer.Err(message)
	case severityWarning:
		return s.writer.Warning(message)
	default:
		return s.writer.Info(message)
	}
}

// close 关闭 syslog 连接。
func (s *unixSink) close() error {
	if s.writer == nil {
		return nil
	}
	return s.writer.Close()
}

// priority 计算 syslog PRI 值：facility 占高 5 位，severity 占低 3 位。
func priority(fac facility, level severity) int {
	return int(fac)*8 + int(level)
}
