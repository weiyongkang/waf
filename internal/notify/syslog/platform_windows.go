//go:build windows || plan9

package syslog

import (
	"errors"
	"runtime"
)

// errUnsupportedPlatform 表示当前操作系统不支持 syslog 通道。
//
// 之所以在构造期直接报错而不是「启用后静默丢弃」：
// 「配置里写了告警通道、实际一条都发不出去」是运维事故的常见成因，
// 必须在启动阶段暴露（与 notify.New 的 fail fast 取向一致）。
var errUnsupportedPlatform = errors.New(
	"当前操作系统不支持 syslog 告警通道（Go 标准库 log/syslog 仅提供类 Unix 实现）：" + runtime.GOOS +
		"，请改用 webhook / wechat / smtp 通道")

// openSink 在非类 Unix 平台恒返回错误。
func openSink(network, address string, fac facility, tag string) (sink, error) {
	_, _, _ = network, address, tag
	_ = fac
	return nil, errUnsupportedPlatform
}
