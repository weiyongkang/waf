//go:build !windows && !plan9

package syslog

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/notify"
)

// TestSendThroughUDPSyslog 端到端验证 UDP syslog 投递。
//
// 用一个本地 UDP 监听器充当 syslog 守护进程：这种方式不依赖机器上是否
// 真的装了 rsyslog，同时又能真实走一遍「Dial -> 写入 -> 报文格式」的链路。
func TestSendThroughUDPSyslog(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("无法启动本地 UDP 监听：%v", err)
	}
	defer func() { _ = listener.Close() }()

	sender, err := New(newInstance("t", map[string]any{
		"network":  "udp",
		"address":  listener.LocalAddr().String(),
		"tag":      "waf-test",
		"facility": "local3",
		"format":   "json",
		"timeout":  "2s",
	}), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("投递失败：%v", err)
	}

	buffer := make([]byte, 4096)
	_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	size, _, err := listener.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("未收到 syslog 报文：%v", err)
	}
	message := string(buffer[:size])

	// PRI 字段格式为 "<facility*8+severity>"；local3 = 19，error = 3，故 PRI = 155。
	if !strings.HasPrefix(message, "<155>") {
		t.Fatalf("报文 PRI 字段不符（应为 <155>）：%s", message)
	}
	if !strings.Contains(message, "waf-test") {
		t.Fatalf("报文应包含配置的 tag：%s", message)
	}
	if !strings.Contains(message, "共享存储不可用") {
		t.Fatalf("报文应包含告警内容：%s", message)
	}
}
