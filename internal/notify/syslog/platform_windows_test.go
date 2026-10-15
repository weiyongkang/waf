//go:build windows || plan9

package syslog

import (
	"strings"
	"testing"

	"github.com/weiyongkang/waf/internal/notify"
)

// TestNewFailsFastOnUnsupportedPlatform 验证非类 Unix 平台上的 syslog 通道
// 在构造阶段就明确报错，而不是「启用后静默丢弃全部告警」。
func TestNewFailsFastOnUnsupportedPlatform(t *testing.T) {
	_, err := New(newInstance("t", map[string]any{"network": "tcp", "address": "127.0.0.1:514"}), notify.Deps{})
	if err == nil {
		t.Fatal("当前平台不支持 syslog，构造应当返回错误")
	}
	if !strings.Contains(err.Error(), "不支持") {
		t.Fatalf("错误信息应说明平台不支持，实际：%v", err)
	}
}
