package logging

import (
	"log/slog"
	"testing"

	"github.com/weiyongkang/waf/internal/config"
)

// TestApplyAllowLevel 覆盖「放行记录策略」对访问日志通道最低级别的影响。
//
// 之所以需要这层映射：allow_level=debug 时若通道级别仍是 info，
// slog 会直接丢弃 debug 级记录，导致「鉴权请求过与不过都留痕」静默失效。
func TestApplyAllowLevel(t *testing.T) {
	cases := []struct {
		name       string
		base       slog.Level
		allowLevel string
		want       slog.Level
		wantErr    bool
	}{
		{name: "空串不改级别", base: slog.LevelInfo, allowLevel: "", want: slog.LevelInfo},
		{name: "info 不改级别", base: slog.LevelInfo, allowLevel: config.AccessAllowLevelInfo, want: slog.LevelInfo},
		{name: "off 不改级别", base: slog.LevelInfo, allowLevel: config.AccessAllowLevelOff, want: slog.LevelInfo},
		{name: "debug 下探到 debug", base: slog.LevelInfo, allowLevel: config.AccessAllowLevelDebug, want: slog.LevelDebug},
		{name: "已更细时不下探成更粗", base: slog.LevelDebug, allowLevel: config.AccessAllowLevelDebug, want: slog.LevelDebug},
		{name: "warn 通道也会被下探", base: slog.LevelWarn, allowLevel: config.AccessAllowLevelDebug, want: slog.LevelDebug},
		{name: "大小写与空白容错", base: slog.LevelInfo, allowLevel: " DEBUG ", want: slog.LevelDebug},
		{name: "非法取值报错", base: slog.LevelInfo, allowLevel: "always", wantErr: true},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			got, err := applyAllowLevel(item.base, item.allowLevel)
			if item.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际成功返回 %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际报错：%v", err)
			}
			if got != item.want {
				t.Fatalf("级别 = %v，期望 %v", got, item.want)
			}
		})
	}
}
