package main

import (
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// newTestConfigFlags 构造用于参数拆分判定的配置参数集合。
func newTestConfigFlags(t *testing.T) *config.FlagSet {
	t.Helper()
	flagSet, err := config.NewFlagSet("test", io.Discard)
	if err != nil {
		t.Fatalf("构造配置参数集合失败：%v", err)
	}
	return flagSet
}

// TestIsConfigFlag 覆盖：配置体系参数名的识别。
func TestIsConfigFlag(t *testing.T) {
	flagSet := newTestConfigFlags(t)

	cases := map[string]bool{
		"c":                     true,
		"config":                true,
		"set":                   true,
		"server-listen":         true,
		"ban-default-ttl":       true,
		"limits-max-mmdb-bytes": true,
		"ip":                    false,
		"ttl":                   false,
		"reason":                false,
		"store":                 false,
		"":                      false,
	}

	for name, want := range cases {
		if got := flagSet.IsConfigFlag(name); got != want {
			t.Fatalf("IsConfigFlag(%q) 期望 %v，实际 %v", name, want, got)
		}
	}
}

// TestSplitConfigArgs 覆盖：业务参数与配置体系参数的拆分。
//
// 拆分的正确性直接决定运维命令是否可用：一旦把 -c 误判成业务参数，
// 标准库 flag 会直接报「flag provided but not defined」。
func TestSplitConfigArgs(t *testing.T) {
	flagSet := newTestConfigFlags(t)

	cases := []struct {
		name     string
		args     []string
		business []string
		global   []string
	}{
		{
			name:     "配置参数与子命令混杂",
			args:     []string{"list", "-c", "x.yaml"},
			business: []string{"list"},
			global:   []string{"-c", "x.yaml"},
		},
		{
			name:     "业务参数与配置参数并存",
			args:     []string{"add", "--ip", "1.2.3.4", "--ttl", "20m", "-c", "x.yaml", "--set", "ban.default_ttl=1h"},
			business: []string{"add", "--ip", "1.2.3.4", "--ttl", "20m"},
			global:   []string{"-c", "x.yaml", "--set", "ban.default_ttl=1h"},
		},
		{
			name:     "内联取值写法",
			args:     []string{"--ip=1.2.3.4", "--store=shared", "--config=x.yaml"},
			business: []string{"--ip=1.2.3.4", "--store=shared"},
			global:   []string{"--config=x.yaml"},
		},
		{
			name:     "标量配置项参数归入配置体系",
			args:     []string{"--ban-default-ttl", "1h", "--ip", "1.2.3.4"},
			business: []string{"--ip", "1.2.3.4"},
			global:   []string{"--ban-default-ttl", "1h"},
		},
		{
			name:     "帮助参数归入业务集合",
			args:     []string{"-h"},
			business: []string{"-h"},
			global:   nil,
		},
		{
			name:     "无参数",
			args:     nil,
			business: nil,
			global:   nil,
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			business, global := splitConfigArgs(flagSet, item.args)
			if !reflect.DeepEqual(business, item.business) {
				t.Fatalf("业务参数不符：期望 %v，实际 %v", item.business, business)
			}
			if !reflect.DeepEqual(global, item.global) {
				t.Fatalf("配置参数不符：期望 %v，实际 %v", item.global, global)
			}
		})
	}
}

// TestParseBanFlagsAcceptsGlobalFlags 覆盖：解析后全局参数被原样保留到 rest，
// 业务参数被正确读出（这是 waf ban 能同时使用业务参数与 -c 的关键）。
func TestParseBanFlagsAcceptsGlobalFlags(t *testing.T) {
	loader, err := newBanFlagSet(banActionAdd, io.Discard)
	if err != nil {
		t.Fatalf("构造参数集合失败：%v", err)
	}
	loader.fs.String("ttl", "", "封禁时长")

	args := []string{"-c", "x.yaml", "--ip", "1.2.3.4", "--ttl", "20m", "--set", "ban.default_ttl=1h"}
	if code := parseBanFlags(loader, args, io.Discard); code != exitOK {
		t.Fatalf("解析应成功，实际退出码 %d", code)
	}

	if loader.ip != "1.2.3.4" {
		t.Fatalf("--ip 解析不符，实际 %q", loader.ip)
	}
	if got := loader.fs.Lookup("ttl").Value.String(); got != "20m" {
		t.Fatalf("--ttl 解析不符，实际 %q", got)
	}

	wantRest := []string{"-c", "x.yaml", "--set", "ban.default_ttl=1h"}
	if !reflect.DeepEqual(loader.rest, wantRest) {
		t.Fatalf("透传参数不符：期望 %v，实际 %v", wantRest, loader.rest)
	}
}

// TestFormatRemaining 覆盖：剩余时长的可读化输出。
func TestFormatRemaining(t *testing.T) {
	if got := formatRemaining(0); got != "-" {
		t.Fatalf("零时长应输出 -，实际 %q", got)
	}
	if got := formatRemaining(20*time.Minute + 40*time.Second); got != "20m40s" {
		t.Fatalf("时长输出不符，实际 %q", got)
	}
}
