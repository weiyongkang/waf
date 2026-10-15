package ban

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

// TestParseKeyScope 覆盖：维度名解析的容错规则（大小写、空白、空串）。
func TestParseKeyScope(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		expect KeyScope
		ok     bool
	}{
		{name: "标准取值", input: "client_ip", expect: ScopeClientIP, ok: true},
		{name: "大写与空白", input: "  CLIENT_IP+PATH  ", expect: ScopeClientIPPath, ok: true},
		{name: "空串取默认维度", input: "", expect: ScopeClientIP, ok: true},
		{name: "未知取值", input: "client_ip+ua", expect: "", ok: false},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			scope, ok := ParseKeyScope(item.input)
			if ok != item.ok || scope != item.expect {
				t.Fatalf("ParseKeyScope(%q) = (%q, %v)，期望 (%q, %v)",
					item.input, scope, ok, item.expect, item.ok)
			}
		})
	}
}

// TestClientIPScopeKey 覆盖：各维度的键构造与关键字段缺失时的兜底 / 放弃行为。
func TestClientIPScopeKey(t *testing.T) {
	cases := []struct {
		name     string
		scope    KeyScope
		clientIP string
		site     string
		path     string
		method   string
		expect   string
	}{
		{name: "按 IP", scope: ScopeClientIP, clientIP: "1.2.3.4", expect: "ip:1.2.3.4"},
		{name: "按 IP 与站点", scope: ScopeClientIPSite, clientIP: "1.2.3.4", site: "shop", expect: "ip:1.2.3.4|site:shop"},
		{name: "站点缺失兜底为默认站点", scope: ScopeClientIPSite, clientIP: "1.2.3.4", expect: "ip:1.2.3.4|site:" + core.DefaultSiteName},
		{name: "按 IP 与路径", scope: ScopeClientIPPath, clientIP: "1.2.3.4", path: "/api/user", expect: "ip:1.2.3.4|path:/api/user"},
		{name: "路径缺失兜底为根路径", scope: ScopeClientIPPath, clientIP: "1.2.3.4", expect: "ip:1.2.3.4|path:/"},
		{name: "按 IP 与方法（大写归一）", scope: ScopeClientIPMethod, clientIP: "1.2.3.4", method: "post", expect: "ip:1.2.3.4|method:POST"},
		{name: "方法缺失时放弃构造", scope: ScopeClientIPMethod, clientIP: "1.2.3.4", expect: ""},
		{name: "IP 缺失时放弃构造", scope: ScopeClientIP, clientIP: "  ", expect: ""},
		{name: "未知维度放弃构造", scope: KeyScope("client_ip+ua"), clientIP: "1.2.3.4", expect: ""},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			got := ClientIPScopeKey(item.scope, item.clientIP, item.site, item.path, item.method)
			if got != item.expect {
				t.Fatalf("键构造不符，实际 %q，期望 %q", got, item.expect)
			}
		})
	}
}

// TestKeyForScopeFromRequest 覆盖：从请求上下文推导各维度键。
func TestKeyForScopeFromRequest(t *testing.T) {
	rctx := newRequestContext("1.2.3.4")
	rctx.Raw.Path = "/api/user"
	rctx.Raw.Method = "GET"
	rctx.Site = &core.Site{Name: "shop"}

	cases := []struct {
		scope  KeyScope
		expect string
	}{
		{ScopeClientIP, "ip:1.2.3.4"},
		{ScopeClientIPSite, "ip:1.2.3.4|site:shop"},
		{ScopeClientIPPath, "ip:1.2.3.4|path:/api/user"},
		{ScopeClientIPMethod, "ip:1.2.3.4|method:GET"},
	}
	for _, item := range cases {
		if got := KeyForScope(item.scope, rctx); got != item.expect {
			t.Fatalf("维度 %s 的键不符，实际 %q，期望 %q", item.scope, got, item.expect)
		}
	}

	if got := KeyForScope(ScopeClientIP, nil); got != "" {
		t.Fatalf("空上下文应返回空键，实际 %q", got)
	}
}

// TestResolveScopes 覆盖：ban_keys 与 ban_key 的取值规则。
func TestResolveScopes(t *testing.T) {
	base := defaultBanConfig()

	// 未配置 ban_keys 时回落为单一主维度（旧配置零改动升级）。
	scopes, err := resolveScopes(base)
	if err != nil {
		t.Fatalf("解析维度失败：%v", err)
	}
	if len(scopes) != 1 || scopes[0] != ScopeClientIP {
		t.Fatalf("未配置 ban_keys 时应回落为 [client_ip]，实际 %v", scopes)
	}

	// 配置多个维度：顺序保持声明顺序，重复项静默去重。
	multi := base
	multi.BanKeys = []string{"client_ip", "client_ip+path", "client_ip"}
	scopes, err = resolveScopes(multi)
	if err != nil {
		t.Fatalf("解析维度失败：%v", err)
	}
	if len(scopes) != 2 || scopes[0] != ScopeClientIP || scopes[1] != ScopeClientIPPath {
		t.Fatalf("多维度解析不符，实际 %v", scopes)
	}

	// 非法维度必须 fail fast（静默忽略会让「配了却没生效」无法被发现）。
	bad := base
	bad.BanKeys = []string{"client_ip", "ip"}
	if _, err := resolveScopes(bad); err == nil {
		t.Fatal("非法维度应在解析阶段报错")
	} else if !strings.Contains(err.Error(), "client_ip+path") {
		t.Fatalf("错误提示应列出可选维度，实际 %v", err)
	}
}

// TestCheckScopesMatchesAllScopes 覆盖：多维度查询命中任一维度即拦截，且回传命中维度。
func TestCheckScopesMatchesAllScopes(t *testing.T) {
	cfg := defaultBanConfig()
	cfg.BanKeys = []string{"client_ip", "client_ip+path"}
	manager, _ := newTestManager(t, cfg)

	ctx := context.Background()
	rctx := newRequestContext("1.2.3.4")
	rctx.Raw.Path = "/api/user"
	rctx.Raw.Method = "GET"

	if banned, _, _, _, err := manager.CheckScopes(ctx, rctx); err != nil || banned {
		t.Fatalf("封禁前不应命中，实际 banned=%v err=%v", banned, err)
	}

	// 只写入「路径维度」的封禁：查询必须能覆盖到它，否则就是「封了却不生效」。
	key := ClientIPScopeKey(ScopeClientIPPath, "1.2.3.4", "", "/api/user", "GET")
	storeRef, err := manager.store()
	if err != nil {
		t.Fatalf("解析存储失败：%v", err)
	}
	if err := storeRef.Ban(ctx, key, time.Minute, "路径维度封禁"); err != nil {
		t.Fatalf("写入路径维度封禁失败：%v", err)
	}

	banned, remaining, matchedKey, scope, err := manager.CheckScopes(ctx, rctx)
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if !banned || matchedKey != key || scope != string(ScopeClientIPPath) {
		t.Fatalf("应命中路径维度，实际 banned=%v key=%q scope=%q", banned, matchedKey, scope)
	}
	if remaining <= 0 {
		t.Fatalf("应回传正的剩余时长，实际 %s", remaining)
	}
}
