package netx

import "testing"

// TestNewSetAndContains 覆盖：单 IP、CIDR、IPv6 与带端口写法的匹配。
func TestNewSetAndContains(t *testing.T) {
	set, err := NewSet([]string{"1.2.3.4", "10.0.0.0/8", "::1", "fd00::/8"})
	if err != nil {
		t.Fatalf("构造集合失败：%v", err)
	}
	if set.Len() != 4 {
		t.Fatalf("条目数应为 4，实际 %d", set.Len())
	}

	cases := []struct {
		value string
		want  bool
	}{
		{value: "1.2.3.4", want: true},
		{value: "10.255.1.1", want: true},
		{value: "11.0.0.1", want: false},
		// 必须按网段边界匹配，不能让 10.example 之外的地址误命中。
		{value: "110.0.0.1", want: false},
		{value: "::1", want: true},
		{value: "fd00::1", want: true},
		{value: "fe80::1", want: false},
		// 兼容带端口与 IPv6 方括号的原始片段（RemoteAddr 的常见写法）。
		{value: "1.2.3.4:8080", want: true},
		{value: "[fd00::1]:8080", want: true},
		{value: "", want: false},
		{value: "not-an-ip", want: false},
	}

	for _, item := range cases {
		if got := set.Contains(item.value); got != item.want {
			t.Fatalf("Contains(%q) 期望 %v，实际 %v", item.value, item.want, got)
		}
	}
}

// TestAddRejectsInvalidEntry 覆盖：非法条目必须在构造阶段暴露（fail fast）。
func TestAddRejectsInvalidEntry(t *testing.T) {
	cases := []string{"1.2.3", "10.0.0.0/33", "hello", "1.2.3.4/abc"}
	for _, entry := range cases {
		if _, err := NewSet([]string{entry}); err == nil {
			t.Fatalf("非法条目 %q 应报错", entry)
		}
	}
}

// TestAddIgnoresEmptyEntry 覆盖：空白条目被忽略而不是报错（便于配置文件里留空占位）。
func TestAddIgnoresEmptyEntry(t *testing.T) {
	set, err := NewSet([]string{"", "   "})
	if err != nil {
		t.Fatalf("空白条目不应报错，实际 %v", err)
	}
	if !set.Empty() {
		t.Fatalf("空白条目不应进入集合，实际条目数 %d", set.Len())
	}
}

// TestNilSet 覆盖：空集合的安全语义（不命中、不 panic）。
func TestNilSet(t *testing.T) {
	var set *Set
	if set.Contains("1.2.3.4") {
		t.Fatal("空集合不应命中任何地址")
	}
	if set.Len() != 0 || !set.Empty() {
		t.Fatal("空集合的规模统计应为 0")
	}
}

// TestParseIP 覆盖：地址文本解析的兼容写法。
func TestParseIP(t *testing.T) {
	if ip := ParseIP("1.2.3.4"); ip == nil || ip.String() != "1.2.3.4" {
		t.Fatalf("解析 1.2.3.4 失败：%v", ip)
	}
	if ip := ParseIP("1.2.3.4:80"); ip == nil || ip.String() != "1.2.3.4" {
		t.Fatalf("解析带端口的地址失败：%v", ip)
	}
	if ip := ParseIP("[::1]:80"); ip == nil || ip.String() != "::1" {
		t.Fatalf("解析 IPv6 方括号写法失败：%v", ip)
	}
	if ip := ParseIP("  "); ip != nil {
		t.Fatalf("空白文本应返回 nil，实际 %v", ip)
	}
}
