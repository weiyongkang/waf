package config

import "testing"

// TestJoinBasePath 覆盖统一前缀的拼接与幂等语义。
func TestJoinBasePath(t *testing.T) {
	cases := []struct {
		name string
		base string
		path string
		want string
	}{
		{name: "空前缀保持原路径", base: "", path: "/waf/auth", want: "/waf/auth"},
		{name: "根前缀保持原路径", base: "/", path: "/waf/auth", want: "/waf/auth"},
		{name: "普通拼接", base: "/gateway", path: "/waf/auth", want: "/gateway/waf/auth"},
		{name: "去掉前缀末尾斜杠", base: "/gateway/", path: "/waf/auth", want: "/gateway/waf/auth"},
		{name: "已包含前缀时不重复拼接", base: "/gateway", path: "/gateway/waf/auth", want: "/gateway/waf/auth"},
		{name: "路径等于前缀", base: "/gateway", path: "/gateway", want: "/gateway"},
		{name: "路径缺少前导斜杠", base: "/gateway", path: "waf/auth", want: "/gateway/waf/auth"},
		{name: "仅按路径段边界判断前缀", base: "/gateway", path: "/gatewayx/auth", want: "/gateway/gatewayx/auth"},
		{name: "空路径返回前缀", base: "/gateway", path: "", want: "/gateway"},
		{name: "空白值会被裁剪", base: " /gateway/ ", path: " /waf/auth ", want: "/gateway/waf/auth"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := JoinBasePath(tc.base, tc.path); got != tc.want {
				t.Fatalf("JoinBasePath(%q, %q) = %q，期望 %q", tc.base, tc.path, got, tc.want)
			}
		})
	}
}
