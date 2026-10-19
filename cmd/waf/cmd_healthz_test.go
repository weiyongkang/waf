package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestHealthzProbeUsesBasePath 覆盖：CLI 探活必须跟随 server.base_path。
func TestHealthzProbeUsesBasePath(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址失败：%v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runHealthz([]string{
		"--server-listen", parsed.Host,
		"--server-base-path", "/gateway",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("探活失败，退出码 %d：%s", code, stderr.String())
	}
	if gotPath != "/gateway/healthz" {
		t.Fatalf("探活路径 = %q，期望 /gateway/healthz", gotPath)
	}
}
