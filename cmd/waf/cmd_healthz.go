package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// healthzProbeTimeout 是本地存活探测的超时时间。
//
// 取值 2s：容器健康检查的 timeout 通常为 2–3s，探测本身只是一个本地 HTTP 请求，
// 超过该时长说明进程已经无法正常服务，应当判定为不健康。
const healthzProbeTimeout = 2 * time.Second

// runHealthz 实现 healthz 子命令：探测本地健康检查端点（自动叠加 server.base_path）。
//
// 用途：容器 HEALTHCHECK 直接调用 `waf healthz`（不依赖镜像内是否安装 curl/wget），
// 这也是 distroless 镜像下唯一可行的健康检查方式。
func runHealthz(args []string, stdout, stderr io.Writer) int {
	resolved, _, code := loadResolved(args, stderr, "waf healthz")
	if code != exitOK {
		return code
	}

	target := probeAddress(resolved.Config.Server.Listen)
	url := "http://" + target + config.JoinBasePath(resolved.Config.Server.BasePath, "/healthz")

	client := &http.Client{Timeout: healthzProbeTimeout}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(stderr, "存活探测失败：%v（目标 %s）\n", err, url)
		return exitRuntimeError
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "存活探测失败：HTTP %d（目标 %s）\n", resp.StatusCode, url)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "ok %s\n", url)
	return exitOK
}

// probeAddress 把监听地址转换为可直接拨号的地址。
//
// 之所以需要转换：监听地址常写成 ":9080" 或 "0.0.0.0:9080"，
// 这类地址无法直接作为 HTTP 客户端的目标，需要替换为回环地址。
func probeAddress(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return net.JoinHostPort("127.0.0.1", "9080")
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// 不合法或缺少端口时，直接返回原值交给 HTTP 客户端报错，便于暴露真实配置问题。
		return listen
	}
	if _, err := strconv.Atoi(port); err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
