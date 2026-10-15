// Package version 提供构建期注入的版本信息。
//
// 版本信息通过构建脚本以 -ldflags 的方式注入，未注入时使用下列默认值，
// 保证本地 `go run` 与 `go test` 场景下也能正常输出。
package version

import (
	"fmt"
	"runtime"
)

// 以下变量由构建脚本通过 -ldflags "-X ..." 注入，禁止在业务代码中直接修改。
var (
	// Version 是语义化版本号，例如 v0.1.0；由构建脚本注入。
	Version = "dev"
	// Commit 是源码提交号（短哈希）；由构建脚本注入。
	Commit = "none"
	// BuildTime 是构建时间，RFC3339 格式；由构建脚本注入。
	BuildTime = "unknown"
)

// Short 返回短版本标识，用于日志、指标标签与 HTTP 响应头。
//
// 形如 "v0.1.0(abc1234)"；当版本号未注入时返回 "dev"。
func Short() string {
	if Commit == "" || Commit == "none" {
		return Version
	}
	return fmt.Sprintf("%s(%s)", Version, Commit)
}

// String 返回多行的完整版本描述，用于 `waf version` 子命令输出。
func String() string {
	return fmt.Sprintf(
		"waf %s\ncommit:     %s\nbuild time: %s\ngo version: %s\nplatform:   %s/%s",
		Version, Commit, BuildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH,
	)
}
