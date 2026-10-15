package main

import (
	"fmt"
	"io"

	"github.com/weiyongkang/waf/internal/version"
)

// runVersion 输出程序版本信息。
//
// 版本信息在构建期通过 -ldflags 注入（见 Dockerfile 与 scripts/build.sh），
// 未注入时回退为 "dev"，用于区分「本地构建」与「正式发布构建」。
func runVersion(stdout io.Writer) int {
	fmt.Fprintln(stdout, version.String())
	return exitOK
}
