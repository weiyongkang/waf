package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// runConfig 实现 config 子命令：当前提供 print，用于输出默认或叠加后的生效配置。
func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "缺少 config 子命令，可用：print")
		return exitConfigError
	}
	switch args[0] {
	case "print":
		return runConfigPrint(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知的 config 子命令 %q，可用：print\n", args[0])
		return exitConfigError
	}
}

// runConfigPrint 输出配置加载结果。
//
// 无参数时输出内置默认值叠加环境变量后的配置；传入 -c/--set/具名配置参数时，
// 按与 run 完全相同的优先级输出最终生效配置。配置文件参数既可以是单个文件，
// 也可以是目录（目录内按文件名字典序合并）。
func runConfigPrint(args []string, stdout, stderr io.Writer) int {
	flagSet, err := config.NewFlagSet("waf config print", stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitConfigError
	}

	// 未显式提供 -c 时不自动读取 /etc/waf/waf.yaml：config print 的默认语义是
	// 「内置默认值 + 环境变量 + CLI」，避免命令输出被宿主机上的默认文件意外改变。
	resolved, err := config.Load(config.Options{
		ConfigFiles:           flagSet.ConfigFiles(),
		CLI:                   flagSet,
		SkipDefaultConfigPath: len(flagSet.ConfigFiles()) == 0,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitConfigError
	}

	effective := resolved.Config
	if effective.Database.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		effective, _, err = applyDatabaseConfig(ctx, effective)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitConfigError
		}
	}

	payload, err := config.EncodeEffectiveConfig(effective)
	if err != nil {
		fmt.Fprintf(stderr, "输出生效配置失败：%v\n", err)
		return exitRuntimeError
	}
	if _, err := stdout.Write(payload); err != nil {
		fmt.Fprintf(stderr, "写入生效配置失败：%v\n", err)
		return exitRuntimeError
	}
	return exitOK
}
