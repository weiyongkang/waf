package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
	"github.com/weiyongkang/waf/internal/responder"
	"github.com/weiyongkang/waf/internal/version"
)

// runCheckConfig 实现 check-config 子命令：加载并校验配置，输出生效配置与来源摘要。
//
// 输出内容（验收项 A21）：
//  1. 版本信息；
//  2. 已加载的配置文件列表；
//  3. 逐项来源摘要（cli / file / env / default）；
//  4. 生效配置的完整 YAML；
//  5. 当前已注册的校验单元类型与告警通道类型（便于发现配置中的类型拼写错误）。
//
// 配置校验失败时退出码为 2，且错误信息包含具体配置项与来源。
func runCheckConfig(args []string, stdout, stderr io.Writer) int {
	resolved, _, code := loadResolved(args, stderr, "waf check-config")
	if code != exitOK {
		return code
	}
	cfg := resolved.Config
	databaseApplied := false
	if cfg.Database.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var applyErr error
		cfg, databaseApplied, applyErr = applyDatabaseConfig(ctx, cfg)
		if applyErr != nil {
			fmt.Fprintf(stderr, "数据库运营策略校验失败：%v\n", applyErr)
			return exitConfigError
		}
	}
	if err := responder.ValidateResponderConfig(cfg.Responder); err != nil {
		fmt.Fprintf(stderr, "拦截响应模板校验失败：%v\n", err)
		return exitConfigError
	}

	fmt.Fprintf(stdout, "%s\n\n", version.String())
	if cfg.Database.Enabled {
		if databaseApplied {
			fmt.Fprintln(stdout, "数据库运营策略已叠加（数据库已初始化，运营字段以数据库为准）")
		} else {
			fmt.Fprintln(stdout, "数据库尚未初始化，本次仅校验配置文件；首次 waf run 会导入运营数据")
		}
		fmt.Fprintln(stdout)
	}

	if len(resolved.Files) > 0 {
		fmt.Fprintln(stdout, "已加载的配置文件（按优先级从低到高）：")
		for _, file := range resolved.Files {
			fmt.Fprintf(stdout, "  - %s\n", file)
		}
	} else {
		fmt.Fprintln(stdout, "未加载任何配置文件，使用内置默认值 + 环境变量 + CLI 覆盖")
	}
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "配置项来源摘要：")
	summary := resolved.SourceSummary()
	if summary == "" {
		fmt.Fprintln(stdout, "  （无任何覆盖项）")
	} else {
		fmt.Fprint(stdout, summary)
	}
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "已注册的校验单元类型：")
	types := core.RegisteredTypes()
	if len(types) == 0 {
		fmt.Fprintln(stdout, "  （当前无已注册类型；插件将在 M1.2–M1.5 陆续接入）")
	} else {
		for _, typeName := range types {
			fmt.Fprintf(stdout, "  - %s\n", typeName)
		}
	}
	fmt.Fprintln(stdout)

	// 告警通道类型单独列出：notifiers[].type 写错时的报错只在「启动装配」阶段出现，
	// 而 check-config 是运维改配置后最先执行的命令，在这里就能看到合法取值能省一轮排障。
	fmt.Fprintln(stdout, "已注册的告警通道类型（notifiers[].type 可选值）：")
	notifierTypes := notify.RegisteredTypes()
	if len(notifierTypes) == 0 {
		fmt.Fprintln(stdout, "  （无已注册类型；请确认 cmd/waf/plugins.go 中已空白导入通道包）")
	} else {
		for _, typeName := range notifierTypes {
			fmt.Fprintf(stdout, "  - %s\n", typeName)
		}
	}
	fmt.Fprintln(stdout)

	encoded, err := config.EncodeEffectiveConfig(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "生效配置序列化失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintln(stdout, "生效配置：")
	fmt.Fprintln(stdout, "---")
	_, _ = stdout.Write(encoded)
	return exitOK
}
