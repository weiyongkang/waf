package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
)

// 封禁名单运维子命令的名称常量。
const (
	banActionList   = "list"
	banActionAdd    = "add"
	banActionRemove = "remove"
)

// banCommandTimeout 是运维命令访问共享存储的超时。
//
// 之所以要有超时：运维命令必须「要么很快给出结果、要么明确报错」，
// 卡住的命令在自动化脚本里会变成难以定位的挂起。
const banCommandTimeout = 5 * time.Second

// runBan 实现 ban 子命令：封禁名单的查询、新增与解除。
//
// 命令形态（设计文档 §2.8）：
//
//	waf ban list   [-c 配置] [--store 存储名]
//	waf ban add    --ip 1.2.3.4 [--ttl 1h] [--reason "暴力破解"] [--site default]
//	waf ban remove --ip 1.2.3.4 [--site default]
//
// 安全边界提醒（需求 R18）：
//
//	本 WAF 的封禁只在系统内部生效——写入共享存储的名单，由 banlist 校验单元拦截；
//	不会执行任何 iptables / firewalld / ufw / nftables 操作。
//
// 多实例一致性（需求 R17）：
//
//	命令读写的是运行期同一个共享存储，因此在多实例部署下对全部实例即时生效
//	（前提是 stores[] 启用了 Redis；仅使用本地实现时只影响本机）。
func runBan(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "缺少 ban 子命令，可用：list / add / remove")
		fmt.Fprintln(stderr, "示例：waf ban list")
		return exitConfigError
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case banActionList:
		return runBanList(rest, stdout, stderr)
	case banActionAdd:
		return runBanAdd(rest, stdout, stderr)
	case banActionRemove:
		return runBanRemove(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知的 ban 子命令 %q，可用：list / add / remove\n", action)
		return exitConfigError
	}
}

// runBanList 列出当前封禁名单。
func runBanList(args []string, stdout, stderr io.Writer) int {
	loader, err := newBanFlagSet(banActionList, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseBanFlags(loader, args, stderr); code != exitOK {
		return code
	}

	stack, code := openBanStack(loader, stderr)
	if code != exitOK {
		return code
	}
	if stack == nil {
		return exitOK
	}
	defer func() { _ = stack.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), banCommandTimeout)
	defer cancel()

	entries, err := stack.bans.List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "读取封禁名单失败：%v\n", err)
		return exitRuntimeError
	}

	if len(entries) == 0 {
		// 名单为空时也把「查询维度」打出来：运维排查「为什么没封上」时，
		// 第一件要确认的事就是「运行期到底在查哪些维度的键」。
		fmt.Fprintf(stdout, "封禁名单为空（0 条；存储实例：%s；查询维度：%s）\n",
			strings.Join(stack.stores.Names(), ","), strings.Join(stack.bans.Scopes(), ","))
		return exitOK
	}

	// 按键排序：运维查看与人工比对时需要稳定顺序（存储实现的返回顺序不做保证）。
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })

	fmt.Fprintf(stdout, "共 %d 条封禁记录（存储实例：%s；主封禁维度：%s；查询维度：%s）\n",
		len(entries), strings.Join(stack.stores.Names(), ","), stack.bans.KeyKind(),
		strings.Join(stack.bans.Scopes(), ","))
	fmt.Fprintf(stdout, "%-44s %-12s %-20s %-22s %-36s %s\n",
		"封禁键", "剩余时长", "封禁维度", "检测目标", "触发URI", "规则 / 原因")
	for _, entry := range entries {
		rule := entry.RuleID
		if rule == "" {
			rule = "-"
		}
		fmt.Fprintf(stdout, "%-44s %-12s %-20s %-22s %-36s %s / %s\n",
			entry.Key, formatRemaining(entry.TTL), valueOrDash(entry.Scope),
			valueOrDash(entry.Target), valueOrDash(entry.URI), rule, entry.Reason)
	}
	return exitOK
}

// valueOrDash 用于封禁列表输出，避免空字段导致列错位。
func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// runBanAdd 新增一条封禁记录。
func runBanAdd(args []string, stdout, stderr io.Writer) int {
	loader, err := newBanFlagSet(banActionAdd, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	loader.fs.String("ttl", "", "封禁时长，例如 30m / 2h；留空使用 ban.default_ttl")
	loader.fs.String("reason", "", "封禁原因（写入名单值，便于运维排查）")

	if code := parseBanFlags(loader, args, stderr); code != exitOK {
		return code
	}
	if strings.TrimSpace(loader.ip) == "" {
		fmt.Fprintln(stderr, "参数 --ip 不能为空，示例：waf ban add --ip 1.2.3.4 --ttl 1h")
		return exitConfigError
	}

	ttl := time.Duration(0)
	if raw := strings.TrimSpace(loader.fs.Lookup("ttl").Value.String()); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			fmt.Fprintf(stderr, "参数 --ttl 格式非法（%s），示例：30m / 2h / 24h\n", raw)
			return exitConfigError
		}
		ttl = parsed
	}
	reason := loader.fs.Lookup("reason").Value.String()

	stack, code := openBanStack(loader, stderr)
	if code != exitOK {
		return code
	}
	if stack == nil {
		return exitOK
	}
	defer func() { _ = stack.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), banCommandTimeout)
	defer cancel()

	key, applied, err := stack.bans.Add(ctx, loader.ip, loader.site, ttl, reason)
	if err != nil {
		fmt.Fprintf(stderr, "写入封禁名单失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "已封禁 %s（键：%s；时长：%s；存储实例：%s）\n",
		strings.TrimSpace(loader.ip), key, applied, strings.Join(stack.stores.Names(), ","))
	fmt.Fprintln(stdout, "提示：封禁仅在本 WAF 内部生效，不涉及任何系统防火墙操作。")
	return exitOK
}

// runBanRemove 解除一条封禁记录。
func runBanRemove(args []string, stdout, stderr io.Writer) int {
	loader, err := newBanFlagSet(banActionRemove, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}

	if code := parseBanFlags(loader, args, stderr); code != exitOK {
		return code
	}
	if strings.TrimSpace(loader.ip) == "" {
		fmt.Fprintln(stderr, "参数 --ip 不能为空，示例：waf ban remove --ip 1.2.3.4")
		return exitConfigError
	}

	stack, code := openBanStack(loader, stderr)
	if code != exitOK {
		return code
	}
	if stack == nil {
		return exitOK
	}
	defer func() { _ = stack.Close() }()

	// 键必须由封禁管理器统一构造：与 banlist 查询键、autoban 写入键完全一致。
	key := stack.bans.KeyForClientIP(loader.ip, loader.site)
	if key == "" {
		fmt.Fprintln(stderr, "参数 --ip 不能为空")
		return exitConfigError
	}

	ctx, cancel := context.WithTimeout(context.Background(), banCommandTimeout)
	defer cancel()

	if err := stack.bans.Unban(ctx, key); err != nil {
		fmt.Fprintf(stderr, "解除封禁失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "已解除封禁（键：%s；存储实例：%s）\n",
		key, strings.Join(stack.stores.Names(), ","))
	return exitOK
}

// openBanStack 是 ban 各子命令共用的装配入口：加载配置 -> 构建存储与封禁管理器。
//
// 返回值语义：
//   - 退出码非 0：调用方直接返回该码；
//   - 退出码为 0 且 stack 为 nil：用户主动请求帮助（-h），正常退出。
func openBanStack(loader *banFlagSet, stderr io.Writer) (*storeStack, int) {
	resolved, _, code := loadResolved(loader.rest, stderr, "waf ban "+loader.action)
	if code != exitOK {
		return nil, code
	}
	if resolved == nil {
		// loadResolved 在用户请求 -h 时返回空配置与 0 退出码。
		return nil, exitOK
	}

	stack, err := buildStoreStack(resolved.Config, cliLogger(stderr), nil, loader.store)
	if err != nil {
		fmt.Fprintf(stderr, "共享存储装配失败：%v\n", err)
		return nil, exitConfigError
	}
	return stack, exitOK
}

// cliLogger 构造运维命令使用的系统日志器。
//
// 之所以只输出 warn 及以上级别且写入 stderr：
//   - stdout 只承载命令结果，便于管道与脚本直接消费；
//   - store / ban 层的 info 级日志（例如「已启用本地降级实现」）在交互式命令中
//     价值有限，而 warn / error（例如「多实例共享未启用」）必须让运维看见。
func cliLogger(stderr io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// formatRemaining 把剩余封禁时长渲染为可读文本。
func formatRemaining(remaining time.Duration) string {
	if remaining <= 0 {
		return "-"
	}
	return remaining.Round(time.Second).String()
}

// banFlagSet 承载 ban 子命令的参数解析中间结果。
//
// 之所以需要一个中间层：ban 的参数分为两类——
// 子命令自身的业务参数（--ip / --site / --store）与全局配置参数（-c / --set）。
// 前者由本结构解析，后者原样透传给 config.FlagSet。
type banFlagSet struct {
	// action 是子命令名（list / add / remove），仅用于日志与用法提示。
	action string
	// fs 是业务参数集合。
	fs *flag.FlagSet
	// cfg 是配置体系参数集合，用于识别 -c / --set 等全局参数（不负责解析）。
	cfg *config.FlagSet
	// rest 是透传给 config.FlagSet 的剩余参数（未识别的参数会被收集到这里）。
	rest []string
	// ip 保存 --ip 的值。
	ip string
	// site 保存 --site 的值（配合 ban.ban_key = client_ip+site 使用）。
	site string
	// store 保存 --store 的值（指定封禁写入哪个存储实例）。
	store string
}

// newBanFlagSet 创建 ban 业务参数集合，并登记各子命令共用的业务参数。
func newBanFlagSet(action string, stderr io.Writer) (*banFlagSet, error) {
	fs := flag.NewFlagSet("waf ban "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("ip", "", "客户端 IP（必填）")
	fs.String("site", "", "站点名；仅在 ban.ban_key = client_ip+site 时需要")
	fs.String("store", "", "封禁写入使用的存储实例名；留空使用默认存储")

	// 配置体系参数集合：只用于识别哪些参数属于配置通道（-c / --config / --set
	// 以及全部标量配置项），实际的配置解析仍由 openBanStack -> loadResolved 完成。
	cfgFlags, err := config.NewFlagSet("waf ban "+action, stderr)
	if err != nil {
		return nil, err
	}
	return &banFlagSet{action: action, fs: fs, cfg: cfgFlags}, nil
}

// parseBanFlags 解析 ban 业务参数，并把配置体系参数保留到 rest 中。
//
// 之所以采用「先拆分、再各自解析」的两段式：
//
//	标准库 flag 不支持「部分已知 + 其余透传」，遇到未定义的参数会直接报错；
//	而 ban 子命令需要同时接受业务参数（--ip / --ttl）与全局配置参数（-c / --set）。
//	因此这里先按参数名把两类参数分开，配置体系参数原样交给下一层的 config.FlagSet。
//
// 该函数被 ban / rules 等全部需要「业务参数 + 配置参数」混用的子命令复用。
func parseBanFlags(loader *banFlagSet, args []string, stderr io.Writer) int {
	business, global := splitConfigArgs(loader.cfg, args)

	if err := loader.fs.Parse(business); err != nil {
		// flag 包已输出错误详情；-h 属于正常退出。
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitConfigError
	}

	loader.ip = loader.fs.Lookup("ip").Value.String()
	loader.site = loader.fs.Lookup("site").Value.String()
	loader.store = loader.fs.Lookup("store").Value.String()
	loader.rest = append(loader.rest, global...)
	// 业务参数之外的位置参数（ban 子命令不接受位置参数）保留在 rest 中，
	// 以便 config.FlagSet 给出统一的「未知参数」报错，而不是被静默忽略。
	loader.rest = append(loader.rest, loader.fs.Args()...)
	_ = stderr
	return exitOK
}

// splitConfigArgs 把参数列表拆分为「业务参数」与「配置体系参数」。
//
// 拆分规则：
//   - 已知的配置体系参数（含 -c / --config / --set 与全部标量配置项）归入 global；
//   - 其余以短横线开头的参数归入 business；
//   - 取值形式支持 "-x v" 与 "-x=v" 两种写法；前者的取值归入同一个集合，
//     避免把某个参数的取值误判成另一个集合的参数。
func splitConfigArgs(cfgFlags *config.FlagSet, args []string) (business, global []string) {
	// pendingGlobal / pendingBusiness 表示「上一个参数需要独立取值」。
	var pendingGlobal, pendingBusiness bool

	for _, arg := range args {
		switch {
		case pendingGlobal:
			global = append(global, arg)
			pendingGlobal = false
		case pendingBusiness:
			business = append(business, arg)
			pendingBusiness = false
		case !strings.HasPrefix(arg, "-"):
			business = append(business, arg)
		default:
			name, inlineValue := splitFlagName(arg)
			if cfgFlags.IsConfigFlag(name) {
				global = append(global, arg)
				pendingGlobal = !inlineValue
				continue
			}
			business = append(business, arg)
			pendingBusiness = !inlineValue
		}
	}
	return business, global
}

// splitFlagName 解析参数名的形态，返回参数名与其是否已内联取值。
//
// 支持 -x / --x / -x=v / --x=v 四种写法。
func splitFlagName(arg string) (name string, inlineValue bool) {
	trimmed := strings.TrimLeft(arg, "-")
	if index := strings.Index(trimmed, "="); index >= 0 {
		return trimmed[:index], true
	}
	return trimmed, false
}
