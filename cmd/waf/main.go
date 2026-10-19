// Command waf 是 WAF 的主入口，提供 forward-auth 前置校验服务与配套运维子命令。
//
// 命令行形态（设计文档 §2.8）：
//
//	waf run          启动 forward-auth 服务（默认命令）
//	waf check-config 仅加载并校验配置，输出生效配置与来源摘要
//	waf config print 输出默认或叠加后的生效配置
//	waf version      输出版本、提交号与构建时间
//	waf healthz      供容器 HEALTHCHECK 调用的本地存活探测
//	waf ban          封禁名单运维（读写共享存储）
//	waf rules        规则包运维（校验 / 打包 / 原子升级 / 回滚 / 热加载触发）
//	waf report       审计与报表（DetectionOnly 试运行「若拦截」清单等）
//
// 配置三通道与优先级（需求 R15 / R16）：CLI > 配置文件 > 环境变量 > 内置默认值。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
)

// 进程退出码约定，供容器编排与 CI 区分失败类型。
const (
	// exitOK 表示执行成功。
	exitOK = 0
	// exitRuntimeError 表示运行期错误（监听失败、服务异常退出等）。
	exitRuntimeError = 1
	// exitConfigError 表示配置错误（校验失败、未知配置项、类型不匹配等）。
	// 单列一个退出码，方便 CI 在配置校验失败时快速定位，而不必解析日志。
	exitConfigError = 2
)

// 子命令名称常量。集中定义避免各处拼写不一致。
const (
	cmdRun         = "run"
	cmdCheckConfig = "check-config"
	cmdConfig      = "config"
	cmdVersion     = "version"
	cmdHealthz     = "healthz"
	cmdBan         = "ban"
	cmdRules       = "rules"
	cmdDB          = "db"
	cmdReport      = "report"
	cmdHelp        = "help"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 是 main 的可测试入口：解析子命令并分发，返回进程退出码。
//
// 之所以把逻辑收进 run 而不是写在 main 里：便于单元测试直接断言退出码与输出，
// 无需 fork 子进程。
func run(args []string, stdout, stderr io.Writer) int {
	command, rest := splitCommand(args)

	switch command {
	case cmdVersion:
		return runVersion(stdout)
	case cmdCheckConfig:
		return runCheckConfig(rest, stdout, stderr)
	case cmdConfig:
		return runConfig(rest, stdout, stderr)
	case cmdRun:
		return runServe(rest, stdout, stderr)
	case cmdHealthz:
		return runHealthz(rest, stdout, stderr)
	case cmdBan:
		return runBan(rest, stdout, stderr)
	case cmdRules:
		return runRules(rest, stdout, stderr)
	case cmdDB:
		return runDB(rest, stdout, stderr)
	case cmdReport:
		return runReport(rest, stdout, stderr)
	case cmdHelp, "-h", "--help":
		printUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "未知命令 %q\n\n", command)
		printUsage(stderr)
		return exitConfigError
	}
}

// splitCommand 拆分子命令与其余参数。
//
// 约定：首个非选项参数即为子命令；若首个参数以 "-" 开头则视为「未指定子命令」，
// 此时使用默认命令 run，使 `waf --config x.yaml` 与 `waf run --config x.yaml` 等价。
func splitCommand(args []string) (command string, rest []string) {
	if len(args) == 0 {
		return cmdRun, nil
	}
	if strings.HasPrefix(args[0], "-") {
		return cmdRun, args
	}
	return args[0], args[1:]
}

// printUsage 输出命令行用法说明。
func printUsage(w io.Writer) {
	fmt.Fprint(w, `waf —— forward-auth 前置校验 WAF

用法：
  waf <命令> [参数]

命令：
  run            启动 forward-auth 鉴权服务（默认命令）
  check-config   加载并校验配置，输出生效配置与来源摘要
  config        配置工具（print：输出默认或叠加后的生效配置）
  version        输出版本、提交号与构建时间
  healthz        探测本地 /healthz（供容器 HEALTHCHECK 使用）
  ban            封禁名单运维（list / add / remove）
  rules          规则包运维（list / verify / manifest / install / rollback / reload）
  db             运行期数据库运维（status / import-config）
  report         审计与报表（detection：DetectionOnly 试运行「若拦截」清单）
  help           显示本帮助

通用参数：
  -c, -config <路径>   配置文件或目录，可多次指定（后者覆盖前者）
                       目录内按文件名字典序加载 .yaml/.yml/.json，并启用热重载
                       未指定时若 /etc/waf/waf.yaml 存在则自动加载
  -set <路径>=<值>     按配置路径覆盖任意标量配置项，可多次指定

配置优先级（高到低）：CLI > 配置文件 > 环境变量 > 内置默认值
环境变量命名（由配置路径机械推导）：ban.default_ttl -> WAF_BAN_DEFAULT_TTL
查看全部可用参数：waf run -h
`)
}

// loadResolved 是各子命令共用的配置加载入口。
//
// 返回值为：生效配置、CLI 通道（供子命令读取额外参数）、进程退出码。
// 退出码非 0 时调用方应直接返回该码。
func loadResolved(args []string, stderr io.Writer, command string) (*config.Resolved, *config.FlagSet, int) {
	flagSet, err := config.NewFlagSet(command, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return nil, nil, exitConfigError
	}

	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// 用户主动请求帮助，属于正常退出。
			return nil, nil, exitOK
		}
		// flag 包已把错误信息写入 stderr，这里只需给出退出码。
		return nil, nil, exitConfigError
	}

	resolved, err := config.Load(config.Options{
		ConfigFiles: flagSet.ConfigFiles(),
		CLI:         flagSet,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return nil, nil, exitConfigError
	}
	return resolved, flagSet, exitOK
}
