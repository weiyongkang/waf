package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/rules"
	"github.com/weiyongkang/waf/internal/rules/exceptions"
)

// rules 子命令的动作名称常量。
const (
	rulesActionList     = "list"
	rulesActionVerify   = "verify"
	rulesActionManifest = "manifest"
	rulesActionInstall  = "install"
	rulesActionRollback = "rollback"
	rulesActionReload   = "reload"
)

// runRules 实现 rules 子命令：规则包的查看、校验、打包、升级、回滚与热加载触发。
//
// 命令形态（设计文档 §2.8 的运维子命令约定）：
//
//	waf rules list     [-c 配置] [--json]                              查看运行态会加载的规则集与例外审计清单
//	waf rules verify   --dir 目录 [-c 配置] [--json]                    按清单校验规则包完整性
//	waf rules manifest --dir 目录 --name 名 --package-version 版本       为规则目录生成 manifest.yaml
//	waf rules install  --source 新目录 --target 在线目录       原子替换规则目录（自动保留上一版本）
//	waf rules rollback --target 在线目录                      回滚到上一版本
//	waf rules reload   [-c 配置]                             触发运行中实例重新加载规则
//
// 与运行态的关系（重要）：除 reload 外，这些命令都**只操作文件与只读校验**，
// 不会连接运行中的服务、也不会修改任何进程内状态。
// 之所以这样设计：规则包的分发与验证属于构建/发布流水线的职责，
// 让它依赖「服务在线」会引入不必要的耦合与权限面（管理面下调到 P3 的原因之一）。
func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "缺少 rules 子命令，可用：list / verify / manifest / install / rollback / reload")
		fmt.Fprintln(stderr, "示例：waf rules list")
		return exitConfigError
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case rulesActionList:
		return runRulesList(rest, stdout, stderr)
	case rulesActionVerify:
		return runRulesVerify(rest, stdout, stderr)
	case rulesActionManifest:
		return runRulesManifest(rest, stdout, stderr)
	case rulesActionInstall:
		return runRulesInstall(rest, stdout, stderr)
	case rulesActionRollback:
		return runRulesRollback(rest, stdout, stderr)
	case rulesActionReload:
		return runRulesReload(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知的 rules 子命令 %q，可用：list / verify / manifest / install / rollback / reload\n", action)
		return exitConfigError
	}
}

// rulesFlagSet 承载 rules 子命令的参数解析中间结果。
//
// 与 ban 子命令同构：业务参数（--dir / --name ...）由本结构解析，
// 配置体系参数（-c / --set 与全部标量配置项）原样透传给 config.FlagSet。
type rulesFlagSet struct {
	// action 是子命令名，用于用法提示。
	action string
	// fs 是业务参数集合。
	fs *flag.FlagSet
	// cfg 是配置体系参数集合，用于识别 -c / --set 等全局参数。
	cfg *config.FlagSet
	// rest 是透传给 config.FlagSet 的剩余参数。
	rest []string
	// jsonOutput 决定是否以 JSON 输出（便于流水线消费）。
	jsonOutput bool
}

// newRulesFlagSet 创建 rules 业务参数集合。
func newRulesFlagSet(action string, stderr io.Writer) (*rulesFlagSet, error) {
	fs := flag.NewFlagSet("waf rules "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	// 所有子命令共用的业务参数在此统一登记：
	// 未使用的参数保持零值即可，比按子命令分别注册更不容易漏项。
	fs.String("dir", "", "规则目录（verify / manifest 使用）")
	fs.String("source", "", "规则包源目录（install 使用）")
	fs.String("target", "", "在线规则目录（install / rollback 使用）")
	fs.String("name", "", "规则包名（manifest 使用）")
	// 注意：这里刻意不叫 --version。
	//
	// 配置体系里存在同名的标量 version（配置格式版本，对应配置文件顶层 version 字段），
	// 业务参数与它同名时会被 splitConfigArgs 归入配置通道，表现为「参数被静默吞掉」：
	// 命令不报错、但版本号拿不到。因此业务参数一律带上语义前缀（package-version）。
	fs.String("package-version", "", "规则包版本（manifest 使用）")
	fs.String("source-url", "", "规则包来源说明，写入清单用于审计（manifest 使用）")
	fs.Bool("json", false, "以 JSON 输出结果（便于流水线消费）")

	cfgFlags, err := config.NewFlagSet("waf rules "+action, stderr)
	if err != nil {
		return nil, err
	}
	if err := ensureBusinessFlagsDistinct(cfgFlags, rulesBusinessFlags); err != nil {
		return nil, err
	}
	return &rulesFlagSet{action: action, fs: fs, cfg: cfgFlags}, nil
}

// rulesBusinessFlags 列出 rules 子命令的业务参数名。
//
// 该清单的唯一用途是「与配置体系参数做冲突检测」（见 ensureBusinessFlagsDistinct）：
// 新增业务参数时必须同步登记，否则冲突检查会漏掉它。
var rulesBusinessFlags = []string{
	"dir", "source", "target", "name", "package-version", "source-url", "json",
}

// ensureBusinessFlagsDistinct 校验业务参数与配置体系参数不重名。
//
// 为什么需要这道检查：业务参数若与配置体系参数同名，splitConfigArgs 会把它
// 归入配置通道并交给 config.FlagSet 解析，命令本身拿到的值恒为空——
// 表现为「参数写对了却不生效」，且没有任何报错。把它变成构造期的硬错误，
// 可以让这类问题在开发/测试阶段就暴露，而不是等运维在流水线里踩到。
func ensureBusinessFlagsDistinct(cfgFlags *config.FlagSet, names []string) error {
	for _, name := range names {
		if cfgFlags.IsConfigFlag(name) {
			return fmt.Errorf("业务参数 --%s 与配置体系参数重名："+
				"请为业务参数换一个带语义前缀的名字（否则该参数会被静默归入配置通道）", name)
		}
	}
	return nil
}

// parseRulesFlags 解析 rules 业务参数，其余参数透传给配置通道。
func parseRulesFlags(loader *rulesFlagSet, args []string, stderr io.Writer) int {
	business, global := splitConfigArgs(loader.cfg, args)

	if err := loader.fs.Parse(business); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitConfigError
	}

	loader.jsonOutput = loader.fs.Lookup("json").Value.String() == "true"
	loader.rest = append(loader.rest, global...)
	loader.rest = append(loader.rest, loader.fs.Args()...)
	_ = stderr
	return exitOK
}

// stringFlag 返回业务参数的字符串取值。
func (l *rulesFlagSet) stringFlag(name string) string {
	return strings.TrimSpace(l.fs.Lookup(name).Value.String())
}

// runRulesList 输出「运行态会加载的规则集」与「误报例外审计清单」。
//
// 之所以用真实的 rules.Load 路径而不是直接列目录：
//
//	运维在排障时最需要确认的是「线上到底加载了哪些文件、多少条规则」，
//	而不是「目录里有什么」。用与运行态完全相同的加载逻辑，才能避免
//	「CLI 说加载了、实际没加载」这类口径差异（也是 M1.5 建立契约测试的同一动机）。
func runRulesList(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionList, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules list")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config
	engine := cfg.Engine

	set, err := rules.Load(rules.Options{
		Source: rules.Source{
			Dirs:        engine.Rules.Dirs,
			CustomDirs:  engine.Rules.CustomDirs,
			Include:     engine.Rules.Include,
			DataInclude: engine.Rules.DataInclude,
			CRSSetup:    engine.Rules.CRSSetup,
		},
		MaxFileBytes:  cfg.Limits.MaxRuleFileBytes,
		MaxTotalBytes: cfg.Limits.MaxRulesTotalBytes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "规则集加载失败：%v\n", err)
		return exitConfigError
	}

	exceptionSet, err := exceptions.Compile(exceptionSettings(engine.Exceptions), exceptions.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "误报例外编译失败：%v\n", err)
		return exitConfigError
	}

	if loader.jsonOutput {
		return writeRulesListJSON(stdout, stderr, cfg, set, exceptionSet)
	}

	fmt.Fprintf(stdout, "规则集来源：%s\n", set.Source)
	fmt.Fprintf(stdout, "规则文件：%d 个（其中规则 %d 个）；数据文件合计 %d 个；总字节 %d\n",
		set.FileCount, set.Rules, set.FileCount-set.Rules, set.TotalBytes)
	fmt.Fprintf(stdout, "引擎模式：%s；偏执等级：PL%d；异常评分阈值：%d\n",
		engine.Mode, engine.ParanoiaLevel, engine.AnomalyScoreThreshold)
	fmt.Fprintf(stdout, "热加载：%v（轮询 %s；标记文件 %s）\n",
		engine.HotReload.Enabled, engine.HotReload.PollInterval.Duration(), displayOrDash(engine.HotReload.MarkerFile))

	fmt.Fprintln(stdout, "\n加载的规则文件：")
	for _, file := range set.Files {
		fmt.Fprintf(stdout, "  - %s\n", file)
	}

	fmt.Fprintf(stdout, "\n误报例外：共 %d 条，其中生效 %d 条（作用域规则 %d 条，全局指令 %d 条）\n",
		len(exceptionSet.Entries), exceptionSet.Applied, len(exceptionSet.Pre), len(exceptionSet.Post))
	if len(exceptionSet.Entries) == 0 {
		fmt.Fprintln(stdout, "  （未配置任何例外）")
		return exitOK
	}
	fmt.Fprintf(stdout, "  %-28s %-10s %-24s %s\n", "名称", "状态", "作用范围", "原因")
	for _, entry := range exceptionSet.Entries {
		fmt.Fprintf(stdout, "  %-28s %-10s %-24s %s\n",
			truncateText(entry.Name, 28), string(entry.Status), truncateText(entry.Scope, 24), entry.Reason)
		for _, directive := range entry.Directives {
			fmt.Fprintf(stdout, "      指令：%s\n", strings.ReplaceAll(directive, "\n", " | "))
		}
	}
	return exitOK
}

// rulesListPayload 是 `rules list --json` 的输出结构。
type rulesListPayload struct {
	Source                string            `json:"source"`
	Files                 []string          `json:"files"`
	FileCount             int               `json:"file_count"`
	RuleCount             int               `json:"rule_count"`
	TotalBytes            int64             `json:"total_bytes"`
	Mode                  string            `json:"mode"`
	ParanoiaLevel         int               `json:"paranoia_level"`
	AnomalyScoreThreshold int               `json:"anomaly_score_threshold"`
	HotReload             hotReloadPayload  `json:"hot_reload"`
	Exceptions            []exceptionRecord `json:"exceptions"`
}

// hotReloadPayload 是热加载配置的输出结构。
type hotReloadPayload struct {
	Enabled      bool   `json:"enabled"`
	Debounce     string `json:"debounce"`
	PollInterval string `json:"poll_interval"`
	MarkerFile   string `json:"marker_file"`
}

// exceptionRecord 是例外审计的输出结构。
type exceptionRecord struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Scope      string   `json:"scope"`
	Reason     string   `json:"reason"`
	Directives []string `json:"directives"`
}

// writeRulesListJSON 以 JSON 输出规则集信息。
func writeRulesListJSON(stdout, stderr io.Writer, cfg *config.Config, set *rules.Set, exceptionSet *exceptions.Set) int {
	payload := rulesListPayload{
		Source:                set.Source,
		Files:                 set.Files,
		FileCount:             set.FileCount,
		RuleCount:             set.Rules,
		TotalBytes:            set.TotalBytes,
		Mode:                  cfg.Engine.Mode,
		ParanoiaLevel:         cfg.Engine.ParanoiaLevel,
		AnomalyScoreThreshold: cfg.Engine.AnomalyScoreThreshold,
		HotReload: hotReloadPayload{
			Enabled:      cfg.Engine.HotReload.Enabled,
			Debounce:     cfg.Engine.HotReload.Debounce.Duration().String(),
			PollInterval: cfg.Engine.HotReload.PollInterval.Duration().String(),
			MarkerFile:   cfg.Engine.HotReload.MarkerFile,
		},
		Exceptions: make([]exceptionRecord, 0, len(exceptionSet.Entries)),
	}
	for _, entry := range exceptionSet.Entries {
		payload.Exceptions = append(payload.Exceptions, exceptionRecord{
			Name:       entry.Name,
			Status:     string(entry.Status),
			Scope:      entry.Scope,
			Reason:     entry.Reason,
			Directives: entry.Directives,
		})
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintf(stderr, "输出 JSON 失败：%v\n", err)
		return exitRuntimeError
	}
	return exitOK
}

// runRulesVerify 校验规则包目录与清单是否一致。
func runRulesVerify(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionVerify, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	dir := loader.stringFlag("dir")
	if dir == "" {
		fmt.Fprintln(stderr, "参数 --dir 不能为空（示例：waf rules verify --dir /etc/waf/rules）")
		return exitConfigError
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules verify")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}

	report, err := rules.Verify(dir, resolved.Config.Limits.MaxRuleFileBytes)
	if err != nil {
		fmt.Fprintf(stderr, "规则包校验失败：%v\n", err)
		return exitConfigError
	}

	if loader.jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(stderr, "输出 JSON 失败：%v\n", err)
			return exitRuntimeError
		}
		return verifyExitCode(report)
	}

	fmt.Fprintf(stdout, "规则包：%s %s（来源：%s；生成时间：%s）\n",
		report.Manifest.Name, report.Manifest.Version,
		displayOrDash(report.Manifest.Source), displayOrDash(report.Manifest.Created))
	fmt.Fprintf(stdout, "清单声明文件：%d 个；总字节：%d\n",
		len(report.Manifest.Files), report.TotalBytes)
	fmt.Fprintf(stdout, "缺失文件：%d 个 %v\n", len(report.Missing), report.Missing)
	fmt.Fprintf(stdout, "摘要不一致：%d 个 %v\n", len(report.Mismatched), report.Mismatched)
	fmt.Fprintf(stdout, "清单未声明的多余文件：%d 个 %v\n", len(report.Unexpected), report.Unexpected)

	if report.OK() {
		fmt.Fprintln(stdout, "校验结果：通过")
	} else {
		fmt.Fprintln(stdout, "校验结果：未通过（请勿把该规则包投入使用）")
	}
	return verifyExitCode(report)
}

// verifyExitCode 把校验结果映射为退出码。
//
// 「多余文件」单独用一个退出码（3）：它通常意味着「升级残留」，
// 虽然清单声明的文件都对，但多出来的文件会被加载并改变检测行为，必须人工确认。
func verifyExitCode(report *rules.VerifyReport) int {
	if !report.OK() {
		return exitConfigError
	}
	if len(report.Unexpected) > 0 {
		return exitUnexpectedFiles
	}
	return exitOK
}

// exitUnexpectedFiles 表示规则包校验「文件齐全但有清单未声明的多余文件」。
const exitUnexpectedFiles = 3

// runRulesManifest 为规则目录生成清单文件。
func runRulesManifest(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionManifest, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	dir := loader.stringFlag("dir")
	name := loader.stringFlag("name")
	// 参数名用 --package-version 而不是 --version：后者与配置体系的 version 字段重名，
	// 会被归入配置通道（详见 newRulesFlagSet 中的说明）。
	version := loader.stringFlag("package-version")
	if dir == "" || name == "" || version == "" {
		fmt.Fprintln(stderr, "参数 --dir / --name / --package-version 均不能为空")
		fmt.Fprintln(stderr, "示例：waf rules manifest --dir ./rules --name owasp-crs --package-version 4.7.0")
		return exitConfigError
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules manifest")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config

	manifest, err := rules.BuildManifest(
		dir,
		cfg.Engine.Rules.Include,
		cfg.Engine.Rules.DataInclude,
		cfg.Engine.Rules.CRSSetup,
		cfg.Limits.MaxRuleFileBytes,
		rules.ManifestMeta{
			Name:    name,
			Version: version,
			Source:  loader.stringFlag("source-url"),
			// 显式传入时间：便于在流水线中生成可复现的清单（同一份输入产出同一份文件）。
			Now: time.Now(),
		},
	)
	if err != nil {
		fmt.Fprintf(stderr, "生成规则包清单失败：%v\n", err)
		return exitConfigError
	}

	path, err := rules.WriteManifest(dir, manifest)
	if err != nil {
		fmt.Fprintf(stderr, "写入规则包清单失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "已生成规则包清单：%s\n", path)
	fmt.Fprintf(stdout, "规则包：%s %s；文件 %d 个；总字节 %d\n", manifest.Name, manifest.Version, len(manifest.Files), manifestTotalBytes(manifest))
	return exitOK
}

// runRulesInstall 把新规则包原子安装到在线规则目录。
func runRulesInstall(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionInstall, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	source := loader.stringFlag("source")
	target := loader.stringFlag("target")
	if source == "" || target == "" {
		fmt.Fprintln(stderr, "参数 --source / --target 均不能为空")
		fmt.Fprintln(stderr, "示例：waf rules install --source ./rules-4.7.0 --target /etc/waf/rules")
		return exitConfigError
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules install")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config

	result, err := rules.Install(source, target, rules.InstallOptions{
		MaxFileBytes:  cfg.Limits.MaxRuleFileBytes,
		MaxTotalBytes: cfg.Limits.MaxRulesTotalBytes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "规则包安装失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "规则包已原子安装到：%s\n", result.Target)
	fmt.Fprintf(stdout, "安装文件：%d 个；总字节：%d\n", result.Files, result.TotalBytes)
	if result.Previous != "" {
		fmt.Fprintf(stdout, "已保留上一版本（可回滚）：%s\n", result.Previous)
	} else {
		fmt.Fprintln(stdout, "本次为首次安装，没有可回滚的上一版本")
	}
	fmt.Fprintln(stdout, "提示：运行中的实例会在下一次轮询（engine.hot_reload.poll_interval）后自动加载新规则；"+
		"也可执行 waf rules reload 立即触发。")
	return exitOK
}

// runRulesRollback 回滚到上一版本规则包。
func runRulesRollback(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionRollback, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	target := loader.stringFlag("target")
	if target == "" {
		fmt.Fprintln(stderr, "参数 --target 不能为空（示例：waf rules rollback --target /etc/waf/rules）")
		return exitConfigError
	}

	// 回滚只操作文件系统，但保留配置通道解析：一方面统一参数体验，
	// 另一方面沿用 limits 中的限额做文件操作保护。
	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules rollback")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}

	failedDir, err := rules.Rollback(target, rules.InstallOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "规则包回滚失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "已回滚：%s 现在是上一版本\n", target)
	fmt.Fprintf(stdout, "回滚前的版本已保留在：%s（确认无误后可手工清理）\n", failedDir)
	return exitOK
}

// runRulesReload 触发运行中实例重新加载规则。
//
// 实现方式（设计取舍）：更新 engine.hot_reload.marker_file 的时间戳。
//
//	运行中的实例在轮询规则目录指纹的同时，也会检查该标记文件的时间戳；
//	时间戳变化即触发一次重载。这样做的原因：
//	  - 不需要管理面 HTTP API（管理面已下调到 P3，不该被 M2 阻塞）；
//	  - 不依赖任何信号（Windows 上 SIGHUP 不可用，跨平台一致性差）；
//	  - 触发动作与「规则目录变化」走同一条代码路径，行为完全一致。
func runRulesReload(args []string, stdout, stderr io.Writer) int {
	loader, err := newRulesFlagSet(rulesActionReload, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseRulesFlags(loader, args, stderr); code != exitOK {
		return code
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf rules reload")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	hot := resolved.Config.Engine.HotReload

	if !hot.Enabled {
		fmt.Fprintln(stderr, "engine.hot_reload.enabled = false，运行中的实例不会监听规则变化；"+
			"请开启热加载，或重启服务使新规则生效")
		return exitConfigError
	}
	marker := strings.TrimSpace(hot.MarkerFile)
	if marker == "" {
		fmt.Fprintln(stderr, "未配置 engine.hot_reload.marker_file，无法主动触发重载；"+
			"规则目录变化仍会在下一次轮询后自动生效")
		return exitConfigError
	}

	if err := touchFile(marker); err != nil {
		fmt.Fprintf(stderr, "更新重载标记文件失败：%v\n", err)
		return exitRuntimeError
	}

	fmt.Fprintf(stdout, "已触发重载：%s（运行中的实例将在下一次轮询后原子替换检测引擎）\n", marker)
	fmt.Fprintln(stdout, "提示：重载失败时旧引擎会继续服务，具体结果请查看系统日志中的「规则热加载」记录。")
	return exitOK
}

// touchFile 更新文件时间戳；文件不存在时创建。
func touchFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// 目录可能不存在（例如标记文件放在日志目录下且该目录尚未创建）。
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return file.Close()
	}

	now := time.Now()
	return os.Chtimes(path, now, now)
}

// manifestTotalBytes 汇总清单声明的总字节数。
func manifestTotalBytes(manifest *rules.Manifest) int64 {
	var total int64
	for _, entry := range manifest.Files {
		total += entry.Size
	}
	return total
}

// displayOrDash 把空字符串渲染为占位符，保证表格列对齐。
func displayOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// truncateText 按「字符数」截断文本，用于固定宽度表格。
//
// 与 coraza 内部的按字节截断不同：这里面向终端输出，
// 按字符截断才不会把中文切成半个字（乱码）。
func truncateText(value string, limit int) string {
	runes := []rune(value)
	if limit <= 0 || len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}
