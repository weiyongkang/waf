package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/fsx"
)

// report 子命令的动作名称常量。
const (
	reportActionDetection = "detection"
	reportActionAttack    = "attack"
	reportActionBan       = "ban"
)

// reportDefaultTop 是排行类报表默认展示的条目数。
const reportDefaultTop = 20

// runReport 实现 report 子命令：从访问日志生成审计与运行报表。
//
// 命令形态：
//
//	waf report detection [-c 配置] [--dir 日志目录] [--since 24h] [--top 20] [--json]
//	waf report attack    [-c 配置] [--dir 日志目录] [--since 24h] [--top 20] [--json]
//	waf report ban       [-c 配置] [--dir 日志目录] [--since 24h] [--top 20] [--json]
//
// 全部子命令都支持把结果导出为文件（需求 P1-9）：
//
//	waf report attack --out /var/tmp/attack.xlsx      （按扩展名推断格式）
//	waf report attack --format csv --out /var/tmp/a.csv
//	waf report attack --format csv > /var/tmp/a.csv   （省略 --out 时写标准输出）
//
// 报表的定位与边界：
//
//	报表直接消费**访问日志**（JSON Lines），不依赖任何运行中的服务或额外组件。
//	这样做的原因：日志是唯一「已经落盘、不可篡改（可归档）」的事实来源，
//	基于它做统计可以让报表在服务重启、实例扩容、甚至整机下线后依然可复现。
//
// 为什么不引入数据库/时序库：报表需求是「按需、离线、可复现」，
// 引入有状态组件会显著提高部署复杂度，与管理面下调到 P3 的判断一致。
func runReport(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "缺少 report 子命令，可用：detection / attack / ban")
		fmt.Fprintln(stderr, "示例：waf report detection --since 24h")
		return exitConfigError
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case reportActionDetection:
		return runReportDetection(rest, stdout, stderr)
	case reportActionAttack:
		return runReportAttack(rest, stdout, stderr)
	case reportActionBan:
		return runReportBan(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知的 report 子命令 %q，可用：detection / attack / ban\n", action)
		return exitConfigError
	}
}

// reportFlagSet 承载 report 子命令的参数解析中间结果。
type reportFlagSet struct {
	// action 是子命令名。
	action string
	// fs 是业务参数集合。
	fs *flag.FlagSet
	// cfg 是配置体系参数集合。
	cfg *config.FlagSet
	// rest 是透传给 config.FlagSet 的剩余参数。
	rest []string
	// jsonOutput 决定是否以 JSON 输出。
	jsonOutput bool
}

// newReportFlagSet 创建 report 业务参数集合。
func newReportFlagSet(action string, stderr io.Writer) (*reportFlagSet, error) {
	fs := flag.NewFlagSet("waf report "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("dir", "", "访问日志目录；留空时使用 logging.access.dir")
	fs.Duration("since", 0, "只统计最近这段时间内的记录，例如 24h / 7*24h；为 0 表示不限时间")
	fs.Int("top", reportDefaultTop, "排行类报表展示的条目数")
	fs.Bool("json", false, "以 JSON 输出结果（便于流水线消费）")
	fs.String("format", reportFormatTable, "输出格式：table（默认，人读表格）/ csv / xlsx")
	fs.String("out", "", "导出文件路径；省略时导出内容写到标准输出（按扩展名推断格式）")

	cfgFlags, err := config.NewFlagSet("waf report "+action, stderr)
	if err != nil {
		return nil, err
	}
	// 与 rules 子命令同样的冲突检测：业务参数一旦和配置体系参数重名会被静默吞掉。
	if err := ensureBusinessFlagsDistinct(cfgFlags, reportBusinessFlags); err != nil {
		return nil, err
	}
	return &reportFlagSet{action: action, fs: fs, cfg: cfgFlags}, nil
}

// reportBusinessFlags 列出 report 子命令的业务参数名（用于与配置体系参数做冲突检测）。
var reportBusinessFlags = []string{"dir", "since", "top", "json", "format", "out"}

// parseReportFlags 解析 report 业务参数。
func parseReportFlags(loader *reportFlagSet, args []string, stderr io.Writer) int {
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
func (l *reportFlagSet) stringFlag(name string) string {
	return strings.TrimSpace(l.fs.Lookup(name).Value.String())
}

// durationFlag 返回业务参数的时长取值。
func (l *reportFlagSet) durationFlag(name string) time.Duration {
	value := l.fs.Lookup(name).Value.String()
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

// intFlag 返回业务参数的整数取值。
func (l *reportFlagSet) intFlag(name string) int {
	var value int
	_, err := fmt.Sscanf(l.fs.Lookup(name).Value.String(), "%d", &value)
	if err != nil {
		return 0
	}
	return value
}

// accessRecord 是访问日志中一行记录的解析结果。
//
// 只声明报表需要的字段：访问日志的具体字段集合由 internal/server 决定，
// 报表按「缺失即忽略」的方式读取，因此新增日志字段不会导致报表失效
// （这是 JSON 日志相对于固定列格式的优势）。
type accessRecord struct {
	Time              time.Time `json:"time"`
	Level             string    `json:"level"`
	Message           string    `json:"msg"`
	RequestID         string    `json:"request_id"`
	Verdict           string    `json:"verdict"`
	Check             string    `json:"check"`
	Site              string    `json:"site"`
	Method            string    `json:"method"`
	Path              string    `json:"path"`
	Host              string    `json:"host"`
	ClientIP          string    `json:"client_ip"`
	RuleID            string    `json:"rule_id"`
	WouldBlock        bool      `json:"would_block"`
	WouldBlockReason  string    `json:"would_block_reason"`
	Score             int       `json:"score"`
	Status            int       `json:"status"`
	DurationMillisecs int64     `json:"duration_ms"`
}

// loadAccessRecords 读取访问日志目录中的全部记录。
//
// 实现要点：
//   - 用 fsx.ScanLines 逐行读取：单文件受 limits.max_rule_file_bytes 同级的
//     「单行长度」约束保护，不会因为某一行异常巨大而打爆内存（需求 R13）；
//   - 逐行 json.Unmarshal，遇到损坏行立刻报错并指出文件名与行号：
//     报表如果静默跳过坏行，会让「统计结果偏小」这类问题极难发现。
func loadAccessRecords(dir string, prefix string, maxFileBytes int64, maxLineBytes int, since time.Duration, now time.Time) ([]accessRecord, error) {
	if dir == "" {
		return nil, errors.New("访问日志目录为空：请通过 --dir 指定，或配置 logging.access.dir")
	}

	pattern := filepath.Join(dir, prefix+"-*.log")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("匹配访问日志文件失败（模式 %s）：%w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("在 %s 中未找到访问日志文件（模式 %s）", dir, prefix+"-*.log")
	}
	sort.Strings(matches)

	var cutoff time.Time
	if since > 0 {
		cutoff = now.Add(-since)
	}

	records := make([]accessRecord, 0, 1024)
	for _, path := range matches {
		_, err := fsx.ScanLines(path, maxFileBytes, maxLineBytes, func(line string, lineNo int) error {
			var record accessRecord
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				return fmt.Errorf("%s 第 %d 行不是合法 JSON：%w", filepath.Base(path), lineNo, err)
			}
			// 时间过滤必须在解析之后：日志中的时间是唯一权威的时间来源，
			// 用文件名（按天轮转）过滤会漏掉跨天的边界记录。
			if !cutoff.IsZero() && !record.Time.IsZero() && record.Time.Before(cutoff) {
				return nil
			}
			records = append(records, record)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return records, nil
}

// counterPair 是「计数 + 数量」的通用聚合结构。
type counterPair struct {
	// Key 是被统计的维度值。
	Key string `json:"key"`
	// Count 是出现次数。
	Count int `json:"count"`
}

// topN 返回计数最高的前 n 项（按次数降序，次数相同时按键名升序保证输出稳定）。
func topN(counter map[string]int, n int) []counterPair {
	pairs := make([]counterPair, 0, len(counter))
	for key, count := range counter {
		pairs = append(pairs, counterPair{Key: key, Count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Key < pairs[j].Key
	})
	if n > 0 && len(pairs) > n {
		pairs = pairs[:n]
	}
	return pairs
}

// detectionReportPayload 是 `report detection --json` 的输出结构。
type detectionReportPayload struct {
	GeneratedAt   string         `json:"generated_at"`
	LogDir        string         `json:"log_dir"`
	Since         string         `json:"since"`
	TotalRecords  int            `json:"total_records"`
	WouldBlock    int            `json:"would_block"`
	WouldBlockPct float64        `json:"would_block_pct"`
	TopRules      []counterPair  `json:"top_rules"`
	TopPaths      []counterPair  `json:"top_paths"`
	TopClients    []counterPair  `json:"top_clients"`
	Samples       []accessRecord `json:"samples"`
}

// runReportDetection 生成 DetectionOnly 试运行报告（需求 P1-6 的闭环产出）。
//
// 报告回答三个问题（它们直接决定「能否把引擎从 detection_only 切到 on」）：
//
//  1. **总量**：窗口内有多少请求、其中多少「本应被拦截」，比例是否可接受；
//  2. **分布**：这些「若拦截」集中在哪些规则 / 路径 / 来源，
//     集中的部分通常是「一条规则误报」或「一个爬虫被拦」，处理方式完全不同；
//  3. **样例**：给出具体请求（request_id + method + path + rule_id），
//     供人工复核与编写例外（engine.exceptions）。
func runReportDetection(args []string, stdout, stderr io.Writer) int {
	loader, err := newReportFlagSet(reportActionDetection, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseReportFlags(loader, args, stderr); code != exitOK {
		return code
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf report detection")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config

	dir := loader.stringFlag("dir")
	if dir == "" {
		dir = cfg.Logging.Access.Dir
	}
	since := loader.durationFlag("since")
	top := loader.intFlag("top")

	now := time.Now()
	records, err := loadAccessRecords(dir, cfg.Logging.Access.File, cfg.Limits.MaxRuleFileBytes, maxLineBytesOf(cfg), since, now)
	if err != nil {
		fmt.Fprintf(stderr, "读取访问日志失败：%v\n", err)
		return exitRuntimeError
	}

	rulesCounter := make(map[string]int)
	pathsCounter := make(map[string]int)
	clientsCounter := make(map[string]int)
	wouldBlock := 0
	samples := make([]accessRecord, 0, top)

	for _, record := range records {
		if !record.WouldBlock {
			continue
		}
		wouldBlock++
		rulesCounter[displayOrDash(record.RuleID)]++
		pathsCounter[displayOrDash(record.Path)]++
		clientsCounter[displayOrDash(record.ClientIP)]++
		if len(samples) < top {
			samples = append(samples, record)
		}
	}

	payload := detectionReportPayload{
		GeneratedAt:  now.Format(time.RFC3339),
		LogDir:       dir,
		Since:        sinceLabel(since),
		TotalRecords: len(records),
		WouldBlock:   wouldBlock,
		TopRules:     topN(rulesCounter, top),
		TopPaths:     topN(pathsCounter, top),
		TopClients:   topN(clientsCounter, top),
		Samples:      samples,
	}
	if len(records) > 0 {
		payload.WouldBlockPct = float64(wouldBlock) * 100 / float64(len(records))
	}

	// 导出后端（需求 P1-9）：--format csv|xlsx 或 --out *.csv|*.xlsx 时接管输出。
	if handled, code := tryExportReport(loader, cfg, stdout, stderr, detectionDocument(payload)); handled {
		return code
	}

	if loader.jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintf(stderr, "输出 JSON 失败：%v\n", err)
			return exitRuntimeError
		}
		return exitOK
	}

	fmt.Fprintf(stdout, "DetectionOnly 试运行报告\n")
	fmt.Fprintf(stdout, "日志目录：%s；时间范围：%s；生成时间：%s\n",
		dir, payload.Since, payload.GeneratedAt)
	fmt.Fprintf(stdout, "窗口内访问记录：%d 条；其中「本应拦截」：%d 条（占比 %.2f%%）\n\n",
		payload.TotalRecords, payload.WouldBlock, payload.WouldBlockPct)

	writeCounterTable(stdout, "若拦截 Top 规则", payload.TopRules)
	writeCounterTable(stdout, "若拦截 Top 路径", payload.TopPaths)
	writeCounterTable(stdout, "若拦截 Top 来源 IP", payload.TopClients)

	if len(payload.Samples) == 0 {
		fmt.Fprintln(stdout, "没有样例可展示（窗口内没有「本应拦截」的记录）")
		fmt.Fprintln(stdout, "\n结论建议：窗口内零误报，可以考虑把 engine.mode 切换为 on（建议先小流量灰度）。")
		return exitOK
	}

	fmt.Fprintln(stdout, "样例（供人工复核；确认误报后可在 engine.exceptions 中登记例外）：")
	fmt.Fprintf(stdout, "  %-22s %-8s %-28s %-10s %s\n", "时间", "方法", "路径", "规则", "request_id")
	for _, sample := range payload.Samples {
		fmt.Fprintf(stdout, "  %-22s %-8s %-28s %-10s %s\n",
			sample.Time.Format("2006-01-02 15:04:05"),
			displayOrDash(sample.Method),
			truncateText(displayOrDash(sample.Path), 28),
			displayOrDash(sample.RuleID),
			sample.RequestID,
		)
	}
	fmt.Fprintln(stdout, "\n处置建议：逐条复核样例，对确认为误报的规则在 engine.exceptions 中登记"+
		"（必须填写 reason），并重新运行本报表确认「若拦截」比例下降后再切换到 on 模式。")
	return exitOK
}

// attackReportPayload 是 `report attack --json` 的输出结构。
type attackReportPayload struct {
	GeneratedAt  string        `json:"generated_at"`
	LogDir       string        `json:"log_dir"`
	Since        string        `json:"since"`
	TotalRecords int           `json:"total_records"`
	Blocked      int           `json:"blocked"`
	Observed     int           `json:"observed"`
	TopRules     []counterPair `json:"top_rules"`
	TopClients   []counterPair `json:"top_clients"`
	TopPaths     []counterPair `json:"top_paths"`
	TopChecks    []counterPair `json:"top_checks"`
}

// runReportAttack 生成攻击态势报表（需求 P1-8 / P1-9 的 CLI 侧交付）。
//
// 与 detection 报表的区别：detection 只统计「若拦截」（观察模式产出），
// attack 统计真实拦截与观察结论，用于日常运营与容量评估。
func runReportAttack(args []string, stdout, stderr io.Writer) int {
	loader, err := newReportFlagSet(reportActionAttack, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseReportFlags(loader, args, stderr); code != exitOK {
		return code
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf report attack")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config

	dir := loader.stringFlag("dir")
	if dir == "" {
		dir = cfg.Logging.Access.Dir
	}
	since := loader.durationFlag("since")
	top := loader.intFlag("top")

	now := time.Now()
	records, err := loadAccessRecords(dir, cfg.Logging.Access.File, cfg.Limits.MaxRuleFileBytes, maxLineBytesOf(cfg), since, now)
	if err != nil {
		fmt.Fprintf(stderr, "读取访问日志失败：%v\n", err)
		return exitRuntimeError
	}

	ruleCounter := make(map[string]int)
	clientCounter := make(map[string]int)
	pathCounter := make(map[string]int)
	checkCounter := make(map[string]int)
	blocked, observed := 0, 0

	for _, record := range records {
		switch record.Verdict {
		case "block", "ratelimit", "unauthorized", "bad_request", "unavailable", "drop", "challenge":
			blocked++
		case "observe":
			observed++
		default:
			continue
		}
		ruleCounter[displayOrDash(record.RuleID)]++
		clientCounter[displayOrDash(record.ClientIP)]++
		pathCounter[displayOrDash(record.Path)]++
		checkCounter[displayOrDash(record.Check)]++
	}

	payload := attackReportPayload{
		GeneratedAt:  now.Format(time.RFC3339),
		LogDir:       dir,
		Since:        sinceLabel(since),
		TotalRecords: len(records),
		Blocked:      blocked,
		Observed:     observed,
		TopRules:     topN(ruleCounter, top),
		TopClients:   topN(clientCounter, top),
		TopPaths:     topN(pathCounter, top),
		TopChecks:    topN(checkCounter, top),
	}

	// 导出后端（需求 P1-9）。
	if handled, code := tryExportReport(loader, cfg, stdout, stderr, attackDocument(payload)); handled {
		return code
	}

	if loader.jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintf(stderr, "输出 JSON 失败：%v\n", err)
			return exitRuntimeError
		}
		return exitOK
	}

	fmt.Fprintf(stdout, "攻击态势报表\n")
	fmt.Fprintf(stdout, "日志目录：%s；时间范围：%s；生成时间：%s\n",
		dir, payload.Since, payload.GeneratedAt)
	fmt.Fprintf(stdout, "窗口内访问记录：%d 条；拦截：%d 条；观察命中：%d 条\n\n",
		payload.TotalRecords, payload.Blocked, payload.Observed)

	writeCounterTable(stdout, "Top 命中规则", payload.TopRules)
	writeCounterTable(stdout, "Top 攻击源 IP", payload.TopClients)
	writeCounterTable(stdout, "Top 被攻击路径", payload.TopPaths)
	writeCounterTable(stdout, "Top 校验单元", payload.TopChecks)
	fmt.Fprintln(stdout, "\n处置建议：对排名靠前的来源 IP 可用 `waf ban add --ip <IP>` 落地内部封禁；"+
		"排名靠前的规则若集中在正常业务上，应按误报治理流程登记例外。")
	return exitOK
}

// banReportPayload 是 `report ban --json` 的输出结构。
type banReportPayload struct {
	GeneratedAt  string        `json:"generated_at"`
	LogDir       string        `json:"log_dir"`
	Since        string        `json:"since"`
	TotalRecords int           `json:"total_records"`
	BanHits      int           `json:"ban_hits"`
	TopClients   []counterPair `json:"top_clients"`
	Timeline     []counterPair `json:"timeline"`
	TopSites     []counterPair `json:"top_sites"`
	TopRules     []counterPair `json:"top_rules"`
}

// runReportBan 生成封禁运维报表（需求 P1-8）。
//
// 报表回答封禁运维必须能答上的三个问题：
//
//  1. **封了谁**：Top 封禁来源 IP（配合 `waf ban list` 查看具体封禁项与剩余时长）；
//  2. **什么时候封的**：按小时聚合的时间线，用于判断「是持续刷还是瞬时爆发」；
//  3. **为什么封**：Top 站点与 Top 规则，用于区分「攻击」与「误封」。
//
// 为什么从访问日志统计而不是直接查存储：封禁名单只记录「当前状态」，
// 而运维复盘需要的是「历史过程」；访问日志是唯一不可篡改的过程记录，
// 且在被封禁来源持续打量的场景下，日志本身就是最好的证据链。
func runReportBan(args []string, stdout, stderr io.Writer) int {
	loader, err := newReportFlagSet(reportActionBan, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "初始化命令行参数失败：%v\n", err)
		return exitConfigError
	}
	if code := parseReportFlags(loader, args, stderr); code != exitOK {
		return code
	}

	resolved, _, code := loadResolved(loader.rest, stderr, "waf report ban")
	if code != exitOK {
		return code
	}
	if resolved == nil {
		return exitOK
	}
	cfg := resolved.Config

	dir := loader.stringFlag("dir")
	if dir == "" {
		dir = cfg.Logging.Access.Dir
	}
	since := loader.durationFlag("since")
	top := loader.intFlag("top")

	now := time.Now()
	records, err := loadAccessRecords(dir, cfg.Logging.Access.File, cfg.Limits.MaxRuleFileBytes, maxLineBytesOf(cfg), since, now)
	if err != nil {
		fmt.Fprintf(stderr, "读取访问日志失败：%v\n", err)
		return exitRuntimeError
	}

	clientCounter := make(map[string]int)
	siteCounter := make(map[string]int)
	ruleCounter := make(map[string]int)
	hourCounter := make(map[string]int)
	banHits := 0

	for _, record := range records {
		if !isBanHit(record) {
			continue
		}
		banHits++
		clientCounter[displayOrDash(record.ClientIP)]++
		siteCounter[displayOrDash(record.Site)]++
		ruleCounter[displayOrDash(record.RuleID)]++
		hourCounter[banHourBucket(record.Time)]++
	}

	payload := banReportPayload{
		GeneratedAt:  now.Format(time.RFC3339),
		LogDir:       dir,
		Since:        sinceLabel(since),
		TotalRecords: len(records),
		BanHits:      banHits,
		TopClients:   topN(clientCounter, top),
		Timeline:     chronologicalBuckets(hourCounter, top),
		TopSites:     topN(siteCounter, top),
		TopRules:     topN(ruleCounter, top),
	}

	// 导出后端（需求 P1-9）。
	if handled, code := tryExportReport(loader, cfg, stdout, stderr, banDocument(payload)); handled {
		return code
	}

	if loader.jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintf(stderr, "输出 JSON 失败：%v\n", err)
			return exitRuntimeError
		}
		return exitOK
	}

	fmt.Fprintf(stdout, "封禁运维报表\n")
	fmt.Fprintf(stdout, "日志目录：%s；时间范围：%s；生成时间：%s\n",
		dir, payload.Since, payload.GeneratedAt)
	fmt.Fprintf(stdout, "窗口内访问记录：%d 条；封禁命中：%d 条\n\n",
		payload.TotalRecords, payload.BanHits)

	writeCounterTable(stdout, "Top 封禁来源 IP", payload.TopClients)
	writeCounterTable(stdout, "封禁命中时间线（按小时）", payload.Timeline)
	writeCounterTable(stdout, "Top 站点", payload.TopSites)
	writeCounterTable(stdout, "Top 规则", payload.TopRules)

	fmt.Fprintln(stdout, "处置建议：")
	fmt.Fprintln(stdout, "  1) 用 `waf ban list` 查看当前封禁清单与剩余时长；")
	fmt.Fprintln(stdout, "  2) 用 `waf ban remove --ip <IP>` 解除确认属于误封的来源；")
	fmt.Fprintln(stdout, "  3) 若某来源持续命中且无业务价值，可配合限速（ratelimit）降低其在封禁窗口外的骚扰量；")
	fmt.Fprintln(stdout, "  4) 封禁只在 WAF 内部生效，不会改动主机防火墙（需求 R18）。")
	return exitOK
}

// isBanHit 判断一条访问记录是否是「内部封禁命中」。
//
// 判定依据是访问日志的 check 字段（校验单元的实例名）不区分大小写地包含 "ban"：
// banlist（封禁名单查询）与 autoban（自动封禁）都能命中，而其它校验单元
// （coraza / ratelimit / ipaccess / threshold）不会误入。
//
// 之所以不新增专用日志字段：封禁命中在日志里天然表现为「某个校验单元拦下了请求」，
// 新增字段会让既有采集规则与字段映射失效，而 check 名本来就在配置里带业务语义
// （运维把封禁实例改名后，本判定会跟着变化——这是刻意的：改名即代表语义变更）。
func isBanHit(record accessRecord) bool {
	switch record.Verdict {
	case "block", "drop", "observe":
	default:
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(record.Check)), "ban")
}

// banHourBucket 把记录时间归入「小时桶」。
//
// 使用记录自带时区而不是强制 UTC：访问日志的时间戳由日志处理器按配置时区写出，
// 强行换算会让运维看到的「凌晨 3 点被打」与实际值班时间对不上。
func banHourBucket(at time.Time) string {
	if at.IsZero() {
		return "时间未知"
	}
	return at.Format("2006-01-02 15:00")
}

// chronologicalBuckets 按时间升序返回全部时间桶。
//
// 与 topN 的差异：时间线必须按时间排序才有意义（「先少后多」与「先多后少」
// 是完全不同的处置结论），按次数排序反而会抹掉趋势。
// n 为 0 或负数时返回全部桶。
func chronologicalBuckets(counter map[string]int, n int) []counterPair {
	buckets := make([]counterPair, 0, len(counter))
	for key, count := range counter {
		buckets = append(buckets, counterPair{Key: key, Count: count})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Key < buckets[j].Key })
	if n > 0 && len(buckets) > n {
		// 超出上限时保留最近的 n 个桶：复盘关注的是「最近发生了什么」。
		buckets = buckets[len(buckets)-n:]
	}
	return buckets
}

// writeCounterTable 输出一个排行表。
func writeCounterTable(stdout io.Writer, title string, pairs []counterPair) {
	fmt.Fprintf(stdout, "%s：\n", title)
	if len(pairs) == 0 {
		fmt.Fprintln(stdout, "  （无数据）")
		fmt.Fprintln(stdout)
		return
	}
	for index, pair := range pairs {
		fmt.Fprintf(stdout, "  %2d. %-40s %d\n", index+1, truncateText(pair.Key, 40), pair.Count)
	}
	fmt.Fprintln(stdout)
}

// maxLineBytesOf 把「单行长度上限」从配置的 int64 限额转换为 int。
//
// 之所以复用 limits.max_scan_token_bytes：访问日志的一行就是一条「待解析的 token」，
// 与规则扫描使用同一个限额语义，不需要为报表新增配置项（需求 R13：限额可配置、不新增冗余开关）。
// 转换时做上界保护：int64 超出 int 表示范围说明配置本身异常，此时回落到默认单行上限。
func maxLineBytesOf(cfg *config.Config) int {
	value := cfg.Limits.MaxScanTokenBytes
	if value <= 0 || value > int64(^uint(0)>>1) {
		return 0
	}
	return int(value)
}

// sinceLabel 把时长渲染为可读标签。
func sinceLabel(since time.Duration) string {
	if since <= 0 {
		return "全部"
	}
	return "最近 " + since.String()
}
