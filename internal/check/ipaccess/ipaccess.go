// Package ipaccess 实现 IP 黑白名单校验单元（PhasePre）。
//
// 能力与语义：
//   - 白名单（allowlist）命中 -> 直接放行，并**短路整条校验链**。
//     之所以短路：白名单表达的是「这些来源可信，不做任何后续检测」，
//     若继续执行后续单元，白名单就退化成「只跳过 IP 类检测」，与运维预期不符；
//   - 黑名单（blocklist，可来自内联列表与文件）命中 -> 按 action 拦截或仅观察；
//   - 两者都不命中 -> 不产生结论（继续执行后续单元）。
//
// 名单中的条目支持单个 IP 与 CIDR；文件按「一行一条」解析，支持 # 注释与空行。
package ipaccess

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/fsx"
	"github.com/weiyongkang/waf/internal/netx"
)

// Type 是本实现的注册类型名。
const Type = "ipaccess"

// 动作常量。
const (
	// ActionBlock 表示命中黑名单时直接拦截。
	ActionBlock = "block"
	// ActionObserve 表示命中黑名单时只记录与告警，不拦截（用于灰度验证名单准确性）。
	ActionObserve = "observe"
)

// init 在包初始化阶段完成类型注册（编译期装配）。
func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 ipaccess 的私有配置片段。
type Settings struct {
	// Allowlist 是白名单条目列表（IP 或 CIDR）。
	Allowlist []string `yaml:"allowlist"`
	// Blocklist 是黑名单条目列表（IP 或 CIDR）。
	Blocklist []string `yaml:"blocklist"`
	// BlocklistFile 是黑名单文件路径（一行一条）；为空表示不加载文件。
	//
	// 之所以支持文件：大规模名单（数万条）写在配置文件里既难以维护，
	// 也无法由外部系统自动更新；文件可以独立下发与热更新（后续里程碑）。
	BlocklistFile string `yaml:"blocklist_file"`
	// Action 是命中黑名单后的动作：block / observe。
	Action string `yaml:"action"`
	// Score 是命中时累加的异常评分（供 threshold 单元聚合判定）。
	Score int `yaml:"score"`
}

// Check 是 IP 黑白名单校验单元实例。
type Check struct {
	// name 是实例名。
	name string
	// phase 是执行阶段（固定为 pre，但仍由配置决定以保持一致性）。
	phase core.Phase
	// order 是执行顺序。
	order int
	// action 是命中黑名单后的动作。
	action string
	// score 是命中时累加的评分。
	score int
	// allowlist / blocklist 是解析后的匹配集合。
	allowlist *netx.Set
	blocklist *netx.Set
	// logger 是系统日志器。
	logger *slog.Logger
}

// New 依据实例配置构造 ipaccess 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	action := settings.Action
	if action == "" {
		action = ActionBlock
	}
	switch action {
	case ActionBlock, ActionObserve:
	default:
		return nil, fmt.Errorf("ipaccess 的 action = %q 非法，可选值：block / observe", action)
	}

	allowlist, err := netx.NewSet(settings.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("解析 allowlist 失败：%w", err)
	}
	blocklist, err := netx.NewSet(settings.Blocklist)
	if err != nil {
		return nil, fmt.Errorf("解析 blocklist 失败：%w", err)
	}

	logger := deps.SystemLoggerOr()
	if settings.BlocklistFile != "" {
		// 名单文件属于外部输入：必须受 limits.max_intel_file_bytes 约束（需求 R13）。
		loaded, err := loadBlocklistFile(settings.BlocklistFile, blocklist, deps.Limits.MaxIntelFileBytes)
		if err != nil {
			return nil, err
		}
		logger.Info("已加载 IP 黑名单文件",
			"check", inst.Name, "path", settings.BlocklistFile, "entries", loaded)
	}

	return &Check{
		name:      inst.Name,
		phase:     inst.Phase,
		order:     inst.Order,
		action:    action,
		score:     settings.Score,
		allowlist: allowlist,
		blocklist: blocklist,
		logger:    logger,
	}, nil
}

// Name 返回实例名。
func (c *Check) Name() string { return c.name }

// Type 返回实现类型。
func (c *Check) Type() string { return Type }

// Phase 返回执行阶段。
func (c *Check) Phase() core.Phase { return c.phase }

// Order 返回执行顺序。
func (c *Check) Order() int { return c.order }

// Evaluate 执行 IP 黑白名单判断。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}

	clientIP := rctx.Raw.ClientIP
	if clientIP == "" {
		// 无法确定来源地址（例如注入头缺失）时不产生结论：
		// 这里刻意不做「代理失败即拦截」，那属于 ingress 的职责范围。
		return nil, nil
	}

	if c.allowlist.Contains(clientIP) {
		result := core.NewResult(c.name, core.VerdictAllow)
		result.AddFinding(core.NewFinding(
			c.name, "ip_allowlist", "客户端 IP 命中白名单，跳过后续检测",
			core.SeverityInfo, 0,
		))
		result.Findings[0].Data = map[string]string{"client_ip": clientIP}
		return result, nil
	}

	if c.blocklist.Contains(clientIP) {
		result := core.NewResult(c.name, core.VerdictBlock)
		if c.action == ActionObserve {
			result.Verdict = core.VerdictObserve
		}
		result.AddFinding(core.NewFinding(
			c.name, "ip_blocklist", "客户端 IP 命中黑名单",
			core.SeverityHigh, c.score,
		))
		result.Findings[0].Data = map[string]string{"client_ip": clientIP}
		return result, nil
	}

	return nil, nil
}

// DefaultOnError 返回失败策略默认值：本单元为纯内存判断，没有外部依赖，
// 因此不存在「运行期故障」这一场景，保持失败开放即可。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 释放资源：本实现不持有需要释放的资源（名单已全部驻留内存）。
func (c *Check) Close() error { return nil }

// loadBlocklistFile 逐行加载黑名单文件并追加到集合中，返回成功加载的条目数。
func loadBlocklistFile(path string, set *netx.Set, maxBytes int64) (int, error) {
	count := 0

	_, err := fsx.ScanLines(path, maxBytes, 0, func(line string, lineNo int) error {
		if err := set.Add(line); err != nil {
			return fmt.Errorf("黑名单文件第 %d 行非法：%w", lineNo, err)
		}
		count++
		return nil
	})
	if err != nil {
		if errors.Is(err, fsx.ErrFileTooLarge) {
			return 0, fmt.Errorf("IP 黑名单文件超过 limits.max_intel_file_bytes 限制：%w", err)
		}
		return 0, err
	}
	return count, nil
}
