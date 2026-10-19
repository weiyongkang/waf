// Package apisec 实现 OpenAPI 请求契约校验单元（PhaseBody）。
//
// 能力边界：
//   - 基于本地 OpenAPI 3.x 文件校验路径参数、查询参数、Header、Cookie 与 JSON 请求体；
//   - 未在 spec 中声明的接口可按 unknown_action 选择放行、观察或拦截；
//   - spec 文件支持轮询热更新，更新失败保留旧契约继续服务。
package apisec

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/apisec"
	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "apisec"

const (
	defaultRuleID        = "apisec_contract_violation"
	defaultPollInterval  = 5 * time.Second
	defaultMaxViolations = 8
)

func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 apisec 的私有配置片段。
type Settings struct {
	// SpecFile 是本地 OpenAPI 3.x YAML/JSON 路径（必填）。
	SpecFile string `yaml:"spec_file"`
	// Action 是命中违规后的动作：block / observe。
	Action string `yaml:"action"`
	// Score 是命中违规时累加的异常评分。
	Score int `yaml:"score"`
	// RuleID 是命中明细的规则标识。
	RuleID string `yaml:"rule_id"`
	// UnknownAction 是「spec 中没有该 method + path」时的动作：off / block / observe。
	// 默认为 off，避免尚未纳入 spec 的旧接口被集中误伤。
	UnknownAction string `yaml:"unknown_action"`
	// CheckParameters 控制是否校验参数，默认 true。
	CheckParameters *bool `yaml:"check_parameters"`
	// CheckBody 控制是否校验 JSON 请求体，默认 true。
	CheckBody *bool `yaml:"check_body"`
	// MaxViolations 是单次请求最多上报的违规数量，避免错误响应与日志被刷爆。
	MaxViolations int `yaml:"max_violations"`
	// MaxBodyBytes 是参与 JSON 契约校验的请求体上限。
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// HotReload 控制是否监听 spec 文件变化；nil 表示默认开启。
	HotReload *bool `yaml:"hot_reload"`
	// PollInterval 是 spec 文件扫描间隔。
	PollInterval core.Duration `yaml:"poll_interval"`
}

// Check 是 OpenAPI 契约校验单元实例。
type Check struct {
	name            string
	phase           core.Phase
	order           int
	action          string
	unknownAction   string
	score           int
	ruleID          string
	checkParameters bool
	checkBody       bool
	maxViolations   int
	maxBodyBytes    int64
	maxSpecBytes    int64
	specFile        string
	logger          *slog.Logger

	mu          sync.RWMutex
	spec        *apisec.Spec
	fingerprint string

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New 构造 OpenAPI 契约校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}
	specFile := strings.TrimSpace(settings.SpecFile)
	if specFile == "" {
		return nil, fmt.Errorf("apisec.spec_file 不能为空")
	}
	action := normalizeAction(settings.Action, "block")
	if action == "" {
		return nil, fmt.Errorf("apisec.action = %q 非法，可选值：block / observe", settings.Action)
	}
	unknownAction := normalizeUnknownAction(settings.UnknownAction)
	if unknownAction == "" {
		return nil, fmt.Errorf("apisec.unknown_action = %q 非法，可选值：off / block / observe", settings.UnknownAction)
	}
	checkParameters := true
	if settings.CheckParameters != nil {
		checkParameters = *settings.CheckParameters
	}
	checkBody := true
	if settings.CheckBody != nil {
		checkBody = *settings.CheckBody
	}
	if checkBody && inst.Phase != core.PhaseBody {
		return nil, fmt.Errorf("apisec 启用 check_body 时必须使用 phase: body（当前 %s）", inst.Phase)
	}
	maxViolations := settings.MaxViolations
	if maxViolations <= 0 {
		maxViolations = defaultMaxViolations
	}
	maxBodyBytes := settings.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = deps.Limits.MaxScanTokenBytes
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 1 << 20
	}

	spec, err := apisec.LoadFile(specFile, deps.Limits.MaxConfigFileBytes)
	if err != nil {
		return nil, err
	}
	fingerprint, err := apisec.Fingerprint(specFile)
	if err != nil {
		return nil, fmt.Errorf("计算 OpenAPI spec 文件指纹失败：%w", err)
	}
	ruleID := strings.TrimSpace(settings.RuleID)
	if ruleID == "" {
		ruleID = defaultRuleID
	}
	check := &Check{
		name: inst.Name, phase: inst.Phase, order: inst.Order,
		action: action, unknownAction: unknownAction, score: settings.Score,
		ruleID: ruleID, checkParameters: checkParameters, checkBody: checkBody,
		maxViolations: maxViolations, maxBodyBytes: maxBodyBytes, specFile: specFile,
		maxSpecBytes: deps.Limits.MaxConfigFileBytes,
		spec:         spec, fingerprint: fingerprint,
		logger: deps.SystemLoggerOr(),
		stop:   make(chan struct{}), done: make(chan struct{}),
	}
	check.logger.Info("OpenAPI 契约校验单元装配完成",
		"instance", inst.Name,
		"spec", specFile,
		"openapi", spec.Version,
		"routes", spec.RouteCount(),
		"check_parameters", checkParameters,
		"check_body", checkBody,
	)

	reloadEnabled := true
	if settings.HotReload != nil {
		reloadEnabled = *settings.HotReload
	}
	interval := settings.PollInterval.Duration()
	if interval <= 0 {
		interval = defaultPollInterval
	}
	if reloadEnabled {
		go check.watch(interval)
	} else {
		close(check.done)
	}
	return check, nil
}

func (c *Check) Name() string      { return c.name }
func (c *Check) Type() string      { return Type }
func (c *Check) Phase() core.Phase { return c.phase }
func (c *Check) Order() int        { return c.order }

// DefaultOnError 返回失败开放：契约文件损坏不应导致全站不可用。
func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Evaluate 执行 OpenAPI 契约校验。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}
	c.mu.RLock()
	spec := c.spec
	c.mu.RUnlock()
	if spec == nil {
		return nil, nil
	}

	query, err := url.ParseQuery(rctx.Raw.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("解析原始查询串失败：%w", err)
	}
	body, bodyViolation := c.readBody(rctx)
	matched, violations := spec.Validate(rctx.Raw.Method, rctx.Raw.Path, query, rctx.Raw.Header,
		body, c.checkParameters, c.checkBody && rctx.Stream != nil, c.maxViolations)
	if bodyViolation != nil {
		violations = append(violations, *bodyViolation)
	}

	action := c.action
	if raw, ok := rctx.Site.Param("apisec.action"); ok {
		if normalized := normalizeAction(raw, ""); normalized != "" {
			action = normalized
		}
	}
	unknownAction := c.unknownAction
	if raw, ok := rctx.Site.Param("apisec.unknown_action"); ok {
		if normalized := normalizeUnknownAction(raw); normalized != "" {
			unknownAction = normalized
		}
	}
	score := c.score
	if raw, ok := rctx.Site.Param("apisec.score"); ok {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil && parsed >= 0 {
			score = parsed
		}
	}

	if !matched {
		if unknownAction == "off" {
			return nil, nil
		}
		return c.result(rctx, unknownAction, score, []apisec.Violation{{
			Location: "request",
			Rule:     "apisec_unknown_route",
			Message:  fmt.Sprintf("接口 %s %s 未在 OpenAPI spec 中声明", rctx.Raw.Method, rctx.Raw.Path),
		}}), nil
	}
	if len(violations) == 0 {
		return nil, nil
	}
	return c.result(rctx, action, score, violations), nil
}

func (c *Check) result(rctx *core.RequestContext, action string, score int, violations []apisec.Violation) *core.Result {
	verdict := core.VerdictBlock
	code := config.CodeBlocked
	if action == "observe" {
		verdict = core.VerdictObserve
		code = ""
	}
	result := core.NewResult(c.name, verdict)
	result.Code = code
	result.Score = score
	message := fmt.Sprintf("API 契约校验失败（%d 项）", len(violations))
	result.Message = message
	for _, violation := range violations {
		finding := core.NewFinding(c.name, c.ruleID,
			fmt.Sprintf("%s: %s", violationRule(violation), violation.Message),
			core.SeverityMedium, 0)
		finding.Data = map[string]string{
			"target":    violation.Location,
			"location":  violation.Location,
			"name":      violation.Name,
			"violation": violation.Rule,
			"method":    rctx.Raw.Method,
			"path":      rctx.Raw.Path,
			"client_ip": rctx.Raw.ClientIP,
		}
		result.Findings = append(result.Findings, finding)
	}
	if verdict == core.VerdictObserve {
		result.MarkWouldBlock(message)
	}
	return result
}

func (c *Check) readBody(rctx *core.RequestContext) ([]byte, *apisec.Violation) {
	if !c.checkBody || rctx.Stream == nil {
		return nil, nil
	}
	if err := rctx.Stream.Rewind(); err != nil {
		return nil, &apisec.Violation{Location: "body", Rule: "body_read_error",
			Message: fmt.Sprintf("请求体读取位置复位失败：%v", err)}
	}
	defer func() { _ = rctx.Stream.Rewind() }()
	payload, err := io.ReadAll(io.LimitReader(rctx.Stream, c.maxBodyBytes+1))
	if err != nil {
		return nil, &apisec.Violation{Location: "body", Rule: "body_read_error",
			Message: fmt.Sprintf("读取请求体失败：%v", err)}
	}
	if int64(len(payload)) > c.maxBodyBytes {
		return nil, &apisec.Violation{Location: "body", Rule: "body_too_large",
			Message: fmt.Sprintf("请求体超过 apisec.max_body_bytes=%d，跳过 JSON 契约校验", c.maxBodyBytes)}
	}
	return payload, nil
}

func (c *Check) watch(interval time.Duration) {
	defer close(c.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.reload()
		}
	}
}

func (c *Check) reload() {
	fingerprint, err := apisec.Fingerprint(c.specFile)
	if err != nil {
		c.logger.Warn("OpenAPI spec 文件指纹计算失败，保留旧契约", "instance", c.name, "error", err.Error())
		return
	}
	c.mu.RLock()
	unchanged := fingerprint == c.fingerprint
	c.mu.RUnlock()
	if unchanged {
		return
	}
	spec, err := apisec.LoadFile(c.specFile, c.maxSpecBytes)
	if err != nil {
		c.logger.Warn("OpenAPI spec 热更新失败，保留旧契约", "instance", c.name, "error", err.Error())
		return
	}
	c.mu.Lock()
	c.spec = spec
	c.fingerprint = fingerprint
	c.mu.Unlock()
	c.logger.Info("OpenAPI 契约已热更新", "instance", c.name, "routes", spec.RouteCount())
}

// Close 停止轮询。
func (c *Check) Close() error {
	if c == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
	return nil
}

func normalizeAction(value, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return fallback
	}
	if normalized != "block" && normalized != "observe" {
		return ""
	}
	return normalized
}

func normalizeUnknownAction(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "off"
	}
	if normalized != "off" && normalized != "block" && normalized != "observe" {
		return ""
	}
	return normalized
}

func violationRule(violation apisec.Violation) string {
	if violation.Name == "" {
		return violation.Rule
	}
	return fmt.Sprintf("%s(%s=%s)", violation.Rule, violation.Location, violation.Name)
}
