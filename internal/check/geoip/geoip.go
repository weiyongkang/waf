// Package geoip 实现本地 GeoIP 地域访问控制校验单元（PhaseRequest）。
//
// 能力边界：
//   - 只读取本地 MaxMind MMDB（GeoLite2 Country/City），不访问云端 API；
//   - 支持国家与洲的放行/拦截，白名单优先于黑名单；
//   - 数据库文件可按 poll_interval 轮询热更新，更新失败保留旧快照；
//   - 站点级可通过 params 覆盖 action / score / 国家与洲名单。
package geoip

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	mmdb "github.com/weiyongkang/waf/internal/geoip"
	"github.com/weiyongkang/waf/internal/netx"
)

// Type 是本实现的注册类型名。
const Type = "geoip"

const (
	defaultPollInterval = 5 * time.Second
	defaultRuleID       = "geoip_country_block"
)

func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 geoip 的私有配置片段。
type Settings struct {
	// Database 是本地 MMDB 路径（必填）。
	Database string `yaml:"database"`
	// Action 是命中黑名单后的动作：block / observe。
	Action string `yaml:"action"`
	// Score 是命中时累加的异常评分。
	Score int `yaml:"score"`
	// RuleID 是命中明细的规则标识。
	RuleID string `yaml:"rule_id"`
	// AllowCountries / BlockCountries 是两位国家代码列表。
	AllowCountries []string `yaml:"allow_countries"`
	BlockCountries []string `yaml:"block_countries"`
	// AllowContinents / BlockContinents 是洲代码列表，例如 AS / EU。
	AllowContinents []string `yaml:"allow_continents"`
	BlockContinents []string `yaml:"block_continents"`
	// HotReload 控制是否监听数据库文件变化；nil 表示默认开启。
	HotReload *bool `yaml:"hot_reload"`
	// PollInterval 是热更新轮询间隔。
	PollInterval core.Duration `yaml:"poll_interval"`
}

// Check 是 GeoIP 校验单元实例。
type Check struct {
	name   string
	phase  core.Phase
	order  int
	action string
	score  int
	ruleID string

	allowCountries  map[string]struct{}
	blockCountries  map[string]struct{}
	allowContinents map[string]struct{}
	blockContinents map[string]struct{}

	db     *mmdb.Database
	logger *slog.Logger

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New 构造 GeoIP 校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}
	if strings.TrimSpace(settings.Database) == "" {
		return nil, fmt.Errorf("geoip.database 不能为空；该能力需要本地 MMDB 文件")
	}

	action := strings.ToLower(strings.TrimSpace(settings.Action))
	if action == "" {
		action = "block"
	}
	if action != "block" && action != "observe" {
		return nil, fmt.Errorf("geoip.action = %q 非法，可选值：block / observe", settings.Action)
	}
	allowCountries, err := normalizeCodes(settings.AllowCountries)
	if err != nil {
		return nil, fmt.Errorf("geoip.allow_countries 非法：%w", err)
	}
	blockCountries, err := normalizeCodes(settings.BlockCountries)
	if err != nil {
		return nil, fmt.Errorf("geoip.block_countries 非法：%w", err)
	}
	allowContinents, err := normalizeCodes(settings.AllowContinents)
	if err != nil {
		return nil, fmt.Errorf("geoip.allow_continents 非法：%w", err)
	}
	blockContinents, err := normalizeCodes(settings.BlockContinents)
	if err != nil {
		return nil, fmt.Errorf("geoip.block_continents 非法：%w", err)
	}
	if len(allowCountries) == 0 && len(blockCountries) == 0 &&
		len(allowContinents) == 0 && len(blockContinents) == 0 {
		return nil, fmt.Errorf("geoip 未配置任何 allow/block 国家或洲；空名单会让该实例静默失效")
	}

	db, err := mmdb.OpenCountry(settings.Database, deps.Limits.MaxMMDBBytes)
	if err != nil {
		return nil, err
	}

	ruleID := strings.TrimSpace(settings.RuleID)
	if ruleID == "" {
		ruleID = defaultRuleID
	}
	check := &Check{
		name:            inst.Name,
		phase:           inst.Phase,
		order:           inst.Order,
		action:          action,
		score:           settings.Score,
		ruleID:          ruleID,
		allowCountries:  allowCountries,
		blockCountries:  blockCountries,
		allowContinents: allowContinents,
		blockContinents: blockContinents,
		db:              db,
		logger:          deps.SystemLoggerOr(),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}

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

	check.logger.Info("GeoIP 校验单元装配完成",
		"instance", inst.Name,
		"database", db.Path(),
		"hot_reload", reloadEnabled,
		"poll_interval", interval.String(),
	)
	return check, nil
}

func (c *Check) Name() string      { return c.name }
func (c *Check) Type() string      { return Type }
func (c *Check) Phase() core.Phase { return c.phase }
func (c *Check) Order() int        { return c.order }

// Evaluate 执地域匹配。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}
	ip := netx.ParseIP(rctx.Raw.ClientIP)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return nil, nil
	}

	country, found, err := c.db.LookupCountry(ip)
	if err != nil {
		return nil, fmt.Errorf("GeoIP 查询失败：%w", err)
	}
	if !found {
		return nil, nil
	}

	allowCountries := c.siteCodeSet(rctx, "geoip.allow_countries", c.allowCountries)
	blockCountries := c.siteCodeSet(rctx, "geoip.block_countries", c.blockCountries)
	allowContinents := c.siteCodeSet(rctx, "geoip.allow_continents", c.allowContinents)
	blockContinents := c.siteCodeSet(rctx, "geoip.block_continents", c.blockContinents)
	action := c.siteString(rctx, "geoip.action", c.action)
	if action != "block" && action != "observe" {
		action = c.action
	}
	score := c.siteInt(rctx, "geoip.score", c.score)

	if _, ok := allowCountries[country.ISO]; ok {
		return allowResult(c.name, rctx), nil
	}
	if _, ok := allowContinents[country.Continent]; ok {
		return allowResult(c.name, rctx), nil
	}
	_, blockCountry := blockCountries[country.ISO]
	_, blockContinent := blockContinents[country.Continent]
	if !blockCountry && !blockContinent {
		return nil, nil
	}

	verdict := core.VerdictBlock
	code := config.CodeBlocked
	if action == "observe" {
		verdict = core.VerdictObserve
		code = ""
	}
	result := core.NewResult(c.name, verdict)
	result.Code = code
	message := fmt.Sprintf("来源地域 %s 命中访问策略", country.ISO)
	finding := core.NewFinding(c.name, c.ruleID, message, core.SeverityHigh, score)
	finding.Data = map[string]string{
		"target":       "client_ip",
		"country":      country.ISO,
		"country_name": country.Name,
		"continent":    country.Continent,
		"action":       action,
		"database":     c.db.Path(),
	}
	result.AddFinding(finding)
	if verdict == core.VerdictObserve {
		result.MarkWouldBlock(message)
	}
	return result, nil
}

func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 停止热更新协程并关闭 MMDB。
func (c *Check) Close() error {
	if c == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
	return c.db.Close()
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
			changed, err := c.db.Reload()
			if err != nil {
				c.logger.Warn("GeoIP 数据库热更新失败，继续使用旧快照",
					"instance", c.name, "database", c.db.Path(), "error", err.Error())
				continue
			}
			if changed {
				c.logger.Info("GeoIP 数据库已热更新", "instance", c.name, "database", c.db.Path())
			}
		}
	}
}

func (c *Check) siteCodeSet(rctx *core.RequestContext, key string, fallback map[string]struct{}) map[string]struct{} {
	raw, ok := rctx.Site.Param(key)
	if !ok {
		return fallback
	}
	set, err := normalizeCodes(splitList(raw))
	if err != nil {
		c.logger.Warn("站点 GeoIP 参数非法，回退实例配置", "instance", c.name, "key", key, "value", raw)
		return fallback
	}
	return set
}

func (c *Check) siteString(rctx *core.RequestContext, key, fallback string) string {
	if raw, ok := rctx.Site.Param(key); ok {
		return strings.ToLower(raw)
	}
	return fallback
}

func (c *Check) siteInt(rctx *core.RequestContext, key string, fallback int) int {
	raw, ok := rctx.Site.Param(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		c.logger.Warn("站点 GeoIP 参数非法，回退实例配置", "instance", c.name, "key", key, "value", raw)
		return fallback
	}
	return parsed
}

func allowResult(check string, rctx *core.RequestContext) *core.Result {
	result := core.NewResult(check, core.VerdictAllow)
	result.Message = "来源地域命中放行策略"
	return result
}

func normalizeCodes(values []string) (map[string]struct{}, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		code := strings.ToUpper(strings.TrimSpace(value))
		if code == "" {
			continue
		}
		if len(code) != 2 && len(code) != 3 {
			return nil, fmt.Errorf("代码 %q 长度非法（国家为 2 位，洲为 2-3 位）", value)
		}
		set[code] = struct{}{}
	}
	return set, nil
}

func splitList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
}
