// Package threatintel 实现本地威胁情报校验单元（PhasePre / PhaseRequest）。
//
// 能力边界：
//   - 匹配本地 CIDR / IP、ASN 与域名情报，不访问云端情报服务；
//   - ASN 匹配需要本地 GeoLite2-ASN MMDB；
//   - 文件或目录按 refresh_interval 轮询，变更后原子替换快照；
//   - 站点级可通过 params 覆盖 action / score。
package threatintel

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	mmdb "github.com/weiyongkang/waf/internal/geoip"
	"github.com/weiyongkang/waf/internal/intel"
)

// Type 是本实现的注册类型名。
const Type = "threatintel"

const (
	defaultRefreshInterval = 5 * time.Minute
	defaultRuleID          = "threat_intel_match"
)

func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 threatintel 的私有配置片段。
type Settings struct {
	Files []string `yaml:"files"`
	Dirs  []string `yaml:"dirs"`
	// ASNDatabase 是 GeoLite2-ASN MMDB；存在 ASN 条目时必填。
	ASNDatabase string `yaml:"asn_database"`
	Action      string `yaml:"action"`
	Score       int    `yaml:"score"`
	RuleID      string `yaml:"rule_id"`
	// MaxTotalBytes 是情报文件总量上限；<=0 时按单文件上限的 16 倍处理。
	MaxTotalBytes int64 `yaml:"max_total_bytes"`
	// HotReload 控制是否监听文件变化；nil 表示默认开启。
	HotReload *bool `yaml:"hot_reload"`
	// RefreshInterval 是文件扫描间隔。
	RefreshInterval core.Duration `yaml:"refresh_interval"`
}

// Check 是威胁情报校验单元实例。
type Check struct {
	name          string
	phase         core.Phase
	order         int
	action        string
	score         int
	ruleID        string
	files         []string
	dirs          []string
	maxFileBytes  int64
	maxTotalBytes int64

	mu          sync.RWMutex
	snapshot    *intel.Snapshot
	fingerprint string
	asnDB       *mmdb.Database

	logger   *slog.Logger
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New 构造威胁情报校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}
	if len(settings.Files) == 0 && len(settings.Dirs) == 0 {
		return nil, fmt.Errorf("threatintel 至少需要配置 files 或 dirs")
	}
	action := strings.ToLower(strings.TrimSpace(settings.Action))
	if action == "" {
		action = "block"
	}
	if action != "block" && action != "observe" {
		return nil, fmt.Errorf("threatintel.action = %q 非法，可选值：block / observe", settings.Action)
	}
	ruleID := strings.TrimSpace(settings.RuleID)
	if ruleID == "" {
		ruleID = defaultRuleID
	}

	snapshot, err := intel.Load(intel.Options{
		Files:         settings.Files,
		Dirs:          settings.Dirs,
		MaxFileBytes:  deps.Limits.MaxIntelFileBytes,
		MaxTotalBytes: settings.MaxTotalBytes,
	})
	if err != nil {
		return nil, err
	}

	var asnDB *mmdb.Database
	if snapshot.HasASN() || strings.TrimSpace(settings.ASNDatabase) != "" {
		if strings.TrimSpace(settings.ASNDatabase) == "" {
			return nil, fmt.Errorf("威胁情报包含 ASN 条目，但未配置 threatintel.asn_database")
		}
		asnDB, err = mmdb.OpenASN(settings.ASNDatabase, deps.Limits.MaxMMDBBytes)
		if err != nil {
			return nil, err
		}
	}

	fingerprint, err := intel.Fingerprint(settings.Files, settings.Dirs)
	if err != nil {
		if asnDB != nil {
			_ = asnDB.Close()
		}
		return nil, err
	}

	check := &Check{
		name: inst.Name, phase: inst.Phase, order: inst.Order,
		action: action, score: settings.Score, ruleID: ruleID,
		files: settings.Files, dirs: settings.Dirs,
		maxFileBytes: deps.Limits.MaxIntelFileBytes, maxTotalBytes: settings.MaxTotalBytes,
		snapshot: snapshot, fingerprint: fingerprint, asnDB: asnDB,
		logger: deps.SystemLoggerOr(),
		stop:   make(chan struct{}), done: make(chan struct{}),
	}

	stats := snapshot.Stats()
	check.logger.Info("威胁情报校验单元装配完成",
		"instance", inst.Name,
		"files", stats.Files,
		"ip_entries", stats.IPEntries,
		"domains", stats.Domains,
		"asns", stats.ASNs,
	)

	reloadEnabled := true
	if settings.HotReload != nil {
		reloadEnabled = *settings.HotReload
	}
	interval := settings.RefreshInterval.Duration()
	if interval <= 0 {
		interval = defaultRefreshInterval
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

// Evaluate 执行威胁情报匹配。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}

	c.mu.RLock()
	snapshot := c.snapshot
	asnDB := c.asnDB
	c.mu.RUnlock()
	if snapshot == nil {
		return nil, nil
	}

	kind, matched := snapshot.MatchIP(rctx.Raw.ClientIP, func(ip net.IP) (uint, bool) {
		if asnDB == nil {
			return 0, false
		}
		record, ok, err := asnDB.LookupASN(ip)
		if err != nil || !ok {
			return 0, false
		}
		return record.Number, true
	})
	value := rctx.Raw.ClientIP
	if !matched {
		for _, host := range domainSources(rctx.Raw) {
			if domain, ok := snapshot.MatchDomain(host); ok {
				kind, matched, value = "domain", true, domain
				break
			}
		}
	}
	if !matched {
		return nil, nil
	}

	action := c.siteString(rctx, "threatintel.action", c.action)
	if action != "block" && action != "observe" {
		action = c.action
	}
	score := c.siteInt(rctx, "threatintel.score", c.score)

	verdict := core.VerdictBlock
	code := config.CodeBlocked
	if action == "observe" {
		verdict = core.VerdictObserve
		code = ""
	}
	result := core.NewResult(c.name, verdict)
	result.Code = code
	message := fmt.Sprintf("来源命中本地威胁情报（%s: %s）", kind, value)
	finding := core.NewFinding(c.name, c.ruleID, message, core.SeverityHigh, score)
	finding.Data = map[string]string{
		"target":     "client_ip",
		"match_type": kind,
		"match":      value,
		"client_ip":  rctx.Raw.ClientIP,
		"action":     action,
	}
	result.AddFinding(finding)
	if verdict == core.VerdictObserve {
		result.MarkWouldBlock(message)
	}
	return result, nil
}

func (c *Check) DefaultOnError() string { return core.OnErrorPass }

// Close 停止轮询并关闭 ASN 数据库。
func (c *Check) Close() error {
	if c == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
	if c.asnDB != nil {
		return c.asnDB.Close()
	}
	return nil
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
	fingerprint, err := intel.Fingerprint(c.files, c.dirs)
	if err != nil {
		c.logger.Warn("威胁情报文件指纹计算失败，保留旧快照", "instance", c.name, "error", err.Error())
		return
	}
	c.mu.RLock()
	unchanged := fingerprint == c.fingerprint
	c.mu.RUnlock()
	if unchanged {
		return
	}

	if c.asnDB != nil {
		if _, reloadErr := c.asnDB.Reload(); reloadErr != nil {
			c.logger.Warn("ASN 数据库热更新失败，保留旧快照", "instance", c.name, "error", reloadErr.Error())
		}
	}
	snapshot, err := intel.Load(intel.Options{
		Files: c.files, Dirs: c.dirs,
		MaxFileBytes: c.maxFileBytes, MaxTotalBytes: c.maxTotalBytes,
	})
	if err != nil {
		c.logger.Warn("威胁情报热更新失败，保留旧快照", "instance", c.name, "error", err.Error())
		return
	}
	c.mu.Lock()
	c.snapshot = snapshot
	c.fingerprint = fingerprint
	c.mu.Unlock()
	c.logger.Info("威胁情报已热更新", "instance", c.name, "stats", snapshot.Stats())
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
		c.logger.Warn("站点威胁情报参数非法，回退实例配置", "instance", c.name, "key", key, "value", raw)
		return fallback
	}
	return parsed
}

func domainSources(raw *core.RawRequest) []string {
	if raw == nil {
		return nil
	}
	sources := make([]string, 0, 4)
	sources = append(sources, raw.Host)
	for _, header := range []string{"Referer", "Origin"} {
		value := raw.HeaderValue(header)
		if value == "" {
			continue
		}
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			sources = append(sources, parsed.Hostname())
		}
	}
	return sources
}
