package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Snapshot 是数据库运营策略的不可变内存快照。
type Snapshot struct {
	// Sites 是数据库中的站点策略（含站点级黑白名单）。
	Sites []config.SiteConfig
	// GlobalAllow / GlobalBlock 是全局 IP 名单，应用到站点与 ipaccess 实例。
	GlobalAllow []string
	GlobalBlock []string
	// CheckAllowlist / CheckBlocklist 是 ipaccess 实例级名单，键为实例名。
	CheckAllowlist map[string][]string
	CheckBlocklist map[string][]string
	// Ban 是数据库中的封禁策略。
	Ban config.BanConfig
	// EngineEnabled / EngineMode / ParanoiaLevel / AnomalyScoreThreshold 是可选覆盖。
	EngineEnabled         *bool
	EngineMode            *string
	ParanoiaLevel         *int
	AnomalyScoreThreshold *int
	// ResponderIncludeDetails / Messages / Template / MaxBodyBytes 是可选覆盖。
	ResponderIncludeDetails *bool
	ResponderMessages       map[string]string
	ResponderTemplate       *string
	ResponderMaxBodyBytes   *int64
	// Revision 是快照对应的策略版本。
	Revision int64
}

// LoadSnapshot 从数据库加载运营策略快照。
func (d *DB) LoadSnapshot(ctx context.Context) (*Snapshot, error) {
	snapshot := &Snapshot{
		CheckAllowlist: make(map[string][]string),
		CheckBlocklist: make(map[string][]string),
	}
	revision, err := d.Revision(ctx)
	if err != nil {
		return nil, err
	}
	snapshot.Revision = revision

	sites, err := d.loadSites(ctx)
	if err != nil {
		return nil, err
	}
	snapshot.Sites = sites
	if err := d.loadIPLists(ctx, snapshot); err != nil {
		return nil, err
	}
	settings, err := d.loadSettings(ctx)
	if err != nil {
		return nil, err
	}
	applyBanSettings(settings, &snapshot.Ban)
	applyEngineSettings(settings, snapshot)
	applyResponderSettings(settings, snapshot)
	return snapshot, nil
}

// loadSites 加载站点策略。
func (d *DB) loadSites(ctx context.Context) ([]config.SiteConfig, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT site, hosts_json, engine_mode, pipeline, access_action, access_score, params_json
		   FROM site_policies
		  WHERE enabled = 1
		  ORDER BY site`)
	if err != nil {
		return nil, fmt.Errorf("读取站点策略失败：%w", err)
	}
	defer func() { _ = rows.Close() }()

	sites := make([]config.SiteConfig, 0)
	for rows.Next() {
		var (
			site, hostsJSON, engineMode, pipeline, action, paramsJSON string
			score                                                     int
		)
		if err := rows.Scan(&site, &hostsJSON, &engineMode, &pipeline, &action, &score, &paramsJSON); err != nil {
			return nil, fmt.Errorf("读取站点策略失败：%w", err)
		}
		var hosts []string
		if err := json.Unmarshal([]byte(hostsJSON), &hosts); err != nil {
			return nil, fmt.Errorf("站点 %q 的 hosts 数据损坏：%w", site, err)
		}
		params := make(map[string]string)
		if strings.TrimSpace(paramsJSON) != "" {
			if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
				return nil, fmt.Errorf("站点 %q 的 params 数据损坏：%w", site, err)
			}
		}
		sites = append(sites, config.SiteConfig{
			Name:         site,
			Hosts:        hosts,
			EngineMode:   engineMode,
			Pipeline:     pipeline,
			AccessAction: action,
			AccessScore:  score,
			Params:       params,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历站点策略失败：%w", err)
	}
	return sites, nil
}

// loadIPLists 加载 IP 名单并回填站点级与实例级集合。
func (d *DB) loadIPLists(ctx context.Context, snapshot *Snapshot) error {
	now := d.Now().UnixMilli()
	rows, err := d.sql.QueryContext(ctx,
		`SELECT list_type, scope, site, check_name, value
		   FROM ip_lists
		  WHERE enabled = 1 AND (expire_at IS NULL OR expire_at > ?)
		  ORDER BY id`, now)
	if err != nil {
		return fmt.Errorf("读取 IP 名单失败：%w", err)
	}
	defer func() { _ = rows.Close() }()

	siteAllow := make(map[string][]string)
	siteBlock := make(map[string][]string)
	for rows.Next() {
		var listType, scope, site, checkName, value string
		if err := rows.Scan(&listType, &scope, &site, &checkName, &value); err != nil {
			return fmt.Errorf("读取 IP 名单失败：%w", err)
		}
		switch scope {
		case "global":
			if listType == "allow" {
				snapshot.GlobalAllow = append(snapshot.GlobalAllow, value)
			} else {
				snapshot.GlobalBlock = append(snapshot.GlobalBlock, value)
			}
		case "site":
			if listType == "allow" {
				siteAllow[site] = append(siteAllow[site], value)
			} else {
				siteBlock[site] = append(siteBlock[site], value)
			}
		case "check":
			if listType == "allow" {
				snapshot.CheckAllowlist[checkName] = append(snapshot.CheckAllowlist[checkName], value)
			} else {
				snapshot.CheckBlocklist[checkName] = append(snapshot.CheckBlocklist[checkName], value)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历 IP 名单失败：%w", err)
	}

	for index := range snapshot.Sites {
		site := &snapshot.Sites[index]
		site.Allowlist = append(append([]string(nil), snapshot.GlobalAllow...), siteAllow[site.Name]...)
		site.Blocklist = append(append([]string(nil), snapshot.GlobalBlock...), siteBlock[site.Name]...)
	}
	return nil
}

// loadSettings 加载全局标量策略。
func (d *DB) loadSettings(ctx context.Context) (map[string]string, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT key, value FROM policy_settings WHERE scope = 'global' AND name = ''`)
	if err != nil {
		return nil, fmt.Errorf("读取策略项失败：%w", err)
	}
	defer func() { _ = rows.Close() }()
	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("读取策略项失败：%w", err)
		}
		settings[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历策略项失败：%w", err)
	}
	return settings, nil
}

// applyBanSettings 把数据库中的封禁策略回填到配置结构。
func applyBanSettings(settings map[string]string, ban *config.BanConfig) {
	if value, ok := settings["ban.default_ttl"]; ok {
		ban.DefaultTTL = parseDuration(value)
	}
	if value, ok := settings["ban.max_ttl"]; ok {
		ban.MaxTTL = parseDuration(value)
	}
	if value, ok := settings["ban.ban_key"]; ok {
		ban.BanKey = value
	}
	if value, ok := settings["ban.ban_keys"]; ok {
		var keys []string
		if json.Unmarshal([]byte(value), &keys) == nil {
			ban.BanKeys = keys
		}
	}
	if value, ok := settings["ban.escalate"]; ok {
		ban.Escalate, _ = strconv.ParseBool(value)
	}
	if value, ok := settings["ban.escalate_steps"]; ok {
		var steps []string
		if json.Unmarshal([]byte(value), &steps) == nil {
			ban.EscalateSteps = make([]core.Duration, 0, len(steps))
			for _, step := range steps {
				ban.EscalateSteps = append(ban.EscalateSteps, parseDuration(step))
			}
		}
	}
	if value, ok := settings["ban.escalate_window"]; ok {
		ban.EscalateWindow = parseDuration(value)
	}
	if value, ok := settings["ban.renew_on_repeat"]; ok {
		ban.RenewOnRepeat, _ = strconv.ParseBool(value)
	}
}

// applyEngineSettings 把数据库中的引擎关键策略回填到快照。
func applyEngineSettings(settings map[string]string, snapshot *Snapshot) {
	if value, ok := settings["engine.enabled"]; ok {
		if parsed, err := strconv.ParseBool(value); err == nil {
			snapshot.EngineEnabled = &parsed
		}
	}
	if value, ok := settings["engine.mode"]; ok {
		snapshot.EngineMode = &value
	}
	if value, ok := settings["engine.paranoia_level"]; ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			snapshot.ParanoiaLevel = &parsed
		}
	}
	if value, ok := settings["engine.anomaly_score_threshold"]; ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			snapshot.AnomalyScoreThreshold = &parsed
		}
	}
}

// applyResponderSettings 把数据库中的响应关键策略回填到快照。
func applyResponderSettings(settings map[string]string, snapshot *Snapshot) {
	if value, ok := settings["responder.include_details"]; ok {
		if parsed, err := strconv.ParseBool(value); err == nil {
			snapshot.ResponderIncludeDetails = &parsed
		}
	}
	if value, ok := settings["responder.messages"]; ok {
		messages := make(map[string]string)
		if json.Unmarshal([]byte(value), &messages) == nil && len(messages) > 0 {
			snapshot.ResponderMessages = messages
		}
	}
	if value, ok := settings["responder.template"]; ok {
		snapshot.ResponderTemplate = &value
	}
	if value, ok := settings["responder.max_body_bytes"]; ok {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			snapshot.ResponderMaxBodyBytes = &parsed
		}
	}
}

// Apply 返回一个应用了数据库策略的配置副本，不修改入参。
func (s *Snapshot) Apply(cfg *config.Config) *config.Config {
	if cfg == nil || s == nil {
		return cfg
	}
	next := *cfg
	next.Sites = cloneSites(s.Sites)
	next.Ban = s.Ban
	next.Pipeline = applyCheckLists(cfg.Pipeline, s.GlobalAllow, s.GlobalBlock, s.CheckAllowlist, s.CheckBlocklist)
	if cfg.Pipelines != nil {
		next.Pipelines = make([]config.PipelineConfig, 0, len(cfg.Pipelines))
		for _, pipeline := range cfg.Pipelines {
			cloned := pipeline
			cloned.Instances = applyCheckLists(pipeline.Instances, s.GlobalAllow, s.GlobalBlock, s.CheckAllowlist, s.CheckBlocklist)
			next.Pipelines = append(next.Pipelines, cloned)
		}
	}
	if s.EngineEnabled != nil {
		next.Engine.Enabled = *s.EngineEnabled
	}
	if s.EngineMode != nil {
		next.Engine.Mode = *s.EngineMode
	}
	if s.ParanoiaLevel != nil {
		next.Engine.ParanoiaLevel = *s.ParanoiaLevel
	}
	if s.AnomalyScoreThreshold != nil {
		next.Engine.AnomalyScoreThreshold = *s.AnomalyScoreThreshold
	}
	if s.ResponderIncludeDetails != nil {
		next.Responder.IncludeDetails = *s.ResponderIncludeDetails
	}
	if s.ResponderMessages != nil {
		next.Responder.Messages = cloneStringMap(s.ResponderMessages)
	}
	if s.ResponderTemplate != nil {
		next.Responder.Template = *s.ResponderTemplate
		// 数据库模板是运营数据；一旦生效，YAML 中的 template_file 不能再参与，
		// 否则 responder 会因「模板与模板文件同时存在」拒绝启动。
		if next.Responder.Template != "" {
			next.Responder.TemplateFile = ""
		}
	}
	if s.ResponderMaxBodyBytes != nil {
		next.Responder.MaxBodyBytes = *s.ResponderMaxBodyBytes
	}
	return &next
}

// applyCheckLists 用数据库名单替换 ipaccess 实例的 YAML 名单。
//
// 全局名单对所有 ipaccess 实例生效，包括数据库中存在但 YAML 实例级名单为空的实例。
func applyCheckLists(
	instances []core.InstanceConfig,
	globalAllow []string,
	globalBlock []string,
	allow map[string][]string,
	block map[string][]string,
) []core.InstanceConfig {
	if instances == nil {
		return nil
	}
	out := make([]core.InstanceConfig, 0, len(instances))
	for _, inst := range instances {
		cloned := inst
		if inst.Type == "ipaccess" {
			settings := make(map[string]any, len(inst.Settings)+2)
			for key, value := range inst.Settings {
				settings[key] = value
			}
			settings["allowlist"] = append(append([]string(nil), globalAllow...), allow[inst.Name]...)
			settings["blocklist"] = append(append([]string(nil), globalBlock...), block[inst.Name]...)
			// 名单文件只在首次初始化时导入，之后由数据库权威管理。
			delete(settings, "blocklist_file")
			cloned.Settings = settings
		}
		out = append(out, cloned)
	}
	return out
}

// cloneSites 深拷贝站点策略，避免运行期修改数据库快照。
func cloneSites(sites []config.SiteConfig) []config.SiteConfig {
	if sites == nil {
		return nil
	}
	out := make([]config.SiteConfig, 0, len(sites))
	for _, site := range sites {
		cloned := site
		cloned.Hosts = append([]string(nil), site.Hosts...)
		cloned.Allowlist = append([]string(nil), site.Allowlist...)
		cloned.Blocklist = append([]string(nil), site.Blocklist...)
		cloned.Params = cloneStringMap(site.Params)
		out = append(out, cloned)
	}
	return out
}

// cloneStringMap 复制字符串映射。
func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
