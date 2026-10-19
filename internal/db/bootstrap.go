package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/fsx"
	"github.com/weiyongkang/waf/internal/netx"
)

// BootstrapResult 描述一次初始化导入的结果。
type BootstrapResult struct {
	// Initialized 表示数据库此前是否已经初始化。
	Initialized bool
	// Imported 表示本次是否实际执行了导入。
	Imported bool
	// Revision 是导入后的策略版本。
	Revision int64
	// ConfigHash 是导入数据（不含外部路径与密钥）的摘要。
	ConfigHash string
}

// sitePolicyRow 是 site_policies 的一行。
type sitePolicyRow struct {
	site         string
	hostsJSON    string
	engineMode   string
	pipeline     string
	accessAction string
	accessScore  int
	paramsJSON   string
}

// ipListRow 是 ip_lists 的一行。
type ipListRow struct {
	listType  string
	scope     string
	site      string
	pipeline  string
	checkName string
	value     string
	action    string
	score     int
	source    string
	reason    string
}

// policySettingRow 是 policy_settings 的一行。
type policySettingRow struct {
	scope string
	name  string
	key   string
	value string
}

// bootstrapData 是首次导入的完整运营数据。
type bootstrapData struct {
	Sites    []sitePolicyRow    `json:"sites"`
	IPLists  []ipListRow        `json:"ip_lists"`
	Settings []policySettingRow `json:"settings"`
}

// MarshalJSON 输出可审计的导入快照。
//
// 行结构内部使用小写字段便于数据库写入；这里显式转换为带 JSON 标签的结构，
// 保证 config_imports 中保存的是可读、可比较的运营数据，而不是空对象。
func (d bootstrapData) MarshalJSON() ([]byte, error) {
	type sitePayload struct {
		Site         string `json:"site"`
		Hosts        any    `json:"hosts"`
		EngineMode   string `json:"engine_mode"`
		Pipeline     string `json:"pipeline"`
		AccessAction string `json:"access_action"`
		AccessScore  int    `json:"access_score"`
		Params       any    `json:"params"`
	}
	type listPayload struct {
		ListType  string `json:"list_type"`
		Scope     string `json:"scope"`
		Site      string `json:"site,omitempty"`
		Pipeline  string `json:"pipeline,omitempty"`
		CheckName string `json:"check_name,omitempty"`
		Value     string `json:"value"`
		Action    string `json:"action,omitempty"`
		Score     int    `json:"score,omitempty"`
		Source    string `json:"source"`
		Reason    string `json:"reason,omitempty"`
	}
	type settingPayload struct {
		Scope string `json:"scope"`
		Name  string `json:"name,omitempty"`
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	payload := struct {
		Sites    []sitePayload    `json:"sites"`
		IPLists  []listPayload    `json:"ip_lists"`
		Settings []settingPayload `json:"settings"`
	}{}
	for _, row := range d.Sites {
		var hosts any
		_ = json.Unmarshal([]byte(row.hostsJSON), &hosts)
		var params any
		_ = json.Unmarshal([]byte(row.paramsJSON), &params)
		payload.Sites = append(payload.Sites, sitePayload{
			Site: row.site, Hosts: hosts, EngineMode: row.engineMode, Pipeline: row.pipeline,
			AccessAction: row.accessAction, AccessScore: row.accessScore, Params: params,
		})
	}
	for _, row := range d.IPLists {
		payload.IPLists = append(payload.IPLists, listPayload{
			ListType: row.listType, Scope: row.scope, Site: row.site, Pipeline: row.pipeline,
			CheckName: row.checkName, Value: row.value, Action: row.action, Score: row.score,
			Source: row.source, Reason: row.reason,
		})
	}
	for _, row := range d.Settings {
		payload.Settings = append(payload.Settings, settingPayload{
			Scope: row.scope, Name: row.name, Key: row.key, Value: row.value,
		})
	}
	return json.Marshal(payload)
}

// Bootstrap 在数据库尚未初始化时导入运营数据；force=true 时强制重新导入。
//
// 重新导入不会删除封禁记录与审计记录：封禁是运行期事实，不能用配置文件覆盖。
func (d *DB) Bootstrap(ctx context.Context, cfg *config.Config, force bool) (BootstrapResult, error) {
	if cfg == nil {
		return BootstrapResult{}, fmt.Errorf("初始化数据库时配置不能为空")
	}
	now := d.Now().UnixMilli()

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("开启初始化事务失败：%w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var initialized int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM bootstrap_state WHERE id = 1`).Scan(&initialized)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("读取初始化状态失败：%w", err)
	}
	if initialized > 0 && !force {
		var storedHash string
		if err := tx.QueryRowContext(ctx,
			`SELECT config_hash FROM bootstrap_state WHERE id = 1`).Scan(&storedHash); err != nil {
			return BootstrapResult{}, fmt.Errorf("读取初始化摘要失败：%w", err)
		}
		revision, revErr := revisionTx(ctx, tx)
		if revErr != nil {
			return BootstrapResult{}, revErr
		}
		if err := tx.Commit(); err != nil {
			return BootstrapResult{}, fmt.Errorf("提交初始化事务失败：%w", err)
		}
		return BootstrapResult{Initialized: true, Imported: false, Revision: revision, ConfigHash: storedHash}, nil
	}

	// 只在首次导入或显式 force 时解析导入源。blocklist_file 等外部路径属于
	// 一次性导入素材，数据库初始化完成后不应继续要求这些文件存在。
	data, err := buildBootstrapData(cfg)
	if err != nil {
		return BootstrapResult{}, err
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("序列化初始化数据失败：%w", err)
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	if initialized > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bootstrap_state`); err != nil {
			return BootstrapResult{}, fmt.Errorf("清理旧初始化状态失败：%w", err)
		}
	}
	// 只重建数据库拥有的运营策略；封禁记录与审计记录保持不变。
	for _, statement := range []string{
		`DELETE FROM site_policies`,
		`DELETE FROM ip_lists`,
		`DELETE FROM policy_settings`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return BootstrapResult{}, fmt.Errorf("清理旧运营数据失败：%w", err)
		}
	}

	for _, row := range data.Sites {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO site_policies(site, hosts_json, engine_mode, pipeline, access_action,
			                           access_score, params_json, enabled, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?)`,
			row.site, row.hostsJSON, row.engineMode, row.pipeline, row.accessAction,
			row.accessScore, row.paramsJSON, now); err != nil {
			return BootstrapResult{}, fmt.Errorf("导入站点策略 %q 失败：%w", row.site, err)
		}
	}
	for _, row := range data.IPLists {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO ip_lists(list_type, scope, site, pipeline, check_name,
			                               value, action, score, enabled, reason, source,
			                               expire_at, created_at, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)`,
			row.listType, row.scope, row.site, row.pipeline, row.checkName, row.value,
			row.action, row.score, row.reason, row.source, now, now); err != nil {
			return BootstrapResult{}, fmt.Errorf("导入 IP 名单失败：%w", err)
		}
	}
	for _, row := range data.Settings {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO policy_settings(scope, name, key, value, updated_at)
			 VALUES(?, ?, ?, ?, ?)
			 ON CONFLICT(scope, name, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			row.scope, row.name, row.key, row.value, now); err != nil {
			return BootstrapResult{}, fmt.Errorf("导入策略项 %s 失败：%w", row.key, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO config_imports(created_at, config_hash, source, payload_json)
		 VALUES(?, ?, ?, ?)`,
		now, hash, "config", string(payload)); err != nil {
		return BootstrapResult{}, fmt.Errorf("保存配置导入快照失败：%w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO bootstrap_state(id, initialized_at, config_hash, config_version, source, imported_at)
		 VALUES(1, ?, ?, ?, 'config', ?)`,
		now, hash, cfg.Version, now); err != nil {
		return BootstrapResult{}, fmt.Errorf("写入初始化状态失败：%w", err)
	}
	if err := bumpRevision(ctx, tx, now); err != nil {
		return BootstrapResult{}, err
	}
	revision, err := revisionTx(ctx, tx)
	if err != nil {
		return BootstrapResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return BootstrapResult{}, fmt.Errorf("提交初始化事务失败：%w", err)
	}
	return BootstrapResult{Initialized: false, Imported: true, Revision: revision, ConfigHash: hash}, nil
}

// Initialized 返回数据库是否已经完成首次导入。
func (d *DB) Initialized(ctx context.Context) (bool, error) {
	var count int
	if err := d.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM bootstrap_state WHERE id = 1`).Scan(&count); err != nil {
		return false, fmt.Errorf("读取初始化状态失败：%w", err)
	}
	return count > 0, nil
}

// buildBootstrapData 从生效配置提取数据库拥有的运营数据。
func buildBootstrapData(cfg *config.Config) (bootstrapData, error) {
	data := bootstrapData{}
	for _, site := range cfg.Sites {
		hostsJSON, err := json.Marshal(site.Hosts)
		if err != nil {
			return data, fmt.Errorf("序列化站点 %q 的 hosts 失败：%w", site.Name, err)
		}
		paramsJSON, err := json.Marshal(site.Params)
		if err != nil {
			return data, fmt.Errorf("序列化站点 %q 的 params 失败：%w", site.Name, err)
		}
		data.Sites = append(data.Sites, sitePolicyRow{
			site:         site.Name,
			hostsJSON:    string(hostsJSON),
			engineMode:   site.EngineMode,
			pipeline:     defaultIfEmpty(site.Pipeline, "default"),
			accessAction: defaultIfEmpty(site.AccessAction, "block"),
			accessScore:  site.AccessScore,
			paramsJSON:   string(paramsJSON),
		})
		for _, value := range normalizeList(site.Allowlist) {
			data.IPLists = append(data.IPLists, ipListRow{
				listType: "allow", scope: "site", site: site.Name, value: value,
				action: site.AccessAction, score: site.AccessScore,
				source: "config", reason: "站点白名单",
			})
		}
		for _, value := range normalizeList(site.Blocklist) {
			data.IPLists = append(data.IPLists, ipListRow{
				listType: "block", scope: "site", site: site.Name, value: value,
				action: site.AccessAction, score: site.AccessScore,
				source: "config", reason: "站点黑名单",
			})
		}
	}

	if err := appendCheckLists("", cfg.Pipeline, cfg.Limits.MaxIntelFileBytes, &data); err != nil {
		return data, err
	}
	for _, pipeline := range cfg.Pipelines {
		if err := appendCheckLists(pipeline.Name, pipeline.Instances, cfg.Limits.MaxIntelFileBytes, &data); err != nil {
			return data, err
		}
	}

	data.Settings = append(data.Settings,
		policySettingRow{scope: "global", key: "ban.default_ttl", value: cfg.Ban.DefaultTTL.Duration().String()},
		policySettingRow{scope: "global", key: "ban.max_ttl", value: cfg.Ban.MaxTTL.Duration().String()},
		policySettingRow{scope: "global", key: "ban.ban_key", value: cfg.Ban.BanKey},
		policySettingRow{scope: "global", key: "ban.ban_keys", value: jsonString(cfg.Ban.BanKeys)},
		policySettingRow{scope: "global", key: "ban.escalate", value: strconv.FormatBool(cfg.Ban.Escalate)},
		policySettingRow{scope: "global", key: "ban.escalate_steps", value: durationListJSON(cfg.Ban.EscalateSteps)},
		policySettingRow{scope: "global", key: "ban.escalate_window", value: cfg.Ban.EscalateWindow.Duration().String()},
		policySettingRow{scope: "global", key: "ban.renew_on_repeat", value: strconv.FormatBool(cfg.Ban.RenewOnRepeat)},
		policySettingRow{scope: "global", key: "engine.enabled", value: strconv.FormatBool(cfg.Engine.Enabled)},
		policySettingRow{scope: "global", key: "engine.mode", value: cfg.Engine.Mode},
		policySettingRow{scope: "global", key: "engine.paranoia_level", value: strconv.Itoa(cfg.Engine.ParanoiaLevel)},
		policySettingRow{scope: "global", key: "engine.anomaly_score_threshold", value: strconv.Itoa(cfg.Engine.AnomalyScoreThreshold)},
		policySettingRow{scope: "global", key: "responder.include_details", value: strconv.FormatBool(cfg.Responder.IncludeDetails)},
		policySettingRow{scope: "global", key: "responder.messages", value: jsonString(cfg.Responder.Messages)},
		policySettingRow{scope: "global", key: "responder.template", value: cfg.Responder.Template},
		policySettingRow{scope: "global", key: "responder.max_body_bytes", value: strconv.FormatInt(cfg.Responder.MaxBodyBytes, 10)},
	)
	return data, nil
}

// appendCheckLists 导入校验链中的 ipaccess 名单。
func appendCheckLists(pipeline string, instances []core.InstanceConfig, maxFileBytes int64, data *bootstrapData) error {
	for _, inst := range instances {
		if inst.Type != "ipaccess" {
			continue
		}
		var settings struct {
			Allowlist     []string `yaml:"allowlist"`
			Blocklist     []string `yaml:"blocklist"`
			BlocklistFile string   `yaml:"blocklist_file"`
			Action        string   `yaml:"action"`
			Score         int      `yaml:"score"`
		}
		if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
			return fmt.Errorf("解析 ipaccess 实例 %q 的名单失败：%w", inst.Name, err)
		}
		if _, err := netx.NewSet(settings.Allowlist); err != nil {
			return fmt.Errorf("ipaccess 实例 %q 的 allowlist 非法：%w", inst.Name, err)
		}
		if _, err := netx.NewSet(settings.Blocklist); err != nil {
			return fmt.Errorf("ipaccess 实例 %q 的 blocklist 非法：%w", inst.Name, err)
		}
		for _, value := range normalizeList(settings.Allowlist) {
			data.IPLists = append(data.IPLists, ipListRow{
				listType: "allow", scope: "check", pipeline: pipeline, checkName: inst.Name,
				value: value, action: settings.Action, score: settings.Score,
				source: "config", reason: "ipaccess 白名单",
			})
		}
		for _, value := range normalizeList(settings.Blocklist) {
			data.IPLists = append(data.IPLists, ipListRow{
				listType: "block", scope: "check", pipeline: pipeline, checkName: inst.Name,
				value: value, action: settings.Action, score: settings.Score,
				source: "config", reason: "ipaccess 黑名单",
			})
		}
		if strings.TrimSpace(settings.BlocklistFile) == "" {
			continue
		}
		set, err := netx.NewSet(nil)
		if err != nil {
			return err
		}
		_, err = fsx.ScanLines(settings.BlocklistFile, maxFileBytes, 0, func(line string, lineNo int) error {
			if err := set.Add(line); err != nil {
				return fmt.Errorf("第 %d 行非法：%w", lineNo, err)
			}
			data.IPLists = append(data.IPLists, ipListRow{
				listType: "block", scope: "check", pipeline: pipeline, checkName: inst.Name,
				value: line, action: settings.Action, score: settings.Score,
				source: "file_import", reason: "ipaccess blocklist_file",
			})
			return nil
		})
		if err != nil {
			return fmt.Errorf("导入 ipaccess 实例 %q 的 blocklist_file 失败：%w", inst.Name, err)
		}
	}
	return nil
}

// normalizeList 去除空项与首尾空白，保持声明顺序。
func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// defaultIfEmpty 返回默认值。
func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// jsonString 把任意值序列化为 JSON 字符串；失败时返回空 JSON。
func jsonString(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

// durationListJSON 把时长列表序列化为字符串 JSON 数组。
func durationListJSON(values []core.Duration) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, value.Duration().String())
	}
	return jsonString(items)
}

// revisionTx 读取事务内策略版本。
func revisionTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM policy_revision WHERE id = 1`).Scan(&revision); err != nil {
		return 0, fmt.Errorf("读取策略版本失败：%w", err)
	}
	return revision, nil
}

// parseDuration 解析策略中的时长；空值或非法值返回零值。
func parseDuration(value string) core.Duration {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return core.Duration(parsed)
}
