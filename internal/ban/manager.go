// Package ban 实现「内部封禁」的统一落地策略（需求 R18 / R19）。
//
// 为什么需要独立一层：
//   - 校验单元只负责产出「应当封禁谁、封多久、为什么」（core.BanRequest）；
//   - 「用哪个存储、如何应用默认时长与上限、是否累进加长、如何写日志与指标」
//     属于运维策略，必须在同一处实现，避免每个插件各写一套而互相不一致。
//
// 安全边界（需求 R18）：封禁**只在 WAF 内部生效**——写入共享存储的名单，
// 由 banlist 校验单元在后续请求上拦截；本包不含任何系统防火墙操作，
// 也不允许出现 os/exec（由 .golangci.yml 与 CI 静态检查共同禁止）。
package ban

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// 封禁键维度常量（配置项 ban.ban_key / ban.ban_keys）。
//
// 取值集合的真源在 internal/ban/keys.go 的 KeyScope；这里保留与旧版本同名的常量，
// 供既有调用方（ban 包内部与测试）继续引用。
const (
	// KeyKindClientIP 表示按客户端 IP 封禁。
	KeyKindClientIP = config.BanKeyClientIP
	// KeyKindClientIPSite 表示按「客户端 IP + 站点」封禁。
	KeyKindClientIPSite = config.BanKeyClientIPSite
	// KeyKindClientIPPath 表示按「客户端 IP + 请求路径」封禁。
	KeyKindClientIPPath = config.BanKeyClientIPPath
	// KeyKindClientIPMethod 表示按「客户端 IP + 请求方法」封禁。
	KeyKindClientIPMethod = config.BanKeyClientIPMethod
)

// escalationNamespace 是累进封禁计数键的命名空间。
//
// 之所以与封禁名单共用同一存储但不同命名空间：计数需要独立 TTL（escalate_window），
// 且不应该出现在 `waf ban list` 的输出里。
const escalationNamespace = "esc:"

// Manager 是内部封禁的统一落地器，实现 core.BanSink。
type Manager struct {
	// cfg 是封禁策略配置。
	cfg config.BanConfig
	// stores 是存储解析器。
	stores core.StoreResolver
	// storeName 是执行封禁写入时使用的存储名；为空表示使用默认存储。
	storeName string
	// scopes 是运行期启用的封禁维度集合（顺序即查询顺序，至少一项）。
	scopes []KeyScope
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
}

// Options 是封禁管理器的构造参数。
type Options struct {
	// Config 是封禁策略配置。
	Config config.BanConfig
	// Stores 是存储解析器；必填。
	Stores core.StoreResolver
	// StoreName 是执行封禁写入时使用的存储名；为空表示使用默认存储。
	StoreName string
	// Logger 是系统日志器；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；可为 nil。
	Metrics core.MetricsRecorder
}

// New 构造封禁管理器。
func New(opts Options) (*Manager, error) {
	if opts.Stores == nil {
		return nil, fmt.Errorf("封禁管理器必须注入存储解析器")
	}

	cfg := opts.Config
	if cfg.DefaultTTL.Duration() <= 0 {
		cfg.DefaultTTL = core.Duration(30 * time.Minute)
	}
	if cfg.MaxTTL.Duration() <= 0 {
		cfg.MaxTTL = core.Duration(24 * time.Hour)
	}
	if cfg.MaxTTL.Duration() < cfg.DefaultTTL.Duration() {
		return nil, fmt.Errorf("ban.max_ttl(%s) 不能小于 ban.default_ttl(%s)",
			cfg.MaxTTL, cfg.DefaultTTL)
	}
	scopes, err := resolveScopes(cfg)
	if err != nil {
		return nil, err
	}

	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}

	return &Manager{
		cfg:       cfg,
		stores:    opts.Stores,
		storeName: opts.StoreName,
		scopes:    scopes,
		logger:    opts.Logger,
		metrics:   metrics,
	}, nil
}

// store 解析本次操作使用的存储实例。
func (m *Manager) store() (core.Store, error) {
	if m.storeName != "" {
		return m.stores.Resolve(m.storeName)
	}
	return m.stores.Default()
}

// Ban 批量落地封禁动作（core.BanSink 实现）。
//
// 实现约束：
//   - **部分失败不影响其余动作**：逐个落地并汇总错误，避免第一条失败导致后续封禁全部丢失；
//   - 返回的错误只用于日志与指标，**不影响本次请求的判定结果**（封禁是「后续请求」的事）。
func (m *Manager) Ban(ctx context.Context, rctx *core.RequestContext, requests []core.BanRequest) error {
	if len(requests) == 0 {
		return nil
	}

	store, err := m.store()
	if err != nil {
		return fmt.Errorf("解析封禁存储失败：%w", err)
	}

	var failures []string
	for _, request := range requests {
		if err := m.banOne(ctx, store, rctx, request); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("封禁落地存在 %d 项失败：%s", len(failures), strings.Join(failures, "；"))
	}
	return nil
}

// banOne 落地单条封禁：解析键与时长的最终取值，写入存储并记录日志与指标。
func (m *Manager) banOne(ctx context.Context, store core.Store, rctx *core.RequestContext, request core.BanRequest) error {
	// 维度取请求显式声明的 scope（autoban 按维度封禁时必然带上）；
	// 未声明时回落到主维度，保证历史调用方的行为完全不变。
	scope := KeyScope(m.cfg.BanKey)
	if declared := strings.TrimSpace(request.Scope); declared != "" {
		parsed, ok := ParseKeyScope(declared)
		if !ok {
			return fmt.Errorf("封禁维度 %q 非法，可选值：%s",
				request.Scope, strings.Join(KeyScopeNames(), " / "))
		}
		scope = parsed
	}

	key := request.Key
	if key == "" {
		key = m.KeyForScope(rctx, string(scope))
	}
	if key == "" {
		return fmt.Errorf("封禁键为空：既未显式指定 key，也无法从请求上下文推导（规则 %s）", request.RuleID)
	}

	ttl := request.TTL
	if ttl <= 0 {
		ttl = m.cfg.DefaultTTL.Duration()
	}
	ttl, escalateCount := m.resolveTTL(ctx, store, key, ttl, request.RuleID)
	if ttl > m.cfg.MaxTTL.Duration() {
		ttl = m.cfg.MaxTTL.Duration()
	}

	reason := request.Reason
	if reason == "" {
		reason = fmt.Sprintf("规则 %s 触发内部封禁", request.RuleID)
	}
	detail := m.banDetail(rctx, request, string(scope))

	created := true
	if m.cfg.RenewOnRepeat {
		if err := m.banWithDetail(ctx, store, key, ttl, reason, detail); err != nil {
			return fmt.Errorf("写入封禁名单失败（key=%s）：%w", key, err)
		}
	} else {
		var err error
		created, err = m.banIfAbsentWithDetail(ctx, store, key, ttl, reason, detail)
		if err != nil {
			return fmt.Errorf("写入封禁名单失败（key=%s）：%w", key, err)
		}
	}
	if !created {
		// 已存在有效封禁：保持首次封禁时确定的到期时间，不刷新 TTL。
		// 这里只记录 debug，避免持续攻击把系统日志刷满。
		if m.logger != nil {
			m.logger.Debug("来源已在封禁名单中，保持原到期时间",
				"key", key,
				"rule_id", request.RuleID,
				"check", detail.Check,
				"target", detail.Target,
				"ban_scope", string(scope),
				"request_id", requestIDOf(rctx),
				"uri", detail.URI,
				"query", detail.Query,
				"params", detail.ParamsJSON,
			)
		}
		return nil
	}

	// 指标按实际维度统计：多维度部署时需要区分「按 IP 封」与「按 IP+路径 封」的量级。
	m.metrics.IncBan(string(scope))
	if m.logger != nil {
		m.logger.Warn("已写入内部封禁名单（仅在本 WAF 内部生效，不涉及系统防火墙）",
			"key", key,
			"ttl", ttl.String(),
			"reason", reason,
			"rule_id", request.RuleID,
			"check", detail.Check,
			"target", detail.Target,
			"ban_scope", string(scope),
			"escalate_count", escalateCount,
			"request_id", requestIDOf(rctx),
			"uri", detail.URI,
			"query", detail.Query,
			"params", detail.ParamsJSON,
		)
	}
	return nil
}

// banWithDetail 优先使用支持结构化上下文的存储实现，否则回退到普通 Ban。
func (m *Manager) banWithDetail(ctx context.Context, store core.Store, key string,
	ttl time.Duration, reason string, detail core.BanDetail) error {
	if detailed, ok := store.(core.BanDetailStore); ok {
		return detailed.BanWithDetail(ctx, key, ttl, reason, detail)
	}
	return store.Ban(ctx, key, ttl, reason)
}

// banIfAbsentWithDetail 优先使用支持结构化上下文的存储实现，否则回退到普通 BanIfAbsent。
func (m *Manager) banIfAbsentWithDetail(ctx context.Context, store core.Store, key string,
	ttl time.Duration, reason string, detail core.BanDetail) (bool, error) {
	if detailed, ok := store.(core.BanDetailStore); ok {
		return detailed.BanIfAbsentWithDetail(ctx, key, ttl, reason, detail)
	}
	return store.BanIfAbsent(ctx, key, ttl, reason)
}

// banDetail 构造封禁请求上下文快照，供 SQLite 与系统日志使用。
func (m *Manager) banDetail(rctx *core.RequestContext, request core.BanRequest, scope string) core.BanDetail {
	detail := core.BanDetail{
		Check:  request.Check,
		RuleID: request.RuleID,
		Target: request.Target,
		Scope:  scope,
	}
	if request.Scope != "" && detail.Target == "" {
		detail.Target = request.Scope
	}
	if rctx == nil {
		return detail
	}
	detail.RequestID = rctx.RequestID
	if rctx.Raw != nil {
		detail.URI = rctx.Raw.URI
		detail.Query = rctx.Raw.RawQuery
		if detail.URI == "" {
			detail.URI = rctx.Raw.Path
			if rctx.Raw.RawQuery != "" {
				detail.URI += "?" + rctx.Raw.RawQuery
			}
		}
	}
	detail.ParamsJSON = core.CaptureRequestParams(rctx, 0).JSON()
	return detail
}

// resolveTTL 依据累进封禁配置计算最终时长。
//
// 语义：当 ban.escalate 开启时，用共享存储记录「同一来源在 escalate_window 内的触发次数」，
// 次数越多次采用越靠后的台阶（超出台阶数量时停留在最后一档）。
// 之所以复用 Store.Incr：累进计数同样需要跨实例共享，否则多实例下每个实例各算一次，阶梯永远升不上去。
func (m *Manager) resolveTTL(ctx context.Context, store core.Store, key string, requested time.Duration, ruleID string) (time.Duration, int64) {
	if !m.cfg.Escalate || len(m.cfg.EscalateSteps) == 0 {
		return requested, 0
	}

	window := m.cfg.EscalateWindow.Duration()
	if window <= 0 {
		window = time.Hour
	}

	count, _, err := store.Incr(ctx, escalationNamespace+key, window)
	if err != nil {
		// 累进计数失败时退回「请求指定的时长」，不因为统计问题改变封禁是否生效。
		if m.logger != nil {
			m.logger.Warn("累进封禁计数失败，本次按请求时长封禁",
				"key", key, "rule_id", ruleID, "error", err.Error())
		}
		return requested, 0
	}

	index := int(count) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(m.cfg.EscalateSteps) {
		index = len(m.cfg.EscalateSteps) - 1
	}

	step := m.cfg.EscalateSteps[index].Duration()
	if step <= 0 {
		return requested, count
	}
	// 取两者较大值：调用方显式给出的更长时长不应被台阶「缩短」。
	if step > requested {
		return step, count
	}
	return requested, count
}

// KeyFor 依据主维度（ban.ban_key）推导请求对应的封禁键；无法推导时返回空串。
//
// 用途：启动日志、运行期排障与 `waf ban list` 的展示口径。
// 运行期的名单查询请使用 CheckScopes——它覆盖全部启用的维度。
func (m *Manager) KeyFor(rctx *core.RequestContext) string {
	return m.KeyForScope(rctx, m.cfg.BanKey)
}

// KeyForScope 依据指定维度推导请求对应的封禁键；无法推导时返回空串。
//
// 键构造统一委托给 ClientIPScopeKey（见 keys.go），
// 从而保证「autoban 写入的键」「banlist 查询的键」「CLI 写入的键」三者同源。
func (m *Manager) KeyForScope(rctx *core.RequestContext, scope string) string {
	if rctx == nil || rctx.Raw == nil {
		return ""
	}
	return ClientIPScopeKey(KeyScope(scope), rctx.Raw.ClientIP, siteNameOf(rctx),
		rctx.Raw.Path, rctx.Raw.Method)
}

// KeyForClientIP 依据主维度（ban.ban_key）与显式字段拼接封禁键。
//
// 该方法是 `waf ban add / remove` 与运行期判定共用的键构造入口，
// 保证「CLI 写入的键」与「校验单元查询的键」一定一致。
func (m *Manager) KeyForClientIP(clientIP, site string) string {
	return ClientIPScopeKey(KeyScope(m.cfg.BanKey), clientIP, site, "", "")
}

// Scopes 返回运行期启用的封禁维度清单（按配置顺序）。
//
// 之所以需要对外暴露：启动日志要打印生效维度，autoban 也要用它校验
// 「自己声明的触发维度是否真的会被查询」，避免配了一个永远查不到的维度。
func (m *Manager) Scopes() []string {
	names := make([]string, 0, len(m.scopes))
	for _, scope := range m.scopes {
		names = append(names, string(scope))
	}
	return names
}

// KeyKind 返回主封禁键维度，供启动日志与 CLI 输出。
func (m *Manager) KeyKind() string { return m.cfg.BanKey }

// DefaultTTL 返回生效的默认封禁时长。
func (m *Manager) DefaultTTL() time.Duration { return m.cfg.DefaultTTL.Duration() }

// MaxTTL 返回生效的封禁时长上限。
func (m *Manager) MaxTTL() time.Duration { return m.cfg.MaxTTL.Duration() }

// CheckScopes 按启用的全部维度依次查询来源是否已被封禁（供 banlist 校验单元复用）。
//
// 返回语义：
//   - banned=true 时 key/scope 是命中的那一项（第一个命中的维度胜出）；
//   - banned=false 且 err=nil 时表示全部维度都未命中；
//   - 查询失败立即返回错误（由调用方按 on_error 策略处理），
//     绝不把「存储不可用」静默降级为「未封禁」。
func (m *Manager) CheckScopes(ctx context.Context, rctx *core.RequestContext) (bool, time.Duration, string, string, error) {
	store, err := m.store()
	if err != nil {
		return false, 0, "", "", err
	}

	for _, scope := range m.scopes {
		key := m.KeyForScope(rctx, string(scope))
		if key == "" {
			continue
		}
		banned, remaining, err := store.IsBanned(ctx, key)
		if err != nil {
			return false, 0, key, string(scope), err
		}
		if banned {
			return true, remaining, key, string(scope), nil
		}
	}
	return false, 0, "", "", nil
}

// List 列出封禁名单。
func (m *Manager) List(ctx context.Context) ([]core.BanEntry, error) {
	store, err := m.store()
	if err != nil {
		return nil, err
	}
	return store.List(ctx)
}

// Unban 解除封禁（运维手工操作）。
func (m *Manager) Unban(ctx context.Context, key string) error {
	store, err := m.store()
	if err != nil {
		return err
	}
	return store.Unban(ctx, key)
}

// Add 手工新增一条封禁（供 `waf ban add` 使用），返回最终生效的键与时长。
func (m *Manager) Add(ctx context.Context, clientIP, site string, ttl time.Duration, reason string) (string, time.Duration, error) {
	key := m.KeyForClientIP(clientIP, site)
	if key == "" {
		return "", 0, fmt.Errorf("客户端 IP 不能为空")
	}

	store, err := m.store()
	if err != nil {
		return "", 0, err
	}

	if ttl <= 0 {
		ttl = m.cfg.DefaultTTL.Duration()
	}
	if ttl > m.cfg.MaxTTL.Duration() {
		ttl = m.cfg.MaxTTL.Duration()
	}
	if reason == "" {
		reason = "运维手工封禁"
	}

	if err := store.Ban(ctx, key, ttl, reason); err != nil {
		return key, ttl, err
	}
	m.metrics.IncBan(m.cfg.BanKey)
	return key, ttl, nil
}

// resolveScopes 计算运行期生效的封禁维度集合。
//
// 取值规则（需求 R5 / R6：能力可自由配置，且不与旧配置冲突）：
//   - ban.ban_keys 非空时以其为准，声明顺序即查询顺序（可配置多个维度）；
//   - ban.ban_keys 为空时回落到单一的 ban.ban_key，旧配置零改动即可升级。
//
// 重复维度会被静默去重而不是报错：配置校验（internal/config）已经会提示重复，
// 运行期再失败一次没有额外价值，反而会让「能启动」变成「启动不了」。
func resolveScopes(cfg config.BanConfig) ([]KeyScope, error) {
	names := cfg.BanKeys
	if len(names) == 0 {
		names = []string{cfg.BanKey}
	}

	scopes := make([]KeyScope, 0, len(names))
	seen := make(map[KeyScope]struct{}, len(names))
	for _, name := range names {
		scope, ok := ParseKeyScope(name)
		if !ok {
			return nil, fmt.Errorf("封禁键维度 %q 非法，可选值：%s",
				name, strings.Join(KeyScopeNames(), " / "))
		}
		if _, duplicated := seen[scope]; duplicated {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// siteNameOf 返回请求命中的站点名。
func siteNameOf(rctx *core.RequestContext) string {
	if rctx == nil || rctx.Site == nil {
		return core.DefaultSiteName
	}
	return rctx.Site.Name
}

// requestIDOf 返回请求标识（用于日志关联）。
func requestIDOf(rctx *core.RequestContext) string {
	if rctx == nil {
		return ""
	}
	return rctx.RequestID
}
