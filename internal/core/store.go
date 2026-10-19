package core

import (
	"context"
	"time"
)

// Store 提供跨请求、跨实例共享的状态：限速计数与内部封禁名单。
//
// 实现与启用策略（需求 R17 / R23）：
//   - redis  : 多实例共享；由 stores[].enabled 控制是否启用；
//   - memory : 本地内存，作为 redis 未启用或运行期降级时的默认实现；
//   - file   : 单机持久化（明确不用于多实例共享）。
//
// 启用规则：
//   - stores[].enabled=false -> 不连接 Redis，直接使用 fallback 指定的本地实现，
//     并以 warn 级写系统日志提示「多实例共享未启用」；
//   - 运行期 Redis 故障 -> 按 stores[].on_error 处理
//     （fail_open / fail_closed / fallback_local）。
//
// 并发安全性：所有实现必须可被多个 goroutine 并发调用。
// 生命周期：由 cmd/waf 在启动时创建、退出时 Close，禁止在校验单元内部创建。
type Store interface {
	// Incr 在滑动窗口内对 key 执行自增并返回当前计数与窗口剩余时间。
	//
	// 语义要求：
	//   - 首次自增时必须为 key 设置 TTL=window（同一窗口内的后续自增不重置 TTL），
	//     从而形成固定窗口计数；这是多实例共享限速的基础；
	//   - 返回值 count 为自增后的计数，ttl 为窗口剩余时间；
	//   - key 由调用方负责拼装（包含维度与窗口信息），Store 不做业务加工。
	Incr(ctx context.Context, key string, window time.Duration) (count int64, ttl time.Duration, err error)

	// Ban 把 key 加入封禁名单并设置 TTL；ttl <= 0 时由调用方使用 ban.default_ttl 兜底。
	// TTL 到期后名单自动失效，无需额外的解封任务。
	//
	// 语义说明：Ban 是「强制写入」——已存在同名记录时会覆盖原因与到期时间，
	// 供运维手工封禁（需要显式续期）使用。自动封禁请使用 BanIfAbsent。
	//
	// reason 会随名单项一并保存，供 `waf ban list` 与排障使用；
	// 之所以把 reason 放进接口而不是让实现自行拼装：原因文本只有调用方（校验单元）知道。
	Ban(ctx context.Context, key string, ttl time.Duration, reason string) error

	// BanIfAbsent 仅在 key 不存在或已过期时写入封禁记录，返回是否实际创建。
	//
	// 这是自动封禁的唯一正确写入方式：封禁到期时间必须在「首次封禁」时确定，
	// 后续相同来源的命中不能刷新 TTL，否则持续攻击会让封禁永不解除。
	// 实现必须保证判断与写入的原子性（Redis 使用 SET NX，内存实现持分片锁）。
	BanIfAbsent(ctx context.Context, key string, ttl time.Duration, reason string) (created bool, err error)

	// IsBanned 查询封禁状态与剩余时长。
	IsBanned(ctx context.Context, key string) (banned bool, remaining time.Duration, err error)

	// List 列出当前封禁名单中的全部条目，供 `waf ban list` 使用。
	List(ctx context.Context) ([]BanEntry, error)

	// Unban 解除封禁（运维手工操作）。
	Unban(ctx context.Context, key string) error

	// Close 释放连接与本地缓存；必须幂等。
	Close() error
}

// BanEntry 是封禁名单中的一条记录。
type BanEntry struct {
	// Key 是封禁键（例如客户端 IP）。
	Key string
	// Reason 是封禁原因。
	Reason string
	// Scope 是封禁维度。
	Scope string
	// RuleID / Check 是触发封禁的规则与校验单元。
	RuleID string
	Check  string
	// Target 是触发封禁的检测目标。
	Target string
	// URI / Query / Params 是触发封禁时的请求快照。
	URI        string
	Query      string
	ParamsJSON string
	// TTL 是剩余封禁时长。
	TTL time.Duration
	// BannedAt 是首次封禁时间；零值表示底层记录未提供该信息。
	BannedAt time.Time
	// ExpireAt 是封禁到期时间；零值表示永不过期或底层记录未提供该信息。
	ExpireAt time.Time
}

// BanDetail 是自动封禁的请求上下文快照。
//
// 该结构只由 internal/ban 在落地 BanRequest 时填充；人工封禁等没有请求上下文的
// 场景允许为零值。
type BanDetail struct {
	RequestID  string
	Check      string
	RuleID     string
	Target     string
	Scope      string
	URI        string
	Query      string
	ParamsJSON string
}

// BanDetailStore 是可选扩展接口：支持结构化保存封禁上下文的存储实现。
//
// 不直接扩展 Store，是为了保持 Redis / memory / file 等实现的兼容性；
// 不支持该接口时，ban.Manager 自动回退到普通 Ban / BanIfAbsent。
type BanDetailStore interface {
	BanWithDetail(ctx context.Context, key string, ttl time.Duration, reason string, detail BanDetail) error
	BanIfAbsentWithDetail(ctx context.Context, key string, ttl time.Duration, reason string, detail BanDetail) (bool, error)
}

// StoreResolver 按配置中的存储名解析已构建好的 Store 实例。
//
// 校验单元只持有该接口，因此完全不感知底层是 Redis、内存还是文件，
// 也不感知 Redis 是单机、哨兵还是集群拓扑（需求 R25）。
type StoreResolver interface {
	// Resolve 返回指定名称的 Store；名称不存在时返回错误（fail fast）。
	Resolve(name string) (Store, error)
	// Default 返回默认 Store（配置中名为 default 的实例，或唯一实例）。
	Default() (Store, error)
	// Names 返回全部已构建的 Store 名称，按字典序排列。
	Names() []string
}

// BanController 是「内部封禁」能力的抽象：查询来源是否被封禁 + 落地封禁动作。
//
// 之所以独立于 Store 并且不放在 pipeline 包：
//   - 校验单元只负责产出「应当封禁谁、封多久、为什么」（BanRequest）；
//   - 「用哪个存储、如何应用默认 / 上限时长、是否累进加长、如何写日志与指标」
//     属于运维策略，由 internal/ban.Manager 统一实现，
//     从而保证「banlist 查询的键」与「autoban 写入的键」永远一致。
//
// 实现位于 internal/ban（core 不反向依赖它，避免循环依赖）。
type BanController interface {
	// CheckScopes 按部署启用的全部封禁维度依次查询本次请求的来源，
	// 命中任一维度即返回（banned=true），并回传命中的键与维度用于日志与响应头。
	//
	// 之所以是「全部维度」而不是单一维度：一个部署可能同时按 IP、按 IP+路径 等
	// 多个维度封禁（需求 R5 / R6 允许配置多个维度），查询必须覆盖全部可能被写入的键，
	// 否则会出现「封了却没有生效」。
	//
	// 实现须按配置顺序短路：名单查询在每个请求的关键路径上，先命中即提前结束。
	CheckScopes(ctx context.Context, rctx *RequestContext) (banned bool, remaining time.Duration, key string, scope string, err error)

	// Ban 批量落地封禁动作；实现需保证「部分失败不影响其余动作」，
	// 返回的错误用于日志与指标，不应影响本次请求的判定结果（需求 R18）。
	Ban(ctx context.Context, rctx *RequestContext, requests []BanRequest) error

	// KeyFor 返回本次请求在主维度（ban.ban_key）下的封禁键，用于日志与排障。
	KeyFor(rctx *RequestContext) string

	// KeyForScope 返回本次请求在指定维度下的封禁键；维度非法或信息不足时返回空串。
	//
	// 校验单元必须通过该方法（而不是自行拼接）获取键，
	// 以保证「写入的键」与「banlist 查询的键」永远同源。
	KeyForScope(rctx *RequestContext, scope string) string

	// Scopes 返回运行期启用的封禁维度清单（按配置顺序），用于启动日志与校验。
	Scopes() []string
}
