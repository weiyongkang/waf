package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/weiyongkang/waf/internal/core"
)

// Redis 拓扑常量（配置项 settings.topology）。
const (
	// TopologyStandalone 表示单机 / 主从（由外部负责故障切换）。
	TopologyStandalone = "standalone"
	// TopologySentinel 表示哨兵拓扑（客户端向哨兵查询主节点地址）。
	TopologySentinel = "sentinel"
	// TopologyCluster 表示 Redis Cluster（客户端按槽位路由）。
	TopologyCluster = "cluster"
)

// banNamespace 是封禁键在 Redis 中的二级命名空间。
//
// 之所以需要独立命名空间：List（`waf ban list`）需要按模式扫描出「全部封禁键」，
// 如果封禁键与限速计数键混在同一前缀下，扫描就会把海量计数键也翻出来。
const banNamespace = "ban:"

// defaultRedisPoolSize / defaultRedisMinIdleConns 是连接池默认值（配置文件可覆盖）。
const (
	defaultRedisPoolSize     = 64
	defaultRedisMinIdleConns = 4
)

// incrScript 是「自增 + 首次设置窗口」的原子脚本。
//
// 之所以必须用脚本而不是两条命令：多实例并发时，如果在 INCR 与 PEXPIRE 之间
// 另一个实例读到了 TTL=-1 的键，就会把「临时计数键」误判为永久键；
// 脚本在 Redis 侧原子执行，从根本上消除这个竞态（需求 R17）。
const incrScript = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`

// RedisStore 是基于 Redis 的共享存储实现，支持 standalone / sentinel / cluster 三种拓扑。
type RedisStore struct {
	// name 是存储实例名。
	name string
	// settings 是生效的 Redis 配置。
	settings Settings
	// client 是 go-redis 的统一客户端（三种拓扑共用同一接口）。
	client redis.UniversalClient
	// script 是自增脚本。
	script *redis.Script
	// cache 是本地「已封禁」结论缓存。
	cache *banCache
	// clock 是时间源，用于记录首次封禁时间。
	clock core.Clock
	// logger 是系统日志器。
	logger *slog.Logger
	// metrics 是指标写入接口。
	metrics core.MetricsRecorder
}

// RedisOptions 是 Redis 存储的构造参数。
type RedisOptions struct {
	// Name 是存储实例名。
	Name string
	// Settings 是强类型配置。
	Settings Settings
	// Logger 是系统日志器；可为 nil。
	Logger *slog.Logger
	// Metrics 是指标写入接口；可为 nil。
	Metrics core.MetricsRecorder
	// Clock 是时间源；为 nil 时使用系统时钟。
	Clock core.Clock
}

// NewRedisStore 构造 Redis 存储。
//
// 注意：构造阶段**不会**因为 Redis 暂时不可达而失败。原因：
// 「Redis 抖动」属于运行期故障，配置里已经通过 on_error 声明了处置方式
// （fail_open / fail_closed / fallback_local）；若在启动时直接失败，
// 反而让「有本地降级能力的部署」无法启动，与需求 R23 的意图相悖。
func NewRedisStore(opts RedisOptions) (*RedisStore, error) {
	settings := opts.Settings
	if settings.Topology == "" {
		settings.Topology = TopologyStandalone
	}
	if settings.PoolSize <= 0 {
		settings.PoolSize = defaultRedisPoolSize
	}
	if settings.MinIdleConns <= 0 {
		settings.MinIdleConns = defaultRedisMinIdleConns
	}

	addrs := normalizeAddrs(settings.Addrs)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w：stores[].settings.addrs 不能为空", ErrMissingAddress)
	}

	switch settings.Topology {
	case TopologyStandalone:
	case TopologySentinel:
		if settings.MasterName == "" {
			return nil, ErrMasterNameRequired
		}
	case TopologyCluster:
		if settings.DB != 0 {
			return nil, fmt.Errorf("cluster 拓扑不支持非 0 数据库（db=%d），请改为 0", settings.DB)
		}
	default:
		return nil, fmt.Errorf("%w：%q（可选值：standalone / sentinel / cluster）", ErrUnknownTopology, settings.Topology)
	}

	tlsConfig, err := buildTLSConfig(settings.TLS)
	if err != nil {
		return nil, err
	}

	metrics := opts.Metrics
	if metrics == nil {
		metrics = core.NoopMetrics{}
	}

	clock := opts.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	store := &RedisStore{
		name:     opts.Name,
		settings: settings,
		script:   redis.NewScript(incrScript),
		cache:    newBanCache(settings.LocalCacheTTL.Duration(), settings.LocalCacheEntries, clock),
		clock:    clock,
		logger:   opts.Logger,
		metrics:  metrics,
	}

	client, err := buildClient(settings, addrs, tlsConfig)
	if err != nil {
		return nil, err
	}
	store.client = client

	// 启动时做一次探活，仅用于日志（不改变构造结果，见上方注释）。
	ctx, cancel := context.WithTimeout(context.Background(), store.operationTimeout())
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		if store.logger != nil {
			store.logger.Warn("Redis 启动探活失败，将在运行期按 on_error 策略处理",
				"store", store.name, "topology", settings.Topology,
				"addrs", addrs, "error", err.Error())
		}
	} else if store.logger != nil {
		store.logger.Info("Redis 连接可用",
			"store", store.name, "topology", settings.Topology, "addrs", addrs)
	}

	return store, nil
}

// Name 返回存储实例名。
func (s *RedisStore) Name() string { return s.name }

// Topology 返回生效的拓扑名称，供启动日志输出。
func (s *RedisStore) Topology() string { return s.settings.Topology }

// Incr 在固定窗口内自增并返回计数与窗口剩余时间（core.Store 实现）。
func (s *RedisStore) Incr(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error) {
	if window <= 0 {
		return 0, 0, fmt.Errorf("限速窗口必须大于 0，当前 %s", window)
	}

	redisKey := s.settings.Prefix + key
	values, err := s.script.Run(ctx, s.client, []string{redisKey}, window.Milliseconds()).Slice()
	if err != nil {
		return 0, 0, s.wrapError("限速计数", err)
	}
	if len(values) < 2 {
		return 0, 0, s.wrapError("限速计数", fmt.Errorf("脚本返回值格式异常：%v", values))
	}

	count, ok := toInt64(values[0])
	if !ok {
		return 0, 0, s.wrapError("限速计数", fmt.Errorf("脚本返回的计数非法：%v", values[0]))
	}
	ttlMillis, ok := toInt64(values[1])
	if !ok || ttlMillis < 0 {
		// PTTL 返回负数说明键已消失（例如被运维清理），按「窗口刚建立」处理。
		ttlMillis = window.Milliseconds()
	}
	return count, time.Duration(ttlMillis) * time.Millisecond, nil
}

// Ban 把 key 加入封禁名单，已存在时强制覆盖（core.Store 实现）。
func (s *RedisStore) Ban(ctx context.Context, key string, ttl time.Duration, reason string) error {
	now := s.clock.Now()
	payload, err := encodeBanValue(reason, now, expiryFrom(now, ttl))
	if err != nil {
		return err
	}

	redisKey := s.banKey(key)
	if ttl <= 0 {
		// ttl<=0 表示永不过期：由调用方保证不会走到这里（ban.default_ttl 兜底），
		// 但实现仍需给出确定语义，避免「0 被当成立即过期」这种致命误解。
		if err := s.client.Set(ctx, redisKey, payload, 0).Err(); err != nil {
			return s.wrapError("写入封禁名单", err)
		}
	} else if err := s.client.Set(ctx, redisKey, payload, ttl).Err(); err != nil {
		return s.wrapError("写入封禁名单", err)
	}

	s.cache.remove(key)
	return nil
}

// BanIfAbsent 仅在 key 不存在时写入封禁记录（core.Store 实现）。
//
// 使用 Redis 的 SET NX 保证跨实例原子性：并发请求中只有一个能创建封禁，
// 其余请求不会修改已有记录的 TTL。
func (s *RedisStore) BanIfAbsent(ctx context.Context, key string, ttl time.Duration, reason string) (bool, error) {
	now := s.clock.Now()
	payload, err := encodeBanValue(reason, now, expiryFrom(now, ttl))
	if err != nil {
		return false, err
	}

	created, err := s.client.SetNX(ctx, s.banKey(key), payload, ttl).Result()
	if err != nil {
		return false, s.wrapError("写入封禁名单", err)
	}
	if created {
		// 本地缓存只缓存「已封禁」结论，新建记录时清除可能存在的旧条目，
		// 让后续查询以 Redis 中的真实 TTL 为准。
		s.cache.remove(key)
	}
	return created, nil
}

// IsBanned 查询封禁状态与剩余时长（core.Store 实现）。
func (s *RedisStore) IsBanned(ctx context.Context, key string) (bool, time.Duration, error) {
	if s.cache.has(key) {
		// 命中本地缓存：直接判定为已封禁，省掉一次 Redis 往返。
		// 剩余时长返回 0，表示「由远端名单决定」，不影响拦截结论。
		return true, 0, nil
	}

	redisKey := s.banKey(key)
	if _, err := s.client.Get(ctx, redisKey).Result(); err != nil {
		if err == redis.Nil {
			return false, 0, nil
		}
		return false, 0, s.wrapError("查询封禁名单", err)
	}

	ttl, err := s.client.TTL(ctx, redisKey).Result()
	if err != nil {
		// GET 已确认记录存在，但 TTL 查询失败时不能据此断言「未封禁」；
		// 按已封禁处理且不写本地缓存，避免把一次临时故障放大成缓存误拦截。
		return true, 0, nil
	}
	if ttl == -2 {
		// GET 与 TTL 之间封禁恰好到期：以 Redis 的最终状态为准，立即解除拦截。
		s.cache.remove(key)
		return false, 0, nil
	}
	// 本地缓存的有效期不能超过 Redis 中封禁的剩余 TTL，
	// 否则封禁到期后本实例仍会继续拦截最多 local_cache_ttl。
	s.cache.set(key, ttl)
	if ttl <= 0 {
		// -1 表示永不过期；0 通常表示剩余不足 1 秒。两者都不影响「已封禁」结论。
		return true, 0, nil
	}
	return true, ttl, nil
}

// List 列出当前封禁名单（core.Store 实现）。
//
// 实现方式：SCAN 游标遍历 + 逐键取剩余时长。
// 之所以用 SCAN 而不是 KEYS：KEYS 会阻塞 Redis 主线程，
// 在生产实例上属于高危命令（可能造成秒级停顿）。
func (s *RedisStore) List(ctx context.Context) ([]core.BanEntry, error) {
	pattern := s.settings.Prefix + banNamespace + "*"
	entries := make([]core.BanEntry, 0, 64)

	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 500).Result()
		if err != nil {
			return nil, s.wrapError("扫描封禁名单", err)
		}

		for _, redisKey := range keys {
			raw, err := s.client.Get(ctx, redisKey).Result()
			if err == redis.Nil {
				// SCAN 与 GET 之间记录已到期：不要把它作为「有效封禁」输出。
				continue
			}
			if err != nil {
				return nil, s.wrapError("读取封禁记录", err)
			}
			reason, bannedAt, expireAt := decodeBanValue(raw)

			ttl := time.Duration(0)
			value, err := s.client.TTL(ctx, redisKey).Result()
			if err == nil && value == -2 {
				// 同上：GET 与 TTL 之间恰好到期。
				continue
			}
			if err == nil && value > 0 {
				ttl = value
			}

			entries = append(entries, core.BanEntry{
				Key:      strings.TrimPrefix(redisKey, s.settings.Prefix+banNamespace),
				Reason:   reason,
				TTL:      ttl,
				BannedAt: bannedAt,
				ExpireAt: expireAt,
			})
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

// Unban 解除封禁（core.Store 实现）。
func (s *RedisStore) Unban(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, s.banKey(key)).Err(); err != nil {
		return s.wrapError("删除封禁记录", err)
	}
	// 本实例的本地缓存必须同步失效，否则会出现「已解封但仍被本实例拦截」的假象。
	s.cache.remove(key)
	return nil
}

// Close 关闭连接池；必须幂等。
func (s *RedisStore) Close() error {
	if s.client == nil {
		return nil
	}
	if err := s.client.Close(); err != nil {
		return fmt.Errorf("关闭 Redis 连接失败：%w", err)
	}
	s.client = nil
	return nil
}

// Ping 探测后端可用性，供启动自检与健康检查使用。
func (s *RedisStore) Ping(ctx context.Context) error {
	if s.client == nil {
		return ErrStoreClosed
	}
	return s.client.Ping(ctx).Err()
}

// banKey 拼接封禁键在 Redis 中的完整键名。
func (s *RedisStore) banKey(key string) string {
	return s.settings.Prefix + banNamespace + key
}

// operationTimeout 返回单次操作的超时上限。
//
// 取写超时与读超时的较大者：它只是「启动探活 / 健康检查」的上界，
// 真正的命令级超时由 go-redis 自身按配置控制。
func (s *RedisStore) operationTimeout() time.Duration {
	timeout := s.settings.ReadTimeout.Duration()
	if write := s.settings.WriteTimeout.Duration(); write > timeout {
		timeout = write
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	return timeout
}

// wrapError 统一包装 Redis 错误并累加存储错误指标。
//
// 之所以统一包装成 ErrStoreUnavailable：上层插件与 on_error 策略只关心
// 「后端是否可用」，而不关心底层的具体错误文本。
func (s *RedisStore) wrapError(operation string, err error) error {
	s.metrics.IncStoreError(s.name)
	return fmt.Errorf("%w：%s失败：%v", ErrStoreUnavailable, operation, err)
}

// buildClient 依据拓扑构造统一客户端。
func buildClient(settings Settings, addrs []string, tlsConfig *tls.Config) (redis.UniversalClient, error) {
	switch settings.Topology {
	case TopologySentinel:
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       settings.MasterName,
			SentinelAddrs:    addrs,
			Username:         settings.Username,
			Password:         settings.Password,
			SentinelPassword: settings.SentinelPassword,
			DB:               settings.DB,
			PoolSize:         settings.PoolSize,
			MinIdleConns:     settings.MinIdleConns,
			DialTimeout:      settings.DialTimeout.Duration(),
			ReadTimeout:      settings.ReadTimeout.Duration(),
			WriteTimeout:     settings.WriteTimeout.Duration(),
			MaxRetries:       settings.MaxRetries,
			TLSConfig:        tlsConfig,
			// 让命令遵循调用方 ctx 的取消与超时，避免请求结束后连接仍被占用。
			ContextTimeoutEnabled: true,
		}), nil
	case TopologyCluster:
		return redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:                 addrs,
			Username:              settings.Username,
			Password:              settings.Password,
			PoolSize:              settings.PoolSize,
			MinIdleConns:          settings.MinIdleConns,
			DialTimeout:           settings.DialTimeout.Duration(),
			ReadTimeout:           settings.ReadTimeout.Duration(),
			WriteTimeout:          settings.WriteTimeout.Duration(),
			MaxRetries:            settings.MaxRetries,
			TLSConfig:             tlsConfig,
			ContextTimeoutEnabled: true,
		}), nil
	default:
		return redis.NewClient(&redis.Options{
			Addr:                  addrs[0],
			Username:              settings.Username,
			Password:              settings.Password,
			DB:                    settings.DB,
			PoolSize:              settings.PoolSize,
			MinIdleConns:          settings.MinIdleConns,
			DialTimeout:           settings.DialTimeout.Duration(),
			ReadTimeout:           settings.ReadTimeout.Duration(),
			WriteTimeout:          settings.WriteTimeout.Duration(),
			MaxRetries:            settings.MaxRetries,
			TLSConfig:             tlsConfig,
			ContextTimeoutEnabled: true,
		}), nil
	}
}

// buildTLSConfig 依据配置构造 TLS 配置；未启用时返回 nil。
func buildTLSConfig(settings TLSSettings) (*tls.Config, error) {
	if !settings.Enabled {
		return nil, nil
	}

	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: settings.InsecureSkipVerify,
	}

	if settings.CAFile != "" {
		caPEM, err := os.ReadFile(settings.CAFile)
		if err != nil {
			return nil, fmt.Errorf("读取 Redis CA 证书失败：%w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("Redis CA 证书解析失败：%s", settings.CAFile)
		}
		config.RootCAs = pool
	}

	if settings.CertFile != "" && settings.KeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("加载 Redis 客户端证书失败：%w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

// normalizeAddrs 清理地址列表中的空白项。
func normalizeAddrs(addrs []string) []string {
	normalized := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			normalized = append(normalized, addr)
		}
	}
	return normalized
}

// encodeBanValue 把封禁原因与时间元数据编码为 Redis 值。
func encodeBanValue(reason string, bannedAt, expireAt time.Time) ([]byte, error) {
	payload := map[string]any{
		"reason":    reason,
		"banned_at": bannedAt.Format(time.RFC3339Nano),
	}
	if !expireAt.IsZero() {
		payload["expire_at"] = expireAt.Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("封禁值序列化失败：%w", err)
	}
	return encoded, nil
}

// decodeBanValue 从封禁值中解析原因与时间元数据。
//
// 之所以容错：名单里可能残留人工写入的裸文本（运维直接用 redis-cli 加名单），
// 或旧版本只写入了 at / reason 字段；解析失败时按纯文本原因展示，
// 时间字段缺失时返回零值，由调用方按「未知」处理。
func decodeBanValue(raw string) (reason string, bannedAt, expireAt time.Time) {
	var payload struct {
		Reason   string `json:"reason"`
		BannedAt string `json:"banned_at"`
		At       string `json:"at"`
		ExpireAt string `json:"expire_at"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return raw, time.Time{}, time.Time{}
	}
	reason = payload.Reason
	if reason == "" {
		reason = raw
	}
	bannedAt = parseRFC3339(payload.BannedAt)
	if bannedAt.IsZero() {
		bannedAt = parseRFC3339(payload.At)
	}
	expireAt = parseRFC3339(payload.ExpireAt)
	return reason, bannedAt, expireAt
}

// parseRFC3339 解析时间字段；空串或格式非法时返回零值。
func parseRFC3339(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// toInt64 把脚本返回的任意数值类型转换为 int64。
func toInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case float64:
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
