package store

import (
	"fmt"

	"github.com/weiyongkang/waf/internal/core"
)

// TLSSettings 是存储链路加密配置。
type TLSSettings struct {
	// Enabled 控制是否启用 TLS。
	Enabled bool `yaml:"enabled"`
	// CAFile 是自签 CA 证书路径（用于校验服务端证书）。
	CAFile string `yaml:"ca_file"`
	// CertFile / KeyFile 是客户端证书（双向认证时使用）。
	CertFile string `yaml:"cert_file"`
	// KeyFile 是客户端私钥路径。
	KeyFile string `yaml:"key_file"`
	// InsecureSkipVerify 关闭服务端证书校验；仅用于自签测试环境。
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Settings 是共享存储的私有配置片段（配置项 stores[].settings）。
//
// 之所以把三种后端的字段放在同一个结构里：
//
//  1. 配置文件里 stores[].settings 只有一份，而「三种拓扑 + 两种本地实现」的字段
//     是互不冲突的可选集合；
//  2. 用单一结构解析可以保持「严格模式」（未知字段直接报错），
//     避免为每个后端各写一份解析而导致拼写错误被静默忽略。
//
// 每个后端只读取自己关心的字段，其余字段被忽略（不报错但也不会生效）。
type Settings struct {
	// ------------------------------------------------------------------
	// 各后端共用
	// ------------------------------------------------------------------

	// Prefix 是键前缀，用于多环境共用同一存储时的隔离。
	Prefix string `yaml:"prefix"`
	// MaxEntries 是本地实现的条目上限（memory / file）。
	MaxEntries int `yaml:"max_entries"`
	// CleanupInterval 是本地实现的过期项清理周期（memory / file）。
	CleanupInterval core.Duration `yaml:"cleanup_interval"`

	// ------------------------------------------------------------------
	// memory 后端
	// ------------------------------------------------------------------

	// Shards 是内存实现的分片数（按 key 哈希分散锁竞争）。
	Shards int `yaml:"shards"`

	// ------------------------------------------------------------------
	// file 后端
	// ------------------------------------------------------------------

	// Path 是封禁名单持久化文件路径（file 后端必填）。
	Path string `yaml:"path"`
	// MaxFileBytes 是持久化文件大小上限，超过触发压缩重写。
	MaxFileBytes int64 `yaml:"max_file_bytes"`

	// ------------------------------------------------------------------
	// redis 后端
	// ------------------------------------------------------------------

	// Topology 是拓扑：standalone / sentinel / cluster。
	Topology string `yaml:"topology"`
	// Addrs 是地址列表（standalone 取首个；sentinel / cluster 填全部）。
	Addrs []string `yaml:"addrs"`
	// Username 是 Redis 6+ ACL 用户名。
	Username string `yaml:"username"`
	// Password 是认证密码。
	Password string `yaml:"password"`
	// DB 是数据库编号；cluster 拓扑下必须为 0。
	DB int `yaml:"db"`
	// MasterName 是哨兵拓扑下的主节点名称。
	MasterName string `yaml:"master_name"`
	// SentinelPassword 是哨兵自身的认证密码。
	SentinelPassword string `yaml:"sentinel_password"`
	// PoolSize 是连接池上限。
	PoolSize int `yaml:"pool_size"`
	// MinIdleConns 是保活的空闲连接数。
	MinIdleConns int `yaml:"min_idle_conns"`
	// DialTimeout 是建连超时。
	DialTimeout core.Duration `yaml:"dial_timeout"`
	// ReadTimeout 是读超时。
	ReadTimeout core.Duration `yaml:"read_timeout"`
	// WriteTimeout 是写超时。
	WriteTimeout core.Duration `yaml:"write_timeout"`
	// MaxRetries 是命令重试次数；0 表示不重试。
	MaxRetries int `yaml:"max_retries"`
	// TLS 是链路加密配置。
	TLS TLSSettings `yaml:"tls"`
	// LocalCacheTTL 是本地「已封禁」结论缓存时长；0 表示不缓存（封禁即时可见）。
	LocalCacheTTL core.Duration `yaml:"local_cache_ttl"`
	// LocalCacheEntries 是本地缓存条目上限。
	LocalCacheEntries int `yaml:"local_cache_entries"`
}

// decodeSettings 解析存储实例的配置片段（严格模式：未知字段直接报错）。
func decodeSettings(name string, raw map[string]any) (Settings, error) {
	var settings Settings
	if err := core.DecodeSettings(raw, &settings); err != nil {
		return Settings{}, fmt.Errorf("解析 stores[%s].settings 失败：%w", name, err)
	}
	return settings, nil
}
