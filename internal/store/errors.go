package store

import "errors"

// 本文件定义共享存储对外暴露的哨兵错误。
//
// 之所以单独抽出一组哨兵错误而不是散落在各实现里：
// 插件需要区分「存储优雅关闭」「容量超限」「后端不可用」三类完全不同的失败，
// 并据此执行各自的 on_error 策略；而错误文本会随实现变化，不适合做判断依据。
var (
	// ErrStoreClosed 表示存储已关闭（进程正在退出）。
	ErrStoreClosed = errors.New("共享存储已关闭")

	// ErrCapacityExceeded 表示本地存储的条目数已达配置上限。
	//
	// 出现该错误通常意味着键空间异常膨胀（例如被扫描器以海量随机源 IP 触发限速），
	// 属于需要告警的容量事件。
	ErrCapacityExceeded = errors.New("共享存储条目数已达上限")

	// ErrStoreUnavailable 表示后端存储不可用（例如 Redis 连接失败）。
	//
	// 语义：调用方不应把「不可用」当作「未命中」——两者对安全判定的影响完全不同。
	// 处置方式由 stores[].on_error 决定（fail_open / fail_closed / fallback_local）。
	ErrStoreUnavailable = errors.New("共享存储不可用")

	// ErrUnknownTopology 表示 Redis 拓扑取值非法。
	ErrUnknownTopology = errors.New("未知的 Redis 拓扑")

	// ErrMissingAddress 表示缺少必需的地址配置。
	ErrMissingAddress = errors.New("缺少存储地址配置")

	// ErrMasterNameRequired 表示哨兵拓扑下未配置主节点名称。
	ErrMasterNameRequired = errors.New("sentinel 拓扑必须配置 master_name")
)
