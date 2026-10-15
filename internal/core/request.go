package core

import (
	"io"
	"net/http"
	"time"
)

// RawRequest 是从代理注入头中还原出来的「原始业务请求」。
//
// 之所以需要还原：forward-auth 形态下，WAF 收到的是代理发出的子请求，
// 其 Method/URI/Host 都属于内部鉴权通道，真正被保护的请求信息全部在注入头里。
// 还原之后，所有校验单元只面向 RawRequest 工作，完全不感知 Nginx 与 Traefik 的差异。
type RawRequest struct {
	// Method 是原始请求方法，例如 GET / POST。
	Method string
	// URI 是原始请求的完整 URI（含查询串），例如 /api/user?id=1。
	URI string
	// Path 是原始请求的路径部分（不含查询串），例如 /api/user。
	Path string
	// RawQuery 是原始请求的查询串（不含问号），例如 id=1。
	RawQuery string
	// Host 是原始请求的 Host（可能来自 X-Forwarded-Host）。
	Host string
	// Proto 是原始请求的协议，例如 HTTP/1.1；可能来自 X-Forwarded-Proto。
	Proto string
	// Header 是原始请求头（已剔除代理内部鉴权通道相关的注入头，避免污染检测）。
	Header http.Header
	// ClientIP 是根据可信代理列表推导出的真实客户端 IP。
	ClientIP string
	// ClientIPChain 是解析出的转发链（从左到右），仅用于日志与取证；可能为空。
	//
	// 保留该字段的原因：当出现「限速误伤办公网 NAT 出口」这类问题时，
	// 只有完整链路才能解释「为什么把多个用户判成同一个来源」。
	ClientIPChain []string
	// PeerTrusted 表示 TCP 对端是否落在可信代理网段内。
	//
	// 为 false 时 ClientIP 直接取 TCP 对端地址，所有转发头被忽略（防伪造，验收项 A10）。
	PeerTrusted bool
	// ContentLength 是原始请求声明的请求体长度，-1 表示未知。
	ContentLength int64
	// ReceivedAt 是该请求到达 WAF 的时间，用于限速窗口与日志时间戳。
	ReceivedAt time.Time

	// Body 是原始请求体（尚未缓冲的原始流）。
	//
	// 生命周期约定：
	//   - 由接入适配器（RequestExtractor）在还原请求时填充；
	//   - 由 pipeline 在「存在启用的 PhaseBody 校验单元」时按需读取并缓冲，
	//     缓冲结果写入 RequestContext.Stream，随后本字段不再被读取；
	//   - 始终由 HTTP 处理层负责关闭（可能是网络连接或落盘的临时文件）。
	//
	// 为 nil 表示本次请求不携带请求体（或该接入形态不转发请求体，例如原生 Nginx）。
	Body io.ReadCloser
}

// HeaderValue 返回指定请求头的首个值，不存在时返回空字符串。
//
// 之所以提供该辅助方法：校验单元读取请求头非常频繁，直接使用 map 索引
// 会返回 []string，容易写出越界访问。此处统一收敛为「取首个值」语义。
func (r *RawRequest) HeaderValue(key string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return r.Header.Get(key)
}

// BodyMeta 描述请求体的元信息。
//
// 该结构的存在意义是满足「不做大体积读取」的约束：校验单元在多数场景下
// 只需要元信息（是否存在、多大、是否被截断），而不需要体内容本身。
type BodyMeta struct {
	// Present 表示本次请求是否携带请求体。
	Present bool
	// Bytes 是实际可读的请求体字节数（可能因超限被截断）。
	Bytes int64
	// Declared 是请求头声明的原始长度，-1 表示未知（例如 chunked 编码）。
	Declared int64
	// Truncated 表示请求体是否因超过限额而被截断。
	Truncated bool
	// Skipped 表示请求体因超限策略为 skip 而被整体跳过检测。
	Skipped bool
	// Missing 表示配置要求必须有请求体，但实际未收到。
	Missing bool
	// Spooled 表示请求体是否落盘到临时文件（超出内存阈值时）。
	Spooled bool
	// ContentType 是请求体的内容类型，便于日志与调试。
	ContentType string
	// Source 是请求体的来源通道，例如 request-body / none。
	Source string
	// Digest 是请求体内容的摘要（例如 SHA-256 十六进制），仅在需要时计算。
	Digest string
}

// BodyStream 是「按需读取」的请求体流。
//
// 实现必须支持流式读取，禁止一次性把整个请求体读入内存（设计文档 §2.5）。
// 当 pipeline 判定本次请求不存在启用的 PhaseBody 校验单元时，根本不会创建该流，
// 因此「不读体」是零成本的。
type BodyStream interface {
	// Read 实现流式读取，单次读取的数据量由调用方缓冲区大小决定。
	io.Reader
	// Rewind 把读取位置重置到起点。
	//
	// 之所以需要它：同一请求可能声明多个 PhaseBody 校验单元（例如「解码检查」与
	// 「CRS 体检测」），每个单元都需要从头读取同一份请求体。由于缓冲结果要么在内存
	// （bytes.Reader）要么在临时文件（*os.File），重置读取位置是零拷贝的。
	Rewind() error
	// Meta 返回请求体的元信息。
	Meta() BodyMeta
	// Close 释放底层资源（例如删除落盘的临时文件）。
	Close() error
}

// RequestExtractor 把代理注入的头与体还原成「原始业务请求」（需求 R1 / R3）。
//
// 之所以把它定义为接口：上层（server / pipeline）完全不感知 Nginx 与 Traefik 的差异，
// 代理差异全部收敛在适配层。实现位于 internal/ingress/forwardauth。
type RequestExtractor interface {
	// Extract 把鉴权子请求还原为原始业务请求。
	Extract(r *http.Request) (*RawRequest, error)
	// IngressType 返回实际生效的接入类型标识。
	//
	// 配置为 auto 时返回的是「判定后的具体类型」，便于日志与排障确认实际生效的通道。
	IngressType() string
}
