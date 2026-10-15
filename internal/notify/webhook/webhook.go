// Package webhook 提供通用 HTTP 告警通道实现（需求 P1-7）。
//
// 适用对象：任何能接收 JSON POST 的采集端，例如自建告警网关、
// Alertmanager 的 webhook receiver、SIEM 的 HTTP 收集接口。
//
// 本实现刻意保持「薄」：只负责把 notify.Payload 序列化后 POST 出去，
// 不做模板渲染、不做重试（重试由 notify.Manager 统一负责）。
// 这样做的好处是「送达语义」只有一处实现，新增通道不会各自造一套重试逻辑。
//
// 本文件为参考 reference/honeypot/internal/notify/generic.go 后**重新实现**的版本
// （需求 R10）：仅借鉴「HTTP POST + 非 2xx 视为失败」的思路，
// 载荷结构、配置项、日志与错误处理均按本项目规范重写，并补充全中文注释。
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// Type 是本实现的注册类型名（配置中 notifiers[].type 的取值）。
const Type = "webhook"

// defaultMaxResponseBytes 是未配置 max_response_bytes 时的响应体读取上限。
//
// 为什么必须限制：对端返回一个巨大的响应体（或恶意/故障对端返回无限流）时，
// 不加限制的 io.ReadAll 会把内存吃光。这里读到上限即截断，仅用于错误提示。
const defaultMaxResponseBytes = 64 * 1024

// init 在包初始化阶段完成类型注册（编译期装配，不使用任何动态加载）。
func init() {
	notify.Register(Type, New)
}

// Settings 是 webhook 通道的私有配置片段（配置文件中的 notifiers[].settings）。
type Settings struct {
	// URL 是接收告警的 HTTP 端点，必须以 http:// 或 https:// 开头。
	URL string `yaml:"url"`
	// Method 是请求方法，默认 POST。仅支持 POST / PUT。
	Method string `yaml:"method"`
	// Headers 是附加请求头（例如自建网关需要的鉴权头）。
	//
	// 注意：这里可以承载令牌，因此配置文件本身的访问权限必须收敛（需求 R21 同源的运维要求）。
	Headers map[string]string `yaml:"headers"`
	// ContentType 是请求体的 Content-Type，默认 application/json。
	ContentType string `yaml:"content_type"`
	// InsecureTLS 为 true 时跳过 TLS 证书校验，仅用于自签名证书的内网环境。
	InsecureTLS bool `yaml:"insecure_tls"`
	// Timeout 是单次送达超时，覆盖 notify.timeout；为 0 表示继承全局值。
	Timeout core.Duration `yaml:"timeout"`
	// MaxResponseBytes 是响应体读取上限（字节）；为 0 时使用内置默认值。
	MaxResponseBytes int `yaml:"max_response_bytes"`
}

// notifier 是 webhook 通道实例。
type notifier struct {
	// name 是实例名。
	name string
	// url 是目标端点。
	url string
	// method 是请求方法。
	method string
	// headers 是附加请求头。
	headers map[string]string
	// contentType 是请求体类型。
	contentType string
	// client 是复用的 HTTP 客户端。
	//
	// 复用而不是每次新建：HTTP 客户端承载连接池，复用它才能让连续告警
	// 复用同一条 TCP 连接，避免每次外送都做一次 TCP + TLS 握手。
	client *http.Client
	// timeout 是单次送达超时。
	timeout time.Duration
	// maxResponseBytes 是响应体读取上限。
	maxResponseBytes int
	// deps 是通道依赖（日志 / 时间源 / 主机名等），构造载荷时需要用到。
	deps notify.Deps
}

// New 依据通道声明构造 webhook 实例。
func New(inst notify.Instance, deps notify.Deps) (notify.Sender, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	target := strings.TrimSpace(settings.URL)
	if target == "" {
		return nil, fmt.Errorf("webhook 通道 %q 缺少 settings.url", inst.Name)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("webhook 通道 %q 的 settings.url 无法解析：%w", inst.Name, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("webhook 通道 %q 的 settings.url 协议必须是 http 或 https，当前为 %q",
			inst.Name, parsed.Scheme)
	}

	method := strings.ToUpper(strings.TrimSpace(settings.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost && method != http.MethodPut {
		return nil, fmt.Errorf("webhook 通道 %q 的 settings.method = %q 不支持，仅支持 POST / PUT",
			inst.Name, settings.Method)
	}

	contentType := strings.TrimSpace(settings.ContentType)
	if contentType == "" {
		contentType = "application/json"
	}

	timeout := settings.Timeout.Duration()
	if timeout <= 0 {
		timeout = deps.TimeoutOr()
	}

	maxResponseBytes := settings.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}

	return &notifier{
		name:             inst.Name,
		url:              target,
		method:           method,
		headers:          settings.Headers,
		contentType:      contentType,
		client:           notify.NewHTTPClient(timeout, settings.InsecureTLS),
		timeout:          timeout,
		maxResponseBytes: maxResponseBytes,
		deps:             deps,
	}, nil
}

// Name 返回通道实例名。
func (n *notifier) Name() string { return n.name }

// Type 返回实现类型名。
func (n *notifier) Type() string { return Type }

// Send 把一条告警以 JSON 形式 POST 到目标端点。
func (n *notifier) Send(ctx context.Context, alert core.Alert) error {
	payload, err := json.Marshal(n.buildPayload(alert))
	if err != nil {
		return fmt.Errorf("webhook 通道 %q 序列化告警失败：%w", n.name, err)
	}

	request, err := http.NewRequestWithContext(ctx, n.method, n.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook 通道 %q 构造请求失败：%w", n.name, err)
	}
	request.Header.Set("Content-Type", n.contentType)
	for key, value := range n.headers {
		request.Header.Set(key, value)
	}

	response, err := n.client.Do(request)
	if err != nil {
		return fmt.Errorf("webhook 通道 %q 请求失败：%w", n.name, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, int64(n.maxResponseBytes)))
		_ = response.Body.Close()
	}()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// 读取有限长度的响应体用于排障：对端往往把失败原因写在响应体里，
		// 不回显这段内容会让「为什么发不出去」变成必须抓包才能回答的问题。
		snippet, _ := io.ReadAll(io.LimitReader(response.Body, int64(n.maxResponseBytes)))
		return fmt.Errorf("webhook 通道 %q 返回非 2xx 状态 %d：%s",
			n.name, response.StatusCode, strings.TrimSpace(string(snippet)))
	}
	n.deps.LoggerOr().Debug("告警外送已送达", "channel", n.name, "url", n.url, "status", response.StatusCode)
	return nil
}

// Close 释放通道资源。
//
// HTTP 客户端本身无需显式释放（其空闲连接由 IdleConnTimeout 回收），
// 这里关闭空闲连接只是为了在关停时立刻释放，而不是等超时。
func (n *notifier) Close() error {
	if n.client != nil {
		n.client.CloseIdleConnections()
	}
	return nil
}

// payload 是外送到目标端点的数据结构。
//
// 直接复用 notify.Payload 的字段（通过类型别名的方式保持结构一致），
// 保证「邮件 / syslog / webhook 看到的字段名完全相同」，
// 采集侧只需要维护一份解析规则。
type payload = notify.Payload

// buildPayload 构造外送载荷。
func (n *notifier) buildPayload(alert core.Alert) payload {
	return notify.BuildPayload(alert, n.deps)
}
