// Package wechat 提供企业微信群机器人告警通道实现（需求 P1-7）。
//
// 为什么企业微信要单独一个实现而不是复用 webhook：
//
//  1. **协议不同**：企业微信机器人要求固定的报文结构
//     （`{"msgtype":"markdown","markdown":{"content":"..."}}`），
//     直接把通用 JSON 载荷 POST 过去会被拒绝；
//  2. **判定语义不同**：企业微信在 HTTP 200 的情况下仍可能返回业务失败
//     （响应体里的 `errcode != 0`），必须解析响应体才能判断「到底发出去没有」。
//     通用 webhook 只按状态码判定，缺少这一层。
//
// 本文件为参考 reference/honeypot/internal/notify/wechat.go 后**重新实现**的版本
// （需求 R10）：借鉴其「markdown 报文 + 非 2xx 视为失败」的思路，
// 新增 `errcode` 业务判定、统一的 notify.Payload 载荷、可配置的响应体上限，
// 并按本项目规范重写、补充全中文注释。
package wechat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// Type 是本实现的注册类型名（配置中 notifiers[].type 的取值）。
const Type = "wechat"

// 消息格式常量。
const (
	// formatMarkdown 使用 markdown 消息，可读性最好，适合安全运营场景。
	formatMarkdown = "markdown"
	// formatText 使用纯文本消息，适合老旧客户端或被二次解析的链路。
	formatText = "text"
)

// defaultMaxResponseBytes 是未配置 max_response_bytes 时的响应体读取上限。
const defaultMaxResponseBytes = 64 * 1024

// init 在包初始化阶段完成类型注册（编译期装配，不使用任何动态加载）。
func init() {
	notify.Register(Type, New)
}

// Settings 是 wechat 通道的私有配置片段（配置文件中的 notifiers[].settings）。
type Settings struct {
	// URL 是企业微信机器人 webhook 地址，形如
	// https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<KEY>。
	URL string `yaml:"url"`
	// Format 是消息格式：markdown（默认）或 text。
	Format string `yaml:"format"`
	// InsecureTLS 为 true 时跳过 TLS 证书校验，仅用于私有化部署场景。
	InsecureTLS bool `yaml:"insecure_tls"`
	// Timeout 是单次送达超时，覆盖 notify.timeout；为 0 表示继承全局值。
	Timeout core.Duration `yaml:"timeout"`
	// MaxResponseBytes 是响应体读取上限（字节）；为 0 时使用内置默认值。
	MaxResponseBytes int `yaml:"max_response_bytes"`
}

// notifier 是企业微信通道实例。
type notifier struct {
	// name 是实例名。
	name string
	// url 是机器人 webhook 地址。
	url string
	// format 是消息格式。
	format string
	// client 是复用的 HTTP 客户端。
	client *http.Client
	// maxResponseBytes 是响应体读取上限。
	maxResponseBytes int
	// deps 是通道依赖。
	deps notify.Deps
}

// New 依据通道声明构造企业微信实例。
func New(inst notify.Instance, deps notify.Deps) (notify.Sender, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	target := strings.TrimSpace(settings.URL)
	if target == "" {
		return nil, fmt.Errorf("wechat 通道 %q 缺少 settings.url", inst.Name)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("wechat 通道 %q 的 settings.url 无法解析：%w", inst.Name, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("wechat 通道 %q 的 settings.url 协议必须是 http 或 https，当前为 %q",
			inst.Name, parsed.Scheme)
	}

	format := strings.ToLower(strings.TrimSpace(settings.Format))
	if format == "" {
		format = formatMarkdown
	}
	if format != formatMarkdown && format != formatText {
		return nil, fmt.Errorf("wechat 通道 %q 的 settings.format = %q 不支持，仅支持 markdown / text",
			inst.Name, settings.Format)
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
		format:           format,
		client:           notify.NewHTTPClient(timeout, settings.InsecureTLS),
		maxResponseBytes: maxResponseBytes,
		deps:             deps,
	}, nil
}

// Name 返回通道实例名。
func (n *notifier) Name() string { return n.name }

// Type 返回实现类型名。
func (n *notifier) Type() string { return Type }

// wechatMessage 是企业微信机器人接口的报文结构。
type wechatMessage struct {
	// MsgType 是消息类型：markdown / text。
	MsgType string `json:"msgtype"`
	// Markdown 仅当 MsgType 为 markdown 时存在。
	Markdown *wechatContent `json:"markdown,omitempty"`
	// Text 仅当 MsgType 为 text 时存在。
	Text *wechatContent `json:"text,omitempty"`
}

// wechatContent 是消息正文容器。
type wechatContent struct {
	// Content 是正文；markdown 类型下使用企业微信支持的 markdown 子集。
	Content string `json:"content"`
}

// wechatResponse 是企业微信接口的响应结构。
type wechatResponse struct {
	// ErrCode 为 0 表示成功；非 0 表示业务失败（例如 key 失效、频率超限）。
	ErrCode int `json:"errcode"`
	// ErrMsg 是错误描述。
	ErrMsg string `json:"errmsg"`
}

// Send 把一条告警推送到企业微信机器人。
func (n *notifier) Send(ctx context.Context, alert core.Alert) error {
	payload := notify.BuildPayload(alert, n.deps)

	message := wechatMessage{MsgType: n.format}
	content := wechatContent{Content: n.render(payload)}
	if n.format == formatText {
		message.Text = &content
	} else {
		message.Markdown = &content
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("wechat 通道 %q 序列化告警失败：%w", n.name, err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("wechat 通道 %q 构造请求失败：%w", n.name, err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := n.client.Do(request)
	if err != nil {
		return fmt.Errorf("wechat 通道 %q 请求失败：%w", n.name, err)
	}
	defer func() { _ = response.Body.Close() }()

	snippet, _ := io.ReadAll(io.LimitReader(response.Body, int64(n.maxResponseBytes)))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("wechat 通道 %q 返回非 2xx 状态 %d：%s",
			n.name, response.StatusCode, strings.TrimSpace(string(snippet)))
	}

	// HTTP 200 不代表成功：企业微信的业务错误码在响应体里。
	var parsed wechatResponse
	if err := json.Unmarshal(snippet, &parsed); err != nil {
		return fmt.Errorf("wechat 通道 %q 响应体无法解析（期望 JSON）：%s",
			n.name, strings.TrimSpace(string(snippet)))
	}
	if parsed.ErrCode != 0 {
		return fmt.Errorf("wechat 通道 %q 业务失败 errcode=%d errmsg=%s",
			n.name, parsed.ErrCode, parsed.ErrMsg)
	}

	n.deps.LoggerOr().Debug("告警外送已送达", "channel", n.name, "type", Type)
	return nil
}

// Close 释放通道资源。
func (n *notifier) Close() error {
	if n.client != nil {
		n.client.CloseIdleConnections()
	}
	return nil
}

// render 把标准载荷渲染为企业微信消息正文。
func (n *notifier) render(payload notify.Payload) string {
	if n.format == formatText {
		return payload.Summary()
	}

	var builder strings.Builder
	builder.WriteString("# ")
	builder.WriteString(levelBadge(payload.Level))
	builder.WriteString(" WAF 告警\n")
	builder.WriteString("> **")
	builder.WriteString(fallback(payload.Title, "WAF 告警"))
	builder.WriteString("**\n")
	if payload.Message != "" {
		builder.WriteString("> ")
		builder.WriteString(singleLine(payload.Message))
		builder.WriteString("\n")
	}
	if payload.Site != "" {
		builder.WriteString("> 站点：")
		builder.WriteString(payload.Site)
		builder.WriteString("\n")
	}
	if payload.ClientIP != "" {
		builder.WriteString("> 客户端：")
		builder.WriteString(payload.ClientIP)
		builder.WriteString("\n")
	}
	if ruleID := payload.Fields["rule_id"]; ruleID != "" {
		builder.WriteString("> 规则：")
		builder.WriteString(ruleID)
		builder.WriteString("\n")
	}
	if payload.RequestID != "" {
		builder.WriteString("> request_id：")
		builder.WriteString(payload.RequestID)
		builder.WriteString("\n")
	}
	builder.WriteString("> 时间：")
	builder.WriteString(payload.At)
	builder.WriteString("\n")
	if payload.Host != "" {
		builder.WriteString("> 实例：")
		builder.WriteString(payload.Host)
		builder.WriteString("\n")
	}
	return builder.String()
}

// levelBadge 把告警级别映射为 markdown 中的中文标识。
func levelBadge(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case string(core.AlertLevelError):
		return "严重"
	case string(core.AlertLevelWarn):
		return "警告"
	default:
		return "提示"
	}
}

// singleLine 把多行文本压成单行。
//
// 企业微信 markdown 的引用块（`>`）在换行处会断开，导致正文排版错乱；
// 压成单行是「保证渲染稳定」与「保留完整信息」之间的取舍，
// 完整的多行内容仍然可以通过 request_id 在访问日志中反查。
func singleLine(value string) string {
	replaced := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(value)
	return strings.Join(strings.Fields(replaced), " ")
}

// fallback 返回首选值；为空时返回兜底值。
func fallback(value string, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}

// 编译期断言：确保 notifier 满足 notify.Sender 契约。
var _ notify.Sender = (*notifier)(nil)
