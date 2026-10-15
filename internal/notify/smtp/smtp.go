// Package smtp 提供邮件告警通道实现（需求 P1-7）。
//
// 适用对象：值班邮箱、邮件组（mailing list）、工单系统收件地址。
// 邮件通道的特点决定了它在本项目中的定位：**低时效、高留存**。
// 因此它适合承接 error 级告警（需要留痕与升级），不适合承接高频 warn 级告警，
// 建议在配置里把本通道的 min_level 设为 error，或依赖 notify.suppress_window 抑制。
//
// 依赖说明：使用标准库 net/smtp。该包在 Go 官方文档中标注为「已冻结、不再接受新特性」，
// 但它并未被移除，且能完整覆盖「SMTP 提交 + STARTTLS + 认证」这一最基本场景。
// 选择它的原因与项目其余部分一致（需求 R10 / R14）：不引入第三方依赖，
// 从而保证 CGO_ENABLED=0 的静态单二进制交付。
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// Type 是本实现的注册类型名（配置中 notifiers[].type 的取值）。
const Type = "smtp"

// TLS 模式常量。
const (
	// tlsModeNone 使用明文 SMTP（仅在受信内网使用，例如本机 postfix 的 25 端口）。
	tlsModeNone = "none"
	// tlsModeStartTLS 先明文建连再通过 STARTTLS 升级加密（587 端口的常见形态）。
	tlsModeStartTLS = "starttls"
	// tlsModeImplicit 建连即 TLS（465 端口的常见形态，又称 SMTPS）。
	tlsModeImplicit = "tls"
)

// defaultPort 是未配置 settings.port 时使用的端口。
const defaultPort = 25

// maxHeaderValueBytes 是单个邮件头字段值的长度上限（字节）。
//
// 为什么需要上限：站点名、规则标题都来自配置或规则文件，理论上可被写成超长字符串；
// 反过来说，任何进入邮件头的值都必须经过「换行过滤 + 长度截断」，
// 否则会有邮件头注入（SMTP header injection）风险。
const maxHeaderValueBytes = 512

// init 在包初始化阶段完成类型注册（编译期装配，不使用任何动态加载）。
func init() {
	notify.Register(Type, New)
}

// Settings 是 smtp 通道的私有配置片段（配置文件中的 notifiers[].settings）。
type Settings struct {
	// Host 是 SMTP 服务器主机名（同时作为 TLS 的 ServerName 与认证域）。
	Host string `yaml:"host"`
	// Port 是 SMTP 端口，默认 25。
	Port int `yaml:"port"`
	// Username 是认证账号；留空表示不认证（匿名提交）。
	Username string `yaml:"username"`
	// Password 是认证密码。
	Password string `yaml:"password"`
	// From 是发件人地址，必填。
	From string `yaml:"from"`
	// To 是收件人地址列表，至少一个。
	To []string `yaml:"to"`
	// SubjectPrefix 是邮件主题前缀，默认 "[WAF]"。
	SubjectPrefix string `yaml:"subject_prefix"`
	// TLS 是加密模式：none / starttls / tls，默认 starttls。
	TLS string `yaml:"tls"`
	// InsecureTLS 为 true 时跳过 TLS 证书校验，仅用于自签名证书的内网邮件服务器。
	InsecureTLS bool `yaml:"insecure_tls"`
	// Timeout 是建连与写入的等待上限，覆盖 notify.timeout；为 0 表示继承全局值。
	Timeout core.Duration `yaml:"timeout"`
}

// notifier 是邮件通道实例。
type notifier struct {
	// name 是实例名。
	name string
	// host 是 SMTP 服务器主机名。
	host string
	// address 是 host:port。
	address string
	// from 是发件人地址。
	from string
	// to 是收件人列表。
	to []string
	// subjectPrefix 是主题前缀。
	subjectPrefix string
	// tlsMode 是加密模式。
	tlsMode string
	// tlsConfig 是 TLS 配置。
	tlsConfig *tls.Config
	// auth 是认证方式；为 nil 表示不认证。
	auth smtp.Auth
	// timeout 是建连与写入的等待上限。
	timeout time.Duration
	// deps 是通道依赖。
	deps notify.Deps
}

// New 依据通道声明构造邮件实例。
func New(inst notify.Instance, deps notify.Deps) (notify.Sender, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	host := strings.TrimSpace(settings.Host)
	if host == "" {
		return nil, fmt.Errorf("smtp 通道 %q 缺少 settings.host", inst.Name)
	}
	from := strings.TrimSpace(settings.From)
	if from == "" {
		return nil, fmt.Errorf("smtp 通道 %q 缺少 settings.from", inst.Name)
	}

	recipients := make([]string, 0, len(settings.To))
	for _, candidate := range settings.To {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		recipients = append(recipients, trimmed)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("smtp 通道 %q 的 settings.to 至少需要一个收件人地址", inst.Name)
	}

	port := settings.Port
	if port <= 0 {
		port = defaultPort
	}
	if port > 65535 {
		return nil, fmt.Errorf("smtp 通道 %q 的 settings.port = %d 非法，必须在 1-65535 之间", inst.Name, settings.Port)
	}

	tlsMode := strings.ToLower(strings.TrimSpace(settings.TLS))
	if tlsMode == "" {
		tlsMode = tlsModeStartTLS
	}
	switch tlsMode {
	case tlsModeNone, tlsModeStartTLS, tlsModeImplicit:
	default:
		return nil, fmt.Errorf("smtp 通道 %q 的 settings.tls = %q 不支持，可选：none / starttls / tls",
			inst.Name, settings.TLS)
	}

	timeout := settings.Timeout.Duration()
	if timeout <= 0 {
		timeout = deps.TimeoutOr()
	}

	var auth smtp.Auth
	username := strings.TrimSpace(settings.Username)
	if username != "" {
		// 说明：smtp.PlainAuth 会拒绝在「非 TLS 且非本机」的连接上发送口令，
		// 这是标准库内置的保护，避免口令被明文传输。因此 tls=none 时
		// 若配置了账号密码，会在发送阶段收到明确错误——这是预期行为，不做绕过。
		auth = smtp.PlainAuth("", username, settings.Password, host)
	}

	prefix := settings.SubjectPrefix
	if strings.TrimSpace(prefix) == "" {
		prefix = "[WAF]"
	}

	return &notifier{
		name:          inst.Name,
		host:          host,
		address:       net.JoinHostPort(host, itoa(port)),
		from:          from,
		to:            recipients,
		subjectPrefix: prefix,
		tlsMode:       tlsMode,
		tlsConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: settings.InsecureTLS,
			MinVersion:         tls.VersionTLS12,
		},
		auth:    auth,
		timeout: timeout,
		deps:    deps,
	}, nil
}

// Name 返回通道实例名。
func (n *notifier) Name() string { return n.name }

// Type 返回实现类型名。
func (n *notifier) Type() string { return Type }

// Send 把一条告警以邮件形式投递。
//
// 投递在独立协程中执行、由 select 保证 ctx 到期即返回：邮件服务器的
// 「连接慢、响应慢」是常态，不能让它占用 notify.Manager 的工作协程。
func (n *notifier) Send(ctx context.Context, alert core.Alert) error {
	message := n.buildMessage(alert)

	done := make(chan error, 1)
	go func() {
		done <- n.deliver(message)
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("smtp 通道 %q 投递失败：%w", n.name, err)
		}
		n.deps.LoggerOr().Debug("告警外送已送达", "channel", n.name, "type", Type)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("smtp 通道 %q 投递超时：%w", n.name, ctx.Err())
	}
}

// Close 释放通道资源。
//
// 本实现每次投递独立建连（不保持长连接）：邮件告警量级低，
// 保持长连接既无收益，又会让「连接被邮件服务器空闲断开」成为一个额外的失败面。
// 因此这里没有需要释放的资源。
func (n *notifier) Close() error { return nil }

// deliver 完成一次完整的 SMTP 会话。
func (n *notifier) deliver(message []byte) error {
	dialer := &net.Dialer{Timeout: n.timeout}
	conn, err := dialer.Dial("tcp", n.address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// 整体截止时间：既覆盖 TLS 握手，也覆盖后续每一轮 SMTP 交互，
	// 保证底层协程不会因为对端不说话而永久存活。
	_ = conn.SetDeadline(time.Now().Add(n.timeout))

	if n.tlsMode == tlsModeImplicit {
		tlsConn := tls.Client(conn, n.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, n.host)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if n.tlsMode == tlsModeStartTLS {
		if err := client.StartTLS(n.tlsConfig); err != nil {
			return err
		}
	}
	if n.auth != nil {
		if err := client.Auth(n.auth); err != nil {
			return err
		}
	}
	if err := client.Mail(n.from); err != nil {
		return err
	}
	for _, recipient := range n.to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// buildMessage 构造完整的 RFC 5322 报文（含头部与正文）。
func (n *notifier) buildMessage(alert core.Alert) []byte {
	payload := notify.BuildPayload(alert, n.deps)

	subject := n.subjectPrefix + " " + payload.Summary()
	subject = clampHeader(subject, maxHeaderValueBytes)

	at := payload.At
	if at == "" {
		at = n.deps.ClockOr().Now().Format(time.RFC1123Z)
	}

	var builder strings.Builder
	// 头部字段顺序遵循常见约定（From / To / Subject / Date / MIME）。
	// 所有取自告警数据的值都经过 sanitizeHeaderValue，防止邮件头注入。
	builder.WriteString("From: ")
	builder.WriteString(sanitizeHeaderValue(n.from, maxHeaderValueBytes))
	builder.WriteString("\r\n")
	builder.WriteString("To: ")
	builder.WriteString(sanitizeHeaderValue(strings.Join(n.to, ", "), maxHeaderValueBytes))
	builder.WriteString("\r\n")
	builder.WriteString("Subject: ")
	builder.WriteString(mime.BEncoding.Encode("UTF-8", subject))
	builder.WriteString("\r\n")
	builder.WriteString("Date: ")
	builder.WriteString(at)
	builder.WriteString("\r\n")
	builder.WriteString("MIME-Version: 1.0\r\n")
	builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	builder.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	builder.WriteString("\r\n")
	builder.WriteString(n.renderBody(payload))
	return []byte(builder.String())
}

// renderBody 渲染邮件正文。
//
// 正文只包含结构化字段与定位信息（request_id），**不含**原始请求体与请求头：
// 邮件会经由第三方邮件系统中转、在多个终端上留存，把业务数据放进去
// 等于把敏感数据的副本散播到不可控的位置（需求 P1-7 的约束）。
func (n *notifier) renderBody(payload notify.Payload) string {
	var builder strings.Builder
	builder.WriteString("WAF 告警\r\n")
	builder.WriteString("----------------------------------------\r\n")
	builder.WriteString("级别：" + payload.Level + "\r\n")
	builder.WriteString("标题：" + payload.Title + "\r\n")
	if payload.Message != "" {
		builder.WriteString("详情：" + payload.Message + "\r\n")
	}
	if payload.Site != "" {
		builder.WriteString("站点：" + payload.Site + "\r\n")
	}
	if payload.ClientIP != "" {
		builder.WriteString("客户端：" + payload.ClientIP + "\r\n")
	}
	if ruleID := payload.Fields["rule_id"]; ruleID != "" {
		builder.WriteString("规则：" + ruleID + "\r\n")
	}
	if payload.RequestID != "" {
		builder.WriteString("request_id：" + payload.RequestID + "\r\n")
	}
	builder.WriteString("时间：" + payload.At + "\r\n")
	builder.WriteString("实例：" + payload.Host + "\r\n")
	builder.WriteString("版本：" + payload.Version + "\r\n")
	builder.WriteString("----------------------------------------\r\n")
	builder.WriteString("完整上下文请按 request_id 在 WAF 访问日志中反查。\r\n")
	return builder.String()
}

// sanitizeHeaderValue 清洗进入邮件头的值：过滤换行并做长度截断。
//
// 安全性说明：CR / LF 是邮件头的分隔符，若告警标题里含有换行
// （例如规则名被构造成 "foo\r\nBcc: attacker@example.com"），
// 未清洗就会变成一次邮件头注入攻击，凭空给攻击者发出邮件副本。
func sanitizeHeaderValue(value string, limit int) string {
	cleaned := strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
	return clampHeader(cleaned, limit)
}

// clampHeader 按字节数截断头部值，并保证截断不落在 UTF-8 字符中间。
func clampHeader(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	truncated := value[:limit]
	// 逐字节回退到「整体是合法 UTF-8」的位置，避免把多字节字符切成两半。
	//
	// 为什么用 ValidString 而不是只判断末字节：一个 3 字节字符被截到
	// 只剩首字节 + 1 个续字节时，末字节确实是续字节（0x80-0xBF），
	// 但整段仍然是非法编码——只检查末字节会漏掉这种情况。
	// 每次截断最多回退 3 字节，因此这个循环的代价可以忽略。
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// itoa 把端口转换为十进制字符串（避免为了一个整数引入 strconv 的读者疑问）。
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 6)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// 编译期断言：确保 notifier 满足 notify.Sender 契约。
var _ notify.Sender = (*notifier)(nil)
