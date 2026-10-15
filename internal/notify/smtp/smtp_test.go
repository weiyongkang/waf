package smtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// testAlert 构造一条用于外送的测试告警。
func testAlert() core.Alert {
	return core.Alert{
		Level:     core.AlertLevelError,
		Title:     "共享存储不可用",
		Message:   "Redis 连接被拒绝",
		Site:      "shop",
		ClientIP:  "203.0.113.10",
		RequestID: "req-1",
		Fields:    map[string]string{"rule_id": "900200"},
		At:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// baseSettings 返回一组合法的通道配置。
func baseSettings() map[string]any {
	return map[string]any{
		"host": "smtp.example.com",
		"port": 587,
		"from": "waf@example.com",
		"to":   []any{"ops@example.com"},
		"tls":  "none",
	}
}

// newInstance 构造通道声明。
func newInstance(name string, settings map[string]any) notify.Instance {
	return notify.Instance{Name: name, Type: Type, Settings: settings}
}

// TestRegistered 验证包在被导入时完成了类型注册。
func TestRegistered(t *testing.T) {
	for _, name := range notify.RegisteredTypes() {
		if name == Type {
			return
		}
	}
	t.Fatalf("类型 %q 未注册，已注册类型：%v", Type, notify.RegisteredTypes())
}

// TestNewRejectsInvalidSettings 验证构造期的配置校验。
func TestNewRejectsInvalidSettings(t *testing.T) {
	cases := map[string]map[string]any{
		"缺少 host":  {"from": "a@b", "to": []any{"c@d"}},
		"缺少 from":  {"host": "smtp.example.com", "to": []any{"c@d"}},
		"缺少收件人":    {"host": "smtp.example.com", "from": "a@b"},
		"端口非法":     {"host": "smtp.example.com", "from": "a@b", "to": []any{"c@d"}, "port": 70000},
		"TLS 模式非法": {"host": "smtp.example.com", "from": "a@b", "to": []any{"c@d"}, "tls": "ssl"},
		"存在未知字段":   {"host": "smtp.example.com", "from": "a@b", "to": []any{"c@d"}, "subject": "x"},
	}
	for name, settings := range cases {
		if _, err := New(newInstance("t", settings), notify.Deps{}); err == nil {
			t.Fatalf("%s：应当返回错误", name)
		}
	}
}

// TestBuildMessageSanitizesHeaderInjection 验证邮件头注入被阻断。
//
// 攻击面：告警标题来自规则名或站点名，若其中含有 CR/LF
// （例如 rule 名被构造成 "x\r\nBcc: attacker@example.com"），
// 未清洗就会凭空给攻击者抄送一份告警邮件。
func TestBuildMessageSanitizesHeaderInjection(t *testing.T) {
	sender, err := New(newInstance("t", baseSettings()), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	notifier := sender.(*notifier)

	alert := testAlert()
	alert.Title = "标题\r\nBcc: attacker@example.com"
	message := string(notifier.buildMessage(alert))

	// 头部区域内不允许出现裸换行后紧跟 "Bcc:"。
	headerEnd := strings.Index(message, "\r\n\r\n")
	if headerEnd < 0 {
		t.Fatal("报文缺少头部与正文的分隔")
	}
	header := message[:headerEnd]
	if strings.Contains(header, "Bcc:") {
		t.Fatalf("邮件头被注入：\n%s", header)
	}
	for _, line := range strings.Split(header, "\r\n") {
		if !strings.Contains(line, ":") {
			t.Fatalf("头部出现非法行（缺少字段名）：%q", line)
		}
	}
}

// TestBuildMessageEncodesSubject 验证中文主题被正确编码，且报文包含必要头部。
func TestBuildMessageEncodesSubject(t *testing.T) {
	sender, err := New(newInstance("t", baseSettings()), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	notifier := sender.(*notifier)

	message := string(notifier.buildMessage(testAlert()))
	for _, expected := range []string{"From: waf@example.com", "To: ops@example.com", "Subject: =?UTF-8?", "Date: ", "Content-Type: text/plain; charset=UTF-8"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("报文缺少 %q：\n%s", expected, message)
		}
	}
	// 正文（8bit 明文）应保留中文原文，便于人工阅读。
	if !strings.Contains(message, "共享存储不可用") {
		t.Fatalf("正文缺少中文内容：\n%s", message)
	}
	// 正文不得包含原始请求体等敏感内容（需求 P1-7）。
	for _, forbidden := range []string{"请求体", "raw_body"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("正文不应包含 %q", forbidden)
		}
	}
}

// TestClampHeaderKeepsValidUTF8 验证头部截断不会切坏多字节字符。
func TestClampHeaderKeepsValidUTF8(t *testing.T) {
	value := strings.Repeat("告警", 200)
	for limit := 1; limit <= 40; limit++ {
		clamped := clampHeader(value, limit)
		if !utf8.ValidString(clamped) {
			t.Fatalf("limit=%d 时截断结果不是合法 UTF-8：%q", limit, clamped)
		}
		if len(clamped) > limit {
			t.Fatalf("limit=%d 时截断结果超长：%d", limit, len(clamped))
		}
	}
	// 限长非正数时不截断。
	if got := clampHeader("abc", 0); got != "abc" {
		t.Fatalf("limit<=0 应不截断，实际 %q", got)
	}
}

// TestSendThroughFakeServer 端到端验证 SMTP 会话流程（连接 -> EHLO -> MAIL -> RCPT -> DATA -> QUIT）。
func TestSendThroughFakeServer(t *testing.T) {
	server := newFakeSMTP(t)
	defer server.Close()

	settings := baseSettings()
	settings["host"] = "127.0.0.1"
	settings["port"] = server.port()
	settings["tls"] = "none"
	settings["timeout"] = "5s"

	sender, err := New(newInstance("t", settings), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err != nil {
		t.Fatalf("投递失败：%v", err)
	}

	lines := server.transcript()
	joined := strings.Join(lines, "\n")
	for _, expected := range []string{"EHLO", "MAIL FROM:<waf@example.com>", "RCPT TO:<ops@example.com>", "DATA", "QUIT"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("SMTP 会话缺少 %q：\n%s", expected, joined)
		}
	}
	if !strings.Contains(joined, "共享存储不可用") {
		t.Fatalf("邮件正文未包含告警标题：\n%s", joined)
	}
}

// TestSendFailsWhenServerUnreachable 验证连接失败时返回错误（而不是静默成功）。
func TestSendFailsWhenServerUnreachable(t *testing.T) {
	settings := baseSettings()
	settings["host"] = "127.0.0.1"
	// 取一个几乎不可能被监听的端口：先监听再立刻关闭，保证端口空闲。
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("无法获取空闲端口：%v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	settings["port"] = port
	settings["tls"] = "none"
	settings["timeout"] = "300ms"

	sender, err := New(newInstance("t", settings), notify.Deps{})
	if err != nil {
		t.Fatalf("构造通道失败：%v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), testAlert()); err == nil {
		t.Fatal("服务器不可达时应当返回错误")
	}
}

// fakeSMTP 是最小可用的假 SMTP 服务器，仅用于验证会话流程。
type fakeSMTP struct {
	// listener 是监听套接字。
	listener net.Listener
	// mu 保护 lines。
	mu sync.Mutex
	// lines 记录收到的全部命令行（用于断言会话流程）。
	lines []string
}

// newFakeSMTP 启动假服务器。
func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动假 SMTP 服务器失败：%v", err)
	}
	server := &fakeSMTP{listener: listener}
	go server.serve()
	return server
}

// port 返回监听端口。
func (s *fakeSMTP) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// Close 关闭服务器。
func (s *fakeSMTP) Close() {
	_ = s.listener.Close()
}

// transcript 返回收到的命令行副本。
func (s *fakeSMTP) transcript() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	lines := make([]string, len(s.lines))
	copy(lines, s.lines)
	return lines
}

// serve 接受单个连接并完成一轮 SMTP 对话。
func (s *fakeSMTP) serve() {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	writer := bufio.NewWriter(conn)
	writeLine := func(line string) {
		_, _ = writer.WriteString(line + "\r\n")
		_ = writer.Flush()
	}

	writeLine("220 fake ESMTP ready")
	reader := bufio.NewReader(conn)
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		s.record(trimmed)

		if inData {
			if trimmed == "." {
				inData = false
				writeLine("250 OK queued")
			}
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "EHLO"), strings.HasPrefix(trimmed, "HELO"):
			writeLine("250-fake greets you")
			writeLine("250 HELP")
		case strings.HasPrefix(trimmed, "MAIL FROM"):
			writeLine("250 OK")
		case strings.HasPrefix(trimmed, "RCPT TO"):
			writeLine("250 OK")
		case trimmed == "DATA":
			inData = true
			writeLine("354 End data with <CR><LF>.<CR><LF>")
		case trimmed == "QUIT":
			writeLine("221 Bye")
			return
		default:
			writeLine("250 OK")
		}
	}
}

// record 记录一行命令。
func (s *fakeSMTP) record(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
}
