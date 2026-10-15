// Package syslog 提供 syslog 告警通道实现（需求 P1-7）。
//
// 适用对象：已部署集中式日志平台（rsyslog / syslog-ng / SIEM 采集器）的环境。
// 用 syslog 而不是 HTTP 的典型理由：日志平台本来就是安全事件的汇聚点，
// 告警走同一条链路可以少维护一套外送配置与网络策略。
//
// **平台差异（务必注意）**：Go 标准库的 log/syslog 只在类 Unix 平台提供实现
// （见 log/syslog/syslog_unix.go 的 `//go:build !windows && !plan9`）。
// 因此本包按平台拆成两个文件：
//
//	syslog.go          公共部分（配置解析、报文渲染、超时控制）
//	platform_unix.go   !windows && !plan9：使用 log/syslog
//	platform_windows.go windows / plan9：构造时明确报错
//
// 这样做的收益是：在 Windows 上交叉编译产品二进制时不会因为一个未使用的通道
// 而导致整体编译失败；同时「Windows 上不支持」是启动期的明确错误，
// 而不是运行期才发现告警发不出去。
package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/notify"
)

// Type 是本实现的注册类型名（配置中 notifiers[].type 的取值）。
const Type = "syslog"

// 报文格式常量。
const (
	// formatSummary 输出一行可读摘要，适合直接人工阅读的 syslog 控制台。
	formatSummary = "summary"
	// formatJSON 输出完整 JSON，适合 SIEM / 日志平台的字段级解析。
	formatJSON = "json"
)

// init 在包初始化阶段完成类型注册（编译期装配，不使用任何动态加载）。
func init() {
	notify.Register(Type, New)
}

// Settings 是 syslog 通道的私有配置片段（配置文件中的 notifiers[].settings）。
type Settings struct {
	// Network 是传输协议：留空表示本机 syslog 套接字（/dev/log），
	// 也可显式配置 udp / tcp / unixgram / unix。
	//
	// 容器化部署请显式配置（例如 tcp + host:514）：容器内通常没有挂载 /dev/log，
	// 留空会退化为「本机套接字不存在」的启动错误。
	Network string `yaml:"network"`
	// Address 是目标地址，例如 127.0.0.1:514 或 /dev/log；
	// Network 非空时为必填。
	Address string `yaml:"address"`
	// Tag 是报文中的程序标识，默认 "waf"。
	Tag string `yaml:"tag"`
	// Facility 是 syslog 设施，默认 local0（避免与系统组件抢用 daemon / auth 等设施）。
	Facility string `yaml:"facility"`
	// Format 是报文格式：summary（默认，一行摘要）或 json（完整结构化载荷）。
	Format string `yaml:"format"`
	// Timeout 是单次写入的等待上限，覆盖 notify.timeout；为 0 表示继承全局值。
	//
	// 为什么需要：syslog 写 TCP 或 Unix 流式套接字时可能因为对端不读而阻塞，
	// 没有上限会让外送协程永久卡住。
	Timeout core.Duration `yaml:"timeout"`
}

// facility 是 syslog 设施编号（RFC 3164）。
//
// 只列出运维实际会用到的取值，编号与系统头文件一致（facility 占 PRI 的高 5 位）。
type facility int

const (
	// facilityKern 是内核。
	facilityKern facility = 0
	// facilityUser 是用户级。
	facilityUser facility = 1
	// facilityMail 是邮件系统。
	facilityMail facility = 2
	// facilityDaemon 是系统守护进程。
	facilityDaemon facility = 3
	// facilityAuth 是认证与授权。
	facilityAuth facility = 4
	// facilitySyslog 是 syslog 自身。
	facilitySyslog facility = 5
	// facilityLPR 是打印系统。
	facilityLPR facility = 6
	// facilityNews 是新闻系统。
	facilityNews facility = 7
	// facilityUUCP 是 UUCP。
	facilityUUCP facility = 8
	// facilityCron 是计划任务。
	facilityCron facility = 9
	// facilityAuthPriv 是私有认证信息。
	facilityAuthPriv facility = 10
	// facilityFTP 是 FTP 守护进程。
	facilityFTP facility = 11
	// facilityLocal0 是本地保留设施 0（默认取值）。
	facilityLocal0 facility = 16
	// facilityLocal1 是本地保留设施 1。
	facilityLocal1 facility = 17
	// facilityLocal2 是本地保留设施 2。
	facilityLocal2 facility = 18
	// facilityLocal3 是本地保留设施 3。
	facilityLocal3 facility = 19
	// facilityLocal4 是本地保留设施 4。
	facilityLocal4 facility = 20
	// facilityLocal5 是本地保留设施 5。
	facilityLocal5 facility = 21
	// facilityLocal6 是本地保留设施 6。
	facilityLocal6 facility = 22
	// facilityLocal7 是本地保留设施 7。
	facilityLocal7 facility = 23
)

// severity 是 syslog 严重级别编号（RFC 3164，占 PRI 的低 3 位）。
type severity int

const (
	// severityErr 是错误级，对应告警级别 error。
	severityErr severity = 3
	// severityWarning 是警告级，对应告警级别 warn。
	severityWarning severity = 4
	// severityInfo 是信息级，对应告警级别 info。
	severityInfo severity = 6
)

// facilityNames 是设施名到编号的映射（配置中 settings.facility 的可选值）。
var facilityNames = map[string]facility{
	"kern":     facilityKern,
	"user":     facilityUser,
	"mail":     facilityMail,
	"daemon":   facilityDaemon,
	"auth":     facilityAuth,
	"syslog":   facilitySyslog,
	"lpr":      facilityLPR,
	"news":     facilityNews,
	"uucp":     facilityUUCP,
	"cron":     facilityCron,
	"authpriv": facilityAuthPriv,
	"ftp":      facilityFTP,
	"local0":   facilityLocal0,
	"local1":   facilityLocal1,
	"local2":   facilityLocal2,
	"local3":   facilityLocal3,
	"local4":   facilityLocal4,
	"local5":   facilityLocal5,
	"local6":   facilityLocal6,
	"local7":   facilityLocal7,
}

// sink 是与平台无关的 syslog 写入抽象。
//
// 之所以抽出这一层：公共代码不应该出现任何 log/syslog 的符号，
// 否则 Windows 构建会因为缺少类型定义而失败。
type sink interface {
	// write 以指定严重级别写入一条消息。
	write(level severity, message string) error
	// close 释放底层连接。
	close() error
}

// notifier 是 syslog 通道实例。
type notifier struct {
	// name 是实例名。
	name string
	// format 是报文格式。
	format string
	// timeout 是单次写入的等待上限。
	timeout time.Duration
	// sink 是平台相关的写入器（构造期完成连接建立）。
	sink sink
	// deps 是通道依赖。
	deps notify.Deps
}

// New 依据通道声明构造 syslog 实例。
//
// 连接在构造期建立，因此「地址写错 / 套接字不存在」会在启动阶段暴露（fail fast）。
func New(inst notify.Instance, deps notify.Deps) (notify.Sender, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}

	network := strings.ToLower(strings.TrimSpace(settings.Network))
	switch network {
	case "", "udp", "tcp", "unixgram", "unix":
	default:
		return nil, fmt.Errorf("syslog 通道 %q 的 settings.network = %q 不支持，可选：udp / tcp / unixgram / unix（留空表示本机套接字）",
			inst.Name, settings.Network)
	}
	address := strings.TrimSpace(settings.Address)
	if network != "" && address == "" {
		return nil, fmt.Errorf("syslog 通道 %q 配置了 settings.network 就必须同时配置 settings.address（例如 127.0.0.1:514）",
			inst.Name)
	}

	tag := strings.TrimSpace(settings.Tag)
	if tag == "" {
		tag = "waf"
	}

	fac := facilityLocal0
	if value := strings.ToLower(strings.TrimSpace(settings.Facility)); value != "" {
		parsed, ok := facilityNames[value]
		if !ok {
			return nil, fmt.Errorf("syslog 通道 %q 的 settings.facility = %q 不支持（可选：kern / user / mail / daemon / auth / syslog / lpr / news / uucp / cron / authpriv / ftp / local0-local7）",
				inst.Name, settings.Facility)
		}
		fac = parsed
	}

	format := strings.ToLower(strings.TrimSpace(settings.Format))
	if format == "" {
		format = formatSummary
	}
	if format != formatSummary && format != formatJSON {
		return nil, fmt.Errorf("syslog 通道 %q 的 settings.format = %q 不支持，仅支持 summary / json",
			inst.Name, settings.Format)
	}

	timeout := settings.Timeout.Duration()
	if timeout <= 0 {
		timeout = deps.TimeoutOr()
	}

	writer, err := openSink(network, address, fac, tag)
	if err != nil {
		return nil, fmt.Errorf("syslog 通道 %q 连接失败：%w", inst.Name, err)
	}

	return &notifier{
		name:    inst.Name,
		format:  format,
		timeout: timeout,
		sink:    writer,
		deps:    deps,
	}, nil
}

// Name 返回通道实例名。
func (n *notifier) Name() string { return n.name }

// Type 返回实现类型名。
func (n *notifier) Type() string { return Type }

// Send 把一条告警写入 syslog。
//
// 写入动作放在独立协程里执行，由 select 保证 ctx 到期即返回：
// log/syslog 的 Writer 不支持超时，TCP 或流式套接字对端不读时会阻塞在 write 上。
// 协程会在底层 write 返回后自行退出（可能晚于本函数返回），
// 因此 Send 的耗时有上界，符合 notify.Sender 的契约要求。
func (n *notifier) Send(ctx context.Context, alert core.Alert) error {
	message, err := n.render(alert)
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- n.sink.write(severityFor(alert.Level), message)
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("syslog 通道 %q 写入失败：%w", n.name, err)
		}
		n.deps.LoggerOr().Debug("告警外送已送达", "channel", n.name, "type", Type)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("syslog 通道 %q 写入超时：%w", n.name, ctx.Err())
	}
}

// Close 释放 syslog 连接。
func (n *notifier) Close() error {
	if n.sink == nil {
		return nil
	}
	return n.sink.close()
}

// render 依据配置的格式渲染告警报文。
func (n *notifier) render(alert core.Alert) (string, error) {
	payload := notify.BuildPayload(alert, n.deps)
	if n.format == formatJSON {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("syslog 通道 %q 序列化告警失败：%w", n.name, err)
		}
		return string(encoded), nil
	}
	return payload.Summary(), nil
}

// severityFor 把告警级别映射为 syslog 严重级别。
//
// 未知级别按 info 处理：与通知门槛同一取向——宁可多报，不可静默丢弃。
func severityFor(level core.AlertLevel) severity {
	switch strings.ToLower(strings.TrimSpace(string(level))) {
	case string(core.AlertLevelError):
		return severityErr
	case string(core.AlertLevelWarn):
		return severityWarning
	default:
		return severityInfo
	}
}
