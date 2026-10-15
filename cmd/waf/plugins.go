// 本文件是「内置插件装配点」。
//
// 设计意图（设计文档 §7.2）：所有校验单元实现通过「空白导入 + init 注册」的方式
// 在编译期完成装配，从而保证 CGO_ENABLED=0 下的单二进制交付，
// 不使用 Go plugin 包、不加载任何 .so 动态库。
//
// 装配方式：空白导入，由被导入包在 init 中调用 core.RegisterCheck 完成登记。
//
// 装配状态（对应 docs/development-roadmap.md）：
//
//	M1.2  passthrough            空校验单元（冒烟与压测基线对照）
//	M1.3  banlist                内部封禁名单查询（PhasePre）
//	      ipaccess               IP 黑白名单（PhasePre）
//	      ratelimit              多维限速（共享存储计数）
//	      threshold              异常评分阈值（PhasePost）
//	      autoban                自动封禁（PhasePost）
//	M1.5  coraza                 检测引擎（Coraza + CRS）
//	M3    notify/webhook        通用 HTTP 告警通道
//	      notify/wechat         企业微信群机器人告警通道
//	      notify/syslog         syslog 告警通道（仅类 Unix 平台）
//	      notify/smtp           邮件告警通道
//
// 注意：新增插件必须在此追加空白导入，否则配置里写该 type 会在启动阶段
// 报「类型未注册」并直接失败——这是刻意设计的 fail fast，
// 避免出现「配置里写了防护、实际没生效」。
package main

import (
	// autoban 把命中结论转化为内部封禁动作（PhasePost）。
	_ "github.com/weiyongkang/waf/internal/check/autoban"
	// banlist 查询内部封禁名单（PhasePre）。
	_ "github.com/weiyongkang/waf/internal/check/banlist"
	// coraza 是检测引擎（Coraza + CRS，PhaseRequest / PhaseBody）。
	_ "github.com/weiyongkang/waf/internal/check/coraza"
	// ipaccess 提供 IP 黑白名单（PhasePre）。
	_ "github.com/weiyongkang/waf/internal/check/ipaccess"
	// passthrough 是空校验单元，用于装配冒烟与压测基线对照。
	_ "github.com/weiyongkang/waf/internal/check/passthrough"
	// ratelimit 提供多维限速（共享存储计数）。
	_ "github.com/weiyongkang/waf/internal/check/ratelimit"
	// threshold 聚合异常评分并给出阈值结论（PhasePost）。
	_ "github.com/weiyongkang/waf/internal/check/threshold"

	// smtp 是邮件告警通道（复用 net/smtp，无第三方依赖）。
	_ "github.com/weiyongkang/waf/internal/notify/smtp"
	// syslog 是 syslog 告警通道（Windows 上构造会明确报错，见该包注释）。
	_ "github.com/weiyongkang/waf/internal/notify/syslog"
	// webhook 是通用 HTTP 告警通道。
	_ "github.com/weiyongkang/waf/internal/notify/webhook"
	// wechat 是企业微信群机器人告警通道。
	_ "github.com/weiyongkang/waf/internal/notify/wechat"
)
