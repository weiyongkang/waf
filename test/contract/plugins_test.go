// 本文件是契约测试的「内置插件装配点」。
//
// 与 cmd/waf/plugins.go 保持一致：契约测试走真实的装配路径（pipeline.New -> core.NewCheck），
// 因此必须先把插件包空白导入进来完成注册，否则配置里写 type: coraza / ratelimit
// 会直接报「类型未注册」。
//
// 之所以不把这些导入放到 harness_test.go：装配点集中在一个文件里，
// 新增插件时只需改这一处，避免遗漏导致契约测试出现与生产不一致的假象。
package contract

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
