package core

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Phase 决定校验单元在串联链中的执行阶段。
//
// 串联顺序固定为 Pre -> Request -> Body -> Post，同一阶段内再按 Order 升序排列。
// 阶段划分的意义：内存与 IO 代价高的能力（例如读请求体）必须晚于廉价的静态判断，
// 从而在廉价阶段短路时完全不产生昂贵开销。
type Phase int

const (
	// PhasePre 是引擎前阶段：封禁名单、IP 黑白名单、限速等纯元数据判断，
	// 不解析请求头与请求体，代价最低，应排在链首。
	PhasePre Phase = iota
	// PhaseRequest 是请求头阶段：Coraza header 阶段、UA/方法/协议校验、GeoIP 等，
	// 只需要请求行与请求头即可完成判断。
	PhaseRequest
	// PhaseBody 是请求体阶段：Coraza body 阶段、上传文件检查、解码类能力。
	// 只有存在该阶段的启用插件时，运行时才会真正读取请求体（按需读体）。
	PhaseBody
	// PhasePost 是引擎后阶段：异常评分阈值判定、自动封禁、告警外送等，
	// 用于对前序阶段收集到的结论做聚合与落地。
	PhasePost
)

// 阶段名称到枚举值的映射，用于配置解析。
var phaseByName = map[string]Phase{
	"pre":     PhasePre,
	"request": PhaseRequest,
	"body":    PhaseBody,
	"post":    PhasePost,
}

// 枚举值到阶段名称的映射，用于日志与配置摘要输出。
var phaseName = map[Phase]string{
	PhasePre:     "pre",
	PhaseRequest: "request",
	PhaseBody:    "body",
	PhasePost:    "post",
}

// String 返回阶段的小写名称，用于日志、指标标签与配置来源摘要。
func (p Phase) String() string {
	if name, ok := phaseName[p]; ok {
		return name
	}
	return fmt.Sprintf("phase(%d)", int(p))
}

// ParsePhase 把配置中的阶段字符串解析为 Phase。
//
// 支持 pre / request / body / post 四种取值；非法取值返回错误，
// 由配置校验阶段统一汇总后以「配置项 + 来源」的形式报错。
func ParsePhase(s string) (Phase, error) {
	if p, ok := phaseByName[s]; ok {
		return p, nil
	}
	return 0, fmt.Errorf("非法的阶段取值 %q，可选值：pre / request / body / post", s)
}

// UnmarshalYAML 实现 yaml.v3 的自定义反序列化，允许配置中直接写阶段名称字符串。
func (p *Phase) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := ParsePhase(value.Value)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalYAML 实现 yaml.v3 的自定义序列化，输出阶段名称字符串而非整数。
func (p Phase) MarshalYAML() (any, error) {
	return p.String(), nil
}
