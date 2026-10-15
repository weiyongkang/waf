package core

import (
	"context"
	"sync"
	"time"
)

// RequestContext 是单次请求在校验链中流转的上下文。
//
// 生命周期：由 HTTP Handler 在收到鉴权子请求后创建，贯穿全部校验单元，
// 最终由 responder 用于渲染响应、由 access 日志用于记录。
type RequestContext struct {
	// Context 是本次请求的上下文，由 HTTP 处理层创建、由校验链执行器绑定。
	//
	// 之所以需要它：Check.Evaluate 只接收 RequestContext，而访问共享存储、调用外部服务的
	// 校验单元必须能感知请求取消与超时（否则客户端断开后仍会继续占用连接与后端资源）。
	// 字段保证非 nil：NewRequestContext 兜底为 context.Background()。
	Context context.Context
	// RequestID 是本次请求的标识，同时写入响应头 X-WAF-Request-Id 与两类日志。
	RequestID string
	// ReceivedAt 是请求到达时间。
	ReceivedAt time.Time
	// Site 是命中的站点策略，永不为 nil（未命中任何站点时使用默认站点）。
	Site *Site
	// Raw 是还原后的原始业务请求。
	Raw *RawRequest
	// Body 是请求体元信息；Stream 为 nil 时表示本次请求不读取请求体。
	Body BodyMeta
	// Stream 是按需读取的请求体流；为 nil 表示本次请求不需要读取请求体。
	Stream BodyStream
	// IngressType 是实际生效的接入适配类型（auto 会被解析为具体类型）。
	IngressType string
	// Extra 是跨校验单元共享的附加信息（例如注入头缺失告警），
	// 只写不参与判定，用于日志补充。
	Extra map[string]string

	// stateMu 保护 State 的并发访问；校验链本体是串行的，
	// 但发布到 PhasePost 的异步动作（例如告警外送）可能并发读取。
	stateMu sync.RWMutex
	// state 是跨校验单元共享的状态存储（例如异常评分累计）。
	state map[string]any

	// results 记录已执行校验单元的结论，供日志与调试使用。
	results []*Result
}

// NewRequestContext 创建请求上下文并初始化内部状态容器。
func NewRequestContext(requestID string, receivedAt time.Time) *RequestContext {
	return &RequestContext{
		Context:    context.Background(),
		RequestID:  requestID,
		ReceivedAt: receivedAt,
		Raw:        &RawRequest{ReceivedAt: receivedAt},
		Site:       &Site{Name: DefaultSiteName, Hosts: []string{"*"}},
		Extra:      make(map[string]string),
		state:      make(map[string]any),
	}
}

// SetState 写入跨校验单元共享的状态。
func (c *RequestContext) SetState(key string, value any) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.state == nil {
		c.state = make(map[string]any)
	}
	c.state[key] = value
}

// State 读取跨校验单元共享的状态；不存在时返回 nil。
func (c *RequestContext) State(key string) any {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.state == nil {
		return nil
	}
	return c.state[key]
}

// AddScore 累加异常评分并返回累加后的总分。
//
// 调用约定：由执行器（internal/pipeline）在合并各校验单元结论时统一调用，
// 插件**不要**自行调用——插件只需填写 Result.Score，执行器会把它汇总到这里。
// 这样「一次命中只计一次分」，PhasePost 的 threshold 单元（以及需要读取总分的
// autoban 单元）读取到的就是唯一的权威总分。
func (c *RequestContext) AddScore(delta int) int {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.state == nil {
		c.state = make(map[string]any)
	}
	current, _ := c.state[StateKeyScore].(int)
	current += delta
	c.state[StateKeyScore] = current
	return current
}

// Score 返回当前累计的异常评分。
func (c *RequestContext) Score() int {
	value, _ := c.State(StateKeyScore).(int)
	return value
}

// AppendResult 记录一个已执行校验单元的结论。
func (c *RequestContext) AppendResult(res *Result) {
	if res == nil {
		return
	}
	c.results = append(c.results, res)
}

// Results 返回已执行校验单元的结论集合（只读用途）。
func (c *RequestContext) Results() []*Result {
	return c.results
}

// AllFindings 汇总全部校验单元的命中明细。
func (c *RequestContext) AllFindings() []Finding {
	var findings []Finding
	for _, res := range c.results {
		if res == nil {
			continue
		}
		findings = append(findings, res.Findings...)
	}
	return findings
}

// StateKeyScore 是异常评分在 State 中使用的键名。
const StateKeyScore = "anomaly_score"
