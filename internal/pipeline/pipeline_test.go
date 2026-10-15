package pipeline

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// stubType 是测试用校验单元的注册类型名。
const stubType = "test-pipeline-stub"

// stubSettings 是测试用校验单元的配置片段。
type stubSettings struct {
	// Verdict 是期望返回的判定：空 / block / observe。
	Verdict string `yaml:"verdict"`
	// Fail 为 true 时返回错误，用于验证 on_error 策略。
	Fail bool `yaml:"fail"`
	// ReadBody 为 true 时读取请求体，用于验证按需读体与游标复位。
	ReadBody bool `yaml:"read_body"`
	// DefaultOnError 是该测试单元自报的失败策略默认值。
	DefaultOnError string `yaml:"default_on_error"`
}

// stubCheck 是测试用校验单元。
type stubCheck struct {
	name       string
	phase      core.Phase
	order      int
	settings   stubSettings
	evaluated  int
	closeCount int
	bodySeen   string
}

// Name 返回实例名。
func (c *stubCheck) Name() string { return c.name }

// Type 返回实现类型。
func (c *stubCheck) Type() string { return stubType }

// Phase 返回执行阶段。
func (c *stubCheck) Phase() core.Phase { return c.phase }

// Order 返回同阶段内的执行顺序。
func (c *stubCheck) Order() int { return c.order }

// DefaultOnError 返回自报的失败策略默认值。
func (c *stubCheck) DefaultOnError() string {
	if c.settings.DefaultOnError == core.OnErrorBlock {
		return core.OnErrorBlock
	}
	return core.OnErrorPass
}

// Evaluate 依据配置返回结论、错误或读取请求体。
func (c *stubCheck) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	c.evaluated++
	if c.settings.ReadBody && rctx.Stream != nil {
		data, err := io.ReadAll(rctx.Stream)
		if err != nil {
			return nil, err
		}
		c.bodySeen = string(data)
	}
	if c.settings.Fail {
		return &core.Result{Check: c.name}, errors.New("模拟校验单元内部故障")
	}

	switch c.settings.Verdict {
	case "block":
		return core.NewResult(c.name, core.VerdictBlock).
			AddFinding(core.NewFinding(c.name, "test_rule", "测试拦截", core.SeverityHigh, 5)), nil
	case "observe":
		return &core.Result{Verdict: core.VerdictObserve, Check: c.name, Score: 3}, nil
	default:
		return nil, nil
	}
}

// Close 记录关闭次数，用于验证幂等性。
func (c *stubCheck) Close() error {
	c.closeCount++
	return nil
}

var (
	// stubMu 保护 stubs 切片。
	stubMu sync.Mutex
	// stubs 记录本次用例中构造出的全部测试校验单元。
	stubs []*stubCheck
)

// init 注册测试用校验单元类型。
func init() {
	core.RegisterCheck(stubType, func(inst core.InstanceConfig, _ *core.Deps) (core.Check, error) {
		var settings stubSettings
		if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
			return nil, err
		}

		check := &stubCheck{
			name:     inst.Name,
			phase:    inst.Phase,
			order:    inst.Order,
			settings: settings,
		}
		stubMu.Lock()
		stubs = append(stubs, check)
		stubMu.Unlock()
		return check, nil
	})
}

// resetStubs 清空用例间的测试单元记录。
func resetStubs() {
	stubMu.Lock()
	stubs = nil
	stubMu.Unlock()
}

// findStub 按实例名取出测试单元；不存在时终止用例。
func findStub(t *testing.T, name string) *stubCheck {
	t.Helper()

	stubMu.Lock()
	defer stubMu.Unlock()
	for _, check := range stubs {
		if check.name == name {
			return check
		}
	}
	t.Fatalf("未找到实例 %q", name)
	return nil
}

// instance 构造一条测试用实例声明。
func instance(t *testing.T, name, phase string, order int, enabled bool, onError string, settings map[string]any) core.InstanceConfig {
	t.Helper()

	parsed, err := core.ParsePhase(phase)
	if err != nil {
		t.Fatalf("阶段取值非法：%v", err)
	}
	return core.InstanceConfig{
		Name:     name,
		Type:     stubType,
		Enabled:  enabled,
		Order:    order,
		Phase:    parsed,
		OnError:  onError,
		Settings: settings,
	}
}

// newTestPipeline 构造校验链并注册清理动作。
func newTestPipeline(t *testing.T, cfg Config) *Pipeline {
	t.Helper()

	resetStubs()
	deps := &core.Deps{Metrics: core.NoopMetrics{}, Clock: core.SystemClock{}}

	pipeline, err := New(cfg, deps)
	if err != nil {
		t.Fatalf("构造校验链失败：%v", err)
	}
	t.Cleanup(func() { _ = pipeline.Close() })
	return pipeline
}

// newContext 构造带原始请求的请求上下文。
func newContext(body string) *core.RequestContext {
	rctx := core.NewRequestContext("test-request", time.Now())
	rctx.Raw = &core.RawRequest{
		Method:        "POST",
		URI:           "/api/login",
		Path:          "/api/login",
		Host:          "example.com",
		Header:        map[string][]string{"Content-Type": {"application/json"}},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
	}
	return rctx
}

// bodyConfig 返回测试用请求体配置。
func bodyConfig() config.BodyConfig {
	return config.BodyConfig{
		Mode:            config.BodyModeOptional,
		Source:          "request-body",
		Lazy:            true,
		MaxBytes:        1024,
		ChunkBytes:      16,
		OnExceed:        config.BodyOnExceedTruncate,
		Spool:           config.SpoolMemory,
		MemoryThreshold: 0,
	}
}

// TestNewFiltersDisabledAndSorts 覆盖：关闭实例被丢弃，剩余实例按阶段 + order 排序。
func TestNewFiltersDisabledAndSorts(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "pre-20", "pre", 20, true, "", nil),
			instance(t, "request-10", "request", 10, true, "", nil),
			instance(t, "pre-10", "pre", 10, true, "", nil),
			instance(t, "disabled", "pre", 5, false, "", nil),
		},
	})

	want := []string{"pre-10", "pre-20", "request-10"}
	if len(pipeline.entries) != len(want) {
		t.Fatalf("启用实例数应为 %d，实际 %d", len(want), len(pipeline.entries))
	}
	for index, name := range want {
		if got := pipeline.entries[index].check.Name(); got != name {
			t.Fatalf("第 %d 个实例应为 %q，实际 %q", index, name, got)
		}
	}

	stubMu.Lock()
	defer stubMu.Unlock()
	for _, check := range stubs {
		if check.name == "disabled" {
			t.Fatal("enabled=false 的实例不应被构造")
		}
	}
}

// TestDecideShortCircuits 覆盖：终态结论立即中断串联。
func TestDecideShortCircuits(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "blocker", "request", 10, true, "", map[string]any{"verdict": "block"}),
			instance(t, "after", "request", 20, true, "", nil),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %s", result.Verdict)
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "test_rule" {
		t.Fatalf("命中明细未正确合并：%+v", result.Findings)
	}
	if got := findStub(t, "after").evaluated; got != 0 {
		t.Fatalf("短路后不应执行后续单元，实际执行 %d 次", got)
	}
}

// TestDecideRunsPostPhaseAfterShortCircuit 覆盖：链短路后收尾阶段（post）仍然执行。
//
// 之所以需要这条语义：PhasePost 承担评分聚合、封禁落地与告警外送，
// 这些动作必须在「已经拦截」的情况下依然发生，
// 否则「命中即拦截」的规则永远不会触发自动封禁与告警。
func TestDecideRunsPostPhaseAfterShortCircuit(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "blocker", "request", 10, true, "", map[string]any{"verdict": "block"}),
			instance(t, "after", "request", 20, true, "", nil),
			instance(t, "finalizer", "post", 90, true, "", nil),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %s", result.Verdict)
	}
	if got := findStub(t, "after").evaluated; got != 0 {
		t.Fatalf("短路后不应执行中间阶段单元，实际执行 %d 次", got)
	}
	if got := findStub(t, "finalizer").evaluated; got != 1 {
		t.Fatalf("短路后应执行收尾阶段单元，实际执行 %d 次", got)
	}
}

// TestDecideAggregatesScoreIntoContext 覆盖：各单元评分被汇总到请求上下文。
//
// 汇总的目的：PhasePost 的阈值单元只持有 RequestContext，
// 必须能读到「整条链的评分总量」，否则阈值判定无从下手。
func TestDecideAggregatesScoreIntoContext(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "observer", "request", 10, true, "", map[string]any{"verdict": "observe"}),
		},
	})

	rctx := newContext("")
	result := pipeline.Decide(context.Background(), rctx)
	if result.Score != 3 {
		t.Fatalf("结论评分应为 3，实际 %d", result.Score)
	}
	if rctx.Score() != 3 {
		t.Fatalf("请求上下文中的累计评分应为 3，实际 %d", rctx.Score())
	}
}

// TestDecideAllContinueMeansAllow 覆盖：全部单元无结论等价于放行（验收项 A3）。
func TestDecideAllContinueMeansAllow(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "noise-1", "request", 10, true, "", nil),
			instance(t, "noise-2", "post", 10, true, "", nil),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictAllow {
		t.Fatalf("期望放行结论，实际 %s", result.Verdict)
	}
	if result.Check != deciderName {
		t.Fatalf("放行结论的执行器名应为 %q，实际 %q", deciderName, result.Check)
	}
}

// TestDecideObserveThenBlock 覆盖：观察结论不短路，后续拦截结论可以覆盖它。
func TestDecideObserveThenBlock(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "observer", "request", 10, true, "", map[string]any{"verdict": "observe"}),
			instance(t, "blocker", "request", 20, true, "", map[string]any{"verdict": "block"}),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictBlock {
		t.Fatalf("期望拦截结论，实际 %s", result.Verdict)
	}
	if result.Score != 8 {
		t.Fatalf("评分应为 3（观察）+ 5（命中） = 8，实际 %d", result.Score)
	}
}

// TestDecideEmptyChainAllows 覆盖：空校验链直接放行，且不需要读体。
func TestDecideEmptyChainAllows(t *testing.T) {
	pipeline := newTestPipeline(t, Config{Instances: nil, Body: bodyConfig()})

	if pipeline.NeedsBody() {
		t.Fatal("空校验链不应需要读取请求体")
	}
	if result := pipeline.Decide(context.Background(), newContext("")); result.Verdict != core.VerdictAllow {
		t.Fatalf("期望放行结论，实际 %s", result.Verdict)
	}
}

// TestDecideOnErrorPass 覆盖：失败开放时放过请求并继续串联。
func TestDecideOnErrorPass(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "failing", "request", 10, true, "", map[string]any{"fail": true}),
			instance(t, "blocker", "request", 20, true, "", map[string]any{"verdict": "block"}),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictBlock {
		t.Fatalf("失败开放后应继续串联并拦截，实际 %s", result.Verdict)
	}
	if got := findStub(t, "blocker").evaluated; got != 1 {
		t.Fatalf("失败开放后应继续执行后续单元，实际执行 %d 次", got)
	}
}

// TestDecideOnErrorBlock 覆盖：失败关闭时返回服务不可用并短路。
func TestDecideOnErrorBlock(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "failing", "request", 10, true, core.OnErrorBlock, map[string]any{"fail": true}),
			instance(t, "after", "request", 20, true, "", nil),
		},
	})

	result := pipeline.Decide(context.Background(), newContext(""))
	if result.Verdict != core.VerdictUnavailable {
		t.Fatalf("失败关闭应返回服务不可用，实际 %s", result.Verdict)
	}
	if result.Err == nil {
		t.Fatal("失败关闭的结论应保留原始错误")
	}
	if got := findStub(t, "after").evaluated; got != 0 {
		t.Fatalf("失败关闭后不应执行后续单元，实际执行 %d 次", got)
	}
}

// TestDecideOnErrorFromImplementationDefault 覆盖：实例未配置 on_error 时取实现自报的默认值。
func TestDecideOnErrorFromImplementationDefault(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "failing", "request", 10, true, "", map[string]any{
				"fail":             true,
				"default_on_error": core.OnErrorBlock,
			}),
		},
	})

	if result := pipeline.Decide(context.Background(), newContext("")); result.Verdict != core.VerdictUnavailable {
		t.Fatalf("实现自报 block 时应失败关闭，实际 %s", result.Verdict)
	}
}

// TestNeedsBodyDependsOnBodyPhase 覆盖：仅当存在启用的体阶段单元且体通道可用时才读体（验收项 A14）。
func TestNeedsBodyDependsOnBodyPhase(t *testing.T) {
	cases := []struct {
		name      string
		instances []core.InstanceConfig
		body      config.BodyConfig
		want      bool
	}{
		{
			name:      "存在体阶段单元",
			instances: []core.InstanceConfig{instance(t, "body-check", "body", 10, true, "", nil)},
			body:      bodyConfig(),
			want:      true,
		},
		{
			name:      "只有头阶段单元",
			instances: []core.InstanceConfig{instance(t, "header-check", "request", 10, true, "", nil)},
			body:      bodyConfig(),
			want:      false,
		},
		{
			name:      "体阶段单元被关闭",
			instances: []core.InstanceConfig{instance(t, "body-check", "body", 10, false, "", nil)},
			body:      bodyConfig(),
			want:      false,
		},
		{
			name:      "体通道被禁用",
			instances: []core.InstanceConfig{instance(t, "body-check", "body", 10, true, "", nil)},
			body: func() config.BodyConfig {
				cfg := bodyConfig()
				cfg.Mode = config.BodyModeDisabled
				return cfg
			}(),
			want: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			pipeline := newTestPipeline(t, Config{Instances: testCase.instances, Body: testCase.body})
			if got := pipeline.NeedsBody(); got != testCase.want {
				t.Fatalf("NeedsBody 期望 %v，实际 %v", testCase.want, got)
			}
		})
	}
}

// TestDecideBuffersBodyOnceForAllBodyChecks 覆盖：请求体只读一次，多个体阶段单元均能读到完整内容。
func TestDecideBuffersBodyOnceForAllBodyChecks(t *testing.T) {
	body := `{"user":"admin"}`
	tracked := &trackingReadCloser{reader: strings.NewReader(body)}

	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "body-1", "body", 10, true, "", map[string]any{"read_body": true}),
			instance(t, "body-2", "body", 20, true, "", map[string]any{"read_body": true}),
		},
		Body: bodyConfig(),
	})

	rctx := newContext(body)
	rctx.Raw.Body = tracked
	rctx.Raw.ContentLength = int64(len(body))

	result := pipeline.Decide(context.Background(), rctx)
	if result.Verdict != core.VerdictAllow {
		t.Fatalf("期望放行结论，实际 %s", result.Verdict)
	}

	if got := findStub(t, "body-1").bodySeen; got != body {
		t.Fatalf("第一个体阶段单元读到的内容应为 %q，实际 %q", body, got)
	}
	// 第二个单元能读到完整内容，说明执行器在体阶段单元前完成了游标复位。
	if got := findStub(t, "body-2").bodySeen; got != body {
		t.Fatalf("第二个体阶段单元读到的内容应为 %q，实际 %q", body, got)
	}
	if rctx.Body.Bytes != int64(len(body)) {
		t.Fatalf("请求体元信息字节数应为 %d，实际 %d", len(body), rctx.Body.Bytes)
	}
	// 原始请求体只能被消费一次：若被两个体阶段单元各消费一次，字节数会翻倍。
	if tracked.bytesRead != int64(len(body)) {
		t.Fatalf("原始请求体应只被消费 %d 字节，实际 %d 字节", len(body), tracked.bytesRead)
	}
}

// TestDecideDoesNotReadBodyWithoutBodyPhase 覆盖：无体阶段单元时完全不读取请求体（验收项 A14）。
func TestDecideDoesNotReadBodyWithoutBodyPhase(t *testing.T) {
	tracked := &trackingReadCloser{reader: strings.NewReader("payload")}

	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{instance(t, "header-check", "request", 10, true, "", nil)},
		Body:      bodyConfig(),
	})

	rctx := newContext("payload")
	rctx.Raw.Body = tracked

	if result := pipeline.Decide(context.Background(), rctx); result.Verdict != core.VerdictAllow {
		t.Fatalf("期望放行结论，实际 %s", result.Verdict)
	}
	if tracked.bytesRead != 0 {
		t.Fatalf("无体阶段单元时不应读取请求体，实际读取 %d 字节", tracked.bytesRead)
	}
	if rctx.Stream != nil {
		t.Fatal("无体阶段单元时不应创建请求体流")
	}
}

// TestDecideRejectsOversizedBody 覆盖：超限策略为 reject 时返回 400 结论。
func TestDecideRejectsOversizedBody(t *testing.T) {
	cfg := bodyConfig()
	cfg.MaxBytes = 4
	cfg.OnExceed = config.BodyOnExceedReject

	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{instance(t, "body-check", "body", 10, true, "", map[string]any{"read_body": true})},
		Body:      cfg,
	})

	result := pipeline.Decide(context.Background(), newContext("0123456789"))
	if result.Verdict != core.VerdictBadRequest {
		t.Fatalf("超限拒绝应返回 400 结论，实际 %s", result.Verdict)
	}
	if got := findStub(t, "body-check").evaluated; got != 0 {
		t.Fatalf("超限拒绝时不应执行体阶段单元，实际执行 %d 次", got)
	}
}

// TestCloseIsIdempotent 覆盖：关闭必须幂等，且逆序关闭全部实例。
func TestCloseIsIdempotent(t *testing.T) {
	pipeline := newTestPipeline(t, Config{
		Instances: []core.InstanceConfig{
			instance(t, "first", "request", 10, true, "", nil),
			instance(t, "second", "request", 20, true, "", nil),
		},
	})

	if err := pipeline.Close(); err != nil {
		t.Fatalf("首次关闭不应返回错误：%v", err)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatalf("重复关闭不应返回错误：%v", err)
	}

	for _, name := range []string{"first", "second"} {
		if got := findStub(t, name).closeCount; got != 1 {
			t.Fatalf("实例 %q 的关闭次数应为 1，实际 %d", name, got)
		}
	}
}

// TestNewRollsBackOnUnknownType 覆盖：类型未注册时构造失败（fail fast）。
func TestNewRollsBackOnUnknownType(t *testing.T) {
	resetStubs()
	deps := &core.Deps{Metrics: core.NoopMetrics{}, Clock: core.SystemClock{}}

	_, err := New(Config{Instances: []core.InstanceConfig{{
		Name:    "unknown",
		Type:    "does-not-exist",
		Enabled: true,
		Phase:   core.PhaseRequest,
	}}, Body: bodyConfig()}, deps)
	if err == nil {
		t.Fatal("未注册的类型应当导致构造失败")
	}
}

// trackingReadCloser 统计底层读取器被消费的次数，用于验证「按需读体」与「只读一次」。
type trackingReadCloser struct {
	// reader 是被包装的原始读取器。
	reader io.Reader
	// bytesRead 是累计读取到的字节数。
	bytesRead int64
}

// Read 转发读取并累加计数。
func (r *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

// Close 关闭底层读取器（此处无资源可释放）。
func (r *trackingReadCloser) Close() error { return nil }
