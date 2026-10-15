// Package ftw 是 go-ftw 兼容用例的**离线执行器**（对应门禁 G2：在册用例全部通过）。
//
// 为什么自己实现执行器而不直接依赖 go-ftw：
//
//	go-ftw 是独立可执行文件，需要下载二进制、需要网络目标地址，
//	而本项目的交付约束是「无额外运行时依赖 + 可完全离线构建与回归」（R10 / R14）。
//	因此这里实现一个最小执行器：直接读 go-ftw 的用例格式，
//	在**进程内**驱动真实的校验链（config.Load -> pipeline -> coraza），
//	既保留了「用例格式与社区一致」的好处，又能编入 CI 与离线构建流程。
//
// 覆盖范围（刻意保持最小，避免变成另一个测试框架）：
//
//	input.method  请求方法
//	input.uri     请求 URI（含查询串）
//	input.headers 请求头（至少包含 Host）
//	input.data    请求体
//	output.log_contains / no_log_contains  对命中明细中的规则 ID 做包含/排除断言
//	output.status                          对最终对外状态码做断言
package ftw

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/logging"
	"github.com/weiyongkang/waf/internal/pipeline"
	"github.com/weiyongkang/waf/internal/responder"
	"github.com/weiyongkang/waf/internal/sites"
	"gopkg.in/yaml.v3"

	// 插件装配点：与 cmd/waf/plugins.go 保持一致。
	_ "github.com/weiyongkang/waf/internal/check/banlist"
	_ "github.com/weiyongkang/waf/internal/check/coraza"
	_ "github.com/weiyongkang/waf/internal/check/threshold"
)

// ftwCorpusDir 是默认的用例目录（相对本测试文件所在的包路径）。
const ftwCorpusDir = "../../configs/ftw"

// ftwConfigTemplate 是执行用例所用的配置模板。
//
// 与 test/contract 的做法一致：用「模板 + 占位符」而不是完整配置文件，
// 让「执行用例所需的配置」一眼可见、可审阅。
// 两个 %s 分别是系统日志目录与访问日志目录（均指向临时目录，避免污染工作区）。
const ftwConfigTemplate = `
version: 1
server:
  listen: ":0"
  metrics_listen: "127.0.0.1:0"
  read_header_timeout: 3s
  shutdown_timeout: 5s
ingress:
  path: "/waf/auth"
  deny_path: "/waf/deny"
  body:
    mode: optional
    source: request-body
    lazy: true
    max_bytes: 1048576
    chunk_bytes: 32768
    on_exceed: truncate
    spool: auto
    memory_threshold: 65536
    read_timeout: 2s
responder:
  type: json
  include_details: true
engine:
  enabled: true
  mode: on
  paranoia_level: 1
  anomaly_score_threshold: 5
  rules:
    dirs: []
    custom_dirs: []
    include: ["*.conf"]
    data_include: ["*.data"]
    crs_setup: crs-setup.conf
  inline_directives:
    - "SecRequestBodyAccess On"
  body:
    access: true
    limit_bytes: 13107200
    in_memory_limit_bytes: 131072
    limit_action: reject
    json_depth_limit: 4096
    parse_multipart: false
  hot_reload:
    enabled: false
    debounce: 1s
    poll_interval: 5s
    marker_file: ""
sites:
  - name: default
    hosts: ["*"]
    engine_mode: inherit
    pipeline: default
pipeline:
  - name: crs-header
    type: coraza
    enabled: true
    order: 30
    phase: request
    on_error: block
    settings:
      process_body: false
  - name: crs-body
    type: coraza
    enabled: true
    order: 31
    phase: body
    on_error: block
    settings:
      process_body: true
  - name: threshold
    type: threshold
    enabled: true
    order: 40
    phase: post
    settings:
      action: block
stores:
  - name: default
    type: memory
    enabled: true
    on_error: fallback_local
    settings: {}
ban:
  default_ttl: 30m
  max_ttl: 24h
  ban_key: client_ip
logging:
  system:
    enabled: false
    level: debug
    format: json
    outputs: ["file"]
    dir: "%s"
    file: waf-system
    rotate: daily
    max_file_bytes: 1048576
    keep_days: 1
  access:
    enabled: false
    level: info
    format: json
    outputs: ["file"]
    dir: "%s"
    file: waf-access
    rotate: daily
    max_file_bytes: 1048576
    keep_days: 1
metrics:
  enabled: false
  namespace: waf
  path: /metrics
`

// ftwCaseFile 是用例文件的顶层结构（go-ftw 兼容）。
type ftwCaseFile struct {
	Meta  ftwMeta   `yaml:"meta"`
	Tests []ftwTest `yaml:"tests"`
}

// ftwMeta 是用例集元信息。
type ftwMeta struct {
	Author      string `yaml:"author"`
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// ftwTest 是一条测试（可含多个 stage）。
type ftwTest struct {
	Title  string     `yaml:"test_title"`
	Desc   string     `yaml:"desc"`
	Stages []ftwStage `yaml:"stages"`
}

// ftwStage 是测试中的一个阶段。
type ftwStage struct {
	Stage ftwStageBody `yaml:"stage"`
}

// ftwStageBody 是阶段的内容（请求与期望）。
type ftwStageBody struct {
	Input  ftwInput  `yaml:"input"`
	Output ftwOutput `yaml:"output"`
}

// ftwInput 描述一次请求。
type ftwInput struct {
	Method  string            `yaml:"method"`
	URI     string            `yaml:"uri"`
	Headers map[string]string `yaml:"headers"`
	Data    string            `yaml:"data"`
}

// ftwOutput 描述期望输出。
type ftwOutput struct {
	// LogContains 期望命中明细中出现该片段（通常写作 'id "942100"'）。
	LogContains string `yaml:"log_contains"`
	// NoLogContains 期望命中明细中不出现该片段。
	NoLogContains string `yaml:"no_log_contains"`
	// Status 期望的对外 HTTP 状态码；0 表示不断言。
	Status int `yaml:"status"`
}

// ruleIDPattern 从 log_contains 片段中提取规则 ID。
//
// go-ftw 的原始语义是「在审计日志里匹配这段文本」，其中规则 ID 以
// `id "942100"` 的形式出现。本项目没有 ModSecurity 风格的审计日志文本，
// 因此把断言等价地落到「命中明细的规则 ID 集合」上：
// 提取引号中的 ID 前缀，并支持前缀匹配（'id "942' 表示 942xxx 全部）。
var ruleIDPattern = regexp.MustCompile(`id\s*"([0-9]*)`)

// TestFTWCorpus 读取 configs/ftw 下的全部用例并逐条执行。
//
// 每条用例都复用同一份已装配的校验链：Coraza 的规则编译很贵（数百毫秒），
// 逐条重新装配会让用例数增长时回归时间线性恶化。
// 用例之间彼此独立（只读同一引擎实例，Coraza 的 NewTransaction 是并发安全的）。
func TestFTWCorpus(t *testing.T) {
	dir := ftwCorpusDir
	if override := strings.TrimSpace(os.Getenv("WAF_FTW_DIR")); override != "" {
		dir = override
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatalf("匹配用例文件失败：%v", err)
	}
	if len(files) == 0 {
		t.Fatalf("在 %s 中未找到任何 *.yaml 用例文件", dir)
	}
	sort.Strings(files)

	decider := newDecider(t)

	total := 0
	for _, path := range files {
		file := loadCaseFile(t, path)
		if !file.Meta.Enabled {
			t.Logf("跳过已禁用的用例集：%s", file.Meta.Name)
			continue
		}
		for _, test := range file.Tests {
			for index, stage := range test.Stages {
				name := fmt.Sprintf("%s/%s#%d", file.Meta.Name, test.Title, index+1)
				total++
				t.Run(name, func(t *testing.T) {
					runStage(t, decider, stage.Stage)
				})
			}
		}
	}
	t.Logf("go-ftw 离线回归：共执行 %d 个阶段", total)
}

// loadCaseFile 读取并解析用例文件（严格模式，拼写错误直接报错）。
func loadCaseFile(t *testing.T, path string) *ftwCaseFile {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取用例文件 %s 失败：%v", path, err)
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)

	var file ftwCaseFile
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("解析用例文件 %s 失败：%v", path, err)
	}
	if len(file.Tests) == 0 {
		t.Fatalf("用例文件 %s 不含任何 tests", path)
	}
	return &file
}

// runStage 执行一个阶段并断言输出。
func runStage(t *testing.T, decider core.Decider, stage ftwStageBody) {
	t.Helper()

	rctx := buildContext(stage.Input)
	result := decider.Decide(rctx.Context, rctx)

	status := statusForResult(result)

	if stage.Output.Status != 0 && status != stage.Output.Status {
		t.Fatalf("状态码 = %d，期望 %d（verdict=%s code=%s message=%s findings=%s）",
			status, stage.Output.Status, result.Verdict, result.Code, result.Message, describeFindings(result))
	}

	if pattern := strings.TrimSpace(stage.Output.LogContains); pattern != "" {
		if !matchesFinding(result, pattern) {
			t.Fatalf("期望命中明细包含 %q，实际命中：%s", pattern, describeFindings(result))
		}
	}
	if pattern := strings.TrimSpace(stage.Output.NoLogContains); pattern != "" {
		if matchesFinding(result, pattern) {
			t.Fatalf("期望命中明细不包含 %q，实际命中：%s", pattern, describeFindings(result))
		}
	}
}

// statusForResult 计算代理最终观察到的 HTTP 状态码。
//
// 为什么不能只用 responder.StatusForCode：放行分支在 internal/server 中是**显式回 200**
// （并携带 X-WAF-Verdict 等响应头），根本不经过「错误码 -> 状态码」的映射；
// 只有拦截类结论才会走 responder。执行器必须复刻这条分支，否则放行用例会被算成 403。
// 两处逻辑的等价性由契约测试（test/contract）间接保障。
func statusForResult(result *core.Result) int {
	if result == nil {
		return http.StatusOK
	}
	switch result.Verdict {
	case core.VerdictAllow, core.VerdictObserve:
		// 显式放行与旁路观察都不阻断请求：对外状态码是 200。
		return http.StatusOK
	}
	if result.Code != "" {
		return responder.StatusForCode(result.Code)
	}
	return responder.StatusForCode(responder.CodeForVerdict(result.Verdict))
}

// matchesFinding 判断命中明细是否匹配 go-ftw 风格的 log_contains 片段。
func matchesFinding(result *core.Result, pattern string) bool {
	if result == nil {
		return false
	}

	submatch := ruleIDPattern.FindStringSubmatch(pattern)
	if len(submatch) < 2 || submatch[1] == "" {
		// 片段中没有规则 ID：退化为「任意命中明细的文本包含」，
		// 保证用例作者写的其它片段（例如自研规则标识）也能被断言。
		for _, finding := range result.Findings {
			if strings.Contains(finding.RuleID, pattern) || strings.Contains(finding.Message, pattern) {
				return true
			}
		}
		return false
	}

	prefix := submatch[1]
	for _, finding := range result.Findings {
		if strings.HasPrefix(finding.RuleID, prefix) {
			return true
		}
	}
	return false
}

// describeFindings 生成「实际命中」的可读描述，用于断言失败时的排障。
func describeFindings(result *core.Result) string {
	if result == nil || len(result.Findings) == 0 {
		return "（无命中）"
	}
	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.RuleID)
	}
	return "[" + strings.Join(ids, ",") + "]"
}

// buildContext 依据用例的输入构造请求上下文。
func buildContext(input ftwInput) *core.RequestContext {
	now := time.Now()
	rctx := core.NewRequestContext("ftw", now)

	header := make(http.Header, len(input.Headers))
	for name, value := range input.Headers {
		header.Set(name, value)
	}

	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}

	path, rawQuery := splitURI(input.URI)

	body := input.Data
	raw := &core.RawRequest{
		Method:        method,
		URI:           input.URI,
		Path:          path,
		RawQuery:      rawQuery,
		Host:          header.Get("Host"),
		Proto:         "HTTP/1.1",
		Header:        header,
		ClientIP:      "203.0.113.10",
		PeerTrusted:   true,
		ContentLength: int64(len(body)),
		ReceivedAt:    now,
	}
	if body != "" {
		raw.Body = io.NopCloser(strings.NewReader(body))
		// 保真：真实 HTTP 请求携带请求体时，net/http 一定会补齐 Content-Length 头。
		// 漏掉它会让 CRS 的 920180（POST 缺少 Content-Length / Transfer-Encoding）误报，
		// 造成「离线用例变红、线上却放行」的假阴性。
		header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}

	rctx.Raw = raw
	return rctx
}

// splitURI 拆分 URI 的路径与查询串。
func splitURI(uri string) (path, query string) {
	if index := strings.Index(uri, "?"); index >= 0 {
		return uri[:index], uri[index+1:]
	}
	return uri, ""
}

// newDecider 按真实装配路径构建校验链。
func newDecider(t *testing.T) core.Decider {
	t.Helper()

	logDir := t.TempDir()
	// Windows 路径含反斜杠，写进双引号 YAML 标量会被当成转义序列，统一转正斜杠。
	slashDir := filepath.ToSlash(logDir)

	path := filepath.Join(t.TempDir(), "ftw.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(ftwConfigTemplate, slashDir, slashDir)), 0o600); err != nil {
		t.Fatalf("写入执行器配置失败：%v", err)
	}

	resolved, err := config.Load(config.Options{
		ConfigFiles:           []string{path},
		SkipDefaultConfigPath: true,
	})
	if err != nil {
		t.Fatalf("加载执行器配置失败：%v", err)
	}
	cfg := resolved.Config

	loggers, err := logging.Build(cfg.Logging)
	if err != nil {
		t.Fatalf("日志装配失败：%v", err)
	}
	t.Cleanup(func() { _ = loggers.Close() })

	siteResolver, err := sites.New(sites.Options{Declared: cfg.Sites})
	if err != nil {
		t.Fatalf("站点策略装配失败：%v", err)
	}

	deps := &core.Deps{
		SystemLogger: loggers.System,
		AccessLogger: loggers.Access,
		Metrics:      core.NoopMetrics{},
		Clock:        core.SystemClock{},
		Limits: core.Limits{
			MaxHeaderBytes:     cfg.Limits.MaxHeaderBytes,
			MaxScanTokenBytes:  cfg.Limits.MaxScanTokenBytes,
			MaxIntelFileBytes:  cfg.Limits.MaxIntelFileBytes,
			MaxRuleFileBytes:   cfg.Limits.MaxRuleFileBytes,
			MaxRulesTotalBytes: cfg.Limits.MaxRulesTotalBytes,
		},
		Sites:   siteResolver.Sites(),
		Engine:  engineSettings(cfg),
		Version: "ftw-test",
	}

	decider, err := pipeline.New(pipeline.Config{
		Instances: cfg.Pipeline,
		Body:      cfg.Ingress.Body,
	}, deps)
	if err != nil {
		t.Fatalf("校验链装配失败：%v", err)
	}
	t.Cleanup(func() { _ = decider.Close() })
	return decider
}

// engineSettings 把配置树的 engine 段映射为 core.EngineSettings。
//
// 与 cmd/waf/cmd_run.go 保持等价：离线执行器必须走与生产完全相同的映射，
// 否则会出现「用例通过、线上不生效」的假象（这也是 M1.6 契约测试确立的原则）。
func engineSettings(cfg *config.Config) core.EngineSettings {
	engine := cfg.Engine
	processors := make([]core.BodyProcessorSetting, 0, len(engine.Body.Processors))
	for _, item := range engine.Body.Processors {
		processors = append(processors, core.BodyProcessorSetting{
			Name:         item.Name,
			ContentTypes: item.ContentTypes,
			Enabled:      item.Enabled,
		})
	}

	exceptions := make([]core.ExceptionSetting, 0, len(engine.Exceptions))
	for _, item := range engine.Exceptions {
		// 启用开关不做过滤：与 cmd/waf 的映射保持一致，让编译器的状态口径成为唯一来源。
		exceptions = append(exceptions, core.ExceptionSetting{
			Name:       item.Name,
			Enabled:    item.Enabled,
			Reason:     item.Reason,
			RuleIDs:    item.RuleIDs,
			Tags:       item.Tags,
			Targets:    item.Targets,
			URLPattern: item.URLPattern,
			Methods:    item.Methods,
			ExpiresAt:  parseExpiresAt(item.ExpiresAt),
		})
	}

	return core.EngineSettings{
		Enabled:                engine.Enabled,
		Mode:                   engine.Mode,
		ParanoiaLevel:          engine.ParanoiaLevel,
		RuleDirs:               engine.Rules.Dirs,
		CustomRuleDirs:         engine.Rules.CustomDirs,
		RuleInclude:            engine.Rules.Include,
		RuleDataInclude:        engine.Rules.DataInclude,
		CRSSetup:               engine.Rules.CRSSetup,
		InlineDirectives:       engine.InlineDirectives,
		BodyAccess:             engine.Body.Access,
		BodyLimitBytes:         engine.Body.LimitBytes,
		BodyInMemoryLimitBytes: engine.Body.InMemoryLimitBytes,
		BodyLimitAction:        engine.Body.LimitAction,
		JSONDepthLimit:         engine.Body.JSONDepthLimit,
		ParseMultipart:         engine.Body.ParseMultipart,
		Processors:             processors,
		AnomalyScoreThreshold:  engine.AnomalyScoreThreshold,
		Exceptions:             exceptions,
		HotReload: core.HotReloadSetting{
			Enabled:      false, // 离线回归不需要热加载：用例在单进程内一次性执行完。
			Debounce:     engine.HotReload.Debounce.Duration(),
			PollInterval: engine.HotReload.PollInterval.Duration(),
		},
	}
}

// parseExpiresAt 解析例外的失效时间（解析失败等价于永不过期，与生产映射一致）。
func parseExpiresAt(value string) time.Time {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
