package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/core"
	"github.com/weiyongkang/waf/internal/netx"
	"github.com/weiyongkang/waf/internal/vpatch"
)

// metricNamePattern 限定指标名前缀的合法字符集（与 Prometheus 指标名规范一致）。
var metricNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidationError 汇总配置校验中发现的全部问题。
//
// 之所以「一次性收集全部问题」而不是遇到第一个就返回：
// 运维修改配置时通常一次调整多项，逐条报错会造成「改一处、跑一次」的循环。
type ValidationError struct {
	// Problems 是逐条问题描述，格式为「配置项路径：期望格式 / 当前值」。
	Problems []string
}

// Error 实现 error 接口。
func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "配置校验失败：" + e.Problems[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "配置校验失败，共 %d 项问题：", len(e.Problems))
	for _, problem := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(problem)
	}
	return b.String()
}

// addf 追加一条问题描述。
func (e *ValidationError) addf(format string, args ...any) {
	e.Problems = append(e.Problems, fmt.Sprintf(format, args...))
}

// addEnum 追加一条枚举取值问题。
func (e *ValidationError) addEnum(path, current string, allowed ...string) {
	e.addf("%s = %q 非法，可选值：%s", path, current, strings.Join(allowed, " / "))
}

// Validate 校验配置的结构合法性、取值范围与交叉依赖。
//
// 校验边界说明：本函数只做「结构层面」的校验；
//
//   - 校验单元的 type 是否已注册：由 pipeline 构建阶段检查（core.NewCheck），
//     这样错误信息可以同时列出当前可用的全部类型；
//   - 存储的拓扑参数（standalone / sentinel / cluster）是否自洽：
//     由各 Store 实现在构造时检查（它们才知道自己需要哪些字段）。
func Validate(cfg *Config) error {
	errs := &ValidationError{}
	if cfg == nil {
		errs.addf("配置对象为空")
		return errs
	}

	validateVersion(cfg, errs)
	validateServer(cfg, errs)
	validateIngress(cfg, errs)
	validateResponder(cfg, errs)
	validateEngine(cfg, errs)
	validatePipeline(cfg, errs)
	validateStores(cfg, errs)
	validateBan(cfg, errs)
	validateLogging(cfg, errs)
	validateNotifiers(cfg, errs)
	validateSites(cfg, errs)
	validateMetrics(cfg, errs)
	validateRouteCollisions(cfg, errs)
	validateLimits(cfg, errs)
	validateCache(cfg, errs)
	validateDatabase(cfg, errs)

	if len(errs.Problems) > 0 {
		return errs
	}
	return nil
}

// validateVersion 校验配置格式版本。
func validateVersion(cfg *Config, errs *ValidationError) {
	if cfg.Version != 1 {
		errs.addf("version = %d 不受支持，当前仅支持 version: 1", cfg.Version)
	}
}

// validateServer 校验 HTTP 服务配置。
func validateServer(cfg *Config, errs *ValidationError) {
	if strings.TrimSpace(cfg.Server.Listen) == "" {
		errs.addf("server.listen 不能为空，示例 \":9080\"")
	}
	basePath := strings.TrimSpace(cfg.Server.BasePath)
	if basePath != "" && basePath != "/" {
		switch {
		case !strings.HasPrefix(basePath, "/"):
			errs.addf("server.base_path = %q 非法，必须以 \"/\" 开头", cfg.Server.BasePath)
		case strings.HasSuffix(basePath, "/"):
			errs.addf("server.base_path = %q 非法，不能以 \"/\" 结尾", cfg.Server.BasePath)
		case strings.ContainsAny(basePath, "?#"):
			errs.addf("server.base_path = %q 非法，不能包含查询串或片段", cfg.Server.BasePath)
		case strings.Contains(basePath, "//"):
			errs.addf("server.base_path = %q 非法，不能包含连续的 \"/\"", cfg.Server.BasePath)
		default:
			for _, segment := range strings.Split(basePath, "/") {
				if segment == "." || segment == ".." {
					errs.addf("server.base_path = %q 非法，不能包含 \".\" 或 \"..\" 路径段", cfg.Server.BasePath)
					break
				}
			}
		}
	}
	if cfg.Server.ReadHeaderTimeout.Duration() <= 0 {
		errs.addf("server.read_header_timeout 必须大于 0，示例 \"3s\"")
	}
	if cfg.Server.ShutdownTimeout.Duration() <= 0 {
		errs.addf("server.shutdown_timeout 必须大于 0，示例 \"10s\"")
	}
	if cfg.Server.MetricsListen == cfg.Server.Listen && cfg.Server.Listen != "" {
		errs.addf("server.metrics_listen 与 server.listen 不能相同（%q），否则端口冲突", cfg.Server.Listen)
	}
}

// validateIngress 校验接入适配与请求体配置。
func validateIngress(cfg *Config, errs *ValidationError) {
	ingress := cfg.Ingress

	switch ingress.Type {
	case IngressTypeAuto, IngressTypeTraefik, IngressTypeNginxOpenResty, IngressTypeNginxAuthOnly:
	default:
		errs.addEnum("ingress.type", ingress.Type,
			IngressTypeAuto, IngressTypeTraefik, IngressTypeNginxOpenResty, IngressTypeNginxAuthOnly)
	}

	if !strings.HasPrefix(ingress.Path, "/") {
		errs.addf("ingress.path = %q 非法，必须以 \"/\" 开头", ingress.Path)
	}
	if !strings.HasPrefix(ingress.DenyPath, "/") {
		errs.addf("ingress.deny_path = %q 非法，必须以 \"/\" 开头", ingress.DenyPath)
	}
	if len(ingress.Headers.URI) == 0 {
		errs.addf("ingress.headers.uri 不能为空，否则无法还原原始请求 URI")
	}

	switch ingress.Body.Mode {
	case BodyModeRequired, BodyModeOptional, BodyModeDisabled:
	default:
		errs.addEnum("ingress.body.mode", ingress.Body.Mode, BodyModeRequired, BodyModeOptional, BodyModeDisabled)
	}
	switch ingress.Body.Source {
	case "request-body", "none":
	default:
		errs.addf("ingress.body.source = %q 非法，可选值：request-body / none", ingress.Body.Source)
	}
	switch ingress.Body.OnExceed {
	case BodyOnExceedTruncate, BodyOnExceedReject, BodyOnExceedSkip:
	default:
		errs.addEnum("ingress.body.on_exceed", ingress.Body.OnExceed,
			BodyOnExceedTruncate, BodyOnExceedReject, BodyOnExceedSkip)
	}
	switch ingress.Body.Spool {
	case SpoolMemory, SpoolDisk, SpoolAuto:
	default:
		errs.addEnum("ingress.body.spool", ingress.Body.Spool, SpoolMemory, SpoolDisk, SpoolAuto)
	}
	if ingress.Body.MaxBytes <= 0 {
		errs.addf("ingress.body.max_bytes = %d 非法，必须大于 0", ingress.Body.MaxBytes)
	}
	if ingress.Body.ChunkBytes <= 0 {
		errs.addf("ingress.body.chunk_bytes = %d 非法，必须大于 0", ingress.Body.ChunkBytes)
	}
	if ingress.Body.MemoryThreshold < 0 {
		errs.addf("ingress.body.memory_threshold = %d 非法，不能为负数", ingress.Body.MemoryThreshold)
	}
	if ingress.Body.Spool == SpoolAuto && ingress.Body.MemoryThreshold == 0 {
		errs.addf("ingress.body.spool = \"auto\" 时 ingress.body.memory_threshold 必须大于 0，否则请求体将全部落盘")
	}
	if ingress.Body.ReadTimeout.Duration() <= 0 {
		errs.addf("ingress.body.read_timeout 必须大于 0，示例 \"2s\"")
	}
	validateMissingMethods(ingress.Body, errs)
	if ingress.Body.Mode == BodyModeDisabled && len(ingress.Headers.URI) == 0 {
		errs.addf("ingress.body.mode = \"disabled\" 时 ingress.headers.uri 仍不能为空")
	}
	validateDecompress(ingress.Body.Decompress, errs)
}

// validateMissingMethods 校验「预期携带请求体的方法」列表。
//
// 校验要点：
//   - 方法名必须是合法 token（非空、不含空白），写错会让「请求体缺失」检测静默失效；
//   - 不能重复声明：重复不致命，但会让运维产生「改了一处还有一处」的错觉；
//   - mode = required 时列表不能为空：否则「预期携带请求体」这个断言永远不会触发，
//     属于典型的静默失效配置，必须在加载阶段直接报错。
func validateMissingMethods(cfg BodyConfig, errs *ValidationError) {
	seen := make(map[string]struct{}, len(cfg.MissingMethods))
	for i, method := range cfg.MissingMethods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			errs.addf("ingress.body.missing_methods[%d] 不能为空", i)
			continue
		}
		if strings.ContainsAny(normalized, " \t") {
			errs.addf("ingress.body.missing_methods[%d] = %q 含空白字符，方法名必须是单个 token", i, method)
			continue
		}
		if _, dup := seen[normalized]; dup {
			errs.addf("ingress.body.missing_methods[%d] = %q 重复出现", i, method)
			continue
		}
		seen[normalized] = struct{}{}
	}
	if cfg.Mode == BodyModeRequired && len(seen) == 0 {
		errs.addf("ingress.body.mode = \"required\" 时 ingress.body.missing_methods 不能为空，" +
			"否则「请求体缺失」永远不会被发现（配置静默失效）")
	}
}

// validateDecompress 校验压缩请求体解压配置。
//
// 校验要点：
//   - 编码名只接受 gzip / deflate：br 需要第三方依赖，本项目不引入，
//     直接在配置阶段报错而不是运行期静默跳过（否则会形成「以为在检测、其实没检测」的缺口）；
//   - max_bytes 必须为正：解压后上限是防 zip bomb 的唯一闸门，不能缺省；
//   - 解压后上限必须 >= 压缩体上限：否则每个开启解压的请求都会立刻超限。
func validateDecompress(cfg DecompressConfig, errs *ValidationError) {
	for _, encoding := range cfg.Encodings {
		switch strings.ToLower(strings.TrimSpace(encoding)) {
		case DecompressEncodingGzip, DecompressEncodingDeflate:
		default:
			errs.addf("ingress.body.decompress.encodings 含不支持的编码 %q，当前仅支持 gzip / deflate"+
				"（br 需要第三方依赖，本项目不引入）", encoding)
		}
	}
	if cfg.Enabled && len(cfg.Encodings) == 0 {
		errs.addf("ingress.body.decompress.enabled = true 时 encodings 不能为空")
	}
	if cfg.MaxBytes <= 0 {
		errs.addf("ingress.body.decompress.max_bytes = %d 非法，必须大于 0", cfg.MaxBytes)
	}
	switch cfg.UnsupportedAction {
	case DecompressActionBlock, DecompressActionPass:
	default:
		errs.addEnum("ingress.body.decompress.unsupported_action", cfg.UnsupportedAction,
			DecompressActionBlock, DecompressActionPass)
	}
}

// validateResponder 校验拦截响应配置。
func validateResponder(cfg *Config, errs *ValidationError) {
	if cfg.Responder.Type != "json" {
		errs.addEnum("responder.type", cfg.Responder.Type, "json")
	}
	if cfg.Responder.Template != "" && cfg.Responder.TemplateFile != "" {
		errs.addf("responder.template 与 responder.template_file 不能同时配置")
	}
	if cfg.Responder.MaxBodyBytes < 0 {
		errs.addf("responder.max_body_bytes = %d 非法，不能为负数", cfg.Responder.MaxBodyBytes)
	}
}

// validateEngine 校验检测引擎配置。
func validateEngine(cfg *Config, errs *ValidationError) {
	engine := cfg.Engine
	if !engine.Enabled {
		return
	}

	switch engine.Mode {
	case EngineModeOn, EngineModeDetectionOnly:
	default:
		errs.addEnum("engine.mode", engine.Mode, EngineModeOn, EngineModeDetectionOnly)
	}
	if engine.ParanoiaLevel < 1 || engine.ParanoiaLevel > 4 {
		errs.addf("engine.paranoia_level = %d 非法，取值范围 1–4", engine.ParanoiaLevel)
	}
	switch engine.Body.LimitAction {
	case "reject", "processPartial":
	default:
		errs.addEnum("engine.body.limit_action", engine.Body.LimitAction, "reject", "processPartial")
	}
	if engine.Body.LimitBytes <= 0 {
		errs.addf("engine.body.limit_bytes = %d 非法，必须大于 0", engine.Body.LimitBytes)
	}
	if engine.Body.InMemoryLimitBytes < 0 {
		errs.addf("engine.body.in_memory_limit_bytes = %d 非法，不能为负数", engine.Body.InMemoryLimitBytes)
	}
	if engine.Body.InMemoryLimitBytes > engine.Body.LimitBytes {
		errs.addf("engine.body.in_memory_limit_bytes(%d) 不能大于 engine.body.limit_bytes(%d)",
			engine.Body.InMemoryLimitBytes, engine.Body.LimitBytes)
	}
	if cfg.Ingress.Body.MaxBytes > engine.Body.LimitBytes {
		errs.addf("ingress.body.max_bytes(%d) 不应大于 engine.body.limit_bytes(%d)，否则多余字节无法参与检测",
			cfg.Ingress.Body.MaxBytes, engine.Body.LimitBytes)
	}
	if engine.Body.JSONDepthLimit < 0 {
		errs.addf("engine.body.json_depth_limit = %d 非法，不能为负数", engine.Body.JSONDepthLimit)
	}
	validateEngineBodyProcessors(cfg, errs)
	if engine.AnomalyScoreThreshold < 1 {
		errs.addf("engine.anomaly_score_threshold = %d 非法，必须大于等于 1（CRS 默认值为 5）",
			engine.AnomalyScoreThreshold)
	}
	if engine.HotReload.Enabled {
		if engine.HotReload.Debounce.Duration() <= 0 {
			errs.addf("engine.hot_reload.enabled = true 时 engine.hot_reload.debounce 必须大于 0")
		}
		if engine.HotReload.PollInterval.Duration() <= 0 {
			errs.addf("engine.hot_reload.enabled = true 时 engine.hot_reload.poll_interval 必须大于 0")
		}
		// 说明：这里刻意不校验「规则目录是否为空」。
		// 规则目录可以由 pipeline 实例通过 settings.rule_dirs 覆盖（实例级优先），
		// 只看全局配置会误报；「热加载已开启但没有可监听的目录」由装配阶段打 WARN 提示
		// （见 internal/check/coraza/reload.go），既准确又不阻断启动。
	}
	validateExceptions(engine.Exceptions, errs)
	for index, name := range engine.VirtualPatches {
		if !vpatch.Known(name) {
			errs.addf("engine.virtual_patches[%d] = %q 不是内置虚拟补丁模板", index, name)
		}
	}
	for index, file := range engine.VirtualPatchFiles {
		if strings.TrimSpace(file) == "" {
			errs.addf("engine.virtual_patch_files[%d] 不能为空", index)
		}
	}
}

// validateExceptions 校验误报例外清单。
//
// 校验要点（每条都对应一类「配了但没生效」的典型事故）：
//   - name 唯一且非空：审计报表用它定位例外，重名会让报表无法区分；
//   - reason 必填：例外等于关闭部分防护，必须留下理由；
//   - 至少声明一种作用维度：否则会生成空指令，属于无效配置；
//   - targets 必须配合 rule_ids：SecRuleUpdateTargetById 需要明确的目标规则；
//   - url_pattern 必须可编译：正则语法错误必须在配置阶段暴露；
//   - expires_at 必须能被解析：无法解析的时间会让「过期即失效」机制失效。
func validateExceptions(exceptions []ExceptionConfig, errs *ValidationError) {
	seen := make(map[string]int, len(exceptions))
	for index, item := range exceptions {
		path := fmt.Sprintf("engine.exceptions[%d]", index)
		name := strings.TrimSpace(item.Name)
		if name == "" {
			errs.addf("%s.name 不能为空（例外必须有审计标识）", path)
		} else if previous, exists := seen[name]; exists {
			errs.addf("%s.name = %q 重复（与 engine.exceptions[%d] 同名），例外名必须唯一", path, name, previous)
		} else {
			seen[name] = index
		}

		if strings.TrimSpace(item.Reason) == "" {
			errs.addf("%s（name=%q）必须填写 reason：例外等于关闭部分防护，原因必须留档可审计", path, name)
		}
		if len(item.RuleIDs) == 0 && len(item.Tags) == 0 && len(item.Targets) == 0 {
			errs.addf("%s（name=%q）至少要声明 rule_ids / tags / targets 之一，否则该例外不产生任何效果", path, name)
		}
		if len(item.Targets) > 0 && len(item.RuleIDs) == 0 {
			errs.addf("%s（name=%q）声明了 targets 但未声明 rule_ids："+
				"摘除检测目标需要明确作用在哪些规则上（SecRuleUpdateTargetById 的语义要求）", path, name)
		}
		if pattern := strings.TrimSpace(item.URLPattern); pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				errs.addf("%s.url_pattern 不是合法正则（%v）", path, err)
			}
		}
		for _, method := range item.Methods {
			if strings.TrimSpace(method) == "" {
				errs.addf("%s.methods 含空字符串", path)
			}
		}
		if expires := strings.TrimSpace(item.ExpiresAt); expires != "" {
			if _, err := time.Parse(time.RFC3339, expires); err != nil {
				errs.addf("%s.expires_at = %q 无法解析（需 RFC3339，例如 2026-12-31T00:00:00+08:00）", path, expires)
			}
		}
	}
}

// validateEngineBodyProcessors 校验请求体处理器映射配置。
//
// 校验要点：
//   - 处理器名必须是 Coraza 支持的四个名称之一（大小写不敏感）；
//   - 内容类型必须是可编译的正则表达式，否则引擎装配时才会报错，定位成本高；
//   - 启用的映射必须至少含一条内容类型，否则该映射永远不会被选用（属于静默失效）。
func validateEngineBodyProcessors(cfg *Config, errs *ValidationError) {
	allowed := []string{
		BodyProcessorJSON, BodyProcessorXML, BodyProcessorMultipart, BodyProcessorURLEncoded,
	}
	for index, processor := range cfg.Engine.Body.Processors {
		path := fmt.Sprintf("engine.body.processors[%d]", index)
		if !processor.Enabled {
			continue
		}
		name := strings.ToUpper(strings.TrimSpace(processor.Name))
		switch name {
		case BodyProcessorJSON, BodyProcessorXML, BodyProcessorMultipart, BodyProcessorURLEncoded:
		default:
			errs.addEnum(path+".name", processor.Name, allowed...)
		}
		if len(processor.ContentTypes) == 0 {
			errs.addf("%s.content_types 不能为空，否则该处理器永远不会被选用", path)
		}
		for index, pattern := range processor.ContentTypes {
			if _, err := regexp.Compile(pattern); err != nil {
				errs.addf("%s.content_types[%d] = %q 不是合法的正则表达式：%v", path, index, pattern, err)
			}
		}
	}
}

// validatePipeline 校验校验链声明的唯一性与取值合法性。
func validatePipeline(cfg *Config, errs *ValidationError) {
	seen := make(map[string]struct{}, len(cfg.Pipeline))
	validateInstances := func(prefix string, instances []core.InstanceConfig) {
		for i, inst := range instances {
			instPrefix := fmt.Sprintf("%s[%d]", prefix, i)

			if strings.TrimSpace(inst.Name) == "" {
				errs.addf("%s.name 不能为空", instPrefix)
			} else if _, dup := seen[inst.Name]; dup {
				errs.addf("%s.name = %q 重复，实例名必须全局唯一", instPrefix, inst.Name)
			} else {
				seen[inst.Name] = struct{}{}
			}

			if strings.TrimSpace(inst.Type) == "" {
				errs.addf("%s.type 不能为空（%s[%s] 必须声明实现类型）", instPrefix, prefix, inst.Name)
			}

			switch inst.OnError {
			case "", "pass", "block":
			default:
				errs.addEnum(instPrefix+".on_error", inst.OnError, "pass", "block")
			}
		}
	}

	validateInstances("pipeline", cfg.Pipeline)
	names := make(map[string]struct{}, len(cfg.Pipelines))
	for i, pipeline := range cfg.Pipelines {
		prefix := fmt.Sprintf("pipelines[%d]", i)
		name := strings.TrimSpace(pipeline.Name)
		switch {
		case name == "":
			errs.addf("%s.name 不能为空", prefix)
		case name == "default":
			errs.addf("%s.name = \"default\" 是保留名，默认链请使用顶层 pipeline", prefix)
		case !segmentPattern.MatchString(name):
			errs.addf("%s.name = %q 非法，只能由小写字母、数字与下划线组成，且不能以数字开头", prefix, name)
		default:
			if _, dup := names[name]; dup {
				errs.addf("%s.name = %q 重复，具名校验链名必须唯一", prefix, name)
			} else {
				names[name] = struct{}{}
			}
		}
		validateInstances(prefix+".instances", pipeline.Instances)
	}
}

// validateStores 校验共享存储声明的合法性与降级配置的自洽性。
func validateStores(cfg *Config, errs *ValidationError) {
	if len(cfg.Stores) == 0 && referencesStore(cfg) {
		errs.addf("pipeline 中引用了共享存储，但 stores 为空；请至少声明一个名为 default 的存储")
	}

	seen := make(map[string]struct{}, len(cfg.Stores))
	for i, store := range cfg.Stores {
		prefix := fmt.Sprintf("stores[%d]", i)

		if strings.TrimSpace(store.Name) == "" {
			errs.addf("%s.name 不能为空", prefix)
		} else if _, dup := seen[store.Name]; dup {
			errs.addf("%s.name = %q 重复，存储实例名必须唯一", prefix, store.Name)
		} else {
			seen[store.Name] = struct{}{}
		}

		switch store.Type {
		case "redis", "memory", "file":
		default:
			errs.addEnum(prefix+".type", store.Type, "redis", "memory", "file")
		}

		switch store.Fallback {
		case "", "memory", "file":
		default:
			errs.addEnum(prefix+".fallback", store.Fallback, "memory", "file")
		}

		switch store.OnError {
		case "", StoreOnErrorFailOpen, StoreOnErrorFailClosed, StoreOnErrorFallbackLocal:
		default:
			errs.addEnum(prefix+".on_error", store.OnError,
				StoreOnErrorFailOpen, StoreOnErrorFailClosed, StoreOnErrorFallbackLocal)
		}

		// 需求 R23：Redis 未启用时必须能够降级到本地实现，否则多实例共享能力会静默缺失。
		if store.Type == "redis" && !store.Enabled && strings.TrimSpace(store.Fallback) == "" {
			errs.addf("%s.type = \"redis\" 且 enabled = false 时，必须显式声明 %s.fallback（memory 或 file）",
				prefix, prefix)
		}
	}
}

// referencesStore 判断 pipeline 中是否存在引用了共享存储的实例。
//
// 判断依据是实例的 settings.store 字段；这类实例缺少存储定义时无法工作，
// 因此必须在启动阶段报错，而不是在首个请求到达时才失败。
func referencesStore(cfg *Config) bool {
	hasStore := func(instances []core.InstanceConfig) bool {
		for _, inst := range instances {
			if !inst.Enabled {
				continue
			}
			if _, ok := inst.Settings["store"]; ok {
				return true
			}
		}
		return false
	}
	if hasStore(cfg.Pipeline) {
		return true
	}
	for _, pipeline := range cfg.Pipelines {
		if hasStore(pipeline.Instances) {
			return true
		}
	}
	return false
}

// parseBanKeyKind 判断给定取值是否为合法的封禁键维度，并返回规范化后的取值。
//
// 之所以在 config 包内自带一份实现：维度取值需要在此做「配置层」校验，
// 而 internal/ban 依赖 config，反向引入会形成循环依赖。
func parseBanKeyKind(name string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, kind := range BanKeyKinds() {
		if kind == normalized {
			return kind, true
		}
	}
	return "", false
}

// validateBan 校验封禁策略配置。
func validateBan(cfg *Config, errs *ValidationError) {
	ban := cfg.Ban

	if ban.DefaultTTL.Duration() <= 0 {
		errs.addf("ban.default_ttl 必须大于 0，默认建议 \"30m\"")
	}
	if ban.MaxTTL.Duration() <= 0 {
		errs.addf("ban.max_ttl 必须大于 0，默认建议 \"24h\"")
	}
	if ban.DefaultTTL.Duration() > 0 && ban.MaxTTL.Duration() > 0 &&
		ban.DefaultTTL.Duration() > ban.MaxTTL.Duration() {
		errs.addf("ban.default_ttl(%s) 不能大于 ban.max_ttl(%s)",
			ban.DefaultTTL, ban.MaxTTL)
	}

	switch ban.BanKey {
	case BanKeyClientIP, BanKeyClientIPSite, BanKeyClientIPPath, BanKeyClientIPMethod:
	default:
		errs.addEnum("ban.ban_key", ban.BanKey, BanKeyKinds()...)
	}

	// ban_keys 是运行期实际参与查询的维度集合：逐项校验取值并检测重复。
	//
	// 之所以要求它必须包含主维度 ban_key：运维命令 `waf ban add/remove` 按主维度写键，
	// 而 banlist 按 ban_keys 查询；两者不含同一维度时会出现
	// 「CLI 提示已封禁、运行期却查不到」的静默失效，属于本项目最需要避免的失败形态。
	if len(ban.BanKeys) > 0 {
		seen := make(map[string]struct{}, len(ban.BanKeys))
		primaryIncluded := false
		for index, item := range ban.BanKeys {
			kind, ok := parseBanKeyKind(item)
			if !ok {
				errs.addEnum(fmt.Sprintf("ban.ban_keys[%d]", index), item, BanKeyKinds()...)
				continue
			}
			if _, duplicated := seen[kind]; duplicated {
				errs.addf("ban.ban_keys[%d] = %q 重复出现，同一维度只需声明一次", index, item)
				continue
			}
			seen[kind] = struct{}{}
			if kind == ban.BanKey {
				primaryIncluded = true
			}
		}
		if _, ok := parseBanKeyKind(ban.BanKey); ok && !primaryIncluded {
			errs.addf("ban.ban_keys 必须包含 ban.ban_key = %q"+
				"（运维命令按主维度写键，缺少该维度会导致名单写入后无法被拦截）", ban.BanKey)
		}
	}

	if ban.Escalate {
		if len(ban.EscalateSteps) == 0 {
			errs.addf("ban.escalate = true 时 ban.escalate_steps 不能为空，示例 [30m, 2h, 24h]")
		}
		if ban.EscalateWindow.Duration() <= 0 {
			errs.addf("ban.escalate = true 时 ban.escalate_window 必须大于 0，示例 \"24h\"")
		}
		for i, step := range ban.EscalateSteps {
			if step.Duration() <= 0 {
				errs.addf("ban.escalate_steps[%d] 必须大于 0", i)
			}
			if ban.MaxTTL.Duration() > 0 && step.Duration() > ban.MaxTTL.Duration() {
				errs.addf("ban.escalate_steps[%d] = %s 超过 ban.max_ttl = %s", i, step, ban.MaxTTL)
			}
		}
	}
}

// validateLogging 校验两类日志的输出配置。
func validateLogging(cfg *Config, errs *ValidationError) {
	validateLogOutput("logging.system", cfg.Logging.System, errs)
	validateLogOutput("logging.access", cfg.Logging.Access.LogOutputConfig, errs)

	if cfg.Logging.Access.MaxBodySnippetBytes < 0 {
		errs.addf("logging.access.max_body_snippet_bytes = %d 非法，不能为负数",
			cfg.Logging.Access.MaxBodySnippetBytes)
	}
	if cfg.Logging.Access.IncludeBody && cfg.Logging.Access.MaxBodySnippetBytes == 0 {
		errs.addf("logging.access.include_body = true 时 max_body_snippet_bytes 必须大于 0，否则记录不到任何内容")
	}

	// 放行记录策略必须显式合法：写错时会退化成「放行请求完全不留痕」，
	// 而这类静默失效只有在事后查日志时才会被发现。
	switch cfg.Logging.Access.AllowLevel {
	case AccessAllowLevelInfo, AccessAllowLevelDebug, AccessAllowLevelOff:
	default:
		errs.addEnum("logging.access.allow_level", cfg.Logging.Access.AllowLevel, AccessAllowLevels()...)
	}
}

// validateLogOutput 校验单个日志输出通道。
func validateLogOutput(prefix string, cfg LogOutputConfig, errs *ValidationError) {
	if !cfg.Enabled {
		return
	}

	switch cfg.Level {
	case "debug", "info", "warn", "error":
	default:
		errs.addEnum(prefix+".level", cfg.Level, "debug", "info", "warn", "error")
	}
	if cfg.Format != "json" {
		errs.addEnum(prefix+".format", cfg.Format, "json")
	}
	if len(cfg.Outputs) == 0 {
		errs.addf("%s.outputs 不能为空，可选值：stdout / file", prefix)
	}

	needFile := false
	for _, output := range cfg.Outputs {
		switch output {
		case "stdout":
		case "file":
			needFile = true
		default:
			errs.addEnum(prefix+".outputs", output, "stdout", "file")
		}
	}

	switch cfg.Rotate {
	case "daily", "size", "both":
	default:
		errs.addEnum(prefix+".rotate", cfg.Rotate, "daily", "size", "both")
	}

	if needFile {
		if strings.TrimSpace(cfg.Dir) == "" {
			errs.addf("%s.dir 不能为空（outputs 含 file）", prefix)
		}
		if strings.TrimSpace(cfg.File) == "" {
			errs.addf("%s.file 不能为空（outputs 含 file）", prefix)
		}
		if cfg.KeepDays <= 0 {
			errs.addf("%s.keep_days 必须大于 0（outputs 含 file），示例 30", prefix)
		}
		if cfg.Rotate == "size" || cfg.Rotate == "both" {
			if cfg.MaxFileBytes <= 0 {
				errs.addf("%s.rotate = %q 时 %s.max_file_bytes 必须大于 0", prefix, cfg.Rotate, prefix)
			}
		}
	}
}

// validateNotifiers 校验告警通道声明。
func validateNotifiers(cfg *Config, errs *ValidationError) {
	notify := cfg.Notify
	validateNotifyPolicy(notify, errs)

	// 已启用的通道不允许重复：同名会让「告警到底发到哪个通道」变得无法判断。
	seen := make(map[string]struct{}, len(cfg.Notifiers))
	enabled := 0
	for i, notifier := range cfg.Notifiers {
		prefix := fmt.Sprintf("notifiers[%d]", i)
		if strings.TrimSpace(notifier.Name) == "" {
			errs.addf("%s.name 不能为空", prefix)
		} else if _, dup := seen[notifier.Name]; dup {
			errs.addf("%s.name = %q 重复，通道实例名必须唯一", prefix, notifier.Name)
		} else {
			seen[notifier.Name] = struct{}{}
		}
		if strings.TrimSpace(notifier.Type) == "" {
			errs.addf("%s.type 不能为空", prefix)
		}
		if level := strings.TrimSpace(notifier.MinLevel); level != "" {
			validateAlertLevel(prefix+".min_level", level, errs)
		}
		if notifier.SuppressWindow.Duration() < 0 {
			errs.addf("%s.suppress_window = %s 非法，不能为负数（0 表示继承 notify.suppress_window）",
				prefix, notifier.SuppressWindow.Duration())
		}
		if notifier.Enabled {
			enabled++
		}
	}

	// 「总开关开着却没有任何启用的通道」是典型的静默失效配置：
	// 运维以为已经接了告警，实际一条都发不出去。这里直接报错要求二选一。
	if notify.Enabled && enabled == 0 && len(cfg.Notifiers) > 0 {
		errs.addf("notify.enabled = true，但 notifiers 中没有任何 enabled = true 的通道")
	}
}

// validateNotifyPolicy 校验告警外送的公共策略。
//
// 校验重点都对应一类「配了但不生效 / 反而更糟」的问题：
// 队列为 0 会让全部告警被丢弃；workers 为 0 会让队列永远无人消费；
// 重试次数与间隔非法会让重试机制形同虚设。
func validateNotifyPolicy(notify NotifyConfig, errs *ValidationError) {
	// 说明：总开关关闭时其余参数不参与运行，但仍然校验明显非法的取值，
	// 避免「打开总开关的那一刻才发现参数写错」。
	if notify.QueueSize < 0 {
		errs.addf("notify.queue_size = %d 非法，不能为负数", notify.QueueSize)
	}
	if notify.Workers < 0 {
		errs.addf("notify.workers = %d 非法，不能为负数", notify.Workers)
	}
	if notify.Timeout.Duration() <= 0 {
		errs.addf("notify.timeout = %s 非法，必须大于 0（没有超时的外送会长期占用协程）",
			notify.Timeout.Duration())
	}
	if level := strings.TrimSpace(notify.MinLevel); level != "" {
		validateAlertLevel("notify.min_level", level, errs)
	}
	if notify.SuppressWindow.Duration() < 0 {
		errs.addf("notify.suppress_window = %s 非法，不能为负数（0 表示不抑制）",
			notify.SuppressWindow.Duration())
	}
	if notify.MaxAttempts < 0 {
		errs.addf("notify.max_attempts = %d 非法，不能为负数", notify.MaxAttempts)
	}
	if notify.RetryBackoff.Duration() < 0 {
		errs.addf("notify.retry_backoff = %s 非法，不能为负数", notify.RetryBackoff.Duration())
	}
	if notify.MaxTrackedKeys < 0 {
		errs.addf("notify.max_tracked_keys = %d 非法，不能为负数", notify.MaxTrackedKeys)
	}
}

// validateAlertLevel 校验告警级别取值。
func validateAlertLevel(path, level string, errs *ValidationError) {
	switch level {
	case string(core.AlertLevelInfo), string(core.AlertLevelWarn), string(core.AlertLevelError):
	default:
		errs.addf("%s = %q 非法，可选值：info / warn / error", path, level)
	}
}

// validateSites 校验站点策略声明。
func validateSites(cfg *Config, errs *ValidationError) {
	pipelines := make(map[string]struct{}, len(cfg.Pipelines))
	for _, pipeline := range cfg.Pipelines {
		pipelines[strings.TrimSpace(pipeline.Name)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(cfg.Sites))
	for i, site := range cfg.Sites {
		prefix := fmt.Sprintf("sites[%d]", i)
		if strings.TrimSpace(site.Name) == "" {
			errs.addf("%s.name 不能为空", prefix)
		} else if _, dup := seen[site.Name]; dup {
			errs.addf("%s.name = %q 重复，站点名必须唯一", prefix, site.Name)
		} else {
			seen[site.Name] = struct{}{}
		}
		if len(site.Hosts) == 0 {
			errs.addf("%s.hosts 不能为空，默认站点请使用 [\"*\"]", prefix)
		}
		switch site.EngineMode {
		case "", EngineModeInherit, EngineModeOn, EngineModeDetectionOnly:
		default:
			errs.addEnum(prefix+".engine_mode", site.EngineMode,
				EngineModeInherit, EngineModeOn, EngineModeDetectionOnly)
		}
		switch site.AccessAction {
		case "", "block", "observe":
		default:
			errs.addEnum(prefix+".access_action", site.AccessAction, "block", "observe")
		}
		if site.AccessScore < 0 {
			errs.addf("%s.access_score = %d 非法，不能为负数", prefix, site.AccessScore)
		}
		if _, err := netx.NewSet(site.Allowlist); err != nil {
			errs.addf("%s.allowlist 非法：%v", prefix, err)
		}
		if _, err := netx.NewSet(site.Blocklist); err != nil {
			errs.addf("%s.blocklist 非法：%v", prefix, err)
		}
		pipeline := strings.TrimSpace(site.Pipeline)
		if pipeline != "" && pipeline != "default" {
			if _, ok := pipelines[pipeline]; !ok {
				errs.addf("%s.pipeline = %q 不存在；请在 pipelines[] 中声明该具名校验链", prefix, site.Pipeline)
			}
		}
	}
}

// validateMetrics 校验指标端点配置。
func validateMetrics(cfg *Config, errs *ValidationError) {
	metrics := cfg.Metrics
	path := strings.TrimSpace(metrics.Path)
	switch {
	case path == "":
		errs.addf("metrics.path 不能为空，示例 \"/metrics\"")
	case !strings.HasPrefix(path, "/"):
		errs.addf("metrics.path = %q 非法，必须以 / 开头", metrics.Path)
	}

	if !metrics.Enabled {
		return
	}
	if !metricNamePattern.MatchString(metrics.Namespace) {
		errs.addf("metrics.namespace = %q 非法，只能由字母、数字与下划线组成，且不能以数字开头", metrics.Namespace)
	}
}

// validateRouteCollisions 校验全部 WAF HTTP 端点叠加统一前缀后的最终路径是否冲突。
//
// 为什么必须在配置阶段拦截：重复注册同一路径会让 http.ServeMux 在启动阶段
// 直接 panic（而不是给出可读错误）。同时，前缀会让「配置里看起来不同的路径」
// 在叠加 server.base_path 后变成同一个路径（例如 base=/waf、path=/auth 与
// deny_path=/waf/auth），因此必须比较最终生效路径而不是原始配置值。
func validateRouteCollisions(cfg *Config, errs *ValidationError) {
	base := cfg.Server.BasePath
	endpoints := []struct {
		name string
		path string
	}{
		{name: "ingress.path", path: cfg.Ingress.Path},
		{name: "ingress.deny_path", path: cfg.Ingress.DenyPath},
		{name: "内置端点 /healthz", path: "/healthz"},
		{name: "内置端点 /readyz", path: "/readyz"},
		{name: "内置端点 /version", path: "/version"},
		{name: "metrics.path", path: strings.TrimSpace(cfg.Metrics.Path)},
	}

	seen := make(map[string]string, len(endpoints))
	for _, endpoint := range endpoints {
		path := JoinBasePath(base, endpoint.path)
		if path == "" {
			continue
		}
		if previous, exists := seen[path]; exists {
			errs.addf("%s 与 %s 的最终路径冲突（均为 %q，已叠加 server.base_path=%q），请修改其中一个路径",
				endpoint.name, previous, path, base)
			continue
		}
		seen[path] = endpoint.name
	}
}

// validateLimits 校验资源与容量限额。
//
// 需求 R13 要求「不做大体积读取」，因此所有限额项都必须为正数：
// 值为 0 会让「限额」退化为「不限制」，属于危险的静默失效。
func validateLimits(cfg *Config, errs *ValidationError) {
	limits := cfg.Limits
	check := func(path string, value int64) {
		if value <= 0 {
			errs.addf("%s = %d 非法，必须大于 0（0 或负数会使限额静默失效）", path, value)
		}
	}

	check("limits.max_rule_file_bytes", limits.MaxRuleFileBytes)
	check("limits.max_rules_total_bytes", limits.MaxRulesTotalBytes)
	check("limits.max_scan_token_bytes", limits.MaxScanTokenBytes)
	check("limits.max_intel_file_bytes", limits.MaxIntelFileBytes)
	check("limits.max_mmdb_bytes", limits.MaxMMDBBytes)
	check("limits.max_config_file_bytes", limits.MaxConfigFileBytes)
	check("limits.max_header_bytes", limits.MaxHeaderBytes)

	if limits.MaxScanTokenBytes > limits.MaxHeaderBytes {
		errs.addf("limits.max_scan_token_bytes(%d) 不应大于 limits.max_header_bytes(%d)",
			limits.MaxScanTokenBytes, limits.MaxHeaderBytes)
	}
	if limits.MaxRulesTotalBytes < limits.MaxRuleFileBytes {
		errs.addf("limits.max_rules_total_bytes(%d) 不能小于 limits.max_rule_file_bytes(%d)",
			limits.MaxRulesTotalBytes, limits.MaxRuleFileBytes)
	}
}

// validateCache 校验本地缓存配置。
func validateCache(cfg *Config, errs *ValidationError) {
	cache := cfg.Cache
	if !cache.Enabled {
		return
	}
	if cache.RuleCacheEntries < 0 {
		errs.addf("cache.rule_cache_entries = %d 非法，不能为负数", cache.RuleCacheEntries)
	}
	if cache.BanCacheEntries < 0 {
		errs.addf("cache.ban_cache_entries = %d 非法，不能为负数", cache.BanCacheEntries)
	}
	if cache.MaxBytes <= 0 {
		errs.addf("cache.max_bytes = %d 非法，必须大于 0（禁用缓存请设置 cache.enabled = false）", cache.MaxBytes)
	}
	if cache.TTL.Duration() <= 0 {
		errs.addf("cache.ttl 必须大于 0，示例 \"5m\"")
	}
}

// validateDatabase 校验 SQLite 数据库配置。
func validateDatabase(cfg *Config, errs *ValidationError) {
	database := cfg.Database
	if !database.Enabled {
		// 关闭时只允许保留默认值；不影响原有 stores[] 行为。
		return
	}
	if strings.TrimSpace(database.Path) == "" {
		errs.addf("database.enabled = true 时 database.path 不能为空")
	}
	if database.BusyTimeout.Duration() <= 0 {
		errs.addf("database.busy_timeout 必须大于 0")
	}
	if database.ReloadInterval.Duration() <= 0 {
		errs.addf("database.reload_interval 必须大于 0")
	}
	switch database.Audit.Mode {
	case DatabaseAuditModeOff:
		return
	case DatabaseAuditModeEvents, DatabaseAuditModeAll:
	default:
		errs.addEnum("database.audit.mode", database.Audit.Mode,
			DatabaseAuditModeOff, DatabaseAuditModeEvents, DatabaseAuditModeAll)
		return
	}
	if database.Audit.Retention.Duration() < 0 {
		errs.addf("database.audit.retention 不能为负数")
	}
	if database.Audit.QueueSize <= 0 {
		errs.addf("database.audit.queue_size 必须大于 0")
	}
	if database.Audit.BatchSize <= 0 {
		errs.addf("database.audit.batch_size 必须大于 0")
	}
	if database.Audit.FlushInterval.Duration() <= 0 {
		errs.addf("database.audit.flush_interval 必须大于 0")
	}
}
