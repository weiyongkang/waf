package responder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/template"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// DefaultMaxBodyBytes 是模板渲染结果的默认字节上限。
const DefaultMaxBodyBytes int64 = 8192

// maxTemplateFileBytes 是外部模板文件的大小上限。
const maxTemplateFileBytes int64 = 64 * 1024

// errTemplateBodyTooLarge 表示模板输出超过配置上限。
var errTemplateBodyTooLarge = errors.New("模板渲染结果超过 responder.max_body_bytes")

// TemplateData 是拦截响应模板的渲染数据。
type TemplateData struct {
	// Code 是对外错误码，例如 WAF_BLOCKED。
	Code string
	// Status 是本次响应使用的 HTTP 状态码。
	Status int
	// Message 是错误码对应的提示语（来自 responder.messages）。
	Message string
	// RequestID 是请求标识。
	RequestID string
	// Timestamp 是响应时间，RFC3339Nano 格式。
	Timestamp string
	// Verdict 是判定结论。
	Verdict string
	// Target 是触发拦截 / 封禁的检测目标。
	Target string
	// BanScope 是导致本次拦截的封禁维度。
	BanScope string
	// URI 是触发拦截的完整原始 URI（含查询串）。
	URI string
	// Site 是命中的站点名。
	Site string
	// Path 是原始请求路径。
	Path string
	// ClientIP 是客户端 IP。
	ClientIP string
	// Check 是产生结论的校验单元实例名。
	Check string
	// RuleID 是命中的规则标识。
	RuleID string
	// Score 是累计异常评分。
	Score int
	// RetryAfter 是建议退避秒数；仅限速场景大于 0。
	RetryAfter int
	// HasDetails 表示本次响应是否包含检测细节。
	HasDetails bool
	// Details 是检测细节；HasDetails=false 时各字段为零值。
	Details ErrorDetails
	// Messages 是完整的错误码到提示语映射，便于模板按需取用。
	Messages map[string]string
}

// responseTemplate 是编译后的响应模板。
type responseTemplate struct {
	tmpl     *template.Template
	maxBytes int64
	logger   *slog.Logger
}

// newResponseTemplate 依据配置加载并编译响应模板；未配置模板时返回 nil。
func newResponseTemplate(cfg Config) (*responseTemplate, error) {
	text, err := templateText(cfg.Template, cfg.TemplateFile)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	tmpl, err := compileTemplate(text)
	if err != nil {
		return nil, err
	}
	maxBytes := cfg.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	renderer := &responseTemplate{tmpl: tmpl, maxBytes: maxBytes, logger: cfg.Logger}

	// 启动阶段用样例数据执行一次并校验 JSON，避免上线后才发现模板不可用。
	if _, err := renderer.Render(sampleTemplateData(cfg.Messages)); err != nil {
		return nil, fmt.Errorf("响应模板校验失败：%w", err)
	}
	return renderer, nil
}

// ValidateResponderConfig 校验 responder 模板配置，供 check-config 等命令提前失败。
func ValidateResponderConfig(cfg config.ResponderConfig) error {
	if cfg.Template != "" && cfg.TemplateFile != "" {
		return errors.New("responder.template 与 responder.template_file 不能同时配置")
	}
	renderer, err := newResponseTemplate(Config{
		Template:     cfg.Template,
		TemplateFile: cfg.TemplateFile,
		MaxBodyBytes: cfg.MaxBodyBytes,
	})
	if err != nil {
		return err
	}
	_ = renderer
	return nil
}

// Render 执行模板并返回 JSON 字节。
func (r *responseTemplate) Render(data TemplateData) ([]byte, error) {
	if r == nil || r.tmpl == nil {
		return nil, errors.New("响应模板未编译")
	}
	writer := &limitedBuffer{limit: r.maxBytes}
	if err := r.tmpl.Execute(writer, data); err != nil {
		return nil, err
	}
	if writer.exceeded {
		return nil, errTemplateBodyTooLarge
	}
	payload := writer.buf.Bytes()
	if !json.Valid(payload) {
		return nil, errors.New("响应模板输出不是合法 JSON")
	}
	return append([]byte(nil), payload...), nil
}

// templateText 读取内联或外部模板；两者互斥。
func templateText(inline, file string) (string, error) {
	if inline != "" && file != "" {
		return "", errors.New("responder.template 与 responder.template_file 不能同时配置")
	}
	if file == "" {
		return inline, nil
	}
	info, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("响应模板文件 %s 无法访问：%w", file, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("响应模板文件 %s 是目录，不是文件", file)
	}
	if info.Size() > maxTemplateFileBytes {
		return "", fmt.Errorf("响应模板文件 %s 大小 %d 字节，超过上限 %d 字节",
			file, info.Size(), maxTemplateFileBytes)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("读取响应模板文件 %s 失败：%w", file, err)
	}
	return string(content), nil
}

// compileTemplate 解析模板并注册 JSON 转义函数。
func compileTemplate(text string) (*template.Template, error) {
	tmpl, err := template.New("responder").Funcs(template.FuncMap{
		"json": templateJSON,
	}).Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("响应模板语法错误：%w", err)
	}
	return tmpl, nil
}

// templateJSON 把任意值编码为 JSON 字面量，供模板安全地输出字符串。
func templateJSON(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", fmt.Errorf("模板值序列化为 JSON 失败：%w", err)
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

// sampleTemplateData 是启动校验使用的样例数据。
//
// Messages 会合并内置默认文案与用户自定义文案：模板可能按自定义错误码
// 取文案（{{ .Messages.WAF_CUSTOM }}），样例数据必须覆盖这些键，否则
// 合法的模板会被 missingkey=error 误判为非法。
func sampleTemplateData(custom map[string]string) TemplateData {
	messages := make(map[string]string, len(config.Default().Responder.Messages)+len(custom))
	for code, message := range config.Default().Responder.Messages {
		messages[code] = message
	}
	for code, message := range custom {
		messages[code] = message
	}

	return TemplateData{
		Code:       config.CodeBlocked,
		Status:     403,
		Message:    "请求被安全策略拦截",
		RequestID:  "template-check",
		Timestamp:  "2026-01-01T00:00:00Z",
		Verdict:    core.VerdictBlock.String(),
		Target:     "ARGS:id",
		BanScope:   "client_ip",
		URI:        "/api/user?id=1",
		Site:       core.DefaultSiteName,
		Path:       "/",
		ClientIP:   "127.0.0.1",
		Check:      "template",
		RuleID:     "0",
		Score:      0,
		RetryAfter: 0,
		HasDetails: true,
		Details: ErrorDetails{
			Verdict:  core.VerdictBlock.String(),
			Check:    "template",
			RuleID:   "0",
			Target:   "ARGS:id",
			BanScope: "client_ip",
			URI:      "/api/user?id=1",
			Score:    0,
		},
		Messages: messages,
	}
}

// limitedBuffer 是带输出上限的缓冲区。
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	exceeded bool
}

// Write 在超过上限时停止写入并标记 exceeded。
func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.limit > 0 && int64(w.buf.Len()+len(p)) > w.limit {
		w.exceeded = true
		return 0, errTemplateBodyTooLarge
	}
	return w.buf.Write(p)
}
