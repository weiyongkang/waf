package core

import (
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"strings"
)

// defaultRequestParamsMaxBytes 是日志 / 审计中请求体参数快照的默认上限。
const defaultRequestParamsMaxBytes int64 = 4096

// RequestParams 是一次请求的参数快照。
//
// 只保存结构化参数，不保存完整请求体；请求体超过上限时标记 BodyTruncated。
// 敏感字段（口令、令牌、Cookie 等）的值会被替换为 [REDACTED]。
type RequestParams struct {
	// Query 是查询串参数。
	Query map[string]any `json:"query,omitempty"`
	// Body 是 JSON 或 form 请求体中的参数。
	Body map[string]any `json:"body,omitempty"`
	// BodyTruncated 表示请求体超过采集上限，Body 可能不完整。
	BodyTruncated bool `json:"body_truncated,omitempty"`
}

// Empty 报告参数快照是否为空。
func (p RequestParams) Empty() bool {
	return len(p.Query) == 0 && len(p.Body) == 0
}

// JSON 把参数快照序列化为单行 JSON；为空时返回空串。
func (p RequestParams) JSON() string {
	if p.Empty() {
		return ""
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(payload)
}

// CaptureRequestParams 提取查询参数，并在请求体已被 pipeline 缓冲时提取 JSON / form 参数。
//
// 请求体来自 RequestContext.Stream，因此不会再次读取网络流；读取前后都会 Rewind，
// 保证后续审计或日志采集不会改变请求体检测结果。未启用体阶段校验时 Stream 为 nil，
// 此时只采集查询参数，避免为了日志额外读取请求体。
func CaptureRequestParams(rctx *RequestContext, maxBodyBytes int64) RequestParams {
	if rctx == nil {
		return RequestParams{}
	}
	params := RequestParams{}
	if rctx.Raw != nil {
		params.Query = parseURLValues(rctx.Raw.RawQuery)
	}
	if rctx.Stream == nil {
		return params
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultRequestParamsMaxBytes
	}

	meta := rctx.Stream.Meta()
	bodyParams, truncated := readBodyParams(rctx, maxBodyBytes)
	params.Body = bodyParams
	params.BodyTruncated = truncated || meta.Truncated
	return params
}

// readBodyParams 从已缓冲的请求体读取参数。
func readBodyParams(rctx *RequestContext, maxBytes int64) (map[string]any, bool) {
	if err := rctx.Stream.Rewind(); err != nil {
		return nil, false
	}
	defer func() { _ = rctx.Stream.Rewind() }()

	data, err := io.ReadAll(io.LimitReader(rctx.Stream, maxBytes+1))
	if err != nil || len(data) == 0 {
		return nil, false
	}
	truncated := int64(len(data)) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}

	contentType := ""
	if rctx.Raw != nil {
		contentType = rctx.Raw.HeaderValue("Content-Type")
	}
	if contentType == "" {
		contentType = rctx.Body.ContentType
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, truncated
	}
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return parseURLValues(string(data)), truncated
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return parseJSONParams(data, truncated), truncated
	default:
		return nil, truncated
	}
}

// parseJSONParams 把 JSON 对象转换为参数映射；非对象值保存在 _value 下。
func parseJSONParams(data []byte, truncated bool) map[string]any {
	if truncated {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	if object, ok := parsed.(map[string]any); ok {
		return redactMap(object)
	}
	return map[string]any{"_value": redactValue("", parsed)}
}

// parseURLValues 把查询串或 form 编码转换为参数映射。
func parseURLValues(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	result := make(map[string]any, len(values))
	for key, items := range values {
		switch len(items) {
		case 0:
			result[key] = "[REDACTED]"
		case 1:
			result[key] = redactValue(key, items[0])
		default:
			redacted := make([]any, 0, len(items))
			for _, item := range items {
				redacted = append(redacted, redactValue(key, item))
			}
			result[key] = redacted
		}
	}
	return result
}

// redactMap 递归脱敏参数映射。
func redactMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = redactValue(key, value)
	}
	return result
}

// redactValue 对敏感字段值脱敏，并递归处理嵌套对象。
func redactValue(key string, value any) any {
	if sensitiveParam(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed)
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, redactValue("", item))
		}
		return result
	default:
		return value
	}
}

// sensitiveParam 判断参数名是否属于常见敏感字段。
func sensitiveParam(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{
		"password", "passwd", "secret", "token", "authorization", "cookie",
		"api_key", "apikey", "session", "credential", "private_key",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
