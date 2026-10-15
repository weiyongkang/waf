package coraza

import "strings"

// 本文件实现 JSON 嵌套深度防护。
//
// 为什么需要它（重要）：Coraza v3.0.0 的 JSON 请求体处理器把整个 JSON 喂给
// gjson 递归展开，源码中明确留有 "TODO add some anti DOS protection"，
// 也就是说上游对「深层嵌套 / 超宽数组」没有任何深度限制。
// 攻击者可以用一个几十 KB、嵌套上万层的 JSON（或超宽数组）让请求处理线程
// 长时间占用 CPU 与内存，形成不依赖带宽的拒绝服务。
//
// 因此本项目自行实现一个「先扫深度、再交给引擎」的前置守卫，
// 深度上限来自配置项 engine.body.json_depth_limit（需求 R13：限额不得硬编码）。
//
// 扫描实现刻意做得保守：只统计花括号 / 方括号的嵌套层级，并正确跳过字符串内部
// （含转义字符），因此「字符串里写满 {{[[」不会造成误判。

// jsonDepthExceededRuleID 是 JSON 深度超限命中明细使用的规则标识。
const jsonDepthExceededRuleID = "json_depth_exceeded"

// maxJSONDepth 扫描 JSON 文本并返回最大嵌套深度。
//
// 返回值语义：depth 为观察到的最大深度（0 表示没有嵌套结构）。
// 该函数不做 JSON 语法校验——语法错误由引擎侧的 JSON 处理器负责，
// 这里只关心「嵌套有多深」，因此可以做到单遍扫描、零分配。
func maxJSONDepth(data []byte) int {
	// depth 是当前嵌套层级，maxDepth 是观察到的最大值。
	depth := 0
	maxDepth := 0
	// inString 表示当前是否位于字符串字面量内部。
	inString := false
	// escaped 表示上一个字符是反斜杠，用于正确跳过 \" 这类转义。
	escaped := false

	for _, char := range data {
		if inString {
			switch {
			case escaped:
				// 转义序列的第二个字符，无条件跳过。
				escaped = false
			case char == '\\':
				escaped = true
			case char == '"':
				inString = false
			}
			continue
		}

		switch char {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}

// isJSONContentType 判断内容类型是否属于 JSON。
//
// 同时接受 application/json 与其 +json 后缀形式（例如 application/vnd.api+json）。
func isJSONContentType(contentType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(contentType))
	if normalized == "" {
		return false
	}
	// 去掉参数部分（例如 "; charset=utf-8"）。
	if idx := strings.IndexByte(normalized, ';'); idx >= 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	return normalized == "application/json" || strings.HasSuffix(normalized, "+json")
}

// isMultipartContentType 判断内容类型是否属于 multipart/form-data。
//
// 只识别 multipart/form-data：其余 multipart 子类型（mixed、related 等）不是
// 文件上传语义，Coraza 也不会为它们选择 MULTIPART 处理器，无需在此处理。
func isMultipartContentType(contentType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(contentType))
	if normalized == "" {
		return false
	}
	// 去掉参数部分（例如 "; boundary=..."）。
	if idx := strings.IndexByte(normalized, ';'); idx >= 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	return normalized == "multipart/form-data"
}
