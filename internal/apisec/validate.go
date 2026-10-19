package apisec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Validate 校验一次请求。matched 为 false 表示 OpenAPI 中没有该 method + path。
func (s *Spec) Validate(method, requestPath string, query url.Values, header http.Header,
	body []byte, checkParameters, checkBody bool, maxViolations int) (bool, []Violation) {
	route, pathParams := s.Match(method, requestPath)
	if route == nil {
		return false, nil
	}
	v := newValidator(s, maxViolations)
	if checkParameters {
		for _, parameter := range route.Parameters {
			violations := validateParameter(v, parameter, query, header, pathParams)
			v.violations = append(v.violations, violations...)
			if v.reachedLimit() {
				return true, v.violations
			}
		}
	}
	if checkBody {
		violations := validateBody(v, route, header.Get("Content-Type"), body)
		v.violations = append(v.violations, violations...)
	}
	return true, v.violations
}

func validateParameter(v *validator, parameter Parameter, query url.Values,
	header http.Header, pathParams map[string]string) []Violation {
	location := parameter.In
	name := parameter.Name
	values := make([]string, 0, 2)
	switch location {
	case "path":
		if value, exists := pathParams[name]; exists {
			values = append(values, value)
		}
	case "query":
		values = append(values, query[name]...)
	case "header":
		values = append(values, header.Values(name)...)
	case "cookie":
		request := &http.Request{Header: header}
		for _, cookie := range request.Cookies() {
			if strings.EqualFold(cookie.Name, name) {
				values = append(values, cookie.Value)
			}
		}
	}
	if len(values) == 0 {
		if parameter.Required {
			return []Violation{{Location: location, Name: name,
				Rule: "parameter_required", Message: "缺少必填参数"}}
		}
		return nil
	}

	converted, err := coerceParameter(parameter.Schema, values)
	if err != nil {
		return []Violation{{Location: location, Name: name,
			Rule: "parameter_type", Message: err.Error()}}
	}
	return v.check(parameter.Schema, converted, location, name, 0)
}

func coerceParameter(schema any, values []string) (any, error) {
	resolved, ok := resolveSchemaStatic(schema)
	if !ok {
		return values[0], nil
	}
	obj, _ := asMap(resolved)
	types := schemaTypes(obj)
	expected := ""
	if len(types) > 0 {
		expected = types[0]
	}
	if expected == "array" {
		items := values
		if len(values) == 1 && strings.Contains(values[0], ",") {
			items = strings.Split(values[0], ",")
		}
		result := make([]any, 0, len(items))
		itemSchema := obj["items"]
		for _, item := range items {
			converted, err := coercePrimitive(itemSchema, item)
			if err != nil {
				return nil, err
			}
			result = append(result, converted)
		}
		return result, nil
	}
	return coercePrimitive(schema, values[0])
}

func resolveSchemaStatic(schema any) (any, bool) {
	// 参数 schema 直接写在 spec 中时通常不含 $ref；含 $ref 的情况由
	// validator.check 在真正校验阶段解析。这里只做类型提示。
	return schema, true
}

func coercePrimitive(schema any, raw string) (any, error) {
	obj, _ := asMap(schema)
	types := schemaTypes(obj)
	if len(types) == 0 {
		return raw, nil
	}
	for _, expected := range types {
		switch expected {
		case "string", "null":
			return raw, nil
		case "integer":
			parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err == nil {
				return json.Number(strconv.FormatInt(parsed, 10)), nil
			}
		case "number":
			parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err == nil {
				return parsed, nil
			}
		case "boolean":
			parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
			if err == nil {
				return parsed, nil
			}
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "1":
				return true, nil
			case "0":
				return false, nil
			}
		}
	}
	return nil, fmt.Errorf("参数值 %q 无法转换为 %s", raw, strings.Join(types, " / "))
}

func validateBody(v *validator, route *Route, contentType string, body []byte) []Violation {
	if route.Body == nil {
		return nil
	}
	if len(body) == 0 {
		if route.Body.Required {
			return []Violation{{Location: "body", Rule: "body_required", Message: "缺少请求体"}}
		}
		return nil
	}
	if len(route.Body.Content) == 0 {
		return nil
	}
	base := mediaTypeBase(contentType)
	schema, matched := selectMediaSchema(route.Body.Content, base)
	if !matched {
		return []Violation{{Location: "body", Name: "Content-Type", Rule: "body_content_type",
			Message: fmt.Sprintf("请求体媒体类型 %q 未在 spec 中声明", contentType)}}
	}
	if !isJSONMediaType(base) {
		// 当前版本只解析 JSON 请求体；其它媒体类型不做结构校验，避免把
		// multipart / form 数据误报为违规。
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return []Violation{{Location: "body", Rule: "body_json",
			Message: fmt.Sprintf("请求体不是合法 JSON：%v", err)}}
	}
	if err := ensureEOF(decoder); err != nil {
		return []Violation{{Location: "body", Rule: "body_json",
			Message: "JSON 请求体后存在多余内容"}}
	}
	if schema == nil {
		return nil
	}
	return v.check(schema, value, "body", "", 0)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("多余 JSON 值")
	}
	return err
}

func selectMediaSchema(content map[string]any, base string) (any, bool) {
	if schema, ok := content[base]; ok {
		return schema, true
	}
	bestScore := -1
	var best any
	for mediaType, schema := range content {
		score := mediaMatchScore(strings.ToLower(strings.TrimSpace(mediaType)), base)
		if score > bestScore {
			bestScore, best = score, schema
		}
	}
	if bestScore >= 0 {
		return best, true
	}
	return nil, false
}

func mediaMatchScore(declared, actual string) int {
	if declared == actual {
		return 100
	}
	if declared == "*/*" {
		return 10
	}
	declaredBase, declaredSub, ok := strings.Cut(declared, "/")
	if !ok {
		return -1
	}
	actualBase, actualSub, ok := strings.Cut(actual, "/")
	if !ok {
		return -1
	}
	if declaredBase != "*" && declaredBase != actualBase {
		return -1
	}
	if declaredSub == "*" {
		return 20
	}
	if strings.HasSuffix(declaredSub, "+json") && strings.HasSuffix(actualSub, "+json") {
		return 30
	}
	return -1
}

func isJSONMediaType(value string) bool {
	base := mediaTypeBase(value)
	return base == "application/json" || base == "text/json" || strings.HasSuffix(base, "+json")
}
