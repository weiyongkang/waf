package apisec

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type rawSpec struct {
	OpenAPI    string                 `yaml:"openapi"`
	Paths      map[string]rawPathItem `yaml:"paths"`
	Components rawComponents          `yaml:"components"`
}

type rawComponents struct {
	Schemas map[string]any `yaml:"schemas"`
}

type rawPathItem struct {
	Ref        string         `yaml:"$ref"`
	Parameters []rawParameter `yaml:"parameters"`
	Get        *rawOperation  `yaml:"get"`
	Put        *rawOperation  `yaml:"put"`
	Post       *rawOperation  `yaml:"post"`
	Delete     *rawOperation  `yaml:"delete"`
	Options    *rawOperation  `yaml:"options"`
	Head       *rawOperation  `yaml:"head"`
	Patch      *rawOperation  `yaml:"patch"`
	Trace      *rawOperation  `yaml:"trace"`
}

type rawOperation struct {
	Parameters  []rawParameter  `yaml:"parameters"`
	RequestBody *rawRequestBody `yaml:"requestBody"`
}

type rawParameter struct {
	Ref      string         `yaml:"$ref"`
	Name     string         `yaml:"name"`
	In       string         `yaml:"in"`
	Required bool           `yaml:"required"`
	Schema   any            `yaml:"schema"`
	Content  map[string]any `yaml:"content"`
}

type rawRequestBody struct {
	Ref      string              `yaml:"$ref"`
	Required bool                `yaml:"required"`
	Content  map[string]rawMedia `yaml:"content"`
}

type rawMedia struct {
	Schema any `yaml:"schema"`
}

// Parse 解析 OpenAPI 3.x YAML 或 JSON。
//
// OpenAPI 本身是 JSON 对象，JSON 是 YAML 的子集，因此统一用 yaml.v3 解析，
// 避免同时维护两套文档结构。
func Parse(data []byte) (*Spec, error) {
	var document rawSpec
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("不是合法的 YAML/JSON：%w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(document.OpenAPI), "3.") {
		return nil, fmt.Errorf("openapi = %q，当前仅支持 OpenAPI 3.x", document.OpenAPI)
	}
	if len(document.Paths) == 0 {
		return nil, fmt.Errorf("paths 为空，spec 中没有任何可校验接口")
	}
	schemas := document.Components.Schemas
	if schemas == nil {
		schemas = map[string]any{}
	}

	spec := &Spec{Version: document.OpenAPI, schemas: schemas}
	for path, item := range document.Paths {
		if strings.TrimSpace(path) == "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("paths 中的路径 %q 非法，必须以 \"/\" 开头", path)
		}
		if item.Ref != "" {
			return nil, fmt.Errorf("path %q 使用 $ref 引用；当前版本要求直接声明路径操作", path)
		}
		operations := map[string]*rawOperation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post, "DELETE": item.Delete,
			"OPTIONS": item.Options, "HEAD": item.Head, "PATCH": item.Patch, "TRACE": item.Trace,
		}
		for method, operation := range operations {
			if operation == nil {
				continue
			}
			parameters, err := mergeParameters(path, item.Parameters, operation.Parameters)
			if err != nil {
				return nil, err
			}
			route := Route{Method: method, Path: path, Parameters: parameters}
			route.segments, route.score = compileSegments(path)
			if operation.RequestBody != nil {
				body, bodyErr := compileRequestBody(path, method, operation.RequestBody)
				if bodyErr != nil {
					return nil, bodyErr
				}
				route.Body = body
			}
			spec.routes = append(spec.routes, route)
		}
	}
	if len(spec.routes) == 0 {
		return nil, fmt.Errorf("paths 中没有任何 HTTP 操作")
	}
	sortRoutes(spec.routes)
	return spec, nil
}

func mergeParameters(path string, groups ...[]rawParameter) ([]Parameter, error) {
	merged := make(map[string]Parameter)
	order := make([]string, 0)
	for _, group := range groups {
		for _, item := range group {
			if item.Ref != "" {
				return nil, fmt.Errorf("path %q 的参数使用 $ref 引用；当前版本要求内联参数 schema", path)
			}
			name := strings.TrimSpace(item.Name)
			location := strings.ToLower(strings.TrimSpace(item.In))
			if name == "" || location == "" {
				return nil, fmt.Errorf("path %q 存在缺少 name 或 in 的参数", path)
			}
			switch location {
			case "path", "query", "header", "cookie":
			default:
				return nil, fmt.Errorf("path %q 参数 %q 的 in=%q 非法", path, name, item.In)
			}
			schema := item.Schema
			if schema == nil && len(item.Content) > 0 {
				for _, media := range item.Content {
					schema = media
					break
				}
			}
			key := location + "\x00" + strings.ToLower(name)
			if _, exists := merged[key]; !exists {
				order = append(order, key)
			}
			merged[key] = Parameter{
				Name: name, In: location, Required: item.Required || location == "path", Schema: schema,
			}
		}
	}
	parameters := make([]Parameter, 0, len(order))
	for _, key := range order {
		parameters = append(parameters, merged[key])
	}
	return parameters, nil
}

func compileRequestBody(path, method string, raw *rawRequestBody) (*RequestBody, error) {
	if raw.Ref != "" {
		return nil, fmt.Errorf("%s %s 的 requestBody 使用 $ref 引用；当前版本要求内联 requestBody", method, path)
	}
	if len(raw.Content) == 0 {
		return &RequestBody{Required: raw.Required, Content: map[string]any{}}, nil
	}
	content := make(map[string]any, len(raw.Content))
	for mediaType, media := range raw.Content {
		content[strings.ToLower(strings.TrimSpace(mediaType))] = media.Schema
	}
	return &RequestBody{Required: raw.Required, Content: content}, nil
}

// ResolveRef 解析本地 components.schemas 引用。
func (s *Spec) ResolveRef(ref string) (any, bool) {
	const prefix = "#/components/schemas/"
	if s == nil || !strings.HasPrefix(ref, prefix) {
		return nil, false
	}
	name := strings.ReplaceAll(strings.TrimPrefix(ref, prefix), "~1", "/")
	name = strings.ReplaceAll(name, "~0", "~")
	schema, ok := s.schemas[name]
	return schema, ok
}

func asMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[any]any:
		converted := make(map[string]any, len(typed))
		for key, item := range typed {
			converted[fmt.Sprint(key)] = item
		}
		return converted, true
	default:
		return nil, false
	}
}

func asSlice(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	default:
		return nil, false
	}
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func asBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconvParseBool(typed)
		return parsed, err == nil
	default:
		return false, false
	}
}

func strconvParseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("不是布尔值")
	}
}

func asFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	default:
		return 0, false
	}
}
