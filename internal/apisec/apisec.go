// Package apisec 提供本地 OpenAPI 3.x 请求契约校验。
//
// 设计边界：
//   - 只读取本地 spec 文件，不访问任何远端 API 文档；
//   - 只校验请求侧（参数与 JSON 请求体），不生成响应；
//   - 不实现完整 JSON Schema，仅覆盖 OpenAPI 契约校验的高频子集。
package apisec

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Violation 是一条请求契约违规。
type Violation struct {
	// Location 是违规位置：path / query / header / cookie / body。
	Location string
	// Name 是参数名或 JSON 路径。
	Name string
	// Rule 是稳定的违规类型标识，便于告警聚合。
	Rule string
	// Message 是人类可读说明。
	Message string
}

func (v Violation) String() string {
	if v.Name == "" {
		return fmt.Sprintf("%s: %s", v.Rule, v.Message)
	}
	return fmt.Sprintf("%s %q: %s", v.Rule, v.Name, v.Message)
}

// Route 是一条 OpenAPI 路径 + 方法的匹配规则。
type Route struct {
	// Method 是规范化后的 HTTP 方法。
	Method string
	// Path 是 OpenAPI 模板路径，例如 /users/{id}。
	Path string
	// Parameters 是路径级与操作级合并后的参数声明。
	Parameters []Parameter
	// Body 是请求体声明；nil 表示该操作没有 requestBody。
	Body *RequestBody

	segments []segment
	score    int
}

type segment struct {
	literal string
	name    string
}

// Parameter 是一个 OpenAPI 参数声明。
type Parameter struct {
	Name     string
	In       string
	Required bool
	Schema   any
}

// RequestBody 是 OpenAPI requestBody 声明。
type RequestBody struct {
	Required bool
	// Content 是「媒体类型 -> schema」；媒体类型保留原始字符串。
	Content map[string]any
}

// Spec 是已编译的 OpenAPI 契约。
type Spec struct {
	// Version 是 openapi 字段值。
	Version string
	// Path 是来源文件路径（用于日志）。
	Path string

	routes  []Route
	schemas map[string]any
}

// RouteCount 返回已加载的「路径 + 方法」数量。
func (s *Spec) RouteCount() int {
	if s == nil {
		return 0
	}
	return len(s.routes)
}

// LoadFile 读取并编译 OpenAPI 文件。
func LoadFile(path string, maxBytes int64) (*Spec, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, fmt.Errorf("OpenAPI spec 文件路径不能为空")
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec 文件 %s 不可访问：%w", trimmed, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("OpenAPI spec 路径 %s 是目录，必须指向 .yaml/.yml/.json 文件", trimmed)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("OpenAPI spec 文件 %s 大小 %d 超过 limits.max_config_file_bytes=%d",
			trimmed, info.Size(), maxBytes)
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		return nil, fmt.Errorf("读取 OpenAPI spec 文件 %s 失败：%w", trimmed, err)
	}
	spec, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("解析 OpenAPI spec 文件 %s 失败：%w", trimmed, err)
	}
	spec.Path = trimmed
	return spec, nil
}

// Fingerprint 返回文件大小与修改时间指纹，用于热更新判断。
func Fingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

// Match 返回请求命中的路由；未命中返回 nil。
func (s *Spec) Match(method, requestPath string) (*Route, map[string]string) {
	if s == nil {
		return nil, nil
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	parts := splitPath(requestPath)
	for index := range s.routes {
		route := &s.routes[index]
		if route.Method != method {
			continue
		}
		if params, ok := route.match(parts); ok {
			return route, params
		}
	}
	return nil, nil
}

func (r *Route) match(parts []string) (map[string]string, bool) {
	if len(parts) != len(r.segments) {
		return nil, false
	}
	params := make(map[string]string)
	for index, item := range r.segments {
		value := parts[index]
		if item.name != "" {
			decoded, err := url.PathUnescape(value)
			if err != nil {
				decoded = value
			}
			params[item.name] = decoded
			continue
		}
		if item.literal != value {
			return nil, false
		}
	}
	return params, true
}

func splitPath(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{""}
	}
	if strings.HasPrefix(value, "/") {
		value = value[1:]
	}
	if value == "" {
		return []string{""}
	}
	return strings.Split(value, "/")
}

func compileSegments(path string) ([]segment, int) {
	parts := splitPath(path)
	segments := make([]segment, 0, len(parts))
	score := 0
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") && len(part) > 2 {
			segments = append(segments, segment{name: strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")})
			continue
		}
		segments = append(segments, segment{literal: part})
		if part != "" {
			score += 10
		}
	}
	return segments, score
}

// sortRoutes 让更具体的路径先匹配：先比字面段数量，再比段数。
func sortRoutes(routes []Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].score != routes[j].score {
			return routes[i].score > routes[j].score
		}
		return len(routes[i].segments) > len(routes[j].segments)
	})
}

// mediaTypeBase 去掉参数部分并转小写。
func mediaTypeBase(value string) string {
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.TrimSpace(value))
}
