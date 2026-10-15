package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// segmentPattern 限定可参与「环境变量 / CLI」覆盖的路径片段形态。
//
// 之所以需要它：responder.messages 这类映射的键由用户自定义（例如 WAF_BLOCKED），
// 无法机械地推导出唯一的环境变量名，因此这类路径只允许通过配置文件设置。
var segmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// schema 描述配置树的合法路径集合，以及三通道命名推导规则。
type schema struct {
	// known 是全部合法配置路径（叶子路径 + 中间节点路径），用于未知配置项检查。
	known map[string]struct{}
	// leaves 是全部叶子路径（含数组叶子与标量叶子），用于配置项总数统计。
	leaves map[string]struct{}
	// scalars 是「可被环境变量 / CLI 覆盖的标量叶子」路径及其中间默认值类型信息。
	scalars map[string]any
	// envNames 是「环境变量名 -> 配置路径」索引。
	envNames map[string]string
	// flagNames 是「CLI 参数名（不含前导 --）-> 配置路径」索引。
	flagNames map[string]string
	// pathToFlag 是「配置路径 -> CLI 参数名」的反向索引，用于帮助信息。
	pathToFlag map[string]string
}

// openMapPaths 是「键名由用户自由定义」的映射路径集合，其子路径不参与未知项检查。
var openMapPaths = map[string]struct{}{
	"responder.messages": {},
}

// buildSchema 以默认配置为蓝本构建配置 schema。
//
// 之所以从默认配置推导而非手工维护清单：
//   - 默认配置就是唯一的字段真源，新增字段后 schema 自动同步，不会出现「文档漏写」；
//   - 环境变量名与 CLI 参数名可以机械推导，保证与配置路径一一对应（设计文档 §2.7）。
func buildSchema() (*schema, error) {
	cfg := Default()
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("默认配置无法序列化：%w", err)
	}

	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("默认配置无法反序列化：%w", err)
	}

	leaves := make(map[string]any)
	flattenLeaves("", tree, leaves)

	sch := &schema{
		known:      make(map[string]struct{}),
		leaves:     make(map[string]struct{}),
		scalars:    make(map[string]any),
		envNames:   make(map[string]string),
		flagNames:  make(map[string]string),
		pathToFlag: make(map[string]string),
	}

	for path, value := range leaves {
		sch.known[path] = struct{}{}
		sch.leaves[path] = struct{}{}
		// 同时登记所有中间节点路径，保证未知项检查能给出「父节点合法但字段不存在」的准确结论。
		segments := splitPath(path)
		for i := 1; i < len(segments); i++ {
			sch.known[strings.Join(segments[:i], ".")] = struct{}{}
		}

		if !isScalar(value) || !isOverridablePath(path) {
			continue
		}
		sch.scalars[path] = value
	}

	if err := sch.buildIndexes(); err != nil {
		return nil, err
	}
	return sch, nil
}

// buildIndexes 推导环境变量名与 CLI 参数名，并检测命名冲突。
//
// 冲突检测的意义：单下划线推导存在天然歧义（ban.default_ttl 与 ban.default.ttl
// 会得到同一个名字）。一旦未来新增字段造成冲突，必须在开发阶段立即暴露，
// 而不是在运行期静默地「配置项互相覆盖」。
func (s *schema) buildIndexes() error {
	for path := range s.scalars {
		envName := "WAF_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
		if existing, ok := s.envNames[envName]; ok {
			return fmt.Errorf("环境变量名冲突：%s 同时对应 %s 与 %s", envName, existing, path)
		}
		s.envNames[envName] = path

		flagName := strings.ReplaceAll(strings.ReplaceAll(path, ".", "-"), "_", "-")
		if existing, ok := s.flagNames[flagName]; ok {
			return fmt.Errorf("CLI 参数名冲突：--%s 同时对应 %s 与 %s", flagName, existing, path)
		}
		s.flagNames[flagName] = path
		s.pathToFlag[path] = flagName
	}
	return nil
}

// isScalar 判断展平后的叶子值是否为标量（可被环境变量 / CLI 表达）。
//
// 数组与映射不属于标量：环境变量无法无损表达嵌套数组语义。
func isScalar(value any) bool {
	switch value.(type) {
	case nil, string, bool, int, int64, float64:
		return true
	default:
		return false
	}
}

// isOverridablePath 判断路径的每一段是否都符合机械命名规则。
func isOverridablePath(path string) bool {
	for _, segment := range splitPath(path) {
		if !segmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}

// isOpenPath 判断路径是否为「键名自由」的映射，其子路径允许任意命名。
func isOpenPath(path string) bool {
	if _, ok := openMapPaths[path]; ok {
		return true
	}
	segments := splitPath(path)
	if len(segments) == 0 {
		return false
	}
	last := segments[len(segments)-1]
	// settings（插件/存储私有配置）与 params（站点参数覆盖）的键由实现方定义。
	return last == "settings" || last == "params"
}

// collectUnknown 递归收集配置树中「不在 schema 内」的路径。
//
// 该检查替代 go-yaml 的 KnownFields 严格模式：一是能给出「配置项 + 来源」的精确错误
// （设计文档 §2.7 要求），二是能正确跳过 settings / messages / params 这类开放映射。
func collectUnknown(prefix string, value any, sch *schema, out *[]string) {
	if isOpenPath(prefix) {
		return
	}
	if asMap, ok := value.(map[string]any); ok {
		for _, key := range sortedKeys(asMap) {
			path := joinPath(prefix, key)
			if _, known := sch.known[path]; !known {
				// 只有叶子才报错：中间节点缺失时，其子节点同样不存在，避免重复告警。
				if _, isMap := asMap[key].(map[string]any); !isMap {
					*out = append(*out, path)
				}
				continue
			}
			collectUnknown(path, asMap[key], sch, out)
		}
	}
}
