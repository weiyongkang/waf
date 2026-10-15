package config

import (
	"fmt"
	"sort"
	"strings"
)

// joinPath 拼接点分路径。
func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// splitPath 拆分点分路径。
func splitPath(path string) []string {
	return strings.Split(path, ".")
}

// flattenLeaves 把嵌套配置树展平为「点分路径 -> 叶子值」。
//
// 展平规则：
//   - 映射（map）继续递归；
//   - 数组与标量都视为叶子（数组整体作为一个叶子）。
//
// 之所以数组视为叶子：结构化列表（pipeline / stores / notifiers / sites）
// 只允许通过配置文件声明，环境变量与 CLI 无法表达数组语义（设计文档 §2.7）。
func flattenLeaves(prefix string, value any, out map[string]any) {
	if asMap, ok := value.(map[string]any); ok {
		for key, child := range asMap {
			flattenLeaves(joinPath(prefix, key), child, out)
		}
		return
	}
	out[prefix] = value
}

// setLeaf 把一个叶子值写入嵌套配置树的指定点分路径。
//
// 路径必须已存在（由 schema 保证），否则返回错误——这属于程序缺陷而非用户配置错误。
func setLeaf(tree map[string]any, path string, value any) error {
	segments := splitPath(path)
	current := tree
	for i := 0; i < len(segments)-1; i++ {
		next, exists := current[segments[i]]
		if !exists {
			return fmt.Errorf("配置路径 %q 的中间节点 %q 不存在", path, segments[i])
		}
		asMap, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("配置路径 %q 的中间节点 %q 不是映射类型", path, segments[i])
		}
		current = asMap
	}
	current[segments[len(segments)-1]] = value
	return nil
}

// mergeTree 把 src 深度合并进 dst，并逐个记录叶子来源。
//
// 合并语义：
//   - 映射递归合并；
//   - 标量与数组整体替换。
//
// 之所以不用「追加」语义：配置项一旦被更高优先级通道设置，就应当整体覆盖低优先级值，
// 例如 pipeline 数组在文件中声明后应完整替换默认值，而不是与默认值拼接。
func mergeTree(dst, src map[string]any, prefix string, origin Origin, origins map[string]Origin) {
	for key, value := range src {
		path := joinPath(prefix, key)
		if srcMap, ok := value.(map[string]any); ok {
			dstMap, ok := dst[key].(map[string]any)
			if !ok {
				dstMap = make(map[string]any, len(srcMap))
				dst[key] = dstMap
			}
			mergeTree(dstMap, srcMap, path, origin, origins)
			continue
		}
		dst[key] = value
		markOrigin(origins, path, origin)
	}
}

// markOrigin 记录某配置路径（及其子路径）的来源。
//
// 对于数组类叶子无法枚举内部元素，只记录数组根路径；
// 之所以还要标记子路径：文件中的嵌套映射被合并时，父路径也应体现来源，
// 便于 `check-config` 摘要输出「pipeline 来自文件」这类信息。
func markOrigin(origins map[string]Origin, path string, origin Origin) {
	if existing, ok := origins[path]; ok && originPriority[existing] > originPriority[origin] {
		return
	}
	origins[path] = origin
}

// sortedKeys 返回映射的键列表（字典序），用于可复现的输出。
func sortedKeys(in map[string]any) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
