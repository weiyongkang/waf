package config

import (
	"fmt"
	"os"
	"strconv"
)

// applyEnv 按 schema 逐个检查环境变量，把命中的项写入配置树并记录来源。
//
// 之所以「按 schema 正查」而不是「遍历 os.Environ 反查」：
//   - 正查可以精确识别配置路径，避免单下划线推导带来的歧义；
//   - 反查还需要额外过滤系统中无关的 WAF_ 前缀变量，容易误伤。
//
// 返回值是本次实际生效的环境变量名列表（按配置路径字典序），用于启动日志与来源摘要。
func applyEnv(tree map[string]any, sch *schema, origins map[string]Origin, lookup func(string) (string, bool)) ([]string, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	applied := make([]string, 0, len(sch.scalars))
	for path, defaultValue := range sch.scalars {
		envName := "WAF_" + upperSnake(path)
		raw, ok := lookup(envName)
		if !ok {
			continue
		}

		value, err := coerceValue(defaultValue, raw)
		if err != nil {
			return nil, fmt.Errorf("环境变量 %s 的值 %q 非法：%w（配置项 %s）", envName, raw, err, path)
		}
		if err := setLeaf(tree, path, value); err != nil {
			return nil, fmt.Errorf("环境变量 %s 无法写入配置路径 %s：%w", envName, path, err)
		}
		markOrigin(origins, path, OriginEnv)
		applied = append(applied, envName)
	}
	return applied, nil
}

// coerceValue 把字符串形式的覆盖值转换为默认值所属的类型。
//
// 之所以以「默认值的类型」为基准：环境变量与 CLI 只能传入字符串，
// 而配置项的期望类型由默认配置唯一确定（例如 logging.system.level 是 string，
// ingress.body.max_bytes 是 int），据此转换可以同时完成类型推断与格式校验。
func coerceValue(defaultValue any, raw string) (any, error) {
	switch defaultValue.(type) {
	case nil:
		// 默认值为 nil 时无法推断类型，按字符串处理。
		return raw, nil
	case string:
		return raw, nil
	case bool:
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("期望布尔值（true/false）")
		}
		return parsed, nil
	case int:
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("期望整数")
		}
		return parsed, nil
	case int64:
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("期望 64 位整数")
		}
		return parsed, nil
	case float64:
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("期望浮点数")
		}
		return parsed, nil
	default:
		// 数组等非标量叶子不会进入该分支（schema 已排除）。
		return raw, nil
	}
}

// upperSnake 把点分路径转换为环境变量片段，例如 ban.default_ttl -> BAN_DEFAULT_TTL。
func upperSnake(path string) string {
	out := make([]byte, 0, len(path))
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '.':
			out = append(out, '_')
		case '-':
			// 配置键中的连字符统一转换为下划线，保证环境变量名合法。
			out = append(out, '_')
		default:
			c := path[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			out = append(out, c)
		}
	}
	return string(out)
}
