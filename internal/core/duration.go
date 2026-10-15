package core

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration 是带 YAML/JSON 反序列化能力的时长类型。
//
// 之所以不直接使用 time.Duration：go-yaml 会把 "30m" 这样的字符串按整数解析，
// 导致配置写成人类可读时长后报类型错误。本类型统一承载 "300ms" / "30s" / "5m" / "24h"
// 这类写法，并保持与 time.Duration 的零成本转换。
type Duration time.Duration

// Duration 返回标准库时长类型，便于直接参与 time 包运算。
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// String 返回时长的人类可读表示，例如 "30m0s"。
func (d Duration) String() string {
	return time.Duration(d).String()
}

// IsZero 判断时长是否为零值，用于「未配置即使用默认值」的判断。
func (d Duration) IsZero() bool {
	return time.Duration(d) == 0
}

// UnmarshalYAML 实现 yaml.v3 的自定义反序列化。
//
// 支持两种写法：
//   - 字符串时长，例如 "300ms" / "30s" / "5m" / "24h"（内部使用 time.ParseDuration）；
//   - 裸整数，按纳秒解释，仅用于兼容程序化生成的配置。
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := parseDurationNode(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML 实现 yaml.v3 的自定义序列化，统一输出字符串时长，
// 保证 `check-config` 打印的生效配置与示例配置风格一致。
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// parseDurationNode 解析 YAML 节点为 time.Duration，供 UnmarshalYAML 复用。
func parseDurationNode(value *yaml.Node) (time.Duration, error) {
	switch value.Tag {
	case "!!int":
		var n int64
		if err := value.Decode(&n); err != nil {
			return 0, fmt.Errorf("时长字段无法按整数解析：%w", err)
		}
		return time.Duration(n), nil
	default:
		var s string
		if err := value.Decode(&s); err != nil {
			return 0, fmt.Errorf("时长字段必须是字符串（如 \"30m\"）：%w", err)
		}
		if s == "" {
			return 0, nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("时长格式非法 %q，示例：\"300ms\" / \"30s\" / \"5m\" / \"24h\"", s)
		}
		return parsed, nil
	}
}
