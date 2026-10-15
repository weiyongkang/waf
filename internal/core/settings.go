package core

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// DecodeSettings 把插件实例的通用配置片段（配置文件中该实例的 settings 节点）
// 解码为插件自定义的强类型结构体。
//
// 解码采用「严格模式」：出现结构体中不存在的字段会直接报错。
// 这样做是为了避免拼写错误的配置项被静默忽略——这类问题在安全产品上
// 往往表现为「以为开了防护，其实没开」，必须 fail fast。
//
// 用法：
//
//	var cfg struct {
//	    Store string        `yaml:"store"`
//	    TTL   core.Duration `yaml:"ttl"`
//	}
//	if err := core.DecodeSettings(inst.Settings, &cfg); err != nil { ... }
func DecodeSettings(settings map[string]any, out any) error {
	if out == nil {
		return errors.New("DecodeSettings 的目标参数不能为 nil")
	}
	if len(settings) == 0 {
		return nil
	}

	raw, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("插件配置片段无法序列化：%w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("插件配置片段解析失败（请检查字段名与类型）：%w", err)
	}
	return nil
}
