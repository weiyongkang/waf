package config

import (
	"bytes"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath 是未显式指定 -c 时尝试加载的默认配置文件路径。
//
// 之所以「存在才加载」：容器场景通常通过挂载该路径下发配置，
// 而本地开发与单元测试则直接使用内置默认值，避免为了跑起来必须先造一个文件。
const DefaultConfigPath = "/etc/waf/waf.yaml"

// Options 是配置加载的输入参数。
type Options struct {
	// ConfigFiles 是按顺序生效的配置文件路径列表（后者覆盖前者）。
	// 通常由 FlagSet.ConfigFiles() 提供。
	ConfigFiles []string
	// CLI 是已解析完成的 CLI 通道；为 nil 时跳过 CLI 叠加。
	CLI *FlagSet
	// LookupEnv 用于读取环境变量，为 nil 时使用 os.LookupEnv（测试可注入伪造实现）。
	LookupEnv func(string) (string, bool)
	// SkipDefaultConfigPath 为 true 时不尝试加载 DefaultConfigPath。
	SkipDefaultConfigPath bool
}

// Load 执行「内置默认值 -> 环境变量 -> 配置文件 -> CLI」的逐层叠加，
// 完成未知配置项检查与结构校验，返回最终生效配置与逐项来源。
//
// 优先级最终等价于 CLI > 配置文件 > 环境变量 > 内置默认值（需求 R16）。
func Load(opts Options) (*Resolved, error) {
	sch, err := buildSchema()
	if err != nil {
		return nil, err
	}

	tree, err := defaultTree()
	if err != nil {
		return nil, err
	}

	origins := make(map[string]Origin)

	// 第 1 层：环境变量（最低优先级，仅高于默认值）。
	envApplied, err := applyEnv(tree, sch, origins, opts.LookupEnv)
	if err != nil {
		return nil, err
	}
	_ = envApplied // 环境变量清单在 check-config 中通过来源摘要体现，此处无需额外保存。

	// 第 2 层：配置文件。读取上限取「已应用环境变量之后」的限额值，
	// 这样即便限额本身通过环境变量调整过，也能被正确采纳。
	files := opts.ConfigFiles
	if len(files) == 0 && !opts.SkipDefaultConfigPath {
		if _, statErr := os.Stat(DefaultConfigPath); statErr == nil {
			files = []string{DefaultConfigPath}
		}
	}
	limit := limitFromTree(tree, "limits.max_config_file_bytes", 1<<20)

	loadedFiles := make([]string, 0, len(files))
	for _, path := range files {
		fileTree, err := loadConfigFile(path, limit)
		if err != nil {
			return nil, err
		}

		var unknown []string
		collectUnknown("", fileTree, sch, &unknown)
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, fmt.Errorf(
				"配置文件 %s 存在未知配置项（来源：file）：%v", path, unknown,
			)
		}

		mergeTree(tree, fileTree, "", OriginFile, origins)
		loadedFiles = append(loadedFiles, path)
	}

	// 第 3 层：CLI（最高优先级）。
	if opts.CLI != nil {
		if err := opts.CLI.Apply(tree, origins); err != nil {
			return nil, err
		}
	}

	cfg, err := decodeConfig(tree)
	if err != nil {
		return nil, err
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}

	return &Resolved{
		Config:     cfg,
		Origins:    origins,
		Files:      loadedFiles,
		TotalItems: len(sch.leaves),
	}, nil
}

// defaultTree 把内置默认配置转换为通用配置树（map 形式），作为叠加的起点。
func defaultTree() (map[string]any, error) {
	raw, err := yaml.Marshal(Default())
	if err != nil {
		return nil, fmt.Errorf("内置默认配置无法序列化：%w", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("内置默认配置无法反序列化：%w", err)
	}
	return tree, nil
}

// decodeConfig 把叠加完成的配置树解码为强类型配置结构。
func decodeConfig(tree map[string]any) (*Config, error) {
	raw, err := yaml.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("生效配置无法序列化：%w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("生效配置无法解码（字段类型不匹配）：%w", err)
	}
	return cfg, nil
}

// limitFromTree 从配置树中按点分路径读取一个 int64 限额值。
//
// 之所以需要它：配置文件的读取上限本身就来自配置，必须在「文件尚未读取」时先取到该值。
func limitFromTree(tree map[string]any, path string, fallback int64) int64 {
	current := any(tree)
	for _, segment := range splitPath(path) {
		asMap, ok := current.(map[string]any)
		if !ok {
			return fallback
		}
		next, ok := asMap[segment]
		if !ok {
			return fallback
		}
		current = next
	}
	switch value := current.(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	default:
		return fallback
	}
}

// EncodeEffectiveConfig 把生效配置序列化为 YAML 文本，供 `check-config` 输出。
//
// 输出使用与示例配置一致的字段名与时长写法，便于与 configs/waf.example.yaml 对照。
func EncodeEffectiveConfig(cfg *Config) ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(cfg); err != nil {
		return nil, fmt.Errorf("生效配置无法编码：%w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("生效配置编码器关闭失败：%w", err)
	}
	return buf.Bytes(), nil
}
