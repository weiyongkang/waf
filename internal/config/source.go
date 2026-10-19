package config

import (
	"fmt"
	"sort"
	"strings"
)

// Origin 表示某个配置项的最终生效来源。
//
// 优先级由低到高为：Default < Env < File < CLI（需求 R16）。
type Origin string

const (
	// OriginDefault 表示该配置项未被任何通道覆盖，使用内置默认值。
	OriginDefault Origin = "default"
	// OriginEnv 表示该配置项来自环境变量。
	OriginEnv Origin = "env"
	// OriginFile 表示该配置项来自配置文件。
	OriginFile Origin = "file"
	// OriginCLI 表示该配置项来自命令行参数。
	OriginCLI Origin = "cli"
)

// 来源的数值化优先级，用于「后写的层只有在优先级不低于已记录来源时才覆盖来源标记」。
var originPriority = map[Origin]int{
	OriginDefault: 0,
	OriginEnv:     1,
	OriginFile:    2,
	OriginCLI:     3,
}

// Resolved 是配置加载的最终结果：生效配置 + 逐项来源 + 参与叠加的文件列表。
type Resolved struct {
	// Config 是完成三通道叠加与校验后的生效配置。
	Config *Config
	// Origins 记录「点分路径 -> 生效来源」，用于 `check-config` 的来源摘要。
	Origins map[string]Origin
	// Files 是按顺序参与叠加的配置文件列表（后者覆盖前者）。
	Files []string
	// ConfigInputs 是用户通过 -c 指定的原始路径列表（文件或目录），供配置目录监听使用。
	ConfigInputs []string
	// ConfigDirs 是 ConfigInputs 中属于目录的路径，只有这些目录会启用动态监听。
	ConfigDirs []string
	// TotalItems 是配置项总数（叶子路径数量），用于统计「使用内置默认值」的项数。
	TotalItems int
}

// OriginOf 返回指定点分路径的生效来源；未记录时视为默认值。
func (r *Resolved) OriginOf(path string) Origin {
	if r == nil || r.Origins == nil {
		return OriginDefault
	}
	if origin, ok := r.Origins[path]; ok {
		return origin
	}
	return OriginDefault
}

// Paths 返回全部已记录来源的配置路径，按字典序排列。
func (r *Resolved) Paths() []string {
	paths := make([]string, 0, len(r.Origins))
	for path := range r.Origins {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// SourceSummary 生成「配置项 -> 来源」的文本摘要。
//
// 输出形态（每个来源一段，段内按路径字典序）：
//
//	[cli]
//	  server.listen = :9081
//	[file] (configs/waf.yaml)
//	  pipeline
//	[env]
//	  logging.system.level
//	[default]
//	  ...（仅统计数量，避免刷屏）
//
// 之所以不逐项打印默认值：默认值数量庞大，逐项输出反而掩盖真正被覆盖的项。
func (r *Resolved) SourceSummary() string {
	countByOrigin := make(map[Origin][]string)
	for _, path := range r.Paths() {
		origin := r.OriginOf(path)
		countByOrigin[origin] = append(countByOrigin[origin], path)
	}

	var b strings.Builder
	// 按优先级从高到低输出，便于运维快速确认「我改的到底生效没有」。
	for _, origin := range []Origin{OriginCLI, OriginFile, OriginEnv} {
		paths := countByOrigin[origin]
		if len(paths) == 0 {
			continue
		}
		if origin == OriginFile && len(r.Files) > 0 {
			fmt.Fprintf(&b, "[file] (%s)\n", strings.Join(r.Files, ", "))
		} else {
			fmt.Fprintf(&b, "[%s]\n", origin)
		}
		for _, path := range paths {
			fmt.Fprintf(&b, "  %s\n", path)
		}
	}

	// 默认值数量庞大，只统计数量，避免逐项输出掩盖真正被覆盖的配置项。
	if defaultCount := r.TotalItems - len(r.Origins); defaultCount > 0 {
		fmt.Fprintf(&b, "[default]\n  其余 %d 项使用内置默认值\n", defaultCount)
	}
	return b.String()
}
