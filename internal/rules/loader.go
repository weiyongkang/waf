// Package rules 负责检测引擎规则集（CRS + 自定义规则）的加载、限额校验与来源解析。
//
// 设计要点：
//
//  1. 离线打包（需求 R10 / R14）：CRS 规则以 go:embed 的方式编入二进制，
//     运行期不依赖任何外部规则目录，因此 distroless 镜像里只有一个可执行文件。
//
//  2. 限额真实生效（需求 R13）：所有规则内容都经由「带上限的读取」载入内存，
//     单文件超限直接拒绝加载、总量超限直接失败，绝不把大文件整个读进内存。
//     之所以先读进内存再交给 Coraza，而不是让 Coraza 直接读 fs：
//     只有自己读取才能对单文件与总量做硬性限制（Coraza 内部读取不受我们控制）。
//
//  3. 来源可切换（需求 R5 / R6）：engine.rules.dirs 为空时使用内置规则集，
//     非空时完全改用磁盘目录，custom_dirs 可追加自定义规则，
//     因此「内置 CRS / 自带规则 / 混合」都可以纯配置切换，无需改代码。
package rules

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"sort"
	"strings"
)

// embeddedCRSDir 是内置 CRS 规则在本包目录中的位置。
const embeddedCRSDir = "crs"

//go:embed crs
var embedded embed.FS

// embeddedCRS 是内置 CRS 规则集的只读文件系统，根目录即规则根。
var embeddedCRS fs.FS

// embeddedSourceLabel 是内置规则来源的可读名。
const embeddedSourceLabel = "内置嵌入 CRS"

// 默认文件匹配模式。
var (
	// defaultIncludePatterns 是规则文件的默认匹配模式。
	defaultIncludePatterns = []string{"*.conf"}
	// defaultDataPatterns 是规则所引用数据文件的默认匹配模式。
	defaultDataPatterns = []string{"*.data"}
)

func init() {
	sub, err := fs.Sub(embedded, embeddedCRSDir)
	if err != nil {
		// go:embed 的目录必然存在，此处失败只可能是构建期问题，属于不可恢复错误。
		panic("rules: 无法定位内置 CRS 规则目录：" + err.Error())
	}
	embeddedCRS = sub
}

// Source 描述规则集的来源。
type Source struct {
	// Dirs 是主规则目录列表；为空表示使用内置（编译期嵌入）的 CRS 规则集。
	Dirs []string
	// CustomDirs 是追加的自定义规则目录，在主规则集之后加载。
	CustomDirs []string
	// Include 是目录内的文件匹配模式；为空时取 ["*.conf"]。
	Include []string
	// DataInclude 是「规则引用的数据文件」匹配模式；为空时取 ["*.data"]。
	//
	// 这些文件只被载入规则文件系统（供 @pmFromFile 这类算子按相对路径读取），
	// 不会被 Include：它们不是 SecLang 规则，按规则解析会直接报错。
	DataInclude []string
	// CRSSetup 是 CRS 设置文件名；为空时表示不使用设置文件。
	CRSSetup string
}

// Set 是加载完成的规则集。
type Set struct {
	// FS 是只读规则文件系统，包含全部规则与数据文件（键为不含目录的基名）。
	FS fs.FS
	// Setup 是 CRS 设置文件在 FS 中的路径；为空表示没有设置文件。
	Setup string
	// Files 是规则文件在 FS 中的路径，已按字典序排序（确定性加载顺序）。
	Files []string
	// Source 是来源描述，用于启动日志。
	Source string
	// FileCount 是加载的规则文件数量（含设置文件）。
	FileCount int
	// Rules 是实际交给引擎解析的规则文件数量（不含设置文件与数据文件）。
	Rules int
	// TotalBytes 是加载的规则内容总字节数。
	TotalBytes int64
}

// Options 是加载参数。
type Options struct {
	// Source 是规则来源描述。
	Source Source
	// MaxFileBytes 是单个规则文件大小上限（字节）；必须大于 0。
	MaxFileBytes int64
	// MaxTotalBytes 是规则集总量上限（字节）；必须大于 0。
	MaxTotalBytes int64
	// Logger 是系统日志器，可为 nil。
	Logger *slog.Logger
}

// ruleFile 是已读取到内存的单个规则文件。
type ruleFile struct {
	// content 是文件内容。
	content []byte
	// origin 是来源描述，用于重名冲突时的报错。
	origin string
}

// Load 依据来源描述加载规则集，并逐项校验大小限额。
func Load(opts Options) (*Set, error) {
	if opts.MaxFileBytes <= 0 {
		return nil, errors.New("规则加载需要正数的 max_file_bytes（禁止把限额设为 0 或负数）")
	}
	if opts.MaxTotalBytes <= 0 {
		return nil, errors.New("规则加载需要正数的 max_total_bytes（禁止把限额设为 0 或负数）")
	}

	include := normaliseInclude(opts.Source.Include)
	dataInclude := normalisePatterns(opts.Source.DataInclude, defaultDataPatterns)

	groups, err := sourceGroups(opts.Source)
	if err != nil {
		return nil, err
	}

	collected := make(map[string]ruleFile)
	var totalBytes int64
	var sourceLabels []string
	ruleFiles := make(map[string]struct{})

	for _, group := range groups {
		names, err := globRuleFiles(group.fsys, union(include, dataInclude))
		if err != nil {
			return nil, fmt.Errorf("扫描规则目录 %s 失败：%w", group.label, err)
		}
		if len(names) == 0 {
			continue
		}
		sourceLabels = append(sourceLabels, group.label)

		// 单独算出「哪些文件是规则文件」：数据文件同样要载入文件系统，
		// 但只有规则文件才会被 Include 交给 SecLang 解析。
		patternFiles, err := globRuleFiles(group.fsys, include)
		if err != nil {
			return nil, fmt.Errorf("扫描规则目录 %s 失败：%w", group.label, err)
		}
		for _, name := range patternFiles {
			ruleFiles[name] = struct{}{}
		}

		for _, name := range names {
			content, err := readLimited(group.fsys, name, opts.MaxFileBytes)
			if err != nil {
				return nil, fmt.Errorf("读取规则文件 %s（来源：%s）失败：%w", name, group.label, err)
			}

			base := path.Base(name)
			if previous, exists := collected[base]; exists {
				return nil, fmt.Errorf(
					"规则文件重名：%s 同时来自 %s 与 %s；请重命名其中一份（重名会让加载结果依赖扫描顺序）",
					base, previous.origin, group.label,
				)
			}

			totalBytes += int64(len(content))
			if totalBytes > opts.MaxTotalBytes {
				return nil, fmt.Errorf(
					"规则集总量超过上限 %d 字节（已加载到 %s 时超限）；请调整 limits.max_rules_total_bytes",
					opts.MaxTotalBytes, base,
				)
			}

			collected[base] = ruleFile{content: content, origin: group.label}
		}
	}

	setup := ""
	if name := strings.TrimSpace(opts.Source.CRSSetup); name != "" {
		base := path.Base(name)
		if _, exists := collected[base]; !exists {
			return nil, fmt.Errorf("配置的 CRS 设置文件 %s 不存在（已加载文件：%d 个）", base, len(collected))
		}
		setup = base
	}

	files := make([]string, 0, len(collected)-len(setup))
	for name := range collected {
		if name == setup {
			continue
		}
		if _, isRule := ruleFiles[name]; !isRule {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	if len(files) == 0 {
		if len(collected) == 0 {
			return nil, fmt.Errorf(
				"规则集为空（来源：%s；规则匹配模式：%v）；检测引擎将无法拦截任何请求，请检查 engine.rules 配置",
				strings.Join(sourceLabels, "、"), include,
			)
		}
		return nil, fmt.Errorf(
			"规则集不含任何规则文件（来源：%s；规则匹配模式：%v；已加载的其它文件：%d 个）；请检查 engine.rules.include 配置",
			strings.Join(sourceLabels, "、"), include, len(collected),
		)
	}

	label := strings.Join(sourceLabels, "、")
	if label == "" {
		label = "未知来源"
	}

	set := &Set{
		FS:         newMemFS(collected),
		Setup:      setup,
		Files:      files,
		Source:     label,
		FileCount:  len(collected),
		Rules:      len(files),
		TotalBytes: totalBytes,
	}

	if opts.Logger != nil {
		opts.Logger.Info("检测引擎规则集已加载",
			"source", set.Source,
			"files", set.FileCount,
			"rules", set.Rules,
			"total_bytes", set.TotalBytes,
			"setup", set.Setup,
			"includes", include,
			"data_includes", dataInclude,
		)
	}
	return set, nil
}

// sourceGroup 是一个待扫描的规则来源。
type sourceGroup struct {
	// label 是来源的可读名，用于日志与报错。
	label string
	// fsys 是该来源的只读文件系统。
	fsys fs.FS
}

// sourceGroups 把来源描述展开为「文件系统 + 可读名」列表。
//
// 顺序即加载顺序：主规则集在前、自定义规则集在后，
// 保证自定义规则（例如 SecRuleUpdateTargetById）能覆盖主规则集中的规则。
func sourceGroups(source Source) ([]sourceGroup, error) {
	var groups []sourceGroup

	if len(source.Dirs) == 0 {
		groups = append(groups, sourceGroup{label: embeddedSourceLabel, fsys: embeddedCRS})
	} else {
		for _, dir := range source.Dirs {
			group, err := dirGroup(dir)
			if err != nil {
				return nil, err
			}
			groups = append(groups, group)
		}
	}

	for _, dir := range source.CustomDirs {
		group, err := dirGroup(dir)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// dirGroup 把一个磁盘目录转换为规则来源。
func dirGroup(dir string) (sourceGroup, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return sourceGroup{}, errors.New("规则目录不能为空字符串")
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return sourceGroup{}, fmt.Errorf("规则目录 %s 不可访问：%w", trimmed, err)
	}
	if !info.IsDir() {
		return sourceGroup{}, fmt.Errorf("规则路径 %s 不是目录", trimmed)
	}
	return sourceGroup{label: trimmed, fsys: os.DirFS(trimmed)}, nil
}

// normaliseInclude 归一化文件匹配模式。
// normalisePatterns 归一化文件匹配模式；全部为空时回退到 fallback。
func normalisePatterns(input []string, fallback []string) []string {
	patterns := make([]string, 0, len(input))
	for _, pattern := range input {
		if trimmed := strings.TrimSpace(pattern); trimmed != "" {
			patterns = append(patterns, trimmed)
		}
	}
	if len(patterns) == 0 {
		return append([]string(nil), fallback...)
	}
	return patterns
}

// normaliseInclude 归一化规则文件匹配模式。
func normaliseInclude(include []string) []string {
	return normalisePatterns(include, defaultIncludePatterns)
}

// union 合并两组模式并去重，保持先后顺序。
func union(first, second []string) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	merged := make([]string, 0, len(first)+len(second))
	for _, group := range [][]string{first, second} {
		for _, pattern := range group {
			if _, exists := seen[pattern]; exists {
				continue
			}
			seen[pattern] = struct{}{}
			merged = append(merged, pattern)
		}
	}
	return merged
}

// globRuleFiles 按多个模式在同一个文件系统内收集规则文件，结果去重并按字典序排序。
func globRuleFiles(fsys fs.FS, patterns []string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := fs.Glob(fsys, pattern)
		if err != nil {
			return nil, fmt.Errorf("匹配模式 %q 非法：%w", pattern, err)
		}
		for _, match := range matches {
			info, err := fs.Stat(fsys, match)
			if err != nil {
				return nil, fmt.Errorf("读取 %s 的元信息失败：%w", match, err)
			}
			if info.IsDir() {
				continue
			}
			seen[match] = struct{}{}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// readLimited 读取文件内容，并在超过单文件上限时拒绝。
//
// 之所以多读 1 个字节：只有这样才能区分「恰好等于上限」与「超过上限」，
// 否则恰好超限一个字节的文件会被当成合法文件放行。
func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf(
			"文件大小超过单文件上限 %d 字节，已拒绝加载（请调整 limits.max_rule_file_bytes）", limit,
		)
	}
	return content, nil
}
