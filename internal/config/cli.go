package config

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// stringList 是支持重复出现的字符串参数值，例如 -c a.yaml -c b.yaml。
type stringList []string

// String 返回以逗号连接的字符串表示，用于 flag 包的帮助输出。
func (s *stringList) String() string { return strings.Join(*s, ",") }

// Set 追加一个值，使该参数可以重复出现。
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// FlagSet 是配置的 CLI 通道。
//
// 设计要点：全部「标量配置项」都会被机械注册为一个同名参数
// （ban.default_ttl -> --ban-default-ttl），从而保证 CLI 与配置路径一一对应；
// 只有被显式传入的参数才会覆盖配置，未传入的参数保持低优先级通道的值。
type FlagSet struct {
	// fs 是底层标准库参数集合。
	fs *flag.FlagSet
	// sch 是配置 schema，用于路径推导与类型转换。
	sch *schema
	// values 保存「配置路径 -> 参数值指针」，供 Parse 后读取原始字符串。
	values map[string]*string
	// overrides 保存「配置路径 -> 原始字符串」，仅包含显式传入的参数。
	overrides map[string]string
	// generic 保存 --set 的原始表达式列表（形如 a.b=c）。
	generic stringList
	// configFiles 保存 -c / --config 指定的配置文件列表（可多次指定，后者覆盖前者）。
	configFiles stringList
	// cliSource 记录每个覆盖项是由哪个参数产生的，用于错误信息。
	cliSource map[string]string
}

// NewFlagSet 构造配置参数集合，并注册全部标量配置项对应的参数。
func NewFlagSet(name string, output io.Writer) (*FlagSet, error) {
	sch, err := buildSchema()
	if err != nil {
		return nil, err
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(output)

	cf := &FlagSet{
		fs:          fs,
		sch:         sch,
		values:      make(map[string]*string, len(sch.scalars)),
		overrides:   make(map[string]string),
		cliSource:   make(map[string]string),
		configFiles: nil,
	}

	// 注册配置文件参数：可多次指定，后者覆盖前者。
	fs.Var(&cf.configFiles, "config", "配置文件或目录路径，可多次指定（后者覆盖前者；目录按文件名字典序加载并热重载）")
	fs.Var(&cf.configFiles, "c", "配置文件或目录路径（-config 的简写），可多次指定")

	// 注册通用覆盖参数：用于表达「配置路径 -> 值」，作为所有标量项的逃生通道。
	fs.Var(&cf.generic, "set", "按路径覆盖配置项，格式 路径=值，可多次指定（例如 --set server.listen=:9081）")

	// 机械注册全部标量配置项参数。
	for path := range sch.scalars {
		flagName := sch.pathToFlag[path]
		value := new(string)
		cf.values[path] = value
		fs.StringVar(value, flagName, "", flagUsage(path, sch.scalars[path]))
	}

	return cf, nil
}

// flagUsage 生成参数帮助文本，包含配置路径与默认值，便于运维反查。
func flagUsage(path string, defaultValue any) string {
	return fmt.Sprintf("配置项 %s（默认 %v）", path, defaultValue)
}

// Parse 解析参数列表，并收集所有被显式设置的覆盖项。
func (f *FlagSet) Parse(args []string) error {
	if err := f.fs.Parse(args); err != nil {
		return err
	}

	// 收集显式设置的具名参数。
	f.fs.Visit(func(fl *flag.Flag) {
		path, ok := f.sch.flagNames[fl.Name]
		if !ok {
			// -config / -c / -set 由后续逻辑单独处理。
			return
		}
		if ptr, ok := f.values[path]; ok && ptr != nil {
			f.overrides[path] = *ptr
			f.cliSource[path] = "--" + fl.Name
		}
	})

	// 处理通用覆盖表达式。
	for _, expr := range f.generic {
		path, value, err := splitAssignment(expr)
		if err != nil {
			return err
		}
		if _, ok := f.sch.scalars[path]; !ok {
			if _, known := f.sch.known[path]; known {
				return fmt.Errorf("--set %s 不可用：该配置项不是标量（数组或映射只能写在配置文件中）", path)
			}
			return fmt.Errorf("--set %s 不可用：配置项不存在", path)
		}
		f.overrides[path] = value
		f.cliSource[path] = "--set " + expr
	}

	return nil
}

// splitAssignment 解析 "路径=值" 形式的通用覆盖表达式。
func splitAssignment(expr string) (path string, value string, err error) {
	index := strings.Index(expr, "=")
	if index <= 0 {
		return "", "", fmt.Errorf("--set 表达式 %q 非法，正确格式为 路径=值（例如 server.listen=:9081）", expr)
	}
	path = strings.TrimSpace(expr[:index])
	if path == "" {
		return "", "", fmt.Errorf("--set 表达式 %q 的配置路径为空", expr)
	}
	return path, expr[index+1:], nil
}

// IsConfigFlag 判断给定参数名（不含前导短横线）是否属于「配置体系」。
//
// 之所以需要该判断：运维子命令（例如 waf ban）同时接受自己的业务参数
// （--ip / --ttl）与全局配置参数（-c / --set / 任一标量配置项）。
// 标准库 flag 遇到未定义的参数会直接报错，因此调用方必须在解析之前
// 先把两类参数分开：配置体系参数交给本 FlagSet，业务参数交给各自的参数集合。
func (f *FlagSet) IsConfigFlag(name string) bool {
	if name == "" {
		return false
	}
	switch name {
	case "c", "config", "set":
		return true
	}
	_, ok := f.sch.flagNames[name]
	return ok
}

// ConfigFiles 返回按顺序生效的配置文件路径列表。
func (f *FlagSet) ConfigFiles() []string {
	return append([]string(nil), f.configFiles...)
}

// HasOverrides 判断是否存在任何显式覆盖项。
func (f *FlagSet) HasOverrides() bool {
	return len(f.overrides) > 0
}

// OverridePaths 返回全部显式覆盖的配置路径（字典序），用于日志记录。
func (f *FlagSet) OverridePaths() []string {
	paths := make([]string, 0, len(f.overrides))
	for path := range f.overrides {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// Apply 把 CLI 覆盖项写入配置树并记录来源。
//
// 该函数必须最后调用（优先级最高，需求 R16）。
func (f *FlagSet) Apply(tree map[string]any, origins map[string]Origin) error {
	for _, path := range f.OverridePaths() {
		raw := f.overrides[path]
		value, err := coerceValue(f.sch.scalars[path], raw)
		if err != nil {
			return fmt.Errorf("参数 %s 的值 %q 非法：%w（配置项 %s）", f.cliSource[path], raw, err, path)
		}
		if err := setLeaf(tree, path, value); err != nil {
			return fmt.Errorf("参数 %s 无法写入配置路径 %s：%w", f.cliSource[path], path, err)
		}
		markOrigin(origins, path, OriginCLI)
	}
	return nil
}

// FlagNameFor 返回指定配置路径对应的 CLI 参数名，便于文档与提示信息引用。
func (f *FlagSet) FlagNameFor(path string) (string, bool) {
	name, ok := f.sch.pathToFlag[path]
	return name, ok
}

// ScalaPaths 返回全部可被 CLI 覆盖的配置路径（字典序）。
//
// 供测试与文档生成使用，保证「文档中列出的可覆盖项」与实现保持一致。
func (f *FlagSet) ScalaPaths() []string {
	paths := make([]string, 0, len(f.sch.scalars))
	for path := range f.sch.scalars {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
