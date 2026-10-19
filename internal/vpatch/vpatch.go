// Package vpatch 提供内置 CVE 虚拟补丁模板与自定义补丁文件加载。
//
// 设计边界：虚拟补丁最终编译为 Coraza SecLang 规则，与 CRS 共用同一事务、
// 评分与日志链路；不在插件层另造一套正则匹配引擎。
package vpatch

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Template 是一条虚拟补丁模板。
type Template struct {
	// ID 是配置中使用的稳定标识。
	ID string
	// CVE 是关联的 CVE 编号（可为空）。
	CVE string
	// Name 是补丁名称。
	Name string
	// Description 是补丁用途说明。
	Description string
	// Directives 是编译后追加给 Coraza 的 SecLang 指令。
	Directives []string
}

// Resolved 是实际启用的补丁。
type Resolved struct {
	ID         string
	CVE        string
	Name       string
	Source     string
	Directives []string
}

// Builtins 返回全部内置模板（按 ID 排序）。
func Builtins() []Template {
	templates := []Template{
		{
			ID: "cve-2021-44228", CVE: "CVE-2021-44228", Name: "Log4Shell JNDI lookup",
			Description: "阻断请求头、参数、URI 与请求体中的 ${jndi:...} 注入",
			Directives: []string{
				`SecRule REQUEST_HEADERS|REQUEST_URI|ARGS|REQUEST_BODY "@rx (?i)\$\{jndi:(?:ldaps?|rmi|dns|nis|iiop|corba|nds|http)s?:" "id:9101001,phase:2,deny,status:403,log,msg:'Virtual patch CVE-2021-44228 Log4Shell JNDI lookup'"`,
			},
		},
		{
			ID: "cve-2022-22965", CVE: "CVE-2022-22965", Name: "Spring4Shell classLoader access",
			Description: "阻断 Spring MVC 参数绑定中的 class.module.classLoader 链",
			Directives: []string{
				`SecRule ARGS|REQUEST_BODY "@rx (?i)class\.module\.classLoader\." "id:9101002,phase:2,deny,status:403,log,msg:'Virtual patch CVE-2022-22965 Spring4Shell classLoader access'"`,
			},
		},
		{
			ID: "cve-2021-41773", CVE: "CVE-2021-41773", Name: "Apache path traversal",
			Description: "阻断 Apache HTTP Server 路径穿越变体",
			Directives: []string{
				`SecRule REQUEST_URI "@rx (?i)(?:\.\./|%2e%2e%2f|%2e%2e/|\.\.%2f)" "id:9101003,phase:1,deny,status:403,log,msg:'Virtual patch CVE-2021-41773 path traversal'"`,
			},
		},
		{
			ID: "cve-2024-3400", CVE: "CVE-2024-3400", Name: "PAN-OS command injection",
			Description: "阻断 GlobalProtect SESSID Cookie 中的命令注入特征",
			Directives: []string{
				`SecRule REQUEST_COOKIES:SESSID "@rx (?i)(?:;|\||` + "`" + `|\$\(|\$\{|\n).*(?:id|whoami|curl|wget|bash|sh|python|perl)" "id:9101004,phase:1,deny,status:403,log,msg:'Virtual patch CVE-2024-3400 PAN-OS command injection'"`,
			},
		},
	}
	sort.SliceStable(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates
}

// Options 是补丁解析参数。
type Options struct {
	// Names 是启用的内置模板 ID 或 CVE 编号。
	Names []string
	// Files 是自定义 SecLang 补丁文件。
	Files []string
	// MaxFileBytes 是单个自定义补丁文件大小上限。
	MaxFileBytes int64
}

// Resolve 解析并加载启用的补丁。
func Resolve(opts Options) ([]Resolved, error) {
	byID := make(map[string]Template)
	for _, template := range Builtins() {
		byID[template.ID] = template
		if template.CVE != "" {
			byID[strings.ToLower(template.CVE)] = template
		}
	}

	resolved := make([]Resolved, 0, len(opts.Names)+len(opts.Files))
	seen := make(map[string]struct{})
	for _, name := range opts.Names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		template, ok := byID[key]
		if !ok {
			return nil, fmt.Errorf("未知虚拟补丁模板 %q（可用：%s）", name, builtinIDs())
		}
		if _, dup := seen[template.ID]; dup {
			continue
		}
		seen[template.ID] = struct{}{}
		resolved = append(resolved, Resolved{
			ID: template.ID, CVE: template.CVE, Name: template.Name,
			Source: "builtin", Directives: append([]string(nil), template.Directives...),
		})
	}

	for _, file := range opts.Files {
		trimmed := strings.TrimSpace(file)
		if trimmed == "" {
			continue
		}
		info, err := os.Stat(trimmed)
		if err != nil {
			return nil, fmt.Errorf("虚拟补丁文件 %s 不可访问：%w", trimmed, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("虚拟补丁文件 %s 是目录，必须指向 .conf 文件", trimmed)
		}
		if opts.MaxFileBytes > 0 && info.Size() > opts.MaxFileBytes {
			return nil, fmt.Errorf("虚拟补丁文件 %s 大小 %d 超过 limits.max_rule_file_bytes=%d", trimmed, info.Size(), opts.MaxFileBytes)
		}
		content, err := os.ReadFile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("读取虚拟补丁文件 %s 失败：%w", trimmed, err)
		}
		directives := splitDirectives(string(content))
		if len(directives) == 0 {
			return nil, fmt.Errorf("虚拟补丁文件 %s 没有有效指令", trimmed)
		}
		id := strings.TrimSuffix(filepath.Base(trimmed), filepath.Ext(trimmed))
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("虚拟补丁标识 %q 重复", id)
		}
		seen[id] = struct{}{}
		resolved = append(resolved, Resolved{
			ID: id, Name: id, Source: trimmed, Directives: directives,
		})
	}
	return resolved, nil
}

// Directives 把已解析补丁展开为单个指令列表。
func Directives(patches []Resolved) []string {
	var directives []string
	for _, patch := range patches {
		directives = append(directives, patch.Directives...)
	}
	return directives
}

// Known 判断名称是否为内置模板 ID 或 CVE 编号。
func Known(name string) bool {
	key := strings.ToLower(strings.TrimSpace(name))
	for _, template := range Builtins() {
		if key == template.ID || key == strings.ToLower(template.CVE) {
			return true
		}
	}
	return false
}

func builtinIDs() string {
	names := make([]string, 0)
	for _, template := range Builtins() {
		names = append(names, template.ID)
	}
	return strings.Join(names, " / ")
}

func splitDirectives(content string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}
