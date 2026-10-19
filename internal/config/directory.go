package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// supportedConfigExtensions 是配置目录中会被自动加载的文件扩展名。
//
// 直接指定的单个文件仍按 YAML 解析（不受此限制），以兼容历史配置；
// 目录模式只挑选明确的配置文件，避免把备份、编辑器临时文件或说明文档误当成配置。
var supportedConfigExtensions = map[string]struct{}{
	".yaml": {},
	".yml":  {},
	".json": {},
}

// expandConfigInputs 展开 -c 指定的配置文件与目录。
//
// 规则：
//   - 文件保持原顺序直接加入；
//   - 目录中的配置文件按文件名字典序加入；
//   - 只接受 .yaml/.yml/.json，跳过子目录、隐藏文件与常见备份/临时文件；
//   - 目录中没有任何可加载文件时直接报错，避免「以为加载了目录，实际使用默认值」。
//
// 返回的第二个值是显式配置目录列表，供运行期目录监听使用。
func expandConfigInputs(inputs []string) ([]string, []string, error) {
	var files []string
	var dirs []string

	for _, input := range inputs {
		path := strings.TrimSpace(input)
		if path == "" {
			return nil, nil, fmt.Errorf("配置文件路径不能为空")
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, nil, fmt.Errorf("配置路径 %s 无法访问：%w", path, err)
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}

		dirFiles, err := configFilesInDir(path)
		if err != nil {
			return nil, nil, err
		}
		if len(dirFiles) == 0 {
			return nil, nil, fmt.Errorf(
				"配置目录 %s 中没有可加载的配置文件（支持 .yaml/.yml/.json）", path,
			)
		}
		files = append(files, dirFiles...)
		dirs = append(dirs, path)
	}

	return files, dirs, nil
}

// configFilesInDir 返回目录中按文件名字典序排列的配置文件绝对/相对路径。
//
// 这里不要求目录非空：监听指纹需要把「目录变空」也视为一次变化，
// 而真正的加载入口会在 expandConfigInputs 中拒绝空目录。
func configFilesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("配置目录 %s 读取失败：%w", dir, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isConfigFileName(entry.Name()) {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	return files, nil
}

// isConfigFileName 判断目录中的文件是否应参与配置合并。
func isConfigFileName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "#") || strings.HasSuffix(name, "~") {
		return false
	}
	_, ok := supportedConfigExtensions[strings.ToLower(filepath.Ext(name))]
	return ok
}
