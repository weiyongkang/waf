package config

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// loadConfigFile 读取并解析单个 YAML 配置文件。
//
// 安全约束（需求 R13）：
//   - 读取前先用 os.Stat 检查文件大小，超过 maxBytes 直接拒绝，绝不整体读入内存；
//   - 读取时使用 io.LimitReader 兜底，防止「检查后文件被替换」的竞态；
//   - 解析结果必须是映射（键值对），数组或标量作为根节点一律视为格式错误。
func loadConfigFile(path string, maxBytes int64) (map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("配置文件 %s 无法访问：%w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("配置文件 %s 是目录，不是文件", path)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf(
			"配置文件 %s 大小 %d 字节，超过 limits.max_config_file_bytes=%d 字节上限",
			path, info.Size(), maxBytes,
		)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("配置文件 %s 打开失败：%w", path, err)
	}
	defer func() {
		// 关闭失败不影响配置内容本身，但需要忽略返回值以满足 lint 要求。
		_ = file.Close()
	}()

	limit := maxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("配置文件 %s 读取失败：%w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf(
			"配置文件 %s 实际读取字节数超过 limits.max_config_file_bytes=%d 上限", path, limit,
		)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("配置文件 %s 内容为空", path)
	}

	var tree map[string]any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("配置文件 %s 解析失败（YAML 格式错误）：%w", path, err)
	}
	if tree == nil {
		return nil, fmt.Errorf("配置文件 %s 的顶层必须是键值对（映射）", path)
	}
	return tree, nil
}
