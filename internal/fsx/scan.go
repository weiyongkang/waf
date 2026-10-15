// Package fsx 提供「受限额约束」的文件读取工具（需求 R13）。
//
// 为什么需要它：本项目多处需要读取外部文件（威胁情报、IP 黑名单、规则文件），
// 这些文件都属于「外部输入」，既可能被误编辑成超大文件，也可能被投毒成畸形内容。
// 统一在此约束「最大字节数」与「单行长度」，避免各插件各写一套、
// 更避免出现「一次性读入整个文件」的写法（R13 明确禁止大体积读取）。
//
// 本包只做读取与限额，不解析内容语义。
package fsx

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// defaultMaxLineBytes 是单行长度的默认上限（字节）。
//
// 之所以需要单行上限：文件总大小受限不代表单行受限，
// 一行几百 MB 的内容同样会把内存打爆（bufio.Scanner 的 token 上限正是为此设计）。
const defaultMaxLineBytes = 64 * 1024

// startBufferBytes 是逐行扫描的初始缓冲区大小（字节）。
//
// 取值 4KB 的理由：绝大多数名单文件的行都很短，从 4KB 起步可以让常见文件
// 只分配一次缓冲；同时它远小于默认的 64KB 单行上限，
// 保证 bufio.Scanner 的「超长行」判定能够按配置真实生效（见 ScanLines 内注释）。
const startBufferBytes = 4096

// ErrFileTooLarge 表示文件大小超过允许的上限。
var ErrFileTooLarge = errors.New("文件超过允许的大小上限")

// ScanLines 逐行扫描文件并把每一行交给回调处理。
//
// 行为约定：
//   - maxBytes <= 0 表示不限制总大小；否则在打开前用 Stat 检查，超限直接返回 ErrFileTooLarge；
//   - maxLineBytes <= 0 时使用 defaultMaxLineBytes；
//   - 空行与以 "#" 开头的注释行会被跳过（回调不会收到）；
//   - 交给回调的行已去除首尾空白；
//   - 任意一行返回错误都会中止扫描并原样返回该错误（便于定位非法配置所在行）。
//
// 返回值 bytesRead 是实际读取的字节数，便于日志与排障。
func ScanLines(path string, maxBytes int64, maxLineBytes int, fn func(line string, lineNo int) error) (int64, error) {
	if strings.TrimSpace(path) == "" {
		return 0, errors.New("文件路径不能为空")
	}
	if maxLineBytes <= 0 {
		maxLineBytes = defaultMaxLineBytes
	}

	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("打开文件失败（%s）：%w", path, err)
	}
	defer func() { _ = file.Close() }()

	// 先用文件大小做一次「廉价的整体上限检查」，避免把超大文件读进内存。
	if maxBytes > 0 {
		info, err := file.Stat()
		if err != nil {
			return 0, fmt.Errorf("读取文件状态失败（%s）：%w", path, err)
		}
		if info.Size() > maxBytes {
			return 0, fmt.Errorf("%w：%s 为 %d 字节，上限 %d 字节", ErrFileTooLarge, path, info.Size(), maxBytes)
		}
	}

	var (
		scanner  = bufio.NewScanner(file)
		lineNo   = 0
		readSize int64
	)
	// 初始缓冲区必须不大于单行上限，否则「单行上限」会形同虚设：
	// bufio.Scanner 只在「缓冲区被填满」时才检查并触发超长错误，
	// 若初始缓冲远大于 maxLineBytes，长度介于两者之间的超长行会被
	// 当成正常 token 直接返回（需求 R13 要求限额真实生效，不能只是声明）。
	startBuffer := startBufferBytes
	if maxLineBytes < startBuffer {
		startBuffer = maxLineBytes
	}
	scanner.Buffer(make([]byte, startBuffer), maxLineBytes)

	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		readSize += int64(len(line)) + 1

		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if err := fn(trimmed, lineNo); err != nil {
			return readSize, err
		}
	}
	if err := scanner.Err(); err != nil {
		return readSize, fmt.Errorf("扫描文件失败（%s）：%w", path, err)
	}
	return readSize, nil
}

// ReadCapped 读取整个文件，但受大小上限约束。
//
// 仅用于「确实需要整体内容且体积已知很小」的场景（例如测试向量、小型映射表）；
// 需要逐行处理的场景请使用 ScanLines，避免一次性读入。
func ReadCapped(path string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("文件路径不能为空")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件状态失败（%s）：%w", path, err)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("%w：%s 为 %d 字节，上限 %d 字节", ErrFileTooLarge, path, info.Size(), maxBytes)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败（%s）：%w", path, err)
	}
	return content, nil
}
