// Package intel 实现本地威胁情报的加载、匹配与文件指纹。
//
// 支持三类条目：
//   - ip：单个 IP 或 CIDR；
//   - asn：AS 号（需要同时配置 GeoLite2-ASN MMDB 才能匹配）；
//   - domain：精确域名或 *.example.com 通配后缀。
//
// 文件格式：
//   - .txt / .list：一行一条，支持 `type value`、`type:value` 与纯值自动识别；
//   - .csv：两列或三列，首列 type、次列 value，可选表头；
//   - .yaml / .yml / .json：字符串数组或 {type, value} 对象数组。
package intel

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/weiyongkang/waf/internal/netx"
)

// Options 是情报加载参数。
type Options struct {
	// Files 是显式文件列表。
	Files []string
	// Dirs 是需要递归扫描的目录列表。
	Dirs []string
	// MaxFileBytes 是单个文件大小上限。
	MaxFileBytes int64
	// MaxTotalBytes 是全部情报文件总大小上限；<=0 时使用 MaxFileBytes * 16。
	MaxTotalBytes int64
}

// Snapshot 是一次加载得到的情报快照，查询只读且并发安全。
type Snapshot struct {
	ips          *netx.Set
	domains      map[string]struct{}
	domainSuffix map[string]struct{}
	asns         map[uint]struct{}
	files        []string
	ipCount      int
	domainCount  int
	asnCount     int
}

// Stats 是快照统计信息（日志与 CLI 展示）。
type Stats struct {
	Files      int
	IPEntries  int
	Domains    int
	ASNs       int
	TotalBytes int64
}

// Load 从文件与目录加载情报快照。
func Load(opts Options) (*Snapshot, error) {
	files, totalBytes, err := collectFiles(opts)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("威胁情报未加载到任何文件；请检查 files / dirs 配置与文件扩展名")
	}

	snapshot := &Snapshot{
		ips:          mustSet(),
		domains:      make(map[string]struct{}),
		domainSuffix: make(map[string]struct{}),
		asns:         make(map[uint]struct{}),
		files:        files,
	}
	for _, file := range files {
		if err := snapshot.loadFile(file, opts.MaxFileBytes); err != nil {
			return nil, err
		}
	}
	snapshot.files = files
	snapshot.ipCount = snapshot.ips.Len()
	snapshot.domainCount = len(snapshot.domains) + len(snapshot.domainSuffix)
	snapshot.asnCount = len(snapshot.asns)
	_ = totalBytes
	return snapshot, nil
}

func mustSet() *netx.Set {
	set, _ := netx.NewSet(nil)
	return set
}

// Stats 返回快照统计信息。
func (s *Snapshot) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		Files:     len(s.files),
		IPEntries: s.ipCount,
		Domains:   s.domainCount,
		ASNs:      s.asnCount,
	}
}

// HasASN 报告快照是否包含 ASN 条目。
func (s *Snapshot) HasASN() bool {
	return s != nil && len(s.asns) > 0
}

// MatchIP 匹配 IP/CIDR 与 ASN 条目。
//
// asnLookup 可为 nil；此时只匹配 CIDR。返回命中的条目描述。
func (s *Snapshot) MatchIP(value string, asnLookup func(net.IP) (uint, bool)) (string, bool) {
	if s == nil {
		return "", false
	}
	if s.ips.Contains(value) {
		return "ip", true
	}
	if len(s.asns) == 0 || asnLookup == nil {
		return "", false
	}
	ip := netx.ParseIP(value)
	if ip == nil {
		return "", false
	}
	asn, ok := asnLookup(ip)
	if !ok {
		return "", false
	}
	if _, exists := s.asns[asn]; exists {
		return fmt.Sprintf("asn:AS%d", asn), true
	}
	return "", false
}

// MatchDomain 匹配精确域名与 *.suffix 通配。
func (s *Snapshot) MatchDomain(host string) (string, bool) {
	if s == nil {
		return "", false
	}
	normalized := normalizeDomain(host)
	if normalized == "" {
		return "", false
	}
	if _, ok := s.domains[normalized]; ok {
		return normalized, true
	}
	labels := strings.Split(normalized, ".")
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if _, ok := s.domainSuffix[suffix]; ok {
			return "*." + suffix, true
		}
	}
	return "", false
}

func (s *Snapshot) loadFile(file string, maxFileBytes int64) error {
	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("情报文件 %s 不可访问：%w", file, err)
	}
	if maxFileBytes > 0 && info.Size() > maxFileBytes {
		return fmt.Errorf("情报文件 %s 大小 %d 超过 limits.max_intel_file_bytes=%d", file, info.Size(), maxFileBytes)
	}

	ext := strings.ToLower(filepath.Ext(file))
	switch ext {
	case ".yaml", ".yml", ".json":
		return s.loadStructured(file)
	case ".csv":
		return s.loadCSV(file)
	default:
		return s.loadLines(file)
	}
}

func (s *Snapshot) loadLines(file string) error {
	handle, err := os.Open(file)
	if err != nil {
		return err
	}
	defer handle.Close()

	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if err := s.addEntry(line); err != nil {
			return fmt.Errorf("情报文件 %s 第 %d 行非法：%w", file, lineNo, err)
		}
	}
	return scanner.Err()
}

func (s *Snapshot) loadCSV(file string) error {
	handle, err := os.Open(file)
	if err != nil {
		return err
	}
	defer handle.Close()

	reader := csv.NewReader(handle)
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("解析情报 CSV %s 失败：%w", file, err)
	}
	for index, row := range rows {
		if len(row) == 0 {
			continue
		}
		first := strings.TrimSpace(row[0])
		second := ""
		if len(row) > 1 {
			second = strings.TrimSpace(row[1])
		}
		if strings.EqualFold(first, "type") || strings.EqualFold(first, "kind") {
			continue
		}
		entry := first + " " + second
		if second == "" {
			entry = first
		}
		if err := s.addEntry(entry); err != nil {
			return fmt.Errorf("情报 CSV %s 第 %d 行非法：%w", file, index+1, err)
		}
	}
	return nil
}

func (s *Snapshot) loadStructured(file string) error {
	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var payload any
	if err := yaml.Unmarshal(content, &payload); err != nil {
		return fmt.Errorf("解析情报文件 %s 失败：%w", file, err)
	}
	items, ok := payload.([]any)
	if !ok {
		return fmt.Errorf("情报文件 %s 必须是数组", file)
	}
	for index, item := range items {
		switch typed := item.(type) {
		case string:
			if err := s.addEntry(typed); err != nil {
				return fmt.Errorf("情报文件 %s 第 %d 项非法：%w", file, index+1, err)
			}
		case map[string]any:
			kind := fmt.Sprint(typed["type"])
			value := fmt.Sprint(typed["value"])
			if kind == "<nil>" || value == "<nil>" {
				return fmt.Errorf("情报文件 %s 第 %d 项必须包含 type 与 value", file, index+1)
			}
			if err := s.addEntry(kind + " " + value); err != nil {
				return fmt.Errorf("情报文件 %s 第 %d 项非法：%w", file, index+1, err)
			}
		default:
			return fmt.Errorf("情报文件 %s 第 %d 项类型不支持", file, index+1)
		}
	}
	return nil
}

func (s *Snapshot) addEntry(raw string) error {
	kind, value := splitEntry(raw)
	if kind == "" {
		kind = inferKind(value)
	}
	switch strings.ToLower(kind) {
	case "ip", "cidr", "network":
		return s.addIP(value)
	case "asn", "as":
		return s.addASN(value)
	case "domain", "host", "fqdn":
		return s.addDomain(value)
	default:
		return fmt.Errorf("未知情报类型 %q（支持 ip / asn / domain）", kind)
	}
}

func (s *Snapshot) addIP(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("IP/CIDR 不能为空")
	}
	return s.ips.Add(trimmed)
}

func (s *Snapshot) addASN(value string) error {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "AS")
	parsed, err := strconv.ParseUint(normalized, 10, 32)
	if err != nil || parsed == 0 {
		return fmt.Errorf("ASN %q 非法", value)
	}
	s.asns[uint(parsed)] = struct{}{}
	return nil
}

func (s *Snapshot) addDomain(value string) error {
	normalized := normalizeDomain(value)
	if normalized == "" {
		return fmt.Errorf("域名不能为空")
	}
	if strings.HasPrefix(normalized, "*.") {
		suffix := strings.TrimPrefix(normalized, "*.")
		if suffix == "" || strings.Contains(suffix, "*") {
			return fmt.Errorf("域名通配只支持 *.example.com 形态")
		}
		s.domainSuffix[suffix] = struct{}{}
		return nil
	}
	if strings.Contains(normalized, "*") {
		return fmt.Errorf("域名通配只支持 *.example.com 形态")
	}
	s.domains[normalized] = struct{}{}
	return nil
}

func splitEntry(raw string) (string, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ""
	}
	if index := strings.IndexAny(trimmed, ": \t,"); index > 0 {
		kind := strings.TrimSpace(trimmed[:index])
		value := strings.TrimSpace(trimmed[index+1:])
		switch strings.ToLower(kind) {
		case "ip", "cidr", "network", "asn", "as", "domain", "host", "fqdn":
			return kind, value
		}
	}
	return "", trimmed
}

func inferKind(value string) string {
	if strings.HasPrefix(strings.ToUpper(value), "AS") {
		return "asn"
	}
	if strings.Contains(value, "/") || netx.ParseIP(value) != nil {
		return "ip"
	}
	return "domain"
}

func normalizeDomain(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	trimmed = strings.TrimSuffix(trimmed, ".")
	return trimmed
}

func stripComment(line string) string {
	if index := strings.IndexByte(line, '#'); index >= 0 {
		return line[:index]
	}
	return line
}

func collectFiles(opts Options) ([]string, int64, error) {
	seen := make(map[string]struct{})
	var files []string
	var total int64

	addFile := func(path string) error {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if _, ok := seen[absolute]; ok {
			return nil
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return fmt.Errorf("情报文件 %s 不可访问：%w", path, err)
		}
		if info.IsDir() {
			return nil
		}
		seen[absolute] = struct{}{}
		files = append(files, absolute)
		total += info.Size()
		return nil
	}

	for _, file := range opts.Files {
		if strings.TrimSpace(file) == "" {
			continue
		}
		if err := addFile(file); err != nil {
			return nil, 0, err
		}
	}
	for _, dir := range opts.Dirs {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		absolute, err := filepath.Abs(trimmed)
		if err != nil {
			return nil, 0, err
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, 0, fmt.Errorf("情报目录 %s 不可访问：%w", dir, err)
		}
		if !info.IsDir() {
			return nil, 0, fmt.Errorf("情报目录 %s 不是目录", dir)
		}
		err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				return nil
			}
			if !supportedFile(path) {
				return nil
			}
			return addFile(path)
		})
		if err != nil {
			return nil, 0, fmt.Errorf("扫描情报目录 %s 失败：%w", dir, err)
		}
	}

	maxTotal := opts.MaxTotalBytes
	if maxTotal <= 0 && opts.MaxFileBytes > 0 {
		maxTotal = opts.MaxFileBytes * 16
	}
	if maxTotal > 0 && total > maxTotal {
		return nil, total, fmt.Errorf("威胁情报文件总量 %d 超过上限 %d", total, maxTotal)
	}
	sort.Strings(files)
	return files, total, nil
}

func supportedFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".list", ".csv", ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

// Fingerprint 计算情报文件（目录递归）的内容变更指纹。
//
// 只包含路径、大小与修改时间，不读取文件内容；用于定时热更新判断是否变化。
func Fingerprint(files, dirs []string) (string, error) {
	collected, _, err := collectFiles(Options{Files: files, Dirs: dirs})
	if err != nil {
		return "", err
	}
	entries := make([]string, 0, len(collected))
	for _, file := range collected {
		info, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		entries = append(entries, fmt.Sprintf("%s|%d|%d", filepath.ToSlash(file), info.Size(), info.ModTime().UnixNano()))
	}
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(sum[:]), nil
}
