package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ManifestName 是规则包清单文件的固定文件名。
//
// 之所以固定文件名而不是可配置：清单是「规则包」这一交付物的元数据，
// 类似于包管理器的 metadata 文件，固定名字才能被 CLI 与流水线稳定识别。
const ManifestName = "manifest.yaml"

// 清单中单个文件的类别（kind）。
const (
	// KindRules 表示 SecLang 规则文件。
	KindRules = "rules"
	// KindData 表示规则引用的数据文件（@pmFromFile 等算子使用）。
	KindData = "data"
	// KindSetup 表示 CRS 设置文件。
	KindSetup = "setup"
)

// Manifest 是规则包清单（需求 P1-1：CRS 全量离线打包 + 版本清单）。
//
// 为什么需要清单：
//
//  1. **可验证**：离线交付的规则包必须能证明「文件没有被改过/漏拷」，
//     manifest 中的 SHA-256 与大小提供了这一能力（`waf rules verify`）。
//
//  2. **可审计**：版本号、来源、生成时间回答了「线上跑的是哪一版规则、谁给的」，
//     这是安全事故复盘时最先被问到的问题。
//
//  3. **可回滚**：升级前保存上一版，出问题一条命令回滚（`waf rules rollback`）。
type Manifest struct {
	// Name 是规则包名，例如 "owasp-crs"。
	Name string `yaml:"name" json:"name"`
	// Version 是规则包版本，例如 "4.7.0"。
	Version string `yaml:"version" json:"version"`
	// Source 是来源说明（审计用），例如 "https://github.com/coreruleset/coreruleset"。
	Source string `yaml:"source" json:"source"`
	// Created 是清单生成时间（RFC3339）。
	Created string `yaml:"created" json:"created"`
	// Files 是包内文件清单，按文件名排序。
	Files []FileEntry `yaml:"files" json:"files"`
}

// FileEntry 是清单中的单条文件记录。
type FileEntry struct {
	// Name 是文件名（不含目录）。
	Name string `yaml:"name" json:"name"`
	// Kind 是文件类别：rules / data / setup。
	Kind string `yaml:"kind" json:"kind"`
	// Size 是文件大小（字节）。
	Size int64 `yaml:"size" json:"size"`
	// SHA256 是文件内容的十六进制摘要。
	SHA256 string `yaml:"sha256" json:"sha256"`
}

// ManifestMeta 是生成清单时的元数据。
type ManifestMeta struct {
	// Name 是规则包名。
	Name string
	// Version 是规则包版本。
	Version string
	// Source 是来源说明。
	Source string
	// Now 是生成时间基准；为零值时使用 time.Now()（可注入以便测试稳定）。
	Now time.Time
}

// BuildManifest 扫描目录并生成清单。
//
// 参数：
//   - dir        规则目录；
//   - include    规则文件匹配模式；
//   - dataInclude 数据文件匹配模式；
//   - setup      设置文件名（会被标记为 kind=setup）；为空表示无设置文件；
//   - maxFileBytes 单文件上限，超过则报错（与加载逻辑共用同一份限额，需求 R13）。
func BuildManifest(dir string, include, dataInclude []string, setup string, maxFileBytes int64, meta ManifestMeta) (*Manifest, error) {
	if maxFileBytes <= 0 {
		return nil, fmt.Errorf("生成规则包清单需要正数的 max_file_bytes（当前 %d）", maxFileBytes)
	}

	fsys := os.DirFS(dir)
	ruleNames, err := globRuleFiles(fsys, normaliseInclude(include))
	if err != nil {
		return nil, err
	}
	dataNames, err := globRuleFiles(fsys, normalisePatterns(dataInclude, defaultDataPatterns))
	if err != nil {
		return nil, err
	}

	// 设置文件可能同时匹配 include（例如 crs-setup.conf 匹配 *.conf），
	// 这里统一收敛为「点名判断」：只有等于 setup 的文件才标记为 setup 类别。
	setupName := strings.TrimSpace(setup)

	entries := make([]FileEntry, 0, len(ruleNames)+len(dataNames))
	for _, name := range unionNames(ruleNames, dataNames) {
		entry, err := buildEntry(fsys, name, setupName, maxFileBytes)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		entries = append(entries, *entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("规则目录 %s 中没有任何匹配的文件（include=%v data_include=%v）",
			dir, include, dataInclude)
	}

	now := meta.Now
	if now.IsZero() {
		now = time.Now()
	}

	return &Manifest{
		Name:    meta.Name,
		Version: meta.Version,
		Source:  meta.Source,
		Created: now.Format(time.RFC3339),
		Files:   entries,
	}, nil
}

// buildEntry 为单个文件生成清单记录。
//
// 返回 nil 表示该文件不需要进入清单（当前实现不会发生，保留返回值以便未来扩展过滤）。
func buildEntry(fsys fs.FS, name, setupName string, maxFileBytes int64) (*FileEntry, error) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 的元信息失败：%w", name, err)
	}

	content, err := readLimited(fsys, name, maxFileBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)

	kind := KindRules
	switch {
	case setupName != "" && filepath.Base(name) == setupName:
		kind = KindSetup
	case strings.HasSuffix(strings.ToLower(name), ".data"):
		// 数据文件不是 SecLang 规则，必须单独标记：verify 与加载都会按类别处理。
		kind = KindData
	}

	return &FileEntry{
		Name:   filepath.Base(name),
		Kind:   kind,
		Size:   info.Size(),
		SHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// unionNames 合并两组文件名并去重（保持字典序）。
func unionNames(first, second []string) []string {
	seen := make(map[string]struct{}, len(first)+len(second))
	for _, group := range [][]string{first, second} {
		for _, name := range group {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LoadManifest 读取目录中的清单文件。
func LoadManifest(dir string, maxFileBytes int64) (*Manifest, error) {
	path := filepath.Join(dir, ManifestName)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("规则包清单 %s 不可访问：%w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("规则包清单 %s 是目录", path)
	}
	if maxFileBytes > 0 && info.Size() > maxFileBytes {
		return nil, fmt.Errorf("规则包清单 %s 大小 %d 字节，超过单文件上限 %d 字节", path, info.Size(), maxFileBytes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取规则包清单 %s 失败：%w", path, err)
	}

	// 严格模式：清单里的字段拼写错误必须立刻暴露，否则「以为校验了、其实没有」。
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)

	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("解析规则包清单 %s 失败：%w", path, err)
	}
	if strings.TrimSpace(manifest.Name) == "" {
		return nil, fmt.Errorf("规则包清单 %s 缺少 name", path)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return nil, fmt.Errorf("规则包清单 %s 缺少 version", path)
	}
	return &manifest, nil
}

// WriteManifest 把清单写入目录。
func WriteManifest(dir string, manifest *Manifest) (string, error) {
	if manifest == nil {
		return "", errors.New("清单内容不能为空")
	}
	raw, err := yaml.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("清单序列化失败：%w", err)
	}
	path := filepath.Join(dir, ManifestName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("写入清单 %s 失败：%w", path, err)
	}
	return path, nil
}

// VerifyReport 是规则包校验结果。
//
// 三个切片在构造时初始化为空切片（而不是 nil）：JSON 序列化后是 [] 而不是 null，
// 便于流水线直接对字段做长度判断，不必处处写空值保护。
type VerifyReport struct {
	// Manifest 是读取到的清单。
	Manifest *Manifest `json:"manifest"`
	// Missing 是清单中声明但目录中不存在的文件。
	Missing []string `json:"missing"`
	// Mismatched 是内容摘要与清单不一致的文件。
	Mismatched []string `json:"mismatched"`
	// Unexpected 是目录中存在但清单未声明的文件（更新残留 / 人为放入）。
	Unexpected []string `json:"unexpected"`
	// TotalBytes 是清单声明的总字节数。
	TotalBytes int64 `json:"total_bytes"`
}

// OK 报告校验是否完全通过。
func (r *VerifyReport) OK() bool {
	return r != nil && len(r.Missing) == 0 && len(r.Mismatched) == 0
}

// Verify 依据清单校验目录内容（需求 P1-1：离线规则包可验证）。
//
// 校验三项内容：
//   - 缺失：清单里有、目录里没有（拷贝不完整）；
//   - 变更：大小或摘要不一致（文件被改过、传输损坏）；
//   - 多余：目录里有、清单里没有（升级残留、人为放入，属于必须被发现的异常）。
//
// 之所以把「多余文件」也当作异常：升级包残留的旧规则文件会被加载并参与检测，
// 表现为「升级后行为没变甚至更奇怪」，是最难排查的一类事故。
func Verify(dir string, maxFileBytes int64) (*VerifyReport, error) {
	manifest, err := LoadManifest(dir, maxFileBytes)
	if err != nil {
		return nil, err
	}

	report := &VerifyReport{
		Manifest:   manifest,
		Missing:    make([]string, 0, 4),
		Mismatched: make([]string, 0, 4),
		Unexpected: make([]string, 0, 4),
	}
	declared := make(map[string]FileEntry, len(manifest.Files))

	for _, entry := range manifest.Files {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return nil, fmt.Errorf("清单 %s 中存在空的文件记录", ManifestName)
		}
		declared[name] = entry
		report.TotalBytes += entry.Size

		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			report.Missing = append(report.Missing, name)
			continue
		}
		if entry.Size > 0 && info.Size() != entry.Size {
			report.Mismatched = append(report.Mismatched, name)
			continue
		}

		sum, err := fileSHA256(path, maxFileBytes)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(sum, entry.SHA256) {
			report.Mismatched = append(report.Mismatched, name)
		}
	}

	// 扫描目录中的实际文件，找出「清单未声明」的多余文件。
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取规则目录 %s 失败：%w", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == ManifestName {
			continue
		}
		if _, ok := declared[name]; !ok {
			report.Unexpected = append(report.Unexpected, name)
		}
	}

	sort.Strings(report.Missing)
	sort.Strings(report.Mismatched)
	sort.Strings(report.Unexpected)
	return report, nil
}

// fileSHA256 计算文件内容的摘要（带上限读取，禁止大体积读取）。
func fileSHA256(path string, maxFileBytes int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("打开文件 %s 失败：%w", path, err)
	}
	defer func() { _ = file.Close() }()

	limit := maxFileBytes
	if limit <= 0 {
		limit = defaultVerifyFileLimit
	}

	hasher := sha256.New()
	// 多读 1 字节用于判断是否超限，与 readLimited 的语义保持一致。
	written, err := io.Copy(hasher, io.LimitReader(file, limit+1))
	if err != nil {
		return "", fmt.Errorf("读取文件 %s 失败：%w", path, err)
	}
	if written > limit {
		return "", fmt.Errorf("文件 %s 超过单文件上限 %d 字节（请调整 limits.max_rule_file_bytes）", path, limit)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// defaultVerifyFileLimit 是未提供限额时使用的兜底单文件上限（8 MiB）。
const defaultVerifyFileLimit = 8 * 1024 * 1024

// InstallOptions 是规则包安装（原子替换）参数。
type InstallOptions struct {
	// MaxFileBytes 是单文件大小上限。
	MaxFileBytes int64
	// MaxTotalBytes 是规则包总大小上限。
	MaxTotalBytes int64
	// PreviousSuffix 是「上一版本」目录的后缀；为空时使用 defaultPreviousSuffix。
	PreviousSuffix string
}

// defaultPreviousSuffix 是回滚目录的后缀。
const defaultPreviousSuffix = ".previous"

// InstallResult 是安装结果。
type InstallResult struct {
	// Target 是目标目录。
	Target string
	// Previous 是保留的上一版本目录；为空表示本次是首次安装（无可回滚版本）。
	Previous string
	// Files 是安装的文件数量。
	Files int
	// TotalBytes 是安装的总字节数。
	TotalBytes int64
}

// Install 把源目录中的规则包原子安装到目标目录（需求 P1-2 的「原子替换」）。
//
// 流程（每一步都可逆，任何一步失败都不会破坏现有规则目录）：
//
//  1. 校验源目录（存在清单则先 verify）；
//  2. 把源目录复制到「目标目录.new」（复制过程带单文件与总量限额）；
//  3. 删除残留的「目标目录.new」，若存在；
//  4. 目标目录 -> 目标目录.previous（重命名，O(1)）；
//  5. 目标目录.new -> 目标目录（重命名，O(1)）；
//  6. 任一步失败：把 .previous 改回目标目录，保证「升级失败后线上仍是旧规则」。
//
// 为什么用「重命名」而不是「先删后拷」：重命名是原子的，中间不存在
// 「规则目录为空」的时间窗口；而先删后拷会让运行中的实例在毫秒级窗口内读到半个规则集。
func Install(sourceDir, targetDir string, opts InstallOptions) (*InstallResult, error) {
	sourceDir = strings.TrimSpace(sourceDir)
	targetDir = strings.TrimSpace(targetDir)
	if sourceDir == "" {
		return nil, errors.New("规则包源目录不能为空")
	}
	if targetDir == "" {
		return nil, errors.New("规则包目标目录不能为空")
	}
	if samePath(sourceDir, targetDir) {
		return nil, fmt.Errorf("源目录与目标目录相同（%s），无法安装", sourceDir)
	}

	sourceInfo, err := os.Stat(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("规则包源目录 %s 不可访问：%w", sourceDir, err)
	}
	if !sourceInfo.IsDir() {
		return nil, fmt.Errorf("规则包源路径 %s 不是目录", sourceDir)
	}

	previousSuffix := opts.PreviousSuffix
	if previousSuffix == "" {
		previousSuffix = defaultPreviousSuffix
	}
	stagingDir := targetDir + ".new"
	previousDir := targetDir + previousSuffix

	// 步骤 1：源目录若带清单则先校验，避免把「拷贝不完整」的包推上线。
	if _, statErr := os.Stat(filepath.Join(sourceDir, ManifestName)); statErr == nil {
		report, err := Verify(sourceDir, opts.MaxFileBytes)
		if err != nil {
			return nil, err
		}
		if !report.OK() {
			return nil, fmt.Errorf("规则包校验未通过（缺失 %v，摘要不一致 %v）", report.Missing, report.Mismatched)
		}
	}

	// 步骤 3（提前）：清理上次失败留下的暂存目录。
	if err := os.RemoveAll(stagingDir); err != nil {
		return nil, fmt.Errorf("清理暂存目录 %s 失败：%w", stagingDir, err)
	}

	// 步骤 2：复制到暂存目录。
	result, err := copyTree(sourceDir, stagingDir, opts)
	if err != nil {
		// 复制失败：只在目标目录未被改动的前提下清理暂存目录，避免留下垃圾。
		_ = os.RemoveAll(stagingDir)
		return nil, err
	}
	result.Target = targetDir

	// 步骤 4：目标目录 -> .previous（若目标不存在，说明是首次安装）。
	if _, statErr := os.Stat(targetDir); statErr == nil {
		// 残留的 .previous 先清理：它代表更早的版本，保留多代会让磁盘与排障都变复杂。
		if err := os.RemoveAll(previousDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("清理历史回滚目录 %s 失败：%w", previousDir, err)
		}
		if err := os.Rename(targetDir, previousDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("备份当前规则目录到 %s 失败：%w", previousDir, err)
		}
		result.Previous = previousDir
	}

	// 步骤 5：暂存目录 -> 目标目录。
	if err := os.Rename(stagingDir, targetDir); err != nil {
		// 步骤 6：回滚 —— 把备份改回目标目录，保证线上仍是旧规则。
		if result.Previous != "" {
			if rollbackErr := os.Rename(previousDir, targetDir); rollbackErr != nil {
				return nil, fmt.Errorf("安装规则包失败（%v），且回滚也失败（%v）：规则目录 %s 目前不可用，请人工检查",
					err, rollbackErr, targetDir)
			}
			result.Previous = ""
		}
		return nil, fmt.Errorf("启用新规则目录 %s 失败：%w", targetDir, err)
	}

	return result, nil
}

// Rollback 把目标目录回滚到上一版本。
//
// 为什么回滚要「删除新目录」而不是保留两份：目标目录是运行中的实例实际加载的路径，
// 保留多份会让「当前到底在跑哪一版」变得模糊。历史版本由 .previous 单独承载，
// 每次安装只保留一代，语义清晰。
func Rollback(targetDir string, opts InstallOptions) (string, error) {
	targetDir = strings.TrimSpace(targetDir)
	if targetDir == "" {
		return "", errors.New("规则包目标目录不能为空")
	}
	previousSuffix := opts.PreviousSuffix
	if previousSuffix == "" {
		previousSuffix = defaultPreviousSuffix
	}
	previousDir := targetDir + previousSuffix

	if _, err := os.Stat(previousDir); err != nil {
		return "", fmt.Errorf("未找到可回滚的上一版本（%s）：%w", previousDir, err)
	}

	// 当前版本改名为 .failed：保留它是为了事后排查「回滚前的版本到底哪里有问题」，
	// 而不是直接删除。运维确认无误后手工清理即可。
	failedDir := targetDir + ".failed"
	if err := os.RemoveAll(failedDir); err != nil {
		return "", fmt.Errorf("清理 %s 失败：%w", failedDir, err)
	}
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.Rename(targetDir, failedDir); err != nil {
			return "", fmt.Errorf("暂存当前规则目录到 %s 失败：%w", failedDir, err)
		}
	}
	if err := os.Rename(previousDir, targetDir); err != nil {
		// 回滚失败时把当前版本改回去，避免规则目录缺失。
		if _, statErr := os.Stat(failedDir); statErr == nil {
			_ = os.Rename(failedDir, targetDir)
		}
		return "", fmt.Errorf("回滚规则目录 %s 失败：%w", targetDir, err)
	}
	return failedDir, nil
}

// copyTree 把源目录中的规则文件复制到目标目录（受限额约束）。
func copyTree(sourceDir, targetDir string, opts InstallOptions) (*InstallResult, error) {
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建目录 %s 失败：%w", targetDir, err)
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("读取源目录 %s 失败：%w", sourceDir, err)
	}

	result := &InstallResult{}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("规则包暂不支持子目录（发现 %s）；扁平目录可以保证 @pmFromFile 的相对路径语义一致",
				entry.Name())
		}

		size, err := copyFile(
			filepath.Join(sourceDir, entry.Name()),
			filepath.Join(targetDir, entry.Name()),
			opts.MaxFileBytes,
		)
		if err != nil {
			return nil, err
		}

		result.Files++
		result.TotalBytes += size
		if opts.MaxTotalBytes > 0 && result.TotalBytes > opts.MaxTotalBytes {
			return nil, fmt.Errorf("规则包总大小超过上限 %d 字节（请调整 limits.max_rules_total_bytes）",
				opts.MaxTotalBytes)
		}
	}
	return result, nil
}

// copyFile 复制单个文件并返回写入的字节数（带上限保护）。
func copyFile(source, target string, maxFileBytes int64) (int64, error) {
	in, err := os.Open(source)
	if err != nil {
		return 0, fmt.Errorf("打开 %s 失败：%w", source, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("创建 %s 失败：%w", target, err)
	}

	limit := maxFileBytes
	if limit <= 0 {
		limit = defaultVerifyFileLimit
	}

	written, err := io.Copy(out, io.LimitReader(in, limit+1))
	if err != nil {
		_ = out.Close()
		return 0, fmt.Errorf("复制 %s -> %s 失败：%w", source, target, err)
	}
	if err := out.Close(); err != nil {
		return 0, fmt.Errorf("关闭 %s 失败：%w", target, err)
	}
	if written > limit {
		return 0, fmt.Errorf("文件 %s 超过单文件上限 %d 字节（请调整 limits.max_rule_file_bytes）", source, limit)
	}
	return written, nil
}

// samePath 判断两个路径是否指向同一位置（大小写与相对路径归一化后比较）。
func samePath(first, second string) bool {
	absFirst, errFirst := filepath.Abs(first)
	absSecond, errSecond := filepath.Abs(second)
	if errFirst != nil || errSecond != nil {
		return strings.EqualFold(filepath.Clean(first), filepath.Clean(second))
	}
	return strings.EqualFold(filepath.Clean(absFirst), filepath.Clean(absSecond))
}
