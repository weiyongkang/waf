package rules

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"sort"
	"time"
)

// memFS 是只读的内存文件系统，用于把「已加载并校验过限额」的规则文件交给 Coraza。
//
// 为什么不直接把 os.DirFS / embed.FS 交给 Coraza：
//
//   - 磁盘文件在「限额校验」与「Coraza 实际读取」之间存在竞态：
//     校验通过后文件可能被替换成超大文件，限额形同虚设；
//   - 内置规则与磁盘规则需要在同一命名空间内解析（否则重名冲突无法检测）；
//   - 内存副本让运行期完全不再触碰磁盘（需求 R13：不做大体积读取）。
//
// 文件系统是扁平结构（全部以基名为键），因为 Coraza 的规则目录本来就是单层布局，
// 且 .data 数据文件与规则文件位于同一层，扁平结构正好匹配其查找语义。
type memFS struct {
	// files 是「文件名 -> 内容」映射。
	files map[string][]byte
}

// newMemFS 用已加载的规则文件构造内存文件系统。
func newMemFS(files map[string]ruleFile) *memFS {
	converted := make(map[string][]byte, len(files))
	for name, file := range files {
		converted[name] = file.content
	}
	return &memFS{files: converted}
}

// Open 实现 fs.FS。
func (m *memFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &memDir{fs: m, name: "."}, nil
	}
	content, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{name: name, reader: bytes.NewReader(content), size: int64(len(content))}, nil
}

// ReadFile 实现 fs.ReadFileFS，避免 Open 之后再逐块读取。
func (m *memFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrInvalid}
	}
	content, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrNotExist}
	}
	return content, nil
}

// ReadDir 实现 fs.ReadDirFS，供 fs.Glob 与目录遍历使用。
func (m *memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	names := make([]string, 0, len(m.files))
	for file := range m.files {
		names = append(names, file)
	}
	sort.Strings(names)

	entries := make([]fs.DirEntry, 0, len(names))
	for _, file := range names {
		entries = append(entries, memDirEntry{name: file, size: int64(len(m.files[file]))})
	}
	return entries, nil
}

// memFile 是内存文件的 fs.File 实现。
type memFile struct {
	// name 是文件名。
	name string
	// reader 是内容读取器。
	reader *bytes.Reader
	// size 是文件大小（字节）。
	size int64
}

// Stat 返回文件元信息。
func (f *memFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: f.name, size: f.size}, nil
}

// Read 读取文件内容。
func (f *memFile) Read(p []byte) (int, error) { return f.reader.Read(p) }

// Close 关闭文件（内存文件无需释放资源，保持幂等）。
func (f *memFile) Close() error { return nil }

// memDir 是根目录的 fs.File 实现（仅支持读取目录）。
type memDir struct {
	// fs 是所属文件系统。
	fs *memFS
	// name 是目录名。
	name string
	// offset 是 ReadDir 的游标位置。
	offset int
}

// Stat 返回目录元信息。
func (d *memDir) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: d.name, size: 0, dir: true}, nil
}

// Read 对目录读取返回错误（目录不可按字节读取）。
func (d *memDir) Read(_ []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}

// Close 关闭目录。
func (d *memDir) Close() error { return nil }

// ReadDir 按游标返回剩余目录项，满足 fs.ReadDirFile 语义。
func (d *memDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	if d.offset >= len(entries) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	remaining := entries[d.offset:]
	if n > 0 && n < len(remaining) {
		d.offset += n
		return remaining[:n], nil
	}
	d.offset = len(entries)
	return remaining, nil
}

// memDirEntry 是内存文件系统的目录项实现。
type memDirEntry struct {
	// name 是文件名。
	name string
	// size 是文件大小（字节）。
	size int64
}

// Name 返回文件名。
func (e memDirEntry) Name() string { return e.name }

// IsDir 报告是否为目录（内存文件系统只有文件）。
func (memDirEntry) IsDir() bool { return false }

// Type 返回文件类型位。
func (memDirEntry) Type() fs.FileMode { return 0 }

// Info 返回文件元信息。
func (e memDirEntry) Info() (fs.FileInfo, error) {
	return memFileInfo{name: e.name, size: e.size}, nil
}

// memFileInfo 是内存文件的 fs.FileInfo 实现。
type memFileInfo struct {
	// name 是文件名。
	name string
	// size 是文件大小（字节）。
	size int64
	// dir 表示是否为目录。
	dir bool
}

// Name 返回基名。
func (i memFileInfo) Name() string { return path.Base(i.name) }

// Size 返回文件大小。
func (i memFileInfo) Size() int64 { return i.size }

// Mode 返回文件模式；目录带 fs.ModeDir 位，普通文件为只读常规文件。
func (i memFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}

// ModTime 返回修改时间；内存规则集没有有意义的时间戳，统一返回零值。
func (memFileInfo) ModTime() time.Time { return time.Time{} }

// IsDir 报告是否为目录。
func (i memFileInfo) IsDir() bool { return i.dir }

// Sys 返回底层数据源（内存文件没有）。
func (memFileInfo) Sys() any { return nil }
