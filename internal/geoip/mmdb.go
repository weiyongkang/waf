// Package geoip 提供本地 MaxMind MMDB 的加载、查询与热更新能力。
//
// 设计边界：只读取本地文件，不访问任何云端 GeoIP API；数据库文件是部署输入，
// 因此必须在启动阶段校验存在性与大小上限，避免运行期才发现配置无效。
package geoip

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Country 是国家/地区查询结果。
type Country struct {
	// ISO 是两位国家代码，例如 CN / US。
	ISO string
	// Continent 是洲代码，例如 AS / EU。
	Continent string
	// Name 是国家名称（数据库有该字段时）。
	Name string
}

// ASN 是自治系统查询结果。
type ASN struct {
	// Number 是 AS 号，例如 13335。
	Number uint
	// Organization 是运营组织名称。
	Organization string
}

// Database 是并发安全的 MMDB 快照。
//
// 重新加载采用「先打开新文件、成功后再原子替换」的策略：写坏的数据库不会导致
// 正在运行的查询失败；替换后关闭旧 reader，避免 Windows 下长期占用文件。
type Database struct {
	path     string
	maxBytes int64
	kind     kind

	mu     sync.RWMutex
	reader *maxminddb.Reader
	stamp  fileStamp
}

type kind uint8

const (
	kindCountry kind = iota + 1
	kindASN
)

type fileStamp struct {
	size    int64
	modTime time.Time
}

// OpenCountry 打开国家/城市数据库（GeoLite2-Country / City）。
func OpenCountry(path string, maxBytes int64) (*Database, error) {
	return open(path, maxBytes, kindCountry)
}

// OpenASN 打开 ASN 数据库（GeoLite2-ASN）。
func OpenASN(path string, maxBytes int64) (*Database, error) {
	return open(path, maxBytes, kindASN)
}

func open(path string, maxBytes int64, kind kind) (*Database, error) {
	trimmed := path
	if trimmed == "" {
		return nil, fmt.Errorf("MMDB 数据库路径不能为空")
	}
	info, err := os.Stat(trimmed)
	if err != nil {
		return nil, fmt.Errorf("MMDB 数据库 %s 不可访问：%w", trimmed, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("MMDB 数据库 %s 是目录，必须指向 .mmdb 文件", trimmed)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("MMDB 数据库 %s 大小 %d 超过 limits.max_mmdb_bytes=%d", trimmed, info.Size(), maxBytes)
	}
	reader, err := maxminddb.Open(trimmed)
	if err != nil {
		return nil, fmt.Errorf("打开 MMDB 数据库 %s 失败：%w", trimmed, err)
	}
	return &Database{
		path: trimmed, maxBytes: maxBytes, kind: kind, reader: reader,
		stamp: fileStamp{size: info.Size(), modTime: info.ModTime()},
	}, nil
}

// LookupCountry 查询 IP 的国家与洲信息。
func (d *Database) LookupCountry(ip net.IP) (Country, bool, error) {
	if d == nil || ip == nil {
		return Country{}, false, nil
	}
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
			Names   struct {
				English string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
			Names   struct {
				English string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"registered_country"`
		Continent struct {
			Code string `maxminddb:"code"`
		} `maxminddb:"continent"`
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.kind != kindCountry || d.reader == nil {
		return Country{}, false, fmt.Errorf("不是国家/城市 MMDB 数据库")
	}
	if err := d.reader.Lookup(ip, &record); err != nil {
		return Country{}, false, err
	}
	iso := record.Country.ISOCode
	name := record.Country.Names.English
	if iso == "" {
		iso = record.RegisteredCountry.ISOCode
		name = record.RegisteredCountry.Names.English
	}
	if iso == "" && record.Continent.Code == "" {
		return Country{}, false, nil
	}
	return Country{ISO: iso, Continent: record.Continent.Code, Name: name}, true, nil
}

// LookupASN 查询 IP 所属自治系统。
func (d *Database) LookupASN(ip net.IP) (ASN, bool, error) {
	if d == nil || ip == nil {
		return ASN{}, false, nil
	}
	var record struct {
		Number       uint   `maxminddb:"autonomous_system_number"`
		Organization string `maxminddb:"autonomous_system_organization"`
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.kind != kindASN || d.reader == nil {
		return ASN{}, false, fmt.Errorf("不是 ASN MMDB 数据库")
	}
	if err := d.reader.Lookup(ip, &record); err != nil {
		return ASN{}, false, err
	}
	if record.Number == 0 {
		return ASN{}, false, nil
	}
	return ASN{Number: record.Number, Organization: record.Organization}, true, nil
}

// Reload 在文件指纹变化时重新加载数据库。
//
// 返回 changed 表示文件确实变化；加载失败时返回错误并继续使用旧快照。
func (d *Database) Reload() (bool, error) {
	if d == nil {
		return false, nil
	}
	info, err := os.Stat(d.path)
	if err != nil {
		return false, fmt.Errorf("MMDB 数据库 %s 不可访问：%w", d.path, err)
	}
	if d.maxBytes > 0 && info.Size() > d.maxBytes {
		return false, fmt.Errorf("MMDB 数据库 %s 大小 %d 超过 limits.max_mmdb_bytes=%d", d.path, info.Size(), d.maxBytes)
	}

	d.mu.RLock()
	unchanged := d.stamp.size == info.Size() && d.stamp.modTime.Equal(info.ModTime())
	d.mu.RUnlock()
	if unchanged {
		return false, nil
	}

	reader, err := maxminddb.Open(d.path)
	if err != nil {
		return false, fmt.Errorf("重新加载 MMDB 数据库 %s 失败：%w", d.path, err)
	}

	d.mu.Lock()
	old := d.reader
	d.reader = reader
	d.stamp = fileStamp{size: info.Size(), modTime: info.ModTime()}
	d.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return true, nil
}

// Close 关闭底层 reader。
func (d *Database) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}

// Path 返回数据库路径（日志用）。
func (d *Database) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}
