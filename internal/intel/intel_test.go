package intel

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ip.txt"), []byte(
		"# comment\n1.2.3.0/24\nAS13335\nevil.example.com\n*.bad.example\n"+
			"2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "list.csv"), []byte(
		"type,value\nip,9.9.9.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "more.yaml"), []byte(
		"- type: domain\n  value: yaml.example\n- example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	snapshot, err := Load(Options{Dirs: []string{dir}, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stats := snapshot.Stats()
	if stats.Files != 3 || stats.IPEntries != 3 || stats.ASNs != 1 || stats.Domains != 4 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	for _, ip := range []string{"1.2.3.9", "9.9.9.9", "2001:db8::1"} {
		if kind, matched := snapshot.MatchIP(ip, nil); !matched || kind != "ip" {
			t.Fatalf("ip %s not matched: kind=%s matched=%v", ip, kind, matched)
		}
	}
	if kind, matched := snapshot.MatchIP("203.0.113.1", func(net.IP) (uint, bool) {
		return 13335, true
	}); !matched || kind != "asn:AS13335" {
		t.Fatalf("asn match failed: kind=%s matched=%v", kind, matched)
	}
	for _, host := range []string{"evil.example.com", "evil.example.com:8443", "sub.bad.example", "yaml.example"} {
		if _, matched := snapshot.MatchDomain(host); !matched {
			t.Fatalf("domain %s not matched", host)
		}
	}
	if _, matched := snapshot.MatchDomain("bad.example"); matched {
		t.Fatal("wildcard must not match the suffix itself")
	}
}

func TestFingerprintChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Fingerprint([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1.2.3.5\n2.2.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Fingerprint([]string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("fingerprint did not change after file update")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(Options{}); err == nil {
		t.Fatal("expected error for empty intel source")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{Files: []string{path}, MaxFileBytes: 1}); err == nil {
		t.Fatal("expected size limit error")
	}
}
