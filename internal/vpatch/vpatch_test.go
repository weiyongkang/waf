package vpatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinsAndKnown(t *testing.T) {
	builtins := Builtins()
	if len(builtins) == 0 {
		t.Fatal("no builtin virtual patches")
	}
	for _, item := range builtins {
		if item.ID == "" || len(item.Directives) == 0 {
			t.Fatalf("invalid builtin: %+v", item)
		}
		if !Known(item.ID) || !Known(strings.ToUpper(item.CVE)) {
			t.Fatalf("builtin %s is not recognized", item.ID)
		}
	}
	if Known("not-a-patch") {
		t.Fatal("unknown patch recognized")
	}
}

func TestResolveBuiltinAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.conf")
	content := "# comment\nSecRule ARGS \"@rx bad\" \"id:9200001,phase:2,deny\"\n\nSecRule URI \"@rx evil\" \"id:9200002,phase:1,deny\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(Options{
		Names: []string{"CVE-2021-44228", "cve-2021-44228"},
		Files: []string{path},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected two patches, got %d: %+v", len(resolved), resolved)
	}
	if len(Directives(resolved)) != 3 {
		t.Fatalf("unexpected directive count: %v", Directives(resolved))
	}
	if resolved[1].ID != "custom" || resolved[1].Source != path {
		t.Fatalf("custom patch metadata mismatch: %+v", resolved[1])
	}
}

func TestResolveErrors(t *testing.T) {
	if _, err := Resolve(Options{Names: []string{"missing"}}); err == nil {
		t.Fatal("expected unknown template error")
	}
	if _, err := Resolve(Options{Files: []string{filepath.Join(t.TempDir(), "missing.conf")}}); err == nil {
		t.Fatal("expected missing file error")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(path, []byte("# only comments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(Options{Files: []string{path}}); err == nil {
		t.Fatal("expected empty patch file error")
	}
}
