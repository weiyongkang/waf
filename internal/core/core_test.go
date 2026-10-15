package core

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestParsePhase 验证阶段名称与枚举值的双向转换。
func TestParsePhase(t *testing.T) {
	cases := map[string]Phase{
		"pre":     PhasePre,
		"request": PhaseRequest,
		"body":    PhaseBody,
		"post":    PhasePost,
	}
	for name, want := range cases {
		got, err := ParsePhase(name)
		if err != nil {
			t.Fatalf("ParsePhase(%q) 返回错误：%v", name, err)
		}
		if got != want {
			t.Errorf("ParsePhase(%q) = %v，期望 %v", name, got, want)
		}
		if got.String() != name {
			t.Errorf("Phase(%v).String() = %q，期望 %q", want, got.String(), name)
		}
	}

	if _, err := ParsePhase("header"); err == nil {
		t.Error("非法阶段名应当报错")
	}
}

// TestPhaseYAML 验证阶段可从 YAML 直接写字符串。
func TestPhaseYAML(t *testing.T) {
	var holder struct {
		Phase Phase `yaml:"phase"`
	}
	if err := yaml.Unmarshal([]byte("phase: body\n"), &holder); err != nil {
		t.Fatalf("解析 YAML 失败：%v", err)
	}
	if holder.Phase != PhaseBody {
		t.Fatalf("phase = %v，期望 PhaseBody", holder.Phase)
	}

	encoded, err := yaml.Marshal(holder)
	if err != nil {
		t.Fatalf("序列化 YAML 失败：%v", err)
	}
	if string(encoded) != "phase: body\n" {
		t.Fatalf("序列化结果 = %q，期望 \"phase: body\\n\"", string(encoded))
	}
}

// TestDurationYAML 验证时长支持人类可读写法，并对非法写法报错。
func TestDurationYAML(t *testing.T) {
	var holder struct {
		TTL Duration `yaml:"ttl"`
	}

	if err := yaml.Unmarshal([]byte("ttl: 30m\n"), &holder); err != nil {
		t.Fatalf("解析时长失败：%v", err)
	}
	if holder.TTL.Duration() != 30*time.Minute {
		t.Fatalf("ttl = %s，期望 30m", holder.TTL)
	}

	if err := yaml.Unmarshal([]byte("ttl: 半小时\n"), &holder); err == nil {
		t.Error("非法时长写法应当报错")
	}
}

// TestVerdictSemantics 验证判定结论的短路与拒绝类语义。
func TestVerdictSemantics(t *testing.T) {
	shortCircuit := map[Verdict]bool{
		VerdictContinue:    false,
		VerdictAllow:       true,
		VerdictObserve:     false,
		VerdictBlock:       true,
		VerdictRateLimited: true,
	}
	for verdict, want := range shortCircuit {
		if got := verdict.IsShortCircuit(); got != want {
			t.Errorf("Verdict(%s).IsShortCircuit() = %v，期望 %v", verdict, got, want)
		}
	}

	// 观察模式命中了规则，但不属于拒绝类结论。
	if VerdictObserve.IsBlocking() {
		t.Error("VerdictObserve 不应被视为拒绝类结论")
	}
	if !VerdictBlock.IsBlocking() {
		t.Error("VerdictBlock 应被视为拒绝类结论")
	}
}

// TestRequestIDShape 验证请求标识为 26 位 Crockford Base32（ULID 形态）。
func TestRequestIDShape(t *testing.T) {
	id := NewRequestID(time.Unix(0, 1750000000000000000))
	if len(id) != 26 {
		t.Fatalf("请求标识长度 = %d，期望 26（%s）", len(id), id)
	}
	for _, r := range id {
		if !stringsContainsRune(crockford, r) {
			t.Fatalf("请求标识包含非法字符 %q（%s）", r, id)
		}
	}
	// 不同请求必须得到不同标识。
	other := NewRequestID(time.Unix(0, 1750000000000000001))
	if id == other {
		t.Fatal("两次生成的请求标识相同，随机性不足")
	}
}

// stringsContainsRune 判断字符表中是否包含指定字符（避免引入 strings 包依赖）。
func stringsContainsRune(set string, target rune) bool {
	for _, r := range set {
		if r == target {
			return true
		}
	}
	return false
}

// TestSiteMatches 验证站点 Host 匹配（含通配符的标签边界处理）。
func TestSiteMatches(t *testing.T) {
	site := &Site{Name: "default", Hosts: []string{"*.example.com", "exact.test"}}

	cases := map[string]bool{
		"a.example.com":      true,
		"deep.a.example.com": true,
		"exact.test":         true,
		// 必须按点分标签匹配，避免 aexample.com 误命中 *.example.com。
		"aexample.com": false,
		"example.com":  false,
		"other.test":   false,
	}
	for host, want := range cases {
		if got := site.Matches(host); got != want {
			t.Errorf("Site.Matches(%q) = %v，期望 %v", host, got, want)
		}
	}
}
