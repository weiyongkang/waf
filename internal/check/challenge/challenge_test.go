package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/weiyongkang/waf/internal/core"
)

type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time                  { return f.now }
func (f *fakeClock) Since(t time.Time) time.Duration { return f.now.Sub(t) }

func newChallenge(t *testing.T, settings map[string]any, clock core.Clock) *Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name: "challenge-test", Type: Type, Enabled: true, Phase: core.PhaseRequest, Settings: settings,
	}, &core.Deps{Clock: clock})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return check.(*Check)
}

func basicHeader(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func TestBasicAuthentication(t *testing.T) {
	check := newChallenge(t, map[string]any{
		"mode": "basic", "realm": "admin",
		"users": []any{map[string]any{"username": "alice", "password": "s3cret"}},
	}, &fakeClock{now: time.Unix(1700000000, 0)})

	rctx := core.NewRequestContext("test", time.Now())
	rctx.Raw.Header = http.Header{"Authorization": []string{basicHeader("alice", "s3cret")}}
	result, err := check.Evaluate(rctx)
	if err != nil || result != nil {
		t.Fatalf("valid basic auth rejected: result=%#v err=%v", result, err)
	}

	rctx.Raw.Header.Set("Authorization", basicHeader("alice", "wrong"))
	result, err = check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictUnauthorized {
		t.Fatalf("wrong password should be unauthorized: result=%#v err=%v", result, err)
	}
	if got := result.Headers["WWW-Authenticate"]; !strings.Contains(got, `realm="admin"`) {
		t.Fatalf("realm missing: %q", got)
	}
}

func TestSHA256Password(t *testing.T) {
	digest := sha256.Sum256([]byte("s3cret"))
	check := newChallenge(t, map[string]any{
		"mode": "basic",
		"users": []any{map[string]any{
			"username": "alice", "password_sha256": hex.EncodeToString(digest[:]),
		}},
	}, &fakeClock{now: time.Unix(1700000000, 0)})

	rctx := core.NewRequestContext("test", time.Now())
	rctx.Raw.Header = http.Header{"Authorization": []string{basicHeader("alice", "s3cret")}}
	result, err := check.Evaluate(rctx)
	if err != nil || result != nil {
		t.Fatalf("sha256 credential rejected: result=%#v err=%v", result, err)
	}
}

func TestCookieIssuedAndVerified(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	check := newChallenge(t, map[string]any{
		"mode": "cookie", "cookie_secure": false, "ttl": "1h",
		"secret": "0123456789abcdef0123456789abcdef",
		"users":  []any{map[string]any{"username": "alice", "password": "s3cret"}},
	}, clock)

	rctx := core.NewRequestContext("test", clock.now)
	rctx.Raw.Header = http.Header{"Authorization": []string{basicHeader("alice", "s3cret")}}
	result, err := check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictContinue {
		t.Fatalf("basic should mint cookie: result=%#v err=%v", result, err)
	}
	setCookie := result.Headers["Set-Cookie"]
	pair := strings.SplitN(setCookie, ";", 2)[0]
	if !strings.HasPrefix(pair, defaultCookieName+"=") {
		t.Fatalf("unexpected Set-Cookie: %q", setCookie)
	}

	rctx.Raw.Header = http.Header{"Cookie": []string{pair}}
	result, err = check.Evaluate(rctx)
	if err != nil || result != nil {
		t.Fatalf("valid cookie rejected: result=%#v err=%v", result, err)
	}

	rctx.Raw.Header.Set("Cookie", pair[:len(pair)-1]+"x")
	result, err = check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictUnauthorized {
		t.Fatalf("tampered cookie should be unauthorized: result=%#v err=%v", result, err)
	}

	clock.now = clock.now.Add(2 * time.Hour)
	rctx.Raw.Header.Set("Cookie", pair)
	result, err = check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictUnauthorized {
		t.Fatalf("expired cookie should be unauthorized: result=%#v err=%v", result, err)
	}
}

func TestCookieModeRequiresStrongSecret(t *testing.T) {
	_, err := New(core.InstanceConfig{
		Name: "bad", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{
			"mode": "cookie", "secret": "short",
			"users": []any{map[string]any{"username": "alice", "password": "s3cret"}},
		},
	}, &core.Deps{})
	if err == nil {
		t.Fatal("expected weak secret error")
	}
}

func TestSiteModeOverride(t *testing.T) {
	check := newChallenge(t, map[string]any{
		"mode":  "basic",
		"users": []any{map[string]any{"username": "alice", "password": "s3cret"}},
	}, &fakeClock{now: time.Unix(1700000000, 0)})
	rctx := core.NewRequestContext("test", time.Now())
	rctx.Site.Params = map[string]string{"challenge.mode": "cookie"}
	// 站点覆盖为 cookie 模式但实例没有 Cookie 密钥：运行期应继续走 Basic
	// 失败路径，而不是 panic；这里断言仍返回 401。
	result, err := check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictUnauthorized {
		t.Fatalf("site override should stay safe: result=%#v err=%v", result, err)
	}
}
