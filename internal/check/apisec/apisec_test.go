package apisec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/weiyongkang/waf/internal/core"
)

const specYAML = `openapi: 3.0.3
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: integer
    get:
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              additionalProperties: false
              properties:
                name:
                  type: string
                  minLength: 2
`

func writeSpec(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(specYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newCheck(t *testing.T, settings map[string]any, phase core.Phase) *Check {
	t.Helper()
	check, err := New(core.InstanceConfig{
		Name: "apisec-test", Type: Type, Enabled: true, Phase: phase, Settings: settings,
	}, &core.Deps{Limits: core.Limits{MaxConfigFileBytes: 1 << 20, MaxScanTokenBytes: 1 << 20}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	return check.(*Check)
}

func requestContext(method, path, query string, body []byte) *core.RequestContext {
	rctx := core.NewRequestContext("test", core.SystemClock{}.Now())
	rctx.Raw.Method = method
	rctx.Raw.Path = path
	rctx.Raw.RawQuery = query
	rctx.Raw.Header = map[string][]string{}
	if body != nil {
		rctx.Stream = &memoryStream{Reader: bytes.NewReader(body)}
	}
	return rctx
}

type memoryStream struct {
	*bytes.Reader
}

func (m *memoryStream) Rewind() error {
	_, err := m.Seek(0, 0)
	return err
}

func (m *memoryStream) Meta() core.BodyMeta { return core.BodyMeta{Present: true} }
func (m *memoryStream) Close() error        { return nil }

func TestEvaluateParameters(t *testing.T) {
	check := newCheck(t, map[string]any{
		"spec_file": writeSpec(t), "action": "block", "check_body": false, "hot_reload": false,
		"unknown_action": "off",
	}, core.PhaseRequest)

	result, err := check.Evaluate(requestContext("GET", "/users/42", "q=ok", nil))
	if err != nil || result != nil {
		t.Fatalf("valid request: result=%#v err=%v", result, err)
	}

	result, err = check.Evaluate(requestContext("GET", "/users/42", "", nil))
	if err != nil || result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("missing query should block: result=%#v err=%v", result, err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(result.Findings))
	}
}

func TestEvaluateUnknownAndObserve(t *testing.T) {
	check := newCheck(t, map[string]any{
		"spec_file": writeSpec(t), "action": "observe", "check_body": false, "hot_reload": false,
		"unknown_action": "observe",
	}, core.PhaseRequest)

	result, err := check.Evaluate(requestContext("GET", "/missing", "", nil))
	if err != nil || result == nil || result.Verdict != core.VerdictObserve || !result.WouldBlock {
		t.Fatalf("unknown route observe: result=%#v err=%v", result, err)
	}
}

func TestEvaluateJSONBody(t *testing.T) {
	check := newCheck(t, map[string]any{
		"spec_file": writeSpec(t), "action": "block", "check_body": true, "hot_reload": false,
	}, core.PhaseBody)

	validCtx := requestContext("POST", "/users/42", "q=ok", []byte(`{"name":"alice"}`))
	validCtx.Raw.Header.Set("Content-Type", "application/json")
	result, err := check.Evaluate(validCtx)
	if err != nil || result != nil {
		t.Fatalf("valid body: result=%#v err=%v", result, err)
	}

	rctx := requestContext("POST", "/users/42", "q=ok", []byte(`{"name":"a","admin":true}`))
	rctx.Raw.Header.Set("Content-Type", "application/json")
	result, err = check.Evaluate(rctx)
	if err != nil || result == nil || result.Verdict != core.VerdictBlock {
		t.Fatalf("invalid body should block: result=%#v err=%v", result, err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected two findings, got %d: %#v", len(result.Findings), result.Findings)
	}
	// 检查后请求体游标必须复位，后续 PhaseBody 单元仍能读取完整内容。
	payload := make([]byte, 64)
	n, _ := rctx.Stream.Read(payload)
	if string(payload[:n]) != `{"name":"a","admin":true}` {
		t.Fatalf("stream not rewound: %q", payload[:n])
	}
}

func TestNewRejectsBodyCheckOutsideBodyPhase(t *testing.T) {
	_, err := New(core.InstanceConfig{
		Name: "bad", Type: Type, Enabled: true, Phase: core.PhaseRequest,
		Settings: map[string]any{"spec_file": writeSpec(t), "check_body": true},
	}, &core.Deps{Limits: core.Limits{MaxConfigFileBytes: 1 << 20}})
	if err == nil {
		t.Fatal("expected phase validation error")
	}
}
