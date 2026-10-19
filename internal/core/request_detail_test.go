package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// memoryBodyStream 是测试用可回绕请求体流。
type memoryBodyStream struct {
	data []byte
	pos  int
	meta BodyMeta
}

func (s *memoryBodyStream) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}

func (s *memoryBodyStream) Rewind() error  { s.pos = 0; return nil }
func (s *memoryBodyStream) Meta() BodyMeta { return s.meta }
func (s *memoryBodyStream) Close() error   { return nil }

// TestCaptureRequestParamsRedactsAndRewinds 覆盖查询串与 JSON 请求体采集、
// 敏感字段脱敏，以及采集后请求体仍可从起点被后续校验单元读取。
func TestCaptureRequestParamsRedactsAndRewinds(t *testing.T) {
	body := []byte(`{"name":"alice","password":"p@ss","nested":{"api_key":"secret-key"}}`)
	stream := &memoryBodyStream{data: body, meta: BodyMeta{Present: true, Bytes: int64(len(body))}}
	rctx := NewRequestContext("req-params", SystemClock{}.Now())
	rctx.Raw.RawQuery = "id=7&password=query-secret&token=abc"
	rctx.Raw.Header = http.Header{"Content-Type": []string{"application/json"}}
	rctx.Stream = stream

	params := CaptureRequestParams(rctx, 4096)
	if params.Query["id"] != "7" {
		t.Fatalf("查询参数 id = %#v", params.Query["id"])
	}
	if params.Query["password"] != "[REDACTED]" || params.Query["token"] != "[REDACTED]" {
		t.Fatalf("查询串敏感字段未脱敏：%#v", params.Query)
	}
	if params.Body["name"] != "alice" {
		t.Fatalf("JSON 请求体 name = %#v", params.Body["name"])
	}
	if params.Body["password"] != "[REDACTED]" {
		t.Fatalf("请求体 password 未脱敏：%#v", params.Body["password"])
	}
	nested, _ := params.Body["nested"].(map[string]any)
	if nested["api_key"] != "[REDACTED]" {
		t.Fatalf("嵌套敏感字段未脱敏：%#v", nested)
	}

	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("采集后读取请求体失败：%v", err)
	}
	if !bytes.Equal(raw, body) {
		t.Fatalf("采集后请求体未回绕：%q", raw)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(params.JSON()), &decoded); err != nil {
		t.Fatalf("参数快照不是合法 JSON：%v", err)
	}
}

// TestCaptureRequestParamsFormAndTruncation 覆盖 form 请求体与超限标记。
func TestCaptureRequestParamsFormAndTruncation(t *testing.T) {
	form := []byte("user=bob&password=form-secret&scope=read")
	rctx := NewRequestContext("req-form", SystemClock{}.Now())
	rctx.Raw.Header = http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	rctx.Stream = &memoryBodyStream{data: form, meta: BodyMeta{Present: true, Bytes: int64(len(form))}}

	params := CaptureRequestParams(rctx, 4096)
	if params.Body["user"] != "bob" || params.Body["password"] != "[REDACTED]" {
		t.Fatalf("form 参数解析或脱敏失败：%#v", params.Body)
	}

	rctx.Stream = &memoryBodyStream{data: form, meta: BodyMeta{Present: true, Bytes: int64(len(form))}}
	truncated := CaptureRequestParams(rctx, 8)
	if !truncated.BodyTruncated {
		t.Fatal("请求体超过采集上限时必须标记 body_truncated")
	}
}
