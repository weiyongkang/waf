package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/weiyongkang/waf/internal/core"
)

// directExtract 是「直通适配器」：不做任何注入头还原，直接把鉴权子请求自身
// 当作原始请求使用。
//
// 使用场景与限制（重要）：
//   - 仅用于本地自检（curl 直接访问 /waf/auth）与单元测试；
//   - 生产环境必须使用 ingress/forwardauth 提供的适配器（T5 交付），
//     否则真实流量下的 URI/Method/客户端 IP 会全部错误。
func directExtract(r *http.Request) (*core.RawRequest, error) {
	if r == nil || r.URL == nil {
		return nil, errors.New("鉴权子请求为空或缺少 URL")
	}

	raw := &core.RawRequest{
		Method:        r.Method,
		URI:           r.URL.RequestURI(),
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		Host:          r.Host,
		Proto:         r.Proto,
		Header:        r.Header.Clone(),
		ClientIP:      remoteIP(r.RemoteAddr),
		ContentLength: r.ContentLength,
		// 直通形态下，鉴权子请求自身的请求体就是「原始请求体」。
		Body: r.Body,
	}
	return raw, nil
}

// remoteIP 从 RemoteAddr 中剥离端口，返回纯 IP。
func remoteIP(remoteAddr string) string {
	if index := strings.LastIndex(remoteAddr, ":"); index > 0 {
		return strings.Trim(remoteAddr[:index], "[]")
	}
	return remoteAddr
}

// jsonEncoder 构造禁用 HTML 转义的 JSON 编码器，保证输出中的 < > & 原样可读。
func jsonEncoder(w io.Writer) *json.Encoder {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder
}

// discardWriter 是丢弃全部写入的 io.Writer，仅用于兜底日志器。
type discardWriter struct{}

// Write 丢弃全部数据并报告写入成功。
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
