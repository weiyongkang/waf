// Package challenge 实现本地站点口令 / 人机校验单元（PhaseRequest）。
//
// 提供两种不依赖外部服务的认证方式：
//   - basic：校验 Authorization: Basic，浏览器可直接弹出原生登录框；
//   - cookie：校验 HMAC-SHA256 签名的短期 Cookie，Basic 认证成功后自动下发。
//
// 设计边界：不实现图形验证码或第三方 challenge 服务，也不在 WAF 内维护会话表；
// Cookie 是无状态签名令牌，适合 forward-auth 的多实例部署。
package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/weiyongkang/waf/internal/config"
	"github.com/weiyongkang/waf/internal/core"
)

// Type 是本实现的注册类型名。
const Type = "challenge"

const (
	modeBasic         = "basic"
	modeCookie        = "cookie"
	modeBasicOrCookie = "basic_or_cookie"

	defaultRealm      = "waf"
	defaultCookieName = "waf_auth"
	defaultTTL        = time.Hour
	defaultRuleID     = "challenge_required"
	minSecretBytes    = 16
)

func init() {
	core.RegisterCheck(Type, New)
}

// Settings 是 challenge 的私有配置片段。
type Settings struct {
	// Mode 是认证模式：basic / cookie / basic_or_cookie。
	Mode string `yaml:"mode"`
	// Realm 是 Basic 认证提示域。
	Realm string `yaml:"realm"`
	// Users 是允许访问的用户列表。
	Users []User `yaml:"users"`
	// CookieName 是签名 Cookie 名，默认 waf_auth。
	CookieName string `yaml:"cookie_name"`
	// CookiePath 是 Cookie 作用路径，默认 "/"。
	CookiePath string `yaml:"cookie_path"`
	// CookieSecure 控制是否添加 Secure 标记；默认 true。
	CookieSecure *bool `yaml:"cookie_secure"`
	// Secret 是 Cookie HMAC 密钥；cookie 模式必填，建议至少 32 字节随机值。
	Secret string `yaml:"secret"`
	// SecretFile 是密钥文件路径；与 Secret 二选一。
	SecretFile string `yaml:"secret_file"`
	// TTL 是签名 Cookie 有效期，默认 1h。
	TTL core.Duration `yaml:"ttl"`
	// RuleID 是未认证命中的规则标识。
	RuleID string `yaml:"rule_id"`
}

// User 是一个本地账号。
type User struct {
	Username string `yaml:"username"`
	// Password 是明文口令；与 PasswordSHA256 二选一。
	Password string `yaml:"password"`
	// PasswordSHA256 是口令的 SHA-256 十六进制摘要，优先于明文口令。
	PasswordSHA256 string `yaml:"password_sha256"`
}

type account struct {
	name           []byte
	password       []byte
	passwordSHA256 []byte
}

// Check 是本地挑战校验单元实例。
type Check struct {
	name         string
	phase        core.Phase
	order        int
	mode         string
	realm        string
	cookieName   string
	cookiePath   string
	cookieSecure bool
	secret       []byte
	ttl          time.Duration
	ruleID       string
	users        []account
	clock        core.Clock
}

// New 构造本地挑战校验单元。
func New(inst core.InstanceConfig, deps *core.Deps) (core.Check, error) {
	var settings Settings
	if err := core.DecodeSettings(inst.Settings, &settings); err != nil {
		return nil, err
	}
	mode := normalizeMode(settings.Mode)
	if mode == "" {
		return nil, fmt.Errorf("challenge.mode = %q 非法，可选值：basic / cookie / basic_or_cookie", settings.Mode)
	}
	realm := strings.TrimSpace(settings.Realm)
	if realm == "" {
		realm = defaultRealm
	}
	users, err := compileUsers(settings.Users)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("challenge.users 不能为空")
	}
	cookieName := strings.TrimSpace(settings.CookieName)
	if cookieName == "" {
		cookieName = defaultCookieName
	}
	if !validCookieName(cookieName) {
		return nil, fmt.Errorf("challenge.cookie_name = %q 非法，必须是合法的 HTTP token", cookieName)
	}
	cookiePath := strings.TrimSpace(settings.CookiePath)
	if cookiePath == "" {
		cookiePath = "/"
	}
	if !strings.HasPrefix(cookiePath, "/") {
		return nil, fmt.Errorf("challenge.cookie_path = %q 非法，必须以 / 开头", cookiePath)
	}
	cookieSecure := true
	if settings.CookieSecure != nil {
		cookieSecure = *settings.CookieSecure
	}
	ttl := settings.TTL.Duration()
	if ttl <= 0 {
		ttl = defaultTTL
	}
	ruleID := strings.TrimSpace(settings.RuleID)
	if ruleID == "" {
		ruleID = defaultRuleID
	}

	var secret []byte
	if mode == modeCookie || mode == modeBasicOrCookie {
		secret, err = loadSecret(settings)
		if err != nil {
			return nil, err
		}
	}
	return &Check{
		name: inst.Name, phase: inst.Phase, order: inst.Order,
		mode: mode, realm: realm, cookieName: cookieName, cookiePath: cookiePath,
		cookieSecure: cookieSecure, secret: secret, ttl: ttl, ruleID: ruleID,
		users: users, clock: deps.ClockOr(),
	}, nil
}

func (c *Check) Name() string      { return c.name }
func (c *Check) Type() string      { return Type }
func (c *Check) Phase() core.Phase { return c.phase }
func (c *Check) Order() int        { return c.order }

// Close 释放资源；本实现不持有后台 goroutine，方法仅用于满足 core.Check 契约。
func (c *Check) Close() error { return nil }

// DefaultOnError 返回失败关闭：认证能力自身异常时不能静默放行。
func (c *Check) DefaultOnError() string { return core.OnErrorBlock }

// Evaluate 校验 Authorization Basic 或签名 Cookie。
func (c *Check) Evaluate(rctx *core.RequestContext) (*core.Result, error) {
	if rctx == nil || rctx.Raw == nil {
		return nil, nil
	}
	mode := c.mode
	if raw, ok := rctx.Site.Param("challenge.mode"); ok {
		if normalized := normalizeMode(raw); normalized != "" {
			// 站点不能把「仅 Basic」的实例切换成 Cookie 模式：该实例没有
			// 配置 HMAC 密钥，签发出来的 Cookie 不具备任何安全强度。
			if len(c.secret) > 0 || normalized == modeBasic {
				mode = normalized
			}
		}
	}

	if mode == modeCookie || mode == modeBasicOrCookie {
		if c.cookieAuthenticated(rctx.Raw) {
			return nil, nil
		}
	}
	if mode == modeBasic || mode == modeBasicOrCookie || mode == modeCookie {
		username, password, ok := basicCredentials(rctx.Raw.HeaderValue("Authorization"))
		if ok && c.verifyUser(username, password) {
			if mode == modeBasic {
				return nil, nil
			}
			// cookie / basic_or_cookie：Basic 认证成功后下发短期签名 Cookie，
			// 后续请求不再重复传输口令。若代理不转发 Set-Cookie，浏览器会继续
			// 使用 Basic，认证仍然有效。
			return &core.Result{
				Verdict: core.VerdictContinue,
				Check:   c.name,
				Headers: map[string]string{
					"Set-Cookie": c.issueCookie(username),
					"Vary":       "Cookie, Authorization",
				},
			}, nil
		}
	}

	realm := c.realm
	if raw, ok := rctx.Site.Param("challenge.realm"); ok {
		realm = raw
	}
	message := "需要完成本地身份校验"
	result := core.NewResult(c.name, core.VerdictUnauthorized)
	result.Code = config.CodeUnauthorized
	result.Message = message
	result.Headers = map[string]string{"Vary": "Cookie, Authorization"}
	if mode == modeBasic || mode == modeBasicOrCookie {
		result.Headers["WWW-Authenticate"] = fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, escapeRealm(realm))
	} else {
		result.Headers["X-WAF-Challenge"] = "cookie"
	}
	result.AddFinding(core.NewFinding(c.name, c.ruleID, message, core.SeverityLow, 0))
	return result, nil
}

func (c *Check) verifyUser(username, password string) bool {
	passwordBytes := []byte(password)
	passwordDigest := sha256.Sum256(passwordBytes)
	matched := false
	for _, user := range c.users {
		nameOK := subtle.ConstantTimeCompare(user.name, []byte(username)) == 1
		passwordOK := false
		if len(user.passwordSHA256) > 0 {
			passwordOK = subtle.ConstantTimeCompare(user.passwordSHA256, passwordDigest[:]) == 1
		} else {
			passwordOK = subtle.ConstantTimeCompare(user.password, passwordBytes) == 1
		}
		if nameOK && passwordOK {
			matched = true
		}
	}
	return matched
}

func (c *Check) cookieAuthenticated(raw *core.RawRequest) bool {
	request := &http.Request{Header: raw.Header}
	for _, cookie := range request.Cookies() {
		if cookie.Name != c.cookieName {
			continue
		}
		return c.verifyCookie(cookie.Value)
	}
	return false
}

func (c *Check) issueCookie(username string) string {
	expires := c.clock.Now().Add(c.ttl).Unix()
	payload := username + "|" + strconv.FormatInt(expires, 10)
	token := encodeToken(payload, c.secret)
	attributes := []string{
		c.cookieName + "=" + token,
		"Path=" + c.cookiePath,
		"Max-Age=" + strconv.Itoa(int(c.ttl.Seconds()+0.5)),
		"HttpOnly",
		"SameSite=Lax",
	}
	if c.cookieSecure {
		attributes = append(attributes, "Secure")
	}
	return strings.Join(attributes, "; ")
}

func (c *Check) verifyCookie(value string) bool {
	if len(value) > 4096 {
		return false
	}
	payload, ok := decodeToken(value, c.secret)
	if !ok {
		return false
	}
	index := strings.LastIndexByte(payload, '|')
	if index <= 0 || index == len(payload)-1 {
		return false
	}
	username := payload[:index]
	expires, err := strconv.ParseInt(payload[index+1:], 10, 64)
	if err != nil || c.clock.Now().Unix() >= expires {
		return false
	}
	for _, user := range c.users {
		if subtle.ConstantTimeCompare(user.name, []byte(username)) == 1 {
			return true
		}
	}
	return false
}

func encodeToken(payload string, secret []byte) string {
	signature := sign(payload, secret)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func decodeToken(value string, secret []byte) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	expected := sign(string(payloadBytes), secret)
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return "", false
	}
	return string(payloadBytes), true
}

func sign(payload string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func basicCredentials(header string) (string, string, bool) {
	scheme, encoded, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" {
		return "", "", false
	}
	return username, password, true
}

func compileUsers(settings []User) ([]account, error) {
	users := make([]account, 0, len(settings))
	seen := make(map[string]struct{}, len(settings))
	for index, item := range settings {
		username := strings.TrimSpace(item.Username)
		if username == "" {
			return nil, fmt.Errorf("challenge.users[%d].username 不能为空", index)
		}
		if _, duplicate := seen[username]; duplicate {
			return nil, fmt.Errorf("challenge.users[%d].username = %q 重复", index, username)
		}
		seen[username] = struct{}{}
		user := account{name: []byte(username)}
		hashText := strings.TrimSpace(item.PasswordSHA256)
		switch {
		case hashText != "":
			decoded, err := hex.DecodeString(hashText)
			if err != nil || len(decoded) != sha256.Size {
				return nil, fmt.Errorf("challenge.users[%d].password_sha256 必须是 64 位十六进制 SHA-256", index)
			}
			user.passwordSHA256 = decoded
		case item.Password != "":
			user.password = []byte(item.Password)
		default:
			return nil, fmt.Errorf("challenge.users[%d] 必须配置 password 或 password_sha256", index)
		}
		users = append(users, user)
	}
	return users, nil
}

func loadSecret(settings Settings) ([]byte, error) {
	secret := strings.TrimSpace(settings.Secret)
	file := strings.TrimSpace(settings.SecretFile)
	if secret != "" && file != "" {
		return nil, fmt.Errorf("challenge.secret 与 challenge.secret_file 不能同时配置")
	}
	if file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("读取 challenge.secret_file 失败：%w", err)
		}
		secret = strings.TrimSpace(string(content))
	}
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("challenge 的 Cookie 模式要求密钥至少 %d 字节（secret 或 secret_file）", minSecretBytes)
	}
	return []byte(secret), nil
}

func normalizeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return modeBasic
	case modeBasic:
		return modeBasic
	case modeCookie:
		return modeCookie
	case modeBasicOrCookie:
		return modeBasicOrCookie
	default:
		return ""
	}
}

func validCookieName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", char):
		default:
			return false
		}
	}
	return true
}

func escapeRealm(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
