// Package onlyoffice 对接 ONLYOFFICE Docs（文档编辑服务）。
//
// 安全模型（六步，缺一步就有一个可被利用的洞）：
//  1. 回调必须带 JWT           —— 否则任何能访问回调地址的人都能写入文件
//  2. JWT 签名必须正确          —— 防伪造
//  3. JWT 未过期                —— 防重放
//  4. status 在白名单内          —— 否则可用未知状态触发意外分支
//  5. 回传 URL 的主机在白名单内  —— 这是 SSRF 防护的核心：不校验就等于"任意 URL 下载器"
//  6. 回调内的 key 必须能对应到一个有权限的节点 —— 防"用 A 的回调写 B 的文件"
package onlyoffice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 回调错误分类。
var (
	ErrTokenMissing  = errors.New("缺少回调令牌")
	ErrTokenInvalid  = errors.New("回调令牌无效")
	ErrTokenExpired  = errors.New("回调令牌已过期")
	ErrBadStatus     = errors.New("未知的回调状态")
	ErrURLNotAllowed = errors.New("回传地址不在允许范围内")
)

// 文档服务回调状态码（官方定义）。
const (
	StatusEditing      = 1 // 正在编辑（有人连上编辑器）
	StatusMustSave     = 2 // 需要保存（编辑结束，该下载了）
	StatusSaveError    = 3 // 保存出错
	StatusClosed       = 4 // 无人在编辑，无需保存
	StatusForceSave    = 6 // 强制保存（编辑器内点保存）
	StatusForceSaveErr = 7 // 强制保存出错
)

// Config 是文档服务配置。
type Config struct {
	// URL 是文档服务对外地址，例如 http://onlyoffice:8080
	URL string
	// PublicURL 是本系统对文档服务可达的地址（回调、文件下载都走它）
	PublicURL string
	// InternalURL 是本系统访问文档服务的**内部**地址（容器网络内）。
	//
	// 为什么需要：文档服务回传的下载地址是用"浏览器访问它时用的 Host"拼的
	// （例如 http://127.0.0.1:18091/cache/...）。那个地址在浏览器里可用，
	// 在服务端容器里却是它自己的回环地址——实测就是 connection refused，
	// 表现是"编辑器里提示保存失败、库里不产生新版本"。
	// 这里把这样的地址改写为内部服务名再抓取。
	InternalURL string
	Secret      string
	// AllowedHosts 是允许从回调里下载文件的主机名白名单（通常只有文档服务主机）
	AllowedHosts []string
	// MaxCallbackBytes 单次回传文件大小上限
	MaxCallbackBytes int64
	Timeout          time.Duration
}

// Service 封装签发配置、校验回调与下载。
type Service struct {
	cfg  Config
	http *http.Client
	now  func() time.Time
}

// New 构造服务。未配置 URL/Secret 时返回 nil（编辑器功能关闭）。
func New(cfg Config) *Service {
	if cfg.URL == "" || cfg.Secret == "" {
		return nil
	}
	if cfg.MaxCallbackBytes <= 0 {
		cfg.MaxCallbackBytes = 512 << 20 // 512MB
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Service{
		cfg: cfg,
		http: &http.Client{
			Timeout: cfg.Timeout,
			// 不自动跟随跳转：跳转是绕过主机白名单最常用的手法
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
}

// URL 返回文档服务地址（前端加载 api.js 用）。
func (s *Service) URL() string { return s.cfg.URL }

// PublicURL 返回本系统对外的地址。
func (s *Service) PublicURL() string { return s.cfg.PublicURL }

// EditorConfig 是给前端的编辑器配置（已签名）。
type EditorConfig struct {
	DocumentServerURL string
	Config            map[string]any
	Token             string
}

// BuildEditorConfig 组装并签名编辑器配置。
//
// key 里带 nodeID 与 tenantID：回调时据此定位对象，
// 且**不能**由客户端传入，否则可以伪造"编辑别人的文件"。
func (s *Service) BuildEditorConfig(nodeID, tenantID, userID, userName, fileName, mode string) (EditorConfig, error) {
	if mode != "edit" && mode != "view" {
		mode = "view"
	}
	ext := strings.TrimPrefix(strings.ToLower(filepathExt(fileName)), ".")
	if ext == "" {
		ext = "docx"
	}

	cfg := map[string]any{
		"document": map[string]any{
			"fileType": ext,
			"key":      documentKey(nodeID, mode),
			"title":    fileName,
			// 文档服务不会带我们的访问令牌，因此这里用"签名 URL"：
			// 有效期短、只对这一个节点有效，泄漏也只能取到这一份文件
			"url": s.SignFileURL(nodeID, tenantID),
			"permissions": map[string]any{
				"edit":     mode == "edit",
				"download": true,
				"print":    true,
			},
		},
		"documentType": documentType(ext),
		"editorConfig": map[string]any{
			"mode": mode,
			// callbackUrl 必须显式给出：文档服务靠它把保存结果回传。
			// 缺了它编辑器仍能打开、也能编辑，但**永远不会保存**——
			// 这是最难在联调中发现的一类配置遗漏。
			"callbackUrl": strings.TrimRight(s.cfg.PublicURL, "/") + "/v1/onlyoffice/callback",
			"user":        map[string]any{"id": userID, "name": userName},
			"customization": map[string]any{
				"autosave":  true,
				"forcesave": true,
				"chat":      false,
				"comments":  mode == "edit",
				"goback":    map[string]any{"text": "返回 NeuroDMS", "url": s.cfg.PublicURL + "/files"},
			},
		},
		"height": "100%",
		"width":  "100%",
	}

	// 关键：JWT 的 payload 必须是**配置对象本身**。
	// ONLYOFFICE 在 JWT_ENABLED 时会把 token 解开与收到的 config 逐字段比对，
	// 用自定义 claim（比如只放 nodeId）会被判为"安全令牌格式错误"。
	token, err := SignJWT(s.cfg.Secret, cfg)
	if err != nil {
		return EditorConfig{}, err
	}
	cfg["token"] = token
	return EditorConfig{DocumentServerURL: s.cfg.URL, Config: cfg, Token: token}, nil
}

// SignFileURL 生成供文档服务下载的签名 URL。
//
// 为什么不用普通访问令牌：文档服务无法附加自定义 Authorization 头，
// 而把长期令牌放进 URL 会进它的日志与缓存——所以用短时、单对象签名。
func (s *Service) SignFileURL(nodeID, tenantID string) string {
	exp := s.now().Add(2 * time.Hour).Unix()
	sig := s.signFile(nodeID, tenantID, exp)
	return fmt.Sprintf("%s/v1/onlyoffice/file/%s?t=%s&e=%d&s=%s",
		strings.TrimRight(s.cfg.PublicURL, "/"), nodeID, url.QueryEscape(tenantID), exp, sig)
}

// VerifyFileURL 校验签名 URL。返回租户 ID。
func (s *Service) VerifyFileURL(nodeID, tenantID, expStr, sig string) bool {
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || s.now().Unix() > exp {
		return false
	}
	want := s.signFile(nodeID, tenantID, exp)
	return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1
}

func (s *Service) signFile(nodeID, tenantID string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	fmt.Fprintf(mac, "file|%s|%s|%d", nodeID, tenantID, exp)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// callbackPayload 是回传体的最小必要字段。
type callbackPayload struct {
	Key    string   `json:"key"`
	Status int      `json:"status"`
	URL    string   `json:"url"`
	Users  []string `json:"users"`
}

// Callback 是校验通过的回调。
// Callback 是解析并通过校验后的回调。
//
// 没有 TenantID：回调体里不带租户，而"用载荷里的租户"是不可靠的
// （载荷由文档服务按回调体签发，本来就没有租户字段）。
// 租户由调用方按 NodeID 查库得到——这也顺带保证了工单式交叉校验。
type Callback struct {
	NodeID string
	UserID string
	Status int
	URL    string
}

// ParseCallback 执行第 1~4 步校验并解析回调。
func (s *Service) ParseCallback(token string, body []byte) (Callback, error) {
	if token == "" {
		return Callback{}, ErrTokenMissing
	}
	claims, err := VerifyJWT(s.cfg.Secret, token)
	if err != nil {
		return Callback{}, err
	}
	if exp, ok := claims["exp"].(float64); ok && s.now().Unix() > int64(exp) {
		return Callback{}, ErrTokenExpired
	}

	var p callbackPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return Callback{}, fmt.Errorf("回调体解析失败: %w", err)
	}
	switch p.Status {
	case StatusEditing, StatusMustSave, StatusSaveError, StatusClosed, StatusForceSave, StatusForceSaveErr:
	default:
		return Callback{}, ErrBadStatus
	}

	out := Callback{Status: p.Status, URL: p.URL}

	// 第 6 步：从 key 反解 nodeID。key 由本系统签发（"{nodeID}-{mode}-{hour}"），
	// 文档服务只是原样回传，因此可用它把回调锚定到确定的节点——
	// 不接受回调里的任何"我自己是谁"的自述字段。
	nodeID, err := nodeIDFromKey(p.Key)
	if err != nil {
		return Callback{}, err
	}
	// 若 token 载荷里也带了 key，必须与体一致（防止 token 与体拼接）
	if ck, ok := claims["key"].(string); ok && ck != "" && ck != p.Key {
		return Callback{}, ErrTokenInvalid
	}
	out.NodeID = nodeID
	// 操作人身份优先取**签名载荷**里的，而不是回调体里的。
	//
	// 回调体里的 users 由文档服务回传，而编辑器配置（含 JWT）本身是发给浏览器的：
	// 任何能打开编辑器的人都拿得到 token，也就能构造一份 users 指向别人的回调体，
	// 把"谁保存了这版内容"栽给同事。token 里的 editorConfig.user.id 是本系统
	// 签发时写入的，改不动，因此以它为准；只有在载荷里确实没有时才退回回调体。
	if uid := userIDFromClaims(claims); uid != "" {
		out.UserID = uid
	} else if len(p.Users) > 0 {
		out.UserID = p.Users[0]
	}
	return out, nil
}

// userIDFromClaims 从已验签的配置载荷里取 editorConfig.user.id。
// 载荷结构由 BuildEditorConfig 决定，任何一层类型不符都返回空串（由调用方退回）。
func userIDFromClaims(claims map[string]any) string {
	ec, ok := claims["editorConfig"].(map[string]any)
	if !ok {
		return ""
	}
	user, ok := ec["user"].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := user["id"].(string)
	return id
}

// nodeIDFromKey 从文档 key 中反解节点 ID。
//
// key 形如 "3f2b...-edit-498369"（nodeID-mode-hour）。nodeID 是带连字符的 UUID，
// 因此从**尾部**剥掉 mode 与 hour 两段，剩下的原样拼回，不能按固定索引切。
func nodeIDFromKey(key string) (string, error) {
	parts := strings.Split(key, "-")
	if len(parts) < 3 {
		return "", ErrTokenInvalid
	}
	mode := parts[len(parts)-2]
	if mode != "edit" && mode != "view" {
		return "", ErrTokenInvalid
	}
	if _, err := strconv.ParseInt(parts[len(parts)-1], 10, 64); err != nil {
		return "", ErrTokenInvalid
	}
	nodeID := strings.Join(parts[:len(parts)-2], "-")
	if len(nodeID) < 8 {
		return "", ErrTokenInvalid
	}
	return nodeID, nil
}

// NeedsSave 表示该状态要求下载回传文件。
func (c Callback) NeedsSave() bool {
	return c.Status == StatusMustSave || c.Status == StatusForceSave || c.Status == StatusSaveError
}

// FetchDocument 执行第 5 步校验后下载回传文件。
func (s *Service) FetchDocument(ctx context.Context, rawURL string) ([]byte, error) {
	if rawURL == "" {
		return nil, errors.New("缺少回传地址")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrURLNotAllowed
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrURLNotAllowed
	}

	// 把"浏览器视角的文档服务地址"改写为"服务端可达的内部地址"。
	// 只在主机与配置的对外地址一致时改写，避免变成任意代理。
	if s.cfg.InternalURL != "" {
		if pub, perr := url.Parse(s.cfg.URL); perr == nil && pub.Host == u.Host {
			if in, ierr := url.Parse(s.cfg.InternalURL); ierr == nil && in.Host != "" {
				u.Scheme, u.Host = in.Scheme, in.Host
			}
		}
	}
	if !s.hostAllowed(u.Host) {
		return nil, ErrURLNotAllowed
	}
	fetchURL := u.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载回传文件失败: %d", resp.StatusCode)
	}
	if resp.ContentLength > s.cfg.MaxCallbackBytes {
		return nil, fmt.Errorf("回传文件超过上限（%d 字节）", s.cfg.MaxCallbackBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxCallbackBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > s.cfg.MaxCallbackBytes {
		return nil, fmt.Errorf("回传文件超过上限（%d 字节）", s.cfg.MaxCallbackBytes)
	}
	return data, nil
}

// hostAllowed 比对主机名（忽略端口）。
//
// 用"主机名"而不是整段 URL 前缀：前缀匹配会被
// http://onlyoffice.evil.com 这类地址绕过（前缀相同、域名不同）。
func (s *Service) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, a := range s.cfg.AllowedHosts {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if a == host {
			return true
		}
	}
	return false
}

func filepathExt(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 && i < len(name)-1 {
		return name[i:]
	}
	return ""
}

func documentType(ext string) string {
	switch ext {
	case "doc", "docx", "odt", "rtf", "txt", "pdf", "epub":
		return "word"
	case "xls", "xlsx", "ods", "csv":
		return "cell"
	case "ppt", "pptx", "odp":
		return "slide"
	default:
		return "word"
	}
}

// documentKey 生成文档服务的缓存 key。
// 必须随"版本"变化，否则文档服务会一直用旧缓存，用户看不到新内容。
// 这里用 nodeID + 时间片：同一节点 1 小时内共用一个 key（便于协同），跨小时新开。
func documentKey(nodeID, mode string) string {
	return fmt.Sprintf("%s-%s-%d", nodeID, mode, time.Now().Unix()/3600)
}

// ---------------- 极简 HS256 JWT ----------------
//
// 不引第三方库：只需要 HS256 签发/校验，自己实现 60 行比引入依赖更可控，
// 且能明确拒绝 alg=none 与算法混淆。

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SignJWT 用 HS256 签发 JWT。
func SignJWT(secret string, claims map[string]any) (string, error) {
	if secret == "" {
		return "", errors.New("JWT 密钥为空")
	}
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(p)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil)), nil
}

// VerifyJWT 校验 HS256 JWT 并返回 claims。
func VerifyJWT(secret, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var head struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hb, &head); err != nil || head.Alg != "HS256" {
		// 明确拒绝 none 与其它算法：算法混淆是 JWT 最经典的攻击面
		return nil, ErrTokenInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return nil, ErrTokenInvalid
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}
