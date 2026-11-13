package onlyoffice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	return New(Config{
		URL:          "http://onlyoffice:8080",
		PublicURL:    "http://docvault:18090",
		Secret:       "onlyoffice-secret-0123456789abcdef",
		AllowedHosts: []string{"onlyoffice"},
	})
}

func TestBuildEditorConfigBindsNodeAndSigns(t *testing.T) {
	s := newSvc(t)
	ec, err := s.BuildEditorConfig("node-1", "tenant-1", "user-1", "张三", "报价单.docx", "edit")
	if err != nil {
		t.Fatal(err)
	}
	if ec.DocumentServerURL != "http://onlyoffice:8080" {
		t.Fatalf("文档服务地址不符: %s", ec.DocumentServerURL)
	}
	doc := ec.Config["document"].(map[string]any)
	if doc["fileType"] != "docx" {
		t.Fatalf("fileType 应为 docx，实际 %v", doc["fileType"])
	}
	if !strings.Contains(doc["url"].(string), "/v1/onlyoffice/file/node-1") {
		t.Fatalf("文档下载地址应指向本系统节点: %v", doc["url"])
	}
	if ec.Config["documentType"] != "word" {
		t.Fatalf("documentType 应为 word，实际 %v", ec.Config["documentType"])
	}

	// callbackUrl 是保存链路的唯一入口，缺失时编辑器能打开但永不保存
	editorCfg := ec.Config["editorConfig"].(map[string]any)
	cb, _ := editorCfg["callbackUrl"].(string)
	if !strings.HasSuffix(cb, "/v1/onlyoffice/callback") || !strings.HasPrefix(cb, "http://docvault:18090") {
		t.Fatalf("callbackUrl 必须指向本系统回调端点: %q", cb)
	}

	// JWT 的 payload 必须是配置对象本身：ONLYOFFICE 会逐字段与收到的 config 比对，
	// 自定义 claim 会被判为"安全令牌格式错误"。
	claims, err := VerifyJWT("onlyoffice-secret-0123456789abcdef", ec.Token)
	if err != nil {
		t.Fatalf("配置里的 token 应可校验: %v", err)
	}
	if _, ok := claims["document"]; !ok {
		t.Fatalf("token 载荷应是完整配置对象，实际键: %v", keysOf(claims))
	}
	docClaim, _ := claims["document"].(map[string]any)
	if !strings.Contains(docClaim["url"].(string), "node-1") {
		t.Fatalf("配置载荷里的文档地址应绑定节点: %v", docClaim["url"])
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestViewModeDisablesEditPermission(t *testing.T) {
	s := newSvc(t)
	ec, err := s.BuildEditorConfig("n", "t", "u", "x", "a.xlsx", "view")
	if err != nil {
		t.Fatal(err)
	}
	doc := ec.Config["document"].(map[string]any)
	perms := doc["permissions"].(map[string]any)
	if perms["edit"] != false {
		t.Fatalf("view 模式必须关闭编辑权限，实际 %v", perms)
	}
	if ec.Config["documentType"] != "cell" {
		t.Fatalf("xlsx 应为 cell 类型，实际 %v", ec.Config["documentType"])
	}
}

// signBody 模拟文档服务：把**回调体本身**作为 JWT 载荷签名。
func signBody(t *testing.T, secret string, body map[string]any) (string, []byte) {
	t.Helper()
	tok, err := SignJWT(secret, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return tok, raw
}

func TestParseCallbackRejectsMissingAndForgedToken(t *testing.T) {
	s := newSvc(t)
	body := map[string]any{"key": "node-1-edit-1750000000", "status": 2, "url": "http://onlyoffice/cache/1"}

	if _, err := s.ParseCallback("", mustJSON(t, body)); err != ErrTokenMissing {
		t.Fatalf("缺 token 应拒绝，实际 %v", err)
	}

	forged, raw := signBody(t, "wrong-secret-wrong-secret-wrong-1", body)
	if _, err := s.ParseCallback(forged, raw); err != ErrTokenInvalid {
		t.Fatalf("错误签名应拒绝，实际 %v", err)
	}
}

func TestParseCallbackRejectsAlgNone(t *testing.T) {
	s := newSvc(t)
	body := map[string]any{"key": "node-1-edit-1750000000", "status": 2, "url": "http://onlyoffice/x"}
	// 手工构造 alg=none：header 声明 none，无签名
	token := b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64(mustJSON(t, body)) + "."
	if _, err := s.ParseCallback(token, mustJSON(t, body)); err != ErrTokenInvalid {
		t.Fatalf("alg=none 必须拒绝，实际 %v", err)
	}
}

func TestParseCallbackRejectsExpired(t *testing.T) {
	s := newSvc(t)
	body := map[string]any{"key": "node-1-edit-1750000000", "status": 2, "url": "http://onlyoffice/x"}
	payload := map[string]any{
		"key": body["key"], "status": 2, "url": body["url"],
		"exp": time.Now().Add(-time.Minute).Unix(),
	}
	expired, _ := SignJWT(s.cfg.Secret, payload)
	if _, err := s.ParseCallback(expired, mustJSON(t, body)); err != ErrTokenExpired {
		t.Fatalf("过期 token 必须拒绝，实际 %v", err)
	}
}

func TestParseCallbackRejectsUnknownStatus(t *testing.T) {
	s := newSvc(t)
	body := map[string]any{"key": "node-1-edit-1750000000", "status": 99, "url": "http://onlyoffice/x"}
	tok, raw := signBody(t, s.cfg.Secret, body)
	if _, err := s.ParseCallback(tok, raw); err != ErrBadStatus {
		t.Fatalf("未知状态必须拒绝，实际 %v", err)
	}
}

// 最关键的一条：token 必须与体一致。
// 否则可以拿"A 节点"的合法令牌，配上"B 节点"的体，写到别人的文件上。
func TestParseCallbackRejectsTokenBodyMismatch(t *testing.T) {
	s := newSvc(t)
	signedBody := map[string]any{"key": "node-B-edit-1750000000", "status": 2, "url": "http://onlyoffice/x"}
	tok, _ := signBody(t, s.cfg.Secret, signedBody)

	actual := mustJSON(t, map[string]any{"key": "node-A-edit-1750000000", "status": 2, "url": "http://onlyoffice/x"})
	if _, err := s.ParseCallback(tok, actual); err != ErrTokenInvalid {
		t.Fatalf("token 与体不一致必须拒绝，实际 %v", err)
	}
}

func TestParseCallbackAcceptsValidForcedSave(t *testing.T) {
	s := newSvc(t)
	body := map[string]any{
		"key":    "3f2b1c4d-aaaa-bbbb-cccc-1234567890ab-edit-1750000000",
		"status": 6, "url": "http://onlyoffice/cache/1", "users": []string{"u1"},
	}
	tok, raw := signBody(t, s.cfg.Secret, body)
	cb, err := s.ParseCallback(tok, raw)
	if err != nil {
		t.Fatalf("合法回调应通过: %v", err)
	}
	if !cb.NeedsSave() {
		t.Fatal("status=6 应判定为需要保存")
	}
	if cb.NodeID != "3f2b1c4d-aaaa-bbbb-cccc-1234567890ab" {
		t.Fatalf("应从 key 反解出节点，实际 %q", cb.NodeID)
	}
	if cb.UserID != "u1" {
		t.Fatalf("应取回调里的用户，实际 %q", cb.UserID)
	}
	// status=1（编辑中）不应触发保存
	if (Callback{Status: StatusEditing}).NeedsSave() {
		t.Fatal("编辑中状态不应下载文件")
	}
}

// key 里的节点是 UUID（自带连字符），解析必须从尾部剥 mode 与 hour。
func TestNodeIDFromKey(t *testing.T) {
	id, err := nodeIDFromKey("3f2b1c4d-aaaa-bbbb-cccc-1234567890ab-view-498369")
	if err != nil || id != "3f2b1c4d-aaaa-bbbb-cccc-1234567890ab" {
		t.Fatalf("UUID 形式的 key 解析失败: %q %v", id, err)
	}
	for _, bad := range []string{"", "node-1", "node-1-edit", "node-1-delete-123", "node-1-edit-abc"} {
		if _, err := nodeIDFromKey(bad); err == nil {
			t.Fatalf("非法 key 应拒绝: %q", bad)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFetchDocumentEnforcesHostAllowlist(t *testing.T) {
	s := newSvc(t)
	ctx := context.Background()

	// 非白名单主机（包括形似的前缀域名）必须拒绝——这是 SSRF 的核心防线
	for _, u := range []string{
		"http://evil.com/x",
		"http://onlyoffice.evil.com/x",
		"file:///etc/passwd",
		"ftp://onlyoffice/x",
		"",
	} {
		if _, err := s.FetchDocument(ctx, u); err == nil {
			t.Fatalf("应拒绝 %q", u)
		}
	}
}

func TestFetchDocumentSuccessAndSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DOCX-BYTES"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	host = strings.Split(host, ":")[0]

	s := New(Config{
		URL: "http://x", PublicURL: "http://y", Secret: "s",
		AllowedHosts: []string{host}, MaxCallbackBytes: 4,
	})
	// 先验证能连（但内容超过 4 字节上限，必须拒绝）
	if _, err := s.FetchDocument(context.Background(), srv.URL+"/f"); err == nil {
		t.Fatal("超过大小上限必须拒绝")
	}

	s.cfg.MaxCallbackBytes = 1024
	data, err := s.FetchDocument(context.Background(), srv.URL+"/f")
	if err != nil {
		t.Fatalf("白名单内应可下载: %v", err)
	}
	if string(data) != "DOCX-BYTES" {
		t.Fatalf("内容不符: %q", string(data))
	}
}

func TestFetchDocumentDoesNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SECRET"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	host := strings.Split(strings.TrimPrefix(redirector.URL, "http://"), ":")[0]
	s := New(Config{
		URL: "http://x", PublicURL: "http://y", Secret: "s",
		AllowedHosts: []string{host}, MaxCallbackBytes: 1024,
	})

	// 跳转必须不跟随：否则白名单形同虚设（跳到任意内网地址）
	if _, err := s.FetchDocument(context.Background(), redirector.URL); err == nil {
		t.Fatal("应拒绝跳转响应（302 不是 200）")
	}
}

func TestDocumentKeyChangesPerHour(t *testing.T) {
	k1 := documentKey("n1", "edit")
	if !strings.HasPrefix(k1, "n1-edit-") {
		t.Fatalf("key 应以 nodeID 开头（回调据此校验），实际 %s", k1)
	}
}

func TestSignFileURLRoundTrip(t *testing.T) {
	s := newSvc(t)
	u := s.SignFileURL("node-1", "tenant-1")
	if !strings.Contains(u, "/v1/onlyoffice/file/node-1") || !strings.Contains(u, "s=") {
		t.Fatalf("签名 URL 形态不符: %s", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if !s.VerifyFileURL("node-1", q.Get("t"), q.Get("e"), q.Get("s")) {
		t.Fatal("合法签名应通过")
	}
	// 换节点必须失败：签名与节点绑定
	if s.VerifyFileURL("node-2", q.Get("t"), q.Get("e"), q.Get("s")) {
		t.Fatal("换节点后签名必须失效")
	}
	// 篡改过期时间也必须失败
	if s.VerifyFileURL("node-1", q.Get("t"), "99999999999", q.Get("s")) {
		t.Fatal("篡改过期时间必须失效")
	}
}

func TestVerifyFileURLRejectsExpired(t *testing.T) {
	s := newSvc(t)
	exp := time.Now().Add(-time.Hour).Unix()
	sig := s.signFile("node-1", "tenant-1", exp)
	if s.VerifyFileURL("node-1", "tenant-1", strconv.FormatInt(exp, 10), sig) {
		t.Fatal("过期签名必须拒绝")
	}
}

// 操作人必须取自签名载荷，而不是回调体里的 users。
//
// 编辑器配置（含 JWT）是发给浏览器的，任何能打开编辑器的人都拿得到 token，
// 也就能仿造一份 users 指向同事的回调体，把这次保存栽给别人。
// token 里的 editorConfig.user.id 是签发时写入的，伪造不了。
func TestParseCallbackTakesUserFromSignedClaims(t *testing.T) {
	s := newSvc(t)
	key := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee-edit-1750000000"
	payload := map[string]any{
		"key": key, "status": 2, "url": "http://onlyoffice/cache/1",
		"editorConfig": map[string]any{
			"user": map[string]any{"id": "real-user", "name": "真实用户"},
		},
	}
	token, err := SignJWT(s.cfg.Secret, payload)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, map[string]any{
		"key": key, "status": 2, "url": "http://onlyoffice/cache/1",
		"users": []string{"victim-user"},
	})
	cb, err := s.ParseCallback(token, body)
	if err != nil {
		t.Fatal(err)
	}
	if cb.UserID != "real-user" {
		t.Fatalf("应使用签名载荷里的用户，实际 %q（回调体的 %q 被采信了）", cb.UserID, "victim-user")
	}
}

// 载荷里没有用户信息时才退回回调体（兼容旧版文档服务的回传）。
func TestParseCallbackFallsBackToBodyUsers(t *testing.T) {
	s := newSvc(t)
	key := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee-edit-1750000000"
	body := map[string]any{
		"key": key, "status": 2, "url": "http://onlyoffice/cache/1",
		"users": []string{"body-user"},
	}
	tok, raw := signBody(t, s.cfg.Secret, body)
	cb, err := s.ParseCallback(tok, raw)
	if err != nil {
		t.Fatal(err)
	}
	if cb.UserID != "body-user" {
		t.Fatalf("载荷无用户时应退回回调体，实际 %q", cb.UserID)
	}
}
