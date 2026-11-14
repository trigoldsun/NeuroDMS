package idp

// P0 验证：用 httptest 起一个最小 IdP，逐条验证"该拒的必须拒"。
//
// 这些用例就是交付物本身——它们证明的不是"能登录"，而是"错误的东西进不来"。
// P1 接入时，同样的样本会被搬进 httpapi 的集成测试。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIDP 是最小可用的 OIDC 提供方：discovery + jwks + token。
type fakeIDP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	client string

	mu           sync.Mutex
	lastNonce    string
	lastVerifier string // 收到的 code_verifier（用于校验 PKCE）
	wantVerifier string
	issueAud     string // 故意签错受众
	issueIssuer  string // 故意签错签发者
	expiry       time.Duration
	omitIDToken  bool
}

func newFakeIDP(t *testing.T, clientID string) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key, kid: "k1", client: clientID, expiry: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss,
			"authorization_endpoint":                iss + "/authorize",
			"token_endpoint":                        iss + "/token",
			"jwks_uri":                              iss + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := jose.JSONWebKey{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		verifier := r.Form.Get("code_verifier")
		f.lastVerifier = verifier
		want := f.wantVerifier
		omit := f.omitIDToken
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		// 服务端校验 PKCE：verifier 的 S256 必须等于发起时的 challenge
		if want != "" {
			sum := sha256.Sum256([]byte(verifier))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != want {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}
		}
		if omit {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer",
			"id_token": f.sign(t),
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) sign(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	nonce, aud, iss, exp := f.lastNonce, f.issueAud, f.issueIssuer, f.expiry
	f.mu.Unlock()
	if aud == "" {
		aud = f.client
	}
	if iss == "" {
		iss = f.srv.URL
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"iss": iss, "aud": aud, "sub": "user-123",
		"exp": time.Now().Add(exp).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"nonce": nonce, "email": "alice@example.com", "email_verified": true, "name": "Alice",
	})
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newRP(t *testing.T, f *fakeIDP) *OIDC {
	t.Helper()
	rp, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "https://app.example.com/sso/oidc/callback",
	})
	if err != nil {
		t.Fatalf("discovery 失败: %v", err)
	}
	return rp
}

// 授权地址必须带 PKCE(S256)、state 与 nonce——缺一个都是真实漏洞。
func TestAuthCodeURLHasPKCEStateNonce(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)

	verifier, _ := NewCodeVerifier()
	authURL, aerr := rp.AuthCodeURL("st-1", "no-1", verifier)
	if aerr != nil {
		t.Fatalf("生成授权地址失败: %v", aerr)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("缺少 PKCE: %s", u)
	}
	if q.Get("state") != "st-1" || q.Get("nonce") != "no-1" {
		t.Fatalf("state/nonce 不正确: %s", u)
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("应为授权码模式: %s", u)
	}
}

func TestExchangeReturnsSubject(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)

	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce = "no-1"
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	claims, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1")
	if err != nil {
		t.Fatalf("换取失败: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Fatalf("claims 不正确: %+v", claims)
	}
}

// nonce 不匹配必须失败（否则 id_token 可被重放）。
func TestExchangeRejectsWrongNonce(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce = "no-evil"
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err == nil {
		t.Fatal("nonce 不匹配时不应通过")
	}
}

// 受众不对（别的应用的 token）必须失败。
func TestExchangeRejectsWrongAudience(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce, f.issueAud = "no-1", "other-client"
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err == nil {
		t.Fatal("受众不匹配时不应通过")
	}
}

// 签发者不对必须失败（discovery 被投毒时的最后一道）。
func TestExchangeRejectsWrongIssuer(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce, f.issueIssuer = "no-1", "https://evil.example.com"
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err == nil {
		t.Fatal("签发者不匹配时不应通过")
	}
}

// 过期令牌必须失败。
func TestExchangeRejectsExpired(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce, f.expiry = "no-1", -2*time.Minute
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err == nil {
		t.Fatal("过期令牌不应通过")
	}
}

// PKCE verifier 与服务端记录不一致：令牌端点拒绝，RP 必须把错误抛出来。
func TestExchangeFailsOnPKCEMismatch(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.lastNonce = "no-1"
	f.wantVerifier = codeChallenge("another-verifier")
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err == nil {
		t.Fatal("PKCE 不匹配时应失败")
	}
}

// 没返回 id_token（OAuth2-only 提供商）必须明确报错，而不是"登录成功但没有身份"。
func TestExchangeRequiresIDToken(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	verifier, _ := NewCodeVerifier()
	f.mu.Lock()
	f.omitIDToken = true
	f.wantVerifier = codeChallenge(verifier)
	f.mu.Unlock()

	if _, err := rp.Exchange(context.Background(), "code-1", verifier, "no-1"); err != ErrNoIDToken {
		t.Fatalf("应返回 ErrNoIDToken，实际 %v", err)
	}
}

// state 一次性：重放同一个 state 必须失败。
func TestStateIsOneTimeAndExpires(t *testing.T) {
	s := NewStateStore(time.Minute)
	s.Put(Pending{State: "st-1", Nonce: "n"})
	if _, ok := s.Take("st-1"); !ok {
		t.Fatal("首次应能取出")
	}
	if _, ok := s.Take("st-1"); ok {
		t.Fatal("state 不得重复使用")
	}

	s.Put(Pending{State: "st-2", Expires: time.Now().Add(-time.Second)})
	if _, ok := s.Take("st-2"); ok {
		t.Fatal("过期 state 应失效")
	}
	if n := s.Sweep(); n != 0 {
		t.Fatalf("过期项已被删除，Sweep 应为 0，实际 %d", n)
	}
	_ = strings.TrimSpace("")
}

// TestAuthCodeURLRejectsEmptyParams：三个一次性参数任一为空都必须拒绝。
//
// 这条用例锁的是一个"静默失效"：nonce 为空时，id_token 里也没有 nonce，
// 比对结果是"相等"，重放照样通过，而日志上看不出任何异常。
func TestAuthCodeURLRejectsEmptyParams(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	cases := []struct{ state, nonce, verifier string }{
		{"", "no-1", "verifier-1"},
		{"st-1", "", "verifier-1"},
		{"st-1", "no-1", ""},
	}
	for _, c := range cases {
		if _, err := rp.AuthCodeURL(c.state, c.nonce, c.verifier); err == nil {
			t.Fatalf("空参数应被拒绝: state=%q nonce=%q verifier=%q", c.state, c.nonce, c.verifier)
		}
	}
}

// TestExchangeRejectsEmptyNonce：回调侧同样不能接受空 nonce。
func TestExchangeRejectsEmptyNonce(t *testing.T) {
	f := newFakeIDP(t, "client-1")
	rp := newRP(t, f)
	if _, err := rp.Exchange(context.Background(), "code-1", "verifier-1", ""); err == nil {
		t.Fatal("空 nonce 的回调必须被拒绝")
	}
}

// TestStateStoreRejectsWhenFull：容量上限生效，满时必须拒绝而不是无限增长。
func TestStateStoreRejectsWhenFull(t *testing.T) {
	st := NewStateStore(time.Minute)
	for i := 0; i < maxPending; i++ {
		if !st.Put(Pending{State: "s" + strconv.Itoa(i)}) {
			t.Fatalf("第 %d 条不应被拒绝", i)
		}
	}
	if st.Put(Pending{State: "overflow"}) {
		t.Fatal("超过上限后必须拒绝写入")
	}
	// 过期后腾出空间：仍然可以继续用，而不是永久锁死
	st.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if !st.Put(Pending{State: "after-sweep"}) {
		t.Fatal("清理过期项后应允许写入")
	}
}
