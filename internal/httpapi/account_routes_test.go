package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"docvault/internal/auth"
)

// 账号生命周期与目录路径这几条新路由，必须和其他受保护接口一样"先认证再谈别的"。
//
// 这里不断言业务结果（那需要数据库），只钉住一条最容易在重构中丢失的性质：
// 未带凭证时一律 401，而不是 500/404 或直接进业务逻辑。
func TestAccountAndPathRoutesRequireAuth(t *testing.T) {
	a := &API{Auth: auth.New(nil, []byte("test-secret-for-account-routes-0123456789abcdef"), auth.DefaultConfig())}
	mux := http.NewServeMux()
	a.Register(mux)

	const anyUUID = "00000000-0000-4000-8000-000000000000"
	cases := []struct{ method, path string }{
		{http.MethodGet, "/v1/nodes/" + anyUUID + "/path"},
		{http.MethodGet, "/v1/me/handover-candidates"},
		{http.MethodGet, "/v1/me/account/deletion-preview"},
		{http.MethodPost, "/v1/me/account/delete"},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("未认证访问应返回 401，实际 %d：%s", rec.Code, rec.Body.String())
			}
		})
	}
}
