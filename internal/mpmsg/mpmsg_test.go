package mpmsg

// 订阅消息通道的测试。
//
// 用假的微信服务器（httptest）而不是打真实接口：这里要证明的是
//   - 报文形状对不对（touser / template_id / page / data 四个字段）；
//   - access_token 只取一次（缓存生效），否则每次审批都要多一次外呼；
//   - 一次性订阅的余额真的会减，减到 0 就不再发；
//   - 未配置时不让任何请求发生（Enabled()=false 的短路）。
// 真发一条消息需要企业自己的 appsecret 与已审核模板，这里不做也不假装做了。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/internal/dbtest"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeWX struct {
	tokenCalls int32
	sendCalls  int32
	payload    map[string]any
	failSend   bool
}

func (f *fakeWX) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/cgi-bin/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.tokenCalls, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-1", "expires_in": 7200})
	})
	mux.HandleFunc("/cgi-bin/message/subscribe/send", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.sendCalls, 1)
		if r.URL.Query().Get("access_token") != "tok-1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40001, "errmsg": "invalid credential"})
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&f.payload)
		if f.failSend {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 47003, "errmsg": "argument invalid"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "errmsg": "ok"})
	})
	mux.HandleFunc("/sns/jscode2session", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("js_code") == "bad" {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40029, "errmsg": "invalid code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"openid": "openid-1", "session_key": "sk"})
	})
	return mux
}

func setup(t *testing.T) (*pgxpool.Pool, *Service, *fakeWX, string, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过订阅消息集成测试")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	slug := "mp-" + time.Now().Format("150405-000000")
	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES (gen_random_uuid(), $1, $2, 'business')
		 RETURNING id::text`, slug, "订阅消息测试").Scan(&tenantID); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, tenantID) })

	var userID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO app_user (id, tenant_id, username, display_name)
		 VALUES (gen_random_uuid(), $1, 'approver', '审批人') RETURNING id::text`, tenantID).Scan(&userID); err != nil {
		t.Fatalf("建账号失败: %v", err)
	}

	fw := &fakeWX{}
	srv := httptest.NewServer(fw.handler())
	t.Cleanup(srv.Close)

	svc := New(Config{
		AppID: "app-1", AppSecret: "sec-1", TodoTemplateID: "tmpl-1",
		BaseURL: srv.URL, HTTP: srv.Client(),
	}, pool)
	return pool, svc, fw, tenantID, userID
}

// 未配置三要素时必须是"整体关闭"，且不产生任何外呼。
func TestDisabledWhenNotConfigured(t *testing.T) {
	svc := New(Config{AppID: "a"}, nil)
	if svc.Enabled() {
		t.Fatal("只配了 appid 也应为未启用")
	}
	if _, err := svc.Grant(context.Background(), "t", "u", "", 1); !errors.Is(err, ErrDisabled) {
		t.Fatalf("未配置时应返回 ErrDisabled，实际 %v", err)
	}
	if err := svc.NotifyApproval(context.Background(), "t", "u", Todo{FileName: "x"}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("未配置时应返回 ErrDisabled，实际 %v", err)
	}
}

// 绑定 → 授权 → 发送 → 余额减少；报文形状与缓存都要对。
func TestBindGrantNotify(t *testing.T) {
	_, svc, fw, tenantID, userID := setup(t)
	if !svc.Enabled() {
		t.Fatal("配置齐全时应为启用")
	}
	ctx := context.Background()

	if err := svc.NotifyApproval(ctx, tenantID, userID, Todo{FileName: "合同.pdf"}); !errors.Is(err, ErrNoOpenID) {
		t.Fatalf("未绑定 openid 应返回 ErrNoOpenID，实际 %v", err)
	}

	if _, err := svc.Bind(ctx, tenantID, userID, "bad"); err == nil {
		t.Fatal("非法 code 应报错")
	}
	if _, err := svc.Bind(ctx, tenantID, userID, "good-code"); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}
	if err := svc.NotifyApproval(ctx, tenantID, userID, Todo{FileName: "合同.pdf"}); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("未授权应返回 ErrNoConsent，实际 %v", err)
	}

	left, err := svc.Grant(ctx, tenantID, userID, "", 2)
	if err != nil {
		t.Fatalf("授权失败: %v", err)
	}
	if left != 2 {
		t.Fatalf("授权后余额应为 2，实际 %d", left)
	}
	// 模板不匹配必须拒绝：拿别的模板 ID 攒额度等于绕过模板审核
	if _, err := svc.Grant(ctx, tenantID, userID, "other-tmpl", 1); err == nil {
		t.Fatal("非本小程序模板应被拒")
	}

	todo := Todo{
		FileName: "2026 年度采购合同（终稿）.pdf", Requester: "张三",
		ShareID: "share-9", CreatedAt: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := svc.NotifyApproval(ctx, tenantID, userID, todo); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if n, bound, _ := svc.Remaining(ctx, tenantID, userID); n != 1 || !bound {
		t.Fatalf("发一条后应为 绑定=true 余额=1，实际 %v %d", bound, n)
	}

	// 报文形状
	if fw.payload["touser"] != "openid-1" {
		t.Fatalf("touser 应为 openid，实际 %v", fw.payload["touser"])
	}
	if fw.payload["template_id"] != "tmpl-1" {
		t.Fatalf("template_id 不对: %v", fw.payload["template_id"])
	}
	if page, _ := fw.payload["page"].(string); page != "pages/approvals/approvals?id=share-9" {
		t.Fatalf("page 应指回审批页，实际 %v", fw.payload["page"])
	}
	data, _ := fw.payload["data"].(map[string]any)
	for _, k := range []string{"thing1", "thing2", "time3", "phrase4"} {
		if _, ok := data[k]; !ok {
			t.Fatalf("缺少模板字段 %s：%v", k, data)
		}
	}
	if v := data["thing1"].(map[string]any)["value"].(string); len([]rune(v)) > 20 {
		t.Fatalf("thing 字段超过 20 字符会被微信拒绝：%q", v)
	}
}

// access_token 必须缓存：三次发送只取一次 token。
func TestAccessTokenCached(t *testing.T) {
	_, svc, fw, tenantID, userID := setup(t)
	ctx := context.Background()
	if _, err := svc.Bind(ctx, tenantID, userID, "good-code"); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}
	if _, err := svc.Grant(ctx, tenantID, userID, "", 3); err != nil {
		t.Fatalf("授权失败: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := svc.NotifyApproval(ctx, tenantID, userID, Todo{FileName: "a.txt", ShareID: "s"}); err != nil {
			t.Fatalf("第 %d 次发送失败: %v", i+1, err)
		}
	}
	if got := atomic.LoadInt32(&fw.tokenCalls); got != 1 {
		t.Fatalf("token 应只取 1 次，实际 %d", got)
	}
	if got := atomic.LoadInt32(&fw.sendCalls); got != 3 {
		t.Fatalf("应发送 3 次，实际 %d", got)
	}
	if n, _, _ := svc.Remaining(ctx, tenantID, userID); n != 0 {
		t.Fatalf("发三条后余额应为 0，实际 %d", n)
	}
	if err := svc.NotifyApproval(ctx, tenantID, userID, Todo{FileName: "a.txt"}); !errors.Is(err, ErrNoConsent) {
		t.Fatalf("余额为 0 应返回 ErrNoConsent，实际 %v", err)
	}
}

// 微信报错要如实返回，不能吞掉——否则运维永远不知道提醒没发出去。
func TestSendErrorPropagated(t *testing.T) {
	_, svc, fw, tenantID, userID := setup(t)
	ctx := context.Background()
	if _, err := svc.Bind(ctx, tenantID, userID, "good-code"); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}
	if _, err := svc.Grant(ctx, tenantID, userID, "", 1); err != nil {
		t.Fatalf("授权失败: %v", err)
	}
	fw.failSend = true
	err := svc.NotifyApproval(ctx, tenantID, userID, Todo{FileName: "a.txt"})
	if err == nil {
		t.Fatal("微信报错时应返回错误")
	}
	if !strings.Contains(err.Error(), "47003") {
		t.Fatalf("错误里应带微信错误码，实际 %v", err)
	}
}
