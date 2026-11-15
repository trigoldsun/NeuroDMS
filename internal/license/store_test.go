package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"docvault/internal/dbtest"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 这组用例覆盖"存 → 读 → 判"三段 SQL：单测验签不需要库，
// 但列名写错、jsonb 类型不匹配这类问题只有真库能抓到。
func setup(t *testing.T) (*Manager, ed25519.PrivateKey, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	dbtest.EnsureSchema(t, pool)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(pool, pub)
	id, err := m.InstanceID(context.Background())
	if err != nil {
		t.Fatalf("实例指纹读取失败: %v", err)
	}
	// 每个用例从干净状态开始，否则上一个用例的许可证会影响 Status。
	if _, err := pool.Exec(context.Background(), `DELETE FROM instance_license`); err != nil {
		t.Fatal(err)
	}
	return m, priv, id
}

func makeBlob(t *testing.T, priv ed25519.PrivateKey, p Payload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

func TestApplyAndStatus(t *testing.T) {
	m, priv, id := setup(t)
	blob := makeBlob(t, priv, Payload{
		V: Version, LicenseID: "DV-T1", Customer: "集成测试客户",
		InstanceID: id, Edition: "business", Capabilities: []string{"*"}, Seats: 0,
	})

	// tenantID 传空：只验落库，不动租户表（本包不负责造租户）。
	if _, err := m.Apply(context.Background(), "", blob, "tester"); err != nil {
		t.Fatalf("导入失败: %v", err)
	}

	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Present || !st.Valid {
		t.Fatalf("应为已导入且有效，实际 %+v", st)
	}
	if st.Customer != "集成测试客户" || st.InstanceID != id {
		t.Fatalf("字段回读不对: %+v", st)
	}
	if st.ExpiresAt != "" {
		t.Fatalf("没设到期应回空（永久），实际 %q", st.ExpiresAt)
	}
}

func TestApplyRejectsWrongInstance(t *testing.T) {
	m, priv, _ := setup(t)
	blob := makeBlob(t, priv, Payload{
		V: Version, LicenseID: "DV-T2", Customer: "别的机器",
		InstanceID: "11111111-1111-1111-1111-111111111111",
		Edition:    "business", Capabilities: []string{"*"},
	})
	if _, err := m.Apply(context.Background(), "", blob, "tester"); err == nil {
		t.Fatal("指纹不匹配应被拒绝")
	}
	st, _ := m.Status(context.Background())
	if st.Present {
		t.Fatal("被拒绝的许可证不应落库")
	}
}

func TestApplyExpired(t *testing.T) {
	m, priv, id := setup(t)
	blob := makeBlob(t, priv, Payload{
		V: Version, LicenseID: "DV-T3", Customer: "过期客户",
		InstanceID: id, Edition: "business",
		ExpiresAt: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
	})
	if _, err := m.Apply(context.Background(), "", blob, "tester"); err == nil {
		t.Fatal("过期许可证应被拒绝")
	}
}

func TestStatusWithoutLicense(t *testing.T) {
	m, _, _ := setup(t)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Present || st.Valid {
		t.Fatalf("未导入时应 present=false，实际 %+v", st)
	}
	if st.InstanceID == "" {
		t.Fatal("即使没有许可证，也要能读出实例指纹（客户要用它申请）")
	}
}
