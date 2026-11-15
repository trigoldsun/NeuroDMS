// Package license 是本地部署版的许可证校验（docs/47 §4.5）。
//
// 设计约束（用户已拍板）：
//   - 本地版**不设期限、不设用户数上限**：所以 expiresAt 可空、seats=0 表示不限；
//   - 私钥不进仓库、不进镜像：本包只做**验签**，签发工具在 cmd/licensegen，
//     私钥由厂商侧离线保管（`--key /path/to/ed25519.key`）；
//   - 不做吊销名单：离线环境没有可信的吊销源，做了也是摆设；
//     靠"绑定实例指纹"+"需要时换发"控制范围。
//
// 许可证是一个自包含字符串：
//
//	base64url(payloadJSON) + "." + base64url(ed25519签名)
//
// 为什么不用 JWT：本地版不需要跟任何服务端交互，JWT 的 header/alg 协商
// 反而多一类"alg 混淆"的攻击面。这里算法固定 Ed25519，没有协商余地。
package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Version 是许可证格式版本。格式变更时递增，旧版本仍然可验。
const Version = 2

// 哨兵错误：调用方按类别给出可读提示。
var (
	// ErrNoPublicKey 表示未配置公钥 → 本实例不接受许可证（SaaS 形态）。
	ErrNoPublicKey = errors.New("未配置许可证公钥（DOCVAULT_LICENSE_PUBKEY），许可证功能不可用")
	// ErrMalformed 表示字符串格式不对。
	ErrMalformed = errors.New("许可证格式不合法")
	// ErrBadSignature 表示签名验证失败（改过内容或用错密钥签的）。
	ErrBadSignature = errors.New("许可证签名无效")
	// ErrWrongInstance 表示许可证绑定的是另一台机器。
	ErrWrongInstance = errors.New("许可证与本实例指纹不匹配")
	// ErrExpired 表示已过期。
	ErrExpired = errors.New("许可证已过期")
)

// Payload 是许可证内容。
type Payload struct {
	V            int      `json:"v"`
	LicenseID    string   `json:"licenseId"`
	Customer     string   `json:"customer"`
	InstanceID   string   `json:"instanceId"`
	Edition      string   `json:"edition"`
	Capabilities []string `json:"capabilities"`
	// Seats=0 表示不限人数（本地版口径）。
	Seats int `json:"seats"`
	// ExpiresAt 为空表示**永久**（本地版买断）。
	ExpiresAt string `json:"expiresAt,omitempty"`
	IssuedAt  string `json:"issuedAt,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Expiry 解析到期时间；空串返回零值 + false。
func (p Payload) Expiry() (time.Time, bool, error) {
	if strings.TrimSpace(p.ExpiresAt) == "" {
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%w: expiresAt 需为 RFC3339", ErrMalformed)
	}
	return t, true, nil
}

// AllCaps 判断是否"全功能"。
func (p Payload) AllCaps() bool {
	for _, c := range p.Capabilities {
		if c == "*" {
			return true
		}
	}
	return false
}

// ParsePublicKey 解析公钥：接受 base64（标准或 URL 安全）编码的 32 字节。
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoPublicKey
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("DOCVAULT_LICENSE_PUBKEY 不是合法 base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("DOCVAULT_LICENSE_PUBKEY 需为 %d 字节，当前 %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Decode 拆出 payload 与签名原文（不校验）。
func Decode(blob string) (payload []byte, sig []byte, err error) {
	blob = strings.TrimSpace(blob)
	parts := strings.Split(blob, ".")
	if len(parts) != 2 {
		return nil, nil, ErrMalformed
	}
	payload, err = decodeB64(parts[0])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	sig, err = decodeB64(parts[1])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrMalformed
	}
	return payload, sig, nil
}

func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, ErrMalformed
}

// Verify 校验签名并解析内容。
func Verify(pub ed25519.PublicKey, blob string) (Payload, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Payload{}, ErrNoPublicKey
	}
	raw, sig, err := Decode(blob)
	if err != nil {
		return Payload{}, err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return Payload{}, ErrBadSignature
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, fmt.Errorf("%w: 内容无法解析", ErrMalformed)
	}
	if p.V != Version {
		return Payload{}, fmt.Errorf("%w: 不支持的版本 %d（本系统支持 v%d）", ErrMalformed, p.V, Version)
	}
	if p.LicenseID == "" || p.Customer == "" {
		return Payload{}, fmt.Errorf("%w: 缺少 licenseId 或 customer", ErrMalformed)
	}
	return p, nil
}

// Check 校验"这份许可证能不能在本机用"。
//
// 顺序有意如此：先指纹，再时间。指纹不对的话，讨论到期没有意义；
// 而把"换机器"报成"已过期"，会让客户去查购买记录而不是找我们换发。
func Check(p Payload, instanceID string, now time.Time) error {
	if p.InstanceID != "" && p.InstanceID != instanceID {
		return fmt.Errorf("%w：许可证绑定 %s，本机是 %s",
			ErrWrongInstance, shortID(p.InstanceID), shortID(instanceID))
	}
	exp, has, err := p.Expiry()
	if err != nil {
		return err
	}
	if has && !now.Before(exp) {
		return fmt.Errorf("%w（%s）", ErrExpired, exp.Format("2006-01-02"))
	}
	return nil
}

func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}

// MaskKey 只用于日志：公钥可以公开，但仍不打印完整值，避免被当成密钥复制走。
func MaskKey(s string) string {
	if len(s) <= 10 {
		return "***"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

// ---------------- 存储 ----------------

// Manager 负责把许可证存进库并应用到租户档位。
type Manager struct {
	pool *pgxpool.Pool
	pub  ed25519.PublicKey
	now  func() time.Time
}

// NewManager 构造；pub 为 nil 表示本实例不接受许可证。
func NewManager(pool *pgxpool.Pool, pub ed25519.PublicKey) *Manager {
	return &Manager{pool: pool, pub: pub, now: time.Now}
}

// Enabled 报告本实例是否接受许可证。
func (m *Manager) Enabled() bool { return m != nil && len(m.pub) == ed25519.PublicKeySize }

// InstanceID 读取（必要时创建）实例指纹。
func (m *Manager) InstanceID(ctx context.Context) (string, error) {
	var id string
	err := m.pool.QueryRow(ctx, `SELECT instance_id::text FROM app_instance WHERE id = 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// 迁移里已插入单行；这里兜底，避免手工删表后整个功能不可用。
		err = m.pool.QueryRow(ctx, `
			INSERT INTO app_instance (id) VALUES (1)
			ON CONFLICT (id) DO UPDATE SET id = 1
			RETURNING instance_id::text`).Scan(&id)
	}
	return id, err
}

// Status 是给界面看的许可证状态。
type Status struct {
	Enabled bool   `json:"enabled"`
	Present bool   `json:"present"`
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason"`
	// InstanceID 一定要回给界面：客户申请许可证时要把它发给我们。
	InstanceID   string   `json:"instanceId"`
	LicenseID    string   `json:"licenseId,omitempty"`
	Customer     string   `json:"customer,omitempty"`
	Edition      string   `json:"edition,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Seats        int      `json:"seats,omitempty"`
	ExpiresAt    string   `json:"expiresAt,omitempty"`
	AppliedAt    string   `json:"appliedAt,omitempty"`
}

// Status 计算当前状态（不修改数据）。
func (m *Manager) Status(ctx context.Context) (Status, error) {
	if m == nil || m.pool == nil {
		return Status{Reason: "许可证服务未启用"}, nil
	}
	st := Status{Enabled: m.Enabled()}
	id, err := m.InstanceID(ctx)
	if err != nil {
		return st, err
	}
	st.InstanceID = id

	var blob, appliedAt string
	err = m.pool.QueryRow(ctx,
		`SELECT blob, applied_at::text FROM instance_license WHERE id = 1`).Scan(&blob, &appliedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		st.Reason = "尚未导入许可证"
		if !st.Enabled {
			st.Reason = "云端版无需许可证；本实例未配置许可证公钥"
		}
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Present, st.AppliedAt = true, appliedAt

	if !st.Enabled {
		st.Reason = "库里有许可证，但本实例未配置公钥，无法验签"
		return st, nil
	}
	p, verr := Verify(m.pub, blob)
	if verr != nil {
		st.Reason = verr.Error()
		return st, nil
	}
	st.LicenseID, st.Customer = p.LicenseID, p.Customer
	st.Edition, st.Capabilities, st.Seats = p.Edition, p.Capabilities, p.Seats
	st.ExpiresAt = p.ExpiresAt
	if cerr := Check(p, id, m.now()); cerr != nil {
		st.Reason = cerr.Error()
		return st, nil
	}
	st.Valid = true
	st.Reason = "许可证有效"
	return st, nil
}

// Apply 验签、落库，并把档位应用到租户。
//
// 只改 edtion 与到期：本地版是"全功能 + 不限期 + 不限席位"，
// 再往上写一堆能力覆盖行只会让后续排查多一层。
func (m *Manager) Apply(ctx context.Context, tenantID, blob, actor string) (Payload, error) {
	if !m.Enabled() {
		return Payload{}, ErrNoPublicKey
	}
	blob = strings.TrimSpace(blob)
	p, err := Verify(m.pub, blob)
	if err != nil {
		return Payload{}, err
	}
	id, err := m.InstanceID(ctx)
	if err != nil {
		return Payload{}, err
	}
	if err := Check(p, id, m.now()); err != nil {
		return Payload{}, err
	}

	exp, _, _ := p.Expiry()
	var expArg any
	if !exp.IsZero() {
		expArg = exp
	}
	caps, _ := json.Marshal(p.Capabilities)

	if _, err := m.pool.Exec(ctx, `
		INSERT INTO instance_license (id, blob, license_id, customer, edition,
		                              capabilities, seats, expires_at, instance_id,
		                              applied_at, applied_by)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
		ON CONFLICT (id) DO UPDATE
		   SET blob = EXCLUDED.blob, license_id = EXCLUDED.license_id,
		       customer = EXCLUDED.customer, edition = EXCLUDED.edition,
		       capabilities = EXCLUDED.capabilities, seats = EXCLUDED.seats,
		       expires_at = EXCLUDED.expires_at, instance_id = EXCLUDED.instance_id,
		       applied_at = now(), applied_by = EXCLUDED.applied_by`,
		blob, p.LicenseID, p.Customer, p.Edition, caps, p.Seats, expArg, p.InstanceID, actor); err != nil {
		return Payload{}, err
	}

	if tenantID != "" {
		if err := m.applyEdition(ctx, tenantID, p); err != nil {
			return Payload{}, err
		}
	}
	return p, nil
}

// applyEdition 把许可证的档位写到租户上。
//
// 到期时间一律写 NULL：本地版买断，许可证自己带到期日，
// 再把同一个日期写进 tenant.edition_expires_at 会出现"两处到期日不一致"，
// 而 docs/18 的历史行为是到期自动降档 —— 那是 SaaS 的口径，本地版不能这么做。
func (m *Manager) applyEdition(ctx context.Context, tenantID string, p Payload) error {
	ed := p.Edition
	if ed == "" {
		ed = "business"
	}
	_, err := m.pool.Exec(ctx, `
		UPDATE tenant SET edition = $2, edition_expires_at = NULL, updated_at = now()
		 WHERE id = $1`, tenantID, ed)
	return err
}

// Reapply 启动时把已存的许可证重新应用一次（幂等）。
func (m *Manager) Reapply(ctx context.Context, tenantID string) error {
	if !m.Enabled() {
		return nil
	}
	var blob string
	err := m.pool.QueryRow(ctx, `SELECT blob FROM instance_license WHERE id = 1`).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	p, verr := Verify(m.pub, blob)
	if verr != nil {
		return verr
	}
	id, err := m.InstanceID(ctx)
	if err != nil {
		return err
	}
	if cerr := Check(p, id, m.now()); cerr != nil {
		// 过期或许可证换机器：不降档、不阻断启动，只留给界面提示。
		// 本地版收回已验收能力（降到基础版）的风险远高于继续用。
		return nil
	}
	return m.applyEdition(ctx, tenantID, p)
}
