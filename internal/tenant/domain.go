package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/secretbox"

	"github.com/jackc/pgx/v5"
)

// Domain 是一个租户绑定的自有域名。
type Domain struct {
	Host         string     `json:"host"`
	Primary      bool       `json:"primary"`
	Verified     bool       `json:"verified"`
	HasCert      bool       `json:"hasCert"`
	CertNotAfter *time.Time `json:"certNotAfter"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// ErrCertUnavailable 表示未配置加密密钥，无法安全保存私钥。
var ErrCertUnavailable = secretbox.ErrNoKey

// ListDomains 列出某租户的域名（平台侧）。
func (s *Service) ListDomains(ctx context.Context, slug string) ([]Domain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT host, is_primary, verified, has_cert, cert_not_after, created_at
		   FROM platform_domains($1)`, slug)
	if err != nil {
		if isCode(err, "DV404") {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.Host, &d.Primary, &d.Verified, &d.HasCert,
			&d.CertNotAfter, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDomain 绑定域名并返回 DNS TXT 验证值。
//
// 先绑后验：绑定本身不生效（public_resolve_domain 要求 verified_at 非空），
// 所以"抢注别人的域名"不会产生任何效果——最多占一行待验证记录。
func (s *Service) AddDomain(ctx context.Context, tenantID, host string, primary bool) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if !hostRe.MatchString(host) {
		return "", fmt.Errorf("%w: 域名格式不合法（需为小写 FQDN，不带协议与端口）", ErrInvalidInput)
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 只允许一个主域名：主域名决定"默认跳转到哪里"，多主等于没有主。
		if primary {
			if _, e := tx.Exec(ctx,
				`UPDATE tenant_domain SET is_primary = false WHERE tenant_id = $1`, tenantID); e != nil {
				return e
			}
		}
		_, e := tx.Exec(ctx, `
			INSERT INTO tenant_domain (host, tenant_id, is_primary, verify_token)
			VALUES ($1, $2, $3, $4)`, host, tenantID, primary, token)
		return e
	})
	if err != nil {
		if isDup(err) {
			return "", fmt.Errorf("%w: 该域名已被绑定", ErrInvalidInput)
		}
		return "", err
	}
	return token, nil
}

// RemoveDomain 解绑（连带删除证书）。
func (s *Service) RemoveDomain(ctx context.Context, tenantID, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM tenant_domain WHERE tenant_id = $1 AND host = $2`,
			tenantID, host)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// VerifyToken 读取域名的验证串（平台侧展示给运维去配 DNS）。
func (s *Service) VerifyToken(ctx context.Context, tenantID, host string) (string, error) {
	var token string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT verify_token FROM tenant_domain WHERE tenant_id = $1 AND host = $2`,
			tenantID, strings.ToLower(strings.TrimSpace(host))).Scan(&token)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return token, err
}

// MarkVerified 标记域名已验证。
//
// 真正的验证由调用方完成（查 DNS TXT）。把"查什么"留在上层、把"标记什么"
// 放在这里，是为了让验证方式可以替换（DNS / HTTP / 人工）而不动数据层。
func (s *Service) MarkVerified(ctx context.Context, tenantID, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE tenant_domain SET verified_at = now(), updated_at = now()
			  WHERE tenant_id = $1 AND host = $2 AND verified_at IS NULL`, tenantID, host)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			// 可能已验过，也可能不存在：区分对待，避免把"已验"报成错误
			var n int
			if e := tx.QueryRow(ctx,
				`SELECT count(*) FROM tenant_domain WHERE tenant_id = $1 AND host = $2`,
				tenantID, host).Scan(&n); e != nil {
				return e
			}
			if n == 0 {
				return ErrNotFound
			}
		}
		return nil
	})
}

// CertInfo 是证书摘要。
type CertInfo struct {
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	Domains     []string  `json:"domains"`
}

// SetCertificate 保存证书与私钥（私钥加密后入库）。
//
// 校验三件事，缺一不可：
//  1. 证书与私钥必须配对（否则 TLS 握手直接失败，且报错难懂）；
//  2. 证书必须覆盖该域名（否则浏览器依旧报警，用户以为"配好了"）；
//  3. 证书不能已过期（否则等于没配）。
func (s *Service) SetCertificate(ctx context.Context, box *secretbox.Box,
	tenantID, host, certPEM string, keyPEM []byte) (CertInfo, error) {

	if !box.Available() {
		return CertInfo{}, ErrCertUnavailable
	}
	host = strings.ToLower(strings.TrimSpace(host))

	pair, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		return CertInfo{}, fmt.Errorf("%w: 证书与私钥不匹配: %v", ErrInvalidInput, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertInfo{}, fmt.Errorf("%w: 证书无法解析: %v", ErrInvalidInput, err)
	}
	if !leaf.NotAfter.After(time.Now()) {
		return CertInfo{}, fmt.Errorf("%w: 证书已过期（%s）", ErrInvalidInput, leaf.NotAfter.Format(time.RFC3339))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return CertInfo{}, fmt.Errorf("%w: 证书不覆盖域名 %s: %v", ErrInvalidInput, host, err)
	}

	sum := sha256.Sum256(leaf.Raw)
	info := CertInfo{
		NotAfter:    leaf.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]),
		Domains:     leaf.DNSNames,
	}

	// AAD 绑定"租户 + 域名"：把 A 租户的密文复制到 B 的行里会解不开。
	sealed, err := box.Encrypt(keyPEM, certAAD(tenantID, host))
	if err != nil {
		return CertInfo{}, err
	}

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `
			UPDATE tenant_domain
			   SET cert_pem = $3, key_enc = $4, cert_not_after = $5,
			       cert_fingerprint = $6, updated_at = now()
			 WHERE tenant_id = $1 AND host = $2`,
			tenantID, host, certPEM, sealed, leaf.NotAfter, info.Fingerprint)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	return info, err
}

// CertificateFor 按 Host 取出可用于 TLS 握手的证书（供 GetCertificate 调用）。
func (s *Service) CertificateFor(ctx context.Context, box *secretbox.Box, host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}

	var tenantID, certPEM string
	var keyEnc []byte
	err := s.pool.QueryRow(ctx, `
		SELECT d.tenant_id::text, d.cert_pem, d.key_enc
		  FROM tenant_domain d
		  JOIN tenant t ON t.id = d.tenant_id
		 WHERE d.host = $1 AND d.verified_at IS NOT NULL
		   AND d.cert_pem IS NOT NULL AND d.key_enc IS NOT NULL
		   AND t.status NOT IN ('deleted', 'suspended') AND t.deleted_at IS NULL`,
		host).Scan(&tenantID, &certPEM, &keyEnc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	keyPEM, err := box.Decrypt(keyEnc, certAAD(tenantID, host))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

// HostTenant 把 Host 解析为租户（未验证域名返回 ErrNotFound）。
func (s *Service) HostTenant(ctx context.Context, host string) (tenantID, slug string, err error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	err = s.pool.QueryRow(ctx,
		`SELECT tenant_id::text, tenant_slug FROM public_resolve_domain($1)`, host).
		Scan(&tenantID, &slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return "", "", err
	}
	return tenantID, slug, nil
}

func certAAD(tenantID, host string) string { return "cert:" + tenantID + "|" + host }

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
