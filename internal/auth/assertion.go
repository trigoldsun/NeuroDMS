package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// LoginWithAssertion 用"已由可信代理完成认证"的身份断言登录。
//
// 与 Login 的区别只有一个：不校验口令 —— 因为口令已经由前置代理
// （IIS / nginx + SPNEGO）在 Windows 集成认证阶段验证过了。
//
// 安全前提由调用方（httpapi.ssoGate）负责：
//  1. 请求必须来自配置的可信代理网段；
//  2. 断言头必须由该代理写入，浏览器无法伪造；
//  3. 可选的共享密钥必须匹配。
//
// 这三条缺一条，这个函数就是一个"报个用户名就能登录"的洞。
// 因此这里再做一层兜底：只接受 source='ldap' 的账号——
// 本地账号永远不能靠断言登录，避免代理被攻破后连本地管理员一起沦陷。
func (s *Service) LoginWithAssertion(ctx context.Context, tenantSlug, username, ip, ua string) (Tokens, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return Tokens{}, ErrInvalidCredentials
	}

	tenantID, err := s.resolveTenant(ctx, tenantSlug)
	if err != nil {
		return Tokens{}, err
	}

	u, err := s.findLoginUser(ctx, tenantID, username, LoginDomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 这里可以直说"没同步"：断言头只可能由可信代理写入，
			// 不存在"暴力枚举"的通道（能发断言的人已经在内网被认证过了）。
			return Tokens{}, ErrDomainNotSynced
		}
		return Tokens{}, err
	}

	now := s.now()
	if u.lockedUntil != nil && u.lockedUntil.After(now) {
		return Tokens{}, ErrAccountLocked
	}
	if u.status != "active" || (u.expiresAt != nil && u.expiresAt.Before(now)) {
		return Tokens{}, ErrAccountDisabled
	}

	// 二次验证照常生效：SSO 证明的是"这台电脑前坐着这个人"，
	// 不等于"这个人本人同意此刻登录"。要求 MFA 的组织不应因 SSO 而降低强度。
	if u.mfaNeeded {
		return Tokens{}, s.startMFA(ctx, tenantID, u.id, u.epoch, u.email, ip)
	}

	return s.createSession(ctx, tenantID, u.id, u.epoch, ip, ua)
}

// resolveTenant 由 slug 定位可登录的租户。
//
// 允许登录的状态：active / trial / readonly（suspended / deleted 不允许）。
// 这里曾经只写了 active，导致"刚开通的试用租户一个人都进不去"，
// 而错误信息还说"账号或口令不正确"，把排查方向完全带偏。
func (s *Service) resolveTenant(ctx context.Context, slug string) (string, error) {
	var tenantID string
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM tenant
		 WHERE slug = $1 AND status IN ('active', 'trial', 'readonly')
		   AND deleted_at IS NULL`, slug).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	return tenantID, nil
}
