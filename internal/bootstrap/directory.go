package bootstrap

import (
	"context"
	"fmt"

	"docvault/internal/directory"
	"docvault/internal/platform/config"
)

// BuildDirectory 按配置构造 LDAP 连接。未配置时返回 (nil, nil)。
//
// 构造时会真正连一次目录：目录配错（证书、端口、服务账号口令）
// 应该在启动自检里被发现，而不是等第一个用户登录失败。
func BuildDirectory(ctx context.Context, cfg *config.Config) (*directory.LDAPDirectory, error) {
	if cfg.LDAPURL == "" || cfg.LDAPBaseDN == "" {
		return nil, nil
	}
	d, err := directory.NewLDAP(ctx, directory.LDAPConfig{
		URL:                cfg.LDAPURL,
		StartTLS:           cfg.LDAPStartTLS,
		InsecureSkipVerify: cfg.LDAPInsecure,
		AllowPlaintextBind: cfg.LDAPAllowPlaintext,
		CACertFile:         cfg.LDAPCAFile,
		TLSName:            cfg.LDAPTLSName,
		BindDN:             cfg.LDAPBindDN,
		BindPassword:       cfg.LDAPBindPassword,
		BaseDN:             cfg.LDAPBaseDN,
		UserFilter:         cfg.LDAPUserFilter,
		GroupFilter:        cfg.LDAPGroupFilter,
		SyncUserFilter:     cfg.LDAPSyncFilter,
		ADMode:             cfg.LDAPADMode,
	})
	if err != nil {
		return nil, fmt.Errorf("目录初始化失败: %w", err)
	}
	return d, nil
}

// TenantDirectory 把按租户解析的目录适配成认证服务需要的最小接口。
//
// 每次登录都向 Resolver 要连接：配置存在数据库里、可随时改，
// 启动时固定一个连接会让"改了配置要重启"重新出现。
// Resolver 内部有 60 秒缓存，不会每次登录都重新握手。
type TenantDirectory struct {
	Res *directory.Resolver
}

// Authenticate 实现 auth.DirectoryAuthenticator。
func (a TenantDirectory) Authenticate(ctx context.Context, tenantID, username, password string) (string, bool, error) {
	d, err := a.Res.For(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	if d == nil {
		// 未启用目录：返回错误让认证服务按"凭据错误"处理，
		// 但上游日志能区分（Resolver 已记录原因）。
		return "", false, directory.ErrDirectoryUnavailable
	}
	u, err := d.Authenticate(ctx, username, password)
	if err != nil {
		return "", false, err
	}
	return u.ExternalID, u.Disabled, nil
}
