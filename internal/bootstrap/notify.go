// Package bootstrap 负责把配置装配成可用的运行时对象。
//
// 单独成包而不是写在 main 里：装配逻辑（选哪个通道、缺配置时是降级还是失败）
// 需要能被单元测试覆盖，而 main 里的代码只能靠起进程手工验证。
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"

	"docvault/internal/auth"
	"docvault/internal/notify"
	"docvault/internal/platform/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Notifier 是装配好的通知设施。
type Notifier struct {
	Outbox  *notify.Outbox
	Mailer  *CodeMailer
	Channel string
}

// CodeMailer 把验证码交给同步发送器。
type CodeMailer struct {
	Direct *notify.DirectSender
}

// SendCode 实现 auth.CodeSender。
func (m *CodeMailer) SendCode(ctx context.Context, tenantID, to, purpose, code string) error {
	if m == nil || m.Direct == nil {
		return fmt.Errorf("未配置通知通道")
	}
	msg := notify.Message{
		To:      to,
		Subject: "NeuroDMS 验证码",
		Text:    fmt.Sprintf("您的验证码是 %s，%d 分钟内有效。\n如非本人操作，请忽略本邮件。", code, 10),
		HTML: fmt.Sprintf(
			`<p>您的验证码是 <strong style="font-size:20px;letter-spacing:2px">%s</strong></p>`+
				`<p style="color:#666">10 分钟内有效。如非本人操作，请忽略本邮件。</p>`, code),
	}
	return m.Direct.SendSync(ctx, tenantID, msg, purpose, nil)
}

// BuildNotifier 按配置装配通道。
//
// 返回 (nil, nil) 表示"完全没配通知"——这是允许的（纯内网预览环境），
// 但调用方必须知道：此时 mfa_required 的账号将无法登录（fail-closed）。
func BuildNotifier(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) (*Notifier, error) {
	if pool == nil {
		return nil, nil
	}

	var primary, fallback notify.Sender
	var primaryName string

	if cfg.SMTPHost != "" && cfg.SMTPFrom != "" {
		s, err := notify.NewSMTPSender(notify.SMTPConfig{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort,
			Username: cfg.SMTPUser, Password: cfg.SMTPPass,
			From: cfg.SMTPFrom, TLSMode: cfg.SMTPTLS,
			InsecureSkipVerify: cfg.SMTPInsecure,
		})
		if err != nil {
			return nil, fmt.Errorf("SMTP 配置无效: %w", err)
		}
		primary, primaryName = s, "smtp"
	}

	if cfg.GraphTenantID != "" && cfg.GraphClientID != "" && cfg.GraphClientSecret != "" && cfg.GraphSender != "" {
		g, err := notify.NewGraphSender(notify.GraphConfig{
			TenantID: cfg.GraphTenantID, ClientID: cfg.GraphClientID,
			ClientSecret: cfg.GraphClientSecret, Sender: cfg.GraphSender,
			LoginBase: cfg.GraphLoginBase, GraphBase: cfg.GraphBase,
		})
		if err != nil {
			return nil, fmt.Errorf("Graph 配置无效: %w", err)
		}
		if primary == nil {
			primary, primaryName = g, "graph"
		} else {
			fallback = g
		}
	}

	if primary == nil {
		return nil, nil
	}

	disp := notify.NewDispatcher(primary, fallback)
	log.Info("通知通道已配置", "channels", disp.Channels(), "primary", primaryName)

	return &Notifier{
		Outbox:  notify.NewOutbox(pool, disp, log, primaryName),
		Mailer:  &CodeMailer{Direct: notify.NewDirectSender(pool, disp, log, primaryName)},
		Channel: primaryName,
	}, nil
}

// SetupMFA 把验证码存储与投递通道接到认证服务上。
func SetupMFA(svc *auth.Service, pool *pgxpool.Pool, secret []byte, n *Notifier) {
	if n == nil {
		// 不注入 = mfa_required 账号被拒登。这是有意的：
		// 宁可"外部用户登不进来"（可被发现、可修复），
		// 也不要"双因子配置没生效但没人知道"（不可发现、后果严重）。
		return
	}
	svc.SetMFA(auth.NewOTPStore(pool, secret, auth.DefaultOTPConfig()), n.Mailer)
}
