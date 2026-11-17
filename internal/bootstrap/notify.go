// Package bootstrap 负责把配置装配成可用的运行时对象。
//
// 单独成包而不是写在 main 里：装配逻辑（选哪个通道、缺配置时是降级还是失败）
// 需要能被单元测试覆盖，而 main 里的代码只能靠起进程手工验证。
package bootstrap

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"strings"

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
	// Router 是按租户发信的路由器（可能有 nil 的 fallback）。
	// 暴露出来是为了让"保存邮件配置"能立即失效缓存。
	Router *notify.Router
}

// CodeMailer 把验证码交给同步发送器。
type CodeMailer struct {
	Direct *notify.DirectSender
	// Brand 返回租户的系统名称，用于验证码邮件的标题与正文。
	// 为 nil 时退回产品名（测试装配常见）。
	Brand func(ctx context.Context, tenantID string) string
}

// SendCode 实现 auth.CodeSender。
func (m *CodeMailer) SendCode(ctx context.Context, tenantID, to, purpose, code string) error {
	if m == nil || m.Direct == nil {
		return fmt.Errorf("未配置通知通道")
	}
	brand := "NeuroDMS"
	if m.Brand != nil {
		if b := strings.TrimSpace(m.Brand(ctx, tenantID)); b != "" {
			brand = b
		}
	}
	// 显示名与主题统一走同一规则（企业名 + 文档中心），
	// 避免"发件人一个名字、主题另一个名字"。
	display := notify.BrandDisplayName(brand)
	msg := notify.Message{
		To:       to,
		FromName: display,
		Subject:  "【" + display + "】验证码",
		Text: fmt.Sprintf("您在%s的验证码是 %s，%d 分钟内有效。\n如非本人操作，请忽略本邮件。",
			display, code, 10),
		HTML: fmt.Sprintf(
			`<p>您在 <strong>%s</strong> 的验证码是 <strong style="font-size:20px;letter-spacing:2px">%s</strong></p>`+
				`<p style="color:#666">10 分钟内有效。如非本人操作，请忽略本邮件。</p>`,
			html.EscapeString(display), code),
	}
	return m.Direct.SendSync(ctx, tenantID, msg, purpose, nil)
}

// BuildNotifier 按配置装配通道。
//
// 环境变量里的 SMTP/Graph 是**平台默认**通道；租户可以在管理台
// 「系统设置 · 邮件服务」里配置自己的发件邮箱，此时按租户走（见 notify.Router）。
//
// 返回 (nil, nil) 表示"既没有平台通道、也没有配置仓库"——这是允许的
// （纯内网预览环境），但调用方必须知道：此时 mfa_required 的账号无法登录（fail-closed）。
func BuildNotifier(cfg *config.Config, pool *pgxpool.Pool, store *notify.Store,
	brandName func(ctx context.Context, tenantID string) string, log *slog.Logger) (*Notifier, error) {
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

	var disp *notify.Dispatcher
	if primary != nil {
		disp = notify.NewDispatcher(primary, fallback)
	}

	// 选择 Mailer：
	//   - 有配置仓库 → Router：租户配置优先，否则用 disp（可能为 nil）
	//   - 没有仓库（测试或旧装配）→ 直接用 disp
	// 两者都没有才返回 nil，保持"完全没配通知"的语义。
	var mail notify.Mailer
	var router *notify.Router
	switch {
	case store != nil:
		router = notify.NewRouter(disp, store.Load, log)
		if brandName != nil {
			router.SetBrandName(brandName)
		}
		mail = router
	case disp != nil:
		mail = disp
	default:
		return nil, nil
	}

	if disp != nil {
		log.Info("平台默认通知通道已配置", "channels", disp.Channels(), "primary", primaryName)
	} else {
		log.Info("未配置平台默认邮件通道：仅租户自有配置可用（管理台「系统设置 · 邮件服务」）")
	}
	if primaryName == "" {
		// notification.channel 只允许 smtp/graph；实际通道在发送成功后会被改写，
		// 这里给一个占位值，避免 CHECK 约束把消息挡在队列外。
		primaryName = "smtp"
	}

	return &Notifier{
		Outbox: notify.NewOutbox(pool, mail, log, primaryName),
		Mailer: &CodeMailer{
			Direct: notify.NewDirectSender(pool, mail, log, primaryName),
			Brand:  brandName,
		},
		Channel: primaryName,
		Router:  router,
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
