package httpapi

// 分享链接的邮件外发。
//
// 为什么走 Outbox 而不是直接调 SMTP：
// 业务成功但邮件没发出去，是这类功能最典型的投诉——"我点了发送，对方说没收到"。
// Outbox 把消息和业务写在一起（同一事务可见），后台按退避重试，失败留痕可查。

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strings"

	"docvault/internal/db"
	"docvault/internal/notify"
	"docvault/internal/share"

	"github.com/jackc/pgx/v5"
)

// maxShareRecipients 是单次分享可通知的收件人上限。
// 有上限才不会被当成群发工具：分享是发给"几个人"的，不是营销通道。
const maxShareRecipients = 10

// normalizeRecipients 校验并去重收件人。
//
// 只做形状校验（含 @、有域名、无空白与控制字符），不追求完整 RFC 5322：
// 目的是挡住换行注入（邮件头注入）与明显错输，可达性最终由投递结果反馈。
func normalizeRecipients(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>\"',;") {
			return nil, fmt.Errorf("邮箱格式不合法: %q", raw)
		}
		at := strings.LastIndexByte(e, '@')
		if at <= 0 || at == len(e)-1 || !strings.Contains(e[at+1:], ".") {
			return nil, fmt.Errorf("邮箱格式不合法: %q", raw)
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) > maxShareRecipients {
		return nil, fmt.Errorf("一次最多通知 %d 个收件人", maxShareRecipients)
	}
	return out, nil
}

// publicBaseURL 返回外发链接使用的对外地址。
//
// 优先用配置：反向代理后面 r.Host 常常是内网服务名或 127.0.0.1，
// 拿它拼出来的链接对方一定打不开。
func (a *API) publicBaseURL(r *http.Request) string {
	if b := strings.TrimSpace(a.PublicBaseURL); b != "" {
		return strings.TrimRight(b, "/")
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// shareMailBody 生成邮件正文（纯文本 + HTML 两份）。
//
// 刻意不包含访问口令：邮件与口令必须走两条独立通道，
// 否则"邮箱被看到"就等于"链接可以直接打开"。
func shareMailBody(senderName, objectName, link string, opt share.Options) (subject, text, htmlBody string) {
	var expiry, uses, pwd, verify string
	if opt.ExpiresAt != nil {
		expiry = opt.ExpiresAt.UTC().Format("2006-01-02 15:04") + " (UTC)"
	} else {
		expiry = "长期有效（由分享人随时撤销）"
	}
	if opt.MaxUses != nil {
		uses = fmt.Sprintf("仅可打开 %d 次", *opt.MaxUses)
	} else {
		uses = "可重复打开"
	}
	if opt.PasswordHash != "" {
		pwd = "需要访问口令（由分享人另行告知，本邮件不含口令）"
	} else {
		pwd = "无需口令"
	}
	if opt.RequireVerify {
		verify = "打开后需用本邮箱接收验证码完成验证"
	}

	subject = fmt.Sprintf("【NeuroDMS】%s 向你分享了一个文件", senderName)
	lines := []string{
		fmt.Sprintf("%s 通过 NeuroDMS 向你分享了文件：%s", senderName, objectName),
		"",
		"打开链接：" + link,
		"有效期：" + expiry,
		"访问次数：" + uses,
		"访问条件：" + pwd,
	}
	if verify != "" {
		lines = append(lines, "身份验证："+verify)
	}
	lines = append(lines,
		"",
		"提示：链接不要转发给其他人；如需延长或撤回，请联系分享人。",
		"本邮件由系统自动发送，请勿直接回复。",
	)
	text = strings.Join(lines, "\n")

	htmlBody = fmt.Sprintf(`<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:14px;line-height:1.7;color:#1f2328">
<p><b>%s</b> 通过 NeuroDMS 向你分享了文件：<b>%s</b></p>
<p><a href="%s" style="display:inline-block;padding:8px 16px;background:#12724a;color:#fff;border-radius:6px;text-decoration:none">打开文件</a></p>
<p style="color:#57606a">有效期：%s<br>访问次数：%s<br>访问条件：%s%s</p>
<p style="color:#8b949e;font-size:12px">链接请勿转发。本邮件由系统自动发送，请勿直接回复。</p>
</div>`,
		html.EscapeString(senderName), html.EscapeString(objectName), html.EscapeString(link),
		html.EscapeString(expiry), html.EscapeString(uses), html.EscapeString(pwd),
		func() string {
			if verify == "" {
				return ""
			}
			return "<br>身份验证：" + html.EscapeString(verify)
		}())
	return subject, text, htmlBody
}

// enqueueShareMail 把分享链接投进外发队列（每个收件人一条，便于逐条重试与查状态）。
func (a *API) enqueueShareMail(ctx context.Context, tenantID, shareID, senderName, objectName,
	link string, opt share.Options, recipients []string) (int, error) {

	subject, text, htmlBody := shareMailBody(senderName, objectName, link, opt)
	queued := 0
	err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		for _, to := range recipients {
			if err := a.Outbox.Enqueue(ctx, tx, tenantID, notify.Message{
				To: to, Subject: subject, Text: text, HTML: htmlBody,
			}, "share.link", &shareID); err != nil {
				return err
			}
			queued++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return queued, nil
}

// senderDisplayName 取分享人的显示名（邮件里必须是人名，不是 UUID）。
func (a *API) senderDisplayName(ctx context.Context, tenantID, userID string) string {
	var name, username string
	_ = db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COALESCE(display_name,''), username FROM app_user WHERE id = $1`,
			userID).Scan(&name, &username)
	})
	if name != "" {
		return name
	}
	if username != "" {
		return username
	}
	return "同事"
}

// shareObjectName 取对象名，用于邮件标题与正文。
func (a *API) shareObjectName(ctx context.Context, tenantID, objectType, objectID string) string {
	if objectType == "node" {
		if n, err := a.Content.GetNode(ctx, tenantID, objectID); err == nil {
			return n.Name
		}
		return "文件"
	}
	var name string
	_ = db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name FROM space WHERE id = $1`, objectID).Scan(&name)
	})
	if name == "" {
		name = "空间"
	}
	return name
}
