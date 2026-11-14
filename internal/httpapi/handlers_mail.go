package httpapi

// 邮件服务配置（SMTP / Exchange Online）。
//
// 背景：通道此前只能靠环境变量配置，管理员在界面上看不到、也改不了。
// 客户现场最常问的两个问题——"为什么验证码收不到"、"能不能用我们自己的邮箱发"——
// 都因为缺少这一页而必须让运维动容器。
//
// 权限只给 sysadmin：邮件配置含口令/客户端密钥，能改它就等于能
// 以企业邮箱名义发信（钓鱼的起点），与"改谁能登录"同级。
// secadmin（管密级）与 auditor（只读审计）都不应能改。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/notify"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
)

func (a *API) registerMail(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/mail", a.requireRole(rbac.SysAdmin)(a.handleGetMail))
	mux.HandleFunc("PUT /v1/admin/mail", a.requireRole(rbac.SysAdmin)(a.handlePutMail))
	mux.HandleFunc("POST /v1/admin/mail/test", a.requireRole(rbac.SysAdmin)(a.handleTestMail))
}

// handleGetMail 返回当前配置、平台默认通道状态与队列概况。
//
// 特意把"队列里有没有卡住/终止的邮件"一起返回：管理员来这一页，
// 十有八九是"用户说没收到"。只给配置，他仍然不知道邮件到底发没发出去。
func (a *API) handleGetMail(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Mail == nil {
		writeErr(w, r, http.StatusNotImplemented, "MAIL_CONFIG_UNAVAILABLE", "邮件配置未启用")
		return
	}
	s, err := a.Mail.Load(r.Context(), c.TenantID)
	if err != nil {
		a.logErr("读取邮件配置失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取邮件配置失败")
		return
	}
	// Settings 的 MarshalJSON 保证口令/密钥不出现在响应里。
	// effectiveFromName 是"实际会写进 From 头"的显示名：
	// 配置留空时由系统名称生成，界面要能回显，否则管理员不知道对方看到的是什么。
	writeOK(w, r, map[string]any{
		"config":            s,
		"effectiveFromName": a.mailFromName(r.Context(), c.TenantID, s.FromName),
		"environment": map[string]any{
			"defaultConfigured":  a.MailRouter != nil && a.MailRouter.Fallback() != nil,
			"defaultChannels":    a.mailDefaultChannels(),
			"secretKeyAvailable": a.Mail.Available(),
		},
		"outbox": a.mailOutboxStats(r.Context(), c.TenantID),
	})
}

func (a *API) mailDefaultChannels() []string {
	if a.MailRouter == nil || a.MailRouter.Fallback() == nil {
		return []string{}
	}
	return a.MailRouter.Fallback().Channels()
}

// mailOutboxStats 汇总最近 7 天的发送情况。
func (a *API) mailOutboxStats(ctx context.Context, tenantID string) map[string]any {
	out := map[string]any{"pending": 0, "failed": 0, "dead": 0, "sent24h": 0, "recent": []any{}}
	recent := []map[string]any{}
	var pending, failed, dead, sent24h int
	// 必须在一个事务里读完：rows 的生命周期绑定在事务上，
	// 拿出去再遍历会因为连接已归还而拿不到数据（或直接报错）。
	err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FILTER (WHERE status = 'pending'),
			       COUNT(*) FILTER (WHERE status = 'failed'),
			       COUNT(*) FILTER (WHERE status = 'dead'),
			       COUNT(*) FILTER (WHERE status = 'sent' AND sent_at > now() - interval '24 hours')
			  FROM notification
			 WHERE tenant_id = $1 AND created_at > now() - interval '7 days'`, tenantID).
			Scan(&pending, &failed, &dead, &sent24h); err != nil {
			return err
		}
		// 最近的失败单独列出：只有计数仍然回答不了"发给谁失败了、为什么"
		rows, err := tx.Query(ctx, `
			SELECT to_addr, purpose, COALESCE(last_error, ''), created_at
			  FROM notification
			 WHERE tenant_id = $1 AND status IN ('failed', 'dead')
			 ORDER BY created_at DESC LIMIT 5`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				to, purpose, lastErr string
				at                   time.Time
			)
			if err := rows.Scan(&to, &purpose, &lastErr, &at); err != nil {
				return err
			}
			recent = append(recent, map[string]any{
				"to": to, "purpose": purpose, "error": lastErr, "at": at,
			})
		}
		return rows.Err()
	})
	if err != nil {
		// 统计失败不该让整个配置页打不开：配置本身仍可查看与修改
		a.logErr("统计通知队列失败", "err", err)
		return out
	}
	out["pending"], out["failed"], out["dead"], out["sent24h"] = pending, failed, dead, sent24h
	out["recent"] = recent
	return out
}

// handlePutMail 保存配置。
func (a *API) handlePutMail(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Mail == nil {
		writeErr(w, r, http.StatusNotImplemented, "MAIL_CONFIG_UNAVAILABLE", "邮件配置未启用")
		return
	}
	var in notify.Settings
	if !decode(w, r, &in) {
		return
	}
	// 没有密钥就无法加密保存口令；明文落库是绝对不能接受的降级。
	// 只在"这次真的要写口令"时拦截：仅切换 mode 或改发件地址不该被挡住。
	if !a.Mail.Available() && (in.SMTPPassword != "" || in.GraphClientSecret != "") {
		writeErr(w, r, http.StatusConflict, "NO_SECRET_KEY",
			"未配置 DOCVAULT_SECRET_KEY，无法加密保存邮件口令")
		return
	}

	// 改前值：Save 会覆盖，必须在它之前读
	beforeCfg, _ := a.Mail.Load(r.Context(), c.TenantID)

	saved, err := a.Mail.Save(r.Context(), c.TenantID, c.Subject, in)
	if err != nil {
		switch {
		case errors.Is(err, notify.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		case errors.Is(err, notify.ErrNoSecretKey):
			writeErr(w, r, http.StatusConflict, "NO_SECRET_KEY", err.Error())
		default:
			a.logErr("保存邮件配置失败", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存失败")
		}
		return
	}
	a.invalidateMail(c.TenantID)

	// 只记主机与发件地址，不记口令、密钥与用户名（用户名常含个人信息）。
	// 但这些"不记值"的字段仍然要留一个"是否被改过"的标记：
	// 否则调查"邮件为什么发不出去"时，无法判断是不是有人换过口令。
	detail := auditDiff(mailSnapshot(beforeCfg), mailSnapshot(saved))
	if beforeCfg.SMTPUser != saved.SMTPUser {
		detail["smtpUserChanged"] = true
	}
	if in.SMTPPassword != "" {
		detail["smtpPasswordChanged"] = true
	}
	if in.GraphClientSecret != "" {
		detail["graphSecretChanged"] = true
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "mail.config.update", Result: "ok",
		Detail: detail,
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"config": saved})
}

// handleTestMail 用提交的配置发一封测试邮件（不要求先保存）。
//
// 与目录认证的"测试连接"同一思路：管理员常常要试三四组参数，
// 强制先保存会让"试"变成"改线上配置"。
func (a *API) handleTestMail(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Mail == nil {
		writeErr(w, r, http.StatusNotImplemented, "MAIL_CONFIG_UNAVAILABLE", "邮件配置未启用")
		return
	}
	var req struct {
		notify.Settings
		To string `json:"to"`
	}
	if !decode(w, r, &req) {
		return
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "请填写收件邮箱（建议用你自己的邮箱）")
		return
	}

	// 口令留空 = 用已保存的那个（"我只改了端口，用原口令测一下"是最常见的操作）
	saved, err := a.Mail.Load(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取已保存的配置失败")
		return
	}
	s := req.Settings
	// 显示名留空 = 用品牌默认值（与真实发信一致，测试结果才有参考价值）
	s.FromName = a.mailFromName(r.Context(), c.TenantID, s.FromName)
	if s.SMTPPassword == "" {
		s.SMTPPassword = saved.SMTPPassword
	}
	if s.GraphClientSecret == "" {
		s.GraphClientSecret = saved.GraphClientSecret
	}

	var disp *notify.Dispatcher
	channel := s.Mode
	switch s.Mode {
	case notify.ModeInherit, "":
		channel = "inherit"
		if a.MailRouter != nil {
			disp = a.MailRouter.Fallback()
		}
		if disp == nil {
			writeErr(w, r, http.StatusBadRequest, "NO_DEFAULT_CHANNEL",
				"当前是「跟随平台默认」，但平台没有配置默认邮件通道；请改选 SMTP 或 Exchange Online")
			return
		}
	default:
		// 复用保存时的校验：测试与保存的口径必须一致，
		// 否则会出现"测试通过、保存被拒"或反之的困惑。
		if err := a.Mail.Validate(s, saved); err != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		disp, err = s.Dispatcher()
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	msg := notify.Message{
		To:      to,
		Subject: "NeuroDMS 邮件通道测试",
		Text: fmt.Sprintf("这是一封测试邮件。\n\n如果你在 %s 收到它，说明当前邮件配置可用。\n通道：%s\n发件人：%s\n",
			time.Now().Format("2006-01-02 15:04:05"), channel, firstNonEmpty(s.FromAddr, s.GraphSender)),
		ReplyTo: s.ReplyTo,
	}
	sendErr := disp.Send(ctx, msg)
	_ = a.Mail.MarkTest(ctx, c.TenantID, to, sendErr == nil, sendErr)

	result := "ok"
	msgText := "测试邮件已发出，请查收（含垃圾箱）"
	if sendErr != nil {
		result = "error"
		msgText = sendErr.Error()
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "mail.config.test", Result: result,
		Detail: map[string]any{"mode": channel, "to": to},
	})
	// 连通失败不是 500：这是"测试的结论"，界面要展示原因而不是弹系统错误
	writeOK(w, r, map[string]any{
		"ok":      sendErr == nil,
		"channel": channel,
		"message": msgText,
	})
}

func (a *API) invalidateMail(tenantID string) {
	if a.MailRouter != nil {
		a.MailRouter.Invalidate(tenantID)
	}
}

// mailAvailable 判断"这个租户现在能不能真的发出邮件"。
//
// 不能只看 a.Outbox 是否为 nil：接入租户级配置后，队列几乎总是存在，
// 而"没配任何通道"的情况下消息会入队、发送失败、最后进 dead——
// 用户以为邮件发了，其实没有。宁可在创建分享时就如实告知"服务器不会发邮件"。
func (a *API) mailAvailable(ctx context.Context, tenantID string) bool {
	if a.Outbox == nil {
		return false
	}
	if a.Mail == nil {
		// 旧装配（没有租户配置仓库）：队列存在即视为可用
		return true
	}
	s, err := a.Mail.Load(ctx, tenantID)
	if err == nil && s.Mode != "" && s.Mode != notify.ModeInherit {
		return true
	}
	return a.MailRouter != nil && a.MailRouter.Fallback() != nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// mailSnapshot 取邮件配置里"可比较且不含机密"的字段。
//
// 不含口令、客户端密钥与用户名：前两者进了审计就等于泄密，
// 后者常含个人信息（hu.zhangsan@corp 这类）。它们的变化用 xxxChanged 标记。
func mailSnapshot(s notify.Settings) map[string]any {
	return map[string]any{
		"mode":               s.Mode,
		"fromAddr":           s.FromAddr,
		"fromName":           s.FromName,
		"replyTo":            s.ReplyTo,
		"smtpHost":           s.SMTPHost,
		"smtpPort":           s.SMTPPort,
		"smtpTls":            s.SMTPTLS,
		"smtpInsecure":       s.SMTPInsecure,
		"smtpAllowPlaintext": s.SMTPAllowPlaintext,
		"graphTenantId":      s.GraphTenantID,
		"graphClientId":      s.GraphClientID,
		"graphSender":        s.GraphSender,
		"graphLoginBase":     s.GraphLoginBase,
		"graphBase":          s.GraphBase,
	}
}
