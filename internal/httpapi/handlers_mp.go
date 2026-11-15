package httpapi

// 小程序专属端点：绑定 openid、登记订阅授权、读取能力。
//
// 为什么单开一组 /v1/mp/*：
//   - 它们只对小程序客户端有意义，网页端调了也没有用；
//   - 订阅消息的"授权余额"是有状态的（一次性订阅），不能用无状态的
//     /v1/features 表达。
//
// 三条纪律：
//   1. 未配置微信通道时，/v1/mp/config 返回 enabled=false（不是报错），
//      客户端据此隐藏入口——功能没开不应该表现成故障；
//   2. 绑定与登记都要审计（谁在什么时候开了提醒）；
//   3. openid 只由服务端用 code 换，绝不接受客户端直接上报 openid
//      （否则可以把自己的提醒指向别人的微信）。

import (
	"context"
	"net/http"
	"time"

	"docvault/internal/mpmsg"
)

func (a *API) registerMP(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mp/config", a.requireAuth(a.handleMPConfig))
	mux.HandleFunc("POST /v1/mp/bind", a.requireAuth(a.handleMPBind))
	mux.HandleFunc("POST /v1/mp/subscribe", a.requireAuth(a.handleMPSubscribe))
}

func (a *API) handleMPConfig(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	out := map[string]any{
		"enabled":                 false,
		"todoSubscribeTemplateId": "",
		"openidBound":             false,
		"remaining":               0,
	}
	if a.MP != nil && a.MP.Enabled() {
		out["enabled"] = true
		out["todoSubscribeTemplateId"] = a.MP.TemplateID()
		if n, bound, err := a.MP.Remaining(r.Context(), c.TenantID, c.Subject); err == nil {
			out["openidBound"] = bound
			out["remaining"] = n
		}
	}
	writeOK(w, r, out)
}

func (a *API) handleMPBind(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.MP == nil || !a.MP.Enabled() {
		writeErr(w, r, http.StatusNotImplemented, "NOT_CONFIGURED",
			"本部署未配置小程序消息通道（需要微信 AppID/AppSecret 与订阅消息模板）")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	openid, err := a.MP.Bind(r.Context(), c.TenantID, c.Subject, req.Code)
	if err != nil {
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "mp.bind", Result: "denied",
			Detail: map[string]any{"reason": err.Error()},
		})
		writeErr(w, r, http.StatusBadRequest, "MP_BIND_FAILED", "绑定微信失败："+err.Error())
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "mp.bind", Result: "ok",
		// openid 是外部标识，不能进 object_id（uuid 列），放 detail；
		// 也不写全量：留前 6 位足够在日志里对齐，泄漏了也没用
		Detail: map[string]any{"openidPrefix": prefixOf(openid, 6)},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"bound": true})
}

func (a *API) handleMPSubscribe(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.MP == nil || !a.MP.Enabled() {
		writeErr(w, r, http.StatusNotImplemented, "NOT_CONFIGURED", "本部署未配置小程序消息通道")
		return
	}
	var req struct {
		TemplateID string `json:"templateId"`
		Count      int    `json:"count"`
	}
	if !decode(w, r, &req) {
		return
	}
	left, err := a.MP.Grant(r.Context(), c.TenantID, c.Subject, req.TemplateID, req.Count)
	if err != nil {
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "mp.subscribe", Result: "denied",
			Detail: map[string]any{"reason": err.Error()},
		})
		writeErr(w, r, http.StatusBadRequest, "MP_SUBSCRIBE_FAILED", "登记订阅授权失败："+err.Error())
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "mp.subscribe", Result: "ok",
		Detail: map[string]any{"remaining": left},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"remaining": left})
}

// prefixOf 截取字符串前缀（openid 之类的外部标识只留前几位）。
func prefixOf(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// notifyApprovalAsync 在后台给审批人发一条小程序提醒。
//
// 为什么异步：微信接口会超时。同步发的话，一次抖动就让"创建外链"多等 8 秒，
// 严重点直接超时——用户会以为没建成，再点一次就多一条待审。
// 通知失败只记日志，不影响创建结果（分享已经落库且审批关系已确定）。
func (a *API) notifyApprovalAsync(tenantID, approverID, shareID, fileName, requester string) {
	if a.MP == nil || !a.MP.Enabled() {
		return
	}
	go func() {
		// 不能用请求的 ctx：请求返回后它就被取消，后台发送会立刻失败
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := a.MP.NotifyApproval(ctx, tenantID, approverID, mpmsg.Todo{
			FileName: fileName, Requester: requester, ShareID: shareID, CreatedAt: time.Now(),
		})
		if err == nil {
			return
		}
		switch {
		case err == mpmsg.ErrDisabled, err == mpmsg.ErrNoOpenID, err == mpmsg.ErrNoConsent:
			// 这三种是"用户/配置没准备好"，属于正常状态，不值得刷错误日志
			a.Log.Info("小程序审批提醒跳过", "shareId", shareID, "reason", err.Error())
		default:
			a.logErr("小程序审批提醒失败", "shareId", shareID, "err", err)
		}
	}()
}
