package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"docvault/internal/license"
	"docvault/internal/rbac"
)

// 本地版许可证（docs/47 §4.5）。
//
// 界面上只做三件事：显示实例指纹（客户申请时要发给我们）、粘贴许可证、看当前状态。
// 不用做成"激活码在线校验"——本地版必须能离线运行，联网校验只会让客户
// 在断网的内网里无法启动系统。

func (a *API) registerLicense(mux *http.ServeMux) {
	sys := a.requireRole(rbac.SysAdmin)
	mux.HandleFunc("GET /v1/admin/license", sys(a.handleLicenseStatus))
	mux.HandleFunc("POST /v1/admin/license", sys(a.handleLicenseApply))
}

func (a *API) handleLicenseStatus(w http.ResponseWriter, r *http.Request) {
	if a.License == nil {
		writeOK(w, r, license.Status{
			Reason: "许可证服务未启用（云端版无需许可证）",
		})
		return
	}
	st, err := a.License.Status(r.Context())
	if err != nil {
		a.logErr("读取许可证状态失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取许可证状态失败")
		return
	}
	writeOK(w, r, st)
}

func (a *API) handleLicenseApply(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.License == nil || !a.License.Enabled() {
		writeErr(w, r, http.StatusServiceUnavailable, "LICENSE_DISABLED",
			"本实例未配置许可证公钥（DOCVAULT_LICENSE_PUBKEY），无法校验许可证")
		return
	}
	var req struct {
		License string `json:"license"`
	}
	if !decode(w, r, &req) {
		return
	}
	blob := strings.TrimSpace(req.License)
	if blob == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "请粘贴许可证内容")
		return
	}

	p, err := a.License.Apply(r.Context(), c.TenantID, blob, c.Subject)
	if err != nil {
		switch {
		case errors.Is(err, license.ErrBadSignature):
			writeErr(w, r, http.StatusBadRequest, "LICENSE_BAD_SIGNATURE",
				"许可证签名无效：内容可能被改动，或用的是其它密钥签发")
		case errors.Is(err, license.ErrWrongInstance):
			// 这条要把两个指纹都给出来，否则客户只会回一句"不对啊"。
			writeErr(w, r, http.StatusPreconditionFailed, "LICENSE_WRONG_INSTANCE", err.Error())
		case errors.Is(err, license.ErrExpired):
			writeErr(w, r, http.StatusPreconditionFailed, "LICENSE_EXPIRED", err.Error())
		case errors.Is(err, license.ErrMalformed):
			writeErr(w, r, http.StatusBadRequest, "LICENSE_MALFORMED", err.Error())
		case errors.Is(err, license.ErrNoPublicKey):
			writeErr(w, r, http.StatusServiceUnavailable, "LICENSE_DISABLED", err.Error())
		default:
			a.logErr("应用许可证失败", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "应用许可证失败")
		}
		return
	}

	// 审计：许可证本身不是秘密（客户自己的授权凭据），但也没必要整串落库——
	// 记编号、客户、档位与到期足够回答"什么时候换过授权"。
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.license.apply",
		ObjectType: "instance_license", Result: "ok",
		Detail: map[string]any{
			"licenseId": p.LicenseID, "customer": p.Customer,
			"edition": p.Edition, "seats": p.Seats,
			"expiresAt": p.ExpiresAt, "instanceId": p.InstanceID,
		},
	})

	writeOK(w, r, map[string]any{
		"applied": true, "licenseId": p.LicenseID,
		"customer": p.Customer, "edition": p.Edition,
		"editionExpiresAt": nil,
	})
}
