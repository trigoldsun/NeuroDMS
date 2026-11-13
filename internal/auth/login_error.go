package auth

import (
	"errors"
	"strings"

	"docvault/internal/directory"
)

// LoginMode 是"用哪一种身份登录"。
//
// 同一个租户里，本地账号与域账号**允许同名**（0032 起唯一键含 source）。
// 因此登录时必须让用户显式选择身份；auto 只是给老客户端与"没有歧义"的场景留的兼容档。
type LoginMode string

const (
	// LoginAuto 不限来源：本地账号优先，其次域账号。
	//
	// 为什么本地优先：升级前一个租户里同名只可能有一条，而本地账号通常建立更早。
	// 若改成域优先，这些人的登录口令会突然从本地口令变成域口令，
	// 属于"升级后所有人都登不上"的破坏性变更。
	LoginAuto   LoginMode = "auto"
	LoginLocal  LoginMode = "local"
	LoginDomain LoginMode = "domain"
)

// ParseLoginMode 解析前端传来的登录方式。空值按 auto 处理（兼容旧客户端）。
func ParseLoginMode(raw string) (LoginMode, error) {
	switch LoginMode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", LoginAuto:
		return LoginAuto, nil
	case LoginLocal:
		return LoginLocal, nil
	case LoginDomain:
		return LoginDomain, nil
	default:
		return "", ErrUnknownLoginMode
	}
}

// 以下错误都带"用户下一步该做什么"，由 HTTP 层原样转给前端。
// 与 ErrInvalidCredentials 的区别：这些不是"再试一次"能解决的。
var (
	ErrUnknownLoginMode = errors.New("未知的登录方式")

	// ErrDomainNotSynced 域认证已通过（口令是对的），但系统里没有这个人的记录。
	// 只有口令验证通过后才会返回，因此不构成账号枚举。
	ErrDomainNotSynced = errors.New("域账号验证通过，但尚未同步到本系统")

	// ErrDirectoryNotConfigured 该租户没有启用域登录。
	ErrDirectoryNotConfigured = errors.New("该组织未启用域账号登录")

	// ErrDomainUnavailable 目录不可达（网络、证书、服务账号口令失效等）。
	ErrDomainUnavailable = errors.New("暂时无法连接组织的域控制器")

	ErrDomainLocked          = errors.New("域账号已被锁定")
	ErrDomainPasswordExpired = errors.New("域账号口令已过期")
	ErrDomainPasswordMustChg = errors.New("域账号需要先修改口令")
	ErrDomainDisabledInDir   = errors.New("域账号已在目录中被禁用")
)

// Hint 给出"下一步怎么做"。前端把它显示在错误信息下方。
//
// 集中在这里而不是散落在 handler 与前端：提示文案随错误语义走，
// 换一处实现也不会出现"后端改了错误码、前端还显示旧建议"。
func Hint(err error) string {
	switch {
	case errors.Is(err, ErrUnknownLoginMode):
		return "请刷新页面后重试；若仍失败，请联系管理员。"
	case errors.Is(err, ErrDomainNotSynced):
		return "请联系管理员在「管理台 → 目录认证」执行一次全量同步，同步完成后再登录。"
	case errors.Is(err, ErrDirectoryNotConfigured):
		return "请改用「本地账号」登录；若组织已接入 AD，请联系管理员在「管理台 → 目录认证」启用。"
	case errors.Is(err, ErrDomainUnavailable):
		return "请稍后重试；若持续失败，请联系管理员检查域控地址、网络连通性与证书是否过期。"
	case errors.Is(err, ErrDomainLocked):
		return "域策略会在一段时间后自动解锁（通常 30 分钟）。急需处理请联系 IT 在 AD 中解锁。"
	case errors.Is(err, ErrDomainPasswordExpired):
		return "请在加入域的电脑上按 Ctrl+Alt+Del 修改口令，然后回到本页面重新登录。"
	case errors.Is(err, ErrDomainPasswordMustChg):
		return "请先在域内修改口令（Ctrl+Alt+Del → 更改密码），再回到本页面登录。"
	case errors.Is(err, ErrDomainDisabledInDir):
		return "该账号已在目录中被停用，无法登录。如需恢复请联系 IT；离职账号请勿恢复。"
	case errors.Is(err, ErrAccountLocked):
		return "连续多次口令错误会触发临时锁定，请稍后再试，或联系管理员提前解锁。"
	case errors.Is(err, ErrAccountDisabled):
		return "该账号当前不可用（可能已停用或已过期），请联系管理员确认。"
	case errors.Is(err, ErrInvalidCredentials):
		return "" // 由前端按当前选择的登录方式给出针对性提示
	default:
		return ""
	}
}

// translateDirectoryError 把目录层错误收敛为认证层错误。
//
// 认证服务不应该把 directory 包的错误直接抛给上层：那样 HTTP 层要同时
// 认识两个包的错误集合，新增一种目录失败就得改两处。
func translateDirectoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, directory.ErrInvalidCredentials):
		return ErrInvalidCredentials
	case errors.Is(err, directory.ErrAccountLocked):
		return ErrDomainLocked
	case errors.Is(err, directory.ErrPasswordExpired):
		return ErrDomainPasswordExpired
	case errors.Is(err, directory.ErrPasswordMustChange):
		return ErrDomainPasswordMustChg
	case errors.Is(err, directory.ErrAccountDisabled):
		return ErrDomainDisabledInDir
	default:
		// 目录不可达或未启用：不要归到"口令错误"，否则运维会去查密码。
		return ErrDomainUnavailable
	}
}

// countsAsFailure 判断这次失败是否应该计入"口令错误次数"。
//
// 只有真正输错口令才计数。目录不可达、口令已过期、账号被锁这类情况
// 如果也计数，一次域控维护就会把全员账号锁死在本系统里——
// 那是把外部故障放大成自己的故障。
func countsAsFailure(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrPasswordMismatch)
}
