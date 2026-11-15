package integrations

// 能力域目录。
//
// 为什么需要它：页面要按"能力域"组织（短信/邮件/目录/SSO…），但其中一部分
// 已经有专用配置页、一部分后端尚未接管。如果一律渲染成可编辑表单，
// 就会出现"能保存、但不生效"的假开关——这正是本项目反复强调要避免的。
//
// 三种状态在界面上有明确不同的表现：
//
//	available —— 可在此页配置（凭证中心接管）
//	external  —— 已有专用页面，这里只给入口（避免两处事实）
//	planned   —— 后端尚未接入，灰显并写明"保存不会生效"
type KindInfo struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	// PagePath 仅 external 使用：前端管理台内的相对路径。
	PagePath string `json:"pagePath,omitempty"`
}

// 能力域状态。
const (
	KindAvailable = "available"
	KindExternal  = "external"
	KindPlanned   = "planned"
)

// Catalog 返回全部能力域（顺序固定，前端按此渲染页签）。
func Catalog() []KindInfo {
	return []KindInfo{
		{Kind: KindSMS, Name: "短信通道", Status: KindAvailable,
			Description: "登录验证码与手机号验证。支持四家厂商，可由租户自带账号。"},
		{Kind: KindMail, Name: "邮件外发", Status: KindExternal, PagePath: "/admin/mail",
			Description: "审批通知与分享邮件。已有专用配置页（SMTP / Exchange Online）。"},
		{Kind: KindDirectory, Name: "目录认证", Status: KindExternal, PagePath: "/admin/directory",
			Description: "AD/LDAP 登录与组织同步。已有专用配置页。"},
		{Kind: KindSSO, Name: "统一登录 SSO", Status: KindPlanned,
			Description: "SAML / OIDC / OAuth2。租户级 IdP 注册表尚未接入，保存不会影响登录。"},
		{Kind: KindOnlyOffice, Name: "在线编辑", Status: KindPlanned,
			Description: "OnlyOffice 文档服务。凭证由部署环境决定，尚未做成租户级配置。"},
		{Kind: KindStorage, Name: "对象存储", Status: KindPlanned,
			Description: "S3 / OSS / MinIO。当前使用本机存储，切换存储属部署级变更。"},
		{Kind: KindGeoIP, Name: "IP 归属地", Status: KindPlanned,
			Description: "访问记录的 IP 归属。当前由部署时的离线库提供。"},
		{Kind: KindAntivirus, Name: "病毒扫描", Status: KindPlanned,
			Description: "ClamAV 接入。当前由部署环境变量决定。"},
	}
}

// KindStatus 返回某能力域的状态；未知域按 planned 处理（不给出可编辑入口）。
func KindStatus(kind string) string {
	for _, k := range Catalog() {
		if k.Kind == kind {
			return k.Status
		}
	}
	return KindPlanned
}
