// Package config 负责读取与校验配置。
//
// 纪律（踩坑 67）：启动即 fail-fast，并把"缺了哪些项"一次性列全，
// 不允许带默认值跑起来、等某个功能被触发时才在半夜报错。
package config

import (
	"fmt"
	"strings"
)

// 运行形态。
const (
	ModeDevelopment = "development" // 本地开发：允许弱密钥与缺省 DSN
	ModeStandalone  = "standalone"  // 私有化交付：单机/单集群
	ModeSaaS        = "saas"        // 多租户 SaaS
)

// 生产模式下禁止使用的弱密钥。
var weakSecrets = map[string]bool{
	"":          true,
	"changeme":  true,
	"change-me": true,
	"secret":    true,
	"docvault":  true,
	"password":  true,
	"0000000000000000000000000000000000000000": true,
}

// Config 是进程启动所需的全部外部配置。
type Config struct {
	Mode      string
	HTTPAddr  string
	JWTSecret string
	DBDSN     string

	// StorageDir 是内容存储根目录（内容寻址，按租户分目录）。
	StorageDir string

	// WebDir 是前端构建产物目录；为空或不存时只提供 API。
	WebDir string

	// ---- 预览与在线编辑 ----
	// PreviewEnabled 为真时尝试启用 LibreOffice 转 PDF；未装 soffice 会自动降级
	PreviewEnabled bool
	PreviewDir     string
	// ONLYOFFICE 文档服务
	OfficeURL       string
	OfficePublicURL string
	// InternalURL 是本系统对**服务端组件**（文档服务、回调）可达的地址。
	// 与 OfficePublicURL 分开：浏览器要用外网/主机地址，
	// 而同一 compose 网络里的文档服务要用服务名——两者常不是同一个。
	InternalURL     string
	OfficeJWTSecret string
	// OfficeInternalURL 是本系统访问文档服务的内部地址（容器网络）
	OfficeInternalURL  string
	OfficeAllowedHosts []string

	// MetricsToken 是 /metrics 的独立抓取令牌（与用户会话无关）。
	// 为空时指标端点返回 401。
	MetricsToken string

	// WatermarkDir 是 pdfcpu 的资源目录（字体库/配置）。
	// 必须是可写目录：容器内非 root 用户没有 HOME 时，pdfcpu 默认路径会直接 panic。
	WatermarkDir string
	// WatermarkFont 是水印用的中文字体（TrueType/glyf 轮廓）。
	// 为空或文件不存在时回退内置 Helvetica（只渲染 ASCII）。
	WatermarkFont string

	// ClamAV 扫描器地址（host:port）。为空表示未启用扫描。
	// 启用后上传会走 INSTREAM 扫描，扫描器故障时上传被拒（fail-closed）。
	ClamAVAddr    string
	ClamAVTimeout int // 秒

	// 限流阈值（按客户端 IP 计数，进程内）。
	// 公开端点（登录/开放链接）单独一档：它们是暴力破解与枚举的首选入口。
	RateRPS         float64
	RateBurst       int
	PublicRateRPS   float64
	PublicRateBurst int

	// PlatformToken 是平台运营跨租户只读访问的独立令牌。
	//
	// 为什么单独一个令牌而不是给某个用户加"平台角色"：
	// 跨租户读是**平台方**的能力，不该绑定到客户租户里的任何账号上；
	// 一旦绑成账号，客户管理员就能通过"给自己加角色"获得跨租户视野。
	// 为空时 /v1/platform/* 一律 401（fail-closed）。
	PlatformToken string

	// SecretKey 是"落库前加密"用的 32 字节密钥（base64）。
	// 目前只用于租户证书私钥。为空时"上传证书"接口直接拒绝——
	// 宁可功能不可用，也不把私钥明文写进随时会被 pg_dump 出去的库里。
	SecretKey string

	// 首个平台运营账号（仅在没有平台账号时创建一次）。
	// 与 PlatformToken 的分工：账号用于日常登录（可审计到人），
	// 静态令牌用于应急（平台账号全部不可用时仍能进）。
	PlatformAdminEmail    string
	PlatformAdminPassword string

	// AnchorSecret 是审计日结锚点的签名密钥。
	// 与 JWT 密钥分开：令牌密钥轮换不应让历史锚点全部验不过。
	AnchorSecret string

	// ---- 音视频 ----
	MediaEnabled bool
	MediaDir     string
	// 转码并发上限：默认 CPU 核数一半，最少 1
	MediaConcurrency int

	// ---- 目录（LDAP / AD）----
	LDAPURL          string
	LDAPStartTLS     bool
	LDAPInsecure     bool
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPBaseDN       string
	LDAPUserFilter   string
	LDAPGroupFilter  string
	// LDAPSyncFilter 是同步用的用户过滤条件（无占位符）
	LDAPSyncFilter string
	// LDAPExcludeAccounts 是不参与同步的账号名（逗号分隔）
	LDAPExcludeAccounts []string
	// LDAPCAFile 是信任的企业 CA 证书（PEM）。配了就做真实链校验，不再需要跳过校验
	LDAPCAFile string
	// LDAPTLSName 覆盖证书校验使用的名称（域控证书只有 DNS SAN 时按 IP 连需要它）
	LDAPTLSName string
	LDAPADMode  bool
	// LDAPAllowPlaintext 允许明文绑定（仅实验网；生产必须装 LDAP 证书）
	LDAPAllowPlaintext bool

	// ---- 通知通道（二选一或都配，都配时 SMTP 为主、Graph 为备）----
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPass     string
	SMTPFrom     string
	SMTPTLS      string // none | starttls | tls
	SMTPInsecure bool

	GraphTenantID     string
	GraphClientID     string
	GraphClientSecret string
	GraphSender       string
	GraphLoginBase    string
	GraphBase         string

	// DevSeed 为真时，空库自动创建演示租户与管理员（仅开发/演示用）。
	DevSeed          bool
	DevTenantSlug    string
	DevAdminUser     string
	DevAdminPassword string

	// TrustProxyCIDRs 为空表示不信任任何 X-Forwarded-For（0201-C2 的教训）。
	TrustProxyCIDRs []string

	// ---- 域身份单点登录（SSO）----
	//
	// 这里的 SSO 指"由前置反向代理完成 Windows 集成认证（SPNEGO/NTLM），
	// 把结果通过请求头传给本服务"。本服务不做 Kerberos 协商——
	// Go 的 HTTP 栈没有 SSPI，正确做法是由 IIS/nginx(SPNEGO 模块) 承担。
	//
	// 因此有三条硬门禁：启用开关、可信来源网段、可选共享密钥。
	// 任何一个不满足都拒登，绝不"宽松放行"。
	SSOEnabled      bool
	SSOHeader       string
	SSOSecret       string
	SSOTrustedCIDRs []string
	// SSODefaultTenant 是 SSO 尝试时使用的租户 slug。
	// 浏览器页面加载时还不知道用户属于哪个组织，而内网部署通常只有一个租户。
	SSODefaultTenant string
}

// Getenv 抽象环境变量读取，便于测试注入。
type Getenv func(string) string

// Load 读取并校验配置。返回的错误会列出全部问题项。
func Load(getenv Getenv) (Config, error) {
	c := Config{
		Mode:             strings.TrimSpace(getenv("DOCVAULT_MODE")),
		HTTPAddr:         strings.TrimSpace(getenv("DOCVAULT_HTTP_ADDR")),
		JWTSecret:        getenv("DOCVAULT_JWT_SECRET"),
		DBDSN:            strings.TrimSpace(getenv("DOCVAULT_DB_DSN")),
		StorageDir:       strings.TrimSpace(getenv("DOCVAULT_STORAGE_DIR")),
		WebDir:           strings.TrimSpace(getenv("DOCVAULT_WEB_DIR")),
		DevSeed:          strings.TrimSpace(getenv("DOCVAULT_DEV_SEED")) == "1",
		DevTenantSlug:    orDefault(strings.TrimSpace(getenv("DOCVAULT_DEV_TENANT")), "demo"),
		DevAdminUser:     orDefault(strings.TrimSpace(getenv("DOCVAULT_DEV_ADMIN")), "admin"),
		DevAdminPassword: getenv("DOCVAULT_DEV_ADMIN_PASSWORD"),

		// 预览与在线编辑
		PreviewEnabled:     strings.TrimSpace(getenv("DOCVAULT_PREVIEW_ENABLED")) != "0",
		PreviewDir:         orDefault(strings.TrimSpace(getenv("DOCVAULT_PREVIEW_DIR")), "./data/preview"),
		OfficeURL:          strings.TrimSpace(getenv("DOCVAULT_ONLYOFFICE_URL")),
		OfficePublicURL:    strings.TrimSpace(getenv("DOCVAULT_PUBLIC_URL")),
		InternalURL:        strings.TrimSpace(getenv("DOCVAULT_INTERNAL_URL")),
		OfficeJWTSecret:    getenv("DOCVAULT_ONLYOFFICE_JWT_SECRET"),
		OfficeInternalURL:  strings.TrimSpace(getenv("DOCVAULT_ONLYOFFICE_INTERNAL_URL")),
		OfficeAllowedHosts: splitCSV(getenv("DOCVAULT_ONLYOFFICE_ALLOWED_HOSTS")),

		// 音视频
		MediaEnabled:     strings.TrimSpace(getenv("DOCVAULT_MEDIA_ENABLED")) != "0",
		MediaDir:         orDefault(strings.TrimSpace(getenv("DOCVAULT_MEDIA_DIR")), "./data/media"),
		MediaConcurrency: atoiDefault(getenv("DOCVAULT_MEDIA_CONCURRENCY"), 0),

		// 审计
		AnchorSecret: getenv("DOCVAULT_ANCHOR_SECRET"),

		// 运维与平台令牌
		//
		// 这两个字段曾经只存在于结构体里、Load 忘了读——结果是"配了也不生效"，
		// 而且因为指标端点在未配置时本来就返回 401，缺陷完全静默。
		// load_new_test.go 现在逐个断言"写了环境变量就必须在 Config 里看到"。
		MetricsToken:  getenv("DOCVAULT_METRICS_TOKEN"),
		PlatformToken: getenv("DOCVAULT_PLATFORM_TOKEN"),

		// 落库加密与平台账号
		SecretKey:             strings.TrimSpace(getenv("DOCVAULT_SECRET_KEY")),
		PlatformAdminEmail:    strings.ToLower(strings.TrimSpace(getenv("DOCVAULT_PLATFORM_ADMIN"))),
		PlatformAdminPassword: getenv("DOCVAULT_PLATFORM_ADMIN_PASSWORD"),

		// 水印资源目录
		WatermarkDir:  orDefault(strings.TrimSpace(getenv("DOCVAULT_WATERMARK_DIR")), "./data/pdfcpu"),
		WatermarkFont: orDefault(strings.TrimSpace(getenv("DOCVAULT_WATERMARK_FONT")), "./assets/fonts/WVSans-Regular.ttf"),

		// 病毒扫描
		ClamAVAddr:    strings.TrimSpace(getenv("DOCVAULT_CLAMAV_ADDR")),
		ClamAVTimeout: atoiDefault(getenv("DOCVAULT_CLAMAV_TIMEOUT"), 30),

		// 限流
		RateRPS:         rateDefault(getenv("DOCVAULT_RATE_RPS"), 50),
		RateBurst:       atoiDefault(getenv("DOCVAULT_RATE_BURST"), 100),
		PublicRateRPS:   rateDefault(getenv("DOCVAULT_PUBLIC_RATE_RPS"), 2),
		PublicRateBurst: atoiDefault(getenv("DOCVAULT_PUBLIC_RATE_BURST"), 10),

		// 目录（LDAP / AD）
		LDAPURL:             strings.TrimSpace(getenv("DOCVAULT_LDAP_URL")),
		LDAPStartTLS:        strings.TrimSpace(getenv("DOCVAULT_LDAP_STARTTLS")) == "1",
		LDAPInsecure:        strings.TrimSpace(getenv("DOCVAULT_LDAP_INSECURE")) == "1",
		LDAPBindDN:          strings.TrimSpace(getenv("DOCVAULT_LDAP_BIND_DN")),
		LDAPBindPassword:    getenv("DOCVAULT_LDAP_BIND_PASSWORD"),
		LDAPBaseDN:          strings.TrimSpace(getenv("DOCVAULT_LDAP_BASE_DN")),
		LDAPUserFilter:      strings.TrimSpace(getenv("DOCVAULT_LDAP_USER_FILTER")),
		LDAPGroupFilter:     strings.TrimSpace(getenv("DOCVAULT_LDAP_GROUP_FILTER")),
		LDAPSyncFilter:      strings.TrimSpace(getenv("DOCVAULT_LDAP_SYNC_FILTER")),
		LDAPExcludeAccounts: splitCSV(getenv("DOCVAULT_LDAP_EXCLUDE_ACCOUNTS")),
		LDAPCAFile:          strings.TrimSpace(getenv("DOCVAULT_LDAP_CA_FILE")),
		LDAPTLSName:         strings.TrimSpace(getenv("DOCVAULT_LDAP_TLS_NAME")),
		LDAPADMode:          strings.TrimSpace(getenv("DOCVAULT_LDAP_AD_MODE")) == "1",
		LDAPAllowPlaintext:  strings.TrimSpace(getenv("DOCVAULT_LDAP_ALLOW_PLAINTEXT")) == "1",

		// 通知通道
		SMTPHost:     strings.TrimSpace(getenv("DOCVAULT_SMTP_HOST")),
		SMTPPort:     atoiDefault(getenv("DOCVAULT_SMTP_PORT"), 587),
		SMTPUser:     strings.TrimSpace(getenv("DOCVAULT_SMTP_USER")),
		SMTPPass:     getenv("DOCVAULT_SMTP_PASS"),
		SMTPFrom:     strings.TrimSpace(getenv("DOCVAULT_SMTP_FROM")),
		SMTPTLS:      orDefault(strings.TrimSpace(getenv("DOCVAULT_SMTP_TLS")), "starttls"),
		SMTPInsecure: strings.TrimSpace(getenv("DOCVAULT_SMTP_INSECURE")) == "1",

		GraphTenantID:     strings.TrimSpace(getenv("DOCVAULT_GRAPH_TENANT_ID")),
		GraphClientID:     strings.TrimSpace(getenv("DOCVAULT_GRAPH_CLIENT_ID")),
		GraphClientSecret: getenv("DOCVAULT_GRAPH_CLIENT_SECRET"),
		GraphSender:       strings.TrimSpace(getenv("DOCVAULT_GRAPH_SENDER")),
		GraphLoginBase:    strings.TrimSpace(getenv("DOCVAULT_GRAPH_LOGIN_BASE")),
		GraphBase:         strings.TrimSpace(getenv("DOCVAULT_GRAPH_BASE")),
	}
	c.SSOEnabled = strings.TrimSpace(getenv("DOCVAULT_SSO_ENABLED")) == "1"
	c.SSOHeader = orDefault(strings.TrimSpace(getenv("DOCVAULT_SSO_HEADER")), "X-Remote-User")
	c.SSOSecret = getenv("DOCVAULT_SSO_SHARED_SECRET")
	c.SSOTrustedCIDRs = splitCSV(getenv("DOCVAULT_SSO_TRUSTED_CIDRS"))
	c.SSODefaultTenant = strings.TrimSpace(getenv("DOCVAULT_SSO_DEFAULT_TENANT"))

	if raw := strings.TrimSpace(getenv("DOCVAULT_TRUST_PROXY_CIDRS")); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.TrustProxyCIDRs = append(c.TrustProxyCIDRs, p)
			}
		}
	}

	var problems []string

	if c.Mode == "" {
		c.Mode = ModeDevelopment
	}
	switch c.Mode {
	case ModeDevelopment, ModeStandalone, ModeSaaS:
	default:
		problems = append(problems, fmt.Sprintf("DOCVAULT_MODE=%q 非法，可选 development|standalone|saas", c.Mode))
	}

	if c.HTTPAddr == "" {
		c.HTTPAddr = ":8080"
	}
	if c.StorageDir == "" {
		c.StorageDir = "./data/blob"
	}
	if c.WebDir == "" {
		c.WebDir = "./web/dist"
	}
	// 未单独配置时，内部地址回落到对外地址（单机部署两者相同）
	if c.InternalURL == "" {
		c.InternalURL = c.OfficePublicURL
	}

	// 生产形态必须强密钥；开发形态允许留空以免阻塞本地调试。
	if c.Mode != ModeDevelopment {
		if weakSecrets[c.JWTSecret] {
			problems = append(problems, "DOCVAULT_JWT_SECRET 缺失或为弱值（至少 32 字节随机串）")
		} else if len(c.JWTSecret) < 32 {
			problems = append(problems, fmt.Sprintf("DOCVAULT_JWT_SECRET 长度 %d < 32", len(c.JWTSecret)))
		}
		if c.DBDSN == "" {
			problems = append(problems, "DOCVAULT_DB_DSN 缺失")
		}
	}

	if len(problems) > 0 {
		return Config{}, &Error{Problems: problems}
	}
	return c, nil
}

// Error 汇总全部配置问题。
type Error struct{ Problems []string }

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("配置校验失败：\n")
	for _, p := range e.Problems {
		b.WriteString("  - ")
		b.WriteString(p)
		b.WriteString("\n")
	}
	return b.String()
}

// IsSaaS 判断是否为多租户形态。
func (c Config) IsSaaS() bool { return c.Mode == ModeSaaS }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// atoiDefault 解析整数，失败时回退默认值。
// 配置里写错端口号不该让进程起不来，但也不该静默用 0——
// 所以这里只用于"有合理默认值"的字段（端口、并发数）。
func atoiDefault(v string, def int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 || n > 65535 {
		return def
	}
	return n
}

// splitCSV 解析逗号分隔列表，忽略空项。
func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// rateDefault 解析浮点阈值（如 50、2.5）。非法或非正数时回落到默认值——
// 限流参数写错不该让服务起不来，但必须回落到"有保护"的值，而不是 0（等于关闭）。
func rateDefault(v string, def float64) float64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	var (
		intPart, frac float64
		seenDot       bool
		scale         = 1.0
		ok            bool
	)
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			ok = true
			if seenDot {
				scale *= 10
				frac = frac*10 + float64(r-'0')
			} else {
				intPart = intPart*10 + float64(r-'0')
			}
		case r == '.' && !seenDot:
			seenDot = true
			ok = true
		default:
			return def
		}
	}
	if !ok {
		return def
	}
	out := intPart + frac/scale
	if out <= 0 {
		return def
	}
	return out
}
