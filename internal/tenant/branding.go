package tenant

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/edition"
	"docvault/internal/entitlement"

	"github.com/jackc/pgx/v5"
)

// Branding 是租户品牌信息。
//
// Logo 以字节返回但**不**进 JSON（json:"-"）：base64 塞进每次品牌请求会把
// 响应从 1KB 撑到 300KB，而前端只需要一个可缓存的 URL。
type Branding struct {
	Slug         string `json:"slug"`
	TenantName   string `json:"tenantName"`
	Status       string `json:"status"`
	ProductName  string `json:"productName"`
	PrimaryColor string `json:"primaryColor"`
	AccentColor  string `json:"accentColor"`
	FooterText   string `json:"footerText"`
	// PrivacyURL 是对外公布的隐私政策地址（可为空 = 用平台默认页）。
	// 外发邮件正文底部、分享页页脚都会引用它——采集 IP 与访问记录必须告知。
	PrivacyURL string    `json:"privacyUrl"`
	Logo       []byte    `json:"-"`
	LogoMime   string    `json:"logoMime"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// LogoSHA 给前端做缓存指纹（Logo 变了 URL 才变）。
func (b Branding) LogoSHA() string {
	if len(b.Logo) == 0 {
		return ""
	}
	// 用长度 + 首尾字节做轻量指纹：这里只需要"变了就不同"，
	// 不需要密码学强度，也不值得为此算一次 SHA-256。
	h := len(b.Logo)
	for _, i := range []int{0, len(b.Logo) / 3, len(b.Logo) / 2, len(b.Logo) - 1} {
		h = h*131 + int(b.Logo[i])
	}
	return fmt.Sprintf("%x", uint32(h))
}

// LogoURL 返回图标的公开地址（带内容指纹：换图后 URL 才会变，缓存才会失效）。
//
// 拼装放在这里而不是各 handler 各写一遍：登录页、分享页页眉、浏览器标签图标
// 都用它，某一处少写了 v= 就会出现"侧栏有新图标、标签页还是旧的"——
// 这种问题只有客户能发现，排查成本极高。
func (b Branding) LogoURL(slug string) string {
	if len(b.Logo) == 0 {
		return ""
	}
	if slug == "" {
		slug = b.Slug
	}
	return "/v1/tenant/branding/logo?slug=" + url.QueryEscape(slug) + "&v=" + b.LogoSHA()
}

// LogoMimeOr 返回图标的 MIME；老数据可能没存，按 PNG 兜底。
func (b Branding) LogoMimeOr() string {
	if b.LogoMime == "" {
		return "image/png"
	}
	return b.LogoMime
}

// BrandingInput 是品牌更新请求。
type BrandingInput struct {
	ProductName  string `json:"productName"`
	PrimaryColor string `json:"primaryColor"`
	AccentColor  string `json:"accentColor"`
	FooterText   string `json:"footerText"`
	PrivacyURL   string `json:"privacyUrl"`
	Logo         []byte `json:"logoBase64"` // 允许一次提交，避免两段式上传的中间态
	LogoMime     string `json:"logoMime"`
	RemoveLogo   bool   `json:"removeLogo"`
}

const (
	maxLogoNames  = 256 << 10 // 256KB：与表约束一致
	maxFooterLen  = 200
	maxProductLen = 40

	// 像素上限：品牌 Logo 会渲染到**登录页与分享页**（未登录可见），
	// 也就是每一个访客都会解码它。256KB 的 JPEG 完全可以解成 8000×8000
	// （≈256MB 位图），那是一次访问就能触发的内存放大。
	// 界面上这个图标最大显示 30–40px，4096 已经远超任何合理需求。
	maxLogoPixels = 4096
	minLogoPixels = 16
)

// BrandingBySlug 读取品牌（公开，无租户上下文）。
func (s *Service) BrandingBySlug(ctx context.Context, slug string) (Branding, error) {
	return s.brandingQuery(ctx,
		`SELECT slug, name, status, product_name, primary_color, accent_color,
		        logo, logo_mime, footer_text, updated_at, privacy_url
		   FROM public_branding($1)`, strings.ToLower(strings.TrimSpace(slug)))
}

// BrandingByHost 按请求 Host 解析品牌（自有域名）。
//
// 域名未验证时**不**返回品牌：否则任何人绑一个域名就能把别人的分享页
// 挂到自己域名下，看起来像"官方站点"。
func (s *Service) BrandingByHost(ctx context.Context, host string) (Branding, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	var slug string
	err := s.pool.QueryRow(ctx,
		`SELECT tenant_slug FROM public_resolve_domain($1)`, host).Scan(&slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Branding{}, ErrNotFound
		}
		return Branding{}, err
	}
	return s.BrandingBySlug(ctx, slug)
}

func (s *Service) brandingQuery(ctx context.Context, q string, args ...any) (Branding, error) {
	var b Branding
	err := s.pool.QueryRow(ctx, q, args...).Scan(&b.Slug, &b.TenantName, &b.Status,
		&b.ProductName, &b.PrimaryColor, &b.AccentColor,
		&b.Logo, &b.LogoMime, &b.FooterText, &b.UpdatedAt, &b.PrivacyURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Branding{}, ErrNotFound
		}
		return Branding{}, err
	}
	return b, nil
}

// UpdateBranding 在租户上下文里更新品牌。
func (s *Service) UpdateBranding(ctx context.Context, tenantID string, in BrandingInput) error {
	in.ProductName = strings.TrimSpace(in.ProductName)
	in.PrimaryColor = strings.ToLower(strings.TrimSpace(in.PrimaryColor))
	in.AccentColor = strings.ToLower(strings.TrimSpace(in.AccentColor))
	in.FooterText = strings.TrimSpace(in.FooterText)
	in.PrivacyURL = strings.TrimSpace(in.PrivacyURL)
	in.LogoMime = strings.ToLower(strings.TrimSpace(in.LogoMime))

	if in.ProductName == "" {
		in.ProductName = "文档中心"
	}
	if len([]rune(in.ProductName)) > maxProductLen {
		return fmt.Errorf("%w: 产品名最多 %d 字", ErrInvalidInput, maxProductLen)
	}
	if !colorRe.MatchString(in.PrimaryColor) || !colorRe.MatchString(in.AccentColor) {
		return fmt.Errorf("%w: 颜色需为 #rrggbb", ErrInvalidInput)
	}
	if len([]rune(in.FooterText)) > maxFooterLen {
		return fmt.Errorf("%w: 页脚最多 %d 字", ErrInvalidInput, maxFooterLen)
	}
	// 隐私政策链接只允许 http(s)：它会被渲染成 <a href>，
	// javascript:/data: 之类在这里必须挡掉（分享页是未登录状态）。
	if in.PrivacyURL != "" {
		if len(in.PrivacyURL) > 500 {
			return fmt.Errorf("%w: 隐私政策链接过长", ErrInvalidInput)
		}
		u, err := url.Parse(in.PrivacyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: 隐私政策链接必须是 http(s) 地址", ErrInvalidInput)
		}
	}
	if in.RemoveLogo {
		in.Logo, in.LogoMime = nil, ""
	}
	if len(in.Logo) > 0 {
		switch in.LogoMime {
		case "image/png", "image/jpeg", "image/svg+xml", "image/webp":
		default:
			return fmt.Errorf("%w: Logo 仅支持 PNG/JPEG/SVG/WebP", ErrInvalidInput)
		}
		if len(in.Logo) > maxLogoNames {
			return fmt.Errorf("%w: Logo 不能超过 256KB", ErrInvalidInput)
		}
		// SVG 里可能带脚本；上传链路已净化，这里再挡一次明显特征，
		// 因为品牌 Logo 会被渲染到**登录页**——那是未登录状态。
		if in.LogoMime == "image/svg+xml" && containsScript(in.Logo) {
			return fmt.Errorf("%w: SVG 含脚本，已拒绝", ErrInvalidInput)
		}
		// 位图再查像素：字节数挡不住"小文件解成大位图"。
		// SVG 是矢量的，没有像素概念，跳过。
		if in.LogoMime != "image/svg+xml" {
			format, w, h, ok := imageProbe(in.Logo)
			want := map[string]string{
				"image/png": "png", "image/jpeg": "jpeg", "image/webp": "webp",
			}[in.LogoMime]
			if ok && want != "" && format != want {
				return fmt.Errorf("%w: 图标内容与声明的格式不一致（声明 %s，实际 %s）",
					ErrInvalidInput, want, format)
			}
			if ok {
				if w < minLogoPixels || h < minLogoPixels {
					return fmt.Errorf("%w: 图标至少 %d×%d 像素（当前 %d×%d），放大会模糊",
						ErrInvalidInput, minLogoPixels, minLogoPixels, w, h)
				}
				if w > maxLogoPixels || h > maxLogoPixels {
					return fmt.Errorf("%w: 图标最长边不能超过 %d 像素（当前 %d×%d）",
						ErrInvalidInput, maxLogoPixels, w, h)
				}
			}
		}
	}

	// 保留原值必须靠 SQL 自己算，不能用 EXCLUDED。
	//
	// 早期写法是 `logo = EXCLUDED.logo`，而"只改系统名称"的请求里 Logo 是 nil
	// → EXCLUDED.logo 为 NULL → **改个名字就把图标清空了**。
	// 三种意图必须分开表达：显式移除（removeLogo）、未提供（保留）、替换。
	keepLogo := len(in.Logo) == 0 && !in.RemoveLogo

	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_config (tenant_id, product_name, primary_color, accent_color,
			                           logo, logo_mime, footer_text, privacy_url, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
				product_name  = EXCLUDED.product_name,
				primary_color = EXCLUDED.primary_color,
				accent_color  = EXCLUDED.accent_color,
				logo          = CASE WHEN $9::bool THEN tenant_config.logo
				                     ELSE EXCLUDED.logo END,
				logo_mime     = CASE WHEN $9::bool THEN tenant_config.logo_mime
				                     ELSE EXCLUDED.logo_mime END,
				footer_text   = EXCLUDED.footer_text,
				privacy_url   = EXCLUDED.privacy_url,
				updated_at    = now()`,
			// 参数编号必须连续且**每个都被 SQL 引用**：
			// pgx 按最大 $N 发送参数，中间空号会得到
			// "could not determine data type of parameter $N"（实测踩到）。
			tenantID, in.ProductName, in.PrimaryColor, in.AccentColor,
			nullableLogo(in.Logo), nullifEmpty(in.LogoMime),
			in.FooterText, in.PrivacyURL, keepLogo)
		return err
	})
}

// containsScript 只做低成本的特征判断（品牌 Logo 不是不可信上传的主战场）。
func containsScript(b []byte) bool {
	l := strings.ToLower(string(b))
	return strings.Contains(l, "<script") || strings.Contains(l, "javascript:") ||
		strings.Contains(l, "onload=") || strings.Contains(l, "onerror=")
}

// ---------------- 租户策略 ----------------

// Policy 是租户级可调策略。
//
// 只放**真的会被读取**的项。加一个没人读的键，等于给客户一个假开关，
// 比不提供更糟：客户以为配置生效了，实际按全局默认在跑。
type Policy struct {
	// ShareDefaultExpireDays：创建外链未指定有效期时的默认天数。0 表示不过期。
	ShareDefaultExpireDays int `json:"shareDefaultExpireDays"`
	// MaxUploadMB：单文件上传上限（MB）。0 表示用系统默认。
	MaxUploadMB int `json:"maxUploadMB"`
	// AuditRetentionDays：操作日志与审计事件的保留天数。0 表示用系统默认（730 天 = 2 年）。
	//
	// 这个值决定清理任务删到哪一天。删的是**已经被日结锚点覆盖**的数据，
	// 所以缩短保留期不会让历史变成"无法验证的空白"——锚点仍能证明那段时间存在过。
	AuditRetentionDays int `json:"auditRetentionDays"`
	// VersionKeep：每个文件保留的历史版本数。0 表示用系统默认（10），上限 50。
	//
	// 版本清理只删"超过保留数量的非当前版本"，不会动当前内容；
	// 也不会删除 blob 与物理文件（那属于存储治理的 GC，另行实施）。
	VersionKeep int `json:"versionKeep"`

	// UploadTimeoutSeconds：单个上传请求允许的读取时长（秒）。0 表示用系统默认（300）。
	//
	// 为什么要按租户可配：上行带宽差别极大——同一份 5MB 文件，
	// 办公室 20 秒传完，移动网络要 3 分钟。写死一个值，要么让慢的一方永远失败，
	// 要么让快的一方等一个毫无意义的长超时。
	UploadTimeoutSeconds int `json:"uploadTimeoutSeconds"`

	// FolderUpload 是否在本租户启用"整目录上传"。
	//
	// 这是**档位能力之上的租户开关**，默认关闭：
	// 批量上传会一次产生大量目录与文件，是否开放应该由客户自己决定，
	// 而不是升级后被动生效。档位不支持时这个值不起作用（见 capabilities）。
	FolderUpload bool `json:"folderUpload"`

	// SmsLogin 是否允许"手机号 + 短信验证码"登录。
	//
	// 与 FolderUpload 同构：档位之上再要一次租户确认，默认关闭。
	// 理由是按条计费——开通即产生费用；而且手机号属于个人信息，
	// 不该因为升级到专业版就自动开始收集与使用。
	SmsLogin bool `json:"smsLogin"`

	// AllowedExts：允许上传的扩展名白名单（小写、带点，如 ".pdf"）。空表示不限制。
	//
	// 这是**入口约束**，不是安全边界——真正的安全检查靠危险扩展名与可执行魔数。
	// 目的是让"我们公司只收 office 和 pdf"这类要求在上传前就生效，
	// 而不是让用户传完 200MB 才被告知不支持。
	AllowedExts []string `json:"allowedExts,omitempty"`
}

// 上传超时（秒）的默认值与范围。
//
// 300 秒的依据：1MB 分片在 250 Kbps 上行下约 30 秒，加上代理抖动，
// 300 秒足够覆盖"分片重试一次"的最坏情况；上限 3600 让专线客户传超大分片也能过。
const (
	DefaultUploadTimeoutSeconds = 300
	MinUploadTimeoutSeconds     = 60
	MaxUploadTimeoutSeconds     = 3600
)

// 版本保留数的默认值与上限。
//
// 上限压到 50 而不是放开：版本历史几乎不会被逐版回退，超过几十个之后
// 客户只会在容量报表里看到一堆永远不会用到的条目。
const (
	DefaultVersionKeep = 10
	MaxVersionKeep     = 50
)

// 日志保留期的默认值、上下界（天）。
const (
	DefaultAuditRetentionDays = 730 // 2 年
	MinAuditRetentionDays     = 30
	MaxAuditRetentionDays     = 3650 // 10 年
)

// NormalizeRetention 把配置值收敛到合法区间。
//
// 0 视为"未配置"，落到默认 2 年；越界值夹到边界而不是报错——
// 清理任务读到坏配置时，宁可按最保守（最长）的保留期处理，
// 也不能因为一个手改错的值把日志删光。
func NormalizeRetention(days int) int {
	if days <= 0 {
		return DefaultAuditRetentionDays
	}
	if days < MinAuditRetentionDays {
		return MinAuditRetentionDays
	}
	if days > MaxAuditRetentionDays {
		return MaxAuditRetentionDays
	}
	return days
}

// PolicyFor 在租户上下文里读取策略；无配置时返回零值（由调用方套默认）。
func PolicyFor(ctx context.Context, tx pgx.Tx, tenantID string) (Policy, error) {
	var raw []byte
	err := tx.QueryRow(ctx,
		`SELECT policy FROM tenant_config WHERE tenant_id = $1`, tenantID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			// 解析失败按默认处理，但不能静默：策略坏掉时行为会与界面不一致
			return Policy{}, fmt.Errorf("租户策略无法解析: %w", err)
		}
	}
	// 读取侧补齐默认值：库里的 0 与"没配过"是同一含义，
	// 统一给出生效值，界面才不会显示 0 秒这种无法解释的数字。
	if p.UploadTimeoutSeconds == 0 {
		p.UploadTimeoutSeconds = DefaultUploadTimeoutSeconds
	}
	return p, nil
}

// WithDefaults 把"0 = 用系统默认"的字段填成生效值。
//
// 用途是与 SetPolicy 的落库值对齐：保存时它会把 0 换成默认值，
// 若审计拿"读取值（0）"去比"落库值（10）"，用户原样保存一次
// 也会被记成"版本保留数 0 → 10"的假变更。
//
// 刻意不做范围校验：只补默认值，校验仍由 SetPolicy 负责，
// 这里被错用也不会放过非法值。
func (p Policy) WithDefaults() Policy {
	if p.VersionKeep == 0 {
		p.VersionKeep = DefaultVersionKeep
	}
	if p.AuditRetentionDays == 0 {
		p.AuditRetentionDays = DefaultAuditRetentionDays
	}
	if p.UploadTimeoutSeconds == 0 {
		p.UploadTimeoutSeconds = DefaultUploadTimeoutSeconds
	}
	return p
}

// AllowsExt 判断文件名是否在白名单内。白名单为空表示不限制。
func (p Policy) AllowsExt(name string) bool {
	if len(p.AllowedExts) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	for _, e := range p.AllowedExts {
		if e == ext {
			return true
		}
	}
	return false
}

// NormalizeExts 规范化扩展名白名单：小写、补前导点、去重、排序。
//
// 空输入返回 nil（表示不限制），而不是空切片——两者在 JSON 里不同，
// [] 会被前端渲染成"一项都没选"，语义正好相反。
func NormalizeExts(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if len(e) < 2 || len(e) > 16 {
			return nil, fmt.Errorf("%w: 扩展名长度不合法: %s", ErrInvalidInput, raw)
		}
		for _, c := range e[1:] {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return nil, fmt.Errorf("%w: 扩展名只能含字母与数字: %s", ErrInvalidInput, raw)
			}
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Strings(out)
	return out, nil
}

// SetPolicy 由租户管理员更新策略。
//
// 返回**生效值**而不是 error-only：保留期在保存时会被收敛（0 → 730、越界夹到边界），
// 只回 error 的话调用方拿到的还是提交时的 0，界面会立刻显示 0——
// 用户以为没保存成功，再点一次，如此反复。
func (s *Service) SetPolicy(ctx context.Context, tenantID string, p Policy) (Policy, error) {
	if p.ShareDefaultExpireDays < 0 || p.ShareDefaultExpireDays > 3650 {
		return Policy{}, fmt.Errorf("%w: 默认有效期需在 0-3650 天", ErrInvalidInput)
	}
	if p.MaxUploadMB < 0 || p.MaxUploadMB > 1024*100 {
		return Policy{}, fmt.Errorf("%w: 上传上限需在 0-102400 MB", ErrInvalidInput)
	}
	if p.AuditRetentionDays != 0 &&
		(p.AuditRetentionDays < MinAuditRetentionDays || p.AuditRetentionDays > MaxAuditRetentionDays) {
		return Policy{}, fmt.Errorf("%w: 日志保留期需在 %d-%d 天（2 年请填 %d）",
			ErrInvalidInput, MinAuditRetentionDays, MaxAuditRetentionDays, DefaultAuditRetentionDays)
	}
	// 0 表示跟随系统默认，显式落成生效值，避免界面回显 0 让用户以为没保存
	if p.VersionKeep == 0 {
		p.VersionKeep = DefaultVersionKeep
	}
	if p.VersionKeep < 1 || p.VersionKeep > MaxVersionKeep {
		return Policy{}, fmt.Errorf("%w: 版本保留数需在 1-%d 之间", ErrInvalidInput, MaxVersionKeep)
	}
	// 统一落库为"生效值"：否则界面回显 0，用户以为没保存
	p.AuditRetentionDays = NormalizeRetention(p.AuditRetentionDays)

	if p.UploadTimeoutSeconds == 0 {
		p.UploadTimeoutSeconds = DefaultUploadTimeoutSeconds
	}
	if p.UploadTimeoutSeconds < MinUploadTimeoutSeconds || p.UploadTimeoutSeconds > MaxUploadTimeoutSeconds {
		return Policy{}, fmt.Errorf("%w: 上传超时需在 %d-%d 秒之间",
			ErrInvalidInput, MinUploadTimeoutSeconds, MaxUploadTimeoutSeconds)
	}

	exts, eerr := NormalizeExts(p.AllowedExts)
	if eerr != nil {
		return Policy{}, eerr
	}
	p.AllowedExts = exts

	raw, err := json.Marshal(p)
	if err != nil {
		return Policy{}, err
	}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO tenant_config (tenant_id, policy, updated_at)
			VALUES ($1, $2::jsonb, now())
			ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()`,
			tenantID, raw)
		return e
	})
	return p, err
}

// GetPolicy 读取策略（管理台展示用）。
func (s *Service) GetPolicy(ctx context.Context, tenantID string) (Policy, error) {
	var p Policy
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var e error
		p, e = PolicyFor(ctx, tx, tenantID)
		return e
	})
	return p, err
}

// LoginMethods 是登录页需要的"这家租户支持哪些登录方式"。
//
// 只暴露布尔值：不返回租户名、不返回开关细节，
// 避免它变成一个"探测某组织配了什么"的接口。
type LoginMethods struct {
	Password bool `json:"password"`
	SMS      bool `json:"sms"`
}

// LoginMethodsBySlug 判断该租户当前是否对外开放短信验证码登录。
//
// 与 /v1/me/capabilities 用的是同一套判定（档位 × 租户开关），
// 区别只在"没有登录态"——登录页要在输密码之前就知道该不该显示这个入口。
// 通道是否配置由调用方（httpapi）叠加，这里只管租户侧的两个开关。
func (s *Service) LoginMethodsBySlug(ctx context.Context, slug string) (LoginMethods, error) {
	out := LoginMethods{Password: true}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return out, nil
	}
	var (
		id, declared, status string
		expires              *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, edition, status, edition_expires_at
		  FROM tenant
		 WHERE slug = $1 AND deleted_at IS NULL`, slug).Scan(&id, &declared, &status, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		// 租户不存在时返回"只有口令登录"，不报错：
		// 报错等于告诉外面"这个组织标识不存在"，登录页不需要这个信息。
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !Usable(status) {
		return out, nil
	}
	st := edition.Resolve(declared, expires, time.Now())
	// 授权层：档位默认之外还要看单项加购/强制关（docs/47 §4.1）。
	// 未装配授权服务时按未开通处理——登录页多显示一个点不动的入口，
	// 比"看起来能用、点进去 503"更糟。
	if s.ents == nil {
		return out, nil
	}
	ok, eerr := s.ents.Entitled(ctx, id, entitlement.SMSLogin, st.Edition)
	if eerr != nil || !ok {
		return out, nil
	}
	pol, err := s.GetPolicy(ctx, id)
	if err != nil {
		// 策略读不到一律按"未开通"（fail-closed）：不能因为读失败就放出一个
		// 实际会 503 的登录入口。
		return out, nil
	}
	out.SMS = pol.SmsLogin
	return out, nil
}

// CreateState 报告租户当前的可用形态，供中间件与业务入口判断。
type CreateState struct {
	Status string
}

// ReadOnly 判断该状态是否只读（只允许读操作）。
func ReadOnly(status string) bool { return status == StatusReadonly }

// Usable 判断该状态是否允许登录（suspended/deleted 不允许）。
func Usable(status string) bool {
	return status == StatusActive || status == StatusTrial || status == StatusReadonly
}

// SlugOf 返回租户自己的 slug（需要在租户上下文中调用）。
//
// 用租户上下文查 tenant 表是可行的：tenant 的 RLS 策略就是 id = app.tenant_id，
// 因此这里只能读到"自己"那一行，不需要额外的跨租户函数。
func (s *Service) SlugOf(ctx context.Context, tenantID string) (string, error) {
	var slug string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT slug FROM tenant WHERE id = $1`, tenantID).Scan(&slug)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return slug, err
}

// ---------------- Logo 解码辅助 ----------------

func nullableLogo(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// nullifEmpty 返回 *string 而不是 any：
// any 在 pgx 里是 unknown 类型，SQL 侧无法推断参数类型，会直接报
// "could not determine data type of parameter"（实测踩到）。
func nullifEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// imageProbe 读位图头部拿「格式 + 宽高」，不做完整解码。
//
// 只支持 PNG / JPEG / WebP（与 mime 白名单一致）。解析不出来时 ok=false，
// 调用方按"无法判定"放行——头部损坏的图浏览器也显示不出来，
// 没必要为了一个读不到的尺寸把正常上传堵死。
//
// 同时返回 format：客户的 file.type 有时是空的或是错的（拖拽、改扩展名），
// "上传成功但登录页破图"最难排查，所以顺手校验声明与内容是否一致。
func imageProbe(b []byte) (format string, w, h int, ok bool) {
	switch {
	case len(b) >= 24 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		// IHDR：长度(4) 类型(4) 宽(4) 高(4)，大端
		return "png", int(binary.BigEndian.Uint32(b[16:20])), int(binary.BigEndian.Uint32(b[20:24])), true
	case len(b) >= 21 && bytes.Equal(b[:4], []byte{'R', 'I', 'F', 'F'}) &&
		bytes.Equal(b[8:12], []byte{'W', 'E', 'B', 'P'}):
		w, h, ok = webpSize(b)
		return "webp", w, h, ok
	case len(b) > 3 && b[0] == 0xFF && b[1] == 0xD8:
		w, h, ok = jpegSize(b)
		return "jpeg", w, h, ok
	}
	return "", 0, 0, false
}

// webpSize 支持 VP8X（扩展，带画布尺寸）、VP8（有损）、VP8L（无损）。
func webpSize(b []byte) (int, int, bool) {
	switch string(b[12:16]) {
	case "VP8X":
		// 画布宽高各 3 字节（小端，值 = 实际 - 1），偏移 24 与 27
		if len(b) < 30 {
			return 0, 0, false
		}
		w := int(uint32(b[24])|uint32(b[25])<<8|uint32(b[26])<<16) + 1
		h := int(uint32(b[27])|uint32(b[28])<<8|uint32(b[29])<<16) + 1
		return w, h, true
	case "VP8 ":
		if len(b) < 30 {
			return 0, 0, false
		}
		// 帧头：3 字节起始码 9d 01 2a 之后是宽高（各 14 位，小端）
		w := int(binary.LittleEndian.Uint16(b[26:28]) & 0x3FFF)
		h := int(binary.LittleEndian.Uint16(b[28:30]) & 0x3FFF)
		return w, h, w > 0 && h > 0
	case "VP8L":
		if len(b) < 25 {
			return 0, 0, false
		}
		bits := binary.LittleEndian.Uint32(b[21:25])
		w := int(bits&0x3FFF) + 1
		h := int((bits>>14)&0x3FFF) + 1
		return w, h, true
	}
	return 0, 0, false
}

// jpegSize 遍历段直到 SOFn（段标记 C0–CF，排除 C4/C8/CC）。
func jpegSize(b []byte) (w, h int, ok bool) {
	i := 2
	for i+9 < len(b) {
		if b[i] != 0xFF {
			i++
			continue
		}
		marker := b[i+1]
		// 填充字节
		if marker == 0xFF {
			i++
			continue
		}
		// 无长度字段的标记
		if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 {
			i += 2
			continue
		}
		segLen := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		isSOF := marker >= 0xC0 && marker <= 0xCF &&
			marker != 0xC4 && marker != 0xC8 && marker != 0xCC
		if isSOF {
			h = int(binary.BigEndian.Uint16(b[i+5 : i+7]))
			w = int(binary.BigEndian.Uint16(b[i+7 : i+9]))
			return w, h, w > 0 && h > 0
		}
		if segLen < 2 {
			return 0, 0, false
		}
		i += 2 + segLen
	}
	return 0, 0, false
}
