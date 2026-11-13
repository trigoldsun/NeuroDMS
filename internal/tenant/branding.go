package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// Branding 是租户品牌信息。
//
// Logo 以字节返回但**不**进 JSON（json:"-"）：base64 塞进每次品牌请求会把
// 响应从 1KB 撑到 300KB，而前端只需要一个可缓存的 URL。
type Branding struct {
	Slug         string    `json:"slug"`
	TenantName   string    `json:"tenantName"`
	Status       string    `json:"status"`
	ProductName  string    `json:"productName"`
	PrimaryColor string    `json:"primaryColor"`
	AccentColor  string    `json:"accentColor"`
	FooterText   string    `json:"footerText"`
	Logo         []byte    `json:"-"`
	LogoMime     string    `json:"logoMime"`
	UpdatedAt    time.Time `json:"updatedAt"`
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

// BrandingInput 是品牌更新请求。
type BrandingInput struct {
	ProductName  string `json:"productName"`
	PrimaryColor string `json:"primaryColor"`
	AccentColor  string `json:"accentColor"`
	FooterText   string `json:"footerText"`
	Logo         []byte `json:"logoBase64"` // 允许一次提交，避免两段式上传的中间态
	LogoMime     string `json:"logoMime"`
	RemoveLogo   bool   `json:"removeLogo"`
}

const (
	maxLogoNames  = 256 << 10 // 256KB：与表约束一致
	maxFooterLen  = 200
	maxProductLen = 40
)

// BrandingBySlug 读取品牌（公开，无租户上下文）。
func (s *Service) BrandingBySlug(ctx context.Context, slug string) (Branding, error) {
	return s.brandingQuery(ctx,
		`SELECT slug, name, status, product_name, primary_color, accent_color,
		        logo, logo_mime, footer_text, updated_at
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
		&b.Logo, &b.LogoMime, &b.FooterText, &b.UpdatedAt)
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
	}

	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_config (tenant_id, product_name, primary_color, accent_color,
			                           logo, logo_mime, footer_text, updated_at)
			VALUES ($1, $2, $3, $4, $5, nullif($6,''), $7, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
				product_name  = EXCLUDED.product_name,
				primary_color = EXCLUDED.primary_color,
				accent_color  = EXCLUDED.accent_color,
				logo          = EXCLUDED.logo,
				logo_mime     = EXCLUDED.logo_mime,
				footer_text   = EXCLUDED.footer_text,
				updated_at    = now()`,
			tenantID, in.ProductName, in.PrimaryColor, in.AccentColor,
			in.Logo, in.LogoMime, in.FooterText)
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
