package notify

// 邮件通道的租户级配置（管理台可改）。
//
// 三条纪律，与目录认证（internal/directory/settings.go）一致：
//  1. 口令/密钥只写不读：读接口永不回显，留空表示"沿用已保存的值"；
//  2. 没配密钥（DOCVAULT_SECRET_KEY）就拒绝保存，绝不静默降级为明文落库；
//  3. 校验失败的错误信息面向管理员，可直接展示在界面上。
//
// 与目录配置不同的是"继承"语义：mode=inherit 表示继续用环境变量配置的
// 平台默认通道。这样升级到本版本时所有租户行为不变，管理员可以逐租户切换。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/secretbox"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidInput 表示配置本身不合法（可直接展示给管理员）。
var ErrInvalidInput = errors.New("配置不合法")

// ErrNoSecretKey 表示没有加密密钥，无法安全保存口令。
var ErrNoSecretKey = errors.New("未配置 DOCVAULT_SECRET_KEY，无法加密保存邮件口令")

// 通道模式。
const (
	ModeInherit = "inherit"
	ModeSMTP    = "smtp"
	ModeGraph   = "graph"
)

// Settings 是租户的邮件配置。口令字段只写不读。
type Settings struct {
	Mode     string `json:"mode"`
	FromAddr string `json:"fromAddr"`
	FromName string `json:"fromName"`
	ReplyTo  string `json:"replyTo"`

	SMTPHost string `json:"smtpHost"`
	SMTPPort int    `json:"smtpPort"`
	// SMTPTLS: none | starttls | tls
	SMTPTLS  string `json:"smtpTls"`
	SMTPUser string `json:"smtpUser"`
	// SMTPPassword 只写不读；留空表示沿用已保存的口令。
	//
	// 不能用 json:"-"：那样请求体里的口令根本不会被解析，保存时永远是空，
	// 表现为"界面上显示已保存，实际口令静默丢失"。
	SMTPPassword string `json:"smtpPassword,omitempty"`
	// SMTPInsecure 仅用于自签名证书的内网邮件网关。
	SMTPInsecure bool `json:"smtpInsecure"`
	// SMTPAllowPlaintext 允许在明文连接（tls=none）下发送口令。
	SMTPAllowPlaintext bool `json:"smtpAllowPlaintext"`

	GraphTenantID string `json:"graphTenantId"`
	GraphClientID string `json:"graphClientId"`
	// GraphClientSecret 只写不读。
	GraphClientSecret string `json:"graphClientSecret,omitempty"`
	GraphSender       string `json:"graphSender"`
	GraphLoginBase    string `json:"graphLoginBase"`
	GraphBase         string `json:"graphBase"`

	// ---- 以下为读接口附加信息，保存时忽略 ----
	Source          string     `json:"source"` // database | none
	HasSMTPPassword bool       `json:"hasSmtpPassword"`
	HasGraphSecret  bool       `json:"hasGraphSecret"`
	UpdatedAt       *time.Time `json:"updatedAt,omitempty"`
	LastTestAt      *time.Time `json:"lastTestAt,omitempty"`
	LastTestTo      string     `json:"lastTestTo,omitempty"`
	LastTestOK      *bool      `json:"lastTestOk,omitempty"`
	LastTestError   string     `json:"lastTestError,omitempty"`
}

// MarshalJSON 显式列出可序列化字段，**永不输出口令与密钥**。
//
// 与 directory 的理由相同：只靠调用方"记得清空"迟早会漏，
// 而漏一次就会进浏览器缓存、录屏、工单截图。
func (s Settings) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Mode               string     `json:"mode"`
		FromAddr           string     `json:"fromAddr"`
		FromName           string     `json:"fromName"`
		ReplyTo            string     `json:"replyTo"`
		SMTPHost           string     `json:"smtpHost"`
		SMTPPort           int        `json:"smtpPort"`
		SMTPTLS            string     `json:"smtpTls"`
		SMTPUser           string     `json:"smtpUser"`
		SMTPInsecure       bool       `json:"smtpInsecure"`
		SMTPAllowPlaintext bool       `json:"smtpAllowPlaintext"`
		GraphTenantID      string     `json:"graphTenantId"`
		GraphClientID      string     `json:"graphClientId"`
		GraphSender        string     `json:"graphSender"`
		GraphLoginBase     string     `json:"graphLoginBase"`
		GraphBase          string     `json:"graphBase"`
		Source             string     `json:"source"`
		HasSMTPPassword    bool       `json:"hasSmtpPassword"`
		HasGraphSecret     bool       `json:"hasGraphSecret"`
		UpdatedAt          *time.Time `json:"updatedAt,omitempty"`
		LastTestAt         *time.Time `json:"lastTestAt,omitempty"`
		LastTestTo         string     `json:"lastTestTo,omitempty"`
		LastTestOK         *bool      `json:"lastTestOk,omitempty"`
		LastTestError      string     `json:"lastTestError,omitempty"`
	}{
		Mode: s.Mode, FromAddr: s.FromAddr, FromName: s.FromName, ReplyTo: s.ReplyTo,
		SMTPHost: s.SMTPHost, SMTPPort: s.SMTPPort, SMTPTLS: s.SMTPTLS,
		SMTPUser: s.SMTPUser, SMTPInsecure: s.SMTPInsecure,
		SMTPAllowPlaintext: s.SMTPAllowPlaintext,
		GraphTenantID:      s.GraphTenantID, GraphClientID: s.GraphClientID,
		GraphSender: s.GraphSender, GraphLoginBase: s.GraphLoginBase, GraphBase: s.GraphBase,
		Source: s.Source, HasSMTPPassword: s.HasSMTPPassword, HasGraphSecret: s.HasGraphSecret,
		UpdatedAt: s.UpdatedAt, LastTestAt: s.LastTestAt, LastTestTo: s.LastTestTo,
		LastTestOK: s.LastTestOK, LastTestError: s.LastTestError,
	})
}

// Store 负责邮件配置的持久化与加解密。
type Store struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
}

// NewStore 构造配置仓库。box 可为 nil（此时无法保存口令，保存会被拒绝）。
func NewStore(pool *pgxpool.Pool, box *secretbox.Box) *Store {
	return &Store{pool: pool, box: box}
}

// Available 报告能否加密保存口令。
func (s *Store) Available() bool { return s != nil && s.box != nil && s.box.Available() }

func smtpAAD(tenantID string) string  { return "mail-smtp:" + tenantID }
func graphAAD(tenantID string) string { return "mail-graph:" + tenantID }

// Load 读取租户配置；无记录时返回 Source="none"（= 跟随平台默认）。
func (s *Store) Load(ctx context.Context, tenantID string) (Settings, error) {
	var (
		out     Settings
		smtpEnc []byte
		grEnc   []byte
		updated time.Time
		testAt  *time.Time
		testOK  *bool
	)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT mode, from_addr, from_name, reply_to,
			       smtp_host, smtp_port, smtp_tls, smtp_user, smtp_password_enc,
			       smtp_insecure, smtp_allow_plaintext,
			       graph_tenant_id, graph_client_id, graph_client_secret_enc,
			       graph_sender, graph_login_base, graph_base,
			       updated_at, last_test_at, COALESCE(last_test_to, ''), last_test_ok,
			       COALESCE(last_test_error, '')
			  FROM mail_config WHERE tenant_id = $1`, tenantID).
			Scan(&out.Mode, &out.FromAddr, &out.FromName, &out.ReplyTo,
				&out.SMTPHost, &out.SMTPPort, &out.SMTPTLS, &out.SMTPUser, &smtpEnc,
				&out.SMTPInsecure, &out.SMTPAllowPlaintext,
				&out.GraphTenantID, &out.GraphClientID, &grEnc,
				&out.GraphSender, &out.GraphLoginBase, &out.GraphBase,
				&updated, &testAt, &out.LastTestTo, &testOK, &out.LastTestError)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{Mode: ModeInherit, SMTPPort: 587, SMTPTLS: "starttls", Source: "none"}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	out.Source = "database"
	out.UpdatedAt = &updated
	out.LastTestAt = testAt
	out.LastTestOK = testOK

	// 解不开（换过密钥）不阻断读取：界面显示"口令不可用，请重新录入"，
	// 管理员重填即可，而不是整个配置页报错。
	if len(smtpEnc) > 0 {
		out.HasSMTPPassword = true
		if s.box != nil && s.box.Available() {
			if plain, derr := s.box.Decrypt(smtpEnc, smtpAAD(tenantID)); derr == nil {
				out.SMTPPassword = string(plain)
			}
		}
	}
	if len(grEnc) > 0 {
		out.HasGraphSecret = true
		if s.box != nil && s.box.Available() {
			if plain, derr := s.box.Decrypt(grEnc, graphAAD(tenantID)); derr == nil {
				out.GraphClientSecret = string(plain)
			}
		}
	}
	return out, nil
}

// Save 保存配置。口令/密钥留空表示沿用已保存的值。
//
// 先在事务外读一次旧值：判断"是否有已存口令"必须基于库里的真实状态，
// 不能相信前端传回的 hasSmtpPassword 之类的标志（那是可伪造的输入）。
func (s *Store) Save(ctx context.Context, tenantID, actorID string, in Settings) (Settings, error) {
	in = normalize(in)
	old, err := s.Load(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	if err := s.Validate(in, old); err != nil {
		return Settings{}, err
	}

	var smtpEnc, grEnc []byte
	if in.SMTPPassword != "" {
		if !s.Available() {
			return Settings{}, ErrNoSecretKey
		}
		sealed, e := s.box.Encrypt([]byte(in.SMTPPassword), smtpAAD(tenantID))
		if e != nil {
			return Settings{}, e
		}
		smtpEnc = sealed
	}
	if in.GraphClientSecret != "" {
		if !s.Available() {
			return Settings{}, ErrNoSecretKey
		}
		sealed, e := s.box.Encrypt([]byte(in.GraphClientSecret), graphAAD(tenantID))
		if e != nil {
			return Settings{}, e
		}
		grEnc = sealed
	}

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO mail_config (
				tenant_id, mode, from_addr, from_name, reply_to,
				smtp_host, smtp_port, smtp_tls, smtp_user, smtp_password_enc,
				smtp_insecure, smtp_allow_plaintext,
				graph_tenant_id, graph_client_id, graph_client_secret_enc,
				graph_sender, graph_login_base, graph_base, updated_at, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10::bytea, NULL),
			        $11,$12,$13,$14,COALESCE($15::bytea, NULL),$16,$17,$18,now(),nullif($19,'')::uuid)
			ON CONFLICT (tenant_id) DO UPDATE SET
				mode = EXCLUDED.mode,
				from_addr = EXCLUDED.from_addr,
				from_name = EXCLUDED.from_name,
				reply_to = EXCLUDED.reply_to,
				smtp_host = EXCLUDED.smtp_host,
				smtp_port = EXCLUDED.smtp_port,
				smtp_tls = EXCLUDED.smtp_tls,
				smtp_user = EXCLUDED.smtp_user,
				-- 留空保持原值：COALESCE 不能把已存口令覆盖成 NULL
				smtp_password_enc = COALESCE(EXCLUDED.smtp_password_enc, mail_config.smtp_password_enc),
				smtp_insecure = EXCLUDED.smtp_insecure,
				smtp_allow_plaintext = EXCLUDED.smtp_allow_plaintext,
				graph_tenant_id = EXCLUDED.graph_tenant_id,
				graph_client_id = EXCLUDED.graph_client_id,
				graph_client_secret_enc = COALESCE(EXCLUDED.graph_client_secret_enc, mail_config.graph_client_secret_enc),
				graph_sender = EXCLUDED.graph_sender,
				graph_login_base = EXCLUDED.graph_login_base,
				graph_base = EXCLUDED.graph_base,
				updated_at = now(),
				updated_by = EXCLUDED.updated_by`,
			tenantID, in.Mode, in.FromAddr, in.FromName, in.ReplyTo,
			in.SMTPHost, in.SMTPPort, in.SMTPTLS, in.SMTPUser, smtpEnc,
			in.SMTPInsecure, in.SMTPAllowPlaintext,
			in.GraphTenantID, in.GraphClientID, grEnc,
			in.GraphSender, in.GraphLoginBase, in.GraphBase, actorID)
		return e
	})
	if err != nil {
		return Settings{}, err
	}
	out, err := s.Load(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	// Load 会把口令解出来给内部使用，返回给前端前由 handler 清空（MarshalJSON 已兜底）
	return out, nil
}

// MarkTest 记录一次测试结果。失败原因截断保存，避免把整段 TLS 握手日志写进表。
func (s *Store) MarkTest(ctx context.Context, tenantID, to string, ok bool, cause error) error {
	msg := ""
	if cause != nil {
		msg = cause.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE mail_config
			   SET last_test_at = now(), last_test_to = $2, last_test_ok = $3, last_test_error = $4
			 WHERE tenant_id = $1`, tenantID, to, ok, msg)
		return err
	})
}

func normalize(in Settings) Settings {
	in.Mode = strings.TrimSpace(in.Mode)
	if in.Mode == "" {
		in.Mode = ModeInherit
	}
	in.FromAddr = strings.TrimSpace(in.FromAddr)
	in.FromName = strings.TrimSpace(in.FromName)
	in.ReplyTo = strings.TrimSpace(in.ReplyTo)
	in.SMTPHost = strings.TrimSpace(in.SMTPHost)
	in.SMTPTLS = strings.ToLower(strings.TrimSpace(in.SMTPTLS))
	in.SMTPUser = strings.TrimSpace(in.SMTPUser)
	in.GraphTenantID = strings.TrimSpace(in.GraphTenantID)
	in.GraphClientID = strings.TrimSpace(in.GraphClientID)
	in.GraphSender = strings.TrimSpace(in.GraphSender)
	in.GraphLoginBase = strings.TrimSpace(in.GraphLoginBase)
	in.GraphBase = strings.TrimSpace(in.GraphBase)
	if in.Mode == ModeSMTP {
		if in.SMTPPort == 0 {
			in.SMTPPort = 587
		}
		if in.SMTPTLS == "" {
			in.SMTPTLS = "starttls"
		}
	}
	return in
}

// Validate 校验配置。old 用于判断"库里是否已有口令"。
func (s *Store) Validate(in Settings, old Settings) error {
	switch in.Mode {
	case ModeInherit:
		return nil
	case ModeSMTP:
		if err := validEmail("发件地址", in.FromAddr); err != nil {
			return err
		}
		if in.SMTPHost == "" {
			return fmt.Errorf("%w: SMTP 服务器地址必填", ErrInvalidInput)
		}
		switch in.SMTPTLS {
		case "none", "starttls", "tls":
		default:
			return fmt.Errorf("%w: 加密方式只能是 none / starttls / tls", ErrInvalidInput)
		}
		hasPassword := in.SMTPPassword != "" || old.HasSMTPPassword
		if in.SMTPTLS == "none" && hasPassword && !in.SMTPAllowPlaintext {
			return fmt.Errorf("%w: 明文连接会以明文传输邮箱口令；请改用 starttls/tls，"+
				"确属内网中继再勾选「允许明文连接」", ErrInvalidInput)
		}
		return nil
	case ModeGraph:
		if err := validEmail("发件邮箱", in.GraphSender); err != nil {
			return err
		}
		if in.GraphTenantID == "" || in.GraphClientID == "" {
			return fmt.Errorf("%w: Exchange Online 需要目录（租户）ID 与应用（客户端）ID", ErrInvalidInput)
		}
		if in.GraphClientSecret == "" && !old.HasGraphSecret {
			return fmt.Errorf("%w: Exchange Online 需要应用客户端密钥", ErrInvalidInput)
		}
		return nil
	default:
		return fmt.Errorf("%w: 未知的邮件通道 %q", ErrInvalidInput, in.Mode)
	}
}

func validEmail(label, addr string) error {
	if addr == "" {
		return fmt.Errorf("%w: %s必填", ErrInvalidInput, label)
	}
	if _, err := mail.ParseAddress(addr); err != nil {
		return fmt.Errorf("%w: %s不是合法邮箱地址", ErrInvalidInput, label)
	}
	return nil
}

// Dispatcher 按配置构造通道。mode=inherit 返回 (nil, nil)。
//
// 返回的 Dispatcher 只有主通道、没有备用：租户显式配置了自己的邮箱，
// 失败时若静默换用平台邮箱，邮件会从"意料之外"的域名发出，
// 反而更难排查（也容易被当成钓鱼）。宁可报错，让管理员在页面上看到原因。
func (s Settings) Dispatcher() (*Dispatcher, error) {
	switch s.Mode {
	case ModeSMTP:
		sender, err := NewSMTPSender(SMTPConfig{
			Host: s.SMTPHost, Port: s.SMTPPort,
			Username: s.SMTPUser, Password: s.SMTPPassword,
			From:               formatFrom(s.FromName, s.FromAddr),
			TLSMode:            s.SMTPTLS,
			InsecureSkipVerify: s.SMTPInsecure,
		})
		if err != nil {
			return nil, err
		}
		return NewDispatcher(sender, nil), nil
	case ModeGraph:
		sender, err := NewGraphSender(GraphConfig{
			TenantID: s.GraphTenantID, ClientID: s.GraphClientID,
			ClientSecret: s.GraphClientSecret, Sender: s.GraphSender,
			// 发件人显示名：M365 里邮箱的显示名由租户管理员维护，
			// 我们只能通过 message.from.name 覆盖这一次投递的显示名
			FromName:  s.FromName,
			LoginBase: s.GraphLoginBase, GraphBase: s.GraphBase,
		})
		if err != nil {
			return nil, err
		}
		return NewDispatcher(sender, nil), nil
	case "", ModeInherit:
		return nil, nil
	default:
		return nil, fmt.Errorf("未知的邮件通道 %q", s.Mode)
	}
}

// DefaultFromName 是"没填发件人显示名"时的默认值。
//
// 为什么要这个默认值：此前 From 头只有邮箱地址，收件人在 Outlook/QQ 邮箱里
// 看到的是 "noreply@..."，既不像系统通知，也容易被判垃圾邮件；
// 租户也没法在界面上把它改成自己的品牌。
//
// brand 来自租户品牌（管理台「系统设置 · 品牌与名称」），为空时退回产品名。
func DefaultFromName(brand string) string { return BrandDisplayName(brand) }

// BrandDisplayName 把租户品牌名补成发件人显示名：**企业名 + "文档中心"**。
//
// 三条规则，避免历史上出现过的问题：
//   - 空品牌 → "NeuroDMS文档中心"（不能让显示名退化成邮箱地址）；
//   - 已经以"文档中心"/"文档管理系统"结尾 → 原样返回。曾经有租户把品牌名
//     直接填成"文档中心"，无脑拼接会变成"文档中心文档中心"；
//   - 其余情况追加"文档中心"（如"森莘科创" → "森莘科创文档中心"）。
func BrandDisplayName(brand string) string {
	b := strings.TrimSpace(brand)
	if b == "" {
		b = "NeuroDMS"
	}
	if strings.HasSuffix(b, "文档中心") || strings.HasSuffix(b, "文档管理系统") {
		return b
	}
	return b + "文档中心"
}

// formatFrom 组装 From 头。非 ASCII 显示名必须 RFC 2047 编码，
// 否则 Outlook 里会看到一串乱码或整封信被拒。
func formatFrom(name, addr string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return addr
	}
	return mime.BEncoding.Encode("UTF-8", name) + " <" + addr + ">"
}
