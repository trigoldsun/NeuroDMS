package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/secretbox"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 目录配置的读模型与写入口。
//
// 存在的理由：LDAP/AD 的配置原本只能靠 DOCVAULT_LDAP_* 环境变量，
// 改一次要动 .env 并重建容器——运维在客户现场根本没有这个条件，
// 而 PRD-IAM-11 明确要求"配置页 + 测试连接"。

// ErrInvalidInput 表示配置本身不合法（可直接展示给管理员）。
var ErrInvalidInput = errors.New("配置不合法")

// ErrNoSecretKey 表示未配置加密密钥，无法安全保存服务账号口令。
var ErrNoSecretKey = errors.New("未配置 DOCVAULT_SECRET_KEY，无法加密保存目录口令")

// Settings 是目录配置。口令字段只在内存中出现，永不返回给前端。
type Settings struct {
	Enabled            bool   `json:"enabled"`
	URL                string `json:"url"`
	StartTLS           bool   `json:"startTls"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	CAPEM              string `json:"caPem,omitempty"`
	TLSName            string `json:"tlsName"`
	BindDN             string `json:"bindDn"`
	// BindPassword 只写不读。
	//
	// 不能用 json:"-"：那样连请求体里的 bindPassword 都不会被解析，
	// 保存时永远是空 → 口令静默丢失（界面上还显示"已保存"）。
	// 读取侧由 httpapi.publicDirectoryView 统一清空。
	BindPassword        string   `json:"bindPassword,omitempty"`
	BaseDN              string   `json:"baseDn"`
	UserFilter          string   `json:"userFilter"`
	SyncFilter          string   `json:"syncFilter"`
	GroupFilter         string   `json:"groupFilter"`
	ExcludeAccounts     []string `json:"excludeAccounts"`
	ADMode              bool     `json:"adMode"`
	AllowPlaintext      bool     `json:"allowPlaintext"`
	SyncIntervalMinutes int      `json:"syncIntervalMinutes"`

	// 以下为读接口附加信息，保存时忽略
	Source      string     `json:"source"` // database | env | none
	HasPassword bool       `json:"hasPassword"`
	HasCA       bool       `json:"hasCa"`
	UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
}

// MarshalJSON 显式列出可序列化字段，**永不输出 BindPassword**。
//
// 只靠调用方"记得先清空"不够：一次疏忽（新加一个调试接口、把配置塞进审计 detail）
// 就会把域服务账号口令写进响应或日志。这里从类型层面去掉这个可能。
func (s Settings) MarshalJSON() ([]byte, error) {
	// 空数组必须序列化成 []，不能是 null：
	// 前端会对它调 .join()，null 会直接把整个页面炸成空白。
	exclude := s.ExcludeAccounts
	if exclude == nil {
		exclude = []string{}
	}
	return json.Marshal(struct {
		Enabled             bool       `json:"enabled"`
		URL                 string     `json:"url"`
		StartTLS            bool       `json:"startTls"`
		InsecureSkipVerify  bool       `json:"insecureSkipVerify"`
		CAPEM               string     `json:"caPem,omitempty"`
		TLSName             string     `json:"tlsName"`
		BindDN              string     `json:"bindDn"`
		BaseDN              string     `json:"baseDn"`
		UserFilter          string     `json:"userFilter"`
		SyncFilter          string     `json:"syncFilter"`
		GroupFilter         string     `json:"groupFilter"`
		ExcludeAccounts     []string   `json:"excludeAccounts"`
		ADMode              bool       `json:"adMode"`
		AllowPlaintext      bool       `json:"allowPlaintext"`
		SyncIntervalMinutes int        `json:"syncIntervalMinutes"`
		Source              string     `json:"source"`
		HasPassword         bool       `json:"hasPassword"`
		HasCA               bool       `json:"hasCa"`
		UpdatedAt           *time.Time `json:"updatedAt,omitempty"`
	}{
		Enabled: s.Enabled, URL: s.URL, StartTLS: s.StartTLS,
		InsecureSkipVerify: s.InsecureSkipVerify, CAPEM: s.CAPEM, TLSName: s.TLSName,
		BindDN: s.BindDN, BaseDN: s.BaseDN, UserFilter: s.UserFilter,
		SyncFilter: s.SyncFilter, GroupFilter: s.GroupFilter,
		ExcludeAccounts: exclude, ADMode: s.ADMode,
		AllowPlaintext: s.AllowPlaintext, SyncIntervalMinutes: s.SyncIntervalMinutes,
		Source: s.Source, HasPassword: s.HasPassword, HasCA: s.HasCA, UpdatedAt: s.UpdatedAt,
	})
}

// Store 负责配置的持久化与加密。
type Store struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
}

func NewStore(pool *pgxpool.Pool, box *secretbox.Box) *Store {
	return &Store{pool: pool, box: box}
}

// aad 把密文绑定到"租户 + 用途"：把 A 租户的密文复制到 B 租户的行里会解不开。
func bindAAD(tenantID string) string { return "directory-bind:" + tenantID }

// Load 读取某租户的目录配置；无记录时返回 Source="none"。
func (s *Store) Load(ctx context.Context, tenantID string) (Settings, error) {
	var (
		out     Settings
		enc     []byte
		updated time.Time
	)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT enabled, url, start_tls, insecure_skip_verify, ca_pem, tls_name,
			       bind_dn, bind_password_enc, base_dn, user_filter, sync_filter, group_filter,
			       exclude_accounts, ad_mode, allow_plaintext, sync_interval_minutes, updated_at
			  FROM directory_config WHERE tenant_id = $1`, tenantID).
			Scan(&out.Enabled, &out.URL, &out.StartTLS, &out.InsecureSkipVerify, &out.CAPEM,
				&out.TLSName, &out.BindDN, &enc, &out.BaseDN, &out.UserFilter, &out.SyncFilter,
				&out.GroupFilter, &out.ExcludeAccounts, &out.ADMode, &out.AllowPlaintext,
				&out.SyncIntervalMinutes, &updated)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{Source: "none"}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	out.Source = "database"
	out.UpdatedAt = &updated
	out.HasCA = strings.TrimSpace(out.CAPEM) != ""
	if len(enc) > 0 && s.box != nil && s.box.Available() {
		if plain, derr := s.box.Decrypt(enc, bindAAD(tenantID)); derr == nil {
			out.BindPassword = string(plain)
			out.HasPassword = true
		}
		// 解不开（换过密钥）不阻断读取：界面显示"口令不可用，请重新录入"，
		// 由管理员重填即可，而不是整个配置页报错。
	} else if len(enc) > 0 {
		out.HasPassword = true
	}
	return out, nil
}

// Save 保存配置。
//
// in.BindPassword 为空表示"沿用已保存的口令"——这是界面上的默认行为：
// 读不到口令，也就无法原样回填，留空必须被理解为"不改"。
func (s *Store) Save(ctx context.Context, tenantID, actorID string, in Settings) (Settings, error) {
	in = normalize(in)
	if err := Validate(ctx, s.pool, tenantID, in); err != nil {
		return Settings{}, err
	}

	var enc []byte
	if in.BindPassword != "" {
		if s.box == nil || !s.box.Available() {
			return Settings{}, ErrNoSecretKey
		}
		sealed, err := s.box.Encrypt([]byte(in.BindPassword), bindAAD(tenantID))
		if err != nil {
			return Settings{}, err
		}
		enc = sealed
	}

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO directory_config (
				tenant_id, enabled, url, start_tls, insecure_skip_verify, ca_pem, tls_name,
				bind_dn, bind_password_enc, base_dn, user_filter, sync_filter, group_filter,
				exclude_accounts, ad_mode, allow_plaintext, sync_interval_minutes,
				updated_at, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::bytea, NULL),$10,$11,$12,$13,$14,$15,$16,$17,now(),nullif($18,'')::uuid)
			ON CONFLICT (tenant_id) DO UPDATE SET
				enabled = EXCLUDED.enabled,
				url = EXCLUDED.url,
				start_tls = EXCLUDED.start_tls,
				insecure_skip_verify = EXCLUDED.insecure_skip_verify,
				ca_pem = EXCLUDED.ca_pem,
				tls_name = EXCLUDED.tls_name,
				bind_dn = EXCLUDED.bind_dn,
				-- 口令留空时保持原值：COALESCE 不能覆盖成 NULL
				bind_password_enc = COALESCE(EXCLUDED.bind_password_enc, directory_config.bind_password_enc),
				base_dn = EXCLUDED.base_dn,
				user_filter = EXCLUDED.user_filter,
				sync_filter = EXCLUDED.sync_filter,
				group_filter = EXCLUDED.group_filter,
				exclude_accounts = EXCLUDED.exclude_accounts,
				ad_mode = EXCLUDED.ad_mode,
				allow_plaintext = EXCLUDED.allow_plaintext,
				sync_interval_minutes = EXCLUDED.sync_interval_minutes,
				updated_at = now(),
				updated_by = EXCLUDED.updated_by`,
			tenantID, in.Enabled, in.URL, in.StartTLS, in.InsecureSkipVerify, in.CAPEM,
			in.TLSName, in.BindDN, enc, in.BaseDN, in.UserFilter, in.SyncFilter, in.GroupFilter,
			in.ExcludeAccounts, in.ADMode, in.AllowPlaintext, in.SyncIntervalMinutes, actorID)
		return e
	})
	if err != nil {
		return Settings{}, err
	}
	out, err := s.Load(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	out.BindPassword = in.BindPassword
	return out, nil
}

func normalize(in Settings) Settings {
	in.URL = strings.TrimSpace(in.URL)
	in.TLSName = strings.TrimSpace(in.TLSName)
	in.BindDN = strings.TrimSpace(in.BindDN)
	in.BaseDN = strings.TrimSpace(in.BaseDN)
	in.UserFilter = strings.TrimSpace(in.UserFilter)
	in.SyncFilter = strings.TrimSpace(in.SyncFilter)
	in.GroupFilter = strings.TrimSpace(in.GroupFilter)
	in.CAPEM = strings.TrimSpace(in.CAPEM)

	// 排除账号：去空、去重，避免界面上粘贴出 "a,,b" 这类无效项
	seen := map[string]bool{}
	var clean []string
	for _, a := range in.ExcludeAccounts {
		a = strings.TrimSpace(a)
		if a == "" || seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		clean = append(clean, a)
	}
	in.ExcludeAccounts = clean

	// 过滤器留空时按模式补默认值，避免"填了一半"导致认证永远搜不到人
	if in.UserFilter == "" {
		if in.ADMode {
			in.UserFilter = "(&(objectClass=user)(sAMAccountName=%s))"
		} else {
			in.UserFilter = "(&(objectClass=inetOrgPerson)(uid=%s))"
		}
	}
	if in.SyncFilter == "" {
		if in.ADMode {
			in.SyncFilter = "(&(objectClass=user)(objectCategory=person))"
		} else {
			in.SyncFilter = "(objectClass=inetOrgPerson)"
		}
	}
	if in.GroupFilter == "" {
		if in.ADMode {
			in.GroupFilter = "(objectClass=group)"
		} else {
			in.GroupFilter = "(objectClass=groupOfNames)"
		}
	}
	return in
}

// allowedPorts 是企业目录实际会用到的端口。
//
// 不做"任意端口"：测试连接是**服务端发起的对外连接**，
// 放开任意端口等于把一个内网探测工具交给管理员账号（账号被钓鱼即失守）。
// 3268/3269 是 AD 全局编录，很多跨域部署只用这两个。
var allowedPorts = map[int]bool{389: true, 636: true, 3268: true, 3269: true}

// Validate 校验配置。返回的错误信息面向管理员，可直接展示。
func Validate(ctx context.Context, pool *pgxpool.Pool, tenantID string, in Settings) error {
	// 先补默认值再校验：过滤器留空是"用默认"，不该被当成"没填"而拒绝。
	// 放在这里而不是只放在 Save，是为了让任何调用路径（含测试与将来的导入）行为一致。
	in = normalize(in)
	if !in.Enabled {
		return nil // 停用状态允许保存半成品配置
	}
	if err := ValidateAddress(in.URL); err != nil {
		return err
	}
	u, _ := url.Parse(in.URL)

	// 明文绑定：口令会以明文过网。要求显式勾选，否则拒绝保存。
	encrypted := u.Scheme == "ldaps" || in.StartTLS
	if !encrypted && !in.AllowPlaintext {
		return fmt.Errorf("%w: 未加密的连接会明文传输域口令；请改用 ldaps:// 或启用 StartTLS，"+
			"确属实验网再勾选「允许明文绑定」", ErrInvalidInput)
	}
	if in.BaseDN == "" {
		return fmt.Errorf("%w: 必须填写 BaseDN", ErrInvalidInput)
	}
	if !strings.Contains(in.UserFilter, "%s") {
		return fmt.Errorf("%w: 认证过滤器必须包含 %%s 占位符（认证时替换为用户名）", ErrInvalidInput)
	}
	if strings.Contains(in.SyncFilter, "%s") {
		return fmt.Errorf("%w: 同步过滤器不能包含 %%s（同步要列出所有人）", ErrInvalidInput)
	}
	if strings.TrimSpace(in.CAPEM) != "" {
		if !strings.Contains(in.CAPEM, "BEGIN CERTIFICATE") {
			return fmt.Errorf("%w: CA 内容不是 PEM 格式", ErrInvalidInput)
		}
	}
	if in.SyncIntervalMinutes < 0 || in.SyncIntervalMinutes > 1440 {
		return fmt.Errorf("%w: 自动同步间隔需在 0-1440 分钟", ErrInvalidInput)
	}

	// 应急通道：启用目录认证后，若没有任何本地可登录的 sysadmin，
	// 目录一挂就再也进不来（域账号全拒、本地号也不存在）。
	if pool != nil {
		var localAdmins int
		err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `
				SELECT count(*)
				  FROM app_user u
				  JOIN user_role ur ON ur.user_id = u.id
				  JOIN role r ON r.id = ur.role_id
				 WHERE u.tenant_id = $1 AND r.code = 'sysadmin'
				   AND u.source = 'local' AND u.status = 'active'
				   AND u.deleted_at IS NULL AND u.password_hash IS NOT NULL`, tenantID).Scan(&localAdmins)
		})
		if err != nil {
			return err
		}
		if localAdmins == 0 {
			return fmt.Errorf("%w: 租户内没有可登录的本地系统管理员；"+
				"启用目录认证前请先创建本地应急管理员（目录故障时唯一的入口）", ErrInvalidInput)
		}
	}
	return nil
}

// ValidateAddress 只校验地址本身（scheme / 主机 / 端口 / 是否链路本地）。
//
// 单独抽出是为了"测试连接"能复用：管理员往往先测连通、再补 BaseDN 与过滤器，
// 若测试也要过全量校验，"先测一下"这个动作就做不了。
// 但地址校验必须一致——它正是防 SSRF 的那一层。
func ValidateAddress(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: 必须填写目录地址", ErrInvalidInput)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: 地址无法解析", ErrInvalidInput)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("%w: 地址必须以 ldap:// 或 ldaps:// 开头", ErrInvalidInput)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: 地址缺少主机名", ErrInvalidInput)
	}
	port := defaultPort(u)
	if !allowedPorts[port] {
		return fmt.Errorf("%w: 端口 %d 不被允许（仅支持 389/636/3268/3269）", ErrInvalidInput, port)
	}
	return rejectLinkLocal(host)
}

func defaultPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
		return -1
	}
	if u.Scheme == "ldaps" {
		return 636
	}
	return 389
}

// rejectLinkLocal 挡住云元数据与链路本地地址。
//
// 这些地址在正常企业目录里绝不会出现，但正是 SSRF 最想要的目标
// （169.254.169.254 能拿到云主机临时凭证）。
// 主机名也要解析后判断：攻击者可以用一个解析到 169.254.x.x 的域名绕过字面量检查。
func rejectLinkLocal(host string) error {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if isBlocked(addr) {
			return fmt.Errorf("%w: 目标地址属于链路本地/元数据网段，已拒绝", ErrInvalidInput)
		}
		return nil
	}
	// 解析也要限时：域名解析不了时默认可能等好几秒，保存配置不该卡这么久
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// 解析不了不在这里报错：由"测试连接"给出具体的不可达原因
		return nil
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok && isBlocked(a) {
			return fmt.Errorf("%w: 目标主机解析到链路本地/元数据网段，已拒绝", ErrInvalidInput)
		}
	}
	return nil
}

func isBlocked(a netip.Addr) bool {
	if a.Is4() {
		return netip.MustParsePrefix("169.254.0.0/16").Contains(a)
	}
	// IPv6 链路本地 + 常见元数据地址
	return netip.MustParsePrefix("fe80::/10").Contains(a) || a == netip.MustParseAddr("fd00:ec2::254")
}

// ToLDAPConfig 把配置转成客户端参数。
func (s Settings) ToLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:                s.URL,
		StartTLS:           s.StartTLS,
		InsecureSkipVerify: s.InsecureSkipVerify,
		CAPEM:              []byte(s.CAPEM),
		TLSName:            s.TLSName,
		AllowPlaintextBind: s.AllowPlaintext,
		BindDN:             s.BindDN,
		BindPassword:       s.BindPassword,
		BaseDN:             s.BaseDN,
		UserFilter:         s.UserFilter,
		SyncUserFilter:     s.SyncFilter,
		GroupFilter:        s.GroupFilter,
		ADMode:             s.ADMode,
	}
}
