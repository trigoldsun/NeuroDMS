package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig 是目录连接配置。
type LDAPConfig struct {
	// URL 形如 ldap://dc1.example.com:389 或 ldaps://dc1.example.com:636
	URL string
	// StartTLS 在明文 389 上升级加密。与 ldaps 二选一。
	StartTLS bool
	// InsecureSkipVerify 仅用于内网自签证书。默认 false。
	InsecureSkipVerify bool
	// CACertFile 是信任的 CA 证书（PEM）。配置后不再需要 InsecureSkipVerify：
	// 企业 CA 的根证书可放在这里，做真正的链校验。
	//
	// 为什么不建议"直接跳过校验"：不校验就等于任何能劫持流量的人都能冒充域控，
	// 收走明文的域口令——加密了但没有校验，安全性提升有限。
	CACertFile string
	// CAPEM 是直接给出的 CA 证书内容（PEM）。
	//
	// 为什么需要它：界面里管理员粘贴/上传的 CA 存在数据库里，
	// 不必先落成文件再读——多一处临时文件就多一处"权限没设对"的风险。
	// 与 CACertFile 同时存在时以 CAPEM 为准。
	CAPEM []byte
	// TLSName 覆盖证书校验使用的名称。
	//
	// 典型场景：域控证书只有 DNS SAN（NFSDC01.example.com），没有 IP SAN，
	// 而客户端只能按 IP 连接（跨网段、容器内无内网 DNS、hosts 不便修改）。
	// 此时按 IP 连、按 DNS 名校验，既连通又做了真实校验。
	TLSName string
	// AllowPlaintextBind 允许在未加密连接上做简单绑定（口令明文过网）。
	//
	// 默认 false：不少 AD 没装 LDAP 证书，LDAPS/StartTLS 都不可用，
	// 于是"能连上就先用着"会悄悄把域口令暴露在链路上。
	// 只有在实验网/内网镜像等确知安全边界的场景才应打开，并且必须留日志。
	AllowPlaintextBind bool

	BindDN       string
	BindPassword string
	BaseDN       string

	// UserFilter 是用户过滤条件，%s 会被替换为转义后的用户名。
	// AD 常用：(&(objectClass=user)(sAMAccountName=%s))
	// OpenLDAP 常用：(&(objectClass=inetOrgPerson)(uid=%s))
	UserFilter string
	// SyncUserFilter 是**同步**用的过滤条件（没有用户名占位符）。
	//
	// 必须与 UserFilter 分开：认证要"精确到一个人"，同步要"列出所有人"。
	// 早期版本让两者共用一个字符串，同步时把 %s 原样发出去，结果一个用户都匹配不到——
	// 这个问题在假目录测试里看不出来，接上真实域控才暴露。
	SyncUserFilter string
	// GroupFilter 是组过滤条件。
	GroupFilter string

	// AD 模式：启用后使用 sAMAccountName / objectGUID / memberOf
	ADMode bool

	PageSize int
	Timeout  time.Duration
}

// LDAPDirectory 是 Directory 的 LDAP 实现。
type LDAPDirectory struct {
	cfg LDAPConfig
	// caPool 在启动时加载一次：证书解析失败要在启动时报错，而不是等第一次登录
	caPool *x509.CertPool
}

// NewLDAP 构造 LDAP 实现并做一次连通性检查。
//
// 启动时就连接（而不是等第一次登录才发现配置错）：
// 目录配置错误的典型表现是"所有人都登录失败"，
// 这种事应该在上线前的启动自检里被发现，而不是用户来报障。
func NewLDAP(ctx context.Context, cfg LDAPConfig) (*LDAPDirectory, error) {
	if cfg.URL == "" || cfg.BaseDN == "" {
		return nil, errors.New("LDAP 需要 URL 与 BaseDN")
	}
	if cfg.UserFilter == "" {
		if cfg.ADMode {
			cfg.UserFilter = "(&(objectClass=user)(sAMAccountName=%s))"
		} else {
			cfg.UserFilter = "(&(objectClass=inetOrgPerson)(uid=%s))"
		}
	}
	// 认证过滤器必须带占位符，否则每次都会用同一个字符串去搜，等于搜不到指定用户
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, errors.New("UserFilter 必须包含 %s 占位符（用于认证时替换用户名）")
	}
	if cfg.SyncUserFilter == "" {
		if cfg.ADMode {
			// objectCategory=person 用来排除计算机账号：
			// AD 里 computer 的 objectClass 也包含 user，只用 objectClass=user
			// 会把所有机器当成"用户"同步进来（这是接入 AD 最常见的坑之一）
			cfg.SyncUserFilter = "(&(objectClass=user)(objectCategory=person))"
		} else {
			cfg.SyncUserFilter = "(objectClass=inetOrgPerson)"
		}
	}
	if cfg.GroupFilter == "" {
		if cfg.ADMode {
			cfg.GroupFilter = "(objectClass=group)"
		} else {
			cfg.GroupFilter = "(objectClass=groupOfNames)"
		}
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = 500
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	// 启动即判定：不加密又不显式允许 → 直接拒绝，而不是等到第一次登录才失败
	if !cfg.AllowPlaintextBind && !cfg.StartTLS && !strings.HasPrefix(cfg.URL, "ldaps://") {
		return nil, errors.New("LDAP 地址未加密（既非 ldaps:// 也未启用 StartTLS）：" +
			"域口令会以明文传输。生产环境应给域控安装 LDAP 证书；" +
			"仅在实验网且确认安全边界时可设 AllowPlaintextBind=true")
	}

	d := &LDAPDirectory{cfg: cfg}

	// 加载自定义 CA：企业 CA 的根证书通常不在系统信任库里，
	// 不加载就只能跳过校验，而那等于放弃了中间人防护。
	raw := cfg.CAPEM
	if len(raw) == 0 && cfg.CACertFile != "" {
		f, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
		}
		raw = f
	}
	if len(raw) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("CA 内容中没有可用的 PEM 证书")
		}
		d.caPool = pool
	}
	conn, err := d.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("连接目录失败: %w", err)
	}
	_ = conn.Close()
	return d, nil
}

func (d *LDAPDirectory) dial(ctx context.Context) (*ldap.Conn, error) {
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: d.cfg.Timeout})}
	if strings.HasPrefix(d.cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(d.tlsConfig()))
	}

	type result struct {
		conn *ldap.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ldap.DialURL(d.cfg.URL, opts...)
		if err == nil && d.cfg.StartTLS {
			// 必须复用 tlsConfig()：它带上了企业 CA（RootCAs）与 TLSName。
			// 这里曾经自己拼了一份 tls.Config，结果 StartTLS 既不信任企业 CA，
			// 也不认证书名覆盖——表现是"ldaps 能连、StartTLS 报证书错误"，
			// 而两者本是同一套证书校验逻辑。
			err = c.StartTLS(d.tlsConfig())
		}
		ch <- result{c, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if d.cfg.BindDN != "" {
			if err := r.conn.Bind(d.cfg.BindDN, d.cfg.BindPassword); err != nil {
				_ = r.conn.Close()
				return nil, fmt.Errorf("服务账号绑定失败: %w", err)
			}
		}
		return r.conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close 实现 Directory（每次操作独立连接，无需持有连接池）。
func (d *LDAPDirectory) Close() error { return nil }

// Authenticate 先按用户名搜出 DN，再用该 DN 与用户口令绑定。
//
// 为什么不做"用用户口令直接 bind"：那需要知道用户完整 DN，
// 而 DN 在不同 OU 下不同；先搜后绑是通行做法。
// 注意：搜索用服务账号，绑定用用户账号——两步必须分开，
// 否则无法区分"账号不存在"与"口令错误"（对外应统一为同一个错误）。
func (d *LDAPDirectory) Authenticate(ctx context.Context, username, password string) (User, error) {
	if username == "" || password == "" {
		// 空口令在 LDAP 里会变成"匿名绑定"，很多服务端会返回成功——
		// 这是经典的认证绕过，必须在这里挡住
		return User{}, ErrInvalidCredentials
	}

	conn, err := d.dial(ctx)
	if err != nil {
		return User{}, ErrDirectoryUnavailable
	}
	defer func() { _ = conn.Close() }()

	filter := fmt.Sprintf(d.cfg.UserFilter, ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		d.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, d.userAttrs(), nil,
	))
	if err != nil {
		return User{}, ErrDirectoryUnavailable
	}
	if len(res.Entries) == 0 {
		return User{}, ErrInvalidCredentials
	}

	dn := res.Entries[0].DN
	// 用用户凭据重新绑定，验证口令
	// 用户绑定走独立连接：这里也必须满足加密要求，
	// 否则会出现"服务账号走 TLS、用户口令走明文"的假安全
	if !d.cfg.AllowPlaintextBind && !d.cfg.StartTLS && !strings.HasPrefix(d.cfg.URL, "ldaps://") {
		return User{}, ErrDirectoryUnavailable
	}
	userOpts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: d.cfg.Timeout})}
	if tc := d.tlsConfigIfLDAPS(); tc != nil {
		userOpts = append(userOpts, ldap.DialWithTLSConfig(tc))
	}
	userConn, err := ldap.DialURL(d.cfg.URL, userOpts...)
	if err != nil {
		return User{}, ErrDirectoryUnavailable
	}
	defer func() { _ = userConn.Close() }()
	if d.cfg.StartTLS {
		if err := userConn.StartTLS(d.tlsConfig()); err != nil {
			return User{}, ErrDirectoryUnavailable
		}
	}
	if err := userConn.Bind(dn, password); err != nil {
		// 必须把 AD 的子码翻译出来。"口令错 / 已锁定 / 口令过期 / 必须改密"
		// 对用户的下一步动作完全不同，一律回"口令错误"只会让人反复重试到锁死。
		return User{}, classifyBindError(err)
	}

	return d.entryToUser(res.Entries[0]), nil
}

// Fetch 拉取目录快照。
func (d *LDAPDirectory) Fetch(ctx context.Context, since string) (Snapshot, error) {
	conn, err := d.dial(ctx)
	if err != nil {
		return Snapshot{}, ErrDirectoryUnavailable
	}
	defer func() { _ = conn.Close() }()

	attrs := d.userAttrs()
	users, watermark, err := fetchEntries(ctx, conn, d.cfg, d.cfg.SyncUserFilter, attrs, since, d.entryToUser)
	if err != nil {
		return Snapshot{}, err
	}

	groupAttrs := []string{"cn", "member", "uniqueMember", "memberOf"}
	groups, _, err := fetchEntries(ctx, conn, d.cfg, d.cfg.GroupFilter, groupAttrs, since, d.entryToGroup)
	if err != nil {
		return Snapshot{}, err
	}

	return Snapshot{Users: users, Groups: groups, Watermark: watermark}, nil
}

// fetchEntries 分页搜索并转换。Go 不允许方法带类型参数，因此写成包级函数。
func fetchEntries[T any](
	ctx context.Context, conn *ldap.Conn, cfg LDAPConfig, filter string, attrs []string, since string,
	conv func(*ldap.Entry) T,
) ([]T, string, error) {
	req := ldap.NewSearchRequest(
		cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		cfg.PageSize, int(cfg.Timeout.Seconds()), false, filter, attrs, nil,
	)

	var out []T
	var watermark string
	paging := ldap.NewControlPaging(uint32(cfg.PageSize))

	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		default:
		}

		req.Controls = []ldap.Control{paging}
		res, err := conn.Search(req)
		if err != nil {
			return nil, "", err
		}
		for _, e := range res.Entries {
			// 增量：AD 用 uSNChanged（只增），其他目录用 modifyTimestamp
			if w := e.GetAttributeValue("uSNChanged"); w != "" {
				if w2, err := strconv.ParseInt(w, 10, 64); err == nil {
					if cur, _ := strconv.ParseInt(watermark, 10, 64); w2 > cur {
						watermark = w
					}
				}
			}
			out = append(out, conv(e))
		}

		// 取下一页；没有分页 Cookie 时结束
		if len(res.Controls) == 0 {
			break
		}
		pc, ok := res.Controls[0].(*ldap.ControlPaging)
		if !ok || len(pc.Cookie) == 0 {
			break
		}
		paging.SetCookie(pc.Cookie)
	}
	return out, watermark, nil
}

func (d *LDAPDirectory) userAttrs() []string {
	if d.cfg.ADMode {
		return []string{"sAMAccountName", "mail", "displayName", "objectGUID", "uSNChanged",
			"memberOf", "distinguishedName", "userAccountControl", "department"}
	}
	return []string{"uid", "mail", "cn", "entryUUID", "modifyTimestamp",
		"memberOf", "distinguishedName", "nsAccountLock", "ou"}
}

func (d *LDAPDirectory) entryToUser(e *ldap.Entry) User {
	u := User{
		DN:          e.DN,
		Email:       e.GetAttributeValue("mail"),
		DisplayName: e.GetAttributeValue("displayName"),
		Groups:      e.GetAttributeValues("memberOf"),
		Dept:        e.GetAttributeValue("department"),
	}
	if u.DisplayName == "" {
		u.DisplayName = e.GetAttributeValue("cn")
	}
	if u.Dept == "" {
		if ous := e.GetAttributeValues("ou"); len(ous) > 0 {
			u.Dept = ous[0]
		}
	}
	// OU 链只能从 DN 解析：AD 的 ou 不是用户属性，读属性会得到空
	// （实测：账号挪进 OU 后，department 与 ou 都为空，只有 DN 变了）。
	u.DeptChain = ouChainFromDN(e.DN)
	if u.Dept == "" && len(u.DeptChain) > 0 {
		u.Dept = u.DeptChain[len(u.DeptChain)-1].Name
	}

	if d.cfg.ADMode {
		u.Username = e.GetAttributeValue("sAMAccountName")
		// objectGUID 是**二进制**属性。直接 GetAttributeValue 拿到的是含 NUL 与
		// 非法 UTF-8 的字节串，写进 Postgres 的 text 列会报编码错误——
		// 这个问题只有接上真实域控才会暴露，假目录测试永远发现不了。
		// 这里转成 Windows 风格 GUID 字符串：唯一稳定，且能与 ADUC / PowerShell 的值对照。
		u.ExternalID = guidString(e.GetRawAttributeValue("objectGUID"))
		// userAccountControl 的 0x2 位表示账号已停用（AD 的"禁用账户"）
		if v := e.GetAttributeValue("userAccountControl"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n&0x2 != 0 {
				u.Disabled = true
			}
		}
	} else {
		u.Username = e.GetAttributeValue("uid")
		u.ExternalID = e.GetAttributeValue("entryUUID")
		if v := e.GetAttributeValue("nsAccountLock"); strings.EqualFold(v, "true") {
			u.Disabled = true
		}
	}
	if u.Username == "" {
		u.Username = localPart(u.Email)
	}
	if u.ExternalID == "" {
		// 没有 GUID 的目录用 DN 兜底：DN 在同一目录内唯一且稳定
		u.ExternalID = strings.ToLower(e.DN)
	}
	return u
}

func (d *LDAPDirectory) entryToGroup(e *ldap.Entry) Group {
	members := e.GetAttributeValues("member")
	if len(members) == 0 {
		members = e.GetAttributeValues("uniqueMember")
	}
	return Group{
		DN:      e.DN,
		Name:    e.GetAttributeValue("cn"),
		Members: members,
	}
}

// tlsConfig 组装 TLS 配置。
//
// ServerName 的取值顺序：显式 TLSName → URL 里的主机名。
// 为什么要允许覆盖：域控证书通常只有 DNS SAN，客户端又常常只能按 IP 连
// （跨网段、容器内没有内网 DNS），按 IP 连就会报 "doesn't contain any IP SANs"。
// 覆盖后仍然是真实校验——只是改用证书里确实存在的那个名字。
func (d *LDAPDirectory) tlsConfig() *tls.Config {
	name := d.cfg.TLSName
	if name == "" {
		name = hostOf(d.cfg.URL)
	}
	return &tls.Config{
		ServerName:         name,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: d.cfg.InsecureSkipVerify,
		RootCAs:            d.caPool,
	}
}

func (d *LDAPDirectory) tlsConfigIfLDAPS() *tls.Config {
	if strings.HasPrefix(d.cfg.URL, "ldaps://") {
		return d.tlsConfig()
	}
	return nil
}

// hostOf 从 LDAP URL 中取出主机名（用于 TLS SNI 与证书校验）。
func hostOf(url string) string {
	s := url
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	return s
}

// guidString 把 16 字节的 objectGUID 转成 Windows 风格 GUID：
// 前三段按小端解释、后两段按大端，例如 c9baa54f-3f94-e242-ba15-7a867335f63d。
//
// 为什么不用简单 hex：运维拿这个值去 ADUC / PowerShell 里搜人时，
// 只有这个格式能直接对得上。长度不符时退化为 hex，保证脏数据不会 panic。
func guidString(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 36)
	// 段内字节序：前 3 段小端，后 2 段大端
	order := []int{3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15}
	for _, i := range order {
		if i < 0 {
			out = append(out, '-')
			continue
		}
		out = append(out, hexDigits[b[i]>>4], hexDigits[b[i]&0x0f])
	}
	return string(out)
}

// ouChainFromDN 从 DN 里解析出 OU 链，按"最外层 → 最内层"返回，并带上各自的完整 DN。
//
// 例：CN=xin sun,OU=Data&Tech,OU=Neurongene,DC=neurongene,DC=cn
// → [{Neurongene}, {Data&Tech}]，第一个的 DN 是 OU=Neurongene,DC=...，
//
//	第二个的 DN 是 OU=Data&Tech,OU=Neurongene,DC=...
//
// 带 DN 是为了幂等：OU 改名时按 DN 找不到，会新建而不是错挂到别的树节点上。
func ouChainFromDN(dn string) []DeptNode {
	if dn == "" {
		return nil
	}
	parts := strings.Split(dn, ",")
	var chain []DeptNode
	// 从右往左扫：DN 左侧是更深的层级，倒着扫正好是"外 → 内"
	acc := make([]string, 0, len(parts))
	for i := len(parts) - 1; i >= 0; i-- {
		comp := strings.TrimSpace(parts[i])
		acc = append([]string{comp}, acc...)
		if len(comp) > 3 && strings.EqualFold(comp[:3], "ou=") {
			chain = append(chain, DeptNode{
				Name: strings.TrimSpace(comp[3:]),
				DN:   strings.Join(acc, ","),
			})
		}
	}
	return chain
}

func localPart(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

// classifyBindError 把 AD 的 bind 失败翻译成可操作的错误。
//
// AD 在 LDAP Result Code 49（invalidCredentials）的 diagnosticMessage 里
// 带一个子码，形如：
//
//	80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 775, v4563
//
// 子码语义（微软文档 3.1.1.3.1.1）：
//
//	52e  用户名或口令不正确
//	525  用户不存在
//	530  当前时间不在允许登录时段
//	531  不允许从当前工作站登录
//	532  口令已过期
//	533  账号被禁用
//	701  账号已过期
//	773  必须先修改口令
//	775  账号已锁定（通常是连续输错触发的域策略）
//
// 这里只做"能给出下一步"的归类，其余仍按通用凭据错误处理——
// 不把 530/531 这类需要改网络或时区的边缘情况也暴露出来，
// 那只会让用户更困惑。
func classifyBindError(err error) error {
	var lerr *ldap.Error
	if !errors.As(err, &lerr) || lerr.ResultCode != ldap.LDAPResultInvalidCredentials {
		// 非 49 的失败是链路/服务端问题（TLS、超时、服务账号权限），
		// 不能说成是用户口令错——否则运维会去查密码，方向完全错。
		return fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "data 775"):
		return ErrAccountLocked
	case strings.Contains(msg, "data 532"):
		return ErrPasswordExpired
	case strings.Contains(msg, "data 773"):
		return ErrPasswordMustChange
	case strings.Contains(msg, "data 533"), strings.Contains(msg, "data 701"):
		return ErrAccountDisabled
	default:
		return ErrInvalidCredentials
	}
}
