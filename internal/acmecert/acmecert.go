// Package acmecert 是自动签发与续期证书的 ACME 客户端（docs/47 §4.6）。
//
// 三种模式：
//   - off    不签发，界面提示"证书由边缘/反向代理托管"
//   - http01 自动签发：在 80 端口应答 /.well-known/acme-challenge/，无需人工
//   - dns01  手动签发：把一条 TXT 记录给管理员，加完再点"完成"
//
// 为什么不直接只用 autocert.Manager：它自带 HTTP 处理器与内存缓存，
// 但我们的证书必须落到 tenant_domain 表里（多租户 SNI 要按 Host 取证书），
// 还要能在"客户手工上传"与"自动签发"之间分优先级。用 acme.Client 自己走
// 订单流程，落库这一步就变成可控的一次写，而不是"再同步一份缓存"。
package acmecert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"docvault/internal/secretbox"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/acme"
)

// Mode 是 ACME 的运行模式。
type Mode string

const (
	ModeOff    Mode = "off"
	ModeHTTP01 Mode = "http01"
	ModeDNS01  Mode = "dns01"
)

// 哨兵错误：调用方按类别映射到 HTTP 状态码与可读提示。
var (
	// ErrDisabled 表示 ACME 未启用。
	ErrDisabled = errors.New("自动签发未启用")
	// ErrNotVerified 表示域名还没通过归属验证，不能签发。
	ErrNotVerified = errors.New("域名尚未验证归属")
	// ErrDNSNotReady 表示 DNS-01 的 TXT 记录还没生效。
	ErrDNSNotReady = errors.New("DNS 记录尚未生效")
	// ErrNoAccountKey 表示缺少 DOCVAULT_SECRET_KEY，无法保存账户私钥。
	ErrNoAccountKey = secretbox.ErrNoKey
)

// ParseMode 解析配置值。空串按 off 处理（缺省不签发）。
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeOff:
		return ModeOff, nil
	case ModeHTTP01:
		return ModeHTTP01, nil
	case ModeDNS01:
		return ModeDNS01, nil
	default:
		return ModeOff, fmt.Errorf("未知的 ACME 模式 %q（可选 off / http01 / dns01）", s)
	}
}

// Config 是 ACME 的运行配置。
type Config struct {
	Mode  Mode
	Email string
	// DirectoryURL 为空时用 Let's Encrypt 生产环境。
	// 测试请显式设成 staging，否则反复失败会吃掉生产配额。
	DirectoryURL string
	// HTTP01Addr 是挑战应答监听的地址，默认 ":80"。
	HTTP01Addr string
	// RenewBefore 是提前续期的窗口，默认 30 天。
	RenewBefore time.Duration
}

// DefaultDirectory 是 Let's Encrypt 生产环境目录。
const DefaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// StagingDirectory 是测试环境目录（证书不被浏览器信任，但配额宽松）。
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Saver 把签好的证书写进租户域名（由 tenant.Service 提供）。
//
// 用回调而不是直接依赖 tenant 包：acmecert 只负责"拿到证书"，
// "证书怎么校验、私钥怎么加密"必须与手工上传那条路完全一致，
// 复制一份实现迟早会出现两套 AAD 或两套校验。
type Saver func(ctx context.Context, tenantID, host, certPEM string, keyPEM []byte) error

// Service 是 ACME 客户端。
type Service struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
	cfg  Config
	save Saver

	// key 是账户私钥，启动时从库里解密或新建。
	key crypto.Signer

	// 挑战应答表：token → keyAuth。只在 http01 模式下有所用。
	mu         sync.Mutex
	challenges map[string]string
	srv        *http.Server

	now func() time.Time
	// startErr 记录挑战端口启动失败的原因。
	// 不记下来的话，界面会显示"已启用"，而每次签发都卡在挑战那一步。
	startErr error
}

// New 构造服务。mode=off 时返回的服务所有签发方法都返回 ErrDisabled。
func New(pool *pgxpool.Pool, box *secretbox.Box, cfg Config, save Saver) *Service {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = DefaultDirectory
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 30 * 24 * time.Hour
	}
	if cfg.HTTP01Addr == "" {
		cfg.HTTP01Addr = ":80"
	}
	return &Service{
		pool: pool, box: box, cfg: cfg, save: save,
		challenges: map[string]string{},
		now:        time.Now,
	}
}

// Mode 返回当前模式。
func (s *Service) Mode() Mode { return s.cfg.Mode }

// Status 是给界面看的自检结果。
type Status struct {
	Mode         string `json:"mode"`
	Enabled      bool   `json:"enabled"`
	Available    bool   `json:"available"`
	Reason       string `json:"reason"`
	DirectoryURL string `json:"directoryUrl"`
	ChallengeAt  string `json:"challengeAt,omitempty"`
	Staging      bool   `json:"staging"`
}

// Status 返回当前可用性与原因。
//
// Available=false 时 Reason 必须是一句**能照做**的话，
// 而不是"未配置"——实施人员看到"未配置"只会来问我们。
func (s *Service) Status() Status {
	st := Status{
		Mode:         string(s.cfg.Mode),
		DirectoryURL: s.cfg.DirectoryURL,
		Staging:      s.cfg.DirectoryURL != DefaultDirectory,
	}
	switch s.cfg.Mode {
	case ModeHTTP01:
		st.Enabled, st.Available = true, true
		st.ChallengeAt = s.cfg.HTTP01Addr
		st.Reason = "已启用：在 " + s.cfg.HTTP01Addr + " 上应答 HTTP-01 挑战，签发后自动续期"
	case ModeDNS01:
		st.Enabled, st.Available = true, true
		st.Reason = "已启用：DNS-01 手动模式，每次签发需按提示添加一条 TXT 记录"
	default:
		st.Reason = "未启用（DOCVAULT_ACME_MODE=off）：证书需由反向代理或边缘（如 Cloudflare）托管"
	}
	// 未启用时不再叠加"缺密钥"的提示：此时最该说的是"证书该由谁托管"，
	// 而不是一个与当前模式无关的配置缺失。两句话叠在一起，读的人会挑错重点。
	if s.cfg.Mode == ModeOff {
		return st
	}
	if s.startErr != nil {
		st.Available = false
		st.Reason = "挑战端口启动失败：" + s.startErr.Error() +
			"（80 端口可能被占用；容器部署需映射 80/tcp）"
	}
	if s.box == nil || !s.box.Available() {
		st.Available = false
		st.Reason = "缺少 DOCVAULT_SECRET_KEY，无法加密保存证书私钥；手工上传同样不可用"
	}
	return st
}

// Start 在 mode=http01 时绑定挑战端口。
//
// 绑定失败必须是**启动错误**：80 端口被占用时如果不报错，
// 界面会显示"自动签发已启用"，而每次签发都失败在 challenge 那一步，
// 从错误信息里完全看不出是端口问题。
func (s *Service) Start(ctx context.Context) error {
	if s.cfg.Mode != ModeHTTP01 {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.HTTP01Addr)
	if err != nil {
		s.startErr = err
		return fmt.Errorf("无法监听 ACME 挑战端口 %s: %w", s.cfg.HTTP01Addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		s.mu.Lock()
		keyAuth, ok := s.challenges[token]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(keyAuth))
	})
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// 挑战端口是公开的，写超时与空闲超时要短：它只回一行文本。
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// 这里只能记日志：监听已经成功，后续失败通常是 fd 耗尽。
		}
	}()
	return nil
}

// Stop 关闭挑战端口。
func (s *Service) Stop() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	}
}

// ---------------- 账户密钥 ----------------

// ensureKey 取（或创建）ACME 账户私钥。
//
// 持久化的理由见迁移 0056：频繁重建账户会撞上 CA 的"每 IP 每 3 小时新建账户"配额。
func (s *Service) ensureKey(ctx context.Context) (crypto.Signer, error) {
	if s.key != nil {
		return s.key, nil
	}
	if s.box == nil || !s.box.Available() {
		return nil, ErrNoAccountKey
	}
	aad := accountAAD(s.cfg.DirectoryURL)

	var enc []byte
	err := s.pool.QueryRow(ctx,
		`SELECT key_enc FROM acme_account WHERE directory_url = $1`, s.cfg.DirectoryURL).Scan(&enc)
	switch {
	case err == nil:
		der, derr := s.box.Decrypt(enc, aad)
		if derr != nil {
			return nil, fmt.Errorf("ACME 账户私钥无法解密（可能更换过 DOCVAULT_SECRET_KEY）: %w", derr)
		}
		k, perr := x509.ParsePKCS8PrivateKey(der)
		if perr != nil {
			return nil, fmt.Errorf("ACME 账户私钥损坏: %w", perr)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("ACME 账户私钥类型不支持")
		}
		s.key = signer
		return signer, nil
	case errors.Is(err, pgx.ErrNoRows):
		// 首次：生成并落库
	default:
		return nil, err
	}

	priv, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if gerr != nil {
		return nil, gerr
	}
	der, merr := x509.MarshalPKCS8PrivateKey(priv)
	if merr != nil {
		return nil, merr
	}
	sealed, serr := s.box.Encrypt(der, aad)
	if serr != nil {
		return nil, serr
	}
	if _, ierr := s.pool.Exec(ctx, `
		INSERT INTO acme_account (id, email, directory_url, key_enc)
		VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE
		   SET email = EXCLUDED.email, directory_url = EXCLUDED.directory_url,
		       key_enc = EXCLUDED.key_enc, updated_at = now()`,
		s.cfg.Email, s.cfg.DirectoryURL, sealed); ierr != nil {
		return nil, ierr
	}
	s.key = priv
	return priv, nil
}

func accountAAD(directoryURL string) string { return "acme-account|" + directoryURL }

// client 构造已注册的 ACME 客户端。
func (s *Service) client(ctx context.Context) (*acme.Client, error) {
	key, err := s.ensureKey(ctx)
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: s.cfg.DirectoryURL}

	// KID 不必从库里读：x/crypto 在没有 KID 时会用私钥查一次账户（onlyReturnExisting），
	// 查到就缓存。多一次往返，换掉"库里的 KID 与私钥不一致"这一整类故障。
	acct := &acme.Account{}
	if s.cfg.Email != "" {
		acct.Contact = []string{"mailto:" + s.cfg.Email}
	}
	if _, rerr := c.Register(ctx, acct, acme.AcceptTOS); rerr != nil {
		return nil, fmt.Errorf("ACME 账户注册失败: %w", rerr)
	}
	if c.KID != "" {
		_, _ = s.pool.Exec(ctx,
			`UPDATE acme_account SET kid = $1, updated_at = now() WHERE directory_url = $2`,
			string(c.KID), s.cfg.DirectoryURL)
	}
	return c, nil
}

// ---------------- 签发 ----------------

// CertPEM 把 DER 链打包成 PEM。
func certPEM(chain [][]byte) string {
	var b strings.Builder
	for _, der := range chain {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return b.String()
}

func csrFor(host string, key crypto.Signer) ([]byte, error) {
	tpl := &x509.CertificateRequest{DNSNames: []string{host}}
	// Subject 留空：ACME 只认 SAN，填 CN 反而会在某些 CA 上触发额外校验。
	tpl.Subject = pkix.Name{}
	return x509.CreateCertificateRequest(rand.Reader, tpl, key)
}

// IssueHTTP01 走完整 HTTP-01 流程并落库。
func (s *Service) IssueHTTP01(ctx context.Context, tenantID, host string) error {
	if s.cfg.Mode != ModeHTTP01 {
		return ErrDisabled
	}
	if err := s.requireVerified(ctx, tenantID, host); err != nil {
		return err
	}
	cl, err := s.client(ctx)
	if err != nil {
		return err
	}

	order, err := cl.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: host}})
	if err != nil {
		return fmt.Errorf("创建订单失败: %w", err)
	}
	if err := s.solveHTTP01(ctx, cl, order); err != nil {
		return err
	}
	return s.finalize(ctx, cl, tenantID, host, order.URI)
}

func (s *Service) solveHTTP01(ctx context.Context, cl *acme.Client, order *acme.Order) error {
	for _, u := range order.AuthzURLs {
		authz, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("读取授权失败: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return errors.New("CA 未提供 http-01 挑战，请检查域名解析是否指向本机")
		}
		keyAuth, err := cl.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.challenges[chal.Token] = keyAuth
		s.mu.Unlock()
		defer func(tok string) {
			s.mu.Lock()
			delete(s.challenges, tok)
			s.mu.Unlock()
		}(chal.Token)

		if _, err := cl.Accept(ctx, chal); err != nil {
			return fmt.Errorf("提交挑战失败: %w", err)
		}
		// 等待校验：LE 通常几秒内完成；超时给 2 分钟，
		// 再长说明网络或 DNS 有问题，继续等只是把请求挂住。
		wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, werr := cl.WaitAuthorization(wctx, authz.URI)
		cancel()
		if werr != nil {
			// 把配额后果说清楚：否则用户会一直点"重试"，
			// 5 次之后该域名一小时内连订单都下不了。
			return fmt.Errorf("域名校验未通过（同一域名每小时失败 5 次会被 CA 临时拒绝，请先确认解析生效）: %w", werr)
		}
	}
	return nil
}

func (s *Service) finalize(ctx context.Context, cl *acme.Client, tenantID, host, orderURL string) error {
	// 订单刚创建时 FinalizeURL 已知；为了兼容"从库里恢复的订单"，
	// 统一用 GetOrder 重新取一次（多一次往返，省掉一个状态字段）。
	order, err := cl.GetOrder(ctx, orderURL)
	if err != nil {
		return fmt.Errorf("读取订单失败: %w", err)
	}
	key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if gerr != nil {
		return gerr
	}
	csr, cerr := csrFor(host, key)
	if cerr != nil {
		return cerr
	}
	der, _, ferr := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if ferr != nil {
		return fmt.Errorf("提交证书请求失败: %w", ferr)
	}
	keyDER, kerr := x509.MarshalPKCS8PrivateKey(key)
	if kerr != nil {
		return kerr
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if s.save == nil {
		return errors.New("未装配证书保存回调")
	}
	return s.save(ctx, tenantID, host, certPEM(der), keyPEM)
}

// ---------------- DNS-01（两阶段） ----------------

// DNSChallenge 是给管理员看的 DNS 记录。
type DNSChallenge struct {
	Host  string `json:"host"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	// Note 是一句操作提示（TTL、生效时间、多个域名不要混淆）。
	Note string `json:"note"`
}

// PendingState 是库里的两阶段状态。
type PendingState struct {
	OrderURL string
	AuthURL  string
	DNSName  string
	DNSValue string
}

// BeginDNS01 创建订单并返回要添加的 TXT 记录。
//
// **不在这里 Accept 挑战**：Accept 之后 CA 会立刻查询 DNS，
// 而管理员还没来得及加记录 —— 必然失败，且授权会变成 invalid，只能重来。
// 所以把"下单/取记录"与"校验/完成"拆成两次请求。
func (s *Service) BeginDNS01(ctx context.Context, tenantID, host string) (DNSChallenge, error) {
	if s.cfg.Mode != ModeDNS01 {
		return DNSChallenge{}, ErrDisabled
	}
	if err := s.requireVerified(ctx, tenantID, host); err != nil {
		return DNSChallenge{}, err
	}

	// 已有进行中的订单就复用它：重复点"开始"不应该吃一堆 pending 配额。
	if st, ok, err := s.LoadState(ctx, tenantID, host); err != nil {
		return DNSChallenge{}, err
	} else if ok {
		return DNSChallenge{
			Host: host, Type: "TXT", Name: st.DNSName, Value: st.DNSValue,
			Note: "该域名已有一条待完成的签发，先添加这条 TXT 再点「完成」。",
		}, nil
	}

	cl, err := s.client(ctx)
	if err != nil {
		return DNSChallenge{}, err
	}
	order, err := cl.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: host}})
	if err != nil {
		return DNSChallenge{}, fmt.Errorf("创建订单失败: %w", err)
	}
	if len(order.AuthzURLs) == 0 {
		return DNSChallenge{}, errors.New("订单没有返回授权地址")
	}
	authz, err := cl.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		return DNSChallenge{}, fmt.Errorf("读取授权失败: %w", err)
	}
	var token string
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			token = c.Token
			break
		}
	}
	if token == "" {
		return DNSChallenge{}, errors.New("CA 未提供 dns-01 挑战")
	}
	value, err := cl.DNS01ChallengeRecord(token)
	if err != nil {
		return DNSChallenge{}, err
	}
	name := "_acme-challenge." + host

	st := PendingState{
		OrderURL: order.URI,
		AuthURL:  order.AuthzURLs[0],
		DNSName:  name,
		DNSValue: value,
	}
	if err := s.SaveState(ctx, tenantID, host, st); err != nil {
		return DNSChallenge{}, err
	}
	return DNSChallenge{
		Host: host, Type: "TXT", Name: name, Value: value,
		Note: "添加后等待 1–10 分钟（取决于 DNS 服务商的 TTL），再回到本页点「完成签发」。",
	}, nil
}

// FinishDNS01 在 TXT 记录生效后完成签发。
func (s *Service) FinishDNS01(ctx context.Context, tenantID, host string) error {
	if s.cfg.Mode != ModeDNS01 {
		return ErrDisabled
	}
	st, ok, err := s.LoadState(ctx, tenantID, host)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("没有进行中的签发，请先点「开始签发」获取 TXT 记录")
	}

	// 先用本机解析器确认记录生效。这一步不是多余的：CA 查询失败只会告诉你
	// "validation failed"，而本机能直接说出"还没查到这条 TXT"。
	if !s.txtPresent(ctx, st.DNSName, st.DNSValue) {
		return fmt.Errorf("%w：请确认 %s 的 TXT 值已生效（DNS 生效通常需要几分钟）",
			ErrDNSNotReady, st.DNSName)
	}

	cl, err := s.client(ctx)
	if err != nil {
		return err
	}
	authz, err := cl.GetAuthorization(ctx, st.AuthURL)
	if err != nil {
		return fmt.Errorf("读取授权失败: %w", err)
	}
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("授权里找不到 dns-01 挑战（可能已过期），请重新开始签发")
	}
	if authz.Status != acme.StatusValid {
		if _, err := cl.Accept(ctx, chal); err != nil {
			return fmt.Errorf("提交挑战失败: %w", err)
		}
		wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, werr := cl.WaitAuthorization(wctx, authz.URI)
		cancel()
		if werr != nil {
			return fmt.Errorf("域名校验未通过: %w", werr)
		}
	}

	if err := s.finalize(ctx, cl, tenantID, host, st.OrderURL); err != nil {
		return err
	}
	return s.ClearState(ctx, tenantID, host)
}

func (s *Service) txtPresent(ctx context.Context, name, want string) bool {
	res := &net.Resolver{}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, err := res.LookupTXT(lctx, name)
	if err != nil {
		return false
	}
	for _, r := range records {
		if strings.TrimSpace(r) == want {
			return true
		}
	}
	return false
}

// ---------------- 两阶段状态的持久化 ----------------

// LoadState 读取待完成的签发状态。
func (s *Service) LoadState(ctx context.Context, tenantID, host string) (PendingState, bool, error) {
	var st PendingState
	var state string
	err := s.pool.QueryRow(ctx, `
		SELECT acme_state, acme_order_url, acme_auth_url, acme_dns_name, acme_dns_value
		  FROM tenant_domain
		 WHERE tenant_id = $1 AND host = $2`, tenantID, strings.ToLower(host)).
		Scan(&state, &st.OrderURL, &st.AuthURL, &st.DNSName, &st.DNSValue)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingState{}, false, nil
	}
	if err != nil {
		return PendingState{}, false, err
	}
	if state != "pending" || st.OrderURL == "" {
		return PendingState{}, false, nil
	}
	return st, true, nil
}

// SaveState 写入待完成的签发状态。
func (s *Service) SaveState(ctx context.Context, tenantID, host string, st PendingState) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenant_domain
		   SET acme_state = 'pending', acme_order_url = $3, acme_auth_url = $4,
		       acme_dns_name = $5, acme_dns_value = $6,
		       acme_started_at = now(), acme_last_error = '', updated_at = now()
		 WHERE tenant_id = $1 AND host = $2`,
		tenantID, strings.ToLower(host), st.OrderURL, st.AuthURL, st.DNSName, st.DNSValue)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ClearState 清掉待完成状态（成功或放弃）。
func (s *Service) ClearState(ctx context.Context, tenantID, host string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE tenant_domain
		   SET acme_state = '', acme_order_url = '', acme_auth_url = '',
		       acme_dns_name = '', acme_dns_value = '', updated_at = now()
		 WHERE tenant_id = $1 AND host = $2`, tenantID, strings.ToLower(host))
	return err
}

// RecordError 记录一次失败（页面据此显示"上次为什么没成"）。
func (s *Service) RecordError(ctx context.Context, tenantID, host string, cause error) {
	msg := ""
	if cause != nil {
		msg = truncate(cause.Error(), 300)
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE tenant_domain
		   SET acme_last_error = $3, acme_last_attempt_at = now(), updated_at = now()
		 WHERE tenant_id = $1 AND host = $2`, tenantID, strings.ToLower(host), msg)
}

// Cooldown 返回"距离下次可以再试"的剩余时间与上次失败原因。
//
// 为什么要冷却：Let's Encrypt 对**每个 identifier 每个账号每小时 5 次**
// 授权失败有硬限制，超了之后该域名在一小时内连新订单都下不了。
// 界面上连续点"签发"是最容易把额度烧光的方式，而用户完全不知道有这条限制。
//
// 60 秒足够挡住连点，又不影响"改完 DNS 再试一次"的正常节奏。
func (s *Service) Cooldown(ctx context.Context, tenantID, host string, window time.Duration) (time.Duration, string) {
	var last *time.Time
	var msg string
	err := s.pool.QueryRow(ctx, `
		SELECT acme_last_attempt_at, COALESCE(acme_last_error, '')
		  FROM tenant_domain WHERE tenant_id = $1 AND host = $2`,
		tenantID, strings.ToLower(host)).Scan(&last, &msg)
	if err != nil || last == nil || msg == "" {
		return 0, ""
	}
	left := window - s.now().Sub(*last)
	if left <= 0 {
		return 0, ""
	}
	return left, msg
}

// requireVerified 确认域名已通过归属验证。
//
// 未验证就签发是没有意义的：DNS-01 的 TXT 要加在**你自己的**域名下，
// 未验证意味着这域名可能不属于你，签出来也用不上。
func (s *Service) requireVerified(ctx context.Context, tenantID, host string) error {
	var verified bool
	err := s.pool.QueryRow(ctx,
		`SELECT verified_at IS NOT NULL FROM tenant_domain WHERE tenant_id = $1 AND host = $2`,
		tenantID, strings.ToLower(host)).Scan(&verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("域名不存在")
	}
	if err != nil {
		return err
	}
	if !verified {
		return ErrNotVerified
	}
	return nil
}

// ---------------- 续期 ----------------

// RenewTarget 是续期任务的候选。
type RenewTarget struct {
	TenantID string
	Host     string
	NotAfter time.Time
}

// Due 返回需要续期的域名（仅 source=acme，且快到期或没有证书）。
func (s *Service) Due(ctx context.Context, within time.Duration) ([]RenewTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id::text, host, COALESCE(cert_not_after, to_timestamp(0))
		  FROM tenant_domain
		 WHERE verified_at IS NOT NULL
		   AND cert_source = 'acme'
		   AND (cert_not_after IS NULL OR cert_not_after < now() + $1::interval)
		 ORDER BY cert_not_after NULLS FIRST`, fmt.Sprintf("%d hours", int(within.Hours())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RenewTarget
	for rows.Next() {
		var t RenewTarget
		if err := rows.Scan(&t.TenantID, &t.Host, &t.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RenewDue 处理一批续期。返回成功数与失败数。
//
// 失败不中断整批：一条域名解析挂了不该让其它租户的证书一起过期。
func (s *Service) RenewDue(ctx context.Context) (ok, failed int) {
	// 手动模式不自动续期，也不写"失败"：TXT 要人去加，
	// 把"需要人工"记成错误会让页面上一直挂着一条假的失败记录。
	if s.cfg.Mode == ModeOff || s.cfg.Mode == ModeDNS01 {
		return 0, 0
	}
	targets, err := s.Due(ctx, s.cfg.RenewBefore)
	if err != nil {
		return 0, 0
	}
	for _, t := range targets {
		var ierr error
		switch s.cfg.Mode {
		case ModeHTTP01:
			ierr = s.IssueHTTP01(ctx, t.TenantID, t.Host)
		}
		if ierr != nil {
			failed++
			// 记错但不覆盖 pending 状态：手动模式下用户可能正在加 TXT。
			_, _ = s.pool.Exec(ctx, `
				UPDATE tenant_domain SET acme_last_error = $3, acme_last_attempt_at = now()
				 WHERE tenant_id = $1 AND host = $2`,
				t.TenantID, t.Host, truncate(ierr.Error(), 300))
		} else {
			ok++
		}
	}
	return ok, failed
}

// RenewLoop 周期性续期，直到 ctx 结束。
//
// 首个 tick 不立刻执行：启动瞬间数据库与网络都在忙，续期不是紧急路径。
func (s *Service) RenewLoop(ctx context.Context, every time.Duration, log *slog.Logger) {
	if s.cfg.Mode == ModeOff || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ok, failed := s.RenewDue(ctx)
			if log != nil && ok+failed > 0 {
				log.Info("证书续期完成", "renewed", ok, "failed", failed)
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
