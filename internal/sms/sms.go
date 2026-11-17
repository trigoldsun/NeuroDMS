// Package sms 封装"发短信验证码"与"核验验证码"。
//
// 两种模式（docs/47 §4.5）：
//
//	managed —— 厂商代生成 + 代核验（阿里云短信认证服务 dypnsapi）。
//	           本地不签发、不存储、不比对明文码。
//	local   —— 我方生成 6 位码、HMAC 落库、本地比对（腾讯云/华为云/天翼云）。
//	           这三家只有"发送"接口，没有核验接口；不把核验搬回本地，
//	           登录就会永远失败（或更糟：任意码都过）。
//
// 边界约定：本包只回答"发出去了吗 / 这个码对不对"，
// 账号是否存在、能不能登录、频控与审计都在上层（auth / httpapi）。
package sms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"docvault/internal/integrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotConfigured 表示该租户没有可用通道（既无租户配置，也无平台默认）。
	// 上层必须据此 fail-closed：绝不能因为没配置就跳过验证。
	ErrNotConfigured = errors.New("短信认证服务未配置")
	// ErrUnavailable 表示调用失败（超时、签名错误、欠费、产品未开通等）。
	ErrUnavailable = errors.New("短信认证服务暂不可用")
	// ErrNotSupported 表示该模式不支持此操作（local 模式没有远端核验）。
	ErrNotSupported = errors.New("该通道不支持远端核验")
)

// Mode 是核验模式。
type Mode string

const (
	// Managed 由厂商生成并核验验证码。
	Managed Mode = "managed"
	// Local 由本服务生成并核验验证码。
	Local Mode = "local"
)

// Provider 是一条短信通道。
type Provider interface {
	// Code 返回 provider 编码（aliyun / tencent / huawei / ctyun）。
	Code() string
	// Mode 返回核验模式。
	Mode() Mode
	// Send 发送验证码。managed 模式忽略 code（由厂商生成）。
	Send(ctx context.Context, phone, code string) error
	// Verify 仅 managed 模式实现；local 返回 ErrNotSupported。
	Verify(ctx context.Context, phone, code string) (bool, error)
	// Test 自检：managed 只核验（免费），local 会真发一条。
	Test(ctx context.Context) error
}

// Service 负责按租户解析通道、生成/保存本地验证码。
//
// 解析顺序：租户配置（integration_config 中 kind=sms 的 active 行）
// → 平台默认通道（环境变量）。
//
// 为什么租户配置**坏了**不回落平台通道：那会用"别的签名/别的账号"把短信发出去，
// 客户看到的是陌生签名，还会产生费用归属争议。宁可报错让管理员看见。
type Service struct {
	pool     *pgxpool.Pool
	store    *integrations.Store
	platform Provider
	key      []byte
	now      func() time.Time
}

// NewService 构造服务。store/platform 都可为 nil（此时只有另一边可用）。
// key 用于验证码 HMAC（不得为空，否则 local 模式拒绝工作）。
func NewService(pool *pgxpool.Pool, store *integrations.Store, key []byte, platform Provider) *Service {
	return &Service{pool: pool, store: store, platform: platform, key: key, now: time.Now}
}

// SetNow 供测试注入时钟。
func (s *Service) SetNow(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// Send 发送登录验证码。
func (s *Service) Send(ctx context.Context, tenantID, phone string) error {
	p, err := s.providerFor(ctx, tenantID)
	if err != nil {
		return err
	}
	if p.Mode() == Local {
		if len(s.key) == 0 {
			// 没有 HMAC 密钥就不能安全地存码；不放行。
			return fmt.Errorf("%w: 缺少验证码密钥", ErrNotConfigured)
		}
		code, cerr := randomCode(6)
		if cerr != nil {
			return fmt.Errorf("%w: 生成验证码失败", ErrUnavailable)
		}
		// 先存后发：发失败时码会自然过期；反过来"先发后存"，
		// 用户在存之前输码必然失败。
		if ierr := s.issue(ctx, tenantID, phone, p.Code(), code); ierr != nil {
			return ierr
		}
		if serr := p.Send(ctx, phone, code); serr != nil {
			return serr
		}
		return nil
	}
	return p.Send(ctx, phone, "")
}

// Check 核验验证码。
func (s *Service) Check(ctx context.Context, tenantID, phone, code string) (bool, error) {
	p, err := s.providerFor(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if p.Mode() == Managed {
		return p.Verify(ctx, phone, code)
	}
	return s.verifyLocal(ctx, tenantID, phone, code)
}

// Configured 判断该租户此刻是否具备**可用**的短信通道。
//
// PlatformReady 报告平台默认通道是否已装配。
//
// 为什么要单独暴露：管理台的「短信通道」页只列**租户级**四家通道，
// 于是出现"四家全未配置、标签写着不可用，但短信其实能发"的情况
// （实际走平台默认通道）。界面需要一个字段说明"还有兜底"，
// 否则运维会按标签判断功能不可用，或反过来以为配置生效了。
func (s *Service) PlatformReady() bool { return s.platform != nil }

// local 模式还要求有 HMAC 密钥：没有密钥时通道"能发不能验"，
// 报"已就绪"会让设置页打开一个注定失败的开关。
func (s *Service) Configured(ctx context.Context, tenantID string) bool {
	p, err := s.providerFor(ctx, tenantID)
	if err != nil || p == nil {
		return false
	}
	if p.Mode() == Local && len(s.key) == 0 {
		return false
	}
	return true
}

func (s *Service) providerFor(ctx context.Context, tenantID string) (Provider, error) {
	if s.store != nil && tenantID != "" {
		st, ok, err := s.store.Active(ctx, tenantID, integrations.KindSMS)
		if err != nil {
			// 读不到配置一律 fail-closed：不能因为数据库抖动就偷偷换成平台通道
			return nil, fmt.Errorf("%w: %v", ErrNotConfigured, err)
		}
		if ok {
			p, berr := buildProvider(st.Provider, st.Config, st.Secrets)
			if berr != nil {
				return nil, fmt.Errorf("%w: 租户短信通道不可用（%v）", ErrNotConfigured, berr)
			}
			return p, nil
		}
	}
	if s.platform != nil {
		return s.platform, nil
	}
	return nil, ErrNotConfigured
}

// ProviderCode 返回当前生效的通道编码，用于"这条短信走了哪家"的日志。
// 解析失败返回空串：日志缺一列可以接受，为了记日志把发送流程打断不行。
func (s *Service) ProviderCode(ctx context.Context, tenantID string) string {
	p, err := s.providerFor(ctx, tenantID)
	if err != nil || p == nil {
		return ""
	}
	return p.Code()
}

// ---------------- 本地验证码 ----------------

const (
	codeTTL      = 5 * time.Minute
	codeAttempts = 5
)

func randomCode(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, v.Int64()), nil
}

// issue 写入（覆盖）当前号码的验证码。
func (s *Service) issue(ctx context.Context, tenantID, phone, provider, code string) error {
	ph := s.phoneHash(tenantID, phone)
	ch := s.codeHash(tenantID, phone, code)
	now := s.now()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sms_code (tenant_id, phone_hash, code_hash, provider, sent_at, expires_at, attempts, consumed_at)
		VALUES ($1,$2,$3,$4,$5,$6,0,NULL)
		ON CONFLICT (tenant_id, phone_hash) DO UPDATE
		   SET code_hash = EXCLUDED.code_hash,
		       provider  = EXCLUDED.provider,
		       sent_at   = EXCLUDED.sent_at,
		       expires_at= EXCLUDED.expires_at,
		       attempts  = 0,
		       consumed_at = NULL`,
		tenantID, ph, ch, provider, now, now.Add(codeTTL))
	if err != nil {
		// 表不可用等基础设施问题：不放行，也不把错误当成"码不对"
		return fmt.Errorf("%w: 验证码保存失败", ErrUnavailable)
	}
	return nil
}

// verifyLocal 校验并消费验证码。
//
// 用事务 + FOR UPDATE：并发提交同一个码时只能成功一次
// （否则一个码可以被并发请求重复使用）。
func (s *Service) verifyLocal(ctx context.Context, tenantID, phone, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	ph := s.phoneHash(tenantID, phone)
	want := s.codeHash(tenantID, phone, code)

	var (
		stored   []byte
		expires  time.Time
		attempts int
		consumed *time.Time
	)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx, `
		SELECT code_hash, expires_at, attempts, consumed_at
		  FROM sms_code
		 WHERE tenant_id = $1 AND phone_hash = $2
		   FOR UPDATE`, tenantID, ph).Scan(&stored, &expires, &attempts, &consumed)
	if err != nil {
		// 没有未消费的码：当作"码不对"，不暴露"这个号码有没有发过码"
		return false, nil
	}
	if consumed != nil || !s.now().Before(expires) || attempts >= codeAttempts {
		return false, nil
	}

	if !hmac.Equal(stored, want) {
		if _, e := tx.Exec(ctx, `
			UPDATE sms_code SET attempts = attempts + 1
			 WHERE tenant_id = $1 AND phone_hash = $2`, tenantID, ph); e != nil {
			return false, fmt.Errorf("%w: %v", ErrUnavailable, e)
		}
		if e := tx.Commit(ctx); e != nil {
			return false, fmt.Errorf("%w: %v", ErrUnavailable, e)
		}
		return false, nil
	}

	if _, e := tx.Exec(ctx, `
		UPDATE sms_code SET consumed_at = now()
		 WHERE tenant_id = $1 AND phone_hash = $2`, tenantID, ph); e != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, e)
	}
	if e := tx.Commit(ctx); e != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, e)
	}
	return true, nil
}

func (s *Service) phoneHash(tenantID, phone string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("phone:" + tenantID + "|" + phone))
	return m.Sum(nil)
}

func (s *Service) codeHash(tenantID, phone, code string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("code:" + tenantID + "|" + phone + "|" + code))
	return m.Sum(nil)
}

// ---------------- 注册 ----------------

// Register 把四个 provider 注册进凭证中心（字段描述 + 构造方式）。
//
// 由 main 调用，而不是在 init 里偷偷注册：显式装配才能测"没注册时保存会被拒"。
func Register(reg *integrations.Registry) {
	for _, d := range descriptors() {
		d := d
		reg.Register(d, func(cfg, sec map[string]string) (integrations.Runner, error) {
			p, err := buildProvider(d.Code, cfg, sec)
			if err != nil {
				return nil, err
			}
			return p, nil
		})
	}
}

func descriptors() []integrations.Descriptor {
	testPhone := integrations.Field{
		Key: "testPhone", Label: "自检号码", Placeholder: "13800138000",
		Help: "仅用于「测试连接」。阿里云只核验不发送；其余三家会真发一条，请填自己的号。",
	}
	return []integrations.Descriptor{
		{
			Kind: integrations.KindSMS, Code: "aliyun", Name: "阿里云短信认证服务",
			Mode: string(Managed), DocsURL: "https://help.aliyun.com/product/75010.html",
			Fields: []integrations.Field{
				{Key: "accessKeyId", Label: "AccessKey ID", Required: true},
				{Key: "accessKeySecret", Label: "AccessKey Secret", Required: true, Secret: true},
				{Key: "signName", Label: "签名名称", Required: true,
					Help: "必须与模板同属「短信认证服务」，赠送签名形如「速通互联验证码」。"},
				{Key: "templateCode", Label: "模板 CODE", Required: true,
					Help: "模板内容里的取码变量必须是 ##code##。"},
				{Key: "schemeName", Label: "方案名（可选）"},
				{Key: "endpoint", Label: "服务地址（可选）", Placeholder: "https://dypnsapi.aliyuncs.com"},
				testPhone,
			},
			Notes: []string{
				"验证码由阿里云生成与核验，本地不存码；核验接口免费。",
				"短信认证服务不支持自定义签名，自申请签名请改用「腾讯云/华为云/天翼云」。",
			},
		},
		{
			Kind: integrations.KindSMS, Code: "tencent", Name: "腾讯云短信",
			Mode: string(Local), DocsURL: "https://cloud.tencent.com/document/product/382/55981",
			Fields: []integrations.Field{
				{Key: "secretId", Label: "SecretId", Required: true},
				{Key: "secretKey", Label: "SecretKey", Required: true, Secret: true},
				{Key: "sdkAppId", Label: "SmsSdkAppId", Required: true, Placeholder: "1400006666"},
				{Key: "signName", Label: "签名内容", Required: true},
				{Key: "templateId", Label: "模板 ID", Required: true},
				{Key: "region", Label: "地域", Required: true, Placeholder: "ap-guangzhou"},
				{Key: "endpoint", Label: "服务地址（可选）", Placeholder: "https://sms.tencentcloudapi.com"},
				testPhone,
			},
			Notes: []string{
				"模板里第 1 个变量（{1}）必须是验证码，且变量个数必须正好 1 个。",
				"验证码由本系统生成并按 5 分钟有效核验。",
				"签名填内容（如「某某科技」），不是签名 ID；必须是已审核通过的。",
			},
		},
		{
			Kind: integrations.KindSMS, Code: "huawei", Name: "华为云消息&短信",
			Mode: string(Local), DocsURL: "https://support.huaweicloud.cn/api-msgsms/sms_05_0001.html",
			Fields: []integrations.Field{
				{Key: "appKey", Label: "APP_Key", Required: true},
				{Key: "appSecret", Label: "APP_Secret", Required: true, Secret: true},
				{Key: "sender", Label: "通道号", Required: true, Placeholder: "csms12345678",
					Help: "国内短信必填；在控制台「签名管理」里查看与签名关联的通道号。"},
				{Key: "signature", Label: "签名名称", Required: true},
				{Key: "templateId", Label: "模板 ID", Required: true},
				{Key: "endpoint", Label: "服务地址", Required: true,
					Placeholder: "https://smsapi.cn-north-4.myhuaweicloud.com:443"},
				testPhone,
			},
			Notes: []string{
				"模板变量用 ${1} 形式，且变量个数必须正好 1 个（多的会被判不匹配）。",
				"通道号必须与模板类型一致：国内签名的通道号形如 csms…，国际形如 isms…。",
				"只支持国内号码；国际短信需换通道号与模板。",
			},
		},
		{
			Kind: integrations.KindSMS, Code: "ctyun", Name: "天翼云短信",
			Mode: string(Local), DocsURL: "https://www.ctyun.cn/document/10020426/10021544",
			Fields: []integrations.Field{
				{Key: "accessKey", Label: "AccessKey", Required: true},
				{Key: "secretKey", Label: "SecretKey", Required: true, Secret: true},
				{Key: "signName", Label: "签名名称", Required: true},
				{Key: "templateCode", Label: "模板 CODE", Required: true, Placeholder: "SMS_153055065"},
				{Key: "templateParamKey", Label: "模板变量名", Required: true, Placeholder: "code",
					Help: "模板里 ${code} 的变量名，本系统只替换这一个变量。"},
				{Key: "endpoint", Label: "服务地址（可选）",
					Placeholder: "https://sms-global.ctapi.ctyun.cn/sms/api/v1"},
				testPhone,
			},
			Notes: []string{
				"使用 EOP 签名（AK/SK）；请求体为 JSON，action=SendSms。",
				"模板里验证码变量的名字（默认 code）要与「模板变量名」一致。",
				"尚未与我方生产账号实测：首次配置后务必点「测试连接」，鉴权失败会单独提示。",
			},
		},
	}
}

// buildProvider 按编码构造通道。未知编码返回错误（不静默失败）。
func buildProvider(code string, cfg, sec map[string]string) (Provider, error) {
	switch code {
	case "aliyun":
		return newAliyun(cfg, sec)
	case "tencent":
		return newTencent(cfg, sec)
	case "huawei":
		return newHuawei(cfg, sec)
	case "ctyun":
		return newCtyun(cfg, sec)
	default:
		return nil, fmt.Errorf("%w: %s", integrations.ErrUnknownProvider, code)
	}
}

// ---------------- 开发用模拟通道 ----------------

// Mock 是本地/测试用的实现：不联网，验证码固定。
//
// 只能在显式开启时使用（DOCVAULT_SMS_MOCK=1），且生产环境拒绝启动——
// 一个"永远返回通过"的短信通道，等于把所有账号变成免密登录。
type Mock struct {
	code string
	mu   sync.Mutex
	last map[string]string
}

// NewMock 构造固定验证码的模拟通道。
func NewMock(code string) *Mock {
	if code == "" {
		code = "123456"
	}
	return &Mock{code: code, last: map[string]string{}}
}

func (m *Mock) Code() string { return "mock" }
func (m *Mock) Mode() Mode   { return Managed }

func (m *Mock) Send(_ context.Context, _tenantID, phone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last[phone] = m.code
	return nil
}

func (m *Mock) Verify(_ context.Context, phone, code string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want, ok := m.last[phone]
	if !ok {
		return false, nil
	}
	return code == want, nil
}

// Check 同时满足 auth.SMSProvider 的签名（它用 Check 而不是 Verify）。
// 两个名字一个语义：Provider 层叫 Verify（与厂商"核验"对齐），
// 认证层叫 Check（历史接口），Mock 两个都实现以免测试装配时类型不匹配。
func (m *Mock) Check(ctx context.Context, _tenantID, phone, code string) (bool, error) {
	return m.Verify(ctx, phone, code)
}

func (m *Mock) Test(context.Context) error { return nil }
