// Package integrations 负责"第三方服务凭证"的租户级存储与自检。
//
// 存在的理由（docs/47 §4.4）：短信、SSO、OnlyOffice 这些能力的凭证
// 此前只能写在环境变量里——本地部署客户改一次要重启容器、要运维登录服务器；
// 多租户 SaaS 更不可能给每个租户一套环境变量。
//
// 三条纪律，与 mail_config / directory_config 保持一致：
//  1. **只写不读**：GET 只回 hasSecret 布尔，永不回显密钥；落库走 secretbox。
//  2. **没密钥就拒绝保存**：不允许"先存明文、以后再加密"。
//  3. **换通道不覆盖**：同类可存多个 provider，但只有一个 is_active，
//     出问题时能一键切回旧的。
//
// 本包不认识任何具体厂商：字段描述与构造方式由各 provider 包注册（见 Registry）。
package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"docvault/internal/db"
	"docvault/internal/secretbox"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 能力域。
const (
	KindSMS        = "sms"
	KindMail       = "mail"
	KindDirectory  = "directory"
	KindSSO        = "sso"
	KindOnlyOffice = "onlyoffice"
	KindStorage    = "storage"
	KindGeoIP      = "geoip"
	KindAntivirus  = "antivirus"
)

// 状态。
const (
	StatusUnconfigured = "unconfigured"
	StatusConfigured   = "configured"
	StatusOK           = "ok"
	StatusFailed       = "failed"
)

var (
	// ErrInvalidInput 配置不合法（可直接展示给管理员）。
	ErrInvalidInput = errors.New("配置不合法")
	// ErrNoSecretKey 未配置加密密钥，无法保存密钥类字段。
	ErrNoSecretKey = secretbox.ErrNoKey
	// ErrUnknownProvider 未注册的 provider（防拼写错误被当成"没有"）。
	ErrUnknownProvider = errors.New("未知的通道")
	// ErrNotFound 配置不存在。
	ErrNotFound = errors.New("配置不存在")
	// ErrNotConfigured 必填项缺失或密钥不可用。
	ErrNotConfigured = errors.New("配置不完整")
)

// Field 是一个配置字段的描述。前端按它渲染表单，后端按它做校验与读写分流。
type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
}

// Descriptor 描述一个 provider。
type Descriptor struct {
	Kind    string `json:"kind"`
	Code    string `json:"code"`
	Name    string `json:"name"`
	DocsURL string `json:"docsUrl,omitempty"`
	// Mode 只对短信有意义：managed（厂商生成+核验）/ local（我方生成+核验）。
	Mode   string   `json:"mode,omitempty"`
	Fields []Field  `json:"fields"`
	Notes  []string `json:"notes,omitempty"`
}

// Runner 是可自检的对象。
type Runner interface {
	// Test 真连一次（短信会真发一条，文案里注明"配置自检"）。
	Test(ctx context.Context) error
}

// Build 由 provider 包注册：用保存好的配置构造可自检对象。
// cfg 是非密字段，secrets 是解密后的密钥字段。
type Build func(cfg, secrets map[string]string) (Runner, error)

// Registry 是 provider 注册表。
type Registry struct {
	mu    sync.RWMutex
	desc  map[string]Descriptor
	build map[string]Build
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry {
	return &Registry{desc: map[string]Descriptor{}, build: map[string]Build{}}
}

// Register 注册一个 provider。
func (r *Registry) Register(d Descriptor, b Build) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.desc[d.Kind+"|"+d.Code] = d
	if b != nil {
		r.build[d.Kind+"|"+d.Code] = b
	}
}

// Descriptor 取单个描述。
func (r *Registry) Descriptor(kind, code string) (Descriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.desc[kind+"|"+code]
	return d, ok
}

// ByKind 列出某能力域的全部 provider（顺序稳定，前端按此渲染选项卡）。
func (r *Registry) ByKind(kind string) []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, 4)
	for _, d := range r.desc {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Code < out[i].Code {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (r *Registry) buildFor(kind, code string) (Build, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.build[kind+"|"+code]
	return b, ok
}

// Settings 是一条凭证配置。密钥字段永不进 JSON。
type Settings struct {
	Kind     string            `json:"kind"`
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
	Active   bool              `json:"active"`
	Status   string            `json:"status"`
	// HasSecret 告诉前端"库里已有这个密钥"，用于显示"留空＝沿用"。
	HasSecret map[string]bool `json:"hasSecret"`
	// Secrets 只在进程内使用：负载解密结果、保存请求的输入。
	Secrets map[string]string `json:"-"`

	LastTestAt    *time.Time `json:"lastTestAt,omitempty"`
	LastTestOK    *bool      `json:"lastTestOk,omitempty"`
	LastTestError string     `json:"lastTestError,omitempty"`
	LastTestCode  string     `json:"lastTestCode,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy     string     `json:"updatedBy,omitempty"`
}

// Store 是凭证仓库。
type Store struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
	reg  *Registry
}

// NewStore 构造仓库。box 可为 nil：此时任何带密钥字段的保存都会被拒绝。
func NewStore(pool *pgxpool.Pool, box *secretbox.Box, reg *Registry) *Store {
	return &Store{pool: pool, box: box, reg: reg}
}

// Available 报告能否加密保存密钥。
func (s *Store) Available() bool { return s != nil && s.box != nil && s.box.Available() }

// Registry 暴露注册表（handler 渲染表单用）。
func (s *Store) Registry() *Registry { return s.reg }

func aad(tenantID, kind, provider string) string {
	return "integration:" + tenantID + "|" + kind + "|" + provider
}

// Get 读单条。不存在返回 ErrNotFound。
func (s *Store) Get(ctx context.Context, tenantID, kind, provider string) (Settings, error) {
	var out Settings
	var raw, enc []byte
	var updated time.Time
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT kind, provider, config, secret_enc, is_active, status,
			       last_test_at, last_test_ok, last_test_error, last_test_code,
			       updated_at, updated_by
			  FROM integration_config
			 WHERE tenant_id = $1 AND kind = $2 AND provider = $3`,
			tenantID, kind, provider).
			Scan(&out.Kind, &out.Provider, &raw, &enc, &out.Active, &out.Status,
				&out.LastTestAt, &out.LastTestOK, &out.LastTestError, &out.LastTestCode,
				&updated, &out.UpdatedBy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrNotFound
	}
	if err != nil {
		return Settings{}, err
	}
	out.UpdatedAt = &updated
	out.Config = map[string]string{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.Config); err != nil {
			return Settings{}, fmt.Errorf("配置无法解析: %w", err)
		}
	}
	out.HasSecret = map[string]bool{}
	out.Secrets = map[string]string{}
	if len(enc) > 0 {
		// 解不开（换过密钥）不阻断读取：界面显示"密钥不可用，请重新录入"，
		// 管理员重填即可，而不是整个配置页报错。
		if s.Available() {
			if plain, derr := s.box.Decrypt(enc, aad(tenantID, kind, provider)); derr == nil {
				var m map[string]string
				if json.Unmarshal(plain, &m) == nil {
					out.Secrets = m
				}
			}
		}
		for _, f := range s.fieldsOf(kind, provider) {
			if f.Secret {
				out.HasSecret[f.Key] = true
			}
		}
	}
	return out, nil
}

// List 列出某能力域下全部已保存的 provider。
func (s *Store) List(ctx context.Context, tenantID, kind string) ([]Settings, error) {
	var out []Settings
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT provider, config, is_active, status, last_test_at, last_test_ok,
			       last_test_error, last_test_code, updated_at, updated_by,
			       (secret_enc IS NOT NULL)
			  FROM integration_config
			 WHERE tenant_id = $1 AND kind = $2
			 ORDER BY provider`, tenantID, kind)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var st Settings
			var hasEnc bool
			var rawCfg []byte
			st.Kind = kind
			if e := rows.Scan(&st.Provider, &rawCfg, &st.Active, &st.Status, &st.LastTestAt,
				&st.LastTestOK, &st.LastTestError, &st.LastTestCode,
				&st.UpdatedAt, &st.UpdatedBy, &hasEnc); e != nil {
				return e
			}
			// 非密字段必须回给前端：否则打开页面看到的是空白，
			// 管理员会以为配置没保存，重填一遍反而覆盖掉正确配置。
			st.Config = map[string]string{}
			if len(rawCfg) > 0 {
				if e := json.Unmarshal(rawCfg, &st.Config); e != nil {
					return fmt.Errorf("配置无法解析: %w", e)
				}
			}
			st.HasSecret = map[string]bool{}
			if hasEnc {
				for _, f := range s.fieldsOf(kind, st.Provider) {
					if f.Secret {
						st.HasSecret[f.Key] = true
					}
				}
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	return out, err
}

// Active 返回某能力域当前生效的配置。没有 active 行时 ok=false（不报错）。
func (s *Store) Active(ctx context.Context, tenantID, kind string) (Settings, bool, error) {
	var provider string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT provider FROM integration_config
			  WHERE tenant_id = $1 AND kind = $2 AND is_active`, tenantID, kind).Scan(&provider)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, err
	}
	st, err := s.Get(ctx, tenantID, kind, provider)
	if err != nil {
		return Settings{}, false, err
	}
	return st, true, nil
}

// Save 保存配置。密钥字段留空表示"沿用已保存的值"。
func (s *Store) Save(ctx context.Context, tenantID, actor string, in Settings) (Settings, error) {
	in.Kind = strings.TrimSpace(in.Kind)
	in.Provider = strings.TrimSpace(in.Provider)
	desc, ok := s.reg.Descriptor(in.Kind, in.Provider)
	if !ok {
		return Settings{}, fmt.Errorf("%w: %s/%s", ErrUnknownProvider, in.Kind, in.Provider)
	}
	cfg, sec, err := s.normalize(desc, in)
	if err != nil {
		return Settings{}, err
	}

	old, gerr := s.Get(ctx, tenantID, in.Kind, in.Provider)
	hadOld := gerr == nil
	if gerr != nil && !errors.Is(gerr, ErrNotFound) {
		return Settings{}, gerr
	}
	// 留空的密钥沿用旧值；旧值也解不开时，这里会保持为空，由 Test 报"需重新录入"。
	for k, v := range old.Secrets {
		if _, ok := sec[k]; !ok && v != "" {
			sec[k] = v
		}
	}
	// 校验必填：非密 + 密钥（含沿用的）
	for _, f := range desc.Fields {
		if !f.Required {
			continue
		}
		if f.Secret {
			if sec[f.Key] == "" {
				// 库里明明有密文却解不开：多半是换过 DOCVAULT_SECRET_KEY。
				// 直接说"必填"会让管理员以为没填过，反复保存也过不去。
				if old.HasSecret[f.Key] {
					return Settings{}, fmt.Errorf("%w: %s 无法解密（可能更换过加密密钥），请重新录入",
						ErrInvalidInput, f.Label)
				}
				return Settings{}, fmt.Errorf("%w: %s 必填", ErrInvalidInput, f.Label)
			}
		} else if cfg[f.Key] == "" {
			return Settings{}, fmt.Errorf("%w: %s 必填", ErrInvalidInput, f.Label)
		}
	}

	var enc []byte
	if len(sec) > 0 {
		if !s.Available() {
			return Settings{}, ErrNoSecretKey
		}
		plain, _ := json.Marshal(sec)
		sealed, e := s.box.Encrypt(plain, aad(tenantID, in.Kind, in.Provider))
		if e != nil {
			return Settings{}, e
		}
		enc = sealed
	}
	raw, _ := json.Marshal(cfg)

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 是否生效，三条规则（顺序不能反）：
		//  1. 显式 active=true → 生效；
		//  2. 编辑**已生效**的配置 → 保持生效。否则改一个模板 ID 就把通道关掉，
		//     系统会静默退回平台通道，用我方签名发客户短信；
		//  3. 新增配置 → 只有同类还没有生效项时才自动生效。
		//     早期写成"新增即生效"，加一条备用配置就把线上切走了。
		active := in.Active
		if !active {
			if hadOld {
				active = old.Active
			} else {
				var exists bool
				if e := tx.QueryRow(ctx,
					`SELECT EXISTS(SELECT 1 FROM integration_config
					   WHERE tenant_id = $1 AND kind = $2 AND is_active)`,
					tenantID, in.Kind).Scan(&exists); e != nil {
					return e
				}
				active = !exists
			}
		}
		if active {
			if _, e := tx.Exec(ctx,
				`UPDATE integration_config SET is_active = false
				  WHERE tenant_id = $1 AND kind = $2 AND is_active`,
				tenantID, in.Kind); e != nil {
				return e
			}
		}
		_, e := tx.Exec(ctx, `
			INSERT INTO integration_config
				(tenant_id, kind, provider, config, secret_enc, is_active, status,
				 last_test_at, last_test_ok, last_test_error, last_test_code,
				 updated_by, updated_at)
			VALUES ($1,$2,$3,$4::jsonb,COALESCE($5::bytea, NULL),$6,'configured',
			        NULL,NULL,'','',nullif($7,''),now())
			ON CONFLICT (tenant_id, kind, provider) DO UPDATE SET
				config = EXCLUDED.config,
				-- 留空保持原值：COALESCE 不能把已存密钥覆盖成 NULL
				secret_enc = COALESCE(EXCLUDED.secret_enc, integration_config.secret_enc),
				is_active = EXCLUDED.is_active,
				-- 配置变了，上一次自检结论不再可信
				status = 'configured',
				last_test_at = NULL, last_test_ok = NULL,
				last_test_error = '', last_test_code = '',
				updated_by = EXCLUDED.updated_by,
				updated_at = now()`,
			tenantID, in.Kind, in.Provider, raw, enc, active, actor)
		return e
	})
	if err != nil {
		return Settings{}, err
	}
	return s.Get(ctx, tenantID, in.Kind, in.Provider)
}

// normalize 把请求拆成"非密/密钥"两半，并挡住把密钥塞进 config 的写法。
func (s *Store) normalize(d Descriptor, in Settings) (cfg, sec map[string]string, err error) {
	cfg, sec = map[string]string{}, map[string]string{}
	known := map[string]Field{}
	for _, f := range d.Fields {
		known[f.Key] = f
	}
	for k, v := range in.Config {
		f, ok := known[strings.TrimSpace(k)]
		if !ok {
			return nil, nil, fmt.Errorf("%w: 未知字段 %q", ErrInvalidInput, k)
		}
		if f.Secret {
			// 密钥只认 Secrets 通道：否则会被明文写进 config 并在 GET 里回显
			return nil, nil, fmt.Errorf("%w: %s 是密钥字段，请通过密钥通道提交", ErrInvalidInput, f.Label)
		}
		cfg[k] = strings.TrimSpace(v)
	}
	for k, v := range in.Secrets {
		f, ok := known[k]
		if !ok || !f.Secret {
			return nil, nil, fmt.Errorf("%w: 未知密钥字段 %q", ErrInvalidInput, k)
		}
		if v != "" {
			sec[k] = v // 不 trim：密钥里的空格可能是有效字符
		}
	}
	return cfg, sec, nil
}

// Activate 切换同类中的生效 provider。
func (s *Store) Activate(ctx context.Context, tenantID, kind, provider string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE integration_config SET is_active = false
			  WHERE tenant_id = $1 AND kind = $2 AND is_active`, tenantID, kind); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx,
			`UPDATE integration_config SET is_active = true, updated_at = now()
			  WHERE tenant_id = $1 AND kind = $2 AND provider = $3`,
			tenantID, kind, provider)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Delete 删除一条配置。若删的是生效项，不自动启用别的——
// 让管理员显式选择，避免"删了 A 却意外启用了 B"。
func (s *Store) Delete(ctx context.Context, tenantID, kind, provider string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`DELETE FROM integration_config WHERE tenant_id = $1 AND kind = $2 AND provider = $3`,
			tenantID, kind, provider)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// TestResult 是一次自检的结论。
type TestResult struct {
	OK      bool      `json:"ok"`
	Code    string    `json:"code"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// Test 真连一次并记录结论。
func (s *Store) Test(ctx context.Context, tenantID, kind, provider string) (TestResult, error) {
	st, err := s.Get(ctx, tenantID, kind, provider)
	if err != nil {
		return TestResult{}, err
	}
	now := time.Now()

	res := TestResult{At: now}
	// rawErr 只写 last_test_error（支持人员可见），不进 API 响应：
	// 上游原文里可能带号码、密钥前缀或内部端点。
	rawErr := ""
	if build, ok := s.reg.buildFor(kind, provider); ok {
		runner, berr := build(st.Config, st.Secrets)
		if berr != nil {
			res.Code, res.Message = CodeFromError(berr)
			rawErr = berr.Error()
			if res.Message == "" || res.Code == CodeUnknown {
				res.Message = "配置不完整，请补齐必填项后重试"
			}
		} else if terr := runner.Test(ctx); terr != nil {
			res.Code, res.Message = CodeFromError(terr)
			rawErr = terr.Error()
			if res.Code == CodeUnknown || res.Message == "" {
				res.Message = "自检未通过，详细原因已记录在服务端"
			}
		} else {
			res.OK, res.Code, res.Message = true, "ok", "连接成功"
		}
	} else {
		// 没有自检实现的 provider（例如只有字段声明的占位）：
		// 报告"已保存但未验证"，而不是假装成功。
		res.Code, res.Message = "not_testable", "该通道暂不支持自检"
	}

	status := StatusFailed
	if res.OK {
		status = StatusOK
	}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			UPDATE integration_config
			   SET status = $4, last_test_at = $5, last_test_ok = $6,
			       last_test_error = $7, last_test_code = $8
			 WHERE tenant_id = $1 AND kind = $2 AND provider = $3`,
			tenantID, kind, provider, status, now, res.OK,
			truncate(firstNonEmpty(rawErr, res.Message), 500), res.Code)
		return e
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// fieldsOf 取某 provider 的密钥字段列表（用于 HasSecret）。
func (s *Store) fieldsOf(kind, provider string) []Field {
	if d, ok := s.reg.Descriptor(kind, provider); ok {
		return d.Fields
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
