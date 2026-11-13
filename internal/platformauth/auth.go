// Package platformauth 实现平台运营账号与会话。
//
// 与 internal/auth 的关系：完全并列，互不复用令牌格式。
// 这是刻意的——只要存在"某种令牌既被租户接口接受、又被平台接口接受"，
// 就一定会出现"用租户身份混进平台面"的漏洞。两类令牌在结构上就不可能互换。
package platformauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"docvault/internal/auth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 角色。
const (
	RoleOps      = "ops"
	RoleReadonly = "readonly"
)

// 错误。
var (
	ErrInvalidCredentials = errors.New("账号或口令不正确")
	ErrAccountDisabled    = errors.New("平台账号已停用")
	ErrSessionInvalid     = errors.New("平台会话无效或已过期")
	ErrForbidden          = errors.New("该平台账号为只读角色")
)

// TokenTTL 是平台会话有效期。
//
// 比租户访问令牌长（4 小时）：平台操作是低频、长间隔的运维行为，
// 每 15 分钟重登会让人转而在脚本里硬编码口令——那比长会话更危险。
const TokenTTL = 4 * time.Hour

// Principal 是已认证的平台操作者。
type Principal struct {
	UserID string
	Email  string
	Role   string
	// Static 为真表示用的是应急静态令牌（DOCVAULT_PLATFORM_TOKEN），
	// 不是某个具体账号——审计里要能区分这两种来源。
	Static bool
}

// CanWrite 判断是否允许变更操作。
func (p Principal) CanWrite() bool { return p.Role == RoleOps }

// Service 是平台会话服务。
type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time

	mu    sync.RWMutex
	cache map[string]cachedSession // tokenHash -> session
}

type cachedSession struct {
	p       Principal
	expires time.Time
	checked time.Time
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, now: time.Now, cache: map[string]cachedSession{}}
}

// Login 校验口令并签发不透明令牌。
func (s *Service) Login(ctx context.Context, email, password, ip, ua string) (string, Principal, time.Time, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return "", Principal{}, time.Time{}, ErrInvalidCredentials
	}

	var (
		id, hash, role, status string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, password_hash, role, status FROM platform_user WHERE email = $1`, email).
		Scan(&id, &hash, &role, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 与"口令错"同一错误：区分开会变成账号枚举接口
			return "", Principal{}, time.Time{}, ErrInvalidCredentials
		}
		return "", Principal{}, time.Time{}, err
	}
	if err := auth.VerifyPassword(hash, password); err != nil {
		return "", Principal{}, time.Time{}, ErrInvalidCredentials
	}
	if status != "active" {
		return "", Principal{}, time.Time{}, ErrAccountDisabled
	}

	token := "plat_" + randomHex(32)
	sum := sha256.Sum256([]byte(token))
	expires := s.now().Add(TokenTTL)

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO platform_session (id, user_id, token_hash, expires_at, ip, user_agent)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)`,
		id, sum[:], expires, ip, truncate(ua, 300)); err != nil {
		return "", Principal{}, time.Time{}, err
	}
	_, _ = s.pool.Exec(ctx,
		`UPDATE platform_user SET last_login_at = now() WHERE id = $1`, id)

	p := Principal{UserID: id, Email: email, Role: role}
	return token, p, expires, nil
}

// Authenticate 校验平台令牌。
//
// 静态应急令牌与账号会话都走这里，但**先**比静态令牌：
// 常量时间比较，避免长度/前缀差异泄露信息。
func (s *Service) Authenticate(ctx context.Context, token, staticToken string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrSessionInvalid
	}
	if staticToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(staticToken)) == 1 {
		return Principal{Email: "static-token", Role: RoleOps, Static: true}, nil
	}

	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	s.mu.RLock()
	if c, ok := s.cache[key]; ok && s.now().Sub(c.checked) < 10*time.Second {
		s.mu.RUnlock()
		if c.expires.Before(s.now()) {
			return Principal{}, ErrSessionInvalid
		}
		return c.p, nil
	}
	s.mu.RUnlock()

	var (
		p       Principal
		expires time.Time
		revoked *time.Time
		status  string
		email   string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.id::text, u.email, u.role, u.status, sess.expires_at, sess.revoked_at
		  FROM platform_session sess
		  JOIN platform_user u ON u.id = sess.user_id
		 WHERE sess.token_hash = $1`, sum[:]).Scan(&p.UserID, &email, &p.Role, &status, &expires, &revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, ErrSessionInvalid
		}
		return Principal{}, err
	}
	if revoked != nil || status != "active" || expires.Before(s.now()) {
		return Principal{}, ErrSessionInvalid
	}
	p.Email = email

	s.mu.Lock()
	s.cache[key] = cachedSession{p: p, expires: expires, checked: s.now()}
	s.mu.Unlock()
	return p, nil
}

// Logout 吊销当前会话（立即失效，不等过期）。
func (s *Service) Logout(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	_, err := s.pool.Exec(ctx,
		`UPDATE platform_session SET revoked_at = now()
		  WHERE token_hash = $1 AND revoked_at IS NULL`, sum[:])
	s.mu.Lock()
	s.cache = map[string]cachedSession{}
	s.mu.Unlock()
	return err
}

// RevokeUserSessions 吊销某账号的全部会话（停用账号时调用）。
func (s *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE platform_session SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	s.mu.Lock()
	s.cache = map[string]cachedSession{}
	s.mu.Unlock()
	return err
}

// Bootstrap 在没有任何平台账号时创建首个账号。
//
// 只在启动装配时调用（与 rbac.Bootstrap 同一纪律），绝不放进请求路径。
func (s *Service) Bootstrap(ctx context.Context, email, password, display string) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return false, nil
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM platform_user`).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if len([]rune(password)) < 12 {
		return false, fmt.Errorf("平台账号口令至少 12 位")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return false, err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO platform_user (id, email, display_name, password_hash, role)
		VALUES (gen_random_uuid(), $1, $2, $3, 'ops')`, email, display, hash); err != nil {
		return false, err
	}
	return true, nil
}

// Audit 写一条平台审计。失败不阻断业务，但会被记录到调用方日志——
// 平台操作"看不见"比"没记上"更危险，调用方必须把 err 打出来。
func (s *Service) Audit(ctx context.Context, actor, action, target, result string,
	detail map[string]any, ip string) error {
	if detail == nil {
		detail = map[string]any{}
	}
	var raw []byte
	raw, _ = jsonMarshal(detail)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO platform_audit (actor, action, target, result, detail, ip)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
		actor, action, target, result, string(raw), ip)
	return err
}

// AuditFilter 是平台审计查询条件。
type AuditFilter struct {
	Action string
	Target string
	Limit  int
}

// Event 是平台审计条目。
type Event struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Result    string
	IP        string
	CreatedAt time.Time
}

// AuditList 查询平台审计。
func (s *Service) AuditList(ctx context.Context, f AuditFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, actor, action, target, result, ip, created_at
		  FROM platform_audit
		 WHERE ($1 = '' OR action = $1) AND ($2 = '' OR target = $2)
		 ORDER BY id DESC LIMIT $3`, f.Action, f.Target, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.Result, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败意味着系统熵源坏了，继续签令牌只会更糟
		panic("crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func jsonMarshal(v map[string]any) ([]byte, error) {
	return json.Marshal(v)
}

// ---------------- 平台账号管理（M3 账号管理） ----------------

// 账号管理错误。语义与租户侧保持一致，便于前端统一处理。
var (
	ErrUserExists   = errors.New("该邮箱已被占用")
	ErrSelfTarget   = errors.New("不能对自己执行该操作")
	ErrLastOps      = errors.New("不能停用最后一个可用的运营账号")
	ErrInvalidRole  = errors.New("角色仅支持 ops / readonly")
	ErrInvalidInput = errors.New("参数不合法")
)

// User 是平台账号的对外视图（不含口令材料）。
type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"displayName"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
}

// ListUsers 返回平台账号列表。
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, email, display_name, role, status, created_at, last_login_at
		  FROM platform_user ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status,
			&u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser 创建平台账号。
//
// 为什么平台账号只能由平台自己建：它不属于任何客户租户，
// 一旦允许"从租户侧创建"，就等于给客户留了一条通往跨租户视野的侧门。
func (s *Service) CreateUser(ctx context.Context, email, display, role, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	display = strings.TrimSpace(display)
	if email == "" || !strings.Contains(email, "@") {
		return User{}, fmt.Errorf("%w: 邮箱不合法", ErrInvalidInput)
	}
	switch role {
	case RoleOps, RoleReadonly:
	default:
		return User{}, ErrInvalidRole
	}
	if len([]rune(password)) < 12 {
		return User{}, fmt.Errorf("%w: 初始口令至少 12 位", ErrInvalidInput)
	}
	if display == "" {
		display = email
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return User{}, err
	}

	var u User
	err = s.pool.QueryRow(ctx, `
		INSERT INTO platform_user (id, email, display_name, password_hash, role)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
		RETURNING id::text, email, display_name, role, status, created_at, last_login_at`,
		email, display, hash, role).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return User{}, ErrUserExists
		}
		return User{}, err
	}
	return u, nil
}

// SetUserStatus 启用/停用平台账号。
//
// 两条护栏：
//  1. 不能停用自己（否则一次误操作就把自己踢出去，且没人能救）；
//  2. 不能停用最后一个可用 ops（否则整个平台失去变更能力，只能靠应急令牌）。
//
// 停用必须同时吊销该账号的全部会话——平台令牌是有状态的，
// 这里直接把它置为已吊销，而不是等它 4 小时后过期。
func (s *Service) SetUserStatus(ctx context.Context, actorID, userID, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("%w: 状态仅支持 active/suspended", ErrInvalidInput)
	}
	if actorID != "" && actorID == userID {
		return ErrSelfTarget
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var role, cur string
	if err := tx.QueryRow(ctx,
		`SELECT role, status FROM platform_user WHERE id = $1 FOR UPDATE`, userID).
		Scan(&role, &cur); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionInvalid
		}
		return err
	}

	if status != "active" && role == RoleOps {
		var ops int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM platform_user
			 WHERE role = 'ops' AND status = 'active' AND id <> $1`, userID).Scan(&ops); err != nil {
			return err
		}
		if ops == 0 {
			return ErrLastOps
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE platform_user SET status = $2 WHERE id = $1`, userID, status); err != nil {
		return err
	}
	if status != "active" {
		if _, err := tx.Exec(ctx,
			`UPDATE platform_session SET revoked_at = now()
			  WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	s.cache = map[string]cachedSession{}
	s.mu.Unlock()
	return nil
}

// ResetUserPassword 重置平台账号口令，并吊销其全部会话。
func (s *Service) ResetUserPassword(ctx context.Context, userID, newPassword string) error {
	if len([]rune(newPassword)) < 12 {
		return fmt.Errorf("%w: 新口令至少 12 位", ErrInvalidInput)
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx,
		`UPDATE platform_user SET password_hash = $2 WHERE id = $1`, userID, hash)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrSessionInvalid
	}
	if _, err := tx.Exec(ctx,
		`UPDATE platform_session SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.cache = map[string]cachedSession{}
	s.mu.Unlock()
	return nil
}
