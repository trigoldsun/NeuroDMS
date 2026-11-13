package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 认证失败原因。对外一律映射为可读提示，且不区分"用户不存在"与"口令错误"。
var (
	ErrInvalidCredentials = errors.New("账号或口令不正确")
	ErrAccountLocked      = errors.New("账号已锁定，请稍后再试")
	ErrAccountDisabled    = errors.New("账号不可用")
	ErrSessionInvalid     = errors.New("会话已失效，请重新登录")
	ErrWeakPassword       = errors.New("口令不满足强度要求")
)

// Config 是认证策略，全部来自系统设置（不允许写死在代码里）。
type Config struct {
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	MaxFailed      int
	LockDuration   time.Duration
	MinPasswordLen int
}

// DefaultConfig 给出保守默认值，生产由设置表覆盖。
func DefaultConfig() Config {
	return Config{
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     30 * 24 * time.Hour,
		MaxFailed:      5,
		LockDuration:   30 * time.Minute,
		MinPasswordLen: 12,
	}
}

// Service 处理登录、刷新、登出与改密。
type Service struct {
	pool   *pgxpool.Pool
	secret []byte
	cfg    Config
	now    func() time.Time
	guard  *Guard
	otp    *OTPStore
	sender CodeSender
	dir    DirectoryAuthenticator
}

// DirectoryAuthenticator 是"域账号认证"的最小接口。
// 只暴露认证，不暴露搜索/同步：认证服务不该顺便拥有目录的读权限。
type DirectoryAuthenticator interface {
	// tenantID 必须传入：目录配置现在是**每租户一份**（可以各接各的域），
	// 不带租户就没法选对目录——早期只有全局环境变量时不需要这个参数。
	Authenticate(ctx context.Context, tenantID, username, password string) (externalID string, disabled bool, err error)
}

// SetDirectory 注入目录认证。未注入时，source=ldap 的账号被拒登（fail-closed）。
func (s *Service) SetDirectory(d DirectoryAuthenticator) { s.dir = d }

// CodeSender 负责把验证码送到外部通道（邮件/短信）。
// 定义成接口而不是直接依赖 notify：认证包不该知道"用 SMTP 还是 Graph"。
type CodeSender interface {
	SendCode(ctx context.Context, tenantID, to, purpose, code string) error
}

// SetMFA 注入二次验证依赖。未注入时，mfa_required 的账号会被拒绝登录（fail-closed）。
func (s *Service) SetMFA(otp *OTPStore, sender CodeSender) {
	s.otp = otp
	s.sender = sender
}

// New 构造认证服务。
func New(pool *pgxpool.Pool, secret []byte, cfg Config) *Service {
	return &Service{pool: pool, secret: secret, cfg: cfg, now: time.Now,
		guard: NewGuard(pool, DefaultRevocationTTL)}
}

// Guard 暴露吊销检查器，便于 HTTP 层主动失效缓存。
func (s *Service) Guard() *Guard { return s.guard }

// Tokens 是登录/刷新成功后返回的凭证。
type Tokens struct {
	Access        string
	Refresh       string
	AccessExpires time.Time
	UserID        string
	TenantID      string
	SessionID     string
}

// Login 用租户 slug + 用户名 + 口令登录，mode 指定"按本地身份还是域身份"校验。
//
// 采用"先由 slug 定位租户，再进入该租户上下文校验用户"的方式，
// 因为用户表受 RLS 保护，没有租户上下文就查不到任何人。
//
// 为什么需要 mode：从 0032 起，同一租户允许本地账号与域账号同名。
// 不带来源去查会命中两条，取哪一条都可能是错的——必须由用户选择，
// 而不是由服务端"猜"。
func (s *Service) Login(ctx context.Context, tenantSlug, username, password string, mode LoginMode, ip, ua string) (Tokens, error) {
	if mode == "" {
		mode = LoginAuto
	}
	if mode != LoginAuto && mode != LoginLocal && mode != LoginDomain {
		return Tokens{}, ErrUnknownLoginMode
	}

	tenantID, err := s.resolveTenant(ctx, tenantSlug)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			BurnTime(password) // 保持失败路径耗时一致
		}
		return Tokens{}, err
	}

	u, err := s.findLoginUser(ctx, tenantID, username, mode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 选了"域账号"但本地没有这个人的记录。此时仍然去目录验一次口令：
			//   - 口令通过 → 明确告诉用户"验证通过但没同步"，可直接照做；
			//   - 口令不通过 → 通用凭据错误。
			// 先验口令再给结论，是为了不把这里变成免费的账号枚举接口。
			if mode == LoginDomain {
				return Tokens{}, s.explainMissingDomainUser(ctx, tenantID, username, password)
			}
			BurnTime(password)
			return Tokens{}, ErrInvalidCredentials
		}
		return Tokens{}, err
	}

	now := s.now()
	if u.lockedUntil != nil && u.lockedUntil.After(now) {
		return Tokens{}, ErrAccountLocked
	}
	if u.status != "active" || (u.expiresAt != nil && u.expiresAt.Before(now)) {
		return Tokens{}, ErrAccountDisabled
	}

	verifyErr := errors.New("未设置口令")
	switch {
	case u.source == "ldap":
		// 域账号的口令永远不在本地校验：本地没有它的散列，
		// 即使有也会与目录不同步（改密后本地的旧散列仍然"正确"，这是安全隐患）
		if s.dir == nil {
			return Tokens{}, ErrDirectoryNotConfigured
		}
		extID, disabled, derr := s.dir.Authenticate(ctx, tenantID, username, password)
		switch {
		case derr != nil:
			verifyErr = translateDirectoryError(derr)
		case disabled:
			return Tokens{}, ErrDomainDisabledInDir
		case extID == "":
			verifyErr = ErrInvalidCredentials
		default:
			verifyErr = nil
		}
	case u.passwordHash != nil && *u.passwordHash != "":
		verifyErr = VerifyPassword(*u.passwordHash, password)
	default:
		BurnTime(password)
	}

	if verifyErr != nil {
		// 目录不可达、口令过期、账号被锁：直接如实返回，不计数。
		// 否则一次域控维护就会把全员"锁"在本系统里（见 countsAsFailure）。
		if !countsAsFailure(verifyErr) {
			return Tokens{}, verifyErr
		}

		// 失败计数与锁定必须在**同一个**持锁事务里完成。
		//
		// 早先的写法是"先 SELECT ... FOR UPDATE 读计数（事务随即提交），
		// 再另开一个事务写 failed+1"——行锁在读事务结束时就释放了，
		// 并发请求会全部读到同一个旧值，各自写 failed+1，锁定阈值被绕过。
		// 注释当时写着"FOR UPDATE 保证串行"，但保护范围覆盖不到写入。
		//
		// 这里不把口令校验放进事务（Argon2 要 50ms 量级，持锁太久），
		// 只在写计数时重新加锁并**重读**当前值，因此计数是精确的。
		var (
			locked  bool
			nextVal int
		)
		_ = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			// 重新加锁 + 重读：拿到的是"此刻"的计数，而不是校验口令之前的快照
			var (
				curFailed int
				curLocked *time.Time
			)
			if e := tx.QueryRow(ctx,
				`SELECT failed_attempts, locked_until FROM app_user WHERE id = $1 FOR UPDATE`, u.id).
				Scan(&curFailed, &curLocked); e != nil {
				return e
			}
			// 锁已过期：计数归零，重新给满额机会。
			// 不归零的话，锁定到期后 failed 仍然是 5，用户第一次输错就立刻再锁一轮，
			// 表现为"说好等 30 分钟，等完还是锁着"。
			if curLocked != nil && !curLocked.After(now) {
				curFailed = 0
			}
			nextVal = curFailed + 1

			var lockUntil *time.Time
			if s.cfg.MaxFailed > 0 && nextVal >= s.cfg.MaxFailed {
				t := now.Add(s.cfg.LockDuration)
				lockUntil = &t
				locked = true
			}
			_, e := tx.Exec(ctx, `
				UPDATE app_user
				   SET failed_attempts = $2,
				       locked_until = $3,
				       updated_at = now()
				 WHERE id = $1`, u.id, nextVal, lockUntil)
			return e
		})
		if locked {
			return Tokens{}, ErrAccountLocked
		}
		return Tokens{}, ErrInvalidCredentials
	}

	// 口令已通过。若账号要求二次验证，此处绝不能签发会话——
	// 一旦先签后验，"只偷到口令"就等于完全登录，双因子形同虚设。
	if u.mfaNeeded {
		return Tokens{}, s.startMFA(ctx, tenantID, u.id, u.epoch, u.email, ip)
	}

	// 登录成功：建会话并签发令牌（与二次验证共用同一段逻辑，避免两处漂移）
	return s.createSession(ctx, tenantID, u.id, u.epoch, ip, ua)
}

// loginUser 是登录时需要的账号快照。
type loginUser struct {
	id           string
	passwordHash *string
	status       string
	epoch        int
	failed       int
	lockedUntil  *time.Time
	expiresAt    *time.Time
	email        *string
	mfaNeeded    bool
	source       string
}

// findLoginUser 按登录方式定位账号。
//
// 自动模式的排序（本地 > 域）是刻意的：升级前同名只可能有一条，
// 那条几乎总是本地账号；若改成域优先，这些人会突然改用自己的域口令，
// 表现为"升级后登录不上"。
func (s *Service) findLoginUser(ctx context.Context, tenantID, username string, mode LoginMode) (loginUser, error) {
	var out loginUser

	query := `
		SELECT id, password_hash, status, session_epoch, failed_attempts, locked_until, expires_at,
		       email, mfa_required, source
		  FROM app_user
		 WHERE lower(username) = lower($1) AND deleted_at IS NULL`
	args := []any{username}

	switch mode {
	case LoginLocal:
		query += ` AND source = 'local'`
	case LoginDomain:
		query += ` AND source = 'ldap'`
	}
	if mode == LoginAuto {
		// 只影响"有歧义"的场景：两个同名账号都存在时，默认取本地。
		query += ` ORDER BY CASE source WHEN 'local' THEN 0 WHEN 'ldap' THEN 1 ELSE 2 END`
	}
	query += ` LIMIT 1 FOR UPDATE`

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(
			&out.id, &out.passwordHash, &out.status, &out.epoch, &out.failed,
			&out.lockedUntil, &out.expiresAt, &out.email, &out.mfaNeeded, &out.source)
	})
	return out, err
}

// explainMissingDomainUser 处理"选了域账号，但系统里没有该域账号记录"的情况。
//
// 判断顺序很重要：先用目录验口令，通过后才说"没同步"。
// 反过来（先查库、查不到就回"没同步"）等于给攻击者一个免费的
// "该账号在 AD 中存在"接口。
func (s *Service) explainMissingDomainUser(ctx context.Context, tenantID, username, password string) error {
	if s.dir == nil {
		BurnTime(password)
		return ErrDirectoryNotConfigured
	}
	_, disabled, err := s.dir.Authenticate(ctx, tenantID, username, password)
	switch {
	case err != nil:
		verr := translateDirectoryError(err)
		if errors.Is(verr, ErrInvalidCredentials) {
			BurnTime(password)
		}
		return verr
	case disabled:
		return ErrDomainDisabledInDir
	default:
		// 口令确认无误，只是没同步进来
		return ErrDomainNotSynced
	}
}

// RefreshReplayGrace 是"上一个刷新令牌"仍然可被接受的时间窗口。
//
// 存在的唯一理由：多标签页或客户端重试可能在同一秒内用同一个令牌刷新两次。
// 这种情况不该让任何人下线——第一个请求赢了，第二个落在这里。
// 超过窗口就按重放处理（吊销整条会话），因为正常客户端不会隔几分钟
// 才拿一个已经被换掉的令牌再来一次。
const RefreshReplayGrace = 10 * time.Second

// RefreshReplayError 表示检测到刷新令牌重放，并且已经吊销该会话。
//
// 带上租户与会话，是为了让上层能写一条可追溯的审计——只回 401 的话，
// "谁的会话因为重放被吊销"就只存在于应用日志里，审计查不到。
type RefreshReplayError struct {
	TenantID  string
	UserID    string
	SessionID string
}

func (e *RefreshReplayError) Error() string { return "刷新令牌重放，会话已吊销" }

// ErrRefreshReplay 供 errors.Is 判定（handler 据此写审计与返回明确错误码）。
var ErrRefreshReplay = errors.New("刷新令牌重放")

func (e *RefreshReplayError) Is(target error) bool { return target == ErrRefreshReplay }

// Refresh 用刷新令牌换新的一对令牌，并让旧刷新令牌立即失效（旋转）。
//
// 重放检测的意义：旧令牌被换掉之后，如果它再次出现，只有两种可能——
// 客户端并发/重试，或者令牌已经落到别人手里。后者必须在**第一次**就被发现，
// 否则窃取者可以一直用自己那条链刷新，而合法用户只会看到"登录过期"。
func (s *Service) Refresh(ctx context.Context, refresh, ip, ua string) (Tokens, error) {
	hash := HashRefresh(refresh)

	var tenantID, userID, sessionID string
	// 当前摘要与上一摘要都参与定位：上一摘要命中时才知道"这是被替换掉的旧令牌"。
	// ORDER BY 让"当前"优先，避免两个字段同时相等（理论上不可能）时误判为重放。
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, user_id, id
		  FROM session
		 WHERE refresh_hash = $1 OR prev_refresh_hash = $1
		 ORDER BY (refresh_hash = $1) DESC
		 LIMIT 1`, hash).
		Scan(&tenantID, &userID, &sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tokens{}, ErrSessionInvalid
		}
		return Tokens{}, err
	}

	var epoch int
	now := s.now()
	newRefresh, newHash, err := NewRefreshToken()
	if err != nil {
		return Tokens{}, err
	}
	newExpires := now.Add(s.cfg.AccessTTL)

	// 重放错误不能从事务函数里 return：WithTenant 见到 error 会回滚，
	// 刚写进去的 revoked_at 会一起消失——表现为"检测到了，但会话还在"。
	// 与 share.redeem 里的 pending 是同一个坑：**要保留的写入，必须在提交后报错**。
	var replayErr *RefreshReplayError

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var (
			sessEpoch   int
			revoked     *time.Time
			sessExpires time.Time
			userStatus  string
			userEpoch   int
			curHash     []byte
			prevHash    []byte
			rotatedAt   *time.Time
		)

		// 锁住会话行，保证"同一刷新令牌只能用一次"
		if e := tx.QueryRow(ctx, `
			SELECT s.epoch, s.revoked_at, s.expires_at, u.status, u.session_epoch,
			       s.refresh_hash, s.prev_refresh_hash, s.refresh_rotated_at
			  FROM session s JOIN app_user u ON u.id = s.user_id
			 WHERE s.id = $1 FOR UPDATE`, sessionID).
			Scan(&sessEpoch, &revoked, &sessExpires, &userStatus, &userEpoch,
				&curHash, &prevHash, &rotatedAt); e != nil {
			return e
		}
		if revoked != nil || sessExpires.Before(now) || userStatus != "active" || userEpoch != sessEpoch {
			return ErrSessionInvalid
		}

		switch {
		case bytes.Equal(curHash, hash):
			// 正常路径
		case prevHash != nil && bytes.Equal(prevHash, hash):
			if rotatedAt != nil && now.Sub(*rotatedAt) <= RefreshReplayGrace {
				// 宽限内：并发/重试。只让这一个请求失败，不动会话——
				// 否则一次双击就会把刚拿到新令牌的那个标签页一起踢下线。
				return ErrSessionInvalid
			}
			// 超出宽限：判定为重放，吊销整条会话链。
			// 记下错误但返回 nil，让这次吊销真正提交（见上面 replayErr 的注释）。
			if _, e := tx.Exec(ctx,
				`UPDATE session SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
				sessionID); e != nil {
				return e
			}
			replayErr = &RefreshReplayError{TenantID: tenantID, UserID: userID, SessionID: sessionID}
			return nil
		default:
			// 既不是当前也不是上一摘要：令牌与该会话无关（伪造或已被清理）
			return ErrSessionInvalid
		}

		epoch = sessEpoch
		_, e := tx.Exec(ctx, `
			UPDATE session
			   SET prev_refresh_hash = refresh_hash,
			       refresh_hash = $2,
			       refresh_rotated_at = now(),
			       last_seen_at = now(),
			       user_agent = nullif($3,''),
			       ip = nullif($4,'')::inet
			 WHERE id = $1`, sessionID, newHash, ua, ip)
		return e
	})
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return Tokens{}, ErrSessionInvalid
		}
		return Tokens{}, err
	}
	// 吊销已提交，此时才把"重放"这个结论交给上层（写审计 + 401）
	if replayErr != nil {
		return Tokens{}, replayErr
	}

	access, err := SignAccess(s.secret, Claims{
		Subject: userID, TenantID: tenantID, SessionID: sessionID,
		Epoch: epoch, IssuedAt: now, ExpiresAt: newExpires,
	})
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{
		Access: access, Refresh: newRefresh, AccessExpires: newExpires,
		UserID: userID, TenantID: tenantID, SessionID: sessionID,
	}, nil
}

// Logout 让刷新令牌与会话立即失效。
func (s *Service) Logout(ctx context.Context, refresh string) error {
	hash := HashRefresh(refresh)
	var tenantID, sessionID string
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, id FROM session WHERE refresh_hash=$1`, hash).
		Scan(&tenantID, &sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // 已失效视为成功，避免暴露令牌是否存在
		}
		return err
	}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE session SET revoked_at = now() WHERE id = $1`, sessionID)
		return e
	})
	if err == nil {
		s.guard.InvalidateSession(sessionID)
	}
	return err
}

// Verify 校验访问令牌：先验签（无状态、快），再查吊销状态（有缓存、有界延迟）。
//
// 两级的意义：验签挡住伪造令牌且不触库；吊销检查让"停用/改密/登出"
// 在 TTL（默认 10s，PRD 要求 30s）内收敛，而不是等 15 分钟的 AccessTTL。
// 吊销查询出错时 fail-closed 拒绝，不放行——"查不到就说没事"是安全缺陷。
func (s *Service) Verify(ctx context.Context, access string) (Claims, error) {
	c, err := ParseAccess(s.secret, access)
	if err != nil {
		return Claims{}, err
	}
	if err := s.guard.Check(ctx, c); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// ChangePassword 校验旧口令后改密，并使该用户全部会话失效。
func (s *Service) ChangePassword(ctx context.Context, access, oldPassword, newPassword string) error {
	claims, err := ParseAccess(s.secret, access)
	if err != nil {
		return ErrSessionInvalid
	}
	if len(newPassword) < s.cfg.MinPasswordLen {
		return ErrWeakPassword
	}

	var pwHash *string
	err = db.WithTenant(ctx, s.pool, claims.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash FROM app_user WHERE id = $1 FOR UPDATE`, claims.Subject).
			Scan(&pwHash)
	})
	if err != nil {
		return ErrSessionInvalid
	}
	if pwHash == nil || *pwHash == "" {
		return ErrInvalidCredentials
	}
	if err := VerifyPassword(*pwHash, oldPassword); err != nil {
		return ErrInvalidCredentials
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	return db.WithTenant(ctx, s.pool, claims.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `
			UPDATE app_user SET password_hash = $2, session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, claims.Subject, newHash); e != nil {
			return e
		}
		// 全部会话立即吊销：账号被盗后改密必须能收敛已有凭证
		_, e := tx.Exec(ctx, `UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
			claims.Subject)
		return e
	})
}

// SetUserStatus 启用/停用账号。
//
// 停用必须同时做三件事，少做一件都会留下"停用了还能用"的洞：
//  1. 置 status
//  2. session_epoch + 1（让已签发但未过期的访问令牌在下次检查时失效）
//  3. 吊销全部会话（让刷新令牌彻底不可用）
func (s *Service) SetUserStatus(ctx context.Context, tenantID, userID, status string) error {
	// 取值与 app_user.status 的检查约束保持一致：active / suspended / deleted
	if status != "active" && status != "suspended" && status != "deleted" {
		return errors.New("非法状态：仅支持 active、suspended 或 deleted")
	}
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `
			UPDATE app_user SET status = $2, session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, userID, status); e != nil {
			return e
		}
		if status != "active" {
			if _, e := tx.Exec(ctx,
				`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
				userID); e != nil {
				return e
			}
		}
		return nil
	})
	if err == nil {
		// 本实例立即收敛；其它实例 ≤ TTL
		s.guard.InvalidateAll()
	}
	return err
}

// InvalidateRevocationCache 让本实例立即重新读取会话状态。
//
// 供"管理员在别的路径改了账号状态"时调用：数据库已经改了，
// 但吊销检查有 ≤10s 的进程内缓存，不清掉就会出现
// "已停用/已改密，但本实例上的人还能用几秒"。
func (s *Service) InvalidateRevocationCache() {
	if s.guard != nil {
		s.guard.InvalidateAll()
	}
}

// ErrNoTenant 表示租户不存在（内部使用）。
var ErrNoTenant = fmt.Errorf("租户不存在")

// MFAChallenge 既是一种错误（表示"未完成登录"），也承载继续验证所需的信息。
type MFAChallenge struct {
	Challenge string
	SentTo    string
	ExpiresIn int
}

func (e *MFAChallenge) Error() string { return "需要二次验证" }

// startMFA 签发挑战并把验证码发出去。
func (s *Service) startMFA(ctx context.Context, tenantID, userID string, epoch int, email *string, ip string) error {
	if email == nil || *email == "" {
		return ErrAccountDisabled // 没配邮箱就无法二次验证，只能拒登
	}
	if s.otp == nil || s.sender == nil {
		return ErrAccountDisabled // 未配置投递通道时 fail-closed
	}

	// 清失败计数：口令已经对了，不该因为"等验证码"把人锁死
	_ = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE app_user SET failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1`,
			userID)
		return e
	})

	subject := normalizeSubject(*email)
	code, _, err := s.otp.Issue(ctx, tenantID, subject, purposeLogin2FA)
	if err != nil {
		return err
	}
	if err := s.sender.SendCode(ctx, tenantID, *email, purposeLogin2FA, code); err != nil {
		// 发不出去就等于验证失败，不能返回"已发送"
		return err
	}

	expires := s.now().Add(5 * time.Minute)
	challenge, err := SignChallenge(s.secret, MFAClaims{
		UserID: userID, TenantID: tenantID, Purpose: subject, Epoch: epoch, ExpiresAt: expires,
	})
	if err != nil {
		return err
	}
	return &MFAChallenge{
		Challenge: challenge,
		SentTo:    maskEmail(*email),
		ExpiresIn: int(time.Until(expires).Seconds()),
	}
}

// VerifyMFA 用验证码完成登录，签发正常令牌。
func (s *Service) VerifyMFA(ctx context.Context, challenge, code, ip, ua string) (Tokens, error) {
	c, err := ParseChallenge(s.secret, challenge)
	if err != nil {
		return Tokens{}, err
	}
	if s.otp == nil {
		return Tokens{}, ErrAccountDisabled
	}

	// 验证码按"主体 + 用途"隔离：A 账号的码不能用来完成 B 账号的登录
	if err := s.otp.Verify(ctx, c.TenantID, c.Purpose, purposeLogin2FA, code); err != nil {
		return Tokens{}, err
	}

	// 二次验证通过后，账号状态可能在等待期间被改动，必须重新读一遍
	var epoch int
	var status string
	var email *string
	err = db.WithTenant(ctx, s.pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT session_epoch, status, email FROM app_user WHERE id = $1 AND deleted_at IS NULL`,
			c.UserID).Scan(&epoch, &status, &email)
	})
	if err != nil {
		return Tokens{}, ErrAccountDisabled
	}
	if status != "active" {
		return Tokens{}, ErrAccountDisabled
	}

	return s.createSession(ctx, c.TenantID, c.UserID, epoch, ip, ua)
}

// createSession 建会话并签发令牌。
func (s *Service) createSession(ctx context.Context, tenantID, userID string, epoch int, ip, ua string) (Tokens, error) {
	var out Tokens
	now := s.now()
	refresh, refreshHash, err := NewRefreshToken()
	if err != nil {
		return Tokens{}, err
	}
	expires := now.Add(s.cfg.AccessTTL)
	refreshExpires := now.Add(s.cfg.RefreshTTL)

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `
			UPDATE app_user SET failed_attempts = 0, locked_until = NULL,
			       last_login_at = now(), updated_at = now()
			 WHERE id = $1`, userID); e != nil {
			return e
		}
		var sid string
		if e := tx.QueryRow(ctx, `
			INSERT INTO session (id, tenant_id, user_id, refresh_hash, epoch, user_agent, ip, expires_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, nullif($5,''), nullif($6,'')::inet, $7)
			RETURNING id`,
			tenantID, userID, refreshHash, epoch, ua, ip, refreshExpires).Scan(&sid); e != nil {
			return e
		}
		out.SessionID = sid
		return nil
	})
	if err != nil {
		return Tokens{}, err
	}

	access, err := SignAccess(s.secret, Claims{
		Subject: userID, TenantID: tenantID, SessionID: out.SessionID,
		Epoch: epoch, IssuedAt: now, ExpiresAt: expires,
	})
	if err != nil {
		return Tokens{}, err
	}
	out.Access = access
	out.Refresh = refresh
	out.AccessExpires = expires
	out.UserID = userID
	out.TenantID = tenantID
	return out, nil
}

const purposeLogin2FA = "login_2fa"

func normalizeSubject(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// maskEmail 返回 u***@example.com 这种形式：让用户确认"发到哪了"，
// 又不把完整地址回显到响应/日志里。
func maskEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	name := email[:at]
	if len(name) <= 1 {
		return "***" + email[at:]
	}
	return name[:1] + "***" + email[at:]
}
