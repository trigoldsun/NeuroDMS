import { useEffect, useRef, useState } from 'react'
import { api, setTokens, HttpError, applyTheme } from '../api'
import { Icon, InfoDot, Mark } from '../components/ui'

type LoginResp = {
  accessToken: string
  refreshToken: string
  userId: string
  tenantId: string
}

type MfaResp = {
  mfaRequired?: boolean
  challenge?: string
  sentTo?: string
  expiresIn?: number
}

// 登录方式。同一租户允许本地与域账号同名，所以"用哪种身份"必须由用户选择。
type Mode = 'local' | 'domain'

// 本机记住上次的组织标识：SSO 自动登录需要知道租户，
// 而浏览器在页面加载时唯一能可靠拿到的地方就是上次成功登录的记录。
const TENANT_KEY = 'dv_tenant'

// 左侧用锐进调性：墨底 + 青/紫光晕 + 点阵 + 直角阶梯。
// 工作界面一律用静默调性，只有登录页允许这一档"音量"。
function StepMotif() {
  return (
    <svg className="steps" width="230" height="150" viewBox="0 0 230 150" fill="none" aria-hidden>
      <path d="M8 132 H58 V102 H108 V72 H158 V42 H212" stroke="rgba(255,255,255,.26)" strokeWidth="1.2" />
      {[[58, 132], [58, 102], [108, 102], [108, 72], [158, 72], [158, 42]].map(([x, y], i) => (
        <rect key={i} x={x - 4.5} y={y - 4.5} width="9" height="9" fill="rgba(255,255,255,.42)" />
      ))}
      <rect x="206" y="36" width="12" height="12" fill="var(--sprout)" />
    </svg>
  )
}

function Aside() {
  return (
    <aside className="login-aside">
      <div className="blade" />
      <div className="stack">
        <div className="row-gap" style={{ gap: 10, marginBottom: 34 }}>
          <Mark size={30} />
          <div>
            <div style={{ color: '#F4F9F4', fontWeight: 600, fontSize: 15, letterSpacing: '-.01em' }}>NeuroDMS</div>
            <div style={{ color: 'rgba(234,243,238,.52)', fontSize: 11, letterSpacing: '.14em' }}>DOCUMENT CONTROL</div>
          </div>
        </div>
        <h1>
          把文件管住，
          <br />
          把外发管住，
          <br />
          把责任留痕。
        </h1>
        <p className="lede">
          集中存放、按需授权、随时收回。敏感内容预览即带溯源水印，外发需审批，
          每一次查看都留在审计链上——不是"事后追查"，而是"当场可解释"。
        </p>
        <div className="marks">
          <span>分级授权</span>
          <span>密级管控</span>
          <span>外发审批</span>
          <span>溯源水印</span>
          <span>审计留痕</span>
        </div>
      </div>
      <StepMotif />
      <div className="foot">所有访问均记录于不可篡改的审计链 · 森莘科创</div>
    </aside>
  )
}

export default function Login() {
  const [tenantSlug, setSlug] = useState(() => localStorage.getItem(TENANT_KEY) ?? '')
  const [username, setUser] = useState('')
  const [password, setPass] = useState('')
  const [mode, setMode] = useState<Mode>('local')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [hint, setHint] = useState('')

  // 二次验证：口令通过后服务端返回 202 + challenge，此时**没有任何令牌**。
  // 界面必须把用户停在"输验证码"这一步，不能有任何"已登录"的中间态。
  const [showPass, setShowPass] = useState(false)
  const [challenge, setChallenge] = useState<MfaResp | null>(null)
  const [code, setCode] = useState('')

  // 域身份单点登录：可用时页面加载即尝试一次，失败静默回退到表单。
  const [ssoAvailable, setSsoAvailable] = useState(false)
  const [ssoReason, setSsoReason] = useState('')
  const [ssoTrying, setSsoTrying] = useState(false)
  const autoTried = useRef(false)

  applyTheme()

  function goAfterLogin(access: string, refresh: string, tenant?: string) {
    setTokens(access, refresh)
    if (tenant) localStorage.setItem(TENANT_KEY, tenant)
    const redirect = new URLSearchParams(location.search).get('redirect')
    // 只允许站内相对路径，避免开放重定向
    // 默认落到工作台；带着 redirect 的（例如从某条分享链接被弹回登录）仍然回到原地址
    const safe = redirect && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/home'
    location.assign(safe)
  }

  // showError 统一把"哪里错了"与"下一步做什么"分开保存。
  // 服务端没给 hint 时，按当前登录方式给一句针对性提示——
  // 尤其是"选了本地账号、实际是域账号"这种最常见的困惑。
  function showError(err: unknown, fallback: string) {
    if (err instanceof HttpError) {
      setError(err.message || fallback)
      const serverHint = err.hint ?? ''
      if (serverHint) {
        setHint(serverHint)
      } else if (err.code === 'INVALID_CREDENTIALS') {
        setHint(
          mode === 'local'
            ? '若您使用的是域账号，请把上方登录方式切换为「域账号」后重试。'
            : '请确认域账号已由管理员同步到本系统；若刚改过域口令，请使用新口令。',
        )
      } else {
        setHint('')
      }
      return
    }
    setError(fallback)
    setHint('')
  }

  async function loginWithSSO(tenant: string) {
    setSsoTrying(true)
    setError('')
    setHint('')
    try {
      const data = await api<LoginResp & MfaResp>('/v1/auth/sso', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantSlug: tenant }),
      })
      if (data.mfaRequired && data.challenge) {
        setChallenge(data)
        return
      }
      goAfterLogin(data.accessToken, data.refreshToken, tenant)
    } catch (err) {
      // 断言不可用（浏览器不在域内、代理没配集成认证）：静默回退。
      // 这里绝不能弹错误——外部访客也会走到这段代码。
      if (err instanceof HttpError && (err.code === 'SSO_UNAVAILABLE' || err.status === 401)) {
        setSsoAvailable(false)
        return
      }
      showError(err, '域身份登录失败，请改用账号口令登录')
    } finally {
      setSsoTrying(false)
    }
  }

  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const probe = await api<{ available: boolean; tenant?: string; reason?: string }>('/v1/auth/sso')
        if (!alive) return
        setSsoAvailable(!!probe.available)
        setSsoReason(probe.reason ?? '')
        const tenant = (probe.tenant || localStorage.getItem(TENANT_KEY) || '').trim()
        // 只在"能确定租户"且尚未尝试过时自动登录一次
        if (probe.available && tenant && !autoTried.current) {
          autoTried.current = true
          void loginWithSSO(tenant)
        }
      } catch {
        if (alive) setSsoAvailable(false)
      }
    })()
    return () => {
      alive = false
    }
    // 只在首次挂载时探测；其余依赖都由即时读取的 state 提供
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    setHint('')
    try {
      const data = await api<LoginResp & MfaResp>('/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantSlug, username, password, mode }),
      })
      if (data.mfaRequired && data.challenge) {
        setChallenge(data)
        return
      }
      goAfterLogin(data.accessToken, data.refreshToken, tenantSlug)
    } catch (err) {
      showError(err, '登录失败')
    } finally {
      setBusy(false)
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    if (busy || !challenge?.challenge) return
    setBusy(true)
    setError('')
    setHint('')
    try {
      const data = await api<LoginResp>('/v1/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge: challenge.challenge, code }),
      })
      goAfterLogin(data.accessToken, data.refreshToken, tenantSlug)
    } catch (err) {
      if (err instanceof HttpError && err.code === 'CHALLENGE_STALE') {
        // 挑战过期只能重新登录，不能就地重试
        setChallenge(null)
        setCode('')
        setError('验证会话已失效，请重新登录')
      } else {
        showError(err, '验证失败')
      }
    } finally {
      setBusy(false)
    }
  }

  if (challenge) {
    return (
      <div className="login-wrap">
        <Aside />
        <div className="login-card">
          <div className="login-inner">
            <div className="login-head">
              <span className="label">第二步 / 共两步</span>
              <h2>输入验证码</h2>
              <p>
                验证码已发送至 <b style={{ color: 'var(--ink)' }}>{challenge.sentTo}</b>
                {challenge.expiresIn ? `，${Math.max(1, Math.round(challenge.expiresIn / 60))} 分钟内有效` : ''}。
                外部协作者账号强制二次验证，收不到码将无法登录。
              </p>
            </div>
            <form onSubmit={submitCode}>
              <div className="field">
                <label htmlFor="code">6 位验证码</label>
                <input
                  id="code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  required
                  autoFocus
                  style={{ letterSpacing: '.5em', fontFamily: 'var(--mono)', fontSize: 17, height: 42 }}
                />
              </div>

              {error && (
                <div className="err" role="alert">
                  <span className="ico"><Icon name="alert" size={15} /></span>
                  <span>{error}</span>
                </div>
              )}
              {hint && <div className="hint">{hint}</div>}

              <button className="primary lg" type="submit" disabled={busy || code.length < 4}>
                {busy ? '验证中…' : '验证并登录'}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setChallenge(null)
                  setCode('')
                  setError('')
                  setHint('')
                }}
              >
                返回重新登录
              </button>
            </form>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="login-wrap">
      <Aside />
      <div className="login-card">
        <div className="login-inner">
          <div className="login-head">
            <span className="label">登录 / Sign in</span>
            <h2>进入文档中心</h2>
            <p>用组织标识与账号登录。组织标识就是你们公司在这套系统里的短名，例如 demo。</p>
          </div>

          <form onSubmit={submit}>
            <div className="field">
              <label htmlFor="tenant" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                组织标识
                <InfoDot title="什么是组织标识">
                  <p>组织标识（租户短名）用来把你的账号定位到正确的组织。同一个账号名在不同组织里是不同的人。</p>
                  <p>忘记时问管理员，或用公司门户上的登录链接直接进入。</p>
                  <div className="pop-foot">本机会记住上次成功的组织标识，下次自动填好。</div>
                </InfoDot>
              </label>
              <input
                id="tenant"
                value={tenantSlug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="例如 demo"
                autoComplete="organization"
                required
              />
            </div>

            <div className="field">
              <label htmlFor="user">账号</label>
              <input id="user" value={username} onChange={(e) => setUser(e.target.value)} autoComplete="username" required />
            </div>

            <div className="field">
              <label htmlFor="pass" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                口令
                {mode === 'domain' && (
                  <span className="hint" style={{ marginLeft: 'auto' }}>由公司域统一校验</span>
                )}
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  id="pass"
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPass(e.target.value)}
                  autoComplete="current-password"
                  required
                  style={{ width: '100%', paddingRight: 40 }}
                />
                <button
                  type="button"
                  className="icon ghost"
                  aria-label={showPass ? '隐藏口令' : '显示口令'}
                  onClick={() => setShowPass((v) => !v)}
                  style={{ position: 'absolute', right: 2, top: 2, height: 30, width: 30 }}
                >
                  <Icon name={showPass ? 'eyeOff' : 'eye'} size={16} />
                </button>
              </div>
            </div>

            <div className="field">
              <label>登录方式</label>
              <div className="seg" role="group" aria-label="登录方式" style={{ width: '100%' }}>
                <button type="button" className={mode === 'local' ? 'on' : ''} onClick={() => setMode('local')} style={{ flex: 1 }}>
                  本地账号
                </button>
                <button type="button" className={mode === 'domain' ? 'on' : ''} onClick={() => setMode('domain')} style={{ flex: 1 }}>
                  域账号
                </button>
              </div>
              <div className="hint">
                {mode === 'local'
                  ? '账号与口令由本系统管理。若口令由公司域统一管理，请选择「域账号」。'
                  : '使用公司域（AD/LDAP）账号与口令；账号需先由管理员同步到本系统。'}
              </div>
            </div>

            {error && (
              <div className="err" role="alert">
                <span className="ico"><Icon name="alert" size={15} /></span>
                <span>{error}</span>
              </div>
            )}
            {hint && <div className="hint">{hint}</div>}

            <button className="primary lg" type="submit" disabled={busy || ssoTrying}>
              {busy ? '登录中…' : ssoTrying ? '正在使用域身份登录…' : '登录'}
            </button>

            {ssoAvailable && (
              <>
                <div className="login-sec">或</div>
                <button
                  type="button"
                  className="lg"
                  disabled={busy || ssoTrying || !tenantSlug}
                  onClick={() => void loginWithSSO(tenantSlug)}
                  title="由浏览器与域控完成集成认证，无需输入口令"
                >
                  <Icon name="shield" size={16} /> 使用当前 Windows 域身份登录
                </button>
              </>
            )}

            {!ssoAvailable && ssoReason && <p className="hint" style={{ margin: 0 }}>{ssoReason}</p>}

            <p className="login-note">
              连续多次口令错误会临时锁定账号（按账号计，不按 IP）。<br />
              外部协作者账号强制二次验证；如需帮助请联系管理员。
            </p>
          </form>
        </div>
      </div>
    </div>
  )
}
