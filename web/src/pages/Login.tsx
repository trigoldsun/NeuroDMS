import { useEffect, useRef, useState } from 'react'
import { api, setTokens, HttpError, applyTheme } from '../api'
import { applyProductFavicon } from '../branding'
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

// 登录页是未登录状态，图标与名称来自**公开品牌接口**（/v1/tenant/branding）。
// 之前这里硬编码 NeuroDMS：客户在「品牌与名称」里改了名、传了图标，
// 登录页还是厂商品牌——这是客户第一眼看到的地方，分裂感最明显。
function Aside({ productName, logoUrl, footerText }: {
  productName: string
  logoUrl: string
  footerText: string
}) {
  return (
    <aside className="login-aside">
      <div className="blade" />
      <div className="stack">
        <div className="row-gap" style={{ gap: 10, marginBottom: 34 }}>
          {logoUrl
            ? <img src={logoUrl} alt="" width={30} height={30}
              style={{ width: 30, height: 30, flex: '0 0 30px', objectFit: 'contain' }} />
            : <Mark size={30} />}
          <div style={{ minWidth: 0 }}>
            <div style={{
              color: '#F4F9F4', fontWeight: 600, fontSize: 15, letterSpacing: '-.01em',
              maxWidth: 230, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {productName || 'NeuroDMS'}
            </div>
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
      <div className="foot">
        {footerText || '所有访问均记录于不可篡改的审计链'}
      </div>
    </aside>
  )
}

export default function Login() {
  const [tenantSlug, setSlug] = useState(() => localStorage.getItem(TENANT_KEY) ?? '')
  // 品牌（公开接口，未登录可读）：组织标识一变就重新拉，带 350ms 防抖——
  // 用户逐字输入时不该每敲一下就发一个请求。
  const [brandName, setBrandName] = useState('')
  const [brandLogo, setBrandLogo] = useState('')
  const [brandFooter, setBrandFooter] = useState('')

  // 登录页固定产品图标：这里只显示"是谁的系统"，不替任何租户打标。
  // 登录成功进入站内后，Shell 才会把图标换成当前租户的（见 branding.ts）。
  useEffect(() => { applyProductFavicon() }, [])

  useEffect(() => {
    const slug = tenantSlug.trim()
    if (!slug) {
      setBrandName(''); setBrandLogo(''); setBrandFooter('')
      return
    }
    const ctl = new AbortController()
    const timer = window.setTimeout(() => {
      fetch('/v1/tenant/branding?slug=' + encodeURIComponent(slug), {
        headers: { accept: 'application/json' }, signal: ctl.signal,
        // 品牌接口有 60 秒缓存；登录页是"改完图标马上来验证"的地方，
        // 吃到旧缓存会让人以为没保存成功。
        cache: 'no-store',
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((j) => {
          const d = j?.data
          if (!d) return
          setBrandName(String(d.productName ?? ''))
          setBrandLogo(String(d.logoUrl ?? ''))
          setBrandFooter(String(d.footerText ?? ''))
        })
        .catch(() => { /* 组织标识还没输完/不存在：保持默认品牌即可 */ })
    }, 350)
    return () => { window.clearTimeout(timer); ctl.abort() }
  }, [tenantSlug])

  // 标题也跟着品牌走：只换图标与页眉、标题还写着厂商名，
  // 浏览器标签上就是"森莘创新的标 + NeuroDMS 的标题"，最容易被当成两个系统。
  useEffect(() => {
    const n = brandName.trim()
    document.title = (n || 'NeuroDMS') + ' · 登录'
  }, [brandName])
  const [username, setUser] = useState('')
  const [password, setPass] = useState('')
  const [mode, setMode] = useState<Mode>('local')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [hint, setHint] = useState('')

  // 手机验证码登录：只有该组织开通（档位 × 租户开关 × 通道就绪）时才出现入口。
  // 这个判断要在"输密码之前"完成，所以走公开的 /v1/auth/methods。
  const [smsReady, setSmsReady] = useState(false)
  const [bySms, setBySms] = useState(false)
  const [phone, setPhone] = useState('')
  const [smsCode, setSmsCode] = useState('')
  const [smsSent, setSmsSent] = useState('')
  const [countdown, setCountdown] = useState(0)

  // 二次验证：口令通过后服务端返回 202 + challenge，此时**没有任何令牌**。
  // 界面必须把用户停在"输验证码"这一步，不能有任何"已登录"的中间态。
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

  // 组织标识变化时重新探测"是否支持验证码登录"。
  // 350ms 防抖：组织标识是一个字母一个字母敲进去的，每敲一次都请求没有意义。
  useEffect(() => {
    const t = tenantSlug.trim()
    if (!t) {
      setSmsReady(false)
      setBySms(false)
      return
    }
    let alive = true
    const timer = window.setTimeout(() => {
      api<{ sms: boolean }>(`/v1/auth/methods?tenant=${encodeURIComponent(t)}`)
        .then((r) => {
          if (!alive) return
          setSmsReady(!!r.sms)
          // 关掉开关后停留在验证码模式会让人一直等收不到的短信，退回口令
          if (!r.sms) setBySms(false)
        })
        .catch(() => { if (alive) setSmsReady(false) })
    }, 350)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
  }, [tenantSlug])

  useEffect(() => {
    if (countdown <= 0) return
    const t = window.setTimeout(() => setCountdown((n) => n - 1), 1000)
    return () => window.clearTimeout(t)
  }, [countdown])

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

  async function sendSMSCode() {
    if (busy || countdown > 0) return
    if (!/^1[3-9]\d{9}$/.test(phone.replace(/[\s-]/g, ''))) {
      setError('请填写 11 位手机号')
      setHint('')
      return
    }
    setBusy(true)
    setError('')
    setHint('')
    try {
      const r = await api<{ sentTo: string; retryAfter: number }>('/v1/auth/sms/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account: phone }),
      })
      setSmsSent(r.sentTo || phone)
      setCountdown(r.retryAfter || 60)
    } catch (err) {
      if (err instanceof HttpError && err.code === 'SMS_RATE_LIMITED') {
        setCountdown(err.status === 429 ? 60 : 0)
      }
      showError(err, '验证码发送失败')
    } finally {
      setBusy(false)
    }
  }

  async function submitSMS(e: React.FormEvent) {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    setHint('')
    try {
      const data = await api<LoginResp>('/v1/auth/sms/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account: phone, code: smsCode }),
      })
      goAfterLogin(data.accessToken, data.refreshToken, tenantSlug)
    } catch (err) {
      if (err instanceof HttpError && err.code === 'SMS_CODE_INVALID') {
        setError('验证码不正确或已失效')
        setHint('码 5 分钟内有效；连续失败请重新获取。')
      } else if (err instanceof HttpError && err.code === 'SMS_NOT_CONFIGURED') {
        setError('该组织未开通短信登录')
        setHint('请改用账号口令登录，或联系管理员。')
      } else {
        showError(err, '登录失败')
      }
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
        <Aside productName={brandName} logoUrl={brandLogo} footerText={brandFooter} />
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
      <Aside productName={brandName} logoUrl={brandLogo} footerText={brandFooter} />
      <div className="login-card">
        <div className="login-inner">
          <div className="login-head">
            <span className="label">登录 / Sign in</span>
            <h2>进入文档中心</h2>
            <p>
              {bySms
                ? '用已登记的手机号接收验证码登录。手机号由管理员登记或本人在「账户 → 手机号」绑定。'
                : '用组织标识与账号登录。组织标识就是你们公司在这套系统里的短名，例如 demo。'}
            </p>
          </div>

          {smsReady && (
            <div className="seg" role="group" aria-label="登录方式" style={{ width: '100%', marginBottom: 14 }}>
              <button type="button" className={!bySms ? 'on' : ''} onClick={() => setBySms(false)} style={{ flex: 1 }}>
                账号口令
              </button>
              <button type="button" className={bySms ? 'on' : ''} onClick={() => setBySms(true)} style={{ flex: 1 }}>
                手机验证码
              </button>
            </div>
          )}

          {bySms ? (
            <form onSubmit={submitSMS}>
              <div className="field">
                <label htmlFor="phone">手机号</label>
                <input
                  id="phone"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="11 位手机号"
                  inputMode="numeric"
                  autoComplete="tel"
                  required
                />
              </div>

              <div className="field">
                <label htmlFor="sms-code">验证码</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    id="sms-code"
                    value={smsCode}
                    onChange={(e) => setSmsCode(e.target.value.replace(/\D/g, ''))}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    required
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    disabled={busy || countdown > 0}
                    onClick={() => void sendSMSCode()}
                    style={{ flex: 'none', minWidth: 108 }}
                  >
                    {countdown > 0 ? `${countdown}s` : '获取验证码'}
                  </button>
                </div>
                {smsSent && (
                  <div className="hint">
                    已发送至 <b style={{ color: 'var(--ink)' }}>{smsSent}</b>，5 分钟内有效。
                  </div>
                )}
              </div>

              {error && (
                <div className="err" role="alert">
                  <span className="ico"><Icon name="alert" size={15} /></span>
                  <span>{error}</span>
                </div>
              )}
              {hint && <div className="hint">{hint}</div>}

              <button className="primary lg" type="submit" disabled={busy || smsCode.length < 4}>
                {busy ? '登录中…' : '登录'}
              </button>

              <p className="login-note">
                只有已登记并验证手机号的账号能这样登录；收不到码时请改用账号口令，或联系管理员核对号码。
              </p>
            </form>
          ) : (
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
              {/* 口令一律掩码，不提供"显示"开关：
                  明文的截图/录屏/肩窥风险高于"看不见自己输了什么"的不便，
                  后者由需要设置口令时的二次输入兜底（docs/48）。 */}
              <input
                id="pass"
                type="password"
                value={password}
                onChange={(e) => setPass(e.target.value)}
                autoComplete="current-password"
                required
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
              />
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
          )}
        </div>
      </div>
    </div>
  )
}
