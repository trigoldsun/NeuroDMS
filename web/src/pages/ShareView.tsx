import { useCallback, useEffect, useState } from 'react'
import { Icon, Mark } from '../components/ui'

// 对外分享页：免登录。
//
// 两段式：链接 token 先换 5 分钟票据（ticket），之后所有取字节都只认票据。
// 这样做的好处是 —— 链接可以随时撤销，撤销后票据同时失效；
// 而且票据与来源网段绑定，链接被转发到别的网络也用不了。

type ShareInfo = {
  shareId: string
  objectType: string
  objectId: string
  allowDownload: boolean
  watermark: boolean
  oneTime: boolean
  ticket: string
  expiresIn: number
}

type TicketInfo = {
  objectType: string
  allowDownload: boolean
  watermark: boolean
  expiresAt: string
  name?: string
  size?: number
  mime?: string
}

type TicketNode = { id: string; kind: string; name: string; size: number; mime: string }

type Phase = 'loading' | 'password' | 'wrong-password' | 'locked' | 'verify' | 'gone' | 'error' | 'ready'

// 浏览器能直接渲染的类型白名单；其余一律不塞进 iframe（塞了就是一片空白）
function isRenderable(type: string): boolean {
  return type === 'application/pdf' || type.startsWith('image/') ||
    type.startsWith('video/') || type.startsWith('audio/') || type.startsWith('text/')
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

export default function ShareView({ token }: { token: string }) {
  const [phase, setPhase] = useState<Phase>('loading')
  const [info, setInfo] = useState<ShareInfo | null>(null)
  const [ticket, setTicket] = useState<TicketInfo | null>(null)
  const [nodes, setNodes] = useState<TicketNode[]>([])
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState('')
  const [contentUrl, setContentUrl] = useState('')
  const [contentType, setContentType] = useState('')
  const [textBody, setTextBody] = useState('')
  // PDF 缩放：默认 100%（与站内预览一致）。
  // 宽表按 FitH 会被压到 ~24%，访客容易以为文件坏了；原尺寸起步更接近"打开文件"的直觉。
  const [zoom, setZoom] = useState<'fit' | 50 | 75 | 100>(100)
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [codeSent, setCodeSent] = useState(false)

  // 拿到票据后加载首屏：对象名、目录列表，最后进入 ready。
  // 兑换与"验证后兑换"返回的是同一种载荷，所以这段必须共用，
  // 否则两条路径迟早会漂移成"验证过的那个才能看到目录"。
  const openWith = useCallback(async (data: ShareInfo) => {
    setInfo(data)

    const tResp = await fetch(`/v1/public/tickets/${encodeURIComponent(data.ticket)}`)
    if (tResp.ok) {
      const tBody = await tResp.json()
      setTicket(tBody.data as TicketInfo)
    }

    if (data.objectType === 'space') {
      const lResp = await fetch(`/v1/public/tickets/${encodeURIComponent(data.ticket)}/nodes`)
      if (lResp.ok) {
        const lBody = await lResp.json()
        setNodes((lBody.data?.items ?? []) as TicketNode[])
      }
    }
    setPhase('ready')
  }, [])

  const redeem = useCallback(async (pwd?: string) => {
    setPhase('loading')
    const headers: Record<string, string> = {}
    if (pwd) headers['X-Share-Password'] = pwd
    try {
      const resp = await fetch(`/v1/public/shares/${encodeURIComponent(token)}`, { headers })
      const body = await resp.json().catch(() => ({}))
      const code = body?.code as string | undefined

      if (resp.status === 410) return setPhase('gone')
      if (resp.status === 411 || code === 'PASSWORD_REQUIRED') return setPhase('password')
      // 428 = 口令已通过，但该链接还要求邮箱验证（服务端强制，不是前端能跳过的）
      if (resp.status === 428 || code === 'VERIFY_REQUIRED') return setPhase('verify')
      if (resp.status === 403 && code === 'PASSWORD_WRONG') {
        setMsg('口令不正确')
        return setPhase('wrong-password')
      }
      if (resp.status === 429 || code === 'LINK_LOCKED') {
        setMsg(body?.message ?? '口令错误次数过多，请稍后再试')
        return setPhase('locked')
      }
      if (!resp.ok) {
        setMsg(body?.message ?? '链接暂不可用')
        return setPhase('error')
      }

      await openWith(body.data as ShareInfo)
    } catch {
      setMsg('网络异常，请稍后重试')
      setPhase('error')
    }
  }, [token, openWith])

  useEffect(() => { void redeem() }, [redeem])

  async function requestCode() {
    setMsg('')
    try {
      const resp = await fetch(`/v1/public/shares/${encodeURIComponent(token)}/verify/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      const body = await resp.json().catch(() => ({}))
      if (!resp.ok) {
        setMsg(body?.message ?? '验证码发送失败')
        return
      }
      setCodeSent(true)
      setMsg(`验证码已发送至 ${body?.data?.sentTo ?? email}`)
    } catch {
      setMsg('网络异常，请稍后重试')
    }
  }

  async function confirmCode() {
    setMsg('')
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      // 口令与验证是两道独立关卡：验证请求也要带上口令，否则服务端仍会 411
      if (password) headers['X-Share-Password'] = password
      const resp = await fetch(`/v1/public/shares/${encodeURIComponent(token)}/verify/confirm`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email, code }),
      })
      const body = await resp.json().catch(() => ({}))
      if (resp.status === 411 || body?.code === 'PASSWORD_REQUIRED') return setPhase('password')
      if (!resp.ok) {
        setMsg(body?.message ?? '验证码不正确或已失效')
        return
      }
      await openWith(body.data as ShareInfo)
    } catch {
      setMsg('网络异常，请稍后重试')
    }
  }

  async function loadContent(asDownload: boolean) {
    if (!info) return
    // 服务端用 inline=1 区分"在线查看"与"下载"：
    // 无参数视为下载请求，仅预览的分享会被 403。
    const path = `/v1/public/tickets/${encodeURIComponent(info.ticket)}/content${asDownload ? '?download=1' : '?inline=1'}`
    const resp = await fetch(path)
    if (!resp.ok) {
      // 服务端会给出可读原因（未启用转换 / 过大 / 无权限），原样展示比"读取失败"有用
      const body = await resp.json().catch(() => ({}))
      setMsg(resp.status === 403
        ? '该分享不允许下载'
        : (body?.message ?? '内容读取失败，请稍后重试或联系分享人'))
      return
    }
    if (asDownload) {
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = ticket?.name ?? 'download'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      return
    }
    const type = resp.headers.get('Content-Type') ?? ''
    if (type.startsWith('text/') || type === 'application/json') {
      setTextBody(await resp.text())
      setContentType(type)
      setContentUrl('')
      return
    }
    const blob = await resp.blob()
    setContentUrl(URL.createObjectURL(blob))
    setContentType(type)
    if (!isRenderable(type)) {
      // 服务端已经尽力转换（Office→PDF）；到这里说明是浏览器确实渲染不了的类型。
      // 明确告知 + 给出下载出口，而不是留一个点了没反应的按钮。
      setMsg('该类型无法在浏览器内直接查看' + (ticket?.allowDownload ? '，请使用下方「下载」' : '，请联系分享人开启下载'))
    }
  }

  function renderBody() {
    if (!ticket) return null
    if (ticket.objectType === 'space') {
      return (
        <div className="card" style={{ padding: 0 }}>
          {nodes.length === 0 ? (
            <div className="empty">该分享下暂无可浏览的文件</div>
          ) : (
            <table>
              <thead><tr><th>名称</th><th style={{ width: 110 }}>大小</th></tr></thead>
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.id}>
                    <td className="name">{n.kind === 'folder' ? `${n.name}/` : n.name}</td>
                    <td>{n.kind === 'folder' ? '—' : fmtSize(n.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )
    }

    return (
      <>
        <div className="card" style={{ padding: 12 }}>
          <div style={{ fontWeight: 600 }}>{ticket.name}</div>
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>
            {fmtSize(ticket.size ?? 0)} · {ticket.mime || '未知类型'}
            {ticket.watermark ? ' · 已开启水印' : ''}
          </div>
        </div>

        {contentUrl && contentType.startsWith('image/') && (
          <img src={contentUrl} alt={ticket.name} style={{ maxWidth: '100%', borderRadius: 8 }} />
        )}
        {contentUrl && contentType === 'application/pdf' && (
          <>
            <div className="seg" role="group" aria-label="缩放" style={{ alignSelf: 'flex-start' }}>
              {([50, 75, 100, 'fit'] as const).map((z) => (
                <button key={String(z)} className={zoom === z ? 'on' : ''} onClick={() => setZoom(z)}>
                  {z === 'fit' ? '适应宽度' : `${z}%`}
                </button>
              ))}
            </div>
            {/* key 用缩放值：片段变化不会让 PDF 重新按新比例打开 */}
            <iframe
              key={String(zoom)}
              title="预览"
              src={`${contentUrl}#${zoom === 'fit' ? 'view=FitH' : `zoom=${zoom}`}`}
              style={{ width: '100%', height: '74vh', minHeight: 420, border: 0 }}
            />
          </>
        )}
        {contentUrl && (contentType.startsWith('video/') || contentType.startsWith('audio/')) && (
          contentType.startsWith('video/')
            ? <video src={contentUrl} controls style={{ width: '100%' }} />
            : <audio src={contentUrl} controls style={{ width: '100%' }} />
        )}
        {textBody && (
          <pre className="preview-text">{textBody}</pre>
        )}
        {!contentUrl && !textBody && !msg && (
          <p style={{ color: 'var(--muted)', fontSize: 13 }}>
            点击「在线查看」加载内容。Office 文档会先转换成 PDF 再显示，可能需要几秒。
          </p>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => loadContent(false)}>在线查看</button>
          {ticket.allowDownload && <button onClick={() => loadContent(true)}>下载</button>}
        </div>
      </>
    )
  }

  const wide = !!(contentUrl || textBody || (phase === 'ready' && info))

  return (
    <div className="share-wrap">
      <header className="share-head">
        <Mark size={26} />
        <div>
          <b>NeuroDMS</b>
          <span>安全分享</span>
        </div>
        <div className="grow" />
        <span className="share-badge"><Icon name="shield" size={13} /> 访问全程留痕</span>
      </header>

      <main className={`share-card${wide ? ' wide' : ''}`}>
        {phase === 'loading' && (
          <div className="share-state">
            <div className="spinner" />
            <div style={{ fontWeight: 500, color: 'var(--ink)' }}>正在打开链接…</div>
            <div className="hint">链接有效性与访问条件由服务端校验，任何拒绝都会写明原因。</div>
          </div>
        )}

        {(phase === 'password' || phase === 'wrong-password') && (
          <form className="share-form" onSubmit={(e) => { e.preventDefault(); void redeem(password) }}>
            <div className="share-state" style={{ padding: 0, alignItems: 'flex-start', textAlign: 'left' }}>
              <span className="label">需要口令</span>
              <h1>这条链接受口令保护</h1>
              <p className="hint" style={{ margin: 0 }}>
                请输入分享人通过<b>另一条通道</b>告诉你的口令。口令不会写进分享邮件里。
              </p>
            </div>
            <div className="field">
              <label htmlFor="share-pass">访问口令</label>
              <input id="share-pass" type="password" value={password}
                onChange={(e) => setPassword(e.target.value)} autoComplete="off" required autoFocus />
            </div>
            {phase === 'wrong-password' && (
              <div className="banner danger">
                <span className="ico"><Icon name="alert" size={15} /></span>
                <span>{msg || '口令不正确'}　连续错误会临时锁定，请确认后重试。</span>
              </div>
            )}
            <button className="primary lg" type="submit">打开</button>
          </form>
        )}

        {phase === 'verify' && (
          <form className="share-form" onSubmit={(e) => { e.preventDefault(); void (codeSent ? confirmCode() : requestCode()) }}>
            <div className="share-state" style={{ padding: 0, alignItems: 'flex-start', textAlign: 'left' }}>
              <span className="label">邮箱验证</span>
              <h1>先验证你的邮箱</h1>
              <p className="hint" style={{ margin: 0 }}>
                分享人开启了邮箱验证：验证码会发到你填写的邮箱，用于确认"是谁在查看"。
              </p>
            </div>
            <div className="field">
              <label htmlFor="share-email">邮箱</label>
              <input id="share-email" type="email" value={email} readOnly={codeSent}
                onChange={(e) => setEmail(e.target.value)} autoComplete="email" required autoFocus />
            </div>
            {codeSent && (
              <div className="field">
                <label htmlFor="share-code">验证码</label>
                <input id="share-code" type="text" inputMode="numeric" value={code}
                  onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" required autoFocus />
              </div>
            )}
            {msg && <div className={codeSent ? 'banner danger' : 'banner'}>{msg}</div>}
            <button className="primary lg" type="submit">{codeSent ? '验证并打开' : '发送验证码'}</button>
          </form>
        )}

        {phase === 'locked' && (
          <div className="share-state">
            <div className="empty-art"><Icon name="lock" size={26} /></div>
            <h1>链接已临时锁定</h1>
            <p className="hint" style={{ maxWidth: '42ch' }}>{msg}</p>
            <p className="hint">口令连续错误会按来源锁定一段时间；请稍后重试，或联系分享人重新发送。</p>
          </div>
        )}

        {phase === 'gone' && (
          <div className="share-state">
            <div className="empty-art"><Icon name="alert" size={26} /></div>
            <h1>链接不可用</h1>
            <p className="hint" style={{ maxWidth: '44ch' }}>
              该链接可能已过期、已被使用或已被分享人撤销。请联系分享人重新获取。
            </p>
          </div>
        )}

        {phase === 'error' && (
          <div className="share-state">
            <div className="empty-art"><Icon name="alert" size={26} /></div>
            <h1>打开失败</h1>
            <p className="hint" style={{ maxWidth: '44ch' }}>{msg || '请稍后重试。'}</p>
          </div>
        )}

        {phase === 'ready' && info && (
          <>
            {info.oneTime && (
              <div className="banner warn" style={{ margin: '0 0 10px' }}>
                <span className="ico"><Icon name="alert" size={15} /></span>
                <span>这是一次性链接，本次打开后即失效。</span>
              </div>
            )}
            {renderBody()}
            {msg && <div className="banner danger" style={{ marginTop: 10 }}>{msg}</div>}
          </>
        )}
      </main>

      <footer className="share-foot">
        <span><Icon name="lock" size={12} /> 本次访问的来源、时间与操作已记录</span>
        <div className="grow" />
        <span className="dim">由 NeuroDMS 提供 · 森莘科创</span>
      </footer>
    </div>
  )
}
