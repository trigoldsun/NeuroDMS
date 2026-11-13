import { useState } from 'react'
import { postJSON, HttpError } from '../api'

// 分享抽屉：外链创建 + 邮件发送。
//
// 为什么不再用 window.prompt：分享涉及"次数/有效期/口令/水印/邮箱验证/收件人"
// 六项配置，弹一次 prompt 只能问一项，用户根本不知道其他项是按什么默认值走的。

type Result = {
  shareId: string
  token: string
  shareUrl?: string
  mailQueued?: number
  mailWarning?: string
  mailSkipped?: string
  mailTo?: string[]
  approvalStatus?: string
  // 还有几个人能审批（服务端按空间 ACE 估算）。为 0 说明这条链接
  // 建出来也没人能批——要当场告诉发起人，否则他会一直等。
  approverCount?: number
}

// mailto 生成"用本机邮件客户端发送"的链接。
//
// 服务端没配 SMTP 时这是唯一可用的邮件通道；即使配了，也有人习惯用自己的邮箱发。
// 正文里同样不带口令——邮件与口令必须走两条通道。
function mailto(link: string, to: string[], hasPwd: boolean, name: string, hours: number, oneTime: boolean): string {
  const subject = `文件分享：${name}`
  const lines = [
    `我在 NeuroDMS 上分享了一个文件：${name}`,
    '',
    `打开链接：${link}`,
    `有效期：${hours > 0 ? `${hours} 小时` : '长期有效'}`,
    `访问次数：${oneTime ? '仅可打开 1 次' : '可重复打开'}`,
    `访问条件：${hasPwd ? '需要访问口令（我会另行告知）' : '无需口令'}`,
    '',
    '链接请勿转发。',
  ]
  return `mailto:${encodeURIComponent(to.join(','))}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(lines.join('\n'))}`
}

export default function ShareDrawer({
  target, onClose, onDone, canMail = true,
}: {
  target: { id: string; name: string }
  onClose: () => void
  onDone: (msg: string) => void
  // 当前档位是否支持邮件外发。false 时收件人输入禁用并给出说明，
  // 但链接分享仍然可用——基础版不能连分享都没有。
  canMail?: boolean
}) {
  const [password, setPassword] = useState('')
  const [emails, setEmails] = useState('')
  const [oneTime, setOneTime] = useState(true)
  const [hours, setHours] = useState(24)
  const [allowDownload, setAllowDownload] = useState(false)
  const [watermark, setWatermark] = useState(true)
  const [requireVerify, setRequireVerify] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState<Result | null>(null)

  const recipients = emails.split(/[\s,;，；]+/).map((s) => s.trim()).filter(Boolean)

  async function submit() {
    setBusy(true); setErr('')
    try {
      const data = await postJSON<Result>('/v1/shares', {
        objectType: 'node',
        objectId: target.id,
        maxUses: oneTime ? 1 : undefined,
        expiresInHours: hours > 0 ? hours : undefined,
        allowDownload,
        watermark,
        password: password || undefined,
        requireVerify,
        notifyEmails: recipients,
      })
      setDone(data)
      onDone(data.mailQueued ? `已生成链接并投递邮件（${data.mailQueued} 封）` : '链接已生成')
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '创建分享失败')
    } finally {
      setBusy(false)
    }
  }

  const link = done?.shareUrl || (done ? `${location.origin}/s/${done.token}` : '')

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer">
        <h2>分享「{target.name}」</h2>

        {done ? (
          <>
            {done.approvalStatus === 'pending' && (
              <div className="card pad" style={{ marginBottom: 10 }}>
                {/* 说清三件事：为什么进审批、谁批、去哪批。
                    只写"需审批"会让发起人卡在这里——他不知道该找谁，
                    而审批人也不知道有这件事。 */}
                <div style={{ fontWeight: 'bold', marginBottom: 4 }}>已提交审批，链接暂不可用</div>
                <div className="hint" style={{ lineHeight: 1.6 }}>
                  该文件密级达到租户设置的<strong>外发审批阈值</strong>，需要由<strong>对该文件有管理权限、且密级不低于该文件的人</strong>复核
                  （不能是发起人本人）。审批人可在「管理台 → 外发审批」处理；
                  通过后这条链接立即可用，无需重新创建。
                </div>
                {done.approverCount === 0 ? (
                  <div style={{ marginTop: 8, background: '#C6EE4B', borderRadius: 6, padding: '8px 10px', fontSize: 13, color: '#0A120E', lineHeight: 1.6 }}>
                    <strong>当前没有其他人能审批这个文件。</strong>
                    这个空间的权限可能只在你手里，或同事的密级不够。
                    请先到「文件 → 该空间 → 权限」给一位同事授予<strong>管理</strong>权限，否则这条链接会一直停在审批中。
                  </div>
                ) : (
                  typeof done.approverCount === 'number' && (
                    <div className="hint" style={{ marginTop: 6, fontSize: 12 }}>
                      当前有 {done.approverCount} 人可以审批。
                    </div>
                  )
                )}
              </div>
            )}
            <div className="hint">分享链接</div>
            <div style={{
              wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: 12.5,
              padding: 8, background: 'var(--bg-2)', borderRadius: 6, margin: '4px 0 10px',
            }}>{link}</div>

            {typeof done.mailQueued === 'number' && done.mailQueued > 0 && (
              <div className="hint">已向 {done.mailQueued} 位收件人投递邮件（后台队列发送，失败会自动重试）。</div>
            )}
            {done.mailWarning && <div className="error">{done.mailWarning}</div>}
            {done.mailSkipped && (
              <div className="hint" style={{ marginTop: 8 }}>
                {done.mailSkipped}，请用你自己的邮件客户端发送：
                <a
                  className="hint"
                  style={{ marginLeft: 6 }}
                  href={mailto(link, done.mailTo ?? [], password !== '', target.name, hours, oneTime)}
                >
                  用本机邮件客户端发送
                </a>
              </div>
            )}
            {!done.mailSkipped && (
              <div className="hint" style={{ marginTop: 8 }}>
                <a href={mailto(link, done.mailTo ?? recipients, password !== '', target.name, hours, oneTime)}>
                  改用本机邮件客户端发送
                </a>
              </div>
            )}
            {password && (
              <div className="hint" style={{ marginTop: 8 }}>
                邮件中<strong>不包含</strong>访问口令，请通过另一条通道告知对方。
              </div>
            )}

            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="primary" onClick={() => { void navigator.clipboard.writeText(link).then(() => onDone('链接已复制')).catch(() => undefined) }}>
                复制链接
              </button>
              <button className="ghost" onClick={onClose}>关闭</button>
            </div>
          </>
        ) : (
          <>
            <div className="field">
              <label htmlFor="sh-emails">通过邮件发送给（可留空，多个用逗号分隔）</label>
              <textarea
                id="sh-emails" rows={2} value={emails} onChange={(e) => setEmails(e.target.value)}
                placeholder="alice@example.com, bob@example.com"
                disabled={!canMail}
              />
              <span className="hint">
                {canMail
                  ? '最多 10 个；邮件里只含链接，不含口令。'
                  : '当前档位不支持由服务器代发邮件；链接仍可照常创建，复制后自行发送。'}
              </span>
            </div>

            <div className="field">
              <label htmlFor="sh-pwd">访问口令（可留空）</label>
              <input id="sh-pwd" type="text" value={password} onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password" placeholder="留空表示无口令" />
            </div>

            <div className="field">
              <label>访问次数</label>
              <select value={oneTime ? '1' : '0'} onChange={(e) => setOneTime(e.target.value === '1')}>
                <option value="1">一次性（打开 1 次后失效）</option>
                <option value="0">可重复打开</option>
              </select>
            </div>

            <div className="field">
              <label htmlFor="sh-hours">有效期（小时，0 = 长期）</label>
              <input id="sh-hours" type="number" min={0} value={hours}
                onChange={(e) => setHours(Number(e.target.value))} />
            </div>

            <label style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '6px 0' }}>
              <input type="checkbox" checked={allowDownload} onChange={(e) => setAllowDownload(e.target.checked)} />
              <span>允许下载原件</span>
            </label>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '6px 0' }}>
              <input type="checkbox" checked={watermark} onChange={(e) => setWatermark(e.target.checked)} />
              <span>预览叠加溯源水印</span>
            </label>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '6px 0' }}>
              <input type="checkbox" checked={requireVerify} onChange={(e) => setRequireVerify(e.target.checked)} />
              <span>要求邮箱验证（收件人会用其邮箱接收验证码）</span>
            </label>

            {err && <div className="error" role="alert">{err}</div>}
            <button className="primary" onClick={() => void submit()} disabled={busy} style={{ width: '100%', marginTop: 8 }}>
              {busy ? '正在创建…' : recipients.length > 0 ? '创建链接并发送邮件' : '创建链接'}
            </button>
          </>
        )}

        <div style={{ marginTop: 'auto' }}>
          <button onClick={onClose}>关闭</button>
        </div>
      </aside>
    </>
  )
}
