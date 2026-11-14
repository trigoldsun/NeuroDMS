import { useCallback, useEffect, useState } from 'react'
import { api, postJSON, HttpError } from '../api'

// 分享抽屉：外链创建 + 邮件发送 + 审批人选择。
//
// 为什么不再用 window.prompt：分享涉及"次数/有效期/口令/水印/邮箱验证/收件人"
// 六项配置，弹一次 prompt 只能问一项，用户根本不知道其他项是按什么默认值走的。
// 审批人同理：只在提交后报"需要审批"没有意义，必须在填写时就把人选定下来。

type Approver = {
  id: string
  name: string
  username: string
  isOwner: boolean
  roles?: string[]
  classification: number
  eligible: boolean
}

type Plan = {
  requireApproval: boolean
  reason: string
  objectClass: number
  minClass: number
  twoLayer: boolean
  approvers: Approver[]
  owners: Approver[]
  creatorIsOwner: boolean
  ownerLayerSkipped?: string
  truncated?: boolean
}

type Result = {
  shareId: string
  token: string
  shareUrl?: string
  mailQueued?: number
  mailWarning?: string
  mailSkipped?: string
  mailTo?: string[]
  approvalStatus?: string
  approvalStage?: string
  approverCount?: number
  approver?: Approver
  ownerApprover?: Approver
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

function approverLabel(a: Approver): string {
  const tags: string[] = []
  if (a.isOwner) tags.push('空间所有者')
  if (a.roles && a.roles.length > 0) tags.push(a.roles.join('/'))
  return tags.length > 0 ? `${a.name}（${tags.join(' · ')}）` : a.name
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

  const [plan, setPlan] = useState<Plan | null>(null)
  const [planErr, setPlanErr] = useState('')
  const [approverId, setApproverId] = useState('')
  const [ownerApproverId, setOwnerApproverId] = useState('')

  const recipients = emails.split(/[\s,;，；]+/).map((s) => s.trim()).filter(Boolean)

  const loadPlan = useCallback(async () => {
    setPlanErr('')
    try {
      const d = await api<Plan>(`/v1/shares/approvers?objectType=node&objectId=${encodeURIComponent(target.id)}`)
      setPlan(d)
    } catch (e) {
      setPlanErr(e instanceof HttpError ? e.message : '读取审批要求失败')
    }
  }, [target.id])

  useEffect(() => { void loadPlan() }, [loadPlan])

  const chosen = plan?.approvers.find((a) => a.id === approverId)
  const ownerChoices = (plan?.owners ?? []).filter((o) => o.eligible)

  // 第二层是否需要：只有 5/6 级、且第一层审批人不是所有者时才需要。
  // 发起人本人是所有者时跳过——要求他审批自己会变成死循环。
  const needOwner = !!plan?.requireApproval
    && !!plan?.twoLayer
    && !!chosen
    && !chosen.isOwner
    && plan.ownerLayerSkipped !== 'requester_is_owner'
  const noOwnerAvailable = needOwner && ownerChoices.length === 0

  // 只有一个所有者时直接定下来，避免多一次无意义的选择；
  // 有多个时才让发起人挑（需求里的"弹出选择"）。
  useEffect(() => {
    if (needOwner && ownerChoices.length === 1) {
      setOwnerApproverId(ownerChoices[0].id)
    }
  }, [needOwner, ownerChoices.length, ownerChoices[0]?.id])

  const approvalBlocked = !!plan?.requireApproval && (
    plan.approvers.length === 0 ||
    !approverId ||
    noOwnerAvailable ||
    (needOwner && !ownerApproverId)
  )

  async function submit() {
    setBusy(true); setErr('')
    try {
      const payload: Record<string, unknown> = {
        objectType: 'node',
        objectId: target.id,
        maxUses: oneTime ? 1 : undefined,
        expiresInHours: hours > 0 ? hours : undefined,
        allowDownload,
        watermark,
        password: password || undefined,
        requireVerify,
        notifyEmails: recipients,
      }
      if (plan?.requireApproval) {
        payload.approverId = approverId
        if (needOwner && ownerApproverId) payload.ownerApproverId = ownerApproverId
      }
      const data = await postJSON<Result>('/v1/shares', payload)
      setDone(data)
      onDone(data.approvalStatus === 'pending' ? '已提交审批' : (data.mailQueued ? `已生成链接并投递邮件（${data.mailQueued} 封）` : '链接已生成'))
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
                  该文件密级达到租户设置的<strong>外发审批阈值</strong>，需要复核后才能使用。
                </div>
                <div className="hint" style={{ lineHeight: 1.7, marginTop: 6 }}>
                  <div>第一层审批人：<b style={{ color: 'var(--ink)' }}>{done.approver?.name || '—'}</b></div>
                  {done.ownerApprover && (
                    <div>
                      第二层空间所有者：<b style={{ color: 'var(--ink)' }}>{done.ownerApprover.name}</b>
                      （第一层通过后才会轮到他）
                    </div>
                  )}
                  <div style={{ marginTop: 4 }}>
                    被指定的审批人登录后会在「待我审批」看到这条记录。
                    {done.ownerApprover
                      ? '两层都通过后链接才可用，无需重新创建。'
                      : '通过后链接立即可用，无需重新创建。'}
                  </div>
                </div>
                {done.approverCount === 0 ? (
                  <div style={{ marginTop: 8, background: '#C6EE4B', borderRadius: 6, padding: '8px 10px', fontSize: 13, color: '#0A120E', lineHeight: 1.6 }}>
                    <strong>当前没有其他人能审批这个文件。</strong>
                    请先到「文件 → 该空间 → 权限」给一位同事授予<strong>管理</strong>权限，否则这条链接会一直停在审批中。
                  </div>
                ) : null}
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
            {planErr && (
              <div className="banner danger" style={{ marginBottom: 10 }}>
                <span className="ico">!</span>
                <span>{planErr}。为避免建出无人可批的链接，请重新加载后再试。</span>
                <button className="sm" onClick={() => void loadPlan()}>重试</button>
              </div>
            )}

            {plan?.requireApproval && (
              <div className="card pad" style={{ marginBottom: 10 }}>
                <div style={{ fontWeight: 'bold', marginBottom: 6 }}>
                  需要审批（文件密级 {plan.objectClass} ≥ 阈值 {plan.minClass}）
                </div>
                {plan.approvers.length === 0 ? (
                  <div className="banner danger" style={{ margin: 0 }}>
                    <span className="ico">!</span>
                    <span>
                      没有其他人能审批这份文件。请先给同事授予该文件或空间的<strong>管理</strong>权限，
                      并确保其密级不低于 {plan.objectClass}。
                    </span>
                  </div>
                ) : (
                  <>
                    <div className="field" style={{ marginBottom: 8 }}>
                      <label htmlFor="sh-approver">第一层审批人（必选）</label>
                      <select
                        id="sh-approver"
                        value={approverId}
                        onChange={(e) => { setApproverId(e.target.value); setOwnerApproverId('') }}
                      >
                        <option value="">请选择审批人</option>
                        {plan.approvers.map((a) => (
                          <option key={a.id} value={a.id}>{approverLabel(a)}</option>
                        ))}
                      </select>
                      <span className="hint">
                        名单只包含「对该文件有管理权限、密级不低于 {plan.objectClass}、且不是你本人」的人。
                        {plan.truncated && ' 人数过多，仅显示前 500 人。'}
                      </span>
                    </div>

                    {plan.twoLayer && (
                      <div className="banner warn" style={{ margin: '8px 0' }}>
                        <span className="ico">!</span>
                        <span>
                          这是 <strong>{plan.objectClass} 级（最高两级之一）</strong>文件外发。
                          若第一层审批人不是文件所在空间的拥有者，还需要该空间拥有者再确认一次。
                        </span>
                      </div>
                    )}

                    {chosen?.isOwner && (
                      <div className="hint" style={{ marginBottom: 6 }}>
                        所选审批人就是空间所有者，本次只需一层审批。
                      </div>
                    )}

                    {needOwner && (
                      <div className="field">
                        <label htmlFor="sh-owner-approver">第二层：空间所有者确认（必选）</label>
                        {noOwnerAvailable ? (
                          <div className="banner danger" style={{ margin: 0 }}>
                            <span className="ico">!</span>
                            <span>
                              当前没有密级足够的空间所有者可确认。请先提高所有者密级，
                              或把第一层审批人改为空间所有者本人。
                            </span>
                          </div>
                        ) : ownerChoices.length === 1 ? (
                          <div className="hint" style={{ padding: '7px 9px', background: 'var(--surface-2)', borderRadius: 6 }}>
                            {ownerChoices[0].name}（空间所有者）
                          </div>
                        ) : (
                          <select
                            id="sh-owner-approver"
                            value={ownerApproverId}
                            onChange={(e) => setOwnerApproverId(e.target.value)}
                          >
                            <option value="">请选择空间所有者</option>
                            {ownerChoices.map((o) => (
                              <option key={o.id} value={o.id}>{o.name}</option>
                            ))}
                          </select>
                        )}
                        <span className="hint">
                          该空间有多个拥有者，请选择一位；两层会依次流转，第一层通过后才轮到所有者。
                        </span>
                      </div>
                    )}

                    {plan.creatorIsOwner && plan.ownerLayerSkipped === 'requester_is_owner' && plan.twoLayer && (
                      <div className="hint">
                        你是该空间的所有者：本次发起即视为所有者已知悉，不再要求你审批自己。
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

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
            <button
              className="primary"
              onClick={() => void submit()}
              disabled={busy || !!planErr || approvalBlocked}
              style={{ width: '100%', marginTop: 8 }}
            >
              {busy ? '正在创建…'
                : plan?.requireApproval ? '提交审批并生成链接'
                  : recipients.length > 0 ? '创建链接并发送邮件' : '创建链接'}
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
