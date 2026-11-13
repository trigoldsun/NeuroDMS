import { useCallback, useEffect, useMemo, useState } from 'react'
import { Dialog, Icon, Menu } from '../components/ui'
import { api, del, HttpError, postJSON } from '../api'
import { navigate } from '../router'

// 成员（账号）管理。
//
// 与服务端的分工：界面上隐藏按钮只是"少犯错"，真正的拒绝都在服务端
// （建号要求系统管理员、不能给自己加角色、不能授出高于自己的封顶…）。
// 因此这里对 4xx 一律把 message 原样显示——那些 message 本身就是给人看的。

export type RoleDef = { code: string; name: string; description: string }

// 名下空间（服务端 409 返回）：只够渲染清单，不含内容。
type OwnedSpaceLite = { id: string; name: string; granted: number; onlyMine: boolean; classification: number }

type Member = {
  id: string
  username: string
  email: string
  displayName: string
  principalType: 'internal' | 'external'
  source: string
  status: 'active' | 'suspended' | 'invited'
  deptId: string
  deptName: string
  classification: number
  ceiling: number
  mfaRequired: boolean
  expiresAt: string | null
  lastLoginAt: string | null
  createdAt: string
  roles: string[]
  canLogin: boolean
}

type Dept = { id: string; name: string }

const statusText: Record<string, string> = {
  active: '正常',
  suspended: '已停用',
  invited: '待激活',
}

// 与后端 internal/classification 的内置名称保持一致（等级语义固定，租户只能改名）
const levelText = ['公开', '内部', '敏感', '秘密', '机密', '绝密', '核心']

function fmtTime(s: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export default function Members({ roles, meId }: { roles: RoleDef[]; meId: string }) {
  const [items, setItems] = useState<Member[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [depts, setDepts] = useState<Dept[]>([])
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [toast, setToast] = useState('')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<Member | null>(null)
  const [pwTarget, setPwTarget] = useState<Member | null>(null)
  const [blocked, setBlocked] = useState<{ member: Member; spaces: OwnedSpaceLite[] } | null>(null)

  const flash = useCallback((m: string) => {
    setToast(m)
    window.setTimeout(() => setToast(''), 2400)
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const params = new URLSearchParams()
      if (q.trim()) params.set('q', q.trim())
      if (status) params.set('status', status)
      params.set('limit', '100')
      const d = await api<{ items: Member[]; total: number }>(`/v1/admin/members?${params.toString()}`)
      setItems(d.items ?? [])
      setTotal(d.total ?? 0)
      const dd = await api<{ items: Dept[] }>('/v1/admin/depts')
      setDepts(dd.items ?? [])
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '加载失败')
    } finally {
      setLoading(false)
    }
  }, [q, status])

  useEffect(() => { void load() }, [load])

  // blockedBy 取出服务端附带的"名下空间"清单。
  //
  // 服务端回 409 + data.spaces，而不是只回一句话：操作者需要看到具体是哪几个空间，
  // 否则"请先移交"这四个字完全没有可执行性。
  function blockedBy(e: unknown): OwnedSpaceLite[] | null {
    if (!(e instanceof HttpError) || e.code !== 'OWNS_SPACES') return null
    const d = e.data as { spaces?: OwnedSpaceLite[] } | undefined
    return d?.spaces ?? []
  }

  async function setMemberStatus(m: Member, next: 'active' | 'suspended') {
    const word = next === 'active' ? '启用' : '停用'
    if (next === 'suspended' && !window.confirm(`停用「${m.displayName || m.username}」？\n\n该账号已登录的会话会被立即吊销。`)) return
    try {
      await postJSON(`/v1/admin/members/${m.id}/status`, { status: next })
      flash(`已${word}`)
      await load()
    } catch (e) {
      const spaces = blockedBy(e)
      if (spaces) { setBlocked({ member: m, spaces }); return }
      flash(e instanceof HttpError ? e.message : `${word}失败`)
    }
  }

  async function grantRole(m: Member, code: string) {
    try {
      const d = await postJSON<{ roles: string[] }>(`/v1/admin/members/${m.id}/roles`, { code })
      setItems((list) => list.map((x) => (x.id === m.id ? { ...x, roles: d.roles ?? [] } : x)))
      flash('角色已授予')
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '授予失败')
    }
  }

  async function revokeRole(m: Member, code: string) {
    if (!window.confirm(`撤销「${m.displayName || m.username}」的角色 ${code}？`)) return
    try {
      const d = await del<{ roles: string[] }>(`/v1/admin/members/${m.id}/roles/${code}`)
      setItems((list) => list.map((x) => (x.id === m.id ? { ...x, roles: d.roles ?? [] } : x)))
      flash('角色已撤销')
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '撤销失败')
    }
  }

  async function removeMember(m: Member) {
    if (!window.confirm(`删除「${m.displayName || m.username}」？\n\n逻辑删除：账号立即不可登录，审计记录保留。`)) return
    try {
      await del(`/v1/admin/members/${m.id}`)
      flash('已删除')
      await load()
    } catch (e) {
      const spaces = blockedBy(e)
      if (spaces) { setBlocked({ member: m, spaces }); return }
      flash(e instanceof HttpError ? e.message : '删除失败')
    }
  }

  const missingRoles = useMemo(() => {
    return (m: Member) => roles.filter((r) => !m.roles.includes(r.code))
  }, [roles])

  return (
    <div style={{ padding: 14 }}>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <input
          placeholder="搜索用户名 / 姓名 / 邮箱"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ width: 240 }}
        />
        <div className="seg">
          {[['', '全部'], ['active', '正常'], ['suspended', '已停用']].map(([v, label]) => (
            <button key={v} className={status === v ? 'on' : ''} onClick={() => setStatus(v)}>{label}</button>
          ))}
        </div>
        <span className="hint">共 {total} 人</span>
        <div className="spacer" />
        <button className="primary" onClick={() => setCreating(true)}>新建成员</button>
      </div>

      {err && <div className="card pad error" style={{ marginBottom: 10 }}>{err}</div>}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>成员</th>
              <th style={{ width: 90 }}>状态</th>
              <th style={{ width: 220 }}>角色</th>
              <th style={{ width: 130 }}>部门</th>
              <th style={{ width: 110 }}>密级 / 封顶</th>
              <th style={{ width: 130 }}>最近登录</th>
              <th className="actions">操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.id}>
                <td className="name">
                  {m.displayName || m.username}
                  <span className="code" style={{ marginLeft: 8 }}>{m.username}</span>
                  {m.principalType === 'external' && <span className="badge warn" style={{ marginLeft: 6 }}>外部</span>}
                  {m.mfaRequired && <span className="badge plain" style={{ marginLeft: 4 }}>二次验证</span>}
                  {m.email && <div className="hint">{m.email}</div>}
                </td>
                <td>
                  <span className={`badge ${m.status === 'active' ? 'ok' : 'error'}`}>
                    {statusText[m.status] ?? m.status}
                  </span>
                  {m.status === 'active' && !m.canLogin && <div className="hint">已过期</div>}
                </td>
                <td>
                  {m.roles.length === 0 && <span className="hint">普通成员</span>}
                  {m.roles.map((c) => (
                    <button
                      key={c}
                      className="badge plain"
                      style={{
                        marginRight: 4,
                        cursor: m.id === meId ? 'not-allowed' : 'pointer',
                        border: '1px solid var(--line)',
                        opacity: m.id === meId ? 0.5 : 1,
                      }}
                      title={m.id === meId ? '不能修改自己的角色' : '点击撤销'}
                      disabled={m.id === meId}
                      onClick={() => void revokeRole(m, c)}
                    >{c} ×</button>
                  ))}
                </td>
                <td>{m.deptName || <span className="hint">—</span>}</td>
                <td className="tnum">{levelText[m.classification] ?? m.classification} / {m.ceiling}</td>
                <td className="hint">{fmtTime(m.lastLoginAt)}</td>
                <td className="actions">
                  <button className="sm" onClick={() => setEditing(m)}>编辑</button>
                  <Menu
                    label={`${m.displayName || m.username} 的更多操作`}
                    items={[
                      ...(m.id !== meId && missingRoles(m).length > 0
                        ? [
                          ...missingRoles(m).map((r) => {
                            // 三权分立：审计管理员不能与系统/安全管理员并存。
                            // 服务端会拒绝，但让点击前就知道原因，比点了再看 403 好。
                            const conflict =
                              (r.code === 'auditor' && (m.roles.includes('sysadmin') || m.roles.includes('secadmin'))) ||
                              ((r.code === 'sysadmin' || r.code === 'secadmin') && m.roles.includes('auditor'))
                            return {
                              label: `授予「${r.name}」`,
                              icon: 'shield',
                              disabled: conflict,
                              hint: conflict ? '与现有角色冲突（三权分立）' : undefined,
                              onClick: () => void grantRole(m, r.code),
                            }
                          }),
                          { sep: true, label: 'sep' },
                        ]
                        : []),
                      { label: '重置口令', icon: 'key', onClick: () => setPwTarget(m) },
                      m.status === 'active'
                        ? {
                          label: '停用账号',
                          icon: 'lock',
                          danger: true,
                          hint: m.id === meId ? '不能停用自己' : undefined,
                          onClick: () => { if (m.id !== meId) void setMemberStatus(m, 'suspended') },
                        }
                        : { label: '启用账号', icon: 'check', onClick: () => void setMemberStatus(m, 'active') },
                      { sep: true, label: 'sep' },
                      {
                        label: '删除成员',
                        icon: 'trash',
                        danger: true,
                        hint: m.id === meId ? '不能删除自己' : undefined,
                        onClick: () => { if (m.id !== meId) void removeMember(m) },
                      },
                    ]}
                  />
                </td>
              </tr>
            ))}
            {items.length === 0 && !loading && (
              <tr><td colSpan={7}><div className="empty">没有匹配的成员</div></td></tr>
            )}
          </tbody>
        </table>
      </div>

      {creating && (
        <CreateMember
          depts={depts}
          roles={roles}
          onClose={() => setCreating(false)}
          onDone={async () => { setCreating(false); await load(); flash('成员已创建，可立即登录') }}
        />
      )}

      {editing && (
        <EditMember
          member={editing}
          depts={depts}
          onClose={() => setEditing(null)}
          onDone={async () => { setEditing(null); await load(); flash('已保存') }}
        />
      )}

      {pwTarget && (
        <ResetPassword
          member={pwTarget}
          onClose={() => setPwTarget(null)}
          onDone={() => { setPwTarget(null); flash('口令已重置，该成员需重新登录') }}
        />
      )}

      {blocked && (
        <Dialog
          title="先移交空间，再停用账号"
          icon="alert"
          width={560}
          note={
            <>
              「{blocked.member.displayName || blocked.member.username}」名下还有{" "}
              <b>{blocked.spaces.length}</b> 个文档空间。账号一旦停用就无法登录，
              这些空间将没有负责人；其中只有他一人可进的空间，会直接变成谁也打不开的死空间。
            </>
          }
          onClose={() => setBlocked(null)}
          footer={
            <>
              <button onClick={() => setBlocked(null)}>稍后再说</button>
              <button className="primary" onClick={() => { setBlocked(null); navigate('/admin/spaces') }}>
                <Icon name="share" size={14} /> 去空间台账移交
              </button>
            </>
          }
        >
          <div className="xfer-owned">
            {blocked.spaces.map((sp) => (
              <div className="xfer-owned-row" key={sp.id}>
                <Icon name="folder" size={15} />
                <span className="nm">{sp.name}</span>
                {sp.onlyMine && <span className="badge danger" style={{ height: 18 }}>仅他可达</span>}
                <span className="hint">密级 {sp.classification} · 授权 {sp.granted} 条</span>
              </div>
            ))}
          </div>
          <div className="banner" style={{ background: 'var(--surface-2)', marginTop: 10 }}>
            <span className="ico"><Icon name="info" size={14} /></span>
            <span>
              如果只是担心账号被盗用、需要立刻把此人踢下线，可以先<b>重置口令</b>：
              它会立即吊销全部会话，但不会让空间失去负责人。
            </span>
          </div>
        </Dialog>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}

// ---------------- 新建 ----------------

function CreateMember({ depts, roles, onClose, onDone }:
  { depts: Dept[]; roles: RoleDef[]; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    username: '', displayName: '', email: '', password: '',
    role: '', deptId: '', ceiling: 4, classification: 0,
    principalType: 'internal', mfaRequired: false, expiresAt: '',
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await postJSON('/v1/admin/members', {
        ...f,
        role: f.role || undefined,
        deptId: f.deptId || undefined,
        expiresAt: f.expiresAt ? new Date(f.expiresAt).toISOString() : null,
      })
      onDone()
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.message}` : '创建失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 560 }}>
        <div className="modal-head">
          <strong>新建成员</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>登录名（创建后不可改）</label>
              <input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} required />
            </div>
            <div className="field">
              <label>姓名</label>
              <input value={f.displayName} onChange={(e) => setF({ ...f, displayName: e.target.value })} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>邮箱</label>
              <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
            </div>
            <div className="field">
              <label>部门</label>
              <select value={f.deptId} onChange={(e) => setF({ ...f, deptId: e.target.value })}>
                <option value="">不指定</option>
                {depts.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
              </select>
            </div>
          </div>
          <div className="field">
            <label>初始口令（≥12 位；请让成员首次登录后自行修改）</label>
            <input value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required minLength={12} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>初始角色</label>
              <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
                <option value="">普通成员（无管理角色）</option>
                {roles.map((r) => <option key={r.code} value={r.code}>{r.name}</option>)}
              </select>
            </div>
            <div className="field">
              <label>密级（可见上限）</label>
              <select value={f.classification} onChange={(e) => setF({ ...f, classification: Number(e.target.value) })}>
                {levelText.map((label, i) => <option key={i} value={i}>{i} · {label}</option>)}
              </select>
            </div>
            <div className="field">
              <label>封顶（可授权上限）</label>
              <select value={f.ceiling} onChange={(e) => setF({ ...f, ceiling: Number(e.target.value) })}>
                {levelText.map((label, i) => <option key={i} value={i}>{i} · {label}</option>)}
              </select>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>账号类型</label>
              <select value={f.principalType} onChange={(e) => setF({ ...f, principalType: e.target.value })}>
                <option value="internal">内部成员</option>
                <option value="external">外部协作（强制二次验证）</option>
              </select>
            </div>
            <div className="field">
              <label>有效期（留空 = 长期）</label>
              <input type="date" value={f.expiresAt} onChange={(e) => setF({ ...f, expiresAt: e.target.value })} />
            </div>
          </div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
            <input type="checkbox" checked={f.mfaRequired}
              onChange={(e) => setF({ ...f, mfaRequired: e.target.checked })} />
            强制邮箱二次验证
          </label>
          {err && <div className="error-text">{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose}>取消</button>
            <button className="primary" type="submit" disabled={busy}>{busy ? '创建中…' : '创建'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------- 编辑 ----------------

function EditMember({ member, depts, onClose, onDone }:
  { member: Member; depts: Dept[]; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    displayName: member.displayName,
    email: member.email,
    deptId: member.deptId,
    classification: member.classification,
    ceiling: member.ceiling,
    expiresAt: member.expiresAt ? member.expiresAt.slice(0, 10) : '',
    mfaRequired: member.mfaRequired,
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api(`/v1/admin/members/${member.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          displayName: f.displayName,
          email: f.email,
          deptId: f.deptId,
          classification: f.classification,
          ceiling: f.ceiling,
          mfaRequired: f.mfaRequired,
          expiresAt: f.expiresAt ? new Date(f.expiresAt).toISOString() : null,
          clearExpiry: !f.expiresAt,
        }),
      })
      onDone()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 520 }}>
        <div className="modal-head">
          <strong>编辑 {member.username}</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>姓名</label>
              <input value={f.displayName} onChange={(e) => setF({ ...f, displayName: e.target.value })} />
            </div>
            <div className="field">
              <label>邮箱</label>
              <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>部门</label>
              <select value={f.deptId} onChange={(e) => setF({ ...f, deptId: e.target.value })}>
                <option value="">不指定</option>
                {depts.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
              </select>
            </div>
            <div className="field">
              <label>有效期</label>
              <input type="date" value={f.expiresAt} onChange={(e) => setF({ ...f, expiresAt: e.target.value })} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>密级</label>
              <select value={f.classification} onChange={(e) => setF({ ...f, classification: Number(e.target.value) })}>
                {levelText.map((label, i) => <option key={i} value={i}>{i} · {label}</option>)}
              </select>
            </div>
            <div className="field">
              <label>封顶</label>
              <select value={f.ceiling} onChange={(e) => setF({ ...f, ceiling: Number(e.target.value) })}>
                {levelText.map((label, i) => <option key={i} value={i}>{i} · {label}</option>)}
              </select>
            </div>
          </div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
            <input type="checkbox" checked={f.mfaRequired}
              onChange={(e) => setF({ ...f, mfaRequired: e.target.checked })} />
            强制邮箱二次验证
          </label>
          <div className="hint">密级与封顶不能高于你自己的权限；超过会被服务端拒绝。</div>
          {err && <div className="error-text">{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose}>取消</button>
            <button className="primary" type="submit" disabled={busy}>{busy ? '保存中…' : '保存'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------- 重置口令 ----------------

function ResetPassword({ member, onClose, onDone }:
  { member: Member; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await postJSON(`/v1/admin/members/${member.id}/password`, { password: pw })
      onDone()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '重置失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 420 }}>
        <div className="modal-head">
          <strong>重置 {member.username} 的口令</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div className="field">
            <label>新口令（≥12 位）</label>
            <input value={pw} onChange={(e) => setPw(e.target.value)} required minLength={12} autoFocus />
          </div>
          <div className="hint">重置会立即吊销该成员的全部会话，旧口令同时失效。</div>
          {err && <div className="error-text">{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose}>取消</button>
            <button className="primary" type="submit" disabled={busy}>{busy ? '重置中…' : '确认重置'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}
