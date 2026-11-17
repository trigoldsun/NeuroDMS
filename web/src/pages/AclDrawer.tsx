import { useEffect, useState } from 'react'
import { api, HttpError } from '../api'

type Target = { type: 'space' | 'node'; id: string; name: string }
type AclItem = {
  aceId: string
  subjectType: string
  subjectId: string
  preset: string
  allow: string[]
}
type UserItem = { id: string; username: string; displayName: string }

// 可被显式拒绝的动作。与服务端白名单一致：不含"可见性"与"管理权限"——
// 前者用不授权表达，后者会把配置者自己锁死。
const DENY_ACTIONS: { code: string; label: string }[] = [
  { code: 'download', label: '下载原件' },
  { code: 'print', label: '打印' },
  { code: 'copy', label: '另存副本' },
  { code: 'share_internal', label: '内部分享' },
  { code: 'share_external', label: '外部分享' },
]

const PRESETS: { value: string; label: string; hint: string }[] = [
  { value: 'viewer', label: '查看者', hint: '可见、可预览' },
  { value: 'contributor', label: '贡献者', hint: '+ 下载、上传' },
  { value: 'editor', label: '编辑者', hint: '+ 编辑、复制、改名' },
  { value: 'manager', label: '管理者', hint: '+ 移动、删除、内部分享' },
  { value: 'owner', label: '所有者', hint: '全部能力、可授权' },
]

// 权限抽屉：列出对象上的授权条目，支持授予与撤销。
// 界面只暴露 5 个档位而不是 15 个原子位——这是"可理解性优先"的落地：
// 档位在服务端映射为位图，用户不需要理解位与蕴含关系。
export default function AclDrawer({
  target,
  onClose,
  onChanged,
}: {
  target: Target
  onClose: () => void
  onChanged: () => void
}) {
  const [items, setItems] = useState<AclItem[]>([])
  const [users, setUsers] = useState<UserItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [subjectId, setSubjectId] = useState('')
  const [preset, setPreset] = useState('viewer')
  const [busy, setBusy] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [acl, us] = await Promise.all([
          api<{ items: AclItem[] }>(
            `/v1/acl?objectType=${target.type}&objectId=${encodeURIComponent(target.id)}`,
          ),
          api<{ items: UserItem[] }>('/v1/users'),
        ])
        if (cancelled) return
        setItems(acl.items)
        setUsers(us.items)
        if (us.items.length > 0) setSubjectId(us.items[0].id)
      } catch (err) {
        if (!cancelled) setError(err instanceof HttpError ? err.message : '读取权限失败')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [target])

  async function reload() {
    try {
      const acl = await api<{ items: AclItem[] }>(
        `/v1/acl?objectType=${target.type}&objectId=${encodeURIComponent(target.id)}`,
      )
      setItems(acl.items)
    } catch {
      /* 保持原列表，避免抖动 */
    }
  }

  const [denyOpen, setDenyOpen] = useState(false)
  const [denyActions, setDenyActions] = useState<string[]>([])

  // 追加拒绝：命中后 authz 直接返回 EXPLICIT_DENY，优先级高于任何档位。
  // 因此这里要求二次确认——误配的表现是"他是 owner 却打不开"，极难自查。
  async function deny() {
    if (!subjectId || busy || denyActions.length === 0) return
    const who = users.find((u) => u.id === subjectId)
    const name = who ? who.displayName || who.username : '该用户'
    const labels = DENY_ACTIONS.filter((a) => denyActions.includes(a.code)).map((a) => a.label).join('、')
    if (!window.confirm(
      `给「${name}」追加拒绝：${labels}？\n\n` +
      '拒绝的优先级高于任何档位：即使他是所有者，这些动作也会被直接拒绝。\n' +
      '需要撤销时，在下方条目列表里删除对应 ACE（会同时清掉该条的全部授权）。')) return
    setBusy(true)
    setError('')
    try {
      await api('/v1/acl/deny', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          objectType: target.type,
          objectId: target.id,
          subjectType: 'user',
          subjectId,
          actions: denyActions,
        }),
      })
      setDenyActions([])
      setDenyOpen(false)
      await reload()
      onChanged()
    } catch (err) {
      setError(err instanceof HttpError ? err.message : '追加拒绝失败')
    } finally {
      setBusy(false)
    }
  }

  async function grant() {
    if (!subjectId || busy) return
    setBusy(true)
    setError('')
    try {
      await api('/v1/acl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          objectType: target.type,
          objectId: target.id,
          subjectType: 'user',
          subjectId,
          preset,
        }),
      })
      await reload()
      onChanged()
    } catch (err) {
      if (err instanceof HttpError && err.code === 'CEILING_EXCEEDED') {
        setError('不能授出高于你自己档位的权限')
      } else {
        setError(err instanceof HttpError ? err.message : '授权失败')
      }
    } finally {
      setBusy(false)
    }
  }

  async function revoke(aceId: string) {
    setBusy(true)
    setError('')
    try {
      await api(`/v1/acl/${aceId}`, { method: 'DELETE' })
      await reload()
      onChanged()
    } catch (err) {
      if (err instanceof HttpError && err.code === 'LAST_OWNER') {
        setError('不能移除最后一个所有者')
      } else {
        setError(err instanceof HttpError ? err.message : '撤销失败')
      }
    } finally {
      setBusy(false)
    }
  }

  function userName(id: string): string {
    const u = users.find((x) => x.id === id)
    // 不再回退到 uuid 前 8 位：读者无法判断那是谁，
    // 反而会以为是某个"名字"。查不到就明确说账号已不存在。
    return u ? (u.displayName || u.username) : '账号已删除'
  }

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="权限管理">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <h2>权限管理</h2>
          <span className="pill">{target.name}</span>
          <div style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <select value={subjectId} onChange={(e) => setSubjectId(e.target.value)} disabled={busy}>
            {users.map((u) => (
              <option key={u.id} value={u.id}>{u.displayName || u.username}</option>
            ))}
          </select>
          <select value={preset} onChange={(e) => setPreset(e.target.value)} disabled={busy}>
            {PRESETS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}（{p.hint}）</option>
            ))}
          </select>
          <button className="primary" onClick={grant} disabled={busy || !subjectId}>授予</button>
          <button className="sm" onClick={() => setDenyOpen((v) => !v)} disabled={busy}>
            {denyOpen ? '收起拒绝' : '追加拒绝…'}
          </button>
        </div>

        {denyOpen && (
          <div className="card pad" style={{ display: 'grid', gap: 8 }}>
            <div className="hint" style={{ margin: 0 }}>
              拒绝的优先级<strong>高于任何档位</strong>：勾选后即使该用户是所有者，这些动作也会被直接拒绝。
              典型用法是"可以看、可以管，但不许下载/外发"。<br/>拒绝下载会连带生效为拒绝打印——系统的能力闭包会把"能把内容取走"的动作一起补齐，提交后以返回的生效清单为准。
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {DENY_ACTIONS.map((a) => (
                <label key={a.code} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={denyActions.includes(a.code)}
                    onChange={(e) => setDenyActions((cur) => (
                      e.target.checked ? [...cur, a.code] : cur.filter((c) => c !== a.code)
                    ))}
                  />
                  <span>{a.label}</span>
                </label>
              ))}
            </div>
            <div>
              <button className="danger sm" onClick={() => void deny()} disabled={busy || !subjectId || denyActions.length === 0}>
                追加拒绝
              </button>
            </div>
          </div>
        )}

        {error && <div className="error" role="alert">{error}</div>}

        <div className="card">
          {loading ? (
            <div className="empty">载入中…</div>
          ) : items.length === 0 ? (
            <div className="empty">暂无授权条目</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>主体</th>
                  <th style={{ width: 90 }}>档位</th>
                  <th style={{ width: 120 }} />
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <tr key={it.aceId}>
                    <td>
                      <button className="ghost" onClick={() => setExpanded(expanded === it.aceId ? null : it.aceId)}>
                        {userName(it.subjectId)}
                      </button>
                      {expanded === it.aceId && (
                        <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                          实际生效：{it.allow.join('、')}
                        </div>
                      )}
                    </td>
                    <td><span className="pill">{it.preset || '自定义'}</span></td>
                    <td className="actions">
                      <button className="danger" onClick={() => revoke(it.aceId)} disabled={busy}>移除</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p style={{ fontSize: 12, color: 'var(--muted)' }}>
          档位在服务端映射为 15 个原子权限位；点主体名可查看实际生效的位。
          授权上限受你的账号封顶约束，越界会被拒绝并记录审计。
        </p>
      </aside>
    </>
  )
}
