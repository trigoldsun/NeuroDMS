import { useEffect, useMemo, useState } from 'react'
import { api, HttpError, postJSON, type TransferRequest, type TransferResult } from '../api'
import { Avatar, Dialog, Icon, InfoDot } from './ui'

// 空间移交的两个界面件：
//   SpaceTransferDialog —— 发起移交（所有者本人，或系统管理员）
//   PendingTransferBar  —— 原所有者在这里看到"管理员要拿走我的空间"并点同意

type Person = { id: string; username: string; displayName: string }

const MODE_NOTE: Record<string, string> = {
  admin_to_self: '管理员移给自己需要原所有者确认后才生效',
  admin: '管理员代转，立即生效并记入审计',
  owner: '所有者本人移交，立即生效',
}

export function SpaceTransferDialog({
  spaceId, spaceName, ownerName, meId, isAdmin, isOwner = false, onClose, onDone,
}: {
  spaceId: string
  spaceName: string
  ownerName?: string
  meId: string
  isAdmin: boolean
  // 所有者本人不能把空间转给自己；管理员在不拥有该空间时才允许选自己
  isOwner?: boolean
  onClose: () => void
  onDone: (msg: string) => void
}) {
  const [people, setPeople] = useState<Person[]>([])
  const [q, setQ] = useState('')
  const [picked, setPicked] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    api<{ items: Person[] }>('/v1/users')
      .then((d) => { if (alive) setPeople(d.items ?? []) })
      .catch(() => { if (alive) setErr('读取成员列表失败') })
    return () => { alive = false }
  }, [])

  // 所有者不能转给自己；管理员可以选自己（会走"需原所有者确认"的分支）
  const list = useMemo(() => {
    const k = q.trim().toLowerCase()
    return people
      .filter((p) => (!isOwner || p.id !== meId) && (isAdmin || p.id !== meId))
      .filter((p) => !k || p.username.toLowerCase().includes(k) || (p.displayName || '').toLowerCase().includes(k))
      .slice(0, 40)
  }, [people, q, meId, isAdmin])

  const toSelf = isAdmin && !isOwner && picked === meId
  const pickedName = people.find((p) => p.id === picked)?.displayName || ''

  async function submit() {
    if (!picked) { setErr('请选择接收人'); return }
    setBusy(true); setErr('')
    try {
      const r = await postJSON<TransferResult>(`/v1/spaces/${spaceId}/transfer`, { toUserId: picked, reason })
      if (r.pending) {
        onDone(`已提交移交申请，等待「${ownerName || '原所有者'}」确认后生效`)
      } else {
        onDone(`「${spaceName}」已移交给 ${pickedName}`)
      }
      onClose()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '移交失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      title="移交空间"
      icon="share"
      width={520}
      note={
        <>
          移交会把<b>所有者身份</b>转给对方：空间归属、空间内属于原所有者的文件归属、以及所有者权限一并转移。
          这个动作不可撤销，对方可以再移交给别人。
        </>
      }
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose}>取消</button>
          <button className="primary" disabled={busy || !picked} onClick={() => void submit()}>
            {busy ? '移交中…' : toSelf ? '提交申请，等原所有者确认' : '确认移交'}
          </button>
        </>
      }
    >
      <div className="field">
        <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          接收人
          <InfoDot title="谁可以接收">
            <p>只能选<b>本租户内可登录</b>的成员。停用、已删除、已过期的账号会在这里之后被服务端拒绝。</p>
            <p>接收人的密级必须不低于空间密级——否则移交过去他自己也打不开，等于制造一个新的死空间。</p>
          </InfoDot>
        </label>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="按姓名或账号筛选"
          autoFocus
        />
      </div>

      <div className="xfer-list">
        {list.length === 0 && <div className="hint" style={{ padding: 10 }}>没有匹配的成员</div>}
        {list.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`xfer-item${picked === p.id ? ' on' : ''}`}
            onClick={() => setPicked(p.id)}
          >
            <Avatar name={p.displayName || p.username} size={24} />
            <span className="nm">{p.displayName || p.username}</span>
            <span className="un">{p.username}</span>
            {p.id === meId && <span className="badge plain" style={{ height: 17 }}>我自己</span>}
            {picked === p.id && <Icon name="check" size={15} />}
          </button>
        ))}
      </div>

      <div className="field">
        <label htmlFor="xfer-reason">说明（可选，会写进审计）</label>
        <input
          id="xfer-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="例如：岗位调整，由张伟接手"
        />
      </div>

      {toSelf && (
        <div className="banner warn">
          <span className="ico"><Icon name="alert" size={15} /></span>
          <span>
            你正在把空间移交<b>给自己</b>。为避免管理员借职务取得他人文件，
            这次移交需要原所有者 <b>{ownerName || '（原所有者）'}</b> 在 7 天内点击同意后才会生效。
            在对方确认前，你对这个空间没有任何额外权限。
          </span>
        </div>
      )}

      {!toSelf && picked && (
        <div className="hint" style={{ margin: 0 }}>
          {MODE_NOTE[isAdmin ? 'admin' : 'owner']}。移交后你不再是这个空间的所有者。
        </div>
      )}

      {err && (
        <div className="banner danger">
          <span className="ico"><Icon name="alert" size={15} /></span>
          <span>{err}</span>
        </div>
      )}
    </Dialog>
  )
}

// PendingTransferBar 显示"等我确认"的请求。
//
// 这是一个主动上门的提示：如果只在管理台列表里挂一条，所有者永远不知道
// 自己的空间正在被别人要走——而这正是最需要他知道的一件事。
export function PendingTransferBar({ onChanged }: { onChanged?: () => void }) {
  const [items, setItems] = useState<TransferRequest[]>([])
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  async function load() {
    try {
      const d = await api<{ items: TransferRequest[] }>('/v1/transfers/pending')
      setItems(d.items ?? [])
    } catch { /* 提示条拿不到不影响主体功能 */ }
  }

  useEffect(() => { void load() }, [])

  async function decide(r: TransferRequest, approve: boolean) {
    setBusy(r.id); setErr('')
    try {
      await postJSON(`/v1/transfers/${r.id}/decide`, { approve })
      await load()
      onChanged?.()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '处理失败')
    } finally {
      setBusy('')
    }
  }

  if (items.length === 0) return null

  return (
    <div className="xfer-bar">
      {items.map((r) => (
        <div className="xfer-card" key={r.id}>
          <span className="ico"><Icon name="alert" size={16} /></span>
          <div className="txt">
            <b>{r.initiatorName || r.toName}</b> 请求把「<b>{r.spaceName}</b>」移交给他自己
            <span className="hint" style={{ display: 'block', marginTop: 2 }}>
              {r.reason ? `理由：${r.reason} · ` : ''}
              剩余 {Math.max(0, Math.ceil((new Date(r.expiresAt).getTime() - Date.now()) / 86400000))} 天自动失效。同意后你会失去该空间的所有者身份。
            </span>
          </div>
          <button className="sm" disabled={busy === r.id} onClick={() => void decide(r, false)}>拒绝</button>
          <button className="primary sm" disabled={busy === r.id} onClick={() => void decide(r, true)}>同意移交</button>
        </div>
      ))}
      {err && <div className="banner danger" style={{ margin: '6px 0 0' }}>{err}</div>}
    </div>
  )
}
