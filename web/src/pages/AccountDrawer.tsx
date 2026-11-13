import { useEffect, useState } from 'react'
import {
  clearTokens, deleteAccount, deletionPreview, handoverCandidates, logout,
  HttpError, type HandoverCandidate, type HandoverSummary, type Me,
} from '../api'

// 账户抽屉：退出登录 + 注销账号（含数字资产交接）。
//
// 注销为什么不能"一键完成"：
// 这个账号是资产宿主——空间归属、目录归属、权限条目都挂在他名下。
// 直接删掉会留下"没人能管的空间"和"继续对外开放的外链"。
// 所以必须先选接收人，服务端会整体交接后再软删。

export default function AccountDrawer({ me, onClose }: { me: Me | null; onClose: () => void }) {
  // ui-route-exempt: 抽屉内部的临时分栏（会话/注销），随抽屉一起关闭，
  // 不存在"收藏、分享、后退回到这一栏"的场景；主菜单与列表不适用此豁免。
  const [tab, setTab] = useState<'session' | 'delete'>('session')
  const [sum, setSum] = useState<HandoverSummary | null>(null)
  const [cands, setCands] = useState<HandoverCandidate[]>([])
  const [picked, setPicked] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [done, setDone] = useState('')

  useEffect(() => {
    if (tab !== 'delete') return
    let cancelled = false
    ;(async () => {
      try {
        const [s, list] = await Promise.all([deletionPreview(), handoverCandidates()])
        if (cancelled) return
        setSum(s)
        setCands(list)
      } catch (err) {
        if (!cancelled) setMsg(err instanceof HttpError ? err.message : '读取失败')
      }
    })()
    return () => { cancelled = true }
  }, [tab])

  const username = me?.username ?? ''
  const canSubmit = !!picked && confirm.trim() === username && username !== '' && !busy

  async function onDelete() {
    if (!canSubmit) return
    if (!window.confirm('注销后账号立即失效且不可恢复。确认继续？')) return
    setBusy(true)
    setMsg('')
    try {
      const r = await deleteAccount(picked, confirm)
      setDone(
        `账号已注销。已交接空间 ${r.handedOverSpaces} 个、文件 ${r.handedOverNodes} 个、` +
        `权限 ${r.handedOverGrants} 条；同时撤销外链 ${r.revokedShares} 条。`,
      )
      clearTokens()
      window.setTimeout(() => location.assign('/login'), 2600)
    } catch (err) {
      setMsg(err instanceof HttpError ? err.message : '注销失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer">
        <h2>账户</h2>
        <div className="hint" style={{ marginBottom: 8 }}>
          {me ? `${me.displayName || me.username}（${me.username}）· 密级 ${me.classification}` : '读取中…'}
        </div>

        <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
          <button className={tab === 'session' ? 'primary' : ''} onClick={() => setTab('session')}>会话</button>
          <button className={tab === 'delete' ? 'primary' : ''} onClick={() => setTab('delete')}>注销账号</button>
        </div>

        {tab === 'session' && (
          <>
            <p className="hint" style={{ marginTop: 0 }}>
              退出会在服务端吊销本次登录的刷新令牌，并清空本机保存的凭证。
              共用电脑上请务必先退出再离开。
            </p>
            <button
              className="ghost"
              style={{ width: '100%', marginBottom: 10 }}
              onClick={() => { onClose(); location.assign('/activity') }}
            >
              我的活动
            </button>
            <button className="primary" onClick={() => void logout()} style={{ width: '100%' }}>
              退出登录
            </button>
          </>
        )}

        {tab === 'delete' && (
          <>
            <p className="hint" style={{ marginTop: 0 }}>
              注销是不可逆操作。你名下的空间与文件会整体交接给下面选定的人，
              你创建的外发链接会被撤销（链接属于人，不随资产转移），所有会话立即失效。
            </p>

            {sum && (
              <div className="card pad" style={{ marginBottom: 10 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 4, fontSize: 13 }}>
                  <span>名下空间</span><b className="tnum">{sum.spaces}</b>
                  <span>名下文件/目录</span><b className="tnum">{sum.nodes}</b>
                  <span>权限条目（转交）</span><b className="tnum">{sum.grants}</b>
                  <span>生效中的外链（撤销）</span><b className="tnum">{sum.revokedShares}</b>
                </div>
              </div>
            )}

            <div className="field">
              <label htmlFor="handover">接收人</label>
              <select id="handover" value={picked} onChange={(e) => setPicked(e.target.value)}>
                <option value="">请选择接收人</option>
                {cands.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.displayName || c.username}（{c.username}）
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label htmlFor="confirm-name">输入自己的账号名以确认：{username}</label>
              <input
                id="confirm-name"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder={username}
                autoComplete="off"
              />
            </div>

            {msg && <div className="error" role="alert">{msg}</div>}
            {done && <div className="hint" style={{ color: 'var(--brand)' }}>{done}</div>}

            <button className="danger" onClick={() => void onDelete()} disabled={!canSubmit} style={{ width: '100%' }}>
              {busy ? '正在交接并注销…' : '永久注销我的账号'}
            </button>
            {cands.length === 0 && (
              <div className="hint" style={{ marginTop: 8 }}>
                没有可选的接收人。请先让管理员创建至少一个可用账号，或联系管理员代为处理。
              </div>
            )}
          </>
        )}

        <div style={{ marginTop: 'auto' }}>
          <button onClick={onClose}>关闭</button>
        </div>
      </aside>
    </>
  )
}
