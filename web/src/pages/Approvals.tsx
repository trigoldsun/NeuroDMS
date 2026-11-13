import { useCallback, useEffect, useState } from 'react'
import { api, applyTheme, cycleTheme, fetchMe, HttpError, postJSON, type Me } from '../api'
import { Shell, type SpaceLite } from '../components/Shell'
import { Icon, InfoDot } from '../components/ui'
import AccountDrawer from './AccountDrawer'
import { filesPath, navigate, previewPath } from '../router'

// 外发审批的独立入口。
//
// 为什么不能只放在管理台：能审批的人**不一定是管理员**——判定依据是对该对象
// 有 manage_acl（空间所有者、被授权的管理者都可能有）。如果只有管理台有入口，
// 这些人收到待办却点不进去，等于审批链在最关键的一步断掉。

type Approval = {
  shareId: string
  objectType: 'node' | 'space'
  objectId: string
  name: string
  classification: number
  creator: string
  createdAt: string
  expiresAt?: string | null
}

export default function Approvals() {
  const [me, setMe] = useState<Me | null>(null)
  const [spaces, setSpaces] = useState<SpaceLite[]>([])
  const [items, setItems] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState('')
  const [accountOpen, setAccountOpen] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [list, sp] = await Promise.all([
        api<{ items: Approval[] }>('/v1/shares/pending'),
        api<{ items: SpaceLite[] }>('/v1/spaces'),
      ])
      setItems(list.items ?? [])
      setSpaces(sp.items ?? [])
    } catch {
      setMsg('读取待审批链接失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    applyTheme()
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')
    void fetchMe().then(setMe).catch(() => undefined)
    void load()
  }, [load])

  async function decide(a: Approval, approve: boolean) {
    setBusy(a.shareId); setMsg('')
    try {
      await postJSON(`/v1/shares/${a.shareId}/approve`, { approve })
      setMsg(approve ? '已通过，链接立即可用' : '已驳回，发起人需重新创建链接')
      await load()
    } catch (e) {
      setMsg(e instanceof HttpError ? e.message : '操作失败')
    } finally {
      setBusy('')
    }
  }

  return (
    <Shell
      me={me}
      spaces={spaces}
      activeSpaceId=""
      onSpace={(id) => navigate(filesPath(id))}
      spaceName="待我审批"
      crumbs={[]}
      onOpenAccount={() => setAccountOpen(true)}
      onToggleTheme={() => { const t = cycleTheme(); setTheme(t === 'dark' ? 'dark' : 'light') }}
      theme={theme}
    >
      <div className="content-head">
        <div className="ttl">
          <h1>外发审批</h1>
          <div className="sub">
            <span>{loading ? '载入中…' : `${items.length} 条待处理`}</span>
            <InfoDot title="谁能审批、批了会怎样">
              <p>只列出<b>你有权处置</b>的链接：你对该文件或目录有管理权限，且不是你本人发起。</p>
              <p>通过后链接立即可用；驳回后发起人需要重新创建。系统不会自动通知发起人，请另行告知。</p>
              <div className="pop-foot">这条规则和权限内核一致，不因为"你在不在管理台"而不同。</div>
            </InfoDot>
          </div>
        </div>
      </div>

      {msg && (
        <div className="banner" style={{ marginBottom: 12 }}>
          <span className="ico"><Icon name="info" size={14} /></span>
          <span>{msg}</span>
        </div>
      )}

      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>文件</th>
              <th style={{ width: 70 }}>密级</th>
              <th style={{ width: 120 }}>发起人</th>
              <th style={{ width: 170 }}>提交时间</th>
              <th style={{ width: 170 }}>链接有效期</th>
              <th style={{ width: 150 }} />
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && !loading && (
              <tr><td colSpan={6}><div className="empty">没有需要你审批的外发链接</div></td></tr>
            )}
            {items.map((a) => (
              <tr key={a.shareId}>
                <td>
                  <div className="cell-name">
                    <span className="ftype" style={{ width: 26, height: 26 }}>
                      <Icon name={a.objectType === 'space' ? 'folder' : 'file'} size={14} />
                    </span>
                    <span className="nm">
                      <button className="link" onClick={() => { if (a.objectType === 'node') window.open(previewPath(a.objectId), '_blank') }}>
                        {a.name || '（已删除的对象）'}
                      </button>
                      <span className="sub">{a.objectType === 'space' ? '整个空间' : '单个文件'}</span>
                    </span>
                  </div>
                </td>
                <td><span className={`badge cls-${a.classification}`}>{a.classification}</span></td>
                <td>{a.creator}</td>
                <td className="tnum">{new Date(a.createdAt).toLocaleString('zh-CN')}</td>
                <td className="tnum">{a.expiresAt ? new Date(a.expiresAt).toLocaleString('zh-CN') : '不限期'}</td>
                <td className="actions">
                  <button className="primary sm" disabled={busy === a.shareId} onClick={() => void decide(a, true)}>通过</button>
                  <button className="danger sm" disabled={busy === a.shareId} onClick={() => void decide(a, false)}>驳回</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {accountOpen && <AccountDrawer me={me} onClose={() => setAccountOpen(false)} />}
    </Shell>
  )
}
