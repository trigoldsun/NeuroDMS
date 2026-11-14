import { useCallback, useEffect, useSyncExternalStore, useState } from 'react'
import {
  api, applyTheme, cycleTheme, fetchMe, getMyShares, getShareVisits,
  HttpError, type Me, type MyShare, type ShareVisits,
} from '../api'
import { Shell, type SpaceLite } from '../components/Shell'
import { InfoDot } from '../components/ui'
import { currentPath, filesPath, navigate, subscribe } from '../router'
import AccountDrawer from './AccountDrawer'

// 我的分享：分享人自己的可见性。
//
// 为什么要单独一页：外发之后，"对方到底看没看"是分享人最焦虑的问题，
// 而在此之前只有管理员能在审计里查到。这一页把答案交还给创建者。
//
// 访问明细挂在地址上（?share=xxx）：刷新、后退、把链接发给同事都能落到同一条记录。

const ACTION_LABEL: Record<string, string> = {
  open: '打开',
  redeem: '打开链接',
  preview: '在线预览',
  download: '下载',
  print: '点了打印',
  denied: '被拒绝',
}

function fmtTime(s?: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('zh-CN', { hour12: false })
}

function stateBadge(s: MyShare): { text: string; cls: string } {
  if (s.revokedAt) return { text: '已撤销', cls: 'plain' }
  if (s.approvalStatus === 'pending') return { text: '待审批', cls: 'warn' }
  if (s.approvalStatus === 'rejected') return { text: '已驳回', cls: 'danger' }
  if (s.expiresAt && new Date(s.expiresAt) < new Date()) return { text: '已过期', cls: 'plain' }
  if (s.maxUses && s.usedCount >= s.maxUses) return { text: '已用尽', cls: 'plain' }
  return { text: '有效', cls: 'ok' }
}

export default function MyShares() {
  const loc = useSyncExternalStore(subscribe, currentPath, currentPath)
  const selected = new URLSearchParams(loc.split('?')[1] ?? '').get('share') ?? ''

  const [me, setMe] = useState<Me | null>(null)
  const [spaces, setSpaces] = useState<SpaceLite[]>([])
  const [items, setItems] = useState<MyShare[]>([])
  const [detail, setDetail] = useState<ShareVisits | null>(null)
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [err, setErr] = useState('')
  const [accountOpen, setAccountOpen] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  useEffect(() => { applyTheme() }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const [m, sp, list] = await Promise.all([
        fetchMe(),
        api<{ items: SpaceLite[] }>('/v1/spaces'),
        getMyShares(),
      ])
      setMe(m)
      setSpaces(sp.items ?? [])
      setItems(list.items ?? [])
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  // 详情随地址变化加载：打开、切换、后退都只改地址
  useEffect(() => {
    if (!selected) { setDetail(null); return }
    let alive = true
    setDetailLoading(true)
    void getShareVisits(selected)
      .then((d) => { if (alive) setDetail(d) })
      .catch((e) => { if (alive) setErr(e instanceof HttpError ? e.message : '读取访问记录失败') })
      .finally(() => { if (alive) setDetailLoading(false) })
    return () => { alive = false }
  }, [selected])

  const totalViews = items.reduce((n, s) => n + s.views, 0)
  const touched = items.filter((s) => s.views + s.downloads + s.prints > 0).length

  return (
    <Shell
      me={me}
      spaces={spaces}
      activeSpaceId=""
      onSpace={(id) => navigate(filesPath(id))}
      spaceName="我的分享"
      crumbs={[]}
      onOpenAccount={() => setAccountOpen(true)}
      onToggleTheme={() => { const t = cycleTheme(); setTheme(t === 'dark' ? 'dark' : 'light') }}
      theme={theme}
    >
      <div className="content-head">
        <div className="ttl">
          <h1>我的分享</h1>
          <div className="sub">
            <span>{loading ? '载入中…' : `${items.length} 条链接 · ${touched} 条被访问过 · 累计 ${totalViews} 次预览`}</span>
            <InfoDot title="这些数字从哪来">
              <p>打开、预览、下载由服务端在取内容时记录，<b>准确</b>。</p>
              <p><b>打印</b>是访客点击打印按钮时前端上报的，只能说明"他点了打印"，不能证明纸出来了。</p>
              <p>记录里包含 IP、浏览器与操作系统（由浏览器上报），用于安全审计与泄露追溯。</p>
              <div className="pop-foot">主机名与电脑登录用户名浏览器拿不到，任何网页都拿不到。</div>
            </InfoDot>
          </div>
        </div>
      </div>

      {err && <div className="card empty error" style={{ margin: 12 }}>{err}</div>}

      <div className="card" style={{ margin: 12, padding: 0 }}>
        {loading ? (
          <div className="empty">载入中…</div>
        ) : items.length === 0 ? (
          <div className="empty">你还没有创建过外发链接。</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>文件 / 空间</th>
                <th style={{ width: 90 }}>状态</th>
                <th style={{ width: 70 }}>预览</th>
                <th style={{ width: 70 }}>下载</th>
                <th style={{ width: 70 }}>打印</th>
                <th style={{ width: 90 }}>独立 IP</th>
                <th style={{ width: 170 }}>最近访问</th>
                <th style={{ width: 80 }} />
              </tr>
            </thead>
            <tbody>
              {items.map((s) => {
                const st = stateBadge(s)
                return (
                  <tr key={s.id} className={selected === s.id ? 'selected' : ''}
                    onClick={() => navigate('/shares?share=' + s.id)}>
                    <td className="name">
                      <span>{s.name}</span>
                      <span className="hint" style={{ marginLeft: 8 }}>
                        {s.objectType === 'space' ? '空间' : '文件'}
                        {' · '}
                        {s.allowDownload ? '可下载' : s.allowSave ? '仅保存副本' : '仅在线查看'}
                        {s.allowPrint ? ' · 可打印' : ' · 不可打印'}
                      </span>
                    </td>
                    <td><span className={`badge ${st.cls}`}>{st.text}</span></td>
                    <td>{s.views}</td>
                    <td>{s.downloads}</td>
                    <td>{s.prints}</td>
                    <td>{s.distinctIps}</td>
                    <td>{fmtTime(s.lastSeenAt)}</td>
                    <td>
                      <button className="sm" onClick={(e) => { e.stopPropagation(); navigate('/shares?share=' + s.id) }}>
                        访问记录
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className="card pad" style={{ margin: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <h3 style={{ margin: 0 }}>访问记录</h3>
            {detail?.suspicious && (
              <span className="badge danger" title="多个不同 IP 使用同一条链接，通常意味着被转发">
                疑似被转发
              </span>
            )}
            <div className="grow" />
            <button onClick={() => navigate('/shares', true)}>收起</button>
          </div>

          {detailLoading && <div className="hint">读取中…</div>}
          {detail && (
            <>
              <div className="hint" style={{ marginBottom: 10 }}>
                创建 {fmtTime(detail.createdAt)} ·
                {detail.expiresAt ? ` 到期 ${fmtTime(detail.expiresAt)}` : ' 长期有效'}
                {detail.revokedAt ? ` · 已于 ${fmtTime(detail.revokedAt)} 撤销` : ''}
                {' · '}打开 {detail.summary.opens} 次 / 预览 {detail.summary.views} 次 /
                下载 {detail.summary.downloads} 次 / 打印 {detail.summary.prints} 次 /
                独立 IP {detail.summary.distinctIps} 个
              </div>
              {detail.items.length === 0 ? (
                <div className="empty">还没有人打开过这条链接。</div>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 170 }}>时间</th>
                      <th style={{ width: 120 }}>动作</th>
                      <th style={{ width: 180 }}>IP</th>
                      <th style={{ width: 140 }}>范围 / 归属地</th>
                      <th>客户端</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.items.map((v, i) => (
                      <tr key={`${v.at}-${i}`}>
                        <td>{fmtTime(v.at)}</td>
                        <td>
                          <span className={`badge ${v.result === 'ok' ? 'plain' : 'danger'}`}>
                            {ACTION_LABEL[v.action] ?? v.action}
                          </span>
                        </td>
                        <td className="code">{v.ip || '—'}</td>
                        <td>
                          {v.scope}
                          {v.geo ? ` · ${v.geo}` : ''}
                        </td>
                        <td>{v.browser} · {v.os}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <div className="hint" style={{ marginTop: 8 }}>
                只显示最近 200 条。完整证据链（含哈希校验）在「管理台 · 审计日志」。
              </div>
            </>
          )}
        </div>
      )}

      {accountOpen && <AccountDrawer me={me} onClose={() => setAccountOpen(false)} />}
      <div style={{ height: 24 }} />
    </Shell>
  )
}
