// 平台运营 · 能力授权矩阵（docs/47 §4.4）
//
// 运营要回答的问题只有两类：
//   1. 这家客户现在有什么？（档位给的，还是单独特批的）
//   2. 我要给他加一项 / 收回一项，什么时候到期？
// 所以表格按"能力 × 三档默认 × 当前覆盖"排，而不是按能力分组讲功能。
//
// 桌面化的两处调整（本次重构）：
//   · 不再把整块内容塞进顶栏的工具栏里 —— 之前它被渲染在 .toolbar 内，
//     与"开通租户"按钮挤在同一行 flex 里，表格被压成一条；
//   · 租户选择改为独立一行（下拉 + 搜索），不再用"一堆按钮"占满首屏。
//
// 三条界面纪律保持不变：
//   1. 档位默认不可直接改：改档位是另一件事（有预检、有审计）；
//   2. 开通型特批默认 90 天，并把到期摆在行内——不给"忘了设到期"留白送的入口；
//   3. 过期覆盖必须显式标出来，否则运营会把它当成"已开通"回答客户。

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  listEntitlementDefs, listTenantEntitlements, setEntitlement, lockEntitlement,
  ApiError, type EntitlementDef, type EntitlementItem,
} from './api'
import { Alert, Empty, Note, PageHead, Panel, PfIcon } from './ui'

type Props = {
  tenantSlug: string
  canWrite: boolean
  tenants: { slug: string; name: string; edition: string }[]
  onPick: (slug: string) => void
}

// 服务端统一用 inherit 表示"没有覆盖、跟随档位"（旧服务端返回空串，这里一并认）。
const STATE_TEXT: Record<string, string> = {
  inherit: '跟随档位',
  '': '跟随档位',
  on: '已开通',
  off: '已关闭',
}
const isInherit = (s: string) => s === 'inherit' || s === ''

function fmtDate(iso?: string) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString('zh-CN')
}

// daysLeft 把"快到期"标出来：运营最容易犯的错是续费日已过、
// 客户打电话来才发现在宽限期里。
function daysLeft(iso?: string): number | null {
  if (!iso) return null
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000)
}

function editionLabel(e: string) {
  if (e === 'basic') return '基础版'
  if (e === 'professional') return '专业版'
  if (e === 'business') return '旗舰版'
  return '—'
}

// 页签地址里的 slug 可能是不存在的租户（链接过期、租户被删）。
// 这里给出明确提示，而不是让页面一直停在"加载中"。
export default function Entitlements({ tenantSlug, canWrite, tenants, onPick }: Props) {
  const [items, setItems] = useState<EntitlementItem[]>([])
  const [defs, setDefs] = useState<EntitlementDef[]>([])
  const [edition, setEdition] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [q, setQ] = useState('')
  // 行内编辑：到期日与原因，避免每改一项都弹窗
  const [draftExpiry, setDraftExpiry] = useState<Record<string, string>>({})
  const [draftReason, setDraftReason] = useState<Record<string, string>>({})

  const load = useCallback(async (slug: string) => {
    if (!slug) return
    setLoading(true)
    setErr('')
    try {
      const r = await listTenantEntitlements(slug)
      setItems(r.items ?? [])
      setEdition(r.edition ?? '')
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : '读取能力授权失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load(tenantSlug) }, [tenantSlug, load])

  // 能力定义只在首次拉一次：清单变化频率极低。
  // 拉到之后用于"平台强制关闭"区（只有声明 platformLockable 的项可锁）。
  useEffect(() => {
    listEntitlementDefs()
      .then((r) => setDefs(r.items ?? []))
      .catch(() => { /* 矩阵本身已带定义字段，定义接口失败不阻塞 */ })
  }, [])

  const picked = tenants.find((t) => t.slug === tenantSlug)
  const unknownSlug = !!tenantSlug && !picked && !loading

  const filteredTenants = useMemo(() => {
    const k = q.trim().toLowerCase()
    if (!k) return tenants
    return tenants.filter((t) => t.slug.toLowerCase().includes(k) || t.name.toLowerCase().includes(k))
  }, [tenants, q])

  const counts = useMemo(() => {
    let on = 0
    let off = 0
    let locked = 0
    for (const it of items) {
      if (it.locked) locked++
      else if (it.state === 'on') on++
      else if (it.state === 'off') off++
    }
    return { on, off, locked }
  }, [items])

  async function apply(code: string, state: 'inherit' | 'on' | 'off') {
    if (!tenantSlug) return
    setBusy(code + state)
    setErr('')
    setMsg('')
    try {
      const expiry = draftExpiry[code]
      const body: { state: 'inherit' | 'on' | 'off'; reason?: string; expiresAt?: string } = {
        state,
        reason: draftReason[code] ?? '',
      }
      if (state !== 'inherit' && expiry) {
        // date input 给的是 YYYY-MM-DD，转成当天 23:59:59 的 RFC3339：
        // 否则"到期日当天"会被算成已过期。
        body.expiresAt = new Date(expiry + 'T23:59:59').toISOString()
      }
      await setEntitlement(tenantSlug, code, body)
      setMsg(
        state === 'inherit'
          ? '已恢复为档位默认'
          : state === 'on' ? '已开通（未填到期则默认 90 天）' : '已关闭',
      )
      await load(tenantSlug)
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : '操作失败')
    } finally {
      setBusy('')
    }
  }

  async function toggleLock(it: EntitlementItem, locked: boolean) {
    setBusy('lock:' + it.code)
    setErr('')
    try {
      await lockEntitlement(it.code, locked, locked ? '平台合规下线' : '')
      await load(tenantSlug)
      setMsg(locked ? `已对全平台强制关闭「${it.name}」` : `已解除「${it.name}」的强制关闭`)
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : '操作失败')
    } finally {
      setBusy('')
    }
  }

  // ---------------- 未选租户：挑一个 ----------------

  if (!tenantSlug) {
    return (
      <>
        <PageHead
          title="能力授权"
          sub="档位决定默认值，这里做的是单租户覆盖——加购或临时开通都在这。选择一个租户开始。"
        />
        <Panel title="选择租户" sub={`共 ${tenants.length} 个`}>
          <div className="pf-search" style={{ maxWidth: 320, marginBottom: 14 }}>
            <PfIcon name="search" size={14} />
            <input
              type="search" value={q} aria-label="搜索租户"
              placeholder="按名称或标识搜索"
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          {filteredTenants.length === 0 && (
            <Empty icon="tenants" title="没有匹配的租户" hint="换个关键字，或先在「租户」页签开通。" />
          )}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 10 }}>
            {filteredTenants.map((t) => (
              <button
                key={t.slug}
                onClick={() => onPick(t.slug)}
                style={{
                  height: 'auto', padding: '12px 14px', textAlign: 'left',
                  display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start',
                }}
              >
                <b style={{ fontSize: 13.5 }}>{t.name}</b>
                <span className="hint" style={{ fontSize: 11.5 }}>
                  {t.slug} · {editionLabel(t.edition)}
                </span>
              </button>
            ))}
          </div>
        </Panel>
      </>
    )
  }

  // ---------------- 已选租户：矩阵 ----------------

  return (
    <>
      <PageHead
        title="能力授权"
        sub={
          <>
            三列默认来自档位定义（<b>只读</b>）。要改默认值请改档位；这里只做单租户覆盖。
            「跟随档位」= 删掉覆盖，立刻回到档位默认。
          </>
        }
        actions={
          <>
            <select
              aria-label="切换租户"
              value={tenantSlug}
              onChange={(e) => onPick(e.target.value)}
              style={{ minWidth: 200 }}
            >
              {tenants.map((t) => (
                <option key={t.slug} value={t.slug}>{t.name}（{t.slug}）</option>
              ))}
            </select>
            <button className="ghost" onClick={() => onPick('')}>换租户</button>
          </>
        }
      />

      {unknownSlug && (
        <Note tone="warn" icon="alert">
          租户「{tenantSlug}」不在当前列表中（可能已被删除，或链接已过期）。请从上方重新选择。
        </Note>
      )}

      {err && <Alert text={err} onClose={() => setErr('')} />}
      {msg && <div className="pf-note ok" style={{ marginBottom: 14 }}>{msg}</div>}

      <Panel
        title={picked ? picked.name : tenantSlug}
        sub={
          <>
            <span className="badge brand" style={{ marginRight: 6 }}>{tenantSlug}</span>
            档位：{editionLabel(edition)}
            　·　特批开通 {counts.on} 项，显式关闭 {counts.off} 项
            {counts.locked > 0 && `，平台强制关闭 ${counts.locked} 项`}
            {loading && '　· 读取中…'}
          </>
        }
        actions={
          <div className="pf-search" style={{ maxWidth: 220 }}>
            <PfIcon name="search" size={14} />
            <input
              type="search" value={q} aria-label="搜索能力"
              placeholder="按名称或编码筛选"
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        }
        body="none"
      >
        <div className="pf-tablewrap">
          <table>
            <thead>
              <tr>
                <th>能力</th>
                <th style={{ width: 70 }}>基础</th>
                <th style={{ width: 70 }}>专业</th>
                <th style={{ width: 70 }}>旗舰</th>
                <th style={{ width: 190 }}>当前</th>
                <th style={{ width: 170 }}>到期</th>
                <th className="pf-sticky" style={{ width: 330 }}>覆盖</th>
              </tr>
            </thead>
            <tbody>
              {items
                .filter((it) => {
                  const k = q.trim().toLowerCase()
                  if (!k) return true
                  return it.name.toLowerCase().includes(k)
                    || it.code.toLowerCase().includes(k)
                    || (it.description ?? '').toLowerCase().includes(k)
                })
                .map((it) => {
                  const left = daysLeft(it.expiresAt)
                  return (
                    <tr key={it.code}>
                      <td className="name" style={{ maxWidth: 320 }}>
                        {it.name}
                        <div className="hint" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{it.code}</div>
                        {it.description && <div className="hint" style={{ fontSize: 11.5 }}>{it.description}</div>}
                      </td>
                      <td>{it.basicDefault ? '✓' : <span className="hint">—</span>}</td>
                      <td>{it.proDefault ? '✓' : <span className="hint">—</span>}</td>
                      <td>{it.flagshipDefault ? '✓' : <span className="hint">—</span>}</td>
                      <td>
                        {it.locked ? (
                          <span className="badge danger">平台强制关闭</span>
                        ) : isInherit(it.state) ? (
                          <span className="badge plain">
                            {STATE_TEXT.inherit}（{(it.basicDefault || it.proDefault || it.flagshipDefault) ? '含' : '不含'}）
                          </span>
                        ) : (
                          <span className={`badge ${it.state === 'on' ? 'ok' : 'plain'}`}>
                            {STATE_TEXT[it.state]}{it.expired ? '（已过期）' : ''}
                          </span>
                        )}
                      </td>
                      <td>
                        {it.expiresAt ? (
                          <span className={left !== null && left >= 0 && left < 15 ? 'badge warn' : ''}>
                            {fmtDate(it.expiresAt)}
                            {left !== null && left >= 0 && ` · ${left} 天`}
                          </span>
                        ) : <span className="hint">—</span>}
                        {it.reason && <div className="hint" style={{ fontSize: 11.5 }}>{it.reason}</div>}
                      </td>
                      <td className="pf-sticky">
                        {!canWrite ? (
                          <span className="hint">只读账号</span>
                        ) : it.locked ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
                            <span className="hint">{it.lockReason || '合规下线'}</span>
                            <button className="sm" disabled={!!busy} onClick={() => void toggleLock(it, false)}>
                              {busy === 'lock:' + it.code ? '…' : '解除强制关闭'}
                            </button>
                          </div>
                        ) : (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                              <button className="sm" disabled={!!busy} onClick={() => void apply(it.code, 'on')}>
                                {busy === it.code + 'on' ? '…' : '开通'}
                              </button>
                              <button className="sm" disabled={!!busy} onClick={() => void apply(it.code, 'off')}>
                                {busy === it.code + 'off' ? '…' : '关闭'}
                              </button>
                              <button
                                className="sm ghost" disabled={!!busy || isInherit(it.state)}
                                onClick={() => void apply(it.code, 'inherit')}
                              >
                                跟随档位
                              </button>
                            </div>
                            <div style={{ display: 'flex', gap: 6 }}>
                              <input
                                type="date"
                                aria-label={`${it.name} 到期日`}
                                value={draftExpiry[it.code] ?? ''}
                                onChange={(e) => setDraftExpiry({ ...draftExpiry, [it.code]: e.target.value })}
                                style={{ flex: '0 0 132px', height: 30, fontSize: 12 }}
                              />
                              <input
                                placeholder="原因（进审计）"
                                aria-label={`${it.name} 变更原因`}
                                value={draftReason[it.code] ?? ''}
                                onChange={(e) => setDraftReason({ ...draftReason, [it.code]: e.target.value })}
                                style={{ height: 30, fontSize: 12 }}
                              />
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )
                })}
              {items.length === 0 && !loading && (
                <tr>
                  <td colSpan={7}>
                    <Empty icon="shield" title="没有读到能力定义" hint="检查迁移 0052 是否已执行。" />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* 平台强制关闭：全平台级，影响所有租户，所以与"单租户覆盖"分开放。
          放在同一行里操作，运营很容易把"给这家关掉"误做成"给所有人关掉"。 */}
      {canWrite && defs.length > 0 && (
        <details style={{ marginTop: 14 }}>
          <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--slate)', padding: '6px 2px' }}>
            平台强制关闭（全平台级，谨慎使用）
          </summary>
          <div style={{ marginTop: 10 }}>
            <Panel body="none">
              <div style={{ padding: '12px 16px' }}>
                <Note tone="warn" icon="alert">
                  这里关闭的是<b>所有租户</b>的该项能力，优先级高于任何特批。
                  用于合规下线或重大故障止损；解除后各租户回到原有授权。
                </Note>
              </div>
              {items.filter((it) => defs.find((d) => d.code === it.code)?.platformLockable).map((it) => (
                <div className="pf-row" key={'lock-' + it.code}>
                  <div className="pf-row-main">
                    <div className="t">{it.name}</div>
                    <div className="s">
                      <code style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{it.code}</code>
                      {it.locked && <span>· 已强制关闭：{it.lockReason || '合规下线'}</span>}
                    </div>
                  </div>
                  <div className="pf-row-acts">
                    {it.locked ? (
                      <button className="sm" disabled={!!busy} onClick={() => void toggleLock(it, false)}>解除</button>
                    ) : (
                      <button className="sm danger" disabled={!!busy} onClick={() => void toggleLock(it, true)}>
                        全平台关闭
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </Panel>
          </div>
        </details>
      )}
    </>
  )
}
