// 平台运营 · 租户详情（整页）
//
// 为什么是整页而不是抽屉：
//   1. 详情要同时看档位、配额、域名、开关、用量——抽屉宽 460px 装不下，只能堆成一条长滚动；
//   2. 抽屉必须配全屏遮罩，而遮罩会把背后的列表一起压暗，运营想"对着列表改下一家"就得反复开关；
//   3. 地址要能发给同事（docs/24 地址即状态）：/platform/tenants/{slug} 本身就是这个页面。
//
// 数据加载用 allSettled 并行：此前是 5 个串行 await，任何一个失败整页空白，
// 而且第一个慢请求会把后面全堵住。现在某一块读不到只影响那一块，并明确说是哪块。

import { useCallback, useEffect, useMemo, useState } from 'react'
import { call, token, ApiError } from './api'
import { AddDomainModal, DnsModal, type DnsRecord } from './modals'
import { Alert, Empty, Modal, Note, PageHead, Panel, PfIcon, useConfirm } from './ui'
import {
  EDITION_TEXT, STATUS_TEXT, flagSourceText, fmtBytes, fmtDate, fmtTime,
  type Domain, type EditionInfo, type Quota, type Tenant, type TenantFlag,
  type TenantFlagResp, type UsagePoint,
} from './types'

// 平台侧可调整的系统管理员（只有密级，不含口令——平台不得接管客户账号）。
type PlatformAdmin = {
  id: string
  username: string
  displayName: string
  status: string
  classification: number
  ceiling: number
  lastLoginAt: string | null
}

type Props = {
  slug: string
  canWrite: boolean
  onBack: () => void
  onChanged: () => void
  flash: (m: string) => void
}

const METRIC_TEXT: Record<string, string> = {
  api_calls: '接口调用',
  transcode_seconds: '转码时长',
  share_views: '外链访问',
  preview_renders: '预览渲染',
  egress_bytes: '出流量',
}

const ON_EXCEED_TEXT: Record<string, string> = {
  reject: '拒绝写入（硬拦）',
  readonly: '降级为只读',
  warn: '仅告警',
}

export default function TenantDetail({ slug, canWrite, onBack, onChanged, flash }: Props) {
  const [tenant, setTenant] = useState<Tenant | null>(null)
  const [quota, setQuota] = useState<Quota | null>(null)
  const [edition, setEdition] = useState<EditionInfo | null>(null)
  const [domains, setDomains] = useState<Domain[]>([])
  const [flags, setFlags] = useState<TenantFlag[]>([])
  const [usage, setUsage] = useState<UsagePoint[]>([])
  const [snapshot, setSnapshot] = useState<{ storageBytes: number; activeUsers: number; files: number } | null>(null)

  // 系统管理员密级：可选集合由服务端按档位给（不在前端复制"档位→密级"的对应关系），
  // 否则迟早出现"下拉里有、提交被拒"。
  const [admins, setAdmins] = useState<PlatformAdmin[] | null>(null)
  const [adminLevels, setAdminLevels] = useState<number[]>([])
  const [adminClassDraft, setAdminClassDraft] = useState<Record<string, number>>({})
  const [adminReason, setAdminReason] = useState('')

  const [loading, setLoading] = useState(true)
  const [loadErr, setLoadErr] = useState('')
  const [actionErr, setActionErr] = useState('')
  const [busy, setBusy] = useState('')

  // 档位草稿
  const [editionDraft, setEditionDraft] = useState('basic')
  const [expiresDraft, setExpiresDraft] = useState('')
  const [reasonDraft, setReasonDraft] = useState('')

  // 租户审计：**不自动加载**。平台读一次就会在客户审计链里写一条 platform.access，
  // 每次进详情页都自动拉等于把客户的审计刷满噪音，运营自己也更难找到真事件。
  const [auditEvents, setAuditEvents] = useState<
    { seq: number; actorType: string; action: string; result: string; createdAt: string }[] | null
  >(null)
  const [auditBusy, setAuditBusy] = useState(false)
  const [auditErr, setAuditErr] = useState('')

  const [addingDomain, setAddingDomain] = useState(false)
  const [dns, setDns] = useState<{ host: string; rec: DnsRecord } | null>(null)
  const [certFor, setCertFor] = useState<string | null>(null)

  const { ask, dialog } = useConfirm()

  const load = useCallback(async () => {
    setLoading(true)
    setLoadErr('')
    const d = (days: number) => {
      const to = new Date()
      const from = new Date(to.getTime() - days * 86400000)
      return `from=${from.toISOString().slice(0, 10)}&to=${to.toISOString().slice(0, 10)}`
    }
    const [t, q, ed, dm, fl, us, ad] = await Promise.allSettled([
      call<Tenant>(`/tenants/${slug}`),
      call<Quota>(`/tenants/${slug}/quota`),
      call<EditionInfo>(`/tenants/${slug}/edition`),
      call<{ items: Domain[] }>(`/tenants/${slug}/domains`),
      call<TenantFlagResp>(`/tenants/${slug}/flags`),
      call<{ points: UsagePoint[]; snapshot: { storageBytes: number; activeUsers: number; files: number } }>(
        `/tenants/${slug}/usage?${d(30)}`,
      ),
      call<{ items: PlatformAdmin[]; classificationLevels: number[] }>(`/tenants/${slug}/admins`),
    ])

    // 分别落地：某一块失败时其余仍然显示，并把"哪几块没读到"说清楚。
    const failed: string[] = []
    if (t.status === 'fulfilled') setTenant(t.value)
    else failed.push('租户基本信息')

    if (q.status === 'fulfilled') setQuota(q.value)
    else failed.push('配额')

    if (ed.status === 'fulfilled') {
      setEdition(ed.value)
      setEditionDraft(ed.value.edition)
      setExpiresDraft(ed.value.expiresAt ? ed.value.expiresAt.slice(0, 10) : '')
      setReasonDraft('')
    } else failed.push('档位')

    if (dm.status === 'fulfilled') setDomains(dm.value.items ?? [])
    else failed.push('域名')

    if (fl.status === 'fulfilled') setFlags(fl.value.effective ?? [])
    else failed.push('能力开关')

    if (us.status === 'fulfilled') {
      setUsage(us.value.points ?? [])
      setSnapshot(us.value.snapshot ?? null)
    } else failed.push('用量')

    if (ad.status === 'fulfilled') {
      setAdmins(ad.value.items ?? [])
      setAdminLevels(ad.value.classificationLevels)
      const draft: Record<string, number> = {}
      for (const it of ad.value.items ?? []) draft[it.id] = it.classification
      setAdminClassDraft(draft)
    } else failed.push('管理员')

    if (failed.length) {
      const first = [t, q, ed, dm, fl, us, ad].find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined
      const msg = first?.reason instanceof ApiError ? `（${first.reason.message}）` : ''
      setLoadErr(`以下数据读取失败：${failed.join('、')}${msg}`)
    }
    setLoading(false)
  }, [slug])

  useEffect(() => { void load() }, [load])

  // title 也随租户走：运营常开多个标签页对比两家客户。
  // 卸载时必须恢复，否则返回列表后标签页还挂着上一家的名字，容易误判自己在看谁。
  useEffect(() => {
    document.title = tenant ? `${tenant.name} · 平台运营控制台` : '平台运营控制台'
    return () => { document.title = '平台运营控制台' }
  }, [tenant])

  async function act(key: string, fn: () => Promise<void>) {
    setBusy(key)
    setActionErr('')
    try {
      await fn()
    } catch (e) {
      setActionErr(e instanceof ApiError || e instanceof Error ? e.message : '操作失败')
    } finally {
      setBusy('')
    }
  }

  // ---------------- 档位 ----------------

  function saveEdition() {
    if (!tenant) return
    const label = EDITION_TEXT[editionDraft] ?? editionDraft
    const order = ['basic', 'professional', 'business']
    const down = edition && order.indexOf(editionDraft) < order.indexOf(edition.edition)
    const run = () => act('edition', async () => {
      const body: Record<string, unknown> = { edition: editionDraft, reason: reasonDraft }
      if (expiresDraft) {
        // 到期日按当天 23:59:59 算，避免"选了今天就当场失效"的歧义
        body.expiresAt = new Date(expiresDraft + 'T23:59:59').toISOString()
      }
      try {
        await call(`/tenants/${slug}/edition`, { method: 'PUT', body: JSON.stringify(body) })
      } catch (e) {
        if (e instanceof ApiError && e.code === 'EDITION_DOWNGRADE_BLOCKED') {
          const d = e.data as { blockedCount?: number; samples?: string[] } | undefined
          const names = d?.samples?.length ? `受影响示例：${d.samples.join('、')}` : ''
          throw new Error(`${e.message}${names ? '。' + names : ''}`)
        }
        throw e
      }
      flash(`档位已改为「${label}」${expiresDraft ? `，到期 ${expiresDraft}` : '，不限期'}`)
      await load()
      onChanged()
    })

    if (down) {
      ask({
        title: '确认降档',
        body: (
          <>
            <p style={{ marginTop: 0 }}>
              将「{tenant.name}」从 <b>{EDITION_TEXT[edition!.edition] ?? edition!.edition}</b> 降为 <b>{label}</b>。
            </p>
            <p style={{ marginBottom: 0 }}>
              降档会立即收回对应能力。如果存量数据无法被目标档位表达（例如存在高档位密级），
              服务端会拒绝并给出受影响清单，不会"先降后报错"。
            </p>
          </>
        ),
        confirmText: '确认降档',
        danger: true,
        onConfirm: run,
      })
      return
    }
    void run()
  }

  // ---------------- 配额 ----------------

  function saveQuota() {
    if (!quota) return
    void act('quota', async () => {
      await call(`/tenants/${slug}/quota`, { method: 'PUT', body: JSON.stringify(quota) })
      flash('配额已保存（立即生效）')
      await load()
    })
  }

  // ---------------- 开关 ----------------

  // ---------------- 系统管理员密级 ----------------
  // 只改"人的密级"，不改口令、不改角色：平台能改口令就等于能接管客户账号（docs/55 §6）。
  function saveAdminClass(a: PlatformAdmin) {
    const want = adminClassDraft[a.id] ?? a.classification
    if (want === a.classification) {
      flash('密级没有变化')
      return
    }
    return act('adminclass', async () => {
      await call(`/tenants/${slug}/admins/${a.id}/classification`, {
        method: 'PUT',
        body: JSON.stringify({ classification: want, reason: adminReason.trim() }),
      })
      flash(`已把 ${a.username} 的密级改为 ${want} 级`)
      setAdminReason('')
      await load()
      onChanged()
    })
  }

  function setFlag(f: TenantFlag, enabled: boolean | null) {
    void act('flag:' + f.code, async () => {
      if (enabled === null) {
        await call(`/tenants/${slug}/flags/${f.code}`, { method: 'DELETE' })
      } else {
        await call(`/tenants/${slug}/flags/${f.code}`, {
          method: 'PUT', body: JSON.stringify({ enabled }),
        })
      }
      const tf = await call<TenantFlagResp>(`/tenants/${slug}/flags`)
      setFlags(tf.effective ?? [])
      flash(enabled === null ? '已恢复平台策略（30 秒内生效）' : '本租户开关已更新（30 秒内生效）')
    })
  }

  // ---------------- 域名 ----------------

  function verifyDomain(host: string) {
    void act('verify:' + host, async () => {
      await call(`/tenants/${slug}/domains/${encodeURIComponent(host)}/verify`, { method: 'POST' })
      flash('域名已验证')
      await load()
    })
  }

  function removeDomain(host: string) {
    ask({
      title: '解绑域名',
      body: <>解绑 <b>{host}</b> 会同时删除已保存的证书，该地址立刻无法访问。</>,
      confirmText: '解绑',
      danger: true,
      onConfirm: () => act('rm:' + host, async () => {
        await call(`/tenants/${slug}/domains/${encodeURIComponent(host)}`, { method: 'DELETE' })
        flash('已解绑')
        await load()
      }),
    })
  }

  // ---------------- 租户审计（按需） ----------------

  async function loadAudit() {
    setAuditBusy(true)
    setAuditErr('')
    try {
      const r = await call<{
        items: { seq: number; actorType: string; action: string; result: string; createdAt: string }[]
      }>(`/tenants/${slug}/audit/events`)
      setAuditEvents(r.items ?? [])
    } catch (e) {
      setAuditErr(e instanceof Error ? e.message : '读取审计失败')
    } finally {
      setAuditBusy(false)
    }
  }

  // ---------------- 租户状态 ----------------

  function patchStatus(status: string) {
    if (!tenant) return
    const label = STATUS_TEXT[status] ?? status
    const run = () => act('status', async () => {
      await call(`/tenants/${slug}`, { method: 'PATCH', body: JSON.stringify({ status }) })
      flash(`已置为「${label}」`)
      await load()
      onChanged()
    })
    if (status === 'suspended') {
      ask({
        title: '停用租户',
        body: <>停用「{tenant.name}」会<b>立即吊销该租户全部已登录会话</b>，成员无法再登录。数据保留。</>,
        confirmText: '停用',
        danger: true,
        onConfirm: run,
      })
      return
    }
    void run()
  }

  function deleteTenant() {
    if (!tenant) return
    ask({
      title: '逻辑删除租户',
      body: (
        <>
          将「{tenant.name}」（<code>{tenant.slug}</code>）标记为已删除，
          <b>数据保留 30 天</b>，期间可由平台恢复。30 天后进入清理流程。
        </>
      ),
      confirmText: '删除',
      danger: true,
      onConfirm: () => act('delete', async () => {
        await call(`/tenants/${slug}`, { method: 'DELETE' })
        flash('已逻辑删除，保留期 30 天')
        onChanged()
        onBack()
      }),
    })
  }

  // ---------------- 对账单下载 ----------------
  //
  // 不能用 call()：那个函数会对响应做 json()，而这里是 CSV，直接抛
  // "Unexpected token" 之类的解析错误（后端能力存在、前端却从未接上）。
  async function downloadInvoice() {
    setActionErr('')
    try {
      const month = new Date().toISOString().slice(0, 7)
      const resp = await fetch(
        `/v1/platform/tenants/${encodeURIComponent(slug)}/invoice.csv?month=${month}`,
        { headers: token() ? { Authorization: `Bearer ${token()}` } : {} },
      )
      if (!resp.ok) {
        const b = await resp.json().catch(() => ({}))
        throw new Error(b.message ?? '导出失败')
      }
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `usage-${slug}-${month}.csv`
      document.body.appendChild(a)
      a.click()
      a.remove()
      // revoke 要延后：立刻撤销会让部分浏览器拿到空文件
      window.setTimeout(() => URL.revokeObjectURL(url), 4000)
      flash('对账单已导出（CSV，可用 Excel 打开）')
    } catch (e) {
      setActionErr(e instanceof Error ? e.message : '导出失败')
    }
  }

  const usageRows = useMemo(() => {
    const byMetric = new Map<string, UsagePoint[]>()
    for (const p of usage) {
      const arr = byMetric.get(p.metric) ?? []
      arr.push(p)
      byMetric.set(p.metric, arr)
    }
    return [...byMetric.entries()].map(([metric, pts]) => {
      const sorted = [...pts].sort((a, b) => a.day.localeCompare(b.day))
      const last = sorted.slice(-14)
      const total = sorted.reduce((s, p) => s + p.quantity, 0)
      const peak = Math.max(1, ...last.map((p) => p.quantity))
      return { metric, total, last, peak }
    })
  }, [usage])

  const statusBadge = tenant
    ? (tenant.status === 'active' ? 'ok' : tenant.status === 'suspended' ? 'danger' : 'warn')
    : 'plain'

  return (
    <>
      <PageHead
        crumbs={
          <div className="pf-crumbs" style={{ marginBottom: 6 }}>
            <button className="pf-link" onClick={onBack}>租户</button>
            <span className="sep">/</span>
            <span>{tenant?.name ?? slug}</span>
          </div>
        }
        title={tenant?.name ?? slug}
        sub={
          <>
            <code style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{slug}</code>
            {tenant && <span className={`badge ${statusBadge}`} style={{ marginLeft: 8 }}>
              {STATUS_TEXT[tenant.status] ?? tenant.status}
            </span>}
            {loading && <span style={{ marginLeft: 8 }}>读取中…</span>}
          </>
        }
        actions={
          <>
            <button onClick={onBack} disabled={!!busy}>
              <PfIcon name="back" />返回列表
            </button>
            <button onClick={() => void downloadInvoice()}>
              <PfIcon name="down" />导出对账单
            </button>
            {canWrite && tenant?.status === 'suspended' && (
              <button onClick={() => patchStatus('active')} disabled={!!busy}>恢复</button>
            )}
            {canWrite && tenant?.status === 'active' && (
              <button onClick={() => patchStatus('readonly')} disabled={!!busy}>设为只读</button>
            )}
            {canWrite && tenant?.status !== 'suspended' && (
              <button className="danger" onClick={() => patchStatus('suspended')} disabled={!!busy}>停用</button>
            )}
            {canWrite && (
              <button className="danger" onClick={deleteTenant} disabled={!!busy}>删除</button>
            )}
          </>
        }
      />

      {loadErr && <Alert text={loadErr} onClose={() => setLoadErr('')} />}
      {actionErr && <Alert text={actionErr} onClose={() => setActionErr('')} />}

      <div className="pf-detail">
        {/* -------- 主列 -------- */}
        <div className="pf-col">
          <Panel
            title="档位与到期"
            sub={edition ? `当前：${EDITION_TEXT[edition.edition] ?? edition.edition}` : undefined}
            actions={edition?.changes?.length ? <span className="hint">共 {edition.changes.length} 次变更</span> : undefined}
          >
            {!edition && <div className="hint">读取中…</div>}
            {edition && (
              <div className="pf-form">
                <div className="pf-grid3">
                  <div className="field">
                    <label htmlFor="ed-edition">档位</label>
                    <select
                      id="ed-edition" value={editionDraft} disabled={!canWrite}
                      onChange={(e) => setEditionDraft(e.target.value)}
                    >
                      <option value="basic">基础版</option>
                      <option value="professional">专业版</option>
                      <option value="business">旗舰版</option>
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="ed-exp">到期日</label>
                    <input
                      id="ed-exp" type="date" value={expiresDraft} disabled={!canWrite}
                      onChange={(e) => setExpiresDraft(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="ed-reason">变更原因</label>
                    <input
                      id="ed-reason" value={reasonDraft} disabled={!canWrite}
                      placeholder="如：2027 年续签" onChange={(e) => setReasonDraft(e.target.value)}
                    />
                  </div>
                </div>
                <Note>
                  改档立即生效（客户下次请求即按新档位判定）。到期日留空表示不限期；
                  到期后进入宽限期，宽限结束按合同约定处理。<b>变更原因会进平台审计</b>，
                  客户来问"为什么能力没了"时按时间能对上。
                </Note>
                <div className="pf-actions">
                  <button
                    className="primary" disabled={!canWrite || busy === 'edition'}
                    onClick={saveEdition}
                  >
                    {busy === 'edition' ? '保存中…' : '保存档位'}
                  </button>
                </div>
                {edition.changes && edition.changes.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <div className="hint" style={{ marginBottom: 6 }}>最近变更</div>
                    {edition.changes.slice(0, 5).map((c, i) => (
                      <div key={i} className="pf-row" style={{ paddingLeft: 0, paddingRight: 0 }}>
                        <div className="pf-row-main">
                          <div className="t">
                            {c.fromEdition ? `${EDITION_TEXT[c.fromEdition] ?? c.fromEdition} → ` : ''}
                            <b>{EDITION_TEXT[c.toEdition] ?? c.toEdition}</b>
                          </div>
                          <div className="s">
                            {fmtTime(c.createdAt)}
                            {c.operator && ` · ${c.operator}`}
                            {c.reason && ` · ${c.reason}`}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Panel>

          <Panel title="配额" sub="留空表示不限">
            {!quota && <div className="hint">读取中…</div>}
            {quota && (
              <div className="pf-form">
                <div className="pf-grid2">
                  <div className="field">
                    <label htmlFor="q-users">用户数上限</label>
                    <input
                      id="q-users" type="number" min={0} disabled={!canWrite}
                      value={quota.maxUsers ?? ''}
                      onChange={(e) => setQuota({
                        ...quota, maxUsers: e.target.value === '' ? null : Number(e.target.value),
                      })}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="q-storage">存储上限（GB）</label>
                    <input
                      id="q-storage" type="number" min={0} step={0.5} disabled={!canWrite}
                      value={quota.maxStorageBytes == null ? '' : quota.maxStorageBytes / (1024 ** 3)}
                      onChange={(e) => setQuota({
                        ...quota,
                        maxStorageBytes: e.target.value === ''
                          ? null
                          : Math.round(Number(e.target.value) * 1024 ** 3),
                      })}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="q-transcode">转码时长上限（秒/月）</label>
                    <input
                      id="q-transcode" type="number" min={0} disabled={!canWrite}
                      value={quota.maxTranscodeSeconds ?? ''}
                      onChange={(e) => setQuota({
                        ...quota,
                        maxTranscodeSeconds: e.target.value === '' ? null : Number(e.target.value),
                      })}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="q-api">接口调用上限（次/日）</label>
                    <input
                      id="q-api" type="number" min={0} disabled={!canWrite}
                      value={quota.maxApiCallsDay ?? ''}
                      onChange={(e) => setQuota({
                        ...quota, maxApiCallsDay: e.target.value === '' ? null : Number(e.target.value),
                      })}
                    />
                  </div>
                </div>
                <div className="field" style={{ maxWidth: 280 }}>
                  <label htmlFor="q-exceed">超限行为</label>
                  <select
                    id="q-exceed" value={quota.onExceed} disabled={!canWrite}
                    onChange={(e) => setQuota({ ...quota, onExceed: e.target.value })}
                  >
                    <option value="reject">{ON_EXCEED_TEXT.reject}</option>
                    <option value="readonly">{ON_EXCEED_TEXT.readonly}</option>
                    <option value="warn">{ON_EXCEED_TEXT.warn}</option>
                  </select>
                </div>
                <div className="pf-actions">
                  <button className="primary" disabled={!canWrite || busy === 'quota'} onClick={saveQuota}>
                    {busy === 'quota' ? '保存中…' : '保存配额'}
                  </button>
                </div>
              </div>
            )}
          </Panel>

          <Panel
            title="系统管理员密级"
            sub="决定该账号能创建/接管多高密级的账号；可设范围由租户档位决定"
          >
            {admins === null && <div className="hint">读取中…</div>}
            {admins !== null && admins.length === 0 && (
              <div className="hint">该租户没有系统管理员，无法在此调整。</div>
            )}
            {admins !== null && admins.length > 0 && (
              <div className="pf-form">
                {admins.map((a) => {
                  const draft = adminClassDraft[a.id] ?? a.classification
                  return (
                    <div
                      key={a.id}
                      style={{
                        display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 150px auto',
                        gap: 12, alignItems: 'end',
                      }}
                    >
                      <div>
                        <b style={{ fontSize: 13 }}>{a.displayName || a.username}</b>
                        <div className="hint" style={{ marginTop: 2 }}>
                          <code>{a.username}</code>
                          {a.status !== 'active' && (
                            <span className="badge warn" style={{ marginLeft: 6 }}>已停用</span>
                          )}
                        </div>
                      </div>
                      <div className="field">
                        <label htmlFor={`ac-${a.id}`}>密级</label>
                        <select
                          id={`ac-${a.id}`}
                          value={draft}
                          disabled={!canWrite || busy === 'adminclass'}
                          onChange={(e) => setAdminClassDraft({ ...adminClassDraft, [a.id]: Number(e.target.value) })}
                        >
                          {adminLevels.map((v) => (
                            <option key={v} value={v}>{v} 级</option>
                          ))}
                          {adminLevels.length === 0 && <option value={a.classification}>{a.classification} 级（本档位不可调）</option>}
                        </select>
                      </div>
                      <button
                        className="primary"
                        style={{ height: 34, marginBottom: 1 }}
                        disabled={!canWrite || busy === 'adminclass' || draft === a.classification}
                        onClick={() => void saveAdminClass(a)}
                      >
                        {busy === 'adminclass' ? '保存中…' : '保存密级'}
                      </button>
                    </div>
                  )
                })}
                <div className="field">
                  <label htmlFor="ac-reason">调整原因（可选，写入平台与租户审计）</label>
                  <input
                    id="ac-reason"
                    value={adminReason}
                    placeholder="例如：客户要求给负责人开放核心级，工单 TCK-1234"
                    onChange={(e) => setAdminReason(e.target.value)}
                    disabled={!canWrite}
                  />
                </div>
                <div className="hint">
                  只能调<b>系统管理员</b>；密级受档位限制（基础版只能 0 级，专业版 0/3/4，旗舰版 0–6）。
                  平台<b>不提供</b>重置口令——那是接管客户账号，不属于运营能力。
                </div>
              </div>
            )}
          </Panel>

          <Panel
            title="自有域名"
            sub="证书可由租户在管理台上传/自动签发，也可由运营代为上传"
            actions={
              <button
                className="primary sm" disabled={!canWrite}
                onClick={() => setAddingDomain(true)}
              >
                <PfIcon name="plus" size={14} />绑定域名
              </button>
            }
            body="none"
          >
            {domains.length === 0 && (
              <Empty
                icon="device"
                title="尚未绑定自有域名"
                hint="绑定后客户可用自己的域名访问，证书需要另行准备（上传或自动签发）。"
              />
            )}
            {domains.map((d) => (
              <div className="pf-row" key={d.host}>
                <div className="pf-row-main">
                  <div className="t">
                    {d.host}
                    {d.primary && <span className="badge brand" style={{ marginLeft: 7 }}>主域名</span>}
                  </div>
                  <div className="s">
                    {d.verified
                      ? <span className="badge ok">已验证</span>
                      : <span className="badge warn">待验证归属</span>}
                    {d.hasCert
                      ? <span className="badge teal">
                        证书至 {fmtDate(d.certNotAfter)}
                      </span>
                      : <span className="badge plain">无证书</span>}
                  </div>
                </div>
                <div className="pf-row-acts">
                  {!d.verified && (
                    <button className="sm" disabled={!canWrite || busy === 'verify:' + d.host}
                      onClick={() => verifyDomain(d.host)}>
                      {busy === 'verify:' + d.host ? '验证中…' : '验证归属'}
                    </button>
                  )}
                  <button className="sm" disabled={!canWrite || !d.verified}
                    onClick={() => setCertFor(d.host)}>上传证书</button>
                  <button className="sm danger" disabled={!canWrite} onClick={() => removeDomain(d.host)}>
                    解绑
                  </button>
                </div>
              </div>
            ))}
          </Panel>

          <Panel
            title="按租户覆盖的功能开关"
            sub="只影响当前租户，不改全局放量"
            body="none"
          >
            {flags.length === 0 && <div className="hint" style={{ padding: 16 }}>读取中…</div>}
            {flags.map((f) => (
              <div className="pf-row" key={f.code}>
                <div className="pf-row-main">
                  <div className="t">{f.description}</div>
                  <div className="s">
                    <code style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{f.code}</code>
                    <span>·</span>
                    <span>{flagSourceText(f)}</span>
                    {f.source !== 'override' && !f.defaultEnabled && <span>· 平台总开关已关闭</span>}
                  </div>
                </div>
                <div className="pf-row-acts">
                  <span className={`badge ${f.enabled ? 'ok' : 'plain'}`}>
                    {f.enabled ? '已开启' : '已关闭'}
                  </span>
                  {f.enabled
                    ? <button className="sm danger" disabled={!canWrite || !!busy}
                      onClick={() => setFlag(f, false)}>关闭</button>
                    : <button className="sm" disabled={!canWrite || !!busy}
                      onClick={() => setFlag(f, true)}>开通</button>}
                  {f.source === 'override' && (
                    <button className="sm ghost" disabled={!canWrite || !!busy}
                      onClick={() => setFlag(f, null)}>恢复默认</button>
                  )}
                </div>
              </div>
            ))}
            <div style={{ padding: '10px 16px', borderTop: '1px solid var(--line-soft)' }}>
              <Note>
                平台整体暂停（放量 0%）时，可在这里为个别客户单独开通——合规场景最常用：
                <b>默认全关，按合同逐个开</b>。
              </Note>
            </div>
          </Panel>
        </div>

        {/* -------- 侧列 -------- */}
        <div className="pf-col">
          <Panel title="概览">
            <div className="pf-dl">
              <div><dt>租户标识</dt><dd className="mono">{slug}</dd></div>
              <div><dt>状态</dt><dd>{tenant ? (STATUS_TEXT[tenant.status] ?? tenant.status) : '—'}</dd></div>
              <div><dt>创建时间</dt><dd>{fmtTime(tenant?.createdAt ?? null)}</dd></div>
              <div><dt>档位到期</dt><dd>{fmtDate(tenant?.editionExpiresAt ?? null)}</dd></div>
              <div><dt>试用结束</dt><dd>{fmtDate(tenant?.trialEndsAt ?? null)}</dd></div>
              <div><dt>删除保留期</dt><dd>{fmtDate(tenant?.retentionUntil ?? null)}</dd></div>
              <div style={{ gridColumn: '1 / -1' }}>
                <dt>联系邮箱</dt>
                <dd>{tenant?.contactEmail || '—'}</dd>
              </div>
            </div>
          </Panel>

          <Panel title="实时规模">
            <div className="pf-dl" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))' }}>
              <div><dt>用户</dt><dd style={{ fontSize: 19, fontWeight: 600 }}>{tenant?.users ?? '—'}</dd></div>
              <div><dt>文件</dt><dd style={{ fontSize: 19, fontWeight: 600 }}>{tenant?.files ?? '—'}</dd></div>
              <div><dt>存储</dt><dd style={{ fontSize: 19, fontWeight: 600 }}>{fmtBytes(tenant?.storageBytes ?? 0)}</dd></div>
            </div>
            {snapshot && (
              <div className="hint" style={{ marginTop: 10 }}>
                用量接口快照：{snapshot.activeUsers} 人 · {snapshot.files} 文件 · {fmtBytes(snapshot.storageBytes)}
              </div>
            )}
          </Panel>

          <Panel
            title="租户最近操作"
            sub="来自该租户自己的审计链"
            actions={
              <button className="sm" disabled={auditBusy} onClick={() => void loadAudit()}>
                {auditBusy ? '读取中…' : auditEvents ? '刷新' : '读取'}
              </button>
            }
            body="none"
          >
            {!auditEvents && !auditErr && (
              <div style={{ padding: 16 }}>
                <Note icon="alert">
                  客户说"文件少了""权限被改了"，先看这里。注意：
                  <b>每次读取都会在客户的审计链里留下一条</b>「平台方读取过」的记录，
                  所以它不会自动加载，需要时点一下。
                </Note>
              </div>
            )}
            {auditErr && <div style={{ padding: 16 }}><Note tone="danger">{auditErr}</Note></div>}
            {auditEvents?.length === 0 && (
              <Empty icon="list" title="没有审计事件" hint="该租户还没有产生需要留痕的操作。" />
            )}
            {/* 只显示最近 20 条：接口一次给 100 条，全铺在侧列里会把页面拉到几千像素，
                运营反而看不到下面的用量。真要看全量应该回租户的管理台。 */}
            {auditEvents && auditEvents.length > 20 && (
              <div className="hint" style={{ padding: '8px 16px', borderBottom: '1px solid var(--line-soft)' }}>
                显示最近 20 条，共 {auditEvents.length} 条
              </div>
            )}
            {auditEvents?.slice(0, 20).map((e) => (
              <div className="pf-row" key={e.seq}>
                <div className="pf-row-main">
                  <div className="t">
                    <code style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{e.action}</code>
                  </div>
                  <div className="s">
                    {fmtTime(e.createdAt)}
                    {' · '}
                    {e.actorType === 'external' ? '外部访客' : e.actorType === 'system' ? '系统' : '成员'}
                    {' · #'}{e.seq}
                  </div>
                </div>
                <div className="pf-row-acts">
                  <span className={`badge ${e.result === 'ok' ? 'ok' : 'danger'}`}>{e.result}</span>
                </div>
              </div>
            ))}
          </Panel>

          <Panel title="近 30 天用量" sub="按指标汇总" body="none">
            {usageRows.length === 0 && (
              <Empty icon="chart" title="暂无计量数据" hint="该租户本月还没有产生可计量的调用。" />
            )}
            {usageRows.map((r) => (
              <div className="pf-row" key={r.metric} style={{ alignItems: 'flex-start' }}>
                <div className="pf-row-main">
                  <div className="t">
                    {METRIC_TEXT[r.metric] ?? r.metric}
                    <span style={{ color: 'var(--slate)', fontSize: 12, marginLeft: 6 }}>
                      {r.total.toLocaleString('zh-CN')}
                    </span>
                  </div>
                  {/* 迷你柱：只表达"哪天有峰"，不追求精确读数——精确值在 CSV 里 */}
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 22, marginTop: 6 }}>
                    {r.last.map((p) => (
                      <div
                        key={p.day}
                        title={`${p.day}：${p.quantity.toLocaleString('zh-CN')}`}
                        style={{
                          flex: '1 1 0',
                          minWidth: 3,
                          height: Math.max(2, Math.round((p.quantity / r.peak) * 22)),
                          background: 'var(--forest)',
                          opacity: .55,
                          borderRadius: 1,
                        }}
                      />
                    ))}
                  </div>
                </div>
              </div>
            ))}
            {usageRows.length > 0 && (
              <div style={{ padding: '10px 16px', borderTop: '1px solid var(--line-soft)' }}>
                <button className="sm" onClick={() => void downloadInvoice()}>
                  <PfIcon name="down" size={13} />导出本月对账单（CSV）
                </button>
              </div>
            )}
          </Panel>
        </div>
      </div>

      {addingDomain && (
        <AddDomainModal
          slug={slug}
          onClose={() => setAddingDomain(false)}
          onAdded={(host, rec) => {
            setAddingDomain(false)
            setDns({ host, rec })
            void load()
          }}
        />
      )}

      {dns && (
        <DnsModal
          host={dns.host}
          rec={dns.rec}
          onClose={() => setDns(null)}
        />
      )}

      {certFor && (
        <CertModal
          slug={slug}
          host={certFor}
          onClose={() => setCertFor(null)}
          onDone={() => { setCertFor(null); flash('证书已保存'); void load() }}
        />
      )}

      {dialog}
    </>
  )
}

// ---------------- 证书上传 ----------------

function CertModal({ slug, host, onClose, onDone }:
  { slug: string; host: string; onClose: () => void; onDone: () => void }) {
  const [certPem, setCertPem] = useState('')
  const [keyPem, setKeyPem] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // 支持"从文件读取"：客户拿到的通常是 .crt/.key 文件，让人手工粘贴整段 PEM
  // 是最容易漏掉首尾标记的一步（漏了报"无法解析证书"，看不出缺什么）。
  async function readFile(file: File, into: 'cert' | 'key') {
    const text = await file.text()
    if (into === 'cert') setCertPem(text)
    else setKeyPem(text)
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await call(`/tenants/${slug}/domains/${encodeURIComponent(host)}/certificate`, {
        method: 'PUT',
        body: JSON.stringify({ certPem, keyPem }),
      })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={`上传证书 · ${host}`} onClose={onClose}>
      <form className="pf-form" onSubmit={submit}>
        <Note icon="alert">
          必须是<b>覆盖该域名</b>的证书（含中间证书链更佳）。私钥会加密保存，
          保存后界面不再显示，也不会进入审计日志。
        </Note>
        <div className="field">
          <label htmlFor="crt">证书（PEM）</label>
          <input
            id="crt-file" type="file" accept=".crt,.pem,.cer,.txt"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void readFile(f, 'cert') }}
          />
          <textarea
            id="crt" rows={5} required value={certPem} spellCheck={false}
            placeholder="-----BEGIN CERTIFICATE-----"
            style={{ fontFamily: 'var(--mono)', fontSize: 12 }}
            onChange={(e) => setCertPem(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="key">私钥（PEM）</label>
          <input
            id="key-file" type="file" accept=".key,.pem,.txt"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void readFile(f, 'key') }}
          />
          <textarea
            id="key" rows={5} required value={keyPem} spellCheck={false}
            placeholder="-----BEGIN PRIVATE KEY-----"
            style={{ fontFamily: 'var(--mono)', fontSize: 12 }}
            onChange={(e) => setKeyPem(e.target.value)}
          />
        </div>
        {err && <Note tone="danger">{err}</Note>}
        <div className="pf-actions">
          <button type="button" onClick={onClose} disabled={busy}>取消</button>
          <button className="primary" type="submit" disabled={busy || !certPem || !keyPem}>
            {busy ? '保存中…' : '保存证书'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
