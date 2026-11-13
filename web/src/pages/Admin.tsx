import { useCallback, useEffect, useMemo, useState } from 'react'
import Members from './Members'
import ActivityTable from './ActivityTable'
import DirectorySettings from './DirectorySettings'
import { adminPath, navigate } from '../router'
import { api, postJSON, fetchMe, applyTheme, cycleTheme, HttpError, type Me } from '../api'
import { Shell } from '../components/Shell'
import { AdminSpaces } from './AdminSpaces'
import { Icon, InfoDot } from '../components/ui'

type Summary = { users: number; spaces: number; nodes: number; files: number; usedBytes: number; generatedAt: string }
type RoleDef = { code: string; name: string; description: string }
type AuditEvent = {
  seq: number
  actorId: string
  actorType: string
  action: string
  objectId: string
  result: string
  ip: string
  createdAt: string
  detail?: Record<string, unknown>
}
type ClassLabel = { level: number; name: string; description: string }
type ClassRequest = {
  id: string
  nodeId: string
  nodeName: string
  fromLevel: number
  toLevel: number
  reason: string
  status: string
  requestedBy: string
  createdAt: string
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

function resultBadge(r: string) {
  const cls = r === 'ok' ? 'ok' : r === 'denied' ? 'danger' : 'warn'
  const text = r === 'ok' ? '成功' : r === 'denied' ? '拒绝' : '异常'
  return <span className={`badge ${cls}`}>{text}</span>
}

type TabKey = 'overview' | 'members' | 'spaces' | 'directory' | 'audit' | 'logs' | 'settings' | 'class' | 'policy' | 'approval' | 'share-approvals'

// 待审批的外发链接。
//
// 这里没有"审批人"字段：谁能审批由服务端按对象权限逐条算，
// 列表返回的就是"你有权处置的那几条"，因此不需要再让用户挑审批人。
type ShareApproval = {
  shareId: string
  objectType: string
  name: string
  classification: number
  creator: string
  createdAt: string
  expiresAt: string | null
}

// 租户策略：这里的每一项都真的被读写（写入后立即影响行为），
// 不放"看起来有用但没人读"的开关。
type TenantPolicy = {
  shareDefaultExpireDays: number
  maxUploadMB: number
  auditRetentionDays: number
  // 单个上传请求允许的读取时长（秒）。0/缺省由服务端给默认 300。
  uploadTimeoutSeconds: number
  // 允许上传的扩展名（小写带点）。null/空表示不限制。
  allowedExts: string[] | null
}

// 格式目录来自服务端 /v1/meta/formats。
//
// 为什么不再写在前端：清单本身可以硬编码，但"能不能预览"取决于服务器
// 实际装了什么（LibreOffice 是否就绪、音视频转码是否启用）。
// 前端自己写一份的结果是标着能看、点开 500，而且要到用户点开才发现。
type FormatItem = { ext: string; name: string; preview: 'native' | 'wasm' | 'convert' | 'none' }
type FormatGroup = { label: string; items: FormatItem[] }
type FormatCatalog = {
  groups: FormatGroup[]
  total: number
  viewable: number
  officeReady: boolean
  mediaTranscoder: boolean
}

// previewBadge 把预览能力映射成徽标。
// 文案只回答"能不能看"；具体怎么实现放 title——设置页的主要任务是勾选，
// 不是读技术说明。
function previewBadge(kind: FormatItem['preview']): { text: string; cls: string; tip: string } {
  switch (kind) {
    case 'native':
      return { text: '可预览', cls: 'teal', tip: '浏览器直接显示' }
    case 'wasm':
      return { text: '可预览', cls: 'teal', tip: '浏览器内解码，iPhone 大图约需 10~20 秒' }
    case 'convert':
      return { text: '可预览 · 转码', cls: 'warn', tip: '服务端转换后显示，首次打开较慢' }
    default:
      return { text: '不可预览', cls: 'plain', tip: '只能下载后本地打开' }
  }
}

export default function Admin({ tab: urlTab }: { tab: string }) {
  const [me, setMe] = useState<Me | null>(null)
  // 页签直接来自地址栏，不另存 state。
  //
  // 曾经是 useState(urlTab) + effect 同步：地址变了就 setTab，点页签就 setTab + navigate。
  // 两份真源不会立刻出错，但会在边界上分叉——比如快速连点两个页签时，
  // 最后一次 setState 与最后一次 pushState 的先后不一定与预期一致。
  // 现在只有地址一个真源，navigate 一次就同时更新了 UI 与历史记录。
  const tab = (urlTab || 'overview') as TabKey
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const [summary, setSummary] = useState<Summary | null>(null)
  const [roles, setRoles] = useState<RoleDef[]>([])

  const [events, setEvents] = useState<AuditEvent[]>([])
  const [auditFilter, setAuditFilter] = useState({ action: '', result: '' })
  const [chainOK, setChainOK] = useState<boolean | null>(null)

  const [classes, setClasses] = useState<ClassLabel[]>([])
  const [policies, setPolicies] = useState<Record<string, number>>({})
  const [newPolicy, setNewPolicy] = useState({ label: '', minLevel: 1 })
  const [requests, setRequests] = useState<ClassRequest[]>([])
  const [shareApprovals, setShareApprovals] = useState<ShareApproval[]>([])
  const [tpolicy, setTpolicy] = useState<TenantPolicy>({
    shareDefaultExpireDays: 0, maxUploadMB: 0, auditRetentionDays: 730,
    uploadTimeoutSeconds: 300, allowedExts: null,
  })
  // 服务端下发的格式目录（含预览能力）；拉不到时设置页仍可手填，只是没有勾选列表
  const [catalog, setCatalog] = useState<FormatCatalog | null>(null)

  // ---- 格式白名单的勾选辅助 ----
  const pickedExts = new Set(tpolicy.allowedExts ?? [])
  const setExts = (next: string[] | null) =>
    setTpolicy((p) => ({
      ...p,
      // 空集合落成 null（= 不限制）；留成 [] 会变成"一项都没选、谁都不许传"
      allowedExts: next && next.length ? [...new Set(next)].sort() : null,
    }))
  const allExts = catalog ? catalog.groups.flatMap((g) => g.items.map((i) => i.ext)) : []
  const pickedAll = catalog
    ? catalog.groups.flatMap((g) => g.items).filter((i) => pickedExts.has(i.ext))
    : []
  const pickedViewable = pickedAll.filter((i) => i.preview !== 'none').length

  const myRoles = me?.roles ?? []
  const isSys = myRoles.includes('sysadmin')
  const isSec = myRoles.includes('secadmin')
  const isAud = myRoles.includes('auditor')

  const flash = useCallback((m: string) => {
    setMsg(m)
    window.setTimeout(() => setMsg(''), 2600)
  }, [])

  // 只展示当前角色真正能用的页签：能看不能用比看不到更糟
  const tabs = useMemo(() => {
    const list: { key: TabKey; label: string }[] = []
    if (isSys) list.push({ key: 'overview', label: '概览' }, { key: 'members', label: '成员与角色' }, { key: 'spaces', label: '空间台账' })
    // 操作日志：sysadmin 看全量治理动作，secadmin 只看权限/密级/外发审批
    if (isSys || isAud || isSec) list.push({ key: 'logs', label: '操作日志' })
    // 外发审批对 sysadmin 与 secadmin 都开放：实际能不能批由服务端按
    // 对象级 manage_acl 判定，角色只决定"能不能进到这个页面"。
    if (isSys || isSec) list.push({ key: 'share-approvals', label: '外发审批' })
    if (isSys) list.push({ key: 'settings', label: '系统设置' }, { key: 'directory', label: '目录认证' })
    if (isAud) list.push({ key: 'audit', label: '审计日志' })
    if (isSec) list.push({ key: 'class', label: '密级定义' }, { key: 'policy', label: '标签策略' }, { key: 'approval', label: '降密审批' })
    return list
  }, [isSys, isSec, isAud])

  useEffect(() => {
    applyTheme()
    void fetchMe().then((m) => {
      setMe(m)
      // 默认落在第一个可用页签，并把它写进地址栏
      const rs = m.roles ?? []
      const first: TabKey = rs.includes('sysadmin') ? 'overview'
        : rs.includes('auditor') ? 'audit'
          : rs.includes('secadmin') ? 'class' : 'overview'
      if (!urlTab) {
        navigate(adminPath(first), true)
      }
      // 地址里已经有页签就什么都不用做：tab 是派生值，天然跟着地址走
    }).catch(() => setErr('读取账号信息失败'))
  }, [urlTab])

  function goTab(k: TabKey) {
    navigate(adminPath(k))
  }

  const load = useCallback(async () => {
    setErr('')
    try {
      if (tab === 'overview') {
        setSummary(await api<Summary>('/v1/admin/summary'))
        const r = await api<{ items: RoleDef[] }>('/v1/admin/roles')
        setRoles(r.items ?? [])
      }
      if (tab === 'members') {
        // 成员列表由 Members 组件自己拉（它还要拉部门、做筛选与分页）
        const r = await api<{ items: RoleDef[] }>('/v1/admin/roles')
        setRoles(r.items ?? [])
      }
      if (tab === 'audit') {
        const q = new URLSearchParams()
        if (auditFilter.action) q.set('action', auditFilter.action)
        if (auditFilter.result) q.set('result', auditFilter.result)
        q.set('limit', '100')
        const d = await api<{ items: AuditEvent[] }>(`/v1/admin/audit/events?${q.toString()}`)
        setEvents(d.items ?? [])
      }
      if (tab === 'class' || tab === 'approval') {
        const d = await api<{ items: ClassLabel[] }>('/v1/classifications')
        setClasses(d.items ?? [])
      }
      if (tab === 'policy') {
        const d = await api<{ policies: Record<string, number> }>('/v1/admin/label-policies')
        setPolicies(d.policies ?? {})
      }
      if (tab === 'settings') {
        const d = await api<TenantPolicy>('/v1/admin/policy')
        setTpolicy({
          shareDefaultExpireDays: d.shareDefaultExpireDays ?? 0,
          maxUploadMB: d.maxUploadMB ?? 0,
          auditRetentionDays: d.auditRetentionDays || 730,
          uploadTimeoutSeconds: d.uploadTimeoutSeconds || 300,
          allowedExts: d.allowedExts ?? null,
        })
        // 清单单独拉：拉失败不该连带让整页报错，用户仍能改超时等其它项
        try {
          setCatalog(await api<FormatCatalog>('/v1/meta/formats'))
        } catch {
          setCatalog(null)
        }
      }
      if (tab === 'approval') {
        const d = await api<{ items: ClassRequest[] }>('/v1/admin/classification/requests?status=pending')
        setRequests(d.items ?? [])
      }
      if (tab === 'share-approvals') {
        const d = await api<{ items: ShareApproval[] }>('/v1/shares/pending')
        setShareApprovals(d.items ?? [])
      }
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '加载失败')
    }
  }, [tab, auditFilter])

  // 地址里的页签不可用时回退：否则会渲染出一个空白面板，用户以为页面坏了
  useEffect(() => {
    if (!urlTab || tabs.length === 0) return
    if (!tabs.some((t) => t.key === urlTab)) {
      navigate(adminPath(tabs[0].key), true)
    }
  }, [urlTab, tabs])

  useEffect(() => { void load() }, [load])

  async function verifyChain() {
    try {
      const d = await api<{ ok: boolean; checked: number; error?: string }>('/v1/admin/audit/verify')
      setChainOK(d.ok)
      flash(d.ok ? `哈希链完整（已校验 ${d.checked} 条）` : `校验失败：${d.error ?? '链被破坏'}`)
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '校验失败')
    }
  }

  async function saveClassLabel(level: number, name: string, description: string) {
    try {
      await api(`/v1/admin/classifications/${level}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description }),
      })
      flash('已保存（等级语义固定，仅名称可改）')
      void load()
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '保存失败')
    }
  }

  async function saveSettings() {
    setErr('')
    // 前端先挡一次，避免用户填 0 天后点保存却看不出问题
    if (tpolicy.auditRetentionDays < 30 || tpolicy.auditRetentionDays > 3650) {
      setErr('日志保留期需在 30-3650 天之间（2 年 = 730 天）')
      return
    }
    if (tpolicy.uploadTimeoutSeconds < 60 || tpolicy.uploadTimeoutSeconds > 3600) {
      setErr('上传超时需在 60-3600 秒之间')
      return
    }
    try {
      const d = await api<TenantPolicy>('/v1/admin/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tpolicy),
      })
      setTpolicy(d)
      flash('系统设置已保存，日志清理会在下一轮（不超过 6 小时）按新保留期执行')
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '保存失败')
    }
  }

  async function savePolicy() {
    if (!newPolicy.label.trim()) { flash('标签不能为空'); return }
    try {
      await api(`/v1/admin/label-policies/${encodeURIComponent(newPolicy.label.trim())}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ minLevel: newPolicy.minLevel }),
      })
      flash('策略已保存')
      setNewPolicy({ label: '', minLevel: 1 })
      void load()
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '保存失败')
    }
  }

  // 外发审批与降密审批是两个独立流程，不共用接口：
  // 前者批的是"这条链接能不能用"，后者批的是"这份文件能不能降级"。
  async function decideShare(id: string, approve: boolean) {
    try {
      await postJSON(`/v1/shares/${id}/approve`, { approve })
      flash(approve ? '已通过，链接立即可用' : '已驳回，发起人需重新创建')
      void load()
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '操作失败')
    }
  }

  async function decide(id: string, approve: boolean) {
    const note = window.prompt(approve ? '审批意见（可选）' : '驳回原因', '') ?? ''
    try {
      await postJSON(`/v1/admin/classification/requests/${id}/decide`, { approve, note })
      flash(approve ? '已通过' : '已驳回')
      void load()
    } catch (e) {
      flash(e instanceof HttpError ? e.message : '处理失败')
    }
  }

  const tabLabel = tabs.find((t) => t.key === tab)?.label ?? '管理台'
  const tabIcon: Record<string, string> = {
    overview: 'grid', members: 'users', spaces: 'folder', logs: 'list', 'share-approvals': 'share',
    settings: 'sparkle', directory: 'users', audit: 'shield', class: 'lock',
    policy: 'tag', approval: 'check',
  }

  return (
    <Shell
      me={me}
      spaces={[]}
      hideSpaceList
      hideQuickNav
      onSpace={(id) => navigate('/files/' + id)}
      spaceName="管理台"
      crumbs={[{ id: tab, name: tabLabel }]}
      onOpenAccount={() => navigate('/files')}
      onToggleTheme={() => { const t = cycleTheme(); flash(t === 'dark' ? '深色' : t === 'light' ? '浅色' : '跟随系统') }}
      theme={document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'}
      actions={tab === 'spaces' ? undefined : <button className="sm" onClick={() => void load()}><Icon name="history" size={14} /> 刷新</button>}
      sidebarNav={
        <div className="side-sec">
          <div className="side-sec-head"><span className="label">管理</span></div>
          <button className="nav-item" onClick={() => navigate('/files')}>
            <span className="ico"><Icon name="arrowLeft" size={16} /></span>
            <span className="txt">返回文档</span>
          </button>
          {tabs.map((t) => (
            <button key={t.key} className={`nav-item ${tab === t.key ? 'on' : ''}`} onClick={() => goTab(t.key)}>
              <span className="ico"><Icon name={tabIcon[t.key] ?? 'grid'} size={16} /></span>
              <span className="txt">{t.label}</span>
            </button>
          ))}
          <div className="hint" style={{ padding: '6px 8px' }}>
            当前角色：{myRoles.join('、') || '无'}
          </div>
        </div>
      }
    >
      <div className="content-head">
        <div className="ttl">
          <h1>{tabLabel}</h1>
          <div className="sub">
            <span>治理与审计</span>
            <span className="dim">·</span>
            <span>所有管理动作都会写审计，含被拒绝的尝试</span>
            <InfoDot title="管理台的边界">
              <p>管理角色管的是<b>配置</b>，不是<b>内容</b>：系统管理员看不到别人空间里的文件，除非被显式授权。</p>
              <p>三权分立：系统管理员 + 审计管理员、安全管理员 + 审计管理员为冲突组合，运行期会拒绝并冻结管理能力。</p>
            </InfoDot>
          </div>
        </div>
      </div>

      <div className="panel" style={{ overflow: 'auto' }}>
        <div className="panel-body">

          {tabs.length === 0 && (
            <div className="empty" style={{ padding: '56px 24px' }}>
              <div className="empty-art" />
              <div>当前账号没有管理角色</div>
              <div className="hint">
                管理台按角色开放：系统管理员（成员/概览）、审计管理员（审计日志）、
                安全管理员（密级/策略/审批）。如需访问，请联系系统管理员授予对应角色。
              </div>
              <button onClick={() => navigate('/files')}>返回文档</button>
            </div>
          )}

          {err && tabs.length > 0 && <div className="card empty error" style={{ margin: 12 }}>{err}</div>}

          {tab === 'overview' && (
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="stats">
                <div className="stat brand"><div className="k">成员</div><div className="v">{summary?.users ?? '—'}</div></div>
                <div className="stat accent"><div className="k">空间</div><div className="v">{summary?.spaces ?? '—'}</div></div>
                <div className="stat"><div className="k">文件</div><div className="v">{summary?.files ?? '—'}</div></div>
                <div className="stat"><div className="k">存储用量</div><div className="v">{summary ? fmtBytes(summary.usedBytes) : '—'}</div></div>
              </div>
              <div className="card pad">
                <h3 style={{ marginBottom: 8 }}>系统角色</h3>
                <table>
                  <thead><tr><th>编码</th><th>名称</th><th>职责</th></tr></thead>
                  <tbody>
                    {roles.map((r) => (
                      <tr key={r.code}>
                        <td><span className="code">{r.code}</span></td>
                        <td className="name">{r.name}</td>
                        <td className="hint">{r.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="hint" style={{ marginTop: 8 }}>
                  审计角色与其他管理角色互斥（三权分立）；撤销最后一名系统管理员会被拒绝。
                </div>
              </div>
            </div>
          )}

          {tab === 'members' && <Members roles={roles} meId={me?.userId ?? ''} />}
          {tab === 'spaces' && <AdminSpaces meId={me?.userId ?? ''} flash={flash} />}

          {tab === 'audit' && (
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <input
                  placeholder="动作，如 acl.grant"
                  value={auditFilter.action}
                  onChange={(e) => setAuditFilter((f) => ({ ...f, action: e.target.value }))}
                  style={{ width: 200 }}
                />
                <select value={auditFilter.result} onChange={(e) => setAuditFilter((f) => ({ ...f, result: e.target.value }))}>
                  <option value="">全部结果</option>
                  <option value="ok">成功</option>
                  <option value="denied">拒绝</option>
                  <option value="error">异常</option>
                </select>
                <button onClick={() => void load()}>查询</button>
                <div className="spacer" style={{ flex: 1 }} />
                <button className="accent" onClick={() => void verifyChain()}>校验哈希链</button>
                {chainOK !== null && (
                  <span className={`badge ${chainOK ? 'ok' : 'danger'}`}>{chainOK ? '链完整' : '链异常'}</span>
                )}
              </div>
              <table>
                <thead>
                  <tr><th style={{ width: 70 }}>序号</th><th style={{ width: 190 }}>时间</th><th>动作</th><th style={{ width: 80 }}>结果</th><th style={{ width: 150 }}>来源 IP</th><th>主体</th></tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr><td colSpan={6}><div className="empty">没有符合条件的审计事件</div></td></tr>
                  ) : events.map((e) => (
                    <tr key={e.seq}>
                      <td className="tnum">{e.seq}</td>
                      <td className="tnum">{new Date(e.createdAt).toLocaleString('zh-CN')}</td>
                      <td className="name"><span className="code">{e.action}</span></td>
                      <td>{resultBadge(e.result)}</td>
                      <td className="tnum">{e.ip || '—'}</td>
                      <td className="hint">{e.actorType === 'system' ? '系统' : e.actorType === 'anonymous' ? '匿名' : (e.actorId || '—')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="hint">审计只可查询与校验，任何修改都会破坏哈希链并被检出。</div>
            </div>
          )}

          {tab === 'class' && (
            <div style={{ padding: 14 }}>
              <table>
                <thead><tr><th style={{ width: 80 }}>等级</th><th style={{ width: 180 }}>名称</th><th>说明</th><th style={{ width: 90 }} /></tr></thead>
                <tbody>
                  {classes.map((c) => (
                    <tr key={c.level}>
                      <td><span className={`badge cls-${c.level}`}>{c.level}</span></td>
                      <td>
                        <input
                          defaultValue={c.name}
                          key={`n-${c.level}-${c.name}`}
                          onBlur={(e) => e.target.value !== c.name && void saveClassLabel(c.level, e.target.value, c.description)}
                          style={{ width: 150 }}
                        />
                      </td>
                      <td>
                        <input
                          defaultValue={c.description}
                          key={`d-${c.level}-${c.description}`}
                          onBlur={(e) => e.target.value !== c.description && void saveClassLabel(c.level, c.name, e.target.value)}
                          style={{ width: '100%' }}
                        />
                      </td>
                      <td><span className="hint">语义固定</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="hint" style={{ marginTop: 8 }}>
                等级顺序不可调整（避免"把机密改名为公开"的欺骗），只能修改展示名称与说明。
              </div>
            </div>
          )}

          {tab === 'policy' && (
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card pad">
                <h3 style={{ marginBottom: 8 }}>新增 / 覆盖策略</h3>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <input placeholder="标签名，如 contract" value={newPolicy.label} onChange={(e) => setNewPolicy((p) => ({ ...p, label: e.target.value }))} style={{ width: 200 }} />
                  <select value={newPolicy.minLevel} onChange={(e) => setNewPolicy((p) => ({ ...p, minLevel: Number(e.target.value) }))}>
                    {classes.map((c) => <option key={c.level} value={c.level}>最低 {c.level} · {c.name}</option>)}
                  </select>
                  <button className="primary" onClick={() => void savePolicy()}>保存</button>
                </div>
                <div className="hint" style={{ marginTop: 8 }}>
                  标签只能"收紧"密级（取对象密级与标签下限的较大值），不能用标签放宽权限。
                </div>
              </div>
              <div className="card">
                <table>
                  <thead><tr><th>标签</th><th style={{ width: 160 }}>最低密级</th></tr></thead>
                  <tbody>
                    {Object.keys(policies).length === 0 ? (
                      <tr><td colSpan={2}><div className="empty">还没有标签策略</div></td></tr>
                    ) : Object.entries(policies).map(([k, v]) => (
                      <tr key={k}><td className="name"><span className="code">{k}</span></td><td><span className={`badge cls-${v}`}>{v}</span></td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {tab === 'logs' && <ActivityTable scope="admin" />}

          {tab === 'directory' && <DirectorySettings onFlash={flash} />}

          {tab === 'settings' && (
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card pad">
                <h3 style={{ marginTop: 0, marginBottom: 10 }}>日志与配额</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '180px 200px 1fr', gap: 10, alignItems: 'center' }}>
                  <label htmlFor="pol-retention">操作日志保留期（天）</label>
                  <input
                    id="pol-retention"
                    type="number"
                    min={30}
                    max={3650}
                    value={tpolicy.auditRetentionDays}
                    onChange={(e) => setTpolicy((p) => ({ ...p, auditRetentionDays: Number(e.target.value) }))}
                  />
                  <span className="hint">
                    默认 730 天（2 年）。到期后只删除<strong>已被日结锚点覆盖</strong>的历史明细，
                    锚点（Merkle 根 + 链头 + 签名）仍保留，因此缩短保留期不会制造"无法验证的空白"。
                  </span>

                  <label htmlFor="pol-share">外链默认有效期（天）</label>
                  <input
                    id="pol-share"
                    type="number"
                    min={0}
                    max={3650}
                    value={tpolicy.shareDefaultExpireDays}
                    onChange={(e) => setTpolicy((p) => ({ ...p, shareDefaultExpireDays: Number(e.target.value) }))}
                  />
                  <span className="hint">创建外链时未指定有效期则用此值；0 表示不过期。</span>

                  <label htmlFor="pol-upload">单文件上传上限（MB）</label>
                  <input
                    id="pol-upload"
                    type="number"
                    min={0}
                    max={102400}
                    value={tpolicy.maxUploadMB}
                    onChange={(e) => setTpolicy((p) => ({ ...p, maxUploadMB: Number(e.target.value) }))}
                  />
                  <span className="hint">0 表示使用系统默认上限。</span>

                  <label htmlFor="pol-timeout">上传超时（秒）</label>
                  <input
                    id="pol-timeout"
                    type="number"
                    min={60}
                    max={3600}
                    value={tpolicy.uploadTimeoutSeconds}
                    onChange={(e) => setTpolicy((p) => ({ ...p, uploadTimeoutSeconds: Number(e.target.value) }))}
                  />
                  <span className="hint">
                    单个上传请求允许的最长读取时间，默认 300 秒。
                    移动网络上行慢时调大：同一份 5MB 文件，办公室 20 秒传完、手机可能要 3 分钟。
                    上传按 1MB 分片，这个值约束的是<strong>每一片</strong>，不是整个文件。
                  </span>
                </div>

                {/* 允许上传的格式 */}
                <div style={{ marginTop: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <strong style={{ fontSize: 13 }}>允许上传的格式</strong>
                    <span className="hint">
                      {pickedAll.length > 0
                        ? `已选 ${pickedAll.length}${catalog ? ` / ${catalog.total}` : ''} 种` +
                          (catalog ? `，其中 ${pickedViewable} 种可在线预览` : '')
                        : '未限制（当前允许任何类型）'}
                    </span>
                    <div className="spacer" style={{ flex: 1 }} />
                    <button className="ghost" onClick={() => setExts(null)}>不限制</button>
                    <button className="ghost" disabled={allExts.length === 0} onClick={() => setExts(allExts)}>
                      全选所有
                    </button>
                  </div>
                  <div className="hint" style={{ marginTop: 4 }}>
                    勾选即生效：用户选择文件时会<strong>立刻</strong>被告知类型不支持，不会等传完才报错。
                    徽标表示能否在线预览——
                    <span className="badge teal" style={{ fontSize: 10, margin: '0 3px' }}>可预览</span>
                    与
                    <span className="badge warn" style={{ fontSize: 10, margin: '0 3px' }}>可预览 · 转码</span>
                    的区别是后者需服务端转换，首次打开较慢；
                    <span className="badge plain" style={{ fontSize: 10, margin: '0 3px' }}>不可预览</span>
                    仍可上传和下载，只是不能在线看。
                  </div>

                  {!catalog ? (
                    <div className="hint" style={{ marginTop: 8 }}>
                      格式清单加载失败，刷新页面可重试；当前已保存的选择不受影响。
                    </div>
                  ) : (
                    <>
                      {!catalog.officeReady && (
                        <div className="card pad error" style={{ marginTop: 8, fontSize: 12 }}>
                          当前服务器未启用文档转换：Office 类格式仍可上传下载，但无法在线预览。
                        </div>
                      )}
                      <div style={{ display: 'grid', gap: 14, marginTop: 10 }}>
                        {catalog.groups.map((g) => {
                          const exts = g.items.map((i) => i.ext)
                          const onCount = exts.filter((e) => pickedExts.has(e)).length
                          const allOn = onCount === exts.length
                          return (
                            <div key={g.label}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                <strong style={{ fontSize: 12 }}>{g.label}</strong>
                                <span className="hint tnum" style={{ fontSize: 11 }}>
                                  {onCount}/{exts.length}
                                </span>
                                <button
                                  className="ghost"
                                  style={{ fontSize: 11, padding: '0 6px' }}
                                  onClick={() => {
                                    const next = new Set(pickedExts)
                                    if (allOn) exts.forEach((e) => next.delete(e))
                                    else exts.forEach((e) => next.add(e))
                                    setExts([...next])
                                  }}
                                >
                                  {allOn ? '取消全选' : '全选'}
                                </button>
                              </div>
                              <div
                                style={{
                                  display: 'grid',
                                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                                  gap: 6,
                                }}
                              >
                                {g.items.map((it) => {
                                  const b = previewBadge(it.preview)
                                  return (
                                    <label
                                      key={it.ext}
                                      title={`${it.ext} — ${b.tip}`}
                                      style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 400 }}
                                    >
                                      <input
                                        type="checkbox"
                                        checked={pickedExts.has(it.ext)}
                                        onChange={(ev) => {
                                          const next = new Set(pickedExts)
                                          if (ev.target.checked) next.add(it.ext)
                                          else next.delete(it.ext)
                                          setExts([...next])
                                        }}
                                      />
                                      <span
                                        style={{
                                          flex: 1, minWidth: 0, overflow: 'hidden',
                                          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                        }}
                                      >
                                        {it.name}
                                      </span>
                                      <span
                                        className={`badge ${b.cls}`}
                                        style={{ fontSize: 10, padding: '0 5px', flexShrink: 0 }}
                                      >
                                        {b.text}
                                      </span>
                                    </label>
                                  )
                                })}
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </>
                  )}
                </div>
                <div style={{ marginTop: 12 }}>
                  <button className="primary" onClick={() => void saveSettings()}>保存设置</button>
                </div>
              </div>

              <div className="hint" style={{ fontSize: 12 }}>
                清理任务每 6 小时运行一次，只处理已结束自然日的锚点覆盖范围；
                清理动作本身会写入一条 <code>audit.purge</code> 记录（含删除条数与截止时间）。
              </div>
            </div>
          )}

          {tab === 'share-approvals' && (
            <div style={{ padding: 14 }}>
              <table>
                <thead>
                  <tr>
                    <th>文件</th>
                    <th style={{ width: 60 }}>密级</th>
                    <th style={{ width: 100 }}>发起人</th>
                    <th style={{ width: 160 }}>提交时间</th>
                    <th style={{ width: 160 }}>链接有效期</th>
                    <th style={{ width: 160 }} />
                  </tr>
                </thead>
                <tbody>
                  {shareApprovals.length === 0 ? (
                    <tr><td colSpan={6}><div className="empty">没有需要你审批的外发链接</div></td></tr>
                  ) : shareApprovals.map((x) => (
                    <tr key={x.shareId}>
                      <td className="name">{x.name}</td>
                      <td><span className={`badge cls-${x.classification}`}>{x.classification}</span></td>
                      <td>{x.creator}</td>
                      <td className="tnum">{new Date(x.createdAt).toLocaleString('zh-CN')}</td>
                      <td className="tnum">
                        {x.expiresAt ? new Date(x.expiresAt).toLocaleString('zh-CN') : '不限期'}
                      </td>
                      <td className="actions">
                        <button className="primary" onClick={() => void decideShare(x.shareId, true)}>通过</button>
                        <button className="danger" onClick={() => void decideShare(x.shareId, false)}>驳回</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="hint" style={{ marginTop: 8 }}>
                只显示<strong>你有权处置</strong>的链接：对该文件或目录有管理权限，且不是你本人发起。
                通过后链接立即可用；驳回后发起人需要重新创建（系统不会通知他，需另行告知）。
              </div>
            </div>
          )}

          {tab === 'approval' && (
            <div style={{ padding: 14 }}>
              <table>
                <thead>
                  <tr><th>文件</th><th style={{ width: 130 }}>变更</th><th>理由</th><th style={{ width: 170 }}>提交时间</th><th style={{ width: 170 }} /></tr>
                </thead>
                <tbody>
                  {requests.length === 0 ? (
                    <tr><td colSpan={5}><div className="empty">没有待审批的降密申请</div></td></tr>
                  ) : requests.map((r) => (
                    <tr key={r.id}>
                      <td className="name">{r.nodeName}</td>
                      <td>
                        <span className={`badge cls-${r.fromLevel}`}>{r.fromLevel}</span>
                        <span className="hint"> → </span>
                        <span className={`badge cls-${r.toLevel}`}>{r.toLevel}</span>
                      </td>
                      <td className="hint">{r.reason}</td>
                      <td className="tnum">{new Date(r.createdAt).toLocaleString('zh-CN')}</td>
                      <td className="actions">
                        <button className="primary" onClick={() => void decide(r.id, true)}>通过</button>
                        <button className="danger" onClick={() => void decide(r.id, false)}>驳回</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="hint" style={{ marginTop: 8 }}>
                不能审批自己提交的申请（服务端强制）；降密会扩大知悉范围，因此必须由第二人确认。
              </div>
            </div>
          )}
        </div>
      </div>

      {msg && <div className="toast">{msg}</div>}
    </Shell>
  )
}
