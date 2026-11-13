import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { currentPath, navigate, subscribe } from '../router'

// 平台控制台的 API 封装。
//
// 令牌存在 sessionStorage（不是 localStorage）：
//   平台权限影响全体租户，关掉标签页就该失效；
//   localStorage 会让它在共用电脑上一直留着。
const TOKEN_KEY = 'plat.token'

class ApiError extends Error {
  code: string
  status: number
  // 部分错误带结构化明细（如降档被拒时的受影响对象清单）
  data?: unknown
  constructor(status: number, code: string, message: string, data?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.data = data
  }
}

function token(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? ''
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch('/v1/platform' + path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
      ...(init?.headers ?? {}),
    },
  })
  if (resp.status === 401) {
    sessionStorage.removeItem(TOKEN_KEY)
    throw new ApiError(401, 'UNAUTHORIZED', '会话已过期，请重新登录')
  }
  const body = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    throw new ApiError(resp.status, body.code ?? 'ERROR', body.message ?? '请求失败', body.data)
  }
  return body.data as T
}

type Tenant = {
  slug: string
  name: string
  status: string
  // plan 已废弃：服务端由触发器强制等于 edition，保留仅为兼容旧响应
  plan: string
  edition: string
  editionExpiresAt: string | null
  createdAt: string
  trialEndsAt: string | null
  suspendedAt: string | null
  contactEmail: string
  users: number
  storageBytes: number
  files: number
}

type Quota = {
  maxUsers: number | null
  maxStorageBytes: number | null
  maxTranscodeSeconds: number | null
  maxApiCallsDay: number | null
  onExceed: string
}

type Flag = { code: string; description: string; defaultEnabled: boolean; rolloutPercent: number }

// 租户级开关的求值结果。
//
// 接口返回的 effective 已经包含"来源"，界面必须用它来解释状态：
// 只显示 enabled 的话，运营看到某个能力关了却找不到是谁关的。
type TenantFlag = {
  code: string
  description: string
  enabled: boolean
  source: 'default' | 'rollout' | 'override' | string
  defaultEnabled: boolean
  rolloutPercent: number
}
type TenantFlagResp = { slug: string; overrides: unknown[]; effective: TenantFlag[] }

function flagSourceText(f: TenantFlag): string {
  switch (f.source) {
    case 'override':
      return '本租户单独设置'
    case 'rollout':
      return f.rolloutPercent <= 0
        ? '平台已暂停（放量 0%）'
        : `平台放量 ${f.rolloutPercent}%`
    default:
      return '跟随平台默认'
  }
}
type UsagePoint = { day: string; metric: string; quantity: number }
type Drift = {
  slug: string
  storageRecorded: number
  storageActual: number
  storageDrift: number
  usersRecorded: number
  usersActual: number
  usersDrift: number
}
type Domain = {
  host: string
  primary: boolean
  verified: boolean
  hasCert: boolean
  certNotAfter: string | null
}
type AuditEvent = { id: number; actor: string; action: string; target: string; result: string; ip: string; createdAt: string }
type PlatUser = {
  id: string
  email: string
  displayName: string
  role: 'ops' | 'readonly'
  status: 'active' | 'suspended'
  createdAt: string
  lastLoginAt: string | null
}

const editionText: Record<string, string> = {
  basic: '基础版',
  professional: '专业版',
  business: '商业版',
}

// 菜单顺序与文案集中在一处：地址、侧栏、标题都从这里取，
// 避免"某个 tab 只加进了一边"这种只在点开时才发现的漏。
const TABS = [
  { key: 'tenants', label: '租户' },
  { key: 'usage', label: '用量与对账' },
  { key: 'flags', label: '灰度开关' },
  { key: 'users', label: '平台账号' },
  { key: 'audit', label: '平台审计' },
] as const

type Tab = (typeof TABS)[number]['key']

const TAB_LABEL: Record<Tab, string> = Object.fromEntries(
  TABS.map((t) => [t.key, t.label]),
) as Record<Tab, string>

// parsePlatformPath 把地址解析成"哪个页签 + 看哪个租户"。
//
// 为什么必须做：此前页签是组件内 state，地址栏永远是 platform.html。
// 后果是刷新回到第一页、后退无效、链接没法发给同事("帮我看下 acme 的配额"只能靠口述)。
// 现在每个页签、每个租户详情都有独立地址，浏览器行为回归正常。
//
// 后端 /platform/* 已经回落到 platform.html（internal/platform/webui），
// 所以 /platform/usage 这类地址刷新不会 404，不需要额外改动。
function parsePlatformPath(p: string): { tab: Tab; tenantSlug: string } {
  const clean = p.split('?')[0]
  const parts = clean.split('/').filter(Boolean)
  // /platform.html 是历史入口，按默认页签处理（组件挂载后会 replace 成规范地址）
  if (parts.length === 0 || parts[0] === 'platform.html') {
    return { tab: 'tenants', tenantSlug: '' }
  }
  const key = parts[1] ?? ''
  const hit = TABS.find((t) => t.key === key)
  const tab: Tab = hit ? hit.key : 'tenants'
  // 只有租户页签带二级地址；其他页签的第三段忽略，避免出现"看似有效实则不存在"的地址
  const tenantSlug = tab === 'tenants' ? (parts[2] ?? '') : ''
  return { tab, tenantSlug }
}

// 开通表单里直接展示每一档的关键差异。
// 运营开单时看的是报价单，不是文档；把"这一档换了什么"写在旁边，比事后解释便宜。
const editionHint: Record<string, string> = {
  basic: '无密级、无 AD、无邮件分享 · 单文件 1GB · 保留 3 个版本',
  professional: '密级 0/3/4、AD、邮件分享 · 单文件 5GB · 保留 10 个版本',
  business: '密级 0–6 全档、AD、邮件、自定义域名 · 单文件 10GB · 保留 50 个版本',
}

type EditionChange = {
  fromEdition: string
  toEdition: string
  reason: string
  operator: string
  createdAt: string
}

type EditionInfo = {
  tenantId: string
  edition: string
  expiresAt: string | null
  changes: EditionChange[] | null
}

const statusText: Record<string, string> = {
  active: '正常',
  trial: '试用',
  readonly: '只读',
  suspended: '已停用',
  deleted: '已删除',
}

function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

function fmtTime(s: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('zh-CN', { hour12: false })
}

// ---------------- 登录 ----------------

function Login({ onDone }: { onDone: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const data = await call<{ accessToken: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      })
      sessionStorage.setItem(TOKEN_KEY, data.accessToken)
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '登录失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card card pad">
        <div className="brand" style={{ marginBottom: 18 }}>
          <span className="brand-mark" aria-hidden />
          <div>
            <strong>平台运营控制台</strong>
            <div className="hint">与租户管理台相互独立，仅平台运营人员可用</div>
          </div>
        </div>
        <form onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div className="field">
            <label htmlFor="email">邮箱</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              autoComplete="username" required />
          </div>
          <div className="field">
            <label htmlFor="pass">口令</label>
            <input id="pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password" required />
          </div>
          {err && <div className="error-text">{err}</div>}
          <button className="primary" type="submit" disabled={busy}>
            {busy ? '登录中…' : '登录'}
          </button>
        </form>
      </div>
    </div>
  )
}

// ---------------- 主控制台 ----------------

export default function Console() {
  const [authed, setAuthed] = useState(!!token())
  const [me, setMe] = useState<{ email: string; role: string; canWrite: boolean; static: boolean } | null>(null)
  // 页签与详情租户都来自地址栏，不再用独立 state —— 地址是唯一真源。
  const loc = useSyncExternalStore(subscribe, currentPath, currentPath)
  const { tab, tenantSlug } = parsePlatformPath(loc)
  const [err, setErr] = useState('')
  const [toast, setToast] = useState('')
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [flags, setFlags] = useState<Flag[]>([])
  const [drifts, setDrifts] = useState<Drift[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [pusers, setPusers] = useState<PlatUser[]>([])
  const [creatingUser, setCreatingUser] = useState(false)
  const [pwUser, setPwUser] = useState<PlatUser | null>(null)
  const [selected, setSelected] = useState<Tenant | null>(null)
  const [tenantFlags, setTenantFlags] = useState<TenantFlag[]>([])
  const [quota, setQuota] = useState<Quota | null>(null)
  const [edition, setEdition] = useState<EditionInfo | null>(null)
  const [editionDraft, setEditionDraft] = useState('basic')
  const [expiresDraft, setExpiresDraft] = useState('')
  const [reasonDraft, setReasonDraft] = useState('')
  const [domains, setDomains] = useState<Domain[]>([])
  const [usage, setUsage] = useState<UsagePoint[]>([])
  const [creating, setCreating] = useState(false)

  const canWrite = me?.canWrite ?? false

  const flash = useCallback((m: string) => {
    setToast(m)
    window.setTimeout(() => setToast(''), 2400)
  }, [])

  const loadMe = useCallback(async () => {
    try {
      setMe(await call('/me'))
    } catch {
      setAuthed(false)
    }
  }, [])

  const loadTenants = useCallback(async () => {
    try {
      const data = await call<{ items: Tenant[] }>('/tenants')
      setTenants(data.items ?? [])
      setErr('')
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取租户失败')
    }
  }, [])

  const loadFlags = useCallback(async () => {
    try {
      const data = await call<{ items: Flag[] }>('/flags')
      setFlags(data.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取开关失败')
    }
  }, [])

  const loadUsers = useCallback(async () => {
    try {
      const data = await call<{ items: PlatUser[] }>('/users')
      setPusers(data.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取平台账号失败')
    }
  }, [])

  const loadAudit = useCallback(async () => {
    try {
      const data = await call<{ items: AuditEvent[] }>('/audit?limit=100')
      setEvents(data.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取审计失败')
    }
  }, [])

  useEffect(() => {
    if (!authed) return
    void loadMe()
    void loadTenants()
    void loadFlags()
    void loadAudit()
    void loadUsers()
  }, [authed, loadMe, loadTenants, loadFlags, loadAudit, loadUsers])

  // openTenant 只改地址，不直接加载详情。
  //
  // 详情加载由地址变化驱动（下方 effect），所以"点列表""直接打开链接""按后退键"
  // 走的是同一条路径。两套逻辑是这类页面的典型漏洞：刷新后数据不出现，或者后退后
  // 面板显示上一个租户。
  function openTenant(t: Tenant) {
    navigate(`/platform/tenants/${t.slug}`)
  }

  async function loadTenantDetail(t: Tenant) {
    setSelected(t)
    setUsage([])
    setEdition(null)
    setTenantFlags([])
    try {
      const q = await call<Quota>(`/tenants/${t.slug}/quota`)
      setQuota(q)
      const d = await call<{ items: Domain[] }>(`/tenants/${t.slug}/domains`)
      setDomains(d.items ?? [])
      const u = await call<{ points: UsagePoint[] }>(`/tenants/${t.slug}/usage`)
      setUsage(u.points ?? [])
      // 能力开关按租户求值：全局页签只说明"平台默认与放量"，
      // 到了具体租户还要看有没有单独覆盖——否则"平台已开启但这家不可用"
      // 这种情况在控制台里完全看不出来。
      const tf = await call<TenantFlagResp>(`/tenants/${t.slug}/flags`)
      setTenantFlags(tf.effective ?? [])
      // 档位单独取：租户列表接口没有这个字段，且历史变更体积较大
      const ed = await call<EditionInfo>(`/tenants/${t.slug}/edition`)
      setEdition(ed)
      setEditionDraft(ed.edition)
      setExpiresDraft(ed.expiresAt ? ed.expiresAt.slice(0, 10) : '')
      setReasonDraft('')
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取详情失败')
    }
  }

  // loadedSlug 挡住重复加载：租户列表刷新会重建数组引用，
  // 若没有这道守卫，每次轮询都会把正在编辑的档位草稿覆盖掉。
  const loadedSlug = useRef('')
  useEffect(() => {
    if (!authed) return
    if (!tenantSlug) {
      setSelected(null)
      loadedSlug.current = ''
      return
    }
    const t = tenants.find((x) => x.slug === tenantSlug)
    if (!t) return // 列表尚未加载：等 tenants 到位后本 effect 会重跑
    if (loadedSlug.current === tenantSlug) return
    loadedSlug.current = tenantSlug
    void loadTenantDetail(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authed, tenantSlug, tenants])

  // 历史入口规范化：/platform.html 与 /platform 都 replace 成 /platform/tenants，
  // 让收藏与复制的地址是稳定的规范形式。
  useEffect(() => {
    const p = window.location.pathname
    if (p === '/platform.html' || p === '/platform' || p === '/platform/') {
      navigate('/platform/tenants', true)
    }
  }, [])

  async function setStatus(t: Tenant, status: string) {
    const label = statusText[status] ?? status
    if (status === 'suspended' || status === 'deleted') {
      const word = status === 'deleted' ? '逻辑删除' : '停用'
      if (!window.confirm(`确认${word}租户「${t.name}」？\n\n这会立即吊销该租户全部已登录会话。`)) return
    }
    try {
      await call(`/tenants/${t.slug}`, { method: 'PATCH', body: JSON.stringify({ status }) })
      flash(`已将 ${t.slug} 置为「${label}」`)
      await loadTenants()
      if (selected?.slug === t.slug) setSelected({ ...t, status })
    } catch (e) {
      setErr(e instanceof Error ? e.message : '操作失败')
    }
  }

  async function deleteTenant(t: Tenant) {
    if (!window.confirm(`确认删除租户「${t.name}」？\n\n逻辑删除，数据保留 30 天。`)) return
    try {
      await call(`/tenants/${t.slug}`, { method: 'DELETE' })
      flash('已逻辑删除，保留期 30 天')
      // 详情由地址驱动，回列表必须改地址；只 setSelected(null) 会被 effect 重新拉起来
      navigate('/platform/tenants')
      await loadTenants()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '删除失败')
    }
  }

  async function setPlatStatus(u: PlatUser, status: 'active' | 'suspended') {
    const word = status === 'active' ? '启用' : '停用'
    if (status === 'suspended' && !window.confirm(`停用平台账号 ${u.email}？\n\n其会话会立即失效。`)) return
    try {
      await call(`/users/${u.id}/status`, { method: 'POST', body: JSON.stringify({ status }) })
      flash(`已${word}`)
      await loadUsers()
    } catch (e) {
      setErr(e instanceof Error ? e.message : `${word}失败`)
    }
  }

  async function saveQuota() {
    if (!selected || !quota) return
    try {
      await call(`/tenants/${selected.slug}/quota`, { method: 'PUT', body: JSON.stringify(quota) })
      flash('配额已保存（立即生效）')
    } catch (e) {
      setErr(e instanceof Error ? e.message : '保存失败')
    }
  }

  async function saveEdition() {
    if (!selected) return
    const label = editionText[editionDraft] ?? editionDraft
    // 降档是破坏性的（会收回能力、可能让客户进只读），必须让运营确认一次
    if (edition && editionDraft !== edition.edition) {
      const down = ['basic', 'professional', 'business'].indexOf(editionDraft) <
        ['basic', 'professional', 'business'].indexOf(edition.edition)
      if (down && !window.confirm(`确认将「${selected.name}」从 ${editionText[edition.edition] ?? edition.edition} 降为 ${label}？\n\n降档会立即收回对应能力；如果存量数据无法被目标档位表达，服务端会拒绝并给出清单。`)) {
        return
      }
    }
    const body: Record<string, unknown> = { edition: editionDraft, reason: reasonDraft }
    if (expiresDraft) {
      // 到期日按当天 23:59:59 计算，避免"选了今天就当场失效"的歧义
      body.expiresAt = new Date(expiresDraft + 'T23:59:59').toISOString()
    }
    try {
      await call(`/tenants/${selected.slug}/edition`, { method: 'PUT', body: JSON.stringify(body) })
      flash(`档位已改为「${label}」${expiresDraft ? `，到期 ${expiresDraft}` : '，不限期'}`)
      const ed = await call<EditionInfo>(`/tenants/${selected.slug}/edition`)
      setEdition(ed)
      setEditionDraft(ed.edition)
    } catch (e) {
      if (e instanceof ApiError && e.code === 'EDITION_DOWNGRADE_BLOCKED') {
        const d = e.data as { blockedCount?: number; samples?: string[] } | undefined
        const names = d?.samples?.length ? `；受影响示例：${d.samples.join('、')}` : ''
        setErr(`${e.message}${names}`)
        return
      }
      setErr(e instanceof Error ? e.message : '改档失败')
    }
  }

  async function runReconcile(repair: boolean) {
    try {
      const data = await call<{ items: Drift[]; driftCount: number }>(
        `/usage/reconcile${repair ? '?repair=true' : ''}`,
      )
      setDrifts(data.items ?? [])
      flash(repair ? `已修正 ${data.driftCount} 个偏差` : `发现 ${data.driftCount} 个偏差`)
      if (repair) await loadTenants()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '对账失败')
    }
  }

  // flagActive 是"这个开关现在是否真的对所有租户生效"。
  //
  // 不能只看 defaultEnabled：放量 0% 时总开关是开着的，实际对所有人关闭。
  // 之前界面只显示总开关，于是出现"显示已开启、功能全部不可用"，
  // 连平台运营自己都找不到原因。
  function flagActive(f: Flag) {
    return f.defaultEnabled && f.rolloutPercent > 0
  }

  async function toggleFlag(f: Flag) {
    const on = flagActive(f)
    // 从"已暂停（放量 0%）"点开时，同时把放量恢复满额：
    // 否则点了按钮状态仍是关闭的，用户会以为按钮坏了。
    const next = on
      ? { defaultEnabled: false, rolloutPercent: f.rolloutPercent }
      : { defaultEnabled: true, rolloutPercent: f.rolloutPercent > 0 ? f.rolloutPercent : 100 }
    try {
      await call(`/flags/${f.code}`, {
        method: 'PUT',
        body: JSON.stringify(next),
      })
      await loadFlags()
      flash('开关已更新（30 秒内全实例生效）')
    } catch (e) {
      setErr(e instanceof Error ? e.message : '更新失败')
    }
  }

  async function setRollout(f: Flag, pct: number) {
    try {
      await call(`/flags/${f.code}`, {
        method: 'PUT',
        body: JSON.stringify({ defaultEnabled: f.defaultEnabled, rolloutPercent: pct }),
      })
      await loadFlags()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '更新失败')
    }
  }

  // setTenantFlag 改的是**租户覆盖**，不动全局放量。
  //
  // 这是运营最常用的动作：平台整体没放开（或已暂停），单独给某个客户开通。
  // enabled=null 表示删除覆盖、回到平台策略。
  async function setTenantFlag(f: TenantFlag, enabled: boolean | null) {
    if (!selected) return
    try {
      if (enabled === null) {
        await call(`/tenants/${selected.slug}/flags/${f.code}`, { method: 'DELETE' })
      } else {
        await call(`/tenants/${selected.slug}/flags/${f.code}`, {
          method: 'PUT',
          body: JSON.stringify({ enabled }),
        })
      }
      const tf = await call<TenantFlagResp>(`/tenants/${selected.slug}/flags`)
      setTenantFlags(tf.effective ?? [])
      flash(enabled === null ? '已恢复平台策略（30 秒内生效）' : '本租户开关已更新（30 秒内生效）')
    } catch (e) {
      setErr(e instanceof Error ? e.message : '更新租户开关失败')
    }
  }

  async function addDomain() {
    if (!selected) return
    const host = window.prompt('要绑定的域名（不带协议与端口，例如 docs.example.com）')
    if (!host) return
    try {
      const data = await call<{ dns: { type: string; name: string; value: string } }>(
        `/tenants/${selected.slug}/domains`,
        { method: 'POST', body: JSON.stringify({ host, primary: domains.length === 0 }) },
      )
      window.alert(
        `请先添加 DNS 记录完成归属验证：\n\n类型：${data.dns.type}\n名称：${data.dns.name}\n值：${data.dns.value}\n\n配好后点「验证」。`,
      )
      const d = await call<{ items: Domain[] }>(`/tenants/${selected.slug}/domains`)
      setDomains(d.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '绑定失败')
    }
  }

  async function verifyDomain(host: string) {
    if (!selected) return
    try {
      await call(`/tenants/${selected.slug}/domains/${encodeURIComponent(host)}/verify`, { method: 'POST' })
      flash('域名已验证')
      const d = await call<{ items: Domain[] }>(`/tenants/${selected.slug}/domains`)
      setDomains(d.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '验证失败（DNS 记录可能还没生效）')
    }
  }

  async function removeDomain(host: string) {
    if (!selected) return
    if (!window.confirm(`解绑域名 ${host}？证书会一并删除。`)) return
    try {
      await call(`/tenants/${selected.slug}/domains/${encodeURIComponent(host)}`, { method: 'DELETE' })
      const d = await call<{ items: Domain[] }>(`/tenants/${selected.slug}/domains`)
      setDomains(d.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '解绑失败')
    }
  }

  const totals = useMemo(() => {
    return tenants.reduce(
      (acc, t) => ({
        users: acc.users + t.users,
        storage: acc.storage + t.storageBytes,
        files: acc.files + t.files,
      }),
      { users: 0, storage: 0, files: 0 },
    )
  }, [tenants])

  if (!authed) {
    return <Login onDone={() => { setAuthed(true) }} />
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="side-head">
          <span className="brand-mark" aria-hidden />
          <div>
            <strong>平台运营</strong>
            <div className="hint">{me?.email ?? '—'}</div>
          </div>
        </div>
        <nav className="tabs" style={{ flexDirection: 'column' }}>
          {TABS.map((t) => (
            <button
              key={t.key}
              className={tab === t.key ? 'on' : ''}
              onClick={() => navigate(`/platform/${t.key}`)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span className={`badge ${me?.role === 'readonly' ? 'warn' : 'teal'}`}>
            {me?.role === 'readonly' ? '只读角色' : '可操作'}
          </span>
          {me?.static && <span className="badge plain">应急令牌</span>}
          <button className="ghost" style={{ marginTop: 8 }}
            onClick={async () => {
              try { await call('/auth/logout', { method: 'POST' }) } catch { /* 忽略 */ }
              sessionStorage.removeItem(TOKEN_KEY)
              setAuthed(false)
            }}>
            退出
          </button>
        </div>
      </aside>

      <main className="main">
        <div className="toolbar">
          <strong>{TAB_LABEL[tab]}</strong>
          <div className="spacer" />
          {tab === 'tenants' && (
            <button className="primary" disabled={!canWrite} onClick={() => setCreating(true)}>开通租户</button>
          )}
          {tab === 'users' && (
            <button className="primary" disabled={!canWrite} onClick={() => setCreatingUser(true)}>新建平台账号</button>
          )}
          {tab === 'usage' && (
            <>
              <button onClick={() => void runReconcile(false)}>对账检查</button>
              <button className="accent" disabled={!canWrite} onClick={() => void runReconcile(true)}>
                对账并修正
              </button>
            </>
          )}
        </div>

        {err && <div className="card pad error" style={{ marginBottom: 12 }}>{err}</div>}

        {tab === 'tenants' && (
          <>
            <div className="stats" style={{ marginBottom: 12 }}>
              <div className="stat"><div className="k">租户</div><div className="v">{tenants.length}</div></div>
              <div className="stat"><div className="k">用户</div><div className="v">{totals.users}</div></div>
              <div className="stat"><div className="k">文件</div><div className="v">{totals.files}</div></div>
              <div className="stat"><div className="k">存储</div><div className="v">{fmtBytes(totals.storage)}</div></div>
            </div>

            <div className="card">
              <table>
                <thead>
                  <tr>
                    <th>租户</th><th>状态</th><th>档位</th>
                    <th style={{ textAlign: 'right' }}>用户</th>
                    <th style={{ textAlign: 'right' }}>文件</th>
                    <th style={{ textAlign: 'right' }}>存储</th>
                    <th className="actions">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {tenants.map((t) => (
                    <tr key={t.slug} className={selected?.slug === t.slug ? 'selected' : ''}>
                      <td className="name">
                        {t.name}
                        <div className="hint">{t.slug}</div>
                      </td>
                      <td><span className={`badge ${t.status === 'active' ? 'ok' : t.status === 'suspended' ? 'error' : 'warn'}`}>
                        {statusText[t.status] ?? t.status}
                      </span></td>
                      <td>
                        {editionText[t.edition] ?? t.edition ?? '—'}
                        {t.editionExpiresAt && (
                          <div className="hint">至 {t.editionExpiresAt.slice(0, 10)}</div>
                        )}
                      </td>
                      <td className="tnum" style={{ textAlign: 'right' }}>{t.users}</td>
                      <td className="tnum" style={{ textAlign: 'right' }}>{t.files}</td>
                      <td className="tnum" style={{ textAlign: 'right' }}>{fmtBytes(t.storageBytes)}</td>
                      <td className="actions">
                        <button className="icon" onClick={() => void openTenant(t)}>详情</button>
                        {canWrite && t.status !== 'suspended' && (
                          <button className="icon danger" onClick={() => void setStatus(t, 'suspended')}>停用</button>
                        )}
                        {canWrite && t.status !== 'active' && t.status !== 'suspended' && (
                          <button className="icon" onClick={() => void setStatus(t, 'active')}>恢复</button>
                        )}
                        {canWrite && t.status !== 'readonly' && (
                          <button className="icon" onClick={() => void setStatus(t, 'readonly')}>设只读</button>
                        )}
                        {canWrite && (
                          <button className="icon danger" onClick={() => void deleteTenant(t)}>删除</button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {tenants.length === 0 && (
                    <tr><td colSpan={7}><div className="empty">暂无租户</div></td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === 'usage' && (
          <div className="card">
            <div className="card-head">
              <h3>账实核对</h3>
              <div className="spacer" />
              <span className="hint">
                存储与用户数由数据库触发器与业务写入同事务维护；此处用真实聚合重算并比对
              </span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>租户</th>
                  <th style={{ textAlign: 'right' }}>账本存储</th>
                  <th style={{ textAlign: 'right' }}>实际存储</th>
                  <th style={{ textAlign: 'right' }}>存储偏差</th>
                  <th style={{ textAlign: 'right' }}>账本用户</th>
                  <th style={{ textAlign: 'right' }}>实际用户</th>
                  <th style={{ textAlign: 'right' }}>用户偏差</th>
                </tr>
              </thead>
              <tbody>
                {drifts.map((d) => (
                  <tr key={d.slug}>
                    <td className="name">{d.slug}</td>
                    <td className="tnum" style={{ textAlign: 'right' }}>{fmtBytes(d.storageRecorded)}</td>
                    <td className="tnum" style={{ textAlign: 'right' }}>{fmtBytes(d.storageActual)}</td>
                    <td className="tnum" style={{ textAlign: 'right', color: d.storageDrift ? 'var(--danger)' : undefined }}>
                      {d.storageDrift}
                    </td>
                    <td className="tnum" style={{ textAlign: 'right' }}>{d.usersRecorded}</td>
                    <td className="tnum" style={{ textAlign: 'right' }}>{d.usersActual}</td>
                    <td className="tnum" style={{ textAlign: 'right', color: d.usersDrift ? 'var(--danger)' : undefined }}>
                      {d.usersDrift}
                    </td>
                  </tr>
                ))}
                {drifts.length === 0 && (
                  <tr><td colSpan={7}><div className="empty">点上方「对账检查」开始核对</div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'flags' && (
          <div className="card">
            <div className="card-head">
              <h3>功能开关</h3>
              <div className="spacer" />
              <span className="hint">关闭后由服务端拒绝，不是隐藏界面</span>
            </div>
            {flags.some((f) => f.defaultEnabled && f.rolloutPercent <= 0) && (
              <div className="card pad error" style={{ margin: '0 0 12px', fontSize: 12 }}>
                有开关处于「总开关开启 + 放量 0%」：这是<strong>暂停</strong>状态，对所有租户实际关闭。
                要给个别客户开通，去「租户 → 该租户 → 能力开关」单独覆盖。
              </div>
            )}
            <table>
              <thead>
                <tr><th>开关</th><th>说明</th><th>状态</th><th>放量</th></tr>
              </thead>
              <tbody>
                {flags.map((f) => (
                  <tr key={f.code}>
                    <td className="name"><code>{f.code}</code></td>
                    <td>{f.description}</td>
                    <td>
                      {/* 显示有效状态：放量 0% 时总开关开着也等于关闭 */}
                      <button className={flagActive(f) ? 'accent' : ''} disabled={!canWrite}
                        onClick={() => void toggleFlag(f)}>
                        {flagActive(f) ? '已开启' : f.defaultEnabled ? '已暂停' : '已关闭'}
                      </button>
                    </td>
                    <td>
                      <div className="seg">
                        {[0, 10, 25, 50, 100].map((p) => (
                          <button key={p} className={f.rolloutPercent === p ? 'on' : ''}
                            disabled={!canWrite} onClick={() => void setRollout(f, p)}>
                            {p}%
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'users' && (
          <div className="card">
            <div className="card-head">
              <h3>平台账号</h3>
              <div className="spacer" />
              <span className="hint">
                平台账号不属于任何租户；ops 可变更，readonly 只能查看
              </span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>邮箱</th><th>姓名</th><th>角色</th><th>状态</th>
                  <th>最近登录</th><th className="actions">操作</th>
                </tr>
              </thead>
              <tbody>
                {pusers.map((u) => (
                  <tr key={u.id}>
                    <td className="name">{u.email}{u.email === me?.email && <span className="badge plain" style={{ marginLeft: 6 }}>我</span>}</td>
                    <td>{u.displayName || '—'}</td>
                    <td>
                      <span className={`badge ${u.role === 'ops' ? 'teal' : 'plain'}`}>
                        {u.role === 'ops' ? '可操作' : '只读'}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${u.status === 'active' ? 'ok' : 'error'}`}>
                        {u.status === 'active' ? '启用' : '已停用'}
                      </span>
                    </td>
                    <td className="hint">{fmtTime(u.lastLoginAt)}</td>
                    <td className="actions">
                      <button className="icon" disabled={!canWrite} onClick={() => setPwUser(u)}>重置口令</button>
                      {u.status === 'active'
                        ? <button className="icon danger" disabled={!canWrite || u.email === me?.email}
                            onClick={() => void setPlatStatus(u, 'suspended')}>停用</button>
                        : <button className="icon" disabled={!canWrite}
                            onClick={() => void setPlatStatus(u, 'active')}>启用</button>}
                    </td>
                  </tr>
                ))}
                {pusers.length === 0 && (
                  <tr><td colSpan={6}><div className="empty">暂无平台账号</div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'audit' && (
          <div className="card">
            <div className="card-head"><h3>平台操作审计</h3><div className="spacer" />
              <span className="hint">平台侧操作单独成表，与租户审计链分离</span></div>
            <table>
              <thead>
                <tr><th>时间</th><th>操作人</th><th>动作</th><th>对象</th><th>结果</th><th>来源</th></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="hint">{fmtTime(e.createdAt)}</td>
                    <td>{e.actor}</td>
                    <td><code>{e.action}</code></td>
                    <td>{e.target || '—'}</td>
                    <td><span className={`badge ${e.result === 'ok' ? 'ok' : 'error'}`}>{e.result}</span></td>
                    <td className="hint">{e.ip}</td>
                  </tr>
                ))}
                {events.length === 0 && <tr><td colSpan={6}><div className="empty">暂无记录</div></td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </main>

      {/* 租户详情抽屉：配额 / 域名 / 用量 */}
      {selected && (
        <>
          <div className="drawer-backdrop" onClick={() => navigate('/platform/tenants')} />
          <aside className="drawer" style={{ width: 460 }}>
            <div className="card-head">
              <h3>{selected.name}</h3>
              <div className="spacer" />
              <button className="ghost" onClick={() => navigate('/platform/tenants')}>关闭</button>
            </div>
            <div style={{ padding: 16, display: 'grid', gap: 16 }}>
              <div className="kv">
                <div><span>标识</span><b>{selected.slug}</b></div>
                <div><span>状态</span><b>{statusText[selected.status] ?? selected.status}</b></div>
                <div><span>档位</span><b>{editionText[selected.edition] ?? selected.edition ?? '—'}</b></div>
                <div><span>用量</span><b>{selected.users} 人 / {fmtBytes(selected.storageBytes)}</b></div>
                <div><span>创建</span><b>{fmtTime(selected.createdAt)}</b></div>
                <div><span>到期</span><b>{fmtTime(selected.trialEndsAt)}</b></div>
              </div>

              <div className="card pad">
                <div className="card-head" style={{ padding: 0, marginBottom: 10 }}>
                  <h3>档位</h3><div className="spacer" />
                  <span className="hint">
                    {edition ? `当前：${editionText[edition.edition] ?? edition.edition}` : '加载中…'}
                  </span>
                </div>
                {edition && (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                      <div className="field" style={{ minWidth: 130 }}>
                        <label>档位</label>
                        <select value={editionDraft} onChange={(e) => setEditionDraft(e.target.value)}>
                          <option value="basic">基础版</option>
                          <option value="professional">专业版</option>
                          <option value="business">商业版</option>
                        </select>
                      </div>
                      <div className="field" style={{ minWidth: 150 }}>
                        <label>到期日（留空=不限期）</label>
                        <input type="date" value={expiresDraft}
                          onChange={(e) => setExpiresDraft(e.target.value)} />
                      </div>
                      <div className="field" style={{ flex: 1, minWidth: 160 }}>
                        <label>变更原因</label>
                        <input value={reasonDraft} placeholder="如：2027 年续签"
                          onChange={(e) => setReasonDraft(e.target.value)} />
                      </div>
                      <button onClick={() => void saveEdition()}>保存档位</button>
                    </div>
                    <div className="hint">
                      改档立即生效（客户下次请求即按新档位判定）。到期后先给 30 天宽限，宽限结束自动降为基础版。
                      降档前会校验存量密级：不通过时返回受影响对象清单，不会"先降后报错"。
                    </div>
                    {edition.changes && edition.changes.length > 0 && (
                      <div style={{ fontSize: 12 }}>
                        <div className="hint" style={{ marginBottom: 4 }}>最近变更</div>
                        {edition.changes.slice(0, 5).map((c, i) => (
                          <div key={i} className="hint">
                            {fmtTime(c.createdAt)} · {c.fromEdition ? `${editionText[c.fromEdition] ?? c.fromEdition} → ` : ''}
                            {editionText[c.toEdition] ?? c.toEdition}
                            {c.operator ? ` · ${c.operator}` : ''}
                            {c.reason ? ` · ${c.reason}` : ''}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="card pad">
                <div className="card-head" style={{ padding: 0, marginBottom: 10 }}>
                  <h3>能力开关</h3><div className="spacer" />
                  <span className="hint">按租户覆盖，不改全局</span>
                </div>
                {tenantFlags.length === 0 && <div className="hint">读取中…</div>}
                {tenantFlags.map((f) => (
                  <div
                    key={f.code}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '7px 0', borderBottom: '1px solid #eef1f5',
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13 }}>{f.description}</div>
                      <div className="hint" style={{ fontSize: 11 }}>
                        <code>{f.code}</code> · {flagSourceText(f)}
                        {f.source !== 'override' && !f.defaultEnabled ? ' · 平台总开关已关闭' : ''}
                      </div>
                    </div>
                    <span className={`badge ${f.enabled ? 'ok' : 'plain'}`}>
                      {f.enabled ? '已开启' : '已关闭'}
                    </span>
                    {f.enabled ? (
                      <button className="icon danger" disabled={!canWrite}
                        onClick={() => void setTenantFlag(f, false)}>关闭</button>
                    ) : (
                      <button className="icon" disabled={!canWrite}
                        onClick={() => void setTenantFlag(f, true)}>开通</button>
                    )}
                    {f.source === 'override' && (
                      <button className="icon" disabled={!canWrite}
                        onClick={() => void setTenantFlag(f, null)}>恢复默认</button>
                    )}
                  </div>
                ))}
                <div className="hint" style={{ marginTop: 8 }}>
                  只影响当前租户。平台整体暂停（放量 0%）时，可在这里为个别客户单独开通——
                  合规场景下这个组合最常用：默认全关，按合同逐个开。
                </div>
              </div>

              <div className="card pad">
                <div className="card-head" style={{ padding: 0, marginBottom: 10 }}>
                  <h3>配额</h3><div className="spacer" />
                  <span className="hint">留空表示不限</span>
                </div>
                {quota && (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <div className="field">
                      <label>用户数上限</label>
                      <input type="number" min={0} value={quota.maxUsers ?? ''}
                        onChange={(e) => setQuota({ ...quota, maxUsers: e.target.value === '' ? null : Number(e.target.value) })} />
                    </div>
                    <div className="field">
                      <label>存储上限（GB）</label>
                      <input type="number" min={0} step={0.5}
                        value={quota.maxStorageBytes == null ? '' : quota.maxStorageBytes / (1024 ** 3)}
                        onChange={(e) => setQuota({
                          ...quota,
                          maxStorageBytes: e.target.value === '' ? null : Math.round(Number(e.target.value) * 1024 ** 3),
                        })} />
                    </div>
                    <div className="field">
                      <label>超限行为</label>
                      <select value={quota.onExceed} onChange={(e) => setQuota({ ...quota, onExceed: e.target.value })}>
                        <option value="reject">拒绝写入（硬拦）</option>
                        <option value="readonly">降级为只读</option>
                        <option value="warn">仅告警</option>
                      </select>
                    </div>
                    <button className="primary" disabled={!canWrite} onClick={() => void saveQuota()}>保存配额</button>
                  </div>
                )}
              </div>

              <div className="card pad">
                <div className="card-head" style={{ padding: 0, marginBottom: 10 }}>
                  <h3>自有域名</h3><div className="spacer" />
                  <button className="icon" disabled={!canWrite} onClick={() => void addDomain()}>绑定</button>
                </div>
                {domains.length === 0 && <div className="hint">未绑定域名</div>}
                {domains.map((d) => (
                  <div key={d.host} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0' }}>
                    <span>{d.host}</span>
                    {d.verified ? <span className="badge ok">已验证</span> : <span className="badge warn">待验证</span>}
                    {d.hasCert ? <span className="badge teal">有证书</span> : <span className="badge plain">无证书</span>}
                    <div className="spacer" style={{ flex: 1 }} />
                    {!d.verified && (
                      <button className="icon" disabled={!canWrite} onClick={() => void verifyDomain(d.host)}>验证</button>
                    )}
                    <button className="icon danger" disabled={!canWrite} onClick={() => void removeDomain(d.host)}>解绑</button>
                  </div>
                ))}
                <div className="hint" style={{ marginTop: 8 }}>
                  证书需上传（ACME 自动签发未实现：私有化环境通常不具备公网 80/443）。
                </div>
              </div>

              <div className="card pad">
                <div className="card-head" style={{ padding: 0, marginBottom: 10 }}>
                  <h3>近 30 天用量</h3>
                </div>
                {usage.length === 0 && <div className="hint">暂无计量数据</div>}
                {usage.slice(-12).map((p, i) => (
                  <div key={i} className="hint" style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>{p.day}</span><span>{p.metric}</span><b>{p.quantity}</b>
                  </div>
                ))}
              </div>
            </div>
          </aside>
        </>
      )}

      {creating && (
        <CreateTenant
          onClose={() => setCreating(false)}
          onDone={async () => {
            setCreating(false)
            await loadTenants()
            flash('租户已开通，管理员可立即登录')
          }}
        />
      )}

      {creatingUser && (
        <CreatePlatUser
          onClose={() => setCreatingUser(false)}
          onDone={async () => { setCreatingUser(false); await loadUsers(); flash('平台账号已创建') }}
        />
      )}

      {pwUser && (
        <ResetPlatPassword
          user={pwUser}
          onClose={() => setPwUser(null)}
          onDone={() => { setPwUser(null); flash('口令已重置，该账号需重新登录') }}
        />
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}

// ---------------- 开通租户 ----------------

function CreateTenant({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    slug: '', name: '', edition: 'basic', editionExpiresAt: '', trialDays: 0, contactEmail: '',
    adminUsername: 'admin', adminPassword: '', adminDisplayName: '',
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await call('/tenants', { method: 'POST', body: JSON.stringify(f) })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '开通失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 520 }}>
        <div className="modal-head">
          <strong>开通租户</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div className="field">
            <label>租户标识（登录时使用，小写字母/数字/连字符）</label>
            <input value={f.slug} onChange={(e) => setF({ ...f, slug: e.target.value })} required
              placeholder="acme" pattern="[a-z0-9][a-z0-9-]{1,40}" />
          </div>
          <div className="field">
            <label>租户名称</label>
            <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required />
          </div>
          <div className="field">
            <label>档位（开通即生效，事后可在详情页调整）</label>
            <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', padding: '2px 0' }}>
              {(['basic', 'professional', 'business'] as const).map((e) => (
                <label key={e} style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 400 }}>
                  <input
                    type="radio" name="edition" value={e}
                    checked={f.edition === e}
                    onChange={() => setF({ ...f, edition: e })}
                  />
                  {editionText[e]}
                </label>
              ))}
            </div>
            <span className="hint">{editionHint[f.edition]}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>档位到期日（留空 = 不限期）</label>
              <input type="date" value={f.editionExpiresAt}
                onChange={(e) => setF({ ...f, editionExpiresAt: e.target.value })} />
              <span className="hint">到期后有 30 天宽限，之后降为基础版，数据不动</span>
            </div>
            <div className="field">
              <label>试用天数（0 = 直接正式）</label>
              <input type="number" min={0} max={365} value={f.trialDays}
                onChange={(e) => setF({ ...f, trialDays: Number(e.target.value) })} />
            </div>
          </div>
          <div className="field">
            <label>联系邮箱</label>
            <input type="email" value={f.contactEmail} onChange={(e) => setF({ ...f, contactEmail: e.target.value })} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="field">
              <label>管理员账号</label>
              <input value={f.adminUsername} onChange={(e) => setF({ ...f, adminUsername: e.target.value })} required />
            </div>
            <div className="field">
              <label>管理员显示名</label>
              <input value={f.adminDisplayName} onChange={(e) => setF({ ...f, adminDisplayName: e.target.value })} />
            </div>
          </div>
          <div className="field">
            <label>初始口令（≥12 位，交付后请让客户立即修改）</label>
            <input type="text" value={f.adminPassword} onChange={(e) => setF({ ...f, adminPassword: e.target.value })}
              required minLength={12} />
          </div>
          {err && <div className="error-text">{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose}>取消</button>
            <button className="primary" type="submit" disabled={busy}>{busy ? '开通中…' : '开通'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------- 平台账号：新建 / 重置口令 ----------------

function CreatePlatUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ email: '', displayName: '', role: 'readonly', password: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await call('/users', { method: 'POST', body: JSON.stringify(f) })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '创建失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 480 }}>
        <div className="modal-head">
          <strong>新建平台账号</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div className="field">
            <label>邮箱（登录用）</label>
            <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required />
          </div>
          <div className="field">
            <label>姓名</label>
            <input value={f.displayName} onChange={(e) => setF({ ...f, displayName: e.target.value })} />
          </div>
          <div className="field">
            <label>角色</label>
            <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
              <option value="readonly">只读（排查问题用，不能变更）</option>
              <option value="ops">可操作（可开通租户、改配额、切开关）</option>
            </select>
          </div>
          <div className="field">
            <label>初始口令（≥12 位）</label>
            <input value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required minLength={12} />
          </div>
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

function ResetPlatPassword({ user, onClose, onDone }:
  { user: PlatUser; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await call(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify({ password: pw }) })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '重置失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 420 }}>
        <div className="modal-head">
          <strong>重置 {user.email} 的口令</strong><div className="spacer" />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
          <div className="field">
            <label>新口令（≥12 位）</label>
            <input value={pw} onChange={(e) => setPw(e.target.value)} required minLength={12} autoFocus />
          </div>
          <div className="hint">重置会立即吊销该账号的全部平台会话。</div>
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
