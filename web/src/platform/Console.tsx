// 平台运营控制台（桌面端）
//
// 这一版把布局从"浏览器默认流式"改成桌面后台骨架：
//   pf-shell（栅格）→ pf-side（240px 固定导航）+ pf-main（顶栏 + 可滚动内容区）。
//
// 为什么要重写而不是"补几条 CSS"：旧代码用的 .layout/.sidebar/.brand 这些类名
// 在 styles.css 里**都不存在**，实测 computed style 是 layout=block、
// sidebar=1600px、整页 1836px 高——即从上到下的竖排列表，看起来就是手机网页。
// 补样式也能"看起来像"，但两种来源（租户端骨架 / 运营台自编类名）会持续互相干扰，
// 所以这里改为独立的 pf- 命名空间，样式集中在 platform.css。
//
// 业务语义一处未改：档位、配额、域名、开关、用量、审计、账号，
// 以及"改档会校验存量密级""只读角色由服务端拒绝"等约束。

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import { currentPath, navigate, subscribe } from '../router'
import { applyTheme, cycleTheme } from '../api'
import { TOKEN_KEY, call, onUnauthorized, token } from './api'
import Entitlements from './Entitlements'
import TenantDetail from './TenantDetail'
import { CreatePlatUser, CreateTenant, ResetPlatPassword } from './modals'
import {
  Alert, Empty, PageHead, Panel, PfIcon, SearchBox, Stat, Toast, useConfirm,
} from './ui'
import {
  EDITION_TEXT, STATUS_TEXT, fmtBytes, fmtTime,
  type AuditEvent, type Drift, type Flag, type Me, type PlatUser, type Tenant,
} from './types'

// 菜单顺序与文案集中在一处：地址、侧栏、标题都从这里取，
// 避免"某个页签只加进了一边"这种只在点开时才发现的漏。
const TABS = [
  { key: 'tenants', label: '租户', icon: 'tenants' },
  { key: 'entitlements', label: '能力授权', icon: 'shield' },
  { key: 'usage', label: '用量与对账', icon: 'chart' },
  { key: 'flags', label: '灰度开关', icon: 'toggle' },
  { key: 'users', label: '平台账号', icon: 'users' },
  { key: 'audit', label: '平台审计', icon: 'list' },
] as const

type Tab = (typeof TABS)[number]['key']

const TAB_LABEL: Record<Tab, string> = Object.fromEntries(
  TABS.map((t) => [t.key, t.label]),
) as Record<Tab, string>

const TAB_SUB: Record<Tab, string> = {
  tenants: '每个租户是一个独立的组织空间。开通、改档、改配额、停用都在这里；点名称进入详情。',
  entitlements: '',
  usage: '计量数据由业务写入与触发器同事务维护；这里的核对用真实聚合重算并比对。',
  flags: '灰度开关决定"这个功能全平台放不放"。它与"客户买没买"（能力授权）是两件事。',
  users: '平台账号不属于任何租户。只读角色可以查全部数据，但变更由服务端拒绝。',
  audit: '平台侧操作单独成表，与租户自己的审计哈希链分离。',
}

// parsePlatformPath 把地址解析成"哪个页签 + 看哪个租户"。
//
// 地址是唯一真源：刷新、后退、把链接发给同事都必须落在同一处。
// 后端 /platform/* 已回落到 platform.html（internal/platform/webui），
// 所以 /platform/usage 这类地址直接刷新不会 404。
function parsePlatformPath(p: string): { tab: Tab; tenantSlug: string } {
  const clean = p.split('?')[0]
  const parts = clean.split('/').filter(Boolean)
  // /platform.html 是历史入口，按默认页签处理（挂载后会 replace 成规范地址）
  if (parts.length === 0 || parts[0] === 'platform.html') {
    return { tab: 'tenants', tenantSlug: '' }
  }
  const key = parts[1] ?? ''
  const hit = TABS.find((t) => t.key === key)
  const tab: Tab = hit ? hit.key : 'tenants'
  // 只有「租户」与「能力授权」带二级地址；其他页签的第三段忽略，
  // 避免出现"看似有效实则不存在"的地址。
  const tenantSlug = (tab === 'tenants' || tab === 'entitlements') ? (parts[2] ?? '') : ''
  return { tab, tenantSlug }
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
    <div className="pf-login">
      <aside className="pf-login-aside">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 40 }}>
            <span className="pf-brand-mark" aria-hidden />
            <b style={{ fontSize: 14, letterSpacing: '.02em' }}>NeuroDMS</b>
          </div>
          <h1>平台运营控制台</h1>
          <p>
            面向厂商运营：租户生命周期、档位与配额、能力授权、用量对账、灰度放量与平台审计。
          </p>
          <ul className="pf-login-points">
            <li>与租户管理台完全独立的两套账号体系</li>
            <li>只读角色可查全部数据，变更由服务端拒绝</li>
            <li>所有平台操作进入独立审计表，可按对象追溯</li>
          </ul>
        </div>
        <div className="pf-login-deco" aria-hidden>
          <i /><i /><i /><i />
        </div>
        <div className="pf-login-foot">
          仅授权人员使用 · 本页不被搜索引擎收录
        </div>
      </aside>

      <main className="pf-login-main">
        <div className="pf-login-card">
          <span className="pf-brand-mark" aria-hidden />
          <h2>登录</h2>
          <div className="sub">使用平台账号登录。租户账号无法进入本控制台。</div>
          <form onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
            <div className="field">
              <label htmlFor="pf-email">邮箱</label>
              <input
                id="pf-email" type="email" value={email} required autoComplete="username"
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="pf-pass">口令</label>
              <input
                id="pf-pass" type="password" value={password} required
                autoComplete="current-password" spellCheck={false}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {err && <div className="pf-note danger">{err}</div>}
            <button className="primary lg" type="submit" disabled={busy} style={{ marginTop: 4 }}>
              {busy ? '登录中…' : '登录'}
            </button>
          </form>
          <div className="hint" style={{ marginTop: 18 }}>
            忘记口令请联系另一位可操作账号的管理员重置；平台侧不提供自助找回。
          </div>
        </div>
      </main>
    </div>
  )
}

// ---------------- 主控制台 ----------------

export default function Console() {
  const [authed, setAuthed] = useState(!!token())
  const [me, setMe] = useState<Me | null>(null)
  const loc = useSyncExternalStore(subscribe, currentPath, currentPath)
  const { tab, tenantSlug } = parsePlatformPath(loc)

  const [toast, setToast] = useState('')
  const [err, setErr] = useState('')
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [flags, setFlags] = useState<Flag[]>([])
  const [drifts, setDrifts] = useState<Drift[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [pusers, setPusers] = useState<PlatUser[]>([])
  const [creatingUser, setCreatingUser] = useState(false)
  const [pwUser, setPwUser] = useState<PlatUser | null>(null)
  const [creating, setCreating] = useState(false)
  const [theme, setTheme] = useState<'auto' | 'light' | 'dark'>('auto')

  // 列表页的筛选与排序
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<{ key: 'name' | 'users' | 'storage' | 'files'; desc: boolean }>(
    { key: 'name', desc: false },
  )
  const [auditQ, setAuditQ] = useState('')

  const canWrite = me?.canWrite ?? false
  const { ask, dialog } = useConfirm()

  const flash = useCallback((m: string) => {
    setToast(m)
    window.setTimeout(() => setToast(''), 2400)
  }, [])

  const loadMe = useCallback(async () => {
    try {
      setMe(await call<Me>('/me'))
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
      const data = await call<{ items: AuditEvent[] }>('/audit?limit=200')
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
    void loadUsers()
    void loadAudit()
  }, [authed, loadMe, loadTenants, loadFlags, loadUsers, loadAudit])

  // 会话过期时回到登录页：清令牌 + 改界面状态，缺一处都会留下空壳页面。
  useEffect(() => {
    onUnauthorized(() => { setAuthed(false); setMe(null) })
    return () => onUnauthorized(null)
  }, [])

  // 历史入口规范化：/platform.html 与 /platform 都 replace 成 /platform/tenants，
  // 让收藏与复制的地址是稳定形式。
  useEffect(() => {
    const p = window.location.pathname
    if (p === '/platform.html' || p === '/platform' || p === '/platform/') {
      navigate('/platform/tenants', true)
    }
  }, [])

  // 主题：沿用租户端的 dv.theme，运营台与工作台切换一次两处一致。
  useEffect(() => {
    const saved = (localStorage.getItem('dv.theme') as 'auto' | 'light' | 'dark' | null) ?? 'auto'
    setTheme(saved)
    applyTheme(saved)
  }, [])

  // ---------------- 租户动作 ----------------

  function patchStatus(t: Tenant, status: string) {
    const label = STATUS_TEXT[status] ?? status
    const run = async () => {
      try {
        await call(`/tenants/${t.slug}`, { method: 'PATCH', body: JSON.stringify({ status }) })
        flash(`已将 ${t.slug} 置为「${label}」`)
        await loadTenants()
      } catch (e) {
        setErr(e instanceof Error ? e.message : '操作失败')
      }
    }
    if (status === 'suspended') {
      ask({
        title: '停用租户',
        body: <>停用「{t.name}」会<b>立即吊销该租户全部已登录会话</b>，成员无法再登录。数据保留。</>,
        confirmText: '停用',
        danger: true,
        onConfirm: run,
      })
      return
    }
    if (status === 'readonly') {
      // 设只读不是"温和的停用"：成员仍能登录、仍能下载，但所有写入被拒。
      // 客户会以为是故障，所以先确认一次。
      ask({
        title: '设为只读',
        body: <>将「{t.name}」置为只读后，成员<b>仍可登录与下载</b>，但所有写入（上传、新建、改权限）都会被服务端拒绝。</>,
        confirmText: '设为只读',
        onConfirm: run,
      })
      return
    }
    void run()
  }

  function deleteTenant(t: Tenant) {
    ask({
      title: '逻辑删除租户',
      body: (
        <>
          将「{t.name}」（<code>{t.slug}</code>）标记为已删除，<b>数据保留 30 天</b>。
          期间可由平台恢复，30 天后进入清理流程。
        </>
      ),
      confirmText: '删除',
      danger: true,
      onConfirm: async () => {
        try {
          await call(`/tenants/${t.slug}`, { method: 'DELETE' })
          flash('已逻辑删除，保留期 30 天')
          await loadTenants()
        } catch (e) {
          setErr(e instanceof Error ? e.message : '删除失败')
        }
      },
    })
  }

  // ---------------- 平台账号动作 ----------------

  function setPlatStatus(u: PlatUser, status: 'active' | 'suspended') {
    const word = status === 'active' ? '启用' : '停用'
    const run = async () => {
      try {
        await call(`/users/${u.id}/status`, { method: 'POST', body: JSON.stringify({ status }) })
        flash(`已${word}`)
        await loadUsers()
      } catch (e) {
        setErr(e instanceof Error ? e.message : `${word}失败`)
      }
    }
    if (status === 'suspended') {
      ask({
        title: '停用平台账号',
        body: <>停用 <b>{u.email}</b> 后其平台会话立即失效，无法再登录运营台。</>,
        confirmText: '停用',
        danger: true,
        onConfirm: run,
      })
      return
    }
    void run()
  }

  // ---------------- 对账与开关 ----------------

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
  // 不能只看 defaultEnabled：放量 0% 时总开关开着，实际对所有人关闭。
  function flagActive(f: Flag) {
    return f.defaultEnabled && f.rolloutPercent > 0
  }

  async function toggleFlag(f: Flag) {
    const on = flagActive(f)
    // 从"已暂停（放量 0%）"点开时同时把放量恢复满额：
    // 否则点了按钮状态仍是关闭的，用户会以为按钮坏了。
    const next = on
      ? { defaultEnabled: false, rolloutPercent: f.rolloutPercent }
      : { defaultEnabled: true, rolloutPercent: f.rolloutPercent > 0 ? f.rolloutPercent : 100 }
    try {
      await call(`/flags/${f.code}`, { method: 'PUT', body: JSON.stringify(next) })
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

  async function doLogout() {
    try {
      await call('/auth/logout', { method: 'POST' })
    } catch { /* 网络失败也要退出本地 */ }
    sessionStorage.removeItem(TOKEN_KEY)
    // 只退平台身份。平台令牌在 sessionStorage、租户令牌在 localStorage，本就是两套：
    // 顺手把租户端也踢下线会影响"同一浏览器里还开着工作台"的正常用法。
    setAuthed(false)
    setMe(null)
  }

  function switchTheme() {
    const next = cycleTheme()
    setTheme(next)
  }

  const totals = useMemo(() => tenants.reduce(
    (a, t) => ({
      users: a.users + t.users,
      storage: a.storage + t.storageBytes,
      files: a.files + t.files,
    }),
    { users: 0, storage: 0, files: 0 },
  ), [tenants])

  const shownTenants = useMemo(() => {
    const k = q.trim().toLowerCase()
    const list = k
      ? tenants.filter((t) => t.slug.toLowerCase().includes(k) || t.name.toLowerCase().includes(k))
      : [...tenants]
    const dir = sort.desc ? -1 : 1
    list.sort((a, b) => {
      if (sort.key === 'name') return a.name.localeCompare(b.name, 'zh-CN') * dir
      if (sort.key === 'users') return (a.users - b.users) * dir
      if (sort.key === 'files') return (a.files - b.files) * dir
      return (a.storageBytes - b.storageBytes) * dir
    })
    return list
  }, [tenants, q, sort])

  const shownEvents = useMemo(() => {
    const k = auditQ.trim().toLowerCase()
    if (!k) return events
    return events.filter((e) =>
      e.action.toLowerCase().includes(k) ||
      e.actor.toLowerCase().includes(k) ||
      (e.target ?? '').toLowerCase().includes(k))
  }, [events, auditQ])

  if (!authed) {
    return (
      <Login
        onDone={() => {
          setAuthed(true)
          // 登录页地址（/platform/login）不是合法页签地址：
          // 不收敛的话，刷新后地址栏会停在一个"能看但不能复制给别人"的位置。
          const p = window.location.pathname
          if (p === '/platform/login' || p === '/platform' || p === '/platform/' ) {
            navigate('/platform/tenants', true)
          }
        }}
      />
    )
  }

  const meName = me?.static ? '应急令牌' : (me?.email ?? '—')

  return (
    <div className="pf-shell">
      {/* -------- 侧栏 -------- */}
      <aside className="pf-side">
        <div className="pf-brand">
          <span className="pf-brand-mark" aria-hidden />
          <div className="pf-brand-text">
            <b>平台运营</b>
            <span>Console</span>
          </div>
        </div>

        <nav className="pf-nav" aria-label="主导航">
          <div className="pf-nav-label">运营</div>
          {TABS.map((t) => (
            <button
              key={t.key}
              className={`pf-nav-item ${tab === t.key ? 'on' : ''}`}
              aria-current={tab === t.key ? 'page' : undefined}
              onClick={() => navigate(`/platform/${t.key}`)}
            >
              <PfIcon name={t.icon} />
              {t.label}
              {t.key === 'tenants' && tenants.length > 0 && (
                <span className="pf-nav-count">{tenants.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="pf-side-foot">
          <div className="pf-who">
            <div className="pf-avatar" aria-hidden>
              {(me?.email ?? 'P').slice(0, 1)}
            </div>
            <div className="pf-who-text">
              <b>{meName}</b>
              <span>{me?.static ? '静态令牌 · 仅应急' : (me?.role === 'readonly' ? '只读角色' : '可操作')}</span>
            </div>
          </div>
          <button className="ghost" onClick={() => void doLogout()}>退出登录</button>
        </div>
      </aside>

      {/* -------- 主区 -------- */}
      <div className="pf-main">
        <header className="pf-appbar">
          <div className="pf-crumbs">
            <span>平台运营</span>
            <span className="sep">/</span>
            <b>{TAB_LABEL[tab]}</b>
            {tab === 'tenants' && tenantSlug && (
              <>
                <span className="sep">/</span>
                <span>{tenantSlug}</span>
              </>
            )}
          </div>
          <div className="pf-grow" />
          <div className="pf-appbar-actions">
            {/* 身份已在侧栏底部展示，顶栏只保留"当前不能写"这个会改变行为的状态，
                避免同一信息在一屏里出现两次。 */}
            {!canWrite && <span className="badge warn">只读角色</span>}
            <button
              className="icon" onClick={switchTheme}
              title={`主题：${theme === 'auto' ? '跟随系统' : theme === 'dark' ? '深色' : '浅色'}`}
              aria-label="切换主题"
            >
              <PfIcon name={theme === 'dark' ? 'moon' : 'sun'} />
            </button>
          </div>
        </header>

        <div className="pf-content">
          <div className="pf-inner">
            {err && <Alert text={err} onClose={() => setErr('')} />}

            {/* ---- 租户详情（整页，替代原来的遮罩抽屉） ---- */}
            {tab === 'tenants' && tenantSlug && (
              <TenantDetail
                slug={tenantSlug}
                canWrite={canWrite}
                onBack={() => navigate('/platform/tenants')}
                onChanged={() => void loadTenants()}
                flash={flash}
              />
            )}

            {/* ---- 租户列表 ---- */}
            {tab === 'tenants' && !tenantSlug && (
              <>
                <PageHead
                  title="租户"
                  sub={TAB_SUB.tenants}
                  actions={
                    <button className="primary" disabled={!canWrite} onClick={() => setCreating(true)}>
                      <PfIcon name="plus" />开通租户
                    </button>
                  }
                />

                <div className="pf-stats">
                  <Stat k="租户" v={tenants.length} s={`正常 ${tenants.filter((t) => t.status === 'active').length} 个`} />
                  <Stat k="用户" v={totals.users} s="全部租户合计" />
                  <Stat k="文件" v={totals.files} s="全部租户合计" />
                  <Stat k="存储" v={fmtBytes(totals.storage)} s="含版本与预览件" />
                </div>

                <Panel body="none">
                  <div className="pf-toolrow">
                    <SearchBox
                      value={q} onChange={setQ} ariaLabel="搜索租户"
                      placeholder="按名称或标识搜索"
                    />
                    <div className="pf-grow" />
                    <span className="hint">
                      共 {tenants.length} 个，显示 {shownTenants.length} 个
                    </span>
                  </div>
                  <div className="pf-tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th>租户</th>
                          <th style={{ width: 90 }}>状态</th>
                          <th style={{ width: 130 }}>档位</th>
                          <th className="pf-r" style={{ width: 90 }}>
                            <button
                              className="ghost sm" style={{ padding: 0, height: 'auto' }}
                              onClick={() => setSort({ key: 'users', desc: sort.key === 'users' ? !sort.desc : true })}
                            >
                              用户{sort.key === 'users' ? (sort.desc ? ' ↓' : ' ↑') : ''}
                            </button>
                          </th>
                          <th className="pf-r" style={{ width: 90 }}>
                            <button
                              className="ghost sm" style={{ padding: 0, height: 'auto' }}
                              onClick={() => setSort({ key: 'files', desc: sort.key === 'files' ? !sort.desc : true })}
                            >
                              文件{sort.key === 'files' ? (sort.desc ? ' ↓' : ' ↑') : ''}
                            </button>
                          </th>
                          <th className="pf-r" style={{ width: 110 }}>
                            <button
                              className="ghost sm" style={{ padding: 0, height: 'auto' }}
                              onClick={() => setSort({ key: 'storage', desc: sort.key === 'storage' ? !sort.desc : true })}
                            >
                              存储{sort.key === 'storage' ? (sort.desc ? ' ↓' : ' ↑') : ''}
                            </button>
                          </th>
                          <th className="pf-sticky" style={{ width: 250 }}>操作</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shownTenants.map((t) => (
                          <tr key={t.slug}>
                            <td className="name">
                              <button
                                className="ghost" style={{ padding: 0, height: 'auto', fontWeight: 600 }}
                                onClick={() => navigate(`/platform/tenants/${t.slug}`)}
                              >
                                {t.name}
                              </button>
                              <div className="hint" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{t.slug}</div>
                            </td>
                            <td>
                              <span className={`badge ${t.status === 'active' ? 'ok' : t.status === 'suspended' ? 'danger' : 'warn'}`}>
                                {STATUS_TEXT[t.status] ?? t.status}
                              </span>
                            </td>
                            <td>
                              {EDITION_TEXT[t.edition] ?? t.edition ?? '—'}
                              {t.editionExpiresAt && (
                                <div className="hint" style={{ fontSize: 11 }}>
                                  至 {t.editionExpiresAt.slice(0, 10)}
                                </div>
                              )}
                            </td>
                            <td className="pf-r" style={{ fontVariantNumeric: 'tabular-nums' }}>{t.users}</td>
                            <td className="pf-r" style={{ fontVariantNumeric: 'tabular-nums' }}>{t.files}</td>
                            <td className="pf-r" style={{ fontVariantNumeric: 'tabular-nums' }}>{fmtBytes(t.storageBytes)}</td>
                            <td className="pf-sticky">
                              <button className="sm" onClick={() => navigate(`/platform/tenants/${t.slug}`)}>详情</button>
                              {canWrite && t.status !== 'suspended' && (
                                <button className="sm danger" onClick={() => patchStatus(t, 'suspended')}>停用</button>
                              )}
                              {canWrite && t.status !== 'active' && t.status !== 'suspended' && (
                                <button className="sm" onClick={() => patchStatus(t, 'active')}>恢复</button>
                              )}
                              {canWrite && t.status !== 'readonly' && (
                                <button className="sm" onClick={() => patchStatus(t, 'readonly')}>设只读</button>
                              )}
                              {canWrite && (
                                <button className="sm danger" onClick={() => deleteTenant(t)}>删除</button>
                              )}
                            </td>
                          </tr>
                        ))}
                        {shownTenants.length === 0 && (
                          <tr>
                            <td colSpan={7}>
                              <Empty
                                icon="tenants"
                                title={tenants.length === 0 ? '还没有租户' : '没有匹配的租户'}
                                hint={tenants.length === 0
                                  ? '点右上角「开通租户」创建第一个客户空间。'
                                  : '换个关键字再试。'}
                              />
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </>
            )}

            {/* ---- 能力授权 ---- */}
            {tab === 'entitlements' && (
              <Entitlements
                tenantSlug={tenantSlug}
                canWrite={canWrite}
                tenants={tenants.map((t) => ({ slug: t.slug, name: t.name, edition: t.edition }))}
                onPick={(slug) => navigate(slug ? `/platform/entitlements/${slug}` : '/platform/entitlements')}
              />
            )}

            {/* ---- 用量与对账 ---- */}
            {tab === 'usage' && (
              <>
                <PageHead
                  title="用量与对账"
                  sub={TAB_SUB.usage}
                  actions={
                    <>
                      <button onClick={() => void runReconcile(false)}>对账检查</button>
                      <button className="primary" disabled={!canWrite} onClick={() => void runReconcile(true)}>
                        对账并修正
                      </button>
                    </>
                  }
                />
                <Panel
                  title="账实核对"
                  sub="存储与用户数由数据库触发器与业务写入同事务维护"
                  body="none"
                >
                  <div className="pf-tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th>租户</th>
                          <th className="pf-r">账本存储</th>
                          <th className="pf-r">实际存储</th>
                          <th className="pf-r">存储偏差</th>
                          <th className="pf-r">账本用户</th>
                          <th className="pf-r">实际用户</th>
                          <th className="pf-r">用户偏差</th>
                        </tr>
                      </thead>
                      <tbody>
                        {drifts.map((d) => (
                          <tr key={d.slug}>
                            <td className="name">
                              <button
                                className="ghost" style={{ padding: 0, height: 'auto' }}
                                onClick={() => navigate(`/platform/tenants/${d.slug}`)}
                              >
                                {d.slug}
                              </button>
                            </td>
                            <td className="pf-r">{fmtBytes(d.storageRecorded)}</td>
                            <td className="pf-r">{fmtBytes(d.storageActual)}</td>
                            <td className="pf-r" style={{ color: d.storageDrift ? 'var(--danger)' : undefined }}>
                              {d.storageDrift ? fmtBytes(Math.abs(d.storageDrift)) : '0'}
                            </td>
                            <td className="pf-r">{d.usersRecorded}</td>
                            <td className="pf-r">{d.usersActual}</td>
                            <td className="pf-r" style={{ color: d.usersDrift ? 'var(--danger)' : undefined }}>
                              {d.usersDrift || '0'}
                            </td>
                          </tr>
                        ))}
                        {drifts.length === 0 && (
                          <tr>
                            <td colSpan={7}>
                              <Empty
                                icon="chart" title="还没有核对结果"
                                hint="点右上角「对账检查」用真实聚合重算一遍，不会修改任何数据。"
                              />
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </>
            )}

            {/* ---- 灰度开关 ---- */}
            {tab === 'flags' && (
              <>
                <PageHead title="灰度开关" sub={TAB_SUB.flags} />

                {flags.some((f) => f.defaultEnabled && f.rolloutPercent <= 0) && (
                  <div style={{ marginBottom: 14 }}>
                    <div className="pf-note warn">
                      <PfIcon name="alert" />
                      <div>
                        有开关处于<b>「总开关开启 + 放量 0%」</b>：这是暂停状态，对所有租户实际关闭。
                        要给个别客户开通，去「能力授权」为该租户单独覆盖。
                      </div>
                    </div>
                  </div>
                )}

                <Panel body="none">
                  <div className="pf-tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 240 }}>开关</th>
                          <th>说明</th>
                          <th style={{ width: 140 }}>状态</th>
                          <th style={{ width: 320 }}>放量</th>
                        </tr>
                      </thead>
                      <tbody>
                        {flags.map((f) => (
                          <tr key={f.code}>
                            <td className="name"><code style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{f.code}</code></td>
                            <td>{f.description}</td>
                            <td>
                              <button
                                className={flagActive(f) ? 'accent sm' : 'sm'}
                                disabled={!canWrite}
                                onClick={() => void toggleFlag(f)}
                              >
                                {flagActive(f) ? '已开启' : f.defaultEnabled ? '已暂停' : '已关闭'}
                              </button>
                            </td>
                            <td>
                              <div className="seg">
                                {[0, 10, 25, 50, 100].map((p) => (
                                  <button
                                    key={p} className={f.rolloutPercent === p ? 'on' : ''}
                                    disabled={!canWrite} onClick={() => void setRollout(f, p)}
                                  >
                                    {p}%
                                  </button>
                                ))}
                              </div>
                            </td>
                          </tr>
                        ))}
                        {flags.length === 0 && (
                          <tr><td colSpan={4}><Empty title="没有开关" hint="检查迁移是否已执行。" /></td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <div style={{ marginTop: 14 }}>
                  <div className="pf-note">
                    <PfIcon name="toggle" />
                    <div>
                      开关变更 30 秒内全实例生效；关闭后由服务端拒绝，不是隐藏界面。
                      「放量 0%」等价于对所有租户关闭，但总开关仍显示为开——这是最容易误判的一种状态。
                    </div>
                  </div>
                </div>
              </>
            )}

            {/* ---- 平台账号 ---- */}
            {tab === 'users' && (
              <>
                <PageHead
                  title="平台账号"
                  sub={TAB_SUB.users}
                  actions={
                    <button className="primary" disabled={!canWrite} onClick={() => setCreatingUser(true)}>
                      <PfIcon name="plus" />新建平台账号
                    </button>
                  }
                />
                <Panel body="none">
                  <div className="pf-tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th>邮箱</th>
                          <th style={{ width: 140 }}>姓名</th>
                          <th style={{ width: 110 }}>角色</th>
                          <th style={{ width: 110 }}>状态</th>
                          <th style={{ width: 180 }}>最近登录</th>
                          <th className="pf-sticky" style={{ width: 200 }}>操作</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pusers.map((u) => (
                          <tr key={u.id}>
                            <td className="name">
                              {u.email}
                              {u.email === me?.email && (
                                <span className="badge plain" style={{ marginLeft: 6 }}>我</span>
                              )}
                            </td>
                            <td>{u.displayName || '—'}</td>
                            <td>
                              <span className={`badge ${u.role === 'ops' ? 'teal' : 'plain'}`}>
                                {u.role === 'ops' ? '可操作' : '只读'}
                              </span>
                            </td>
                            <td>
                              <span className={`badge ${u.status === 'active' ? 'ok' : 'danger'}`}>
                                {u.status === 'active' ? '启用' : '已停用'}
                              </span>
                            </td>
                            <td className="hint" style={{ fontSize: 12 }}>{fmtTime(u.lastLoginAt)}</td>
                            <td className="pf-sticky">
                              <button className="sm" disabled={!canWrite} onClick={() => setPwUser(u)}>
                                重置口令
                              </button>
                              {u.status === 'active' ? (
                                <button
                                  className="sm danger"
                                  disabled={!canWrite || u.email === me?.email}
                                  title={u.email === me?.email ? '不能停用自己，避免把自己锁在门外' : undefined}
                                  onClick={() => setPlatStatus(u, 'suspended')}
                                >
                                  停用
                                </button>
                              ) : (
                                <button className="sm" disabled={!canWrite} onClick={() => setPlatStatus(u, 'active')}>
                                  启用
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                        {pusers.length === 0 && (
                          <tr><td colSpan={6}><Empty icon="users" title="暂无平台账号" /></td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </>
            )}

            {/* ---- 平台审计 ---- */}
            {tab === 'audit' && (
              <>
                <PageHead
                  title="平台审计"
                  sub={TAB_SUB.audit}
                  actions={<button onClick={() => void loadAudit()}>刷新</button>}
                />
                <Panel body="none">
                  <div className="pf-toolrow">
                    <SearchBox
                      value={auditQ} onChange={setAuditQ} ariaLabel="筛选审计"
                      placeholder="按动作、操作人或对象筛选"
                    />
                    <div className="pf-grow" />
                    <span className="hint">最近 {events.length} 条 · 按时间倒序</span>
                  </div>
                  <div className="pf-tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 170 }}>时间</th>
                          <th style={{ width: 200 }}>操作人</th>
                          <th style={{ width: 260 }}>动作</th>
                          <th>对象</th>
                          <th style={{ width: 90 }}>结果</th>
                          <th style={{ width: 150 }}>来源</th>
                        </tr>
                      </thead>
                      <tbody>
                        {shownEvents.map((e) => (
                          <tr key={e.id}>
                            <td className="hint" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmtTime(e.createdAt)}</td>
                            <td>{e.actor}</td>
                            <td><code style={{ fontFamily: 'var(--mono)', fontSize: 11.5 }}>{e.action}</code></td>
                            <td>{e.target || '—'}</td>
                            <td>
                              <span className={`badge ${e.result === 'ok' ? 'ok' : 'danger'}`}>{e.result}</span>
                            </td>
                            <td className="hint" style={{ fontSize: 12 }}>{e.ip}</td>
                          </tr>
                        ))}
                        {shownEvents.length === 0 && (
                          <tr>
                            <td colSpan={6}>
                              <Empty
                                icon="list"
                                title={events.length === 0 ? '暂无记录' : '没有匹配的记录'}
                                hint={events.length === 0 ? '平台侧还没有产生需要留痕的操作。' : '换个关键字再试。'}
                              />
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </>
            )}
          </div>
        </div>
      </div>

      {creating && (
        <CreateTenant
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false)
            void loadTenants()
            flash('租户已开通，管理员可立即登录')
          }}
        />
      )}

      {creatingUser && (
        <CreatePlatUser
          onClose={() => setCreatingUser(false)}
          onDone={() => { setCreatingUser(false); void loadUsers(); flash('平台账号已创建') }}
        />
      )}

      {pwUser && (
        <ResetPlatPassword
          user={pwUser}
          onClose={() => setPwUser(null)}
          onDone={() => { setPwUser(null); void loadUsers(); flash('口令已重置，该账号需重新登录') }}
        />
      )}

      {dialog}
      <Toast text={toast} />
    </div>
  )
}
