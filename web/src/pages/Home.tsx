import { useCallback, useEffect, useState } from 'react'
import { api, applyTheme, cycleTheme, fetchMe, type Me } from '../api'
import { Shell } from '../components/Shell'
import { Icon, InfoDot, Tooltip, fmtSize, relTime } from '../components/ui'
import AccountDrawer from './AccountDrawer'
import { adminPath, filesPath, navigate, previewPath } from '../router'

// 登录后的第一屏：个人工作台。
//
// 为什么不再直接落到"文件"：文件页只回答"这个目录里有什么"，
// 回答不了"我今天该做什么、我最近在弄什么、我的空间还健康吗"。
// 首页按"待办 → 最近 → 资产 → 角色职责"排，是因为这四件事的紧迫性依次递减。

type WsSpace = {
  id: string
  name: string
  kind: string
  ownerId?: string
  ownerName?: string
  usedBytes: number
  quotaBytes?: number | null
  classification?: number
  createdAt?: string
  lastActivity?: string | null
}

type RecentItem = {
  id: string
  name: string
  kind: string
  spaceId: string
  spaceName: string
  action: string
  at: string
}

type Todo = {
  kind: 'transfer' | 'share'
  id: string
  title: string
  detail: string
  url: string
  expiresAt?: string
}

type Ws = {
  spaces: WsSpace[]
  recent: RecentItem[]
  todos: Todo[]
  roles: string[]
  stats: {
    ownedSpaces: number
    sharedSpaces: number
    totalSpaces: number
    storageUsedBytes: number
    pendingTransfers: number
    pendingShareApprovals: number
    activeShares: number
    recentCount: number
  }
  sysadmin?: {
    users: number; spaces: number; files: number; usedBytes: number
    onlyOwnerSpaces: number; orphanSpaces: number
  }
  secadmin?: {
    pendingDowngrades: number
    distribution: Record<string, number>
  }
  auditor?: {
    events24h: number; denied24h: number
    lastAnchorDay?: string; lastAnchorCount?: number
  }
}

const KIND_LABEL: Record<string, string> = {
  personal: '个人空间', dept: '部门空间', project: '项目空间', knowledge: '知识库', archive: '归档空间',
}

const ACTION_LABEL: Record<string, string> = {
  'node.preview': '查看',
  'node.download': '下载',
  'node.upload': '上传',
  'node.rename': '重命名',
  'node.version.restore': '回退版本',
  'node.edit': '编辑',
}

function greeting(): string {
  const h = new Date().getHours()
  if (h < 6) return '夜深了'
  if (h < 12) return '早上好'
  if (h < 14) return '中午好'
  if (h < 18) return '下午好'
  return '晚上好'
}

function iconFor(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase() ?? ''
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'heic', 'bmp', 'svg', 'tif', 'tiff'].includes(ext)) return 'file'
  if (['mp4', 'mov', 'mkv', 'avi', 'webm'].includes(ext)) return 'play'
  return 'file'
}

export default function Home() {
  const [me, setMe] = useState<Me | null>(null)
  const [data, setData] = useState<Ws | null>(null)
  const [err, setErr] = useState('')
  const [accountOpen, setAccountOpen] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  const load = useCallback(async () => {
    setErr('')
    try {
      const [ws, who] = await Promise.all([api<Ws>('/v1/workspace'), fetchMe()])
      setData(ws)
      setMe(who)
    } catch {
      setErr('工作台数据加载失败，请刷新重试')
    }
  }, [])

  useEffect(() => {
    applyTheme()
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')
    void load()
  }, [load])

  const stats = data?.stats
  const spaces = data?.spaces ?? []
  const recent = data?.recent ?? []
  const todos = data?.todos ?? []
  const roles = data?.roles ?? []
  // 管理员通常没有自己的空间；此时个人区全空，摆出来只会让人觉得"系统里没东西"。
  // 有内容或有待办才展示个人区，否则用一行说明带过。
  const hasPersonal = (stats?.totalSpaces ?? 0) > 0 || recent.length > 0
  const isSys = roles.includes('sysadmin')
  const isSec = roles.includes('secadmin')
  const isAud = roles.includes('auditor')

  return (
    <Shell
      me={me}
      spaces={spaces}
      activeSpaceId=""
      onSpace={(id) => navigate(filesPath(id))}
      spaceName="工作台"
      crumbs={[]}
      onOpenAccount={() => setAccountOpen(true)}
      onToggleTheme={() => { const t = cycleTheme(); setTheme(t === 'dark' ? 'dark' : 'light') }}
      theme={theme}
      actions={
        <button className="primary sm" onClick={() => navigate('/files')}>
          <Icon name="folder" size={14} /> 打开文件
        </button>
      }
    >
      <div className="home">
        <header className="home-hero">
          <div>
            <div className="hello">
              {greeting()}{me?.displayName ? `，${me.displayName}` : ''}
            </div>
            <div className="sub">
              {isSys ? '系统管理员' : isSec ? '安全管理员' : isAud ? '审计管理员' : '成员'}
              <span className="dim"> · </span>
              密级 {me?.classification ?? '—'}
              <span className="dim"> · </span>
              {new Date().toLocaleDateString('zh-CN', { month: 'long', day: 'numeric', weekday: 'long' })}
            </div>
          </div>
          <div className="quick">
            <Tooltip content={<><b>跨空间搜索</b><div className="tip-note">按 ⌘K / Ctrl+K，或在顶栏搜索框输入。</div></>}>
              <button className="sm" onClick={() => { /* 交给顶栏搜索，这里只作提示 */ }}>
                <Icon name="search" size={14} /> 搜文件
              </button>
            </Tooltip>
            <button className="sm" onClick={() => navigate('/activity')}>
              <Icon name="clock" size={14} /> 我最近的操作
            </button>
          </div>
        </header>

        {err && (
          <div className="banner danger">
            <span className="ico"><Icon name="alert" size={15} /></span>
            <span>{err}</span>
          </div>
        )}

        {/* 待办：有才显示，避免首页永远挂一块空区块 */}
        {todos.length > 0 && (
          <section className="home-sec">
            <div className="sec-head">
              <h2>等你处理</h2>
              <span className="count">{todos.length}</span>
              <InfoDot title="这些是什么">
                <p><b>移交确认</b>：管理员想把你的空间移交给他自己，需要你同意；7 天不处理自动失效。</p>
                <p><b>外发审批</b>：别人创建的外发链接落在你有管理权限的对象上，需要你批。</p>
                <div className="pop-foot">两项都只在"确实轮到你"时出现，不会因为角色而虚增。</div>
              </InfoDot>
            </div>
            <div className="todo-list">
              {todos.map((t) => (
                <div className={`todo${t.kind === 'transfer' ? ' warn' : ''}`} key={t.kind + t.id}>
                  <span className="ico">
                    <Icon name={t.kind === 'transfer' ? 'share' : 'shield'} size={16} />
                  </span>
                  <div className="txt">
                    <b>{t.title}</b>
                    <span className="note">{t.detail}</span>
                  </div>
                  <button className="sm" onClick={() => navigate(t.url)}>
                    {t.kind === 'transfer' ? '去处理' : '去审批'}
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* 角色工作台 */}
        {(isSys || isSec || isAud) && (
          <section className="home-sec">
            <div className="sec-head">
              <h2>职责视图</h2>
              <InfoDot title="为什么管理员看到的不一样">
                <p>管理角色管的是<b>配置与治理</b>，不是内容：系统管理员看不到别人空间里的文件，除非被显式授权。</p>
                <p>所以这里的数字是"资产有没有人管、有没有待审的事"，而不是"公司有多少文件"。</p>
                <div className="pop-foot">三权分立：系统/安全管理员与审计管理员不能并存于同一账号。</div>
              </InfoDot>
            </div>
            <div className="role-grid">
              {isSys && data?.sysadmin && (
                <div className="role-card">
                  <div className="rh">
                    <span className="badge brand">系统管理员</span>
                    <div className="grow" />
                    <button className="ghost sm" onClick={() => navigate(adminPath(''))}>管理台</button>
                  </div>
                  <div className="mini-row">
                    <div><b>{data.sysadmin.users}</b><span>在用账号</span></div>
                    <div><b>{data.sysadmin.spaces}</b><span>空间</span></div>
                    <div><b>{data.sysadmin.files}</b><span>文件</span></div>
                    <div><b>{fmtSize(data.sysadmin.usedBytes)}</b><span>总占用</span></div>
                  </div>
                  {(data.sysadmin.onlyOwnerSpaces > 0 || data.sysadmin.orphanSpaces > 0) && (
                    <div className={`role-alert${data.sysadmin.orphanSpaces > 0 ? ' danger' : ''}`}>
                      <Icon name="alert" size={14} />
                      <span>
                        {data.sysadmin.orphanSpaces > 0
                          ? <>有 <b>{data.sysadmin.orphanSpaces}</b> 个空间的所有者已停用/删除且无其他授权，现在没人能管。</>
                          : <>有 <b>{data.sysadmin.onlyOwnerSpaces}</b> 个空间仅所有者可达，所有者一旦停用就会失联。</>}
                      </span>
                      <button className="sm" onClick={() => navigate(adminPath('spaces'))}>空间台账</button>
                    </div>
                  )}
                  <div className="links">
                    <button onClick={() => navigate(adminPath('members'))}>成员与角色</button>
                    <button onClick={() => navigate(adminPath('spaces'))}>空间台账</button>
                    <button onClick={() => navigate(adminPath('settings'))}>系统设置</button>
                    <button onClick={() => navigate(adminPath('share-approvals'))}>外发审批</button>
                  </div>
                </div>
              )}

              {isSec && data?.secadmin && (
                <div className="role-card">
                  <div className="rh">
                    <span className="badge teal">安全管理员</span>
                    <div className="grow" />
                    <button className="ghost sm" onClick={() => navigate(adminPath('class'))}>密级定义</button>
                  </div>
                  <div className="mini-row">
                    <div><b>{data.secadmin.pendingDowngrades}</b><span>待审降密</span></div>
                    <div><b>{Object.values(data.secadmin.distribution).reduce((a, b) => a + b, 0)}</b><span>文件总数</span></div>
                  </div>
                  <div className="dist">
                    {Object.entries(data.secadmin.distribution).sort((a, b) => Number(a[0]) - Number(b[0])).map(([lv, n]) => {
                      const total = Object.values(data.secadmin!.distribution).reduce((a, b) => a + b, 0) || 1
                      return (
                        <div className="dist-row" key={lv}>
                          <span className="lv">密级 {lv}</span>
                          <span className="bar"><i style={{ width: `${Math.round((n / total) * 100)}%` }} /></span>
                          <span className="num">{n}</span>
                        </div>
                      )
                    })}
                  </div>
                  <div className="links">
                    <button onClick={() => navigate(adminPath('approval'))}>降密审批</button>
                    <button onClick={() => navigate(adminPath('policy'))}>标签策略</button>
                    <button onClick={() => navigate(adminPath('share-approvals'))}>外发审批</button>
                  </div>
                </div>
              )}

              {isAud && data?.auditor && (
                <div className="role-card">
                  <div className="rh">
                    <span className="badge violet">审计管理员</span>
                    <div className="grow" />
                    <button className="ghost sm" onClick={() => navigate(adminPath('audit'))}>审计日志</button>
                  </div>
                  <div className="mini-row">
                    <div><b>{data.auditor.events24h}</b><span>24h 事件</span></div>
                    <div><b>{data.auditor.denied24h}</b><span>24h 被拒</span></div>
                  </div>
                  <div className="anchor">
                    {data.auditor.lastAnchorDay
                      ? <>最近一次日结锚点：<b>{data.auditor.lastAnchorDay}</b> · {data.auditor.lastAnchorCount} 条</>
                      : '尚未生成日结锚点'}
                  </div>
                  <div className="links">
                    <button onClick={() => navigate(adminPath('logs'))}>操作日志</button>
                    <button onClick={() => navigate(adminPath('audit'))}>审计日志</button>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}
        {/* 关键数字 */}
        {(hasPersonal || todos.length > 0) && (
        <section className="stat-row">
          <div className="stat-card">
            <div className="k">可访问空间</div>
            <div className="v">{stats ? stats.totalSpaces : '—'}</div>
            <div className="s">{stats ? `我创建 ${stats.ownedSpaces} · 共享给我 ${stats.sharedSpaces}` : ''}</div>
          </div>
          <div className="stat-card">
            <div className="k">存储占用</div>
            <div className="v">{stats ? fmtSize(stats.storageUsedBytes) : '—'}</div>
            <div className="s">{stats ? `跨 ${stats.totalSpaces} 个空间` : ''}</div>
          </div>
          <div className="stat-card">
            <div className="k">最近打开</div>
            <div className="v">{stats ? stats.recentCount : '—'}</div>
            <div className="s">近 60 天，去重后</div>
          </div>
          <div className={`stat-card${todos.length ? ' alert' : ''}`}>
            <div className="k">待我处理</div>
            <div className="v">{todos.length}</div>
            <div className="s">
              {todos.length === 0
                ? '没有待办'
                : `移交 ${stats?.pendingTransfers ?? 0} · 审批 ${stats?.pendingShareApprovals ?? 0}`}
            </div>
          </div>
        </section>
        )}

        {hasPersonal ? (
        <>
        {/* 最近文件 */}
        <section className="home-sec">
          <div className="sec-head">
            <h2>最近打开</h2>
            {recent.length > 0 && <span className="count">{recent.length}</span>}
            <div className="grow" />
            <button className="ghost sm" onClick={() => navigate('/activity')}>全部记录</button>
          </div>
          {recent.length === 0 ? (
            <div className={`empty-block${roles.length ? ' compact' : ''}`}>
              <div className="empty-art"><Icon name="clock" size={22} /></div>
              <b>还没有最近打开的文档</b>
              <span className="hint">
                去看过的文件会出现在这里，方便第二天接着做。这些记录来自你自己的审计日志，别人看不到。
              </span>
              <button className="sm" onClick={() => navigate('/files')}>去文件</button>
            </div>
          ) : (
            <div className="file-grid">
              {recent.map((f) => (
                <Tooltip
                  key={f.id}
                  wide
                  content={
                    <>
                      <div className="tip-t"><Icon name={iconFor(f.name)} size={14} /> {f.name}</div>
                      <div className="tip-r"><span>所在空间</span><b>{f.spaceName}</b></div>
                      <div className="tip-r"><span>最近动作</span><b>{ACTION_LABEL[f.action] ?? f.action}</b></div>
                      <div className="tip-r"><span>时间</span><b>{relTime(f.at)}</b></div>
                      <div className="tip-note">点击在新页签打开预览。</div>
                    </>
                  }
                >
                  <button className="file-card" onClick={() => window.open(previewPath(f.id), '_blank', 'noopener')}>
                    <span className="ftype">
                      <Icon name={iconFor(f.name)} size={16} />
                    </span>
                    <span className="nm">{f.name}</span>
                    <span className="meta">
                      <span className="sp">{f.spaceName}</span>
                      <span className="when">{relTime(f.at)}</span>
                    </span>
                  </button>
                </Tooltip>
              ))}
            </div>
          )}
        </section>

        {/* 空间 */}
        <section className="home-sec">
          <div className="sec-head">
            <h2>我的空间</h2>
            <span className="count">{spaces.length}</span>
            {spaces.length > 6 && <span className="hint">按最近更新排序，显示前 6 个</span>}
            <InfoDot title="容量与归属">
              <p>卡片上的进度条是该空间已用 / 配额；没有配额的空间不显示进度条。</p>
              <p>「所有者」是负责这个空间的人。所有者一旦停用或离职，如果没有其他授权，空间会没人能进。</p>
            </InfoDot>
            <div className="grow" />
            <button className="ghost sm" onClick={() => navigate('/files')}>全部空间</button>
          </div>
          {spaces.length === 0 ? (
            <div className={`empty-block${roles.length ? ' compact' : ''}`}>
              <div className="empty-art"><Icon name="folder" size={22} /></div>
              <b>还没有可见的空间</b>
              <span className="hint">空间由管理员或你自己创建；被授权后才会出现在这里。</span>
            </div>
          ) : (
            <div className="space-grid">
              {spaces.slice(0, 6).map((s) => {
                const pct = s.quotaBytes ? Math.min(100, Math.round((s.usedBytes / s.quotaBytes) * 100)) : 0
                return (
                  <button className="space-card" key={s.id} onClick={() => navigate(filesPath(s.id))}>
                    <span className="top">
                      <span className="ftype"><Icon name="folder" size={16} /></span>
                      <span className="nm">{s.name}</span>
                      {s.ownerId === me?.userId && <span className="badge brand" style={{ height: 17 }}>我建的</span>}
                    </span>
                    <span className="meta">
                      {KIND_LABEL[s.kind] ?? s.kind}
                      <span className="dim"> · </span>
                      所有者 {s.ownerName || '—'}
                    </span>
                    {s.quotaBytes ? (
                      <span className="cap">
                        <span className="bar"><i style={{ width: `${pct}%` }} className={pct > 90 ? 'danger' : pct > 75 ? 'warn' : ''} /></span>
                        <span className="num">{fmtSize(s.usedBytes)} / {fmtSize(s.quotaBytes)}</span>
                      </span>
                    ) : (
                      <span className="cap"><span className="num">{fmtSize(s.usedBytes)}</span></span>
                    )}
                    <span className="foot">
                      {s.lastActivity ? `最近更新 ${relTime(s.lastActivity)}` : '还没有内容'}
                    </span>
                  </button>
                )
              })}
            </div>
          )}
        </section>
        </>
        ) : roles.length > 0 ? (
          <div className="empty-block compact">
            <b>你没有需要访问的空间</b>
            <span className="hint">
              管理角色管的是配置与治理，不会自动获得内容权限。需要查看某个空间的文件时，请让空间所有者给你授权。
            </span>
            <button className="sm" onClick={() => navigate('/files')}>去文件</button>
          </div>
        ) : null}

      </div>

      {accountOpen && <AccountDrawer me={me} onClose={() => setAccountOpen(false)} />}
    </Shell>
  )
}
