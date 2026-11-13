// 应用骨架：侧栏（空间 + 快捷）、顶栏（面包屑 + 全局搜索 + 操作）、命令面板。
//
// 为什么把 ⌘K 放在骨架里：搜索是"跨空间找东西"的动作，不属于任何一个页面。
// 放在页面里会导致"在目录页能搜、在预览页不能搜"，用户每次都要重新找回入口。
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { searchNodes, type Me, type SearchHit } from '../api'
import { navigate, adminPath, currentPath, filesPath, previewPath, subscribe } from '../router'
import { Avatar, Icon, Mark, Menu, Tooltip, fmtSize, relTime } from './ui'

export type SpaceLite = {
  id: string
  kind: string
  name: string
  ownerId?: string
  ownerName?: string
  usedBytes: number
  quotaBytes?: number | null
  classification?: number
  createdAt?: string
}

export type Crumb = { id: string; name: string }

export type Command = {
  label: string
  icon?: string
  hint?: string
  run: () => void
  disabled?: boolean
}

const KIND_LABEL: Record<string, string> = {
  personal: '个人空间',
  dept: '部门空间',
  project: '项目空间',
  knowledge: '知识库',
  archive: '归档空间',
}

export function Shell({
  me, spaces, activeSpaceId, onSpace, onCreateSpace,
  crumbs = [], onCrumb, spaceName,
  actions, sidebarNav, commands = [], onOpenHit, hideSpaceList, hideQuickNav,
  children, inspector, onOpenAccount, onToggleTheme, theme,
}: {
  me: Me | null
  spaces: SpaceLite[]
  activeSpaceId?: string
  onSpace: (id: string) => void
  onCreateSpace?: () => void
  hideSpaceList?: boolean
  hideQuickNav?: boolean
  crumbs?: Crumb[]
  onCrumb?: (id: string) => void
  spaceName?: string
  actions?: ReactNode
  sidebarNav?: ReactNode
  commands?: Command[]
  onOpenHit?: (hit: SearchHit) => void
  children: ReactNode
  inspector?: ReactNode
  onOpenAccount?: () => void
  onToggleTheme: () => void
  theme: 'light' | 'dark'
}) {
  const [palette, setPalette] = useState(false)
  // 侧栏高亮跟着地址走：不额外传"当前页"参数，避免两处状态打架
  const curPath = useSyncExternalStore(subscribe, currentPath, currentPath).split('?')[0]
  const current = spaces.find((s) => s.id === activeSpaceId)

  // ⌘K / Ctrl+K 打开命令面板；输入框内不拦截
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setPalette((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="app">
      <aside className="side">
        {/* 左上角产品名＝回工作台。这是全站唯一"always there"的入口，
            放 /files 等于让人只能回到某个目录，回不了自己的首页。 */}
        <a className="side-brand" href="/home" title="回到工作台" onClick={(e) => { e.preventDefault(); navigate('/home') }}>
          <Mark size={30} />
          <span className="word">
            <b>NeuroDMS</b>
            <span className="tenant">受控文档 · 全程留痕</span>
          </span>
        </a>

        <div className="side-scroll">
          {!hideSpaceList && <div className="side-sec">
            <div className="side-sec-head">
              <span className="label">空间</span>
              <Tooltip content={<><b>新建空间</b><div className="tip-note">空间是文件的顶层容器。创建后由你担任所有者，可再授权他人。</div></>}>
                <button className="ghost" aria-label="新建空间" onClick={() => onCreateSpace?.()}>
                  <Icon name="plus" size={13} />
                </button>
              </Tooltip>
            </div>
            {spaces.length === 0 && <div className="hint" style={{ padding: '6px 8px' }}>还没有可见的空间</div>}
            {spaces.map((s) => {
              return (
                <Tooltip
                  key={s.id}
                  wide
                  content={
                    <>
                      <div className="tip-t"><Icon name="folder" size={14} /> {s.name}</div>
                      <div className="tip-r"><span>类型</span><b>{KIND_LABEL[s.kind] ?? s.kind}</b></div>
                      <div className="tip-r"><span>所有者</span><b>{s.ownerName || '—'}</b></div>
                      <div className="tip-r"><span>已用</span><b>{fmtSize(s.usedBytes)}{s.quotaBytes ? ` / ${fmtSize(s.quotaBytes)}` : ''}</b></div>
                      {s.createdAt && <div className="tip-r"><span>创建</span><b>{relTime(s.createdAt)}</b></div>}
                      <div className="tip-sep" />
                      <div className="tip-note">点击进入该空间根目录</div>
                    </>
                  }
                >
                  <button className={`nav-item ${s.id === activeSpaceId ? 'on' : ''}`} onClick={() => onSpace(s.id)}>
                    <span className="ico"><Icon name="folder" size={16} /></span>
                    <span className="txt">{s.name}</span>
                    <span className="meta">{fmtSize(s.usedBytes)}</span>
                  </button>
                </Tooltip>
              )
            })}
            {current?.quotaBytes ? (
              <div className="space-cap">
                <div className="k"><span>本空间容量</span><span>{Math.round((current.usedBytes / current.quotaBytes) * 100)}%</span></div>
                <div className="bar">
                  <i
                    className={current.usedBytes / current.quotaBytes > 0.9 ? 'danger' : current.usedBytes / current.quotaBytes > 0.75 ? 'warn' : ''}
                    style={{ width: `${Math.min(100, (current.usedBytes / current.quotaBytes) * 100)}%` }}
                  />
                </div>
              </div>
            ) : null}
          </div>}

          <div className="side-sec">
            {!hideQuickNav && (
              <>
                <div className="side-sec-head"><span className="label">{hideSpaceList ? '导航' : '快捷'}</span></div>
                <button className={`nav-item ${curPath === '/home' || curPath === '/' ? 'on' : ''}`} onClick={() => navigate('/home')}>
                  <span className="ico"><Icon name="grid" size={16} /></span>
                  <span className="txt">工作台</span>
                </button>
                <button className={`nav-item ${curPath === '/activity' ? 'on' : ''}`} onClick={() => navigate('/activity')}>
                  <span className="ico"><Icon name="clock" size={16} /></span>
                  <span className="txt">最近活动</span>
                </button>
                {me && (me.roles ?? []).length > 0 && (
                  <button className="nav-item" onClick={() => navigate(adminPath(''))}>
                    <span className="ico"><Icon name="shield" size={16} /></span>
                    <span className="txt">管理台</span>
                  </button>
                )}
              </>
            )}
            {sidebarNav}
          </div>
        </div>

        <div className="side-foot">
          <button className="user-card" onClick={() => onOpenAccount?.()}>
            <Avatar name={me?.displayName || me?.username || '?'} size={28} />
            <span className="who">
              <b>{me?.displayName || me?.username || '未登录'}</b>
              <small>密级 {me?.classification ?? 0} · 账户设置</small>
            </span>
            <Icon name="chevronR" size={14} />
          </button>
        </div>
      </aside>

      <div className="main-col">
        <div className="appbar">
          <div className="crumbs">
            {spaceName && (
              <>
                <button onClick={() => activeSpaceId && onSpace(activeSpaceId)} title="回到空间根目录">{spaceName}</button>
              </>
            )}
            {crumbs.map((c, i) => (
              <span key={c.id} style={{ display: 'inline-flex', alignItems: 'center' }}>
                <span className="sep"><Icon name="chevronR" size={12} /></span>
                {i === crumbs.length - 1
                  ? <span className="here">{c.name}</span>
                  : <button onClick={() => onCrumb?.(c.id)}>{c.name}</button>}
              </span>
            ))}
          </div>

          <div className="grow" />

          <button className="search-btn" onClick={() => setPalette(true)} title="搜索文件、空间与操作（⌘K）">
            <Icon name="search" size={15} />
            <span className="ph">搜索文件或操作</span>
            <span className="kbd">⌘K</span>
          </button>

          {actions}

          <Tooltip content={theme === 'dark' ? '切换到浅色' : '切换到深色'}>
            <button className="icon ghost" onClick={onToggleTheme} aria-label="切换主题">
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={17} />
            </button>
          </Tooltip>
          <Menu
            items={[{ label: '账户与退出', icon: 'users', onClick: onOpenAccount }]}
            trigger={(open) => (
              <button className="icon ghost" aria-label="账户" onClick={open} style={{ padding: 0 }}>
                <Avatar name={me?.displayName || me?.username || '?'} size={26} />
              </button>
            )}
          />
        </div>

        <div className={`work${inspector ? ' with-insp' : ''}`}>
          <div className="content">{children}</div>
          {inspector}
        </div>
      </div>

      {palette && (
        <CommandPalette
          spaces={spaces}
          commands={commands}
          onClose={() => setPalette(false)}
          onSpace={(id) => { setPalette(false); onSpace(id) }}
          onHit={(h) => { setPalette(false); onOpenHit?.(h) }}
        />
      )}
    </div>
  )
}

/* ---------------- 命令面板 ---------------- */

type Row =
  | { kind: 'cmd'; cmd: Command }
  | { kind: 'space'; id: string; label: string }
  | { kind: 'hit'; hit: SearchHit }

function CommandPalette({ spaces, commands, onClose, onSpace, onHit }: {
  spaces: SpaceLite[]
  commands: Command[]
  onClose: () => void
  onSpace: (id: string) => void
  onHit: (h: SearchHit) => void
}) {
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<SearchHit[]>([])
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState(0)
  const timer = useRef<number | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  // 停止输入 220ms 再查服务端；只搜文件名，正文检索不在当前能力内
  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current)
    const term = q.trim()
    if (!term) { setHits([]); setBusy(false); return }
    setBusy(true)
    timer.current = window.setTimeout(async () => {
      try { setHits(await searchNodes(term, 8)) } catch { setHits([]) } finally { setBusy(false) }
    }, 220)
    return () => { if (timer.current) window.clearTimeout(timer.current) }
  }, [q])

  const term = q.trim().toLowerCase()
  const spaceRows = useMemo(
    () => spaces.filter((s) => !term || s.name.toLowerCase().includes(term)).slice(0, term ? 5 : 4),
    [spaces, term],
  )
  const cmdRows = useMemo(
    () => commands.filter((c) => !term || c.label.toLowerCase().includes(term)),
    [commands, term],
  )

  const rows: Row[] = useMemo(() => {
    const out: Row[] = []
    cmdRows.forEach((c) => out.push({ kind: 'cmd', cmd: c }))
    spaceRows.forEach((s) => out.push({ kind: 'space', id: s.id, label: s.name }))
    hits.forEach((h) => out.push({ kind: 'hit', hit: h }))
    return out
  }, [cmdRows, spaceRows, hits])

  useEffect(() => { setSel(0) }, [q, rows.length])

  function run(row: Row) {
    if (row.kind === 'cmd') { if (!row.cmd.disabled) { row.cmd.run(); onClose() } }
    else if (row.kind === 'space') onSpace(row.id)
    else onHit(row.hit)
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel((v) => Math.min(v + 1, rows.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((v) => Math.max(v - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); const r = rows[sel]; if (r) run(r) }
  }

  let idx = -1
  const renderRow = () => { idx += 1; return idx }

  return createPortal(
    <div className="cmd-mask" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="cmd" role="dialog" aria-label="搜索与命令">
        <div className="cmd-input">
          <Icon name="search" size={17} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="搜索文件名，或直接说你要做什么：上传、新建、切换空间…"
            aria-label="搜索"
          />
          {busy && <span className="hint">搜索中</span>}
          <span className="kbd">Esc</span>
        </div>
        <div className="cmd-list">
          {rows.length === 0 && (
            <div className="hint" style={{ padding: '18px 12px' }}>
              没有匹配项。搜索只匹配<b>文件名</b>，不搜正文；看不到的条目可能是权限不足。
            </div>
          )}
          {cmdRows.length > 0 && <div className="cmd-sec">操作</div>}
          {cmdRows.map((c) => {
            const i = renderRow()
            return (
              <div key={'c' + c.label} className={`cmd-item${i === sel ? ' sel' : ''}`}
                onMouseEnter={() => setSel(i)} onClick={() => run({ kind: 'cmd', cmd: c })}>
                <span className="ico"><Icon name={c.icon ?? 'arrowRight'} size={15} /></span>
                <span className="t">{c.label}</span>
                {c.hint && <span className="s">{c.hint}</span>}
              </div>
            )
          })}
          {spaceRows.length > 0 && <div className="cmd-sec">空间</div>}
          {spaceRows.map((s) => {
            const i = renderRow()
            return (
              <div key={'s' + s.id} className={`cmd-item${i === sel ? ' sel' : ''}`}
                onMouseEnter={() => setSel(i)} onClick={() => onSpace(s.id)}>
                <span className="ico"><Icon name="folder" size={15} /></span>
                <span className="t">{s.name}</span>
                <span className="s">{fmtSize(s.usedBytes)}</span>
              </div>
            )
          })}
          {hits.length > 0 && <div className="cmd-sec">文件</div>}
          {hits.map((h) => {
            const i = renderRow()
            return (
              <div key={h.nodeId} className={`cmd-item${i === sel ? ' sel' : ''}`}
                onMouseEnter={() => setSel(i)} onClick={() => onHit(h)}>
                <span className="ico"><Icon name={h.kind === 'folder' ? 'folder' : 'file'} size={15} /></span>
                <span className="t">{h.name}</span>
                <span className="s">{h.kind === 'folder' ? '目录' : fmtSize(h.sizeBytes)}</span>
              </div>
            )
          })}
        </div>
        <div className="cmd-foot">
          <span><span className="kbd">↑</span> <span className="kbd">↓</span> 选择</span>
          <span><span className="kbd">↵</span> 打开</span>
          <span><span className="kbd">Esc</span> 关闭</span>
          <span style={{ marginLeft: 'auto' }}>只搜文件名 · 结果已按你的可见性过滤</span>
        </div>
      </div>
    </div>,
    document.body,
  )
}

// goHit 把搜索结果落到具体地址：目录进目录，文件开预览页签。
export function goHit(hit: SearchHit) {
  if (hit.kind === 'folder') navigate(filesPath(hit.spaceId, hit.nodeId))
  else window.open(previewPath(hit.nodeId), '_blank', 'noopener')
}

// themeLabel 给顶栏/菜单用。
export function themeLabel(t: 'light' | 'dark') {
  return t === 'dark' ? '深色' : '浅色'
}

export { KIND_LABEL }
