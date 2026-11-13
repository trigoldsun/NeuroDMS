// 通用界面部件：图标、悬停提示、说明气泡、菜单、对话框、头像。
//
// 三条原则（对应品牌"静默调性"）：
//   1. 图标统一 24 栅格 / 1.55 描边 / 圆头端点，一律线框，不用实心；
//   2. 所有"这个是什么/为什么这样"的解释都放在同一处（Tooltip / InfoDot），
//      不在页面里堆小字，避免把界面做成说明书；
//   3. 弹层一律走 portal，避免被表格或卡片的 overflow 裁掉。
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

/* ---------------- 图标 ---------------- */

const PATHS: Record<string, ReactNode> = {
  search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="M15.4 15.4 20 20" /></>,
  folder: <path d="M3.5 7.2c0-.9.7-1.6 1.6-1.6h3.7l2 2.4h8.1c.9 0 1.6.7 1.6 1.6v9.2c0 .9-.7 1.6-1.6 1.6H5.1c-.9 0-1.6-.7-1.6-1.6V7.2Z" />,
  file: <><path d="M6.4 3.6h6.3l4.9 4.9v11.9H6.4V3.6Z" /><path d="M12.5 3.8v5h4.9" /></>,
  upload: <><path d="M12 16.2V4.6" /><path d="m7.6 9 4.4-4.4L16.4 9" /><path d="M4.6 15.4v3.2c0 .5.4.9.9.9h13c.5 0 .9-.4.9-.9v-3.2" /></>,
  download: <><path d="M12 4.4v11.6" /><path d="m7.6 11.6 4.4 4.4 4.4-4.4" /><path d="M4.6 19.4h14.8" /></>,
  plus: <><path d="M12 5v14" /><path d="M5 12h14" /></>,
  folderPlus: <><path d="M3.5 7.2c0-.9.7-1.6 1.6-1.6h3.7l2 2.4h8.1c.9 0 1.6.7 1.6 1.6v9.2c0 .9-.7 1.6-1.6 1.6H5.1c-.9 0-1.6-.7-1.6-1.6V7.2Z" /><path d="M12 10.6v4.8M9.6 13h4.8" /></>,
  share: <><circle cx="17.6" cy="6.4" r="2.4" /><circle cx="6.4" cy="12" r="2.4" /><circle cx="17.6" cy="17.6" r="2.4" /><path d="m8.6 10.8 6.8-3.2M8.6 13.2l6.8 3.2" /></>,
  edit: <><path d="M4.6 19.4h4l9.3-9.3-4-4-9.3 9.3v4Z" /><path d="m13.2 6.6 4 4" /></>,
  more: <><circle cx="6" cy="12" r="1.3" /><circle cx="12" cy="12" r="1.3" /><circle cx="18" cy="12" r="1.3" /></>,
  shield: <><path d="M12 3.4 4.8 6.3v5.4c0 4.3 3 7.9 7.2 9 4.2-1.1 7.2-4.7 7.2-9V6.3L12 3.4Z" /><path d="m9.2 12 2 2.1 3.7-4" /></>,
  chevronR: <path d="m9.6 6.4 5.6 5.6-5.6 5.6" />,
  chevronD: <path d="m6.4 9.6 5.6 5.6 5.6-5.6" />,
  chevronUp: <path d="m6.4 14.4 5.6-5.6 5.6 5.6" />,
  chevronL: <path d="m14.4 6.4-5.6 5.6 5.6 5.6" />,
  close: <path d="M6.4 6.4l11.2 11.2M17.6 6.4 6.4 17.6" />,
  info: <><circle cx="12" cy="12" r="8.4" /><path d="M12 11v5.4" /><circle cx="12" cy="8.2" r=".9" fill="currentColor" stroke="none" /></>,
  check: <path d="m5.6 12.4 4.2 4.2 8.6-9" />,
  alert: <><path d="M12 4.2 3.6 19h16.8L12 4.2Z" /><path d="M12 10v4.2" /><circle cx="12" cy="16.7" r=".9" fill="currentColor" stroke="none" /></>,
  clock: <><circle cx="12" cy="12" r="8.2" /><path d="M12 7.4V12l3.2 2" /></>,
  users: <><circle cx="9.4" cy="9" r="3" /><path d="M3.8 19.2c0-2.8 2.5-4.8 5.6-4.8s5.6 2 5.6 4.8" /><path d="M16 6.6c1.5.4 2.4 1.5 2.4 2.9 0 1.1-.6 2-1.6 2.5" /><path d="M17.4 14.8c1.8.6 2.8 2 2.8 4.4" /></>,
  lock: <><rect x="5.2" y="10.4" width="13.6" height="9.4" rx="2" /><path d="M8.4 10.4V8a3.6 3.6 0 0 1 7.2 0v2.4" /></>,
  history: <><path d="M4.2 12a7.8 7.8 0 1 0 2.6-5.8" /><path d="M4.2 4.6v4.2h4.2" /><path d="M12 8.4V12l2.8 1.8" /></>,
  trash: <><path d="M4.8 6.8h14.4" /><path d="M9.4 6.8V4.6h5.2v2.2" /><path d="M6.6 6.8l.9 12.2c0 .5.4.9.9.9h7.2c.5 0 .9-.4.9-.9l.9-12.2" /></>,
  key: <><circle cx="8.4" cy="12" r="3.6" /><path d="M12 12h8" /><path d="M17.2 12v3.4M19.8 12v2.4" /></>,
  mail: <><rect x="3.6" y="6" width="16.8" height="12" rx="2" /><path d="m4.4 7.2 7.6 5.4 7.6-5.4" /></>,
  play: <path d="M8.4 5.6v12.8l10-6.4-10-6.4Z" />,
  list: <><path d="M4.4 7h15.2M4.4 12h15.2M4.4 17h15.2" /></>,
  sun: <><circle cx="12" cy="12" r="4.2" /><path d="M12 3.4v2M12 18.6v2M3.4 12h2M18.6 12h2M5.9 5.9l1.4 1.4M16.7 16.7l1.4 1.4M18.1 5.9l-1.4 1.4M7.3 16.7l-1.4 1.4" /></>,
  moon: <path d="M20 14.4A8.2 8.2 0 0 1 9.6 4 8.4 8.4 0 1 0 20 14.4Z" />,
  arrowUp: <><path d="M12 19V5" /><path d="m5.6 11.4 6.4-6.4 6.4 6.4" /></>,
  arrowLeft: <><path d="M19 12H5" /><path d="m10.6 5.6-6.4 6.4 6.4 6.4" /></>,
  arrowRight: <><path d="M5 12h14" /><path d="m13.4 5.6 6.4 6.4-6.4 6.4" /></>,
  external: <><path d="M14 4.6h5.4V10" /><path d="M19.4 4.6 11 13" /><path d="M18 14.4v4.2c0 .5-.4.9-.9.9H5.5c-.5 0-.9-.4-.9-.9V6.9c0-.5.4-.9.9-.9h4.2" /></>,
  eye: <><path d="M2.6 12S6 5.8 12 5.8 21.4 12 21.4 12 18 18.2 12 18.2 2.6 12 2.6 12Z" /><circle cx="12" cy="12" r="3.2" /></>,
  eyeOff: <><path d="M4 4l16 16" /><path d="M9.9 5.2A9.9 9.9 0 0 1 12 5c6 0 9.4 7 9.4 7a17 17 0 0 1-2.7 3.5" /><path d="M6.3 7.4A16.6 16.6 0 0 0 2.6 12S6 19 12 19a9.6 9.6 0 0 0 4.2-.9" /><path d="M10.2 10.3a2.6 2.6 0 0 0 3.5 3.6" /></>,
  sparkle: <><path d="M12 4.2 13.7 9l4.8 1.7-4.8 1.7L12 17.2 10.3 12.4 5.5 10.7 10.3 9 12 4.2Z" /><path d="M18.6 15.4l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8.8-2Z" /></>,
  grid: <><rect x="4.4" y="4.4" width="6.4" height="6.4" rx="1.4" /><rect x="13.2" y="4.4" width="6.4" height="6.4" rx="1.4" /><rect x="4.4" y="13.2" width="6.4" height="6.4" rx="1.4" /><rect x="13.2" y="13.2" width="6.4" height="6.4" rx="1.4" /></>,
  command: <path d="M9 6.6a2.4 2.4 0 1 0-2.4 2.4H17.4A2.4 2.4 0 1 0 15 6.6v10.8A2.4 2.4 0 1 0 17.4 15H6.6A2.4 2.4 0 1 0 9 17.4V6.6Z" />,
  tag: <><path d="M4.6 10.4V5c0-.2.2-.4.4-.4h5.4l8.2 8.2-5.8 5.8-8.2-8.2Z" /><circle cx="8.4" cy="8.4" r="1.1" /></>,
  drop: <><path d="M12 3.6c3.2 3.6 5.2 6.4 5.2 9a5.2 5.2 0 1 1-10.4 0c0-2.6 2-5.4 5.2-9Z" /></>,
}

export function Icon({ name, size = 16, stroke = 1.55, className }: { name: keyof typeof PATHS | string; size?: number; stroke?: number; className?: string }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round"
      className={className} aria-hidden focusable="false"
    >
      {PATHS[name] ?? PATHS.file}
    </svg>
  )
}

/* ---------------- 品牌标记 ---------------- */

// 标志：一个字母 N + 一株苗（取自品牌体系"一个字母，一株苗"）。
// 只在侧栏与登录页出现，工作界面里不重复。
export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none" aria-hidden>
      <rect width="28" height="28" rx="8" fill="var(--forest)" />
      <path d="M8.6 19.6V8.6l10.8 10.8V8.6" stroke="#F7FBF5" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="20.2" cy="7.6" r="2.1" fill="var(--sprout)" />
    </svg>
  )
}

/* ---------------- 头像 ---------------- */

const TONES = ['t1', 't2', 't3', 't4']

function toneOf(name: string): string {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 997
  return TONES[h % TONES.length]
}

export function initials(name: string): string {
  const s = (name || '?').trim()
  if (!s) return '?'
  // 中文取首个字（"张伟" → "张"，"视觉验收" → "视"），西文取首字母
  if (/[\u4e00-\u9fff]/.test(s)) return s[0]
  const parts = s.split(/[\s._-]+/).filter(Boolean)
  return (parts[0]?.[0] ?? '?').toUpperCase() + (parts[1]?.[0]?.toUpperCase() ?? '')
}

export function Avatar({ name, size = 24, title }: { name: string; size?: number; title?: string }) {
  return (
    <span
      className={`avatar ${toneOf(name)}`}
      style={{ width: size, height: size, fontSize: Math.max(10, Math.round(size * 0.42)) }}
      title={title ?? name}
      aria-hidden
    >
      {initials(name)}
    </span>
  )
}

/* ---------------- 悬停提示 ---------------- */

type TipSide = 'top' | 'bottom' | 'right'

export function Tooltip({
  content, children, side = 'top', delay = 140, disabled, wide,
}: {
  content: ReactNode
  children: ReactNode
  side?: TipSide
  delay?: number
  disabled?: boolean
  wide?: boolean
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const timer = useRef<number | null>(null)
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)

  const place = useCallback(() => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    if (side === 'right') {
      setPos({ x: Math.min(r.right + 10, window.innerWidth - 310), y: r.top + r.height / 2 })
    } else {
      const w = wide ? 300 : 240
      const x = Math.max(w / 2 + 10, Math.min(r.left + r.width / 2, window.innerWidth - w / 2 - 10))
      // 上方空间不足时自动翻到下方，否则第一行的提示会被视口顶边裁掉
      const flip = side === 'top' && r.top < 170
      setPos({ x, y: (side === 'bottom' || flip) ? r.bottom + 8 : r.top - 8 })
    }
  }, [side, wide])

  const show = useCallback(() => {
    if (disabled) return
    if (timer.current) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(place, delay)
  }, [delay, disabled, place])

  const hide = useCallback(() => {
    if (timer.current) window.clearTimeout(timer.current)
    setPos(null)
  }, [])

  useEffect(() => {
    if (!pos) return
    const onScroll = () => setPos(null)
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', onScroll)
    }
  }, [pos])

  const flipped = side === 'top' && pos ? (pos.y > (ref.current?.getBoundingClientRect().top ?? 0)) : false
  const below = side === 'bottom' || flipped
  const style = pos
    ? side === 'right'
      ? { left: pos.x, top: pos.y, transform: 'translateY(-50%)' }
      : below
        ? { left: pos.x, top: pos.y }
        : { left: pos.x, top: pos.y, transform: 'translate(-50%, -100%)' }
    : undefined

  return (
    <>
      <span
        ref={ref}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        style={{ display: 'inline-flex', minWidth: 0, maxWidth: '100%' }}
      >
        {children}
      </span>
      {pos && createPortal(
        <div className="tip-pop" role="tooltip" style={style}>{content}</div>,
        document.body,
      )}
    </>
  )
}

/* ---------------- 说明气泡（点击 i 打开） ---------------- */

export function InfoDot({ title, children, label = '更多说明' }: {
  title: string
  children: ReactNode
  label?: string
}) {
  const btn = useRef<HTMLButtonElement>(null)
  const [pos, setPos] = useState<{ x: number; y: number; up: boolean } | null>(null)

  useEffect(() => {
    if (!pos) return
    const onDown = (e: MouseEvent) => {
      if (btn.current && !btn.current.contains(e.target as Node)) setPos(null)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setPos(null) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [pos])

  function toggle() {
    if (pos) { setPos(null); return }
    const r = btn.current?.getBoundingClientRect()
    if (!r) return
    const up = r.top > 260
    const x = Math.max(180, Math.min(r.left - 8, window.innerWidth - 360))
    setPos({ x, y: up ? r.top - 8 : r.bottom + 8, up })
  }

  return (
    <>
      <button
        ref={btn}
        type="button"
        className="info-dot"
        aria-label={label}
        aria-expanded={!!pos}
        onClick={(e) => { e.stopPropagation(); toggle() }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <Icon name="info" size={11} stroke={2} />
      </button>
      {pos && createPortal(
        <div
          className="pop"
          role="dialog"
          aria-label={title}
          style={{
            left: Math.min(pos.x, window.innerWidth - 356),
            top: pos.up ? undefined : pos.y,
            bottom: pos.up ? window.innerHeight - pos.y : undefined,
          }}
        >
          <h4><Icon name="info" size={15} /> {title}</h4>
          <div>{children}</div>
        </div>,
        document.body,
      )}
    </>
  )
}

/* ---------------- 菜单 ---------------- */

export type MenuItem = {
  label: string
  icon?: string
  onClick?: () => void
  danger?: boolean
  hint?: string
  sep?: boolean
  disabled?: boolean
}

export function Menu({ items, label = '更多操作', trigger }: {
  items: MenuItem[]
  label?: string
  trigger?: (open: () => void) => ReactNode
}) {
  const btn = useRef<HTMLElement | null>(null)
  // 面板是 createPortal 到 body 的，**不在 btn 里**。判断"点外面"时必须把它算进来，
  // 否则按在菜单项上的 mousedown 就会把面板卸掉，随后的 click 落在已消失的节点上，
  // 动作永远不执行——这正是"点菜单没反应"的根因。
  const panel = useRef<HTMLDivElement | null>(null)
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)

  useEffect(() => {
    if (!pos) return
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node
      if (panel.current?.contains(t)) return
      if (btn.current?.contains(t)) return
      setPos(null)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setPos(null) }
    const onScroll = (e: Event) => {
      // 菜单自身滚动（条目多时面板可滚）不该把自己关掉
      if (panel.current?.contains(e.target as Node)) return
      setPos(null)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    window.addEventListener('scroll', onScroll, true)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
      window.removeEventListener('scroll', onScroll, true)
    }
  }, [pos])

  function open() {
    if (pos) { setPos(null); return }   // 再点一次收起
    const r = btn.current?.getBoundingClientRect()
    if (!r) return
    const est = Math.min(items.length * 32 + 12, window.innerHeight - 24)
    const below = r.bottom + 6
    // 下方放不下就翻到上方，否则最后一行的菜单会被视口底边裁掉
    const y = below + est > window.innerHeight - 8 ? Math.max(8, r.top - 6 - est) : below
    setPos({ x: Math.max(8, Math.min(r.right - 200, window.innerWidth - 216)), y })
  }

  return (
    <>
      {trigger ? (
        <span ref={(el) => { btn.current = el }} onClick={(e) => { e.stopPropagation(); open() }}>
          {trigger(open)}
        </span>
      ) : (
        <button ref={(el) => { btn.current = el }} type="button" className="icon ghost" aria-label={label} title={label}
          onClick={(e) => { e.stopPropagation(); open() }}>
          <Icon name="more" size={16} />
        </button>
      )}
      {pos && createPortal(
        <div className="menu" ref={panel} style={{ left: pos.x, top: pos.y }} role="menu">
          {items.map((it, i) => it.sep
            ? <div className="menu-sep" key={'s' + i} />
            : (
              <button
                key={it.label}
                type="button"
                role="menuitem"
                className={`menu-item${it.danger ? ' danger' : ''}`}
                disabled={it.disabled}
                title={it.disabled ? it.hint : undefined}
                onClick={(e) => {
                  e.stopPropagation()
                  if (it.disabled) return
                  setPos(null)
                  it.onClick?.()
                }}
              >
                {it.icon && <span className="ico"><Icon name={it.icon} size={15} /></span>}
                <span>{it.label}</span>
                {it.hint && <span className="k dim" style={{ fontSize: 11 }}>{it.hint}</span>}
              </button>
            ))}
        </div>,
        document.body,
      )}
    </>
  )
}

/* ---------------- 对话框 ---------------- */

export function Dialog({ title, icon = 'info', note, children, footer, onClose, width }: {
  title: string
  icon?: string
  note?: ReactNode
  children?: ReactNode
  footer?: ReactNode
  onClose: () => void
  width?: number
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return createPortal(
    <div className="modal-mask" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="dlg" role="dialog" aria-modal="true" aria-label={title} style={width ? { width: `min(${width}px, 100%)` } : undefined}>
        <div className="dlg-head">
          <span style={{ color: 'var(--forest)', marginTop: 2 }}><Icon name={icon} size={18} /></span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <h3>{title}</h3>
            {note && <div className="dlg-note" style={{ marginTop: 4 }}>{note}</div>}
          </div>
        </div>
        <div className="dlg-body">{children}</div>
        {footer && <div className="dlg-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

/* ---------------- 工具 ---------------- */

export function relTime(iso: string): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const d = Date.now() - t
  const min = Math.round(d / 60000)
  if (min < 1) return '刚刚'
  if (min < 60) return `${min} 分钟前`
  const h = Math.round(min / 60)
  if (h < 24) return `${h} 小时前`
  const day = Math.round(h / 24)
  if (day < 30) return `${day} 天前`
  const mo = Math.round(day / 30)
  if (mo < 12) return `${mo} 个月前`
  return `${Math.round(mo / 12)} 年前`
}

export function absTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export function fmtSize(n: number): string {
  if (!n) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

// useOutside 在点击外部/按 Esc 时回调，用于自建浮层。
export function useOutside(ref: React.RefObject<HTMLElement | null>, onAway: () => void, active: boolean) {
  useLayoutEffect(() => {
    if (!active) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onAway()
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onAway() }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [ref, onAway, active])
}
