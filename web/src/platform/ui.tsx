// 平台运营控制台 · 共享 UI 组件
//
// 这里只放"运营台专用"的界面零件：骨架、页头、面板、确认弹窗、空态。
// 基础控件（button / input / table / badge / seg）沿用 styles.css 的既有定义，
// 不再重画一套 —— 两套并存的直接后果是"同一个按钮在两个页签里长得不一样"。
//
// 命名一律 pf- 前缀：运营台与租户端各自演化，不共享布局类名。

import { useCallback, useEffect, useRef, useState } from 'react'

// ---------------- 图标（24 栅格 / 1.55 描边 / 圆头端点） ----------------

const PATHS: Record<string, React.ReactElement> = {
  tenants: <><path d="M4 20V9.5l8-5 8 5V20" /><path d="M9.5 20v-5.5h5V20" /></>,
  shield: <><path d="M12 3.5 19 6v6.2c0 4.2-2.9 7.3-7 8.3-4.1-1-7-4.1-7-8.3V6l7-2.5Z" /><path d="m9.2 11.8 2 2 3.6-3.6" /></>,
  chart: <><path d="M4 19h16" /><path d="M7 19v-6" /><path d="M12 19V6" /><path d="M17 19v-9" /></>,
  toggle: <><rect x="3.5" y="8" width="17" height="8" rx="4" /><circle cx="16" cy="12" r="2.3" /></>,
  users: <><circle cx="9.5" cy="9" r="3.2" /><path d="M3.8 19c0-2.9 2.5-5.2 5.7-5.2s5.7 2.3 5.7 5.2" /><path d="M16.5 6.4a3 3 0 0 1 0 5.6" /><path d="M18 19c0-2.2-.7-3.9-2-5" /></>,
  list: <><path d="M8 7h12" /><path d="M8 12h12" /><path d="M8 17h12" /><circle cx="4.2" cy="7" r=".9" /><circle cx="4.2" cy="12" r=".9" /><circle cx="4.2" cy="17" r=".9" /></>,
  search: <><circle cx="11" cy="11" r="6.2" /><path d="m16 16 4 4" /></>,
  plus: <><path d="M12 5.5v13" /><path d="M5.5 12h13" /></>,
  back: <><path d="M19 12H5" /><path d="m11 6-6 6 6 6" /></>,
  alert: <><circle cx="12" cy="12" r="8.2" /><path d="M12 7.8v5" /><circle cx="12" cy="16.1" r=".9" /></>,
  down: <><path d="M12 4.5v11" /><path d="m7 11 5 5 5-5" /><path d="M5 19.5h14" /></>,
  device: <><rect x="3.5" y="5" width="17" height="12" rx="1.6" /><path d="M8 20h8" /><path d="M12 17v3" /></>,
  moon: <><path d="M20 13.2A8.2 8.2 0 1 1 10.8 4a6.6 6.6 0 0 0 9.2 9.2Z" /></>,
  sun: <><circle cx="12" cy="12" r="4.2" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4" /></>,
}

export function PfIcon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke="currentColor" strokeWidth={1.55}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"
      style={{ flex: '0 0 auto' }}
    >
      {PATHS[name] ?? PATHS.list}
    </svg>
  )
}

// ---------------- 页头 ----------------

export function PageHead(props: {
  title: string
  sub?: React.ReactNode
  actions?: React.ReactNode
  crumbs?: React.ReactNode
}) {
  return (
    <div className="pf-pagehead">
      <div className="pf-titles">
        {props.crumbs}
        <h1>{props.title}</h1>
        {props.sub && <p>{props.sub}</p>}
      </div>
      {props.actions && <div className="pf-head-acts">{props.actions}</div>}
    </div>
  )
}

// ---------------- 面板 ----------------

export function Panel(props: {
  title?: React.ReactNode
  sub?: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
  body?: 'pad' | 'none'
  foot?: React.ReactNode
  className?: string
}) {
  const tidy = props.body === 'none'
  return (
    <section className={`pf-panel ${props.className ?? ''}`}>
      {(props.title || props.actions) && (
        <div className="pf-panel-head">
          {props.title && <h2>{props.title}</h2>}
          {props.sub && <span className="hint">{props.sub}</span>}
          <div className="pf-grow" />
          {props.actions}
        </div>
      )}
      <div className={tidy ? 'pf-panel-body tight' : 'pf-panel-body'}>{props.children}</div>
      {props.foot && <div className="pf-panel-foot">{props.foot}</div>}
    </section>
  )
}

// ---------------- 统计 ----------------

export function Stat(props: { k: string; v: React.ReactNode; s?: React.ReactNode; alert?: boolean }) {
  return (
    <div className={`pf-stat ${props.alert ? 'alert' : ''}`}>
      <div className="k">{props.k}</div>
      <div className="v">{props.v}</div>
      {props.s && <div className="s">{props.s}</div>}
    </div>
  )
}

// ---------------- 空态 ----------------

export function Empty(props: { icon?: string; title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div className="pf-empty">
      <PfIcon name={props.icon ?? 'list'} size={30} />
      <b>{props.title}</b>
      {props.hint && <span style={{ maxWidth: '52ch', lineHeight: 1.7 }}>{props.hint}</span>}
      {props.action}
    </div>
  )
}

// ---------------- 搜索框 ----------------

export function SearchBox(props: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  ariaLabel: string
}) {
  return (
    <div className="pf-search">
      <PfIcon name="search" size={14} />
      <input
        type="search"
        value={props.value}
        aria-label={props.ariaLabel}
        placeholder={props.placeholder ?? '搜索'}
        onChange={(e) => props.onChange(e.target.value)}
      />
    </div>
  )
}

// ---------------- 提示条 ----------------

export function Note(props: {
  tone?: 'info' | 'warn' | 'danger' | 'ok'
  icon?: string
  children: React.ReactNode
}) {
  return (
    <div className={`pf-note ${props.tone && props.tone !== 'info' ? props.tone : ''}`}>
      {props.icon && <PfIcon name={props.icon} />}
      <div>{props.children}</div>
    </div>
  )
}

// ---------------- 弹窗 ----------------

export function Modal(props: {
  title: React.ReactNode
  onClose: () => void
  children: React.ReactNode
  foot?: React.ReactNode
  narrow?: boolean
}) {
  const ref = useRef<HTMLDivElement>(null)

  // Esc 关闭 + 打开时把焦点移进弹窗。
  // 不做这一步，键盘用户会停在背后的页面上敲字（视觉上弹窗在前，操作却落在后面）。
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') props.onClose()
    }
    document.addEventListener('keydown', onKey)
    const first = ref.current?.querySelector<HTMLElement>(
      'input:not([type=hidden]), select, textarea, button.primary',
    )
    first?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [props.onClose])

  return (
    <div className="pf-modal-mask" onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose() }}>
      <div
        className={`pf-modal ${props.narrow ? 'narrow' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={typeof props.title === 'string' ? props.title : undefined}
        ref={ref}
      >
        <div className="pf-modal-head">
          <h2>{props.title}</h2>
          <div className="pf-grow" />
          <button className="ghost" onClick={props.onClose} aria-label="关闭">关闭</button>
        </div>
        <div className="pf-modal-body">{props.children}</div>
        {props.foot && <div className="pf-modal-foot">{props.foot}</div>}
      </div>
    </div>
  )
}

// ---------------- 确认（替代 window.confirm） ----------------

export type ConfirmSpec = {
  title: string
  body: React.ReactNode
  confirmText?: string
  danger?: boolean
  onConfirm: () => void | Promise<void>
}

// useConfirm 返回一个"问一句再执行"的入口。
//
// 为什么不继续用 window.confirm：它不可样式化、在部分浏览器里能勾选"阻止此对话框"
// （之后所有删除都静默通过），而且无法展示"会吊销多少会话"这类结构化后果。
// 破坏性操作统一走这里，文案能写清楚代价。
export function useConfirm() {
  const [spec, setSpec] = useState<ConfirmSpec | null>(null)
  const [busy, setBusy] = useState(false)

  const ask = useCallback((s: ConfirmSpec) => setSpec(s), [])

  async function ok() {
    if (!spec) return
    setBusy(true)
    try {
      await spec.onConfirm()
      setSpec(null)
    } finally {
      setBusy(false)
    }
  }

  const dialog = spec ? (
    <Modal
      title={spec.title}
      narrow
      onClose={() => { if (!busy) setSpec(null) }}
      foot={<>
        <button onClick={() => setSpec(null)} disabled={busy}>取消</button>
        <button className={spec.danger ? 'primary' : 'primary'} onClick={() => void ok()} disabled={busy}>
          {busy ? '执行中…' : (spec.confirmText ?? '确认')}
        </button>
      </>}
    >
      <div style={{ fontSize: 13, lineHeight: 1.7 }}>{spec.body}</div>
    </Modal>
  ) : null

  return { ask, dialog }
}

// ---------------- 提示气泡 ----------------

export function Toast({ text }: { text: string }) {
  if (!text) return null
  // aria-live：读屏用户也要知道"保存成功"这类结果，否则他们只能靠肉眼找不到反馈
  return <div className="pf-toast" role="status" aria-live="polite">{text}</div>
}

// ---------------- 错误条 ----------------

export function Alert({ text, onClose }: { text: string; onClose: () => void }) {
  if (!text) return null
  return (
    <div className="pf-alert" role="alert">
      <PfIcon name="alert" />
      <div className="pf-grow">{text}</div>
      <button className="ghost" onClick={onClose} aria-label="关闭提示">×</button>
    </div>
  )
}
