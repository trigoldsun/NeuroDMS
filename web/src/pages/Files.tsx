import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import {
  api, downloadNode, downloadBatch, del, patchJSON, postJSON, uploadFile,
  fetchMe, cycleTheme, applyTheme, HttpError, getCapabilities,
  type Me, type Capabilities, type SearchHit,
} from '../api'
import AclDrawer from './AclDrawer'
import AccountDrawer from './AccountDrawer'
import ShareDrawer from './ShareDrawer'
import VersionsDrawer from './VersionsDrawer'
import { MediaModal } from './Viewer'
import { currentPath, filesPath, navigate, previewPath, subscribe } from '../router'
import { Shell, goHit, type Command, type Crumb, type SpaceLite } from '../components/Shell'
import { PendingTransferBar, SpaceTransferDialog } from '../components/SpaceTransfer'
import {
  Avatar, Dialog, Icon, InfoDot, Menu, Tooltip, absTime, fmtSize, relTime,
} from '../components/ui'

type Node = {
  id: string
  kind: 'folder' | 'file'
  name: string
  size: number
  mime: string
  createdAt?: string
  updatedAt: string
  classification?: number
  versionNo?: number
  owner?: { id: string; name: string }
  updatedBy?: { name: string }
}
type ClassLabel = { level: number; name: string; description: string }
type VersionLite = { versionNo: number; createdAt: string; createdBy?: string; size?: number }

// 授权摘要只对"能管这个对象的人"返回；没有 manage_acl 时服务端回 visible=false，
// 面板就不显示这一块，而不是报错。
type AclEntry = { subjectType: string; subjectName?: string; preset: string; deny?: boolean; expiresAt?: string }
type AclSummary = {
  visible: boolean
  total?: number
  bySubject?: Record<string, number>
  denyCount?: number
  ownerCount?: number
  expiredCount?: number
  inheritedBroken?: boolean
  entries?: AclEntry[]
}

const PRESET_LABEL: Record<string, string> = {
  viewer: '查看者', contributor: '贡献者', editor: '编辑者', manager: '管理者', owner: '所有者', commenter: '评论者',
}
const SUBJECT_LABEL: Record<string, string> = {
  user: '用户', dept: '部门', role: '角色', group: '组', external: '外部', anonymous: '匿名',
}

type UploadItem = {
  id: string
  name: string
  size: number
  pct: number
  phase: 'wait' | 'hash' | 'upload' | 'done' | 'dedupe' | 'error'
  note?: string
  sentBytes?: number
  totalBytes?: number
  part?: number
  parts?: number
}
type Job = { id: string; file: File; spaceId: string; parentId: string; ac: AbortController }

function fileExt(name: string): string {
  const i = name.lastIndexOf('.')
  return i >= 0 ? name.slice(i).toLowerCase() : ''
}
function isPlayable(mime: string, name: string): boolean {
  if (mime?.startsWith('video/') || mime?.startsWith('audio/')) return true
  return /\.(mp4|m4v|mov|webm|mkv|mp3|m4a|wav|flac|aac|ogg)$/i.test(name)
}
function isOffice(name: string): boolean {
  return /\.(docx?|xlsx?|pptx?|odt|ods|odp)$/i.test(name)
}
function isPdf(name: string, mime: string): boolean {
  return mime === 'application/pdf' || /\.pdf$/i.test(name)
}

// 文件类型的可视化分类：只用于图标底纹与"类型"文案，不参与任何判定。
function kindOf(n: Node): { icon: string; label: string } {
  if (n.kind === 'folder') return { icon: 'folder', label: '目录' }
  const e = fileExt(n.name)
  if (isPdf(n.name, n.mime)) return { icon: 'file', label: 'PDF' }
  if (/\.(docx?|odt|rtf)$/.test(e)) return { icon: 'file', label: 'Word 文档' }
  if (/\.(xlsx?|ods|csv)$/.test(e)) return { icon: 'file', label: '表格' }
  if (/\.(pptx?|odp)$/.test(e)) return { icon: 'file', label: '演示文稿' }
  if (/\.(png|jpe?g|gif|webp|bmp|svg|heic|heif|avif)$/.test(e)) return { icon: 'file', label: '图片' }
  if (/\.(mp4|mov|mkv|webm|avi)$/.test(e)) return { icon: 'play', label: '视频' }
  if (/\.(mp3|wav|flac|aac|ogg|m4a)$/.test(e)) return { icon: 'play', label: '音频' }
  if (/\.(zip|rar|7z|tar|gz)$/.test(e)) return { icon: 'file', label: '压缩包' }
  if (/\.(cr2|cr3|nef|arw|dng|raf|orf|rw2)$/.test(e)) return { icon: 'file', label: '相机 RAW' }
  if (/\.(txt|md|log|json|xml|html?)$/.test(e)) return { icon: 'file', label: '文本' }
  return { icon: 'file', label: e ? e.slice(1).toUpperCase() : '文件' }
}

function uploadLabel(u: UploadItem): string {
  switch (u.phase) {
    case 'wait': return '等待'
    case 'hash': return `校验 ${u.pct}%`
    case 'upload': {
      const seg = u.parts && u.parts > 1 ? ` · ${u.part}/${u.parts} 片` : ''
      const bytes = u.totalBytes ? ` · ${fmtSize(u.sentBytes ?? 0)}/${fmtSize(u.totalBytes)}` : ''
      return `${u.pct}%${bytes}${seg}`
    }
    case 'done': return u.note ?? '完成'
    case 'dedupe': return '秒传'
    case 'error': return u.note ?? '失败'
  }
}

type DlgState =
  | { kind: 'space' }
  | { kind: 'folder' }
  | { kind: 'rename'; node: Node }
  | { kind: 'delete'; node: Node }
  | null

export default function Files({ spaceId, folderId }: { spaceId: string; folderId: string }) {
  const [me, setMe] = useState<Me | null>(null)
  const [spaces, setSpaces] = useState<SpaceLite[]>([])
  const [nodes, setNodes] = useState<Node[]>([])
  const [loading, setLoading] = useState(false)
  const [crumbs, setCrumbs] = useState<Crumb[]>([])
  const [error, setError] = useState('')
  const [toast, setToast] = useState('')
  const [busy, setBusy] = useState('')
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  const [labels, setLabels] = useState<ClassLabel[]>([])
  const [caps, setCaps] = useState<Capabilities | null>(null)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [sort, setSort] = useState<'name' | 'updated' | 'size'>('name')
  const [sortDir, setSortDir] = useState<1 | -1>(1)

  const [dragOver, setDragOver] = useState(false)
  const [uploads, setUploads] = useState<UploadItem[]>([])
  const [upOpen, setUpOpen] = useState(true)
  const queueRef = useRef<Job[]>([])
  const runningRef = useRef(0)
  const runningJobs = useRef<Map<string, Job>>(new Map())
  const currentDirRef = useRef({ space: '', parent: '' })
  const fileInput = useRef<HTMLInputElement>(null)

  const [dlg, setDlg] = useState<DlgState>(null)
  const [dlgText, setDlgText] = useState('')

  const [aclTarget, setAclTarget] = useState<{ type: 'space' | 'node'; id: string; name: string } | null>(null)
  const [xferOpen, setXferOpen] = useState(false)
  const [mediaTarget, setMediaTarget] = useState<Node | null>(null)
  const [accountOpen, setAccountOpen] = useState(false)
  const [shareTarget, setShareTarget] = useState<Node | null>(null)
  const [versionTarget, setVersionTarget] = useState<Node | null>(null)
  const [classTarget, setClassTarget] = useState<Node | null>(null)
  const [moveOpen, setMoveOpen] = useState(false)
  const [versions, setVersions] = useState<VersionLite[]>([])
  const [aclSummary, setAclSummary] = useState<AclSummary | null>(null)

  const activeSpace = spaceId
  const parentId = crumbs.length > 0 ? crumbs[crumbs.length - 1].id : ''

  // 选中项是"列表详情"，必须有独立地址：刷新、后退、把链接发给同事都能还原。
  // 用 replace 而不是 push：点一行不该产生一条历史记录。
  const loc = useSyncExternalStore(subscribe, currentPath, currentPath)
  const selId = new URLSearchParams(loc.split('?')[1] ?? '').get('node') ?? ''
  const selectNode = useCallback((id: string) => {
    const base = filesPath(activeSpace, parentId)
    navigate(id ? `${base}?node=${encodeURIComponent(id)}` : base, true)
  }, [activeSpace, parentId])
  currentDirRef.current = { space: activeSpace, parent: parentId }
  const currentSpace = useMemo(() => spaces.find((s) => s.id === activeSpace), [spaces, activeSpace])

  const finished = uploads.filter((u) => u.phase === 'done' || u.phase === 'dedupe').length
  const failed = uploads.filter((u) => u.phase === 'error').length
  const active = uploads.filter((u) => u.phase === 'hash' || u.phase === 'upload').length

  const canClassify = caps?.capabilities.classification ?? true
  const classLabels = useMemo(() => {
    const allowed = caps?.classificationLevels
    if (!allowed || allowed.length === 0) return labels
    return labels.filter((l) => allowed.includes(l.level))
  }, [labels, caps])

  const flash = useCallback((msg: string) => {
    setToast(msg)
    window.setTimeout(() => setToast(''), 2800)
  }, [])

  useEffect(() => {
    applyTheme()
    setTheme((document.documentElement.dataset.theme === 'dark') ? 'dark' : 'light')
    void fetchMe().then(setMe).catch(() => undefined)
    void api<{ items: ClassLabel[] }>('/v1/classifications').then((d) => setLabels(d.items ?? [])).catch(() => undefined)
    void getCapabilities().then(setCaps).catch(() => undefined)
  }, [])

  const loadSpaces = useCallback(async () => {
    try {
      const data = await api<{ items: SpaceLite[] }>('/v1/spaces')
      setSpaces(data.items)
      // 保留查询串：`?node=` 是"当前详情"，落到第一个空间时不能把它丢掉
      if (!spaceId && data.items[0]) navigate(filesPath(data.items[0].id) + window.location.search, true)
    } catch (err) {
      setError(err instanceof HttpError ? err.message : '读取空间失败')
    }
  }, [spaceId])
  useEffect(() => { void loadSpaces() }, [loadSpaces])

  const loadNodes = useCallback(async (sid: string, pid: string) => {
    if (!sid) return
    setLoading(true)
    setError('')
    setChecked(new Set())
    try {
      const q = pid ? `?parentId=${encodeURIComponent(pid)}` : ''
      const data = await api<{ items: Node[] }>(`/v1/spaces/${sid}/nodes${q}`)
      setNodes(data.items)
    } catch (err) {
      setNodes([])
      setError(err instanceof HttpError && err.status === 404 ? '无权访问该目录' : '读取目录失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!activeSpace) return
    let cancelled = false
    if (!folderId) {
      setCrumbs([])
      void loadNodes(activeSpace, '')
      return
    }
    ;(async () => {
      try {
        const d = await api<{ spaceId: string; items: Crumb[] }>(`/v1/nodes/${folderId}/path`)
        if (cancelled) return
        if (d.spaceId && d.spaceId !== activeSpace) {
          navigate(filesPath(d.spaceId, folderId) + window.location.search, true)
          return
        }
        setCrumbs(d.items ?? [])
        void loadNodes(activeSpace, folderId)
      } catch {
        if (cancelled) return
        setCrumbs([])
        setError('目录不存在或无权访问')
        void loadNodes(activeSpace, '')
      }
    })()
    return () => { cancelled = true }
  }, [activeSpace, folderId, loadNodes])

  // 详情面板的数据：版本列表按需取，避免列表页一次拉全部
  const selNode = useMemo(() => nodes.find((n) => n.id === selId) ?? null, [nodes, selId])
  useEffect(() => {
    setVersions([])
    if (!selNode || selNode.kind !== 'file') return
    let cancelled = false
    ;(async () => {
      try {
        const d = await api<{ items: VersionLite[] }>(`/v1/nodes/${selNode.id}/versions`)
        if (!cancelled) setVersions((d.items ?? []).slice(0, 4))
      } catch { /* 版本不可读时面板不展示该块，不影响其它信息 */ }
    })()
    return () => { cancelled = true }
  }, [selNode])

  // 详情面板的"谁被授权"：只在有 manage_acl 时可见，服务端回 visible=false 就整块不显示。
  useEffect(() => {
    setAclSummary(null)
    if (!selNode) return
    let cancelled = false
    ;(async () => {
      try {
        const d = await api<AclSummary>(`/v1/acl/summary?objectType=node&objectId=${encodeURIComponent(selNode.id)}`)
        if (!cancelled && d.visible) setAclSummary(d)
      } catch { /* 摘要拿不到不影响其它信息 */ }
    })()
    return () => { cancelled = true }
  }, [selNode])

  /* ---------------- 上传 ---------------- */

  const UPLOAD_CONCURRENCY = 3

  function patchUpload(id: string, p: Partial<UploadItem>) {
    setUploads((prev) => prev.map((u) => (u.id === id ? { ...u, ...p } : u)))
  }

  async function runJob(job: Job) {
    patchUpload(job.id, { phase: 'hash', pct: 0 })
    try {
      const res = await uploadFile(job.file, job.spaceId, job.parentId, (p) =>
        patchUpload(job.id, {
          phase: p.phase, pct: p.pct, sentBytes: p.sentBytes,
          totalBytes: p.totalBytes, part: p.part, parts: p.parts,
        }),
        job.ac.signal,
      )
      patchUpload(job.id, {
        phase: res.deduped ? 'dedupe' : 'done',
        pct: 100,
        note: res.deduped ? '内容已存在' : res.resumed ? '已从断点继续' : undefined,
      })
    } catch (err) {
      const canceled = err instanceof HttpError ? err.code === 'CANCELED'
        : err instanceof Error && err.message === '已取消'
      if (canceled) {
        patchUpload(job.id, { phase: 'error', note: '已取消（分片已保留，重选可续传）' })
        return
      }
      const msg = err instanceof HttpError
        ? (err.status === 0 ? '网络中断 · 重选同一文件可续传' : err.message)
        : '上传失败'
      patchUpload(job.id, { phase: 'error', note: msg })
    }
  }

  function cancelUpload(id: string) {
    const idx = queueRef.current.findIndex((j) => j.id === id)
    if (idx >= 0) {
      queueRef.current.splice(idx, 1)
      patchUpload(id, { phase: 'error', note: '已取消' })
      return
    }
    runningJobs.current.get(id)?.ac.abort()
  }

  function pumpUploads() {
    while (runningRef.current < UPLOAD_CONCURRENCY) {
      const job = queueRef.current.shift()
      if (!job) return
      runningRef.current += 1
      runningJobs.current.set(job.id, job)
      void runJob(job).finally(() => {
        runningRef.current -= 1
        runningJobs.current.delete(job.id)
        if (runningRef.current === 0 && queueRef.current.length === 0) {
          const cur = currentDirRef.current
          if (cur.space === job.spaceId && cur.parent === job.parentId) void loadNodes(job.spaceId, job.parentId)
        }
        pumpUploads()
      })
    }
  }

  function enqueueUploads(files: File[]) {
    if (!activeSpace || files.length === 0) return
    const space = activeSpace
    const parent = parentId
    setUpOpen(true)

    const allowed = caps?.limits.allowedExts
    const allowSet = allowed && allowed.length > 0 ? new Set(allowed) : null

    const items: UploadItem[] = files.map((f) => ({
      id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      name: f.name, size: f.size, pct: 0, phase: 'wait',
    }))
    setUploads((prev) => [...prev, ...items])

    files.forEach((f, i) => {
      if (allowSet && !allowSet.has(fileExt(f.name))) {
        setUploads((prev) => prev.map((u) => u.id === items[i].id
          ? { ...u, phase: 'error', note: `不支持的格式 ${fileExt(f.name) || '（无扩展名）'}` }
          : u))
        return
      }
      queueRef.current.push({
        id: items[i].id, file: f, spaceId: space, parentId: parent, ac: new AbortController(),
      })
    })
    pumpUploads()
  }

  /* ---------------- 动作 ---------------- */

  async function onCreateSpace(name: string) {
    try {
      const data = await postJSON<{ spaceId: string }>('/v1/spaces', { kind: 'project', name })
      flash('空间已创建')
      await loadSpaces()
      setDlg(null)
      navigate(filesPath(data.spaceId))
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '创建空间失败')
    }
  }

  async function onCreateFolder(name: string) {
    try {
      await postJSON(`/v1/spaces/${activeSpace}/folders`, { parentId, name })
      flash('已创建文件夹')
      setDlg(null)
      void loadNodes(activeSpace, parentId)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '创建失败')
    }
  }

  async function onRename(n: Node, name: string) {
    try {
      await patchJSON(`/v1/nodes/${n.id}`, { name })
      flash('已重命名')
      setDlg(null)
      void loadNodes(activeSpace, parentId)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '重命名失败')
    }
  }

  async function onDelete(n: Node) {
    try {
      await del(`/v1/nodes/${n.id}`)
      flash('已移入回收站')
      setDlg(null)
      selectNode('')
      void loadNodes(activeSpace, parentId)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '删除失败')
    }
  }

  async function onBatchDownload() {
    const ids = [...checked]
    if (ids.length === 0) return
    setBusy('正在打包…')
    try {
      await downloadBatch(ids)
      flash(`已打包 ${ids.length} 个文件`)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '批量下载失败')
    } finally { setBusy('') }
  }

  async function onBatchMove(targetId: string) {
    const ids = [...checked]
    setBusy('正在移动…')
    try {
      await postJSON('/v1/batch/move', { nodeIds: ids, targetParentId: targetId })
      flash(`已移动 ${ids.length} 项`)
      setMoveOpen(false)
      void loadNodes(activeSpace, parentId)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '批量移动失败')
    } finally { setBusy('') }
  }

  async function onSetClass(node: Node, level: number) {
    try {
      await api(`/v1/nodes/${node.id}/classification`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ level }),
      })
      flash('密级已更新')
      setClassTarget(null)
      void loadNodes(activeSpace, parentId)
    } catch (err) {
      flash(err instanceof HttpError ? err.message : '定密失败')
    }
  }

  function openNode(n: Node) {
    if (n.kind === 'folder') navigate(filesPath(activeSpace, n.id))
    else if (isPlayable(n.mime, n.name)) setMediaTarget(n)
    else window.open(previewPath(n.id), '_blank', 'noopener')
  }

  function openDlg(state: DlgState, initial = '') {
    setDlg(state)
    setDlgText(initial)
  }

  /* ---------------- 派生 ---------------- */

  const shown = useMemo(() => {
    const list = [...nodes]
    const dir = sortDir
    list.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1
      if (sort === 'size') return (a.size - b.size) * dir
      if (sort === 'updated') return (new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime()) * dir
      return a.name.localeCompare(b.name, 'zh-CN') * dir
    })
    return list
  }, [nodes, sort, sortDir])

  const allChecked = shown.length > 0 && checked.size === shown.length
  const filesOnly = [...checked].filter((id) => nodes.find((n) => n.id === id)?.kind === 'file')

  function classBadge(level: number | undefined, withTip = true) {
    const lv = level ?? 0
    const lab = labels.find((l) => l.level === lv)
    const el = <span className={`badge cls-${lv}`}>{lab?.name ?? lv}</span>
    if (!withTip) return el
    return (
      <Tooltip
        wide
        content={
          <>
            <div className="tip-t"><Icon name="lock" size={14} /> 密级 {lv} · {lab?.name ?? '未命名'}</div>
            <div className="tip-note">{lab?.description || '未设置说明'}</div>
            <div className="tip-sep" />
            <div className="tip-note">密级<b>先于权限</b>生效：密级不够时，授权也打不开。调低密级要提交申请并经安全管理员审批。</div>
          </>
        }
      >
        {el}
      </Tooltip>
    )
  }

  const commands: Command[] = [
    { label: '上传文件到当前目录', icon: 'upload', hint: '可多选', run: () => fileInput.current?.click() },
    { label: '在当前目录新建文件夹', icon: 'folderPlus', run: () => openDlg({ kind: 'folder' }) },
    {
      label: '查看空间权限',
      icon: 'key',
      run: () => activeSpace && setAclTarget({ type: 'space', id: activeSpace, name: currentSpace?.name ?? '空间' }),
    },
    { label: '最近活动', icon: 'clock', run: () => navigate('/activity') },
    { label: '刷新当前目录', icon: 'history', run: () => loadNodes(activeSpace, parentId) },
  ]

  const sel = selNode

  return (
    <Shell
      me={me}
      spaces={spaces}
      activeSpaceId={activeSpace}
      onSpace={(id) => navigate(filesPath(id))}
      onCreateSpace={() => openDlg({ kind: 'space' })}
      spaceName={currentSpace?.name}
      crumbs={crumbs}
      onCrumb={(id) => {
        const i = crumbs.findIndex((c) => c.id === id)
        navigate(filesPath(activeSpace, i >= 0 ? id : ''))
      }}
      commands={commands}
      onOpenHit={(h: SearchHit) => goHit(h)}
      onOpenAccount={() => setAccountOpen(true)}
      theme={theme}
      onToggleTheme={() => {
        const t = cycleTheme()
        setTheme(t === 'dark' ? 'dark' : 'light')
        flash(t === 'auto' ? '主题：跟随系统' : t === 'dark' ? '主题：深色' : '主题：浅色')
      }}
      inspector={sel ? (
        <aside className="inspector">
          <div className="insp-head">
            <span className="cell-name" style={{ flex: 'none' }}>
              <span className={`ftype${sel.kind === 'folder' ? ' folder' : ''}`} style={{ width: 34, height: 34 }}>
                <Icon name={kindOf(sel).icon} size={17} />
              </span>
            </span>
            <div className="ttl">
              <b>{sel.name}</b>
              <span>{kindOf(sel).label} · {sel.kind === 'folder' ? '目录' : fmtSize(sel.size)}</span>
            </div>
            <button className="icon ghost" aria-label="关闭详情" onClick={() => selectNode('')}>
              <Icon name="close" size={15} />
            </button>
          </div>

          <div className="insp-scroll">
            <div className="insp-acts">
              <button className="primary sm" onClick={() => openNode(sel)}>
                <Icon name={sel.kind === 'folder' ? 'folder' : 'external'} size={14} />
                {sel.kind === 'folder' ? '打开' : isPlayable(sel.mime, sel.name) ? '播放' : '预览'}
              </button>
              {sel.kind === 'file' && (
                <>
                  <button className="sm" onClick={() => downloadNode(sel.id, sel.name).catch(() => flash('下载失败或无权限'))}>
                    <Icon name="download" size={14} /> 下载
                  </button>
                  <button className="sm" onClick={() => setShareTarget(sel)}><Icon name="share" size={14} /> 分享</button>
                </>
              )}
              <Menu
                items={[
                  { label: '版本历史', icon: 'history', onClick: () => setVersionTarget(sel) },
                  { label: '权限设置', icon: 'key', onClick: () => setAclTarget({ type: 'node', id: sel.id, name: sel.name }) },
                  ...(sel.kind === 'file' && canClassify ? [{ label: '设置密级', icon: 'lock', onClick: () => setClassTarget(sel) }] : []),
                  { label: '重命名', icon: 'edit', onClick: () => openDlg({ kind: 'rename', node: sel }, sel.name) },
                  { sep: true, label: 'sep' },
                  { label: '移入回收站', icon: 'trash', danger: true, onClick: () => openDlg({ kind: 'delete', node: sel }) },
                ]}
                trigger={(open) => (
                  <button className="sm icon" aria-label="更多操作" onClick={open}>
                    <Icon name="more" size={15} />
                  </button>
                )}
              />
            </div>

            <div className="insp-sec">
              <div className="label">归属与流转</div>
              <dl className="insp-dl">
                <dt>所有者</dt>
                <dd>
                  <span className="person">
                    <Avatar name={sel.owner?.name || '—'} size={20} />
                    <span className="nm" style={{ maxWidth: '15ch' }}>{sel.owner?.name || '—'}</span>
                  </span>
                </dd>
                <dt>最近编辑</dt>
                <dd>
                  {sel.kind === 'file' && sel.updatedBy?.name ? (
                    <span className="person">
                      <Avatar name={sel.updatedBy.name} size={20} />
                      <span className="nm" style={{ maxWidth: '12ch' }}>{sel.updatedBy.name}</span>
                      <span className="when">{relTime(sel.updatedAt)}</span>
                    </span>
                  ) : <span className="dim">—</span>}
                </dd>
                <dt>版本</dt>
                <dd>
                  {sel.kind === 'file' ? (
                    <>
                      <span className="mono">v{sel.versionNo ?? 1}</span>
                      <button className="ghost sm" style={{ height: 22 }} onClick={() => setVersionTarget(sel)}>查看历史</button>
                    </>
                  ) : <span className="dim">目录不建版本</span>}
                </dd>
                <dt>密级</dt>
                <dd>{sel.kind === 'file' ? classBadge(sel.classification, false) : <span className="dim">随上级</span>}
                  {sel.kind === 'file' && canClassify && (
                    <button className="ghost sm" style={{ height: 22 }} onClick={() => setClassTarget(sel)}>调整</button>
                  )}
                </dd>
                <dt>大小</dt>
                <dd>{sel.kind === 'folder' ? '—' : fmtSize(sel.size)}</dd>
                <dt>创建</dt>
                <dd>{sel.createdAt ? absTime(sel.createdAt) : '—'}</dd>
                <dt>更新</dt>
                <dd>{absTime(sel.updatedAt)}</dd>
              </dl>
            </div>

            {sel.kind === 'file' && versions.length > 0 && (
              <div className="insp-sec">
                <div className="label">最近版本</div>
                {versions.map((v) => (
                  <div className="ver-item" key={v.versionNo}>
                    <span className="v">v{v.versionNo}</span>
                    <span className="n">
                      {v.createdBy && !/^[0-9a-f-]{30,}$/i.test(v.createdBy) ? `${v.createdBy} · ` : ''}
                      {relTime(v.createdAt)}
                    </span>
                  </div>
                ))}
                <button className="ghost sm" style={{ alignSelf: 'flex-start' }} onClick={() => setVersionTarget(sel)}>
                  全部版本与回退
                </button>
              </div>
            )}

            {aclSummary && (
              <div className="insp-sec">
                <div className="label">
                  谁被授权 · {aclSummary.total}
                  <InfoDot title="这些条目是什么">
                    <p>只统计<b>直接挂在这个对象上</b>的授权条目；从他处继承来的权限不计入，但同样生效。</p>
                    <p>部门、角色、组会覆盖其下所有成员；「拒绝」条目优先于允许条目。</p>
                    <div className="pop-foot">只有对该对象有管理权限的人能看到这一块。撤销与管理请点下方「管理权限」。</div>
                  </InfoDot>
                </div>
                {(aclSummary.total ?? 0) === 0 && (
                  <div className="hint" style={{ paddingLeft: 4 }}>
                    这个对象没有单独授权，访问权限继承自所在空间。
                  </div>
                )}
                {(aclSummary.entries ?? []).map((x) => (
                  <div className="ver-item" key={x.subjectType + (x.subjectName ?? '') + x.preset}>
                    <Avatar name={x.subjectName || SUBJECT_LABEL[x.subjectType] || '?'} size={20} />
                    <span className="n" style={{ color: 'var(--ink-2)' }}>{x.subjectName || SUBJECT_LABEL[x.subjectType] || '未知主体'}</span>
                    {x.deny && <span className="badge danger" style={{ height: 17 }}>拒绝</span>}
                    <span className={`badge ${x.preset === 'owner' ? 'brand' : 'plain'}`} style={{ height: 17 }}>
                      {PRESET_LABEL[x.preset] ?? x.preset}
                    </span>
                  </div>
                ))}
                {(aclSummary.total ?? 0) > (aclSummary.entries?.length ?? 0) && (
                  <div className="hint" style={{ paddingLeft: 4 }}>
                    另有 {aclSummary.total! - aclSummary.entries!.length} 条，进入权限面板查看全部
                  </div>
                )}
                {(aclSummary.denyCount ?? 0) > 0 && (
                  <div className="hint" style={{ paddingLeft: 4 }}>
                    含 {aclSummary.denyCount} 条显式拒绝：被拒绝的人即使属于被授权的部门也打不开
                  </div>
                )}
                {aclSummary.inheritedBroken && (
                  <div className="hint" style={{ paddingLeft: 4 }}>
                    已断开继承：这些条目是断开时对祖先授权的快照
                  </div>
                )}
                <button className="ghost sm" style={{ alignSelf: 'flex-start' }} onClick={() => setAclTarget({ type: 'node', id: sel.id, name: sel.name })}>
                  管理权限
                </button>
              </div>
            )}

            <div className="banner" style={{ background: 'var(--surface-2)' }}>
              <span className="ico"><Icon name="info" size={14} /></span>
              <span>
                看不到某个按钮时，多半是<b>权限不足</b>而不是功能缺失。
                用「权限解释」可以看清卡在哪一步。
              </span>
            </div>
          </div>

          <div className="insp-foot">
            <button className="ghost sm" onClick={() => setAclTarget({ type: 'node', id: sel.id, name: sel.name })}>
              <Icon name="key" size={14} /> 权限
            </button>
            <button className="ghost sm" onClick={() => setVersionTarget(sel)}>
              <Icon name="history" size={14} /> 版本
            </button>
            <div className="grow" />
            <button className="ghost sm" onClick={() => openDlg({ kind: 'rename', node: sel }, sel.name)}>改名</button>
          </div>
        </aside>
      ) : undefined}
    >
      <PendingTransferBar onChanged={() => void loadSpaces()} />

      <div className="content-head">
        <div className="ttl">
          <h1>{crumbs.length ? crumbs[crumbs.length - 1].name : '全部文件'}</h1>
          <div className="sub">
            <span>{loading ? '载入中…' : `${shown.length} 项`}</span>
            {currentSpace?.name && (
              <>
                <span className="dim">·</span>
                <span>{currentSpace.name}</span>
              </>
            )}
            {currentSpace?.ownerName && (
              <>
                <span className="dim">·</span>
                <span>所有者 {currentSpace.ownerName}</span>
              </>
            )}
            <InfoDot title="这一页能做什么">
              <p><b>点文件名</b>＝预览（新页签）；<b>点整行</b>＝在右侧看详情。目录点名称进入。</p>
              <p>勾选左侧方框可批量下载或移动。批量操作会<b>整批预检权限</b>：任一对象无权则整批不执行，避免"做了一半"。</p>
              <div className="pop-foot">按 <b>⌘K</b> 可跨空间搜索文件，或直接执行"上传/新建"等操作。</div>
            </InfoDot>
          </div>
        </div>
        <div className="acts">
          {checked.size > 0 ? (
            <>
              <span className="badge brand">已选 {checked.size}</span>
              <button className="primary sm" onClick={onBatchDownload} disabled={filesOnly.length === 0 || !!busy}>
                <Icon name="download" size={14} /> 打包下载
              </button>
              <button className="sm" onClick={() => setMoveOpen(true)} disabled={!!busy}>
                <Icon name="arrowRight" size={14} /> 移动
              </button>
              <button className="ghost sm" onClick={() => setChecked(new Set())}>清除</button>
            </>
          ) : (
            <>
              <input
                ref={fileInput} type="file" hidden multiple
                onChange={(e) => {
                  const list = e.target.files
                  if (list && list.length) enqueueUploads(Array.from(list))
                  e.currentTarget.value = ''
                }}
              />
              <div className="seg" role="group" aria-label="排序">
                <button className={sort === 'name' ? 'on' : ''} onClick={() => { setSort('name'); setSortDir(sort === 'name' ? (sortDir === 1 ? -1 : 1) : 1) }}>名称</button>
                <button className={sort === 'updated' ? 'on' : ''} onClick={() => { setSort('updated'); setSortDir(sort === 'updated' ? (sortDir === 1 ? -1 : 1) : -1) }}>更新</button>
                <button className={sort === 'size' ? 'on' : ''} onClick={() => { setSort('size'); setSortDir(-1) }}>大小</button>
              </div>
              {currentSpace && me && currentSpace.ownerId === me.userId && (
                <Tooltip
                  wide
                  content={
                    <>
                      <b>移交空间所有权</b>
                      <div className="tip-note">
                        你是这个空间的所有者。移交后，空间归属、空间内你名下文件的归属以及所有者权限会一并转给对方。
                        离职交接、岗位调整时用它。
                      </div>
                      <div className="tip-note">管理员从管理台「空间台账」也能发起，但移给他自己时需要你确认。</div>
                    </>
                  }
                >
                  <button className="sm" onClick={() => setXferOpen(true)}>
                    <Icon name="share" size={14} /> 移交
                  </button>
                </Tooltip>
              )}
              {activeSpace && (
                <Tooltip content={<><b>空间权限</b><div className="tip-note">给整个空间授权：会同时作用于其后新建的内容。单文件授权请用行内「权限」。</div></>}>
                  <button className="sm" onClick={() => setAclTarget({ type: 'space', id: activeSpace, name: currentSpace?.name ?? '空间' })}>
                    <Icon name="key" size={14} /> 空间权限
                  </button>
                </Tooltip>
              )}
              <Tooltip content={<><b>新建文件夹</b><div className="tip-note">在当前层创建目录。上传会落在「当前目录」，不是空间根。</div></>}>
                <button onClick={() => openDlg({ kind: 'folder' })} disabled={!activeSpace}>
                  <Icon name="folderPlus" size={15} /> 新建
                </button>
              </Tooltip>
              <button className="primary" onClick={() => fileInput.current?.click()} disabled={!activeSpace}>
                <Icon name="upload" size={15} /> 上传
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="banner danger">
          <span className="ico"><Icon name="alert" size={15} /></span>
          <div>
            <b>{error}</b>
            <div style={{ marginTop: 2 }}>系统对无权限的对象统一返回"不存在"，避免泄露文件是否存在。可返回上级或联系所有者确认。</div>
          </div>
        </div>
      )}

      <div
        className={`panel dropzone ${dragOver ? 'over' : ''}`}
        onDragOver={(e) => { e.preventDefault(); if (activeSpace) setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault(); setDragOver(false)
          if (!activeSpace) return
          const files = Array.from(e.dataTransfer.files)
          if (files.length) enqueueUploads(files)
        }}
      >
        {loading ? (
          <div className="empty">载入中…</div>
        ) : shown.length === 0 ? (
          <div className="empty">
            <div className="empty-art"><Icon name="folder" size={30} /></div>
            <h3>这个目录还是空的</h3>
            <p>把文件拖到这里即可上传，也可以用右上角「上传」。上传落在<b>当前目录</b>，不是空间根目录。</p>
            <div className="row-gap" style={{ marginTop: 4 }}>
              <button className="primary" onClick={() => fileInput.current?.click()} disabled={!activeSpace}>
                <Icon name="upload" size={15} /> 选择文件
              </button>
              <button onClick={() => openDlg({ kind: 'folder' })} disabled={!activeSpace}>
                <Icon name="folderPlus" size={15} /> 新建文件夹
              </button>
            </div>
          </div>
        ) : (
          <div className="panel-body">
            <table>
              <thead>
                <tr>
                  <th className="tight">
                    <input
                      type="checkbox"
                      checked={allChecked}
                      aria-label="全选"
                      onChange={(e) => setChecked(e.target.checked ? new Set(shown.map((n) => n.id)) : new Set())}
                    />
                  </th>
                  <th>名称</th>
                  <th className="col-owner" style={{ width: 148 }}>归属</th>
                  <th className="col-edit" style={{ width: 176 }}>最近编辑</th>
                  <th className="col-class" style={{ width: 84 }}>密级</th>
                  <th className="col-size" style={{ width: 92, textAlign: 'right' }}>大小</th>
                  <th style={{ width: 48 }} />
                </tr>
              </thead>
              <tbody>
                {shown.map((n) => {
                  const isChecked = checked.has(n.id)
                  const k = kindOf(n)
                  return (
                    <tr
                      key={n.id}
                      className={`${isChecked ? 'selected' : ''}`}
                      style={selId === n.id ? { background: 'var(--surface-3)' } : undefined}
                      onClick={() => selectNode(n.id)}
                    >
                      <td className="tight" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          aria-label={`选择 ${n.name}`}
                          onChange={(e) => {
                            const next = new Set(checked)
                            if (e.target.checked) next.add(n.id); else next.delete(n.id)
                            setChecked(next)
                          }}
                        />
                      </td>
                      <td className="name">
                        <div className="cell-name">
                          <span className={`ftype${n.kind === 'folder' ? ' folder' : ''}`}>
                            <Icon name={k.icon} size={16} />
                          </span>
                          <span className="nm">
                            <Tooltip
                              wide
                              content={
                                <>
                                  <div className="tip-t"><Icon name={k.icon} size={14} /> {n.name}</div>
                                  <div className="tip-r"><span>类型</span><b>{k.label}</b></div>
                                  <div className="tip-r"><span>大小</span><b>{n.kind === 'folder' ? '—' : fmtSize(n.size)}</b></div>
                                  <div className="tip-r"><span>归属</span><b>{n.owner?.name || '—'}</b></div>
                                  {n.kind === 'file' && (
                                    <div className="tip-r"><span>最近编辑</span><b>{n.updatedBy?.name || '—'} · v{n.versionNo ?? 1}</b></div>
                                  )}
                                  <div className="tip-r"><span>更新</span><b>{relTime(n.updatedAt)}</b></div>
                                  <div className="tip-sep" />
                                  <div className="tip-note">
                                    {n.kind === 'folder' ? '点击进入目录；点击整行在右侧查看详情。' : '点击文件名直接预览（新页签）；点击整行在右侧查看详情。'}
                                  </div>
                                </>
                              }
                            >
                              <button
                                className="link"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  if (n.kind === 'folder') navigate(filesPath(activeSpace, n.id))
                                  else if (isPlayable(n.mime, n.name)) setMediaTarget(n)
                                  else window.open(previewPath(n.id), '_blank', 'noopener')
                                }}
                              >
                                {n.name}
                              </button>
                            </Tooltip>
                            <span className="sub">
                              {n.kind === 'file' ? k.label : '目录'}
                              {isPdf(n.name, n.mime) && <span className="badge teal" style={{ height: 17 }}>水印</span>}
                              {n.kind === 'file' && (n.versionNo ?? 1) > 1 && (
                                <span className="dim">v{n.versionNo}</span>
                              )}
                            </span>
                          </span>
                        </div>
                      </td>
                      <td className="col-owner" onClick={(e) => e.stopPropagation()}>
                        <Tooltip
                          wide
                          content={
                            <>
                              <div className="tip-t"><Avatar name={n.owner?.name || '—'} size={20} /> {n.owner?.name || '—'}</div>
                              <div className="tip-note">所有者：可以授权他人、移交所有权。移除最后一个所有者会被系统拒绝。</div>
                            </>
                          }
                        >
                          <span className="person">
                            <Avatar name={n.owner?.name || '—'} size={22} />
                            <span className="nm">{n.owner?.name || '—'}</span>
                          </span>
                        </Tooltip>
                      </td>
                      <td className="col-edit">
                        {n.kind === 'file' && n.updatedBy?.name ? (
                          <Tooltip
                            wide
                            content={
                              <>
                                <div className="tip-t"><Icon name="edit" size={14} /> 最近一次保存</div>
                                <div className="tip-r"><span>贡献者</span><b>{n.updatedBy.name}</b></div>
                                <div className="tip-r"><span>版本</span><b>v{n.versionNo ?? 1}</b></div>
                                <div className="tip-r"><span>时间</span><b>{absTime(n.updatedAt)}</b></div>
                                <div className="tip-sep" />
                                <div className="tip-note">每次在线保存都会追加新版本，不覆盖旧内容，可随时回退。</div>
                              </>
                            }
                          >
                            <span className="person">
                              <Avatar name={n.updatedBy.name} size={22} />
                              <span className="nm">{n.updatedBy.name}</span>
                              <span className="when">{relTime(n.updatedAt)}</span>
                            </span>
                          </Tooltip>
                        ) : <span className="dim">—</span>}
                      </td>
                      <td className="col-class">{n.kind === 'file' ? classBadge(n.classification) : <span className="dim">—</span>}</td>
                      <td className="col-size tnum" style={{ textAlign: 'right' }}>{n.kind === 'folder' ? '—' : fmtSize(n.size)}</td>
                      <td className="actions" onClick={(e) => e.stopPropagation()}>
                        <Menu
                          items={[
                            ...(n.kind === 'folder'
                              ? [{ label: '打开目录', icon: 'folder', onClick: () => navigate(filesPath(activeSpace, n.id)) }]
                              : [
                                { label: isPlayable(n.mime, n.name) ? '播放' : '预览', icon: 'external', onClick: () => openNode(n) },
                                { label: '下载', icon: 'download', onClick: () => downloadNode(n.id, n.name).catch(() => flash('下载失败或无权限')) },
                                ...(isOffice(n.name) ? [{ label: '在线编辑', icon: 'edit', onClick: () => window.open(`/edit/${n.id}`, '_blank', 'noopener') }] : []),
                                { label: '分享', icon: 'share', onClick: () => setShareTarget(n) },
                              ]),
                            { sep: true, label: 'sep' },
                            { label: '版本历史', icon: 'history', onClick: () => setVersionTarget(n) },
                            { label: '权限', icon: 'key', onClick: () => setAclTarget({ type: 'node', id: n.id, name: n.name }) },
                            ...(n.kind === 'file' && canClassify ? [{ label: '设置密级', icon: 'lock', onClick: () => setClassTarget(n) }] : []),
                            { label: '重命名', icon: 'edit', onClick: () => openDlg({ kind: 'rename', node: n }, n.name) },
                            { sep: true, label: 'sep' },
                            { label: '移入回收站', icon: 'trash', danger: true, onClick: () => openDlg({ kind: 'delete', node: n }) },
                          ]}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            <div className="panel-foot">
              <Icon name="upload" size={13} />
              也可以直接把文件拖到这里上传 · 支持多选与断点续传
            </div>
          </div>
        )}
      </div>

      {/* 上传队列：浮层，切目录也不会打断 */}
      {uploads.length > 0 && (
        <div className="up-panel">
          <div className="up-head">
            <Icon name="upload" size={15} />
            <b>上传 {finished}/{uploads.length}</b>
            {failed > 0 && <span className="badge danger">{failed} 个失败</span>}
            {active > 0 && (
              <Tooltip content="大文件先本地算校验值（无网络流量），再分片上传；中途可继续浏览其他目录">
                <span className="hint">进行中 {active}</span>
              </Tooltip>
            )}
            <div className="grow" />
            {active === 0 && <button className="ghost sm" onClick={() => setUploads([])}>清除</button>}
            <button className="icon ghost" aria-label={upOpen ? '收起' : '展开'} onClick={() => setUpOpen((v) => !v)}>
              <Icon name={upOpen ? 'chevronD' : 'chevronUp'} size={15} />
            </button>
          </div>
          {upOpen && (
            <div className="up-body">
              {uploads.map((u) => (
                <div className="up-item" key={u.id}>
                  <div className="r1">
                    <span className="nm" title={u.name}>{u.name}</span>
                    <span className={`st${u.phase === 'error' ? ' err' : u.phase === 'done' || u.phase === 'dedupe' ? ' ok' : ''}`}>
                      {uploadLabel(u)}
                    </span>
                    {(u.phase === 'wait' || u.phase === 'hash' || u.phase === 'upload') && (
                      <button className="ghost sm" style={{ height: 20, padding: '0 4px', fontSize: 11 }}
                        onClick={() => cancelUpload(u.id)}
                        title="取消后已传分片保留，重选同一文件可从断点继续">
                        取消
                      </button>
                    )}
                  </div>
                  <div className={`progress${u.phase === 'error' ? ' error' : u.phase === 'done' || u.phase === 'dedupe' ? ' done' : ''}`}>
                    <i style={{ width: `${u.phase === 'error' ? 100 : u.pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 对话框 */}
      {xferOpen && currentSpace && me && (
        <SpaceTransferDialog
          spaceId={currentSpace.id}
          spaceName={currentSpace.name}
          ownerName={currentSpace.ownerName}
          meId={me.userId}
          isAdmin={(me.roles ?? []).includes('sysadmin')}
          isOwner
          onClose={() => setXferOpen(false)}
          onDone={(m) => { flash(m); void loadSpaces() }}
        />
      )}

      {dlg?.kind === 'space' && (
        <Dialog
          title="新建空间"
          icon="folderPlus"
          note="空间是文件的顶层容器。创建后你是所有者，可再授权他人；新建空间不会自动让别人看见。"
          onClose={() => setDlg(null)}
          footer={
            <>
              <button onClick={() => setDlg(null)}>取消</button>
              <button className="primary" disabled={!dlgText.trim()} onClick={() => void onCreateSpace(dlgText.trim())}>创建</button>
            </>
          }
        >
          <div className="field">
            <label htmlFor="sp-name">空间名称</label>
            <input id="sp-name" autoFocus value={dlgText} onChange={(e) => setDlgText(e.target.value)}
              placeholder="例如：2026 年产品交付" onKeyDown={(e) => { if (e.key === 'Enter' && dlgText.trim()) void onCreateSpace(dlgText.trim()) }} />
          </div>
        </Dialog>
      )}
      {dlg?.kind === 'folder' && (
        <Dialog
          title="新建文件夹"
          icon="folderPlus"
          note={`将创建在「${crumbs.length ? crumbs[crumbs.length - 1].name : currentSpace?.name ?? '空间根'}」下。`}
          onClose={() => setDlg(null)}
          footer={
            <>
              <button onClick={() => setDlg(null)}>取消</button>
              <button className="primary" disabled={!dlgText.trim()} onClick={() => void onCreateFolder(dlgText.trim())}>创建</button>
            </>
          }
        >
          <div className="field">
            <label htmlFor="fd-name">文件夹名称</label>
            <input id="fd-name" autoFocus value={dlgText} onChange={(e) => setDlgText(e.target.value)}
              placeholder="例如：合同终稿" onKeyDown={(e) => { if (e.key === 'Enter' && dlgText.trim()) void onCreateFolder(dlgText.trim()) }} />
          </div>
        </Dialog>
      )}
      {dlg?.kind === 'rename' && (
        <Dialog
          title="重命名"
          icon="edit"
          note="重命名只改显示名，不改内容，也不会产生新版本。"
          onClose={() => setDlg(null)}
          footer={
            <>
              <button onClick={() => setDlg(null)}>取消</button>
              <button className="primary" disabled={!dlgText.trim() || dlgText === dlg.node.name}
                onClick={() => void onRename(dlg.node, dlgText.trim())}>保存</button>
            </>
          }
        >
          <div className="field">
            <label htmlFor="rn-name">新名称</label>
            <input id="rn-name" autoFocus value={dlgText} onChange={(e) => setDlgText(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && dlgText.trim()) void onRename(dlg.node, dlgText.trim()) }} />
          </div>
        </Dialog>
      )}
      {dlg?.kind === 'delete' && (
        <Dialog
          title={`把「${dlg.node.name}」移入回收站？`}
          icon="trash"
          onClose={() => setDlg(null)}
          footer={
            <>
              <button onClick={() => setDlg(null)}>取消</button>
              <button className="danger" onClick={() => void onDelete(dlg.node)}>移入回收站</button>
            </>
          }
        >
          <div className="banner warn">
            <span className="ico"><Icon name="alert" size={15} /></span>
            <div>
              {dlg.node.kind === 'folder'
                ? '目录内的所有内容会一起进入回收站。'
                : '文件会进入回收站，保留期内可恢复。'}
              <div style={{ marginTop: 3 }}>删除是软删除：审计仍可追溯，保留期到期后才由清理任务处理。</div>
            </div>
          </div>
        </Dialog>
      )}

      {aclTarget && (
        <AclDrawer target={aclTarget} onClose={() => setAclTarget(null)} onChanged={() => flash('权限已更新')} />
      )}
      {mediaTarget && <MediaModal target={mediaTarget} onClose={() => setMediaTarget(null)} />}

      {classTarget && (
        <>
          <div className="drawer-backdrop" onClick={() => setClassTarget(null)} />
          <aside className="drawer">
            <h2>设置密级</h2>
            <div className="hint">当前：{classTarget.name}</div>
            <div className="banner" style={{ background: 'var(--surface-2)', marginTop: 4 }}>
              <span className="ico"><Icon name="lock" size={14} /></span>
              <span>只能设置为不超过自身密级的值；<b>降低</b>密级需提交申请，由安全管理员审批。</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
              {classLabels.map((l) => (
                <button
                  key={l.level}
                  className={l.level === (classTarget.classification ?? 0) ? 'primary' : ''}
                  style={{ justifyContent: 'space-between', display: 'flex', textAlign: 'left', height: 'auto', padding: '9px 12px' }}
                  onClick={() => void onSetClass(classTarget, l.level)}
                >
                  <span><span className={`badge cls-${l.level}`}>{l.name}</span> <span className="hint" style={{ marginLeft: 6 }}>等级 {l.level}</span></span>
                  <span className="hint" style={{ maxWidth: '52%', textAlign: 'right' }}>{l.description}</span>
                </button>
              ))}
            </div>
            <div style={{ marginTop: 'auto' }}>
              <button onClick={() => setClassTarget(null)}>关闭</button>
            </div>
          </aside>
        </>
      )}

      {moveOpen && (
        <>
          <div className="drawer-backdrop" onClick={() => setMoveOpen(false)} />
          <aside className="drawer">
            <h2>移动 {checked.size} 项到</h2>
            <div className="hint">只列出当前目录下的子目录；移动到空间根目录始终可用。</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
              <button onClick={() => void onBatchMove('')}><Icon name="folder" size={15} /> 空间根目录</button>
              {nodes.filter((n) => n.kind === 'folder').map((f) => (
                <button key={f.id} onClick={() => void onBatchMove(f.id)}>
                  <Icon name="folder" size={15} /> {f.name}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 'auto' }}>
              <button onClick={() => setMoveOpen(false)}>取消</button>
            </div>
          </aside>
        </>
      )}

      {shareTarget && (
        <ShareDrawer
          target={{ id: shareTarget.id, name: shareTarget.name }}
          onClose={() => setShareTarget(null)}
          onDone={(m) => flash(m)}
          canMail={caps?.capabilities.shareMail ?? true}
        />
      )}
      {versionTarget && (
        <VersionsDrawer
          node={{ id: versionTarget.id, name: versionTarget.name }}
          onClose={() => setVersionTarget(null)}
          onChanged={() => flash('已回退到历史版本')}
        />
      )}
      {accountOpen && <AccountDrawer me={me} onClose={() => setAccountOpen(false)} />}

      {busy && <div className="toast">{busy}</div>}
      {toast && <div className="toast"><Icon name="check" size={14} /> {toast}</div>}
    </Shell>
  )
}
