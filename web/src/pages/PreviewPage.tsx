import { useEffect, useState } from 'react'
import { api, fetchBlob, getAccess, HttpError, downloadNode } from '../api'
import { Icon, Tooltip, absTime, fmtSize, relTime } from '../components/ui'
import { heicToJpeg, isHeic } from '../heic'

// 独立预览页（新页签）。
//
// 为什么不继续用弹窗：文档要看很久、要缩放、要对照别的窗口。
// 弹窗会随主页面一起被 ESC/误点关掉，而且刷新就没了。
// 独立地址 /preview/{nodeId} 可以刷新、可以开多个、可以贴进工单。
//
// 权限仍在服务端：本页只发两个请求（元信息 + 预览字节），拿不到就是 403/404。

type Meta = {
  id: string
  name: string
  mime: string
  size: number
  classification?: number
  versionNo?: number
  createdAt?: string
  updatedAt?: string
  owner?: { id: string; name: string }
  updatedBy?: { name: string }
}

// PDF 打开参数。
//
// 默认 100%（原尺寸）。
//
// 原因：FitH（适应宽度）在表格导出的宽页上会把内容压到 ~24%，字小到看不清；
// 而 50% 虽能看清结构，正文字号仍然偏小。折中方案最终定为原尺寸起步，
// 宽表横向滚动、需要时再自行缩放——"看得清"优先于"看得全"。
type Zoom = 'fit' | 50 | 75 | 100 | 125

const ZOOM_OPTIONS: { key: Zoom; label: string }[] = [
  { key: 50, label: '50%' },
  { key: 75, label: '75%' },
  { key: 100, label: '100%' },
  { key: 'fit', label: '适应宽度' },
]

// pdfSrc 把缩放写进片段标识。
// 片段变化不会触发 iframe 重新加载，所以调用方必须用 key 强制重挂载，
// 否则用户点了按钮却什么也不会发生。
function pdfSrc(url: string, zoom: Zoom): string {
  return `${url}#${zoom === 'fit' ? 'view=FitH' : `zoom=${zoom}`}`
}

function isText(mime: string): boolean {
  return mime.startsWith('text/') || mime === 'application/json'
}

export default function PreviewPage({ nodeId }: { nodeId: string }) {
  const [meta, setMeta] = useState<Meta | null>(null)
  const [url, setUrl] = useState('')
  const [type, setType] = useState('')
  const [text, setText] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [zoom, setZoom] = useState<Zoom>(100)
  // 计时用于"还要等多久"的反馈：慢格式（Office 首次转换 4.4s、RAW 3~11s、
  // HEIC 10~20s）如果只显示"载入中"，用户无法判断是卡死还是真的在算。
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!loading) {
      setElapsed(0)
      return
    }
    const t = window.setInterval(() => setElapsed((n) => n + 1), 1000)
    return () => window.clearInterval(t)
  }, [loading, nodeId])

  useEffect(() => {
    let cancelled = false
    let revoke: (() => void) | undefined

    ;(async () => {
      try {
        const m = await api<Meta>(`/v1/nodes/${nodeId}`)
        if (cancelled) return
        setMeta(m)
        document.title = `${m.name} · 预览`

        if (isText(m.mime)) {
          const resp = await fetch(`/v1/nodes/${nodeId}/preview`, {
            headers: { Authorization: `Bearer ${getAccess()}` },
          })
          if (!resp.ok) throw new HttpError(resp.status, 'PREVIEW_FAILED', '预览失败')
          const body = await resp.text()
          if (!cancelled) setText(body.slice(0, 500_000))
          return
        }

        // HEIC/HEIF：浏览器普遍不能解码（只有 Safari 可以），
        // 先在后端拿到原始字节，再用 wasm 解成 JPEG 显示。
        // 放在 fetchBlob 之前，避免先创建一个大 URL 再丢掉。
        if (isHeic(m.mime, m.name)) {
          const resp = await fetch(`/v1/nodes/${nodeId}/preview`, {
            headers: { Authorization: `Bearer ${getAccess()}` },
          })
          if (!resp.ok) throw new HttpError(resp.status, 'PREVIEW_FAILED', '预览失败')
          const buf = await resp.arrayBuffer()
          const jpeg = await heicToJpeg(buf)
          if (cancelled) return
          const u = URL.createObjectURL(jpeg)
          revoke = () => URL.revokeObjectURL(u)
          setUrl(u)
          setType('image/jpeg')
          return
        }

        const blob = await fetchBlob(`/v1/nodes/${nodeId}/preview`)
        if (cancelled) { blob.revoke(); return }
        revoke = blob.revoke
        setUrl(blob.url)
        setType(blob.type)
      } catch (err) {
        if (cancelled) return
        if (err instanceof HttpError && err.status === 501) {
          setError('该类型暂不支持在线预览，请下载后本地查看')
        } else if (err instanceof HttpError && err.status === 403) {
          setError('没有预览权限')
        } else if (err instanceof HttpError && err.status === 404) {
          setError('文件不存在或无权访问')
        } else {
          // 保留具体原因：HEIC 解码失败可能是"分辨率过高""解码超时"，
          // 一律显示"预览失败"会让用户以为系统坏了，实际上他知道该怎么办。
          setError(err instanceof HttpError ? err.message : (err instanceof Error ? err.message : '预览失败'))
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()

    return () => { cancelled = true; revoke?.() }
  }, [nodeId])

  // loadingHint 按格式给出预期耗时。
  //
  // 数字不是拍脑袋：Office 首次转换实测 4.4 秒（608KB docx）、
  // 相机 RAW 3~11 秒、HEIC 前端解码 10~20 秒、PDF 直出约 0.1 秒。
  // 这些是"首次"的代价，命中缓存后都是百毫秒级——所以文案里强调"首次"。
  function loadingHint(): string {
    const name = (meta?.name ?? '').toLowerCase()
    const mime = (meta?.mime ?? '').toLowerCase()
    let base = '载入中…'
    if (meta && isHeic(meta.mime, meta.name)) {
      base = '正在解码 HEIC 图像（大图约需 10~20 秒）…'
    } else if (/\.(cr2|cr3|nef|arw|dng|orf|rw2|raf|pef)$/.test(name)) {
      base = '正在解码相机 RAW（首次约需 3~15 秒）…'
    } else if (/\.(docx?|xlsx?|pptx?|ppsx?|rtf|odt|ods|odp|wps|et|dps)$/.test(name)) {
      base = '正在转换为可预览格式（首次约需 3~15 秒）…'
    } else if (mime.startsWith('video/')) {
      base = '正在准备视频…'
    }
    // 超过预期还没好，主动解释：网络慢或文件大，避免用户误以为卡死
    if (elapsed >= 10) return `${base}已等待 ${elapsed} 秒，文件较大或网络较慢，请继续等待…`
    if (elapsed >= 4) return `${base}已等待 ${elapsed} 秒`
    return base
  }

  const isPDF = type === 'application/pdf'

  async function onDownload() {
    if (!meta) return
    try {
      await downloadNode(meta.id, meta.name)
    } catch {
      setError('下载失败或没有下载权限')
    }
  }

  const head = (
    <>
      <span className="ftype" style={{ width: 30, height: 30, flex: 'none' }}>
        <Icon name={type.startsWith('image/') ? 'file' : type.startsWith('video/') || type.startsWith('audio/') ? 'play' : 'file'} size={16} />
      </span>
      <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        <Tooltip content={<><b>{meta?.name ?? '预览'}</b><div className="tip-note">独立地址：可刷新、可同时开多个、可贴进工单。</div></>}>
          <strong style={{ fontSize: 14, maxWidth: '48vw', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {meta?.name ?? '预览'}
          </strong>
        </Tooltip>
        <span className="hint" style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {meta && <>{fmtSize(meta.size)} · v{meta.versionNo ?? 1}</>}
          {meta?.updatedBy?.name && <><span className="dim">·</span>最近编辑 {meta.updatedBy.name} {relTime(meta.updatedAt ?? '')}</>}
          {isPDF && <span className="badge teal" style={{ height: 17 }}>溯源水印</span>}
        </span>
      </div>
    </>
  )

  return (
    <div className="viewer">
      <header className="viewer-bar">
        {head}
        <div className="grow" />
        {isPDF && (
          <div className="seg" role="group" aria-label="缩放">
            {ZOOM_OPTIONS.map((o) => (
              <button key={String(o.key)} className={zoom === o.key ? 'on' : ''} onClick={() => setZoom(o.key)}>
                {o.label}
              </button>
            ))}
          </div>
        )}
        {meta && (
          <Tooltip content={<><b>下载原件</b><div className="tip-note">水印只叠加在预览产物上；下载原件需要 download 权限，且会写审计。</div></>}>
            <button onClick={onDownload}><Icon name="download" size={15} /> 下载原件</button>
          </Tooltip>
        )}
        <button className="ghost" onClick={() => window.close()}><Icon name="close" size={15} /> 关闭</button>
      </header>

      <div className="viewer-body">
        {loading && (
          <div className="viewer-state">
            <div className="spinner" />
            <div style={{ fontSize: 14, color: 'var(--ink)', fontWeight: 500 }}>{loadingHint()}</div>
            <div className="hint" style={{ maxWidth: '46ch' }}>
              首次打开慢格式（Office 转换、RAW 解码、HEIC 解码）是正常现象；命中缓存后是百毫秒级。
            </div>
          </div>
        )}

        {!loading && error && (
          <div className="viewer-state">
            <div className="empty-art"><Icon name="alert" size={26} /></div>
            <div style={{ fontSize: 15, color: 'var(--ink)', fontWeight: 600 }}>{error}</div>
            <div className="hint" style={{ maxWidth: '46ch' }}>
              系统对无权限的对象统一返回"不存在"，避免泄露文件是否存在。若确认应有权限，请联系文件所有者。
            </div>
            <div className="row-gap" style={{ marginTop: 4 }}>
              {meta && <button className="primary" onClick={onDownload}><Icon name="download" size={15} /> 下载原件</button>}
              <button onClick={() => window.close()}>关闭页签</button>
            </div>
          </div>
        )}

        {!loading && !error && text && (
          <div className="viewer-sheet">
            <pre className="preview-text" style={{ margin: 0, maxHeight: 'none' }}>{text}</pre>
          </div>
        )}

        {!loading && !error && url && type.startsWith('image/') && (
          <div className="viewer-canvas">
            <img src={url} alt={meta?.name ?? ''} style={{ maxWidth: '100%', boxShadow: 'var(--shadow-2)', borderRadius: 4 }} />
          </div>
        )}

        {!loading && !error && url && isPDF && (
          <iframe key={String(zoom)} title="预览" src={pdfSrc(url, zoom)} className="viewer-frame" />
        )}

        {!loading && !error && url && (type.startsWith('video/') || type.startsWith('audio/')) && (
          <div className="viewer-canvas">
            {type.startsWith('video/')
              ? <video src={url} controls autoPlay style={{ maxWidth: 'min(1100px, 100%)', borderRadius: 8, boxShadow: 'var(--shadow-2)' }} />
              : <audio src={url} controls autoPlay style={{ width: 'min(640px, 100%)' }} />}
          </div>
        )}

        {!loading && !error && url && !isPDF && !type.startsWith('image/') &&
          !type.startsWith('video/') && !type.startsWith('audio/') && (
          <div className="viewer-state">
            <div className="empty-art"><Icon name="file" size={26} /></div>
            <div style={{ fontSize: 15, color: 'var(--ink)', fontWeight: 600 }}>这个格式不支持在浏览器内显示</div>
            <div className="hint" style={{ maxWidth: '48ch' }}>
              压缩包、邮件、CAD、HTML 等格式只能下载后本地查看。HTML 刻意不在线渲染，避免同源脚本风险。
            </div>
            <button className="primary" onClick={onDownload}><Icon name="download" size={15} /> 下载原件</button>
          </div>
        )}
      </div>

      <footer className="viewer-foot">
        <span><Icon name="lock" size={12} /> 本次预览已记入审计{meta?.updatedAt ? ` · 文件更新于 ${absTime(meta.updatedAt)}` : ''}</span>
        <div className="grow" />
        <span className="dim">NeuroDMS</span>
      </footer>
    </div>
  )
}
