// 品牌图标（左上角产品图标）上传字段。
//
// 设计要点：
//  1. **先本地校验再提交**：格式/体积/像素三条都在选文件时判掉，
//     而不是等保存后收到一句"保存品牌失败"——管理员不知道是哪一项超了。
//  2. 尺寸直接读出来给管理员看（"当前 128×128"），规则才可自查；
//     只说"建议 128px 以上"等于让人自己猜。
//  3. 图标会渲染到**未登录可见**的登录页与分享页，所以 SVG 在前端也挡一次脚本，
//     不只依赖服务端（服务端同样挡，两层是刻意的）。
//  4. 不改动已有图标：没选新文件、也没点移除时，保存请求里**不带** logo 字段。
//     后端据此保留原值（早期它会因为字段为空而被清空，见 docs/54）。

import { useRef, useState } from 'react'

export type LogoDraft = {
  dataUrl: string
  mime: string
  bytes: number
  // SVG 是矢量的，没有 naturalWidth；有值时用于展示与校验
  w?: number
  h?: number
}

const MAX_BYTES = 256 * 1024
const MIN_PX = 16
const MAX_PX = 4096
// 界面上的实际显示尺寸（侧栏 30px、登录页 40px）。2 倍屏要清晰 → 建议 ≥96。
const SUGGEST_PX = 128

const MIME_BY_EXT: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  svg: 'image/svg+xml',
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`
}

function readDataURL(f: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(String(fr.result ?? ''))
    fr.onerror = () => reject(new Error('读取文件失败'))
    fr.readAsDataURL(f)
  })
}

function readImageSize(dataUrl: string): Promise<{ w: number; h: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => resolve({ w: img.naturalWidth, h: img.naturalHeight })
    img.onerror = () => reject(new Error('图片无法解码，可能已损坏'))
    img.src = dataUrl
  })
}

export function BrandLogoField(props: {
  currentUrl?: string
  draft: LogoDraft | null
  removing: boolean
  onChange: (d: LogoDraft | null) => void
  onRemove: () => void
  onUndoRemove: () => void
  error: string
  onError: (msg: string) => void
  disabled?: boolean
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)

  const previewUrl = props.draft?.dataUrl ?? (props.removing ? '' : props.currentUrl ?? '')

  async function pick(f: File) {
    const { onError, onChange } = props
    onError('')
    setBusy(true)
    try {
      // 1) 格式：file.type 在拖拽/改扩展名时可能是空串，用扩展名兜底
      const ext = (f.name.split('.').pop() ?? '').toLowerCase()
      const mime = f.type || MIME_BY_EXT[ext] || ''
      if (!MIME_BY_EXT[ext] && !Object.values(MIME_BY_EXT).includes(mime)) {
        onError('仅支持 PNG / JPEG / WebP / SVG 四种格式')
        return
      }
      const finalMime = Object.values(MIME_BY_EXT).includes(mime) ? mime : MIME_BY_EXT[ext]

      // 2) 体积（与数据库约束、服务端上限一致）
      if (f.size > MAX_BYTES) {
        onError(`文件 ${fmtBytes(f.size)}，超过 ${fmtBytes(MAX_BYTES)} 上限。请压缩后再上传。`)
        return
      }

      const dataUrl = await readDataURL(f)

      // 3) SVG：矢量，无像素；但要挡脚本（会渲染到未登录页面）
      if (finalMime === 'image/svg+xml') {
        const text = atob(dataUrl.split(',')[1] ?? '')
        if (/<script|javascript:|onload\s*=|onerror\s*=/i.test(text)) {
          onError('SVG 里包含脚本或事件属性，出于安全已拒绝。请导出为纯图形 SVG。')
          return
        }
        if (!/<svg[\s>]/i.test(text)) {
          onError('这个文件不像 SVG（缺少 <svg> 根元素）')
          return
        }
        onChange({ dataUrl, mime: finalMime, bytes: f.size })
        return
      }

      // 4) 位图：读真实像素，太小会糊、太大是白占内存
      const { w, h } = await readImageSize(dataUrl)
      if (w < MIN_PX || h < MIN_PX) {
        onError(`图片只有 ${w}×${h} 像素，小于 ${MIN_PX}×${MIN_PX}。放到左上角会明显发虚。`)
        return
      }
      if (w > MAX_PX || h > MAX_PX) {
        onError(`图片 ${w}×${h}，最长边超过 ${MAX_PX} 像素。这个图标最大只显示 40px，请缩小后再传。`)
        return
      }
      onChange({ dataUrl, mime: finalMime, bytes: f.size, w, h })
    } catch (e) {
      onError(e instanceof Error ? e.message : '读取图片失败')
    } finally {
      setBusy(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const dim = props.draft?.w && props.draft?.h ? `${props.draft.w}×${props.draft.h}` : '矢量'
  const square = props.draft?.w && props.draft?.h ? props.draft.w === props.draft.h : true

  return (
    <div>
      <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        {/* 预览：与左上角的实际显示保持一致的白底 + 细边，避免"预览好看、上线难看" */}
        <div
          style={{
            width: 72, height: 72, flex: '0 0 72px',
            border: '1px solid var(--line)', borderRadius: 10,
            background: 'var(--surface-2)',
            display: 'grid', placeItems: 'center', overflow: 'hidden',
          }}
          aria-label="图标预览"
        >
          {previewUrl ? (
            <img
              src={previewUrl} alt=""
              style={{ maxWidth: 56, maxHeight: 56, objectFit: 'contain' }}
            />
          ) : (
            <span style={{ fontSize: 11, color: 'var(--mist)' }}>未上传</span>
          )}
        </div>

        <div style={{ flex: 1, minWidth: 240 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/svg+xml,.png,.jpg,.jpeg,.webp,.svg"
              style={{ display: 'none' }}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) void pick(f)
              }}
            />
            <button
              type="button"
              disabled={props.disabled || busy}
              onClick={() => fileRef.current?.click()}
            >
              {busy ? '读取中…' : previewUrl ? '更换图标' : '选择图片'}
            </button>
            {previewUrl && !props.disabled && (
              <button type="button" className="ghost" onClick={props.onRemove}>
                移除
              </button>
            )}
            {props.removing && (
              <button type="button" className="ghost" onClick={props.onUndoRemove}>
                撤销移除
              </button>
            )}
            {props.draft && (
              <span className="hint">
                {dim} · {fmtBytes(props.draft.bytes)}
                {props.draft.w && !square && ' · 不是正方形，显示时会按比例留白'}
                {props.draft.w && square && props.draft.w < SUGGEST_PX && ' · 建议 ≥128×128'}
              </span>
            )}
          </div>

          {props.error && (
            <div className="error-text" style={{ marginTop: 6 }} role="alert">{props.error}</div>
          )}

          <div className="hint" style={{ marginTop: 8, lineHeight: 1.75 }}>
            <b>格式</b>：PNG / JPEG / WebP / SVG（有透明背景请用 PNG 或 SVG）。
            <br />
            <b>分辨率</b>：正方形，建议 <b>128×128</b> 或更大（最大 4096×4096，最小 {MIN_PX}×{MIN_PX}）；
            文件不超过 <b>256KB</b>。
            <br />
            <b>显示位置</b>：登录后左上角（30px）、登录页（40px）。深色底上也能看清的话，建议图标本身带浅色或透明背景。
          </div>
        </div>
      </div>
    </div>
  )
}
