import { useEffect, useRef, useState } from 'react'
import { getDocument, GlobalWorkerOptions } from 'pdfjs-dist'
import workerSrc from 'pdfjs-dist/build/pdf.worker.min.mjs?url'

// PDF 画布渲染器（外链访客用）。
//
// 为什么不用 <iframe src="xxx.pdf">：浏览器自带的 PDF 阅读器工具栏里有
// 「下载」和「打印」两个按钮——那等于在"不允许下载"的分享页上开了一扇正门。
// 之前只读分享仍能下载，根因就在这里（接口层拦了 403，但呈现层把字节交给了阅读器）。
//
// 现在用 pdf.js 把每一页画到 canvas 上：
//   - 页面上没有工具栏，也没有指向原始 PDF 的可点击链接；
//   - 不生成文本层（不能全选复制）；
//   - 打印/另存入口完全由外层按分享策略决定。
//
// 诚实边界：字节最终仍在浏览器里，截图、开发者工具、录屏无法被前端阻止。
// 真正需要"绝对不可带走"的场景只能不外发，或依赖水印 + 审计做追溯。

GlobalWorkerOptions.workerSrc = workerSrc

// 单次最多渲染的页数：几百页的 PDF 一次性铺 canvas 会把标签页卡死。
// 超出的部分明确提示"其余页请联系分享人"，而不是静默截断。
const MAX_RENDER_PAGES = 80

export default function PdfCanvasViewer({
  url,
  scale,
  fit,
  onMeta,
}: {
  url: string
  // scale: 1 = 100%（按 96dpi 估算）
  scale: number
  // fit: 按容器宽度自适应（忽略 scale）
  fit: boolean
  onMeta?: (pages: number, truncated: boolean) => void
}) {
  const pagesRef = useRef<HTMLDivElement>(null)
  const metaRef = useRef(onMeta)
  metaRef.current = onMeta
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [truncated, setTruncated] = useState(false)

  useEffect(() => {
    let cancelled = false
    const box = pagesRef.current
    if (!box) return

    setLoading(true)
    setError('')
    // 用 innerHTML 清空是安全的：这个容器只由本组件写入，没有 React 子节点
    box.innerHTML = ''

    // pdf.js 默认不使用 eval 编译字体，CSP 无需放开 unsafe-eval（与全局策略一致）
    const task = getDocument({ url })
    void (async () => {
      try {
        const doc = await task.promise
        if (cancelled) return
        const renderCount = Math.min(doc.numPages, MAX_RENDER_PAGES)
        setTotal(doc.numPages)
        setTruncated(doc.numPages > renderCount)
        metaRef.current?.(doc.numPages, doc.numPages > renderCount)

        const first = await doc.getPage(1)
        const avail = box.clientWidth || 720
        const fitScale = avail / first.getViewport({ scale: 1 }).width
        const dpr = Math.min(window.devicePixelRatio || 1, 2)

        for (let i = 1; i <= renderCount; i++) {
          if (cancelled) return
          const page = i === 1 ? first : await doc.getPage(i)
          const vp = page.getViewport({ scale: fit ? fitScale : scale })
          const canvas = document.createElement('canvas')
          canvas.className = 'pdf-page'
          canvas.width = Math.floor(vp.width * dpr)
          canvas.height = Math.floor(vp.height * dpr)
          canvas.style.width = `${vp.width}px`
          canvas.style.height = `${vp.height}px`
          box.appendChild(canvas)
          await page.render({
            canvas,
            viewport: vp,
            transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : undefined,
          }).promise
          // 让出一帧，避免长文档渲染期间界面完全无响应
          await new Promise((r) => setTimeout(r, 0))
        }
        if (!cancelled) setLoading(false)
      } catch (e) {
        if (cancelled) return
        setLoading(false)
        setError(e instanceof Error ? e.message : '文档渲染失败')
      }
    })()

    return () => {
      cancelled = true
      void task.destroy()
    }
  }, [url, scale, fit])

  return (
    <div className="pdf-viewer">
      {loading && <div className="pdf-hint">正在渲染…{total > 0 ? `（共 ${total} 页）` : ''}</div>}
      {error && <div className="error">文档渲染失败：{error}（可刷新重试或联系分享人）</div>}
      <div ref={pagesRef} className="pdf-pages" />
      {truncated && (
        <div className="pdf-hint">
          仅显示前 {MAX_RENDER_PAGES} 页（共 {total} 页），其余请联系分享人。
        </div>
      )}
    </div>
  )
}
