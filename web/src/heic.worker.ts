// HEIC 解码 Worker。
//
// 为什么必须离开主线程：一张 4284×5712 的 iPhone 照片，
// libheif 的 display() 是**同步阻塞**的 wasm 调用，实测约 10 秒。
// 放在主线程的后果是页面整整卡死十秒——转圈不动、按钮点不了、
// 用户以为浏览器崩了。放进 Worker 后主线程只等消息，界面全程可交互。
//
// 通信只传 ArrayBuffer（transferable，零拷贝），不传像素：
// 24M 像素的 RGBA 是 98MB，跨线程结构化克隆会直接把内存翻一倍。

import libheif from 'libheif-js/wasm-bundle'

type HeifImage = {
  get_width(): number
  get_height(): number
  display(target: ImageData, cb: (result: ImageData | null) => void): void
}
type LibHeif = { HeifDecoder: new () => { decode(d: Uint8Array): HeifImage[] } }

const MAX_PIXELS = 60_000_000

self.onmessage = async (e: MessageEvent<{ id: number; buf: ArrayBuffer; maxEdge: number; quality: number }>) => {
  const { id, buf, maxEdge, quality } = e.data
  try {
    const lib = (libheif as unknown) as LibHeif
    const decoder = new lib.HeifDecoder()
    const images = decoder.decode(new Uint8Array(buf))
    if (!images || images.length === 0) {
      throw new Error('无法解码 HEIC 图像（可能是不受支持的编码）')
    }
    const img = images[0]
    const w = img.get_width()
    const h = img.get_height()
    if (!w || !h) throw new Error('HEIC 图像尺寸无效')
    if (w * h > MAX_PIXELS) {
      throw new Error(`图片分辨率过高（${w}×${h}），请下载原件后本地查看`)
    }

    // display 的目标缓冲区必须是原始尺寸：尺寸不符会在 wasm 里越界，
    // 而且异常发生在回调内部，外层永远等不到结果。
    const full = new ImageData(w, h)
    await new Promise<void>((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => {
        if (!settled) reject(new Error('HEIC 解码超时，请下载原件查看'))
      }, 60_000)
      img.display(full, () => {
        settled = true
        clearTimeout(timer)
        resolve()
      })
    })

    const src = new OffscreenCanvas(w, h)
    const sctx = src.getContext('2d')
    if (!sctx) throw new Error('浏览器不支持 OffscreenCanvas')
    sctx.putImageData(full, 0, 0)

    const scale = Math.min(1, maxEdge / Math.max(w, h))
    const dw = Math.max(1, Math.round(w * scale))
    const dh = Math.max(1, Math.round(h * scale))
    const out = new OffscreenCanvas(dw, dh)
    const octx = out.getContext('2d')
    if (!octx) throw new Error('浏览器不支持 OffscreenCanvas')
    octx.imageSmoothingQuality = 'high'
    octx.drawImage(src, 0, 0, w, h, 0, 0, dw, dh)

    const blob = await out.convertToBlob({ type: 'image/jpeg', quality })
    const data = await blob.arrayBuffer()
    ;(self as unknown as Worker).postMessage(
      { id, ok: true, data, w: dw, h: dh },
      [data],
    )
  } catch (err) {
    ;(self as unknown as Worker).postMessage({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    })
  }
}
