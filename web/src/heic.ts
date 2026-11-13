// HEIC/HEIF 预览解码。
//
// 为什么放在前端而不是服务端：
//   试过服务端方案——alpine 的 ffmpeg 只带 avif 不带 heic，imagemagick 没编 libheif
//   delegate，libheif 包只有 .so 没有命令行工具。要服务端解码就得自己编带 libheif 的
//   ffmpeg，镜像体积和构建复杂度都上一个台阶，而且只为一类图片。
//   wasm 方案把成本放在"第一次预览 HEIC 时下载一个按需 chunk"，其余格式完全不受影响。
//
// 为什么不用 <img src> 直接显示：
//   只有 Safari 能解 HEIC。Chrome/Edge/Firefox 会显示破图，而且不报错——
//   用户看到的是空白，比"不支持"更让人困惑。
//
// 为什么解码跑在 Worker 里：见 heic.worker.ts 的注释（单张 iPhone 照片约 10 秒，
//   放在主线程会整个页面卡死）。
//
// 注意：只影响**预览**。原文件保持原样上传、原样下载，不做有损转存。

export function isHeic(mime: string, name: string): boolean {
  const m = (mime || '').toLowerCase()
  if (m === 'image/heic' || m === 'image/heif' || m === 'image/heic-sequence' ||
    m === 'image/heif-sequence') {
    return true
  }
  // 上传时 DetectContentType 对 HEIC 常给 application/octet-stream，只能看扩展名
  const n = (name || '').toLowerCase()
  return n.endsWith('.heic') || n.endsWith('.heif')
}

type WorkerReply =
  | { id: number; ok: true; data: ArrayBuffer; w: number; h: number }
  | { id: number; ok: false; error: string }

let worker: Worker | null = null
let seq = 0

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./heic.worker.ts', import.meta.url), { type: 'module' })
  }
  return worker
}

/**
 * 把 HEIC 字节解码成 JPEG Blob（用于 <img> 显示）。
 * maxEdge 是输出图的最长边：iPhone 原图 4284×5712 直接进 canvas 很吃内存，
 * 预览不需要那么大的分辨率。
 */
export function heicToJpeg(buf: ArrayBuffer, maxEdge = 2400, quality = 0.9): Promise<Blob> {
  return new Promise<Blob>((resolve, reject) => {
    let w: Worker
    try {
      w = getWorker()
    } catch (e) {
      reject(e instanceof Error ? e : new Error('无法启动 HEIC 解码线程'))
      return
    }
    const id = ++seq
    let done = false
    const finish = (fn: () => void) => {
      if (done) return
      done = true
      w.removeEventListener('message', onMessage)
      fn()
    }
    const onMessage = (e: MessageEvent<WorkerReply>) => {
      const msg = e.data
      if (!msg || msg.id !== id) return
      if (msg.ok) {
        finish(() => resolve(new Blob([msg.data], { type: 'image/jpeg' })))
      } else {
        finish(() => reject(new Error(msg.error || 'HEIC 解码失败')))
      }
    }
    w.addEventListener('message', onMessage)
    // 超时兜底：Worker 里的 wasm 若 abort，可能既不返回也不抛错
    setTimeout(() => finish(() => reject(new Error('HEIC 解码超时，请下载原件查看'))), 90_000)
    // transfer 而不是复制：像素数据复制一遍会直接把内存翻倍
    w.postMessage({ id, buf, maxEdge, quality }, [buf])
  })
}
