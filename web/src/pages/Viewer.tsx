import { useEffect, useRef, useState } from 'react'
import { getAccess } from '../api'

// hls.js 只用在非 Safari 的播放场景，且体积较大（约 500KB）。
// 静态引入会让所有页面（包括只登录看列表的人）都下载它，
// 因此改成按需动态加载——这也是 bundle 从 826KB 回落到合理体积的原因。

type Target = { id: string; name: string; mime: string }

// 音视频走 /media：服务端转 HLS（源片达标时只 remux，秒级完成）。
// 首次请求可能返回 202（正在转码），所以这里要轮询。
export function MediaModal({ target, onClose }: { target: Target; onClose: () => void }) {
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const [status, setStatus] = useState<'preparing' | 'ready' | 'failed'>('preparing')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    let cancelled = false
    let timer = 0
    let hls: { destroy: () => void } | null = null

    const attach = async (playlistUrl: string) => {
      const el = videoRef.current
      if (!el) return
      // Safari 原生支持 HLS；Chrome/Firefox 需要 hls.js
      if (el.canPlayType('application/vnd.apple.mpegurl')) {
        el.src = playlistUrl
        void el.play().catch(() => undefined)
        return
      }
      const mod = await import('hls.js')
      if (cancelled) return
      const Hls = mod.default
      if (!Hls.isSupported()) {
        setStatus('failed')
        setMsg('当前浏览器不支持 HLS 播放，请下载后观看')
        return
      }
      const instance = new Hls({ maxBufferLength: 30 })
      hls = instance
      instance.loadSource(playlistUrl)
      instance.attachMedia(el)
      instance.on(Hls.Events.MANIFEST_PARSED, () => { void el.play().catch(() => undefined) })
      instance.on(Hls.Events.ERROR, (_e: unknown, data: { fatal: boolean }) => {
        if (data.fatal) {
          setStatus('failed')
          setMsg('播放失败，请稍后重试或下载观看')
        }
      })
    }

    const poll = async () => {
      try {
        const resp = await fetch(`/v1/nodes/${target.id}/media`, {
          headers: { Authorization: `Bearer ${getAccess()}` },
        })
        const body = await resp.json().catch(() => ({}))
        if (cancelled) return

        if (resp.status === 202) {
          setStatus('preparing')
          timer = window.setTimeout(poll, 3000)
          return
        }
        if (resp.status === 501) {
          setStatus('failed')
          setMsg('服务端未启用转码（缺少 ffmpeg），请下载后观看')
          return
        }
        if (!resp.ok) {
          setStatus('failed')
          setMsg(body?.message ?? '无法播放')
          return
        }
        setStatus('ready')
        void attach(body.data.playlistUrl as string)
      } catch {
        if (!cancelled) {
          setStatus('failed')
          setMsg('网络异常')
        }
      }
    }
    void poll()

    return () => {
      cancelled = true
      window.clearTimeout(timer)
      hls?.destroy()
    }
  }, [target.id])

  // Esc 关闭：预览是全屏弹窗，没有键盘出口会逼用户去点右上角
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <strong>{target.name}</strong>
          {status === 'preparing' && <span className="badge warn">转码中</span>}
          <div className="spacer" />
          <span className="hint">Esc 关闭</span>
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>
        <div className="modal-body">
          {status === 'preparing' && <div className="hint">正在准备播放（转码中），请稍候…</div>}
          {status === 'failed' && <div className="error">{msg}</div>}
          <video ref={videoRef} controls style={{ width: '100%', display: status === 'ready' ? 'block' : 'none' }} />
        </div>
      </div>
    </div>
  )
}
