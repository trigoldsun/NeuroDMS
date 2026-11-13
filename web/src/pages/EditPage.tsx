import { useEffect, useState } from 'react'
import { api, HttpError } from '../api'

type EditConfig = {
  documentServerUrl: string
  config: Record<string, unknown>
  mode: string
}

declare global {
  interface Window {
    DocsAPI?: { DocEditor: new (id: string, cfg: Record<string, unknown>) => unknown }
  }
}

// 在线编辑页：加载文档服务提供的 api.js，用它给的回调配置实例化编辑器。
//
// 安全要点（都在服务端做，这里只负责不绕过）：
//   - 配置里的 JWT 由服务端签发，前端无法伪造
//   - 文档下载地址是短时签名 URL，不含用户令牌
//   - 保存走文档服务回调，前端拿不到写权限
export default function EditPage({ nodeId }: { nodeId: string }) {
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  // 编辑器慢在"三件事叠加"：后端签发配置、下载 api.js、文档服务自身加载文档。
  // 首次打开常要 5~15 秒，只写"正在打开编辑器…"用户会以为没有响应。
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!loading) {
      setElapsed(0)
      return
    }
    const t = window.setInterval(() => setElapsed((n) => n + 1), 1000)
    return () => window.clearInterval(t)
  }, [loading])

  useEffect(() => {
    let cancelled = false
    let script: HTMLScriptElement | null = null

    ;(async () => {
      try {
        const data = await api<EditConfig>(`/v1/nodes/${encodeURIComponent(nodeId)}/edit?mode=edit`)
        if (cancelled) return

        // 同一页面只允许一个 api.js
        script = document.createElement('script')
        script.src = `${data.documentServerUrl.replace(/\/$/, '')}/web-apps/apps/api/documents/api.js`
        script.async = true
        script.onload = () => {
          if (cancelled) return
          if (!window.DocsAPI) {
            setError('文档服务脚本加载完成但未提供 DocsAPI')
            setLoading(false)
            return
          }
          try {
            new window.DocsAPI.DocEditor('dv-editor', data.config)
            setLoading(false)
          } catch (e) {
            setError(e instanceof Error ? e.message : '初始化编辑器失败')
            setLoading(false)
          }
        }
        script.onerror = () => {
          if (cancelled) return
          setError('无法加载文档服务脚本，请确认 ONLYOFFICE 地址可访问')
          setLoading(false)
        }
        document.body.appendChild(script)
      } catch (err) {
        if (cancelled) return
        if (err instanceof HttpError && err.status === 501) {
          setError('该部署未启用在线编辑')
        } else if (err instanceof HttpError && err.status === 403) {
          setError('没有编辑权限')
        } else {
          setError(err instanceof HttpError ? err.message : '打开编辑器失败')
        }
        setLoading(false)
      }
    })()

    return () => {
      cancelled = true
      script?.remove()
    }
  }, [nodeId])

  return (
    <div className="editor-page">
      <div className="toolbar">
        <strong>在线编辑</strong>
        <div className="spacer" />
        <button className="ghost" onClick={() => location.assign('/files')}>返回文件列表</button>
      </div>
      {loading && (
        <div className="hint" style={{ padding: 16 }}>
          {elapsed >= 10
            ? `正在打开编辑器…已等待 ${elapsed} 秒。文档服务首次加载较慢，请继续等待。`
            : elapsed >= 4
              ? `正在打开编辑器…已等待 ${elapsed} 秒`
              : '正在打开编辑器…（首次加载约需 5~15 秒）'}
        </div>
      )}
      {error && <div className="card error" style={{ margin: 16 }}>{error}</div>}
      <div id="dv-editor" style={{ height: 'calc(100vh - 52px)' }} />
    </div>
  )
}
