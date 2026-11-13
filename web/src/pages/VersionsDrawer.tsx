import { useCallback, useEffect, useState } from 'react'
import { api, downloadVersion, postJSON, HttpError } from '../api'

type VersionItem = {
  versionNo: number
  sizeBytes: number
  sha256: string
  state: string
  origin: string
  restoredFromNo: number | null
  createdBy: string
  note: string
  createdAt: string
  isCurrent: boolean
  isEffective: boolean
}

// 版本抽屉：列出历史版本，支持"下载此版本"与"回退到此版本"。
//
// 回退在服务端是追加一个新版本（不是切换指针），所以这里要明确告诉用户
// "会生成新版本"，否则他会以为版本号会倒退回去。
export default function VersionsDrawer({
  node,
  onClose,
  onChanged,
}: {
  node: { id: string; name: string }
  onClose: () => void
  onChanged: () => void
}) {
  const [items, setItems] = useState<VersionItem[]>([])
  const [keep, setKeep] = useState(10)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [flash, setFlash] = useState('')
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState(0)

  const load = useCallback(async () => {
    try {
      const [vs, ds] = await Promise.all([
        api<{ items: VersionItem[]; retention?: { keepVersions: number } }>(
          `/v1/nodes/${node.id}/versions`,
        ),
        api<{ count: number }>(`/v1/nodes/${node.id}/doc-session`).catch(() => ({ count: 0 })),
      ])
      setItems(vs.items)
      if (vs.retention?.keepVersions) setKeep(vs.retention.keepVersions)
      setEditing(ds.count)
      setError('')
    } catch (err) {
      setError(err instanceof HttpError ? err.message : '读取版本失败')
    } finally {
      setLoading(false)
    }
  }, [node.id])

  useEffect(() => {
    void load()
  }, [load])

  async function restore(no: number) {
    const tip = [
      `将生成新版本（内容与 v${no} 相同，不占用额外空间）。`,
      '文件密级、共享链接与权限不会随之改变。',
      '已发出的分享链接会立即显示该版本的内容。',
    ].join('\n')
    if (!window.confirm(tip)) return

    setBusy(true)
    setError('')
    try {
      await postJSON(`/v1/nodes/${node.id}/versions/${no}/restore`, {})
      setFlash(`已回退到 v${no} 的内容`)
      await load()
      onChanged()
    } catch (err) {
      // 服务端已经把各种拒绝原因写成了可读文案（正在编辑、内容相同、内容丢失…），
      // 直接显示比在前端再映射一遍更准确。
      setError(err instanceof HttpError ? err.message : '回退失败')
    } finally {
      setBusy(false)
    }
  }

  function originText(v: VersionItem): string {
    if (v.origin === 'restore') return v.restoredFromNo ? `回退自 v${v.restoredFromNo}` : '回退'
    if (v.origin === 'edit') return '在线编辑'
    return '上传'
  }

  function fmtSize(n: number): string {
    if (n < 1024) return `${n} B`
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
  }

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="版本管理">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <h2>版本管理</h2>
          <span className="pill">{node.name}</span>
          <div style={{ flex: 1 }} />
          <button className="ghost" onClick={onClose}>关闭</button>
        </div>

        {editing > 0 && (
          <div className="card" style={{ borderColor: 'var(--warn, #b8860b)' }}>
            <strong>文件正在被编辑</strong>
            <div style={{ fontSize: 12, color: 'var(--muted)' }}>
              {editing} 个编辑会话进行中。回退会被拒绝，以免对方保存时覆盖回退结果。
              等对方关闭编辑窗口（约 10 分钟无操作）后再试。
            </div>
          </div>
        )}

        {flash && <div className="card" role="status">{flash}</div>}
        {error && <div className="error" role="alert">{error}</div>}

        <div className="card">
          {loading ? (
            <div className="empty">载入中…</div>
          ) : items.length === 0 ? (
            <div className="empty">暂无版本</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th style={{ width: 70 }}>版本</th>
                  <th style={{ width: 90 }}>大小</th>
                  <th>来源</th>
                  <th style={{ width: 150 }}>时间</th>
                  <th style={{ width: 140 }} />
                </tr>
              </thead>
              <tbody>
                {items.map((v) => (
                  <tr key={v.versionNo}>
                    <td>
                      v{v.versionNo}
                      {v.isCurrent && <span className="pill" style={{ marginLeft: 6 }}>当前</span>}
                    </td>
                    <td>{fmtSize(v.sizeBytes)}</td>
                    <td>{originText(v)}</td>
                    <td>{new Date(v.createdAt).toLocaleString()}</td>
                    <td className="actions">
                      <button
                        className="ghost"
                        onClick={() =>
                          downloadVersion(node.id, v.versionNo, node.name).catch(() =>
                            setError('下载失败或无权限'),
                          )
                        }
                      >
                        下载
                      </button>
                      <button
                        className="ghost"
                        disabled={busy || v.isCurrent || editing > 0}
                        onClick={() => void restore(v.versionNo)}
                        title={v.isCurrent ? '已是当前版本' : editing > 0 ? '文件正在编辑' : '回退到此版本'}
                      >
                        回退
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p style={{ fontSize: 12, color: 'var(--muted)' }}>
          回退会追加一个新版本（内容取自历史版本），不会改写历史记录。
          每个文件保留最近 <strong>{keep}</strong> 个版本
          {items.length >= keep && '（已达上限，再保存会清理更早的版本）'}；
          如需长期留存，请下载或联系管理员调整保留数量。
        </p>
      </aside>
    </>
  )
}
