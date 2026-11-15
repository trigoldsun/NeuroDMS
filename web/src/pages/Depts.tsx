import { useCallback, useEffect, useMemo, useState } from 'react'
import { Icon } from '../components/ui'
import { api, del, patchJSON, postJSON } from '../api'

// 部门树管理（E2E 验收 F-03）。
//
// 为什么需要这一页：部门是 ACL 的授权主体（`subjectType=dept` 按路径命中整棵子树），
// 但原先只有目录同步会写它。不接 AD 的租户只有一个「总部」，
// "按部门管权限"这个卖点等于用不上。
//
// 三条界面约定：
//  1. 目录同步来的部门（`directory=true`）不提供改名/移动/删除——
//     下次同步会把它建回来，或者与 AD 里的名字打架。按钮禁用并说明原因。
//  2. 有占用（子部门/成员/空间）时不允许删除，提示里给出数量：
//     "先把这 3 个人挪走"比"不能删除"有用。
//  3. 改名不动路径（服务端保证），所以界面上也不提示"路径会变"——
//     路径是 ACL 的匹配依据，改名重写整棵子树代价太大。

type Dept = {
  id: string
  name: string
  parentId: string | null
  path: string
  depth: number
  sort: number
  directory: boolean
  memberCount: number
  spaceCount: number
}

export default function Depts({ canWrite, flash }: { canWrite: boolean; flash: (m: string) => void }) {
  const [items, setItems] = useState<Dept[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')

  const load = useCallback(async () => {
    setErr('')
    try {
      const r = await api<{ items: Dept[] }>('/v1/admin/depts')
      setItems(r.items ?? [])
    } catch (e) {
      setErr(e instanceof Error ? e.message : '读取部门失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  // 新建 / 改名的弹窗状态。两者共用一个表单：字段都只有"名字 + 上级"，
  // 分成两个弹窗会让"改上级"变成另一个入口，用户还得记两条路径。
  const [dialog, setDialog] = useState<
    | { mode: 'create'; parentId: string }
    | { mode: 'rename'; target: Dept }
    | { mode: 'move'; target: Dept }
    | null
  >(null)
  const [name, setName] = useState('')
  const [parentId, setParentId] = useState('')
  const [dialogErr, setDialogErr] = useState('')

  function openCreate(p: string) {
    setDialog({ mode: 'create', parentId: p })
    setName('')
    setParentId(p)
    setDialogErr('')
  }
  function openRename(d: Dept) {
    setDialog({ mode: 'rename', target: d })
    setName(d.name)
    setDialogErr('')
  }
  function openMove(d: Dept) {
    setDialog({ mode: 'move', target: d })
    setParentId(d.parentId ?? '')
    setDialogErr('')
  }

  async function submit(ev: React.FormEvent) {
    ev.preventDefault()
    if (!dialog) return
    setBusy('dialog')
    setDialogErr('')
    try {
      if (dialog.mode === 'create') {
        await postJSON('/v1/admin/depts', { name: name.trim(), parentId: parentId || undefined })
        flash(`已创建「${name.trim()}」`)
      } else if (dialog.mode === 'rename') {
        await patchJSON(`/v1/admin/depts/${dialog.target.id}`, { name: name.trim() })
        flash('已改名')
      } else {
        await postJSON(`/v1/admin/depts/${dialog.target.id}/move`, { parentId: parentId || undefined })
        flash('已移动（整棵子树跟着走）')
      }
      setDialog(null)
      await load()
    } catch (e) {
      setDialogErr(e instanceof Error ? e.message : '保存失败')
    } finally {
      setBusy('')
    }
  }

  const [confirmDel, setConfirmDel] = useState<Dept | null>(null)
  async function remove(d: Dept) {
    setBusy('del')
    setErr('')
    try {
      await del(`/v1/admin/depts/${d.id}`)
      flash(`已删除「${d.name}」`)
      setConfirmDel(null)
      await load()
    } catch (e) {
      // 占用类错误（有子部门/成员/空间）在这里原样显示，含数量
      setErr(e instanceof Error ? e.message : '删除失败')
      setConfirmDel(null)
    } finally {
      setBusy('')
    }
  }

  const roots = useMemo(() => items.filter((d) => !d.parentId), [items])
  const total = items.length

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="card pad" style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <div>
          <strong>部门（{total}）</strong>
          <div className="hint">
            部门是授权主体：在文件的「共享」里可以按部门授权，命中范围是<b>整棵子树</b>。
            来自目录同步的部门标有「目录」，需在 AD / LDAP 里维护。
          </div>
        </div>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="sm" onClick={() => void load()} disabled={loading}>
          <Icon name="history" size={14} /> 刷新
        </button>
        {canWrite && roots.length > 0 && (
          // 顶层不唯一时（目录同步可能造出多个根）仍允许新建：弹窗里必须选上级
          <button className="primary sm" onClick={() => openCreate(roots[0]?.id ?? '')}>
            <Icon name="plus" size={14} /> 新建部门
          </button>
        )}
      </div>

      {err && <div className="card pad error">{err}</div>}

      <div className="card">
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>部门</th>
                <th style={{ width: 90 }} className="tnum">成员</th>
                <th style={{ width: 90 }} className="tnum">空间</th>
                <th style={{ width: 110 }}>来源</th>
                <th style={{ width: 260 }} />
              </tr>
            </thead>
            <tbody>
              {items.map((d) => (
                <tr key={d.id}>
                  <td>
                    {/* 用 depth 缩进：扁平列表 + 缩进比嵌套表格更好做"行内操作" */}
                    <span style={{ display: 'inline-block', width: (d.depth - 1) * 18 }} />
                    <Icon name="folder" size={14} />
                    <span style={{ marginLeft: 6 }}>{d.name}</span>
                  </td>
                  <td className="tnum">{d.memberCount}</td>
                  <td className="tnum">{d.spaceCount}</td>
                  <td>
                    {d.directory
                      ? <span className="badge plain">目录同步</span>
                      : <span className="hint">手工</span>}
                  </td>
                  <td>
                    {canWrite && !d.directory && (
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <button className="sm ghost" onClick={() => openCreate(d.id)}>子部门</button>
                        <button className="sm ghost" onClick={() => openRename(d)}>改名</button>
                        <button className="sm ghost" onClick={() => openMove(d)}>移动</button>
                        <button
                          className="sm ghost danger"
                          disabled={busy === 'del'}
                          onClick={() => setConfirmDel(d)}
                        >
                          删除
                        </button>
                      </div>
                    )}
                    {canWrite && d.directory && <span className="hint">在目录里维护</span>}
                  </td>
                </tr>
              ))}
              {!loading && items.length === 0 && (
                <tr><td colSpan={5} className="hint">还没有部门</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {dialog && (
        <div className="modal-mask" onClick={() => setDialog(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 460 }}>
            <div className="modal-head">
              <strong>
                {dialog.mode === 'create' ? '新建部门'
                  : dialog.mode === 'rename' ? `改名：${dialog.target.name}`
                    : `移动：${dialog.target.name}`}
              </strong>
              <div className="spacer" />
              <button className="ghost" onClick={() => setDialog(null)}>关闭</button>
            </div>
            <form className="modal-body" onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
              {dialog.mode !== 'move' && (
                <div className="field">
                  <label>部门名称</label>
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    maxLength={64}
                    placeholder="例如：财务部"
                    required
                    autoFocus
                  />
                  <div className="hint">同级下不能重名；改名不会影响已授出的权限。</div>
                </div>
              )}
              {dialog.mode !== 'rename' && (
                <div className="field">
                  <label>上级部门</label>
                  <select value={parentId} onChange={(e) => setParentId(e.target.value)}>
                    {items
                      .filter((d) => dialog.mode !== 'move' || d.id !== dialog.target.id)
                      .map((d) => (
                        <option key={d.id} value={d.id}>
                          {'　'.repeat(Math.max(0, d.depth - 1))}{d.name}
                        </option>
                      ))}
                  </select>
                  {dialog.mode === 'move' && (
                    <div className="hint">
                      移动会带着<b>整棵子树</b>一起走；已授给该部门的权限按新路径继续生效。
                    </div>
                  )}
                </div>
              )}
              {dialogErr && <div className="error">{dialogErr}</div>}
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setDialog(null)}>取消</button>
                <button className="primary" type="submit" disabled={busy === 'dialog'}>
                  {busy === 'dialog' ? '保存中…' : '保存'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {confirmDel && (
        <div className="modal-mask" onClick={() => setConfirmDel(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 420 }}>
            <div className="modal-head">
              <strong>删除部门</strong><div className="spacer" />
              <button className="ghost" onClick={() => setConfirmDel(null)}>关闭</button>
            </div>
            <div className="modal-body" style={{ display: 'grid', gap: 12 }}>
              <p>
                将删除「{confirmDel.name}」。
                {confirmDel.memberCount > 0 && <> 该部门下有 <b>{confirmDel.memberCount}</b> 位成员。</>}
                {confirmDel.spaceCount > 0 && <> 还挂着 <b>{confirmDel.spaceCount}</b> 个空间。</>}
              </p>
              <div className="hint">
                有子部门、成员或空间时不允许删除——系统不会替你改掉别人的归属。
                请先把成员移动到其它部门，再删。
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button onClick={() => setConfirmDel(null)}>取消</button>
                <button className="danger" disabled={busy === 'del'} onClick={() => void remove(confirmDel)}>
                  {busy === 'del' ? '删除中…' : '确认删除'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
