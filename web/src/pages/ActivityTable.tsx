import { useCallback, useEffect, useState } from 'react'
import {
  adminActivity, exportActivity, HttpError, myActivity,
  type ActivityFilter, type ActivityItem,
} from '../api'
import {
  actionLabel, ADMIN_GROUPS, resultBadgeClass, resultText, RESULT_OPTIONS, USER_GROUPS,
} from '../activity'
import { Icon, Tooltip } from '../components/ui'

// 日志表格：用户日志与管理日志共用一套交互。
//
// 共用的理由不是"少写代码"，而是**两条链路必须行为一致**：
// 用户看到 20 条一页、能按结果筛、能导出，管理员看到的也该是同一套；
// 各自实现一次，迟早出现"管理员能导出、用户点了 401"这类差异。

const PAGE_SIZE = 20

const DAY_OPTIONS = [
  { value: '0', label: '全部时间' },
  { value: '7', label: '近 7 天' },
  { value: '30', label: '近 30 天' },
  { value: '90', label: '近 90 天' },
]

export default function ActivityTable({ scope }: { scope: 'me' | 'admin' }) {
  const [group, setGroup] = useState('')
  const [result, setResult] = useState('')
  const [days, setDays] = useState('30')
  const [page, setPage] = useState(1)

  const [items, setItems] = useState<ActivityItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [msg, setMsg] = useState('')

  const groups = scope === 'admin' ? ADMIN_GROUPS : USER_GROUPS

  const filter: ActivityFilter = {
    group,
    result,
    from: days === '0' ? undefined : new Date(Date.now() - Number(days) * 86400_000).toISOString(),
    page,
    size: PAGE_SIZE,
  }

  const load = useCallback(async () => {
    setLoading(true)
    setMsg('')
    try {
      const f: ActivityFilter = { group, result, page, size: PAGE_SIZE }
      if (days !== '0') f.from = new Date(Date.now() - Number(days) * 86400_000).toISOString()
      const d = scope === 'admin' ? await adminActivity(f) : await myActivity(f)
      setItems(d.items ?? [])
      setTotal(d.total ?? 0)
    } catch (err) {
      setMsg(err instanceof HttpError ? `${err.code}：${err.message}` : '加载失败')
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [scope, group, result, days, page])

  useEffect(() => { void load() }, [load])

  // 改筛选条件时回到第 1 页。否则会出现"在第 5 页筛出 0 条"，
  // 用户以为没有数据，其实只是页码越界。
  function resetTo(fn: () => void) {
    fn()
    setPage(1)
  }

  async function onExport() {
    try {
      await exportActivity(scope, filter)
      setMsg('已开始下载 CSV（可作为 Excel 打开）')
    } catch (err) {
      setMsg(err instanceof HttpError ? `导出失败：${err.message}` : '导出失败')
    }
  }

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  // 管理日志多一列"操作人"，空态行的 colSpan 必须跟着变，否则会错列
  const cols = scope === 'admin' ? 7 : 6

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <select value={group} onChange={(e) => resetTo(() => setGroup(e.target.value))} aria-label="动作分类">
          {groups.map((g) => <option key={g.value} value={g.value}>{g.label}</option>)}
        </select>
        <select value={result} onChange={(e) => resetTo(() => setResult(e.target.value))} aria-label="结果">
          {RESULT_OPTIONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
        </select>
        <select value={days} onChange={(e) => resetTo(() => setDays(e.target.value))} aria-label="时间范围">
          {DAY_OPTIONS.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}
        </select>
        <div style={{ flex: 1 }} />
        <button className="ghost" onClick={() => void load()} disabled={loading}>刷新</button>
        <button onClick={() => void onExport()}>导出 CSV</button>
      </div>

      {msg && <div className="hint">{msg}</div>}

      <table>
        <thead>
          <tr>
            <th style={{ width: 160 }}>时间</th>
            {/* 管理日志最关键的一列是"谁做的"：没有操作人，这条日志对追责无用 */}
            {scope === 'admin' && <th style={{ width: 130 }}>操作人</th>}
            <th style={{ width: 130 }}>动作</th>
            <th>对象</th>
            <th style={{ width: 90 }}>结果</th>
            <th style={{ width: 140 }}>来源 IP</th>
            <th style={{ width: 90 }}>详情</th>
          </tr>
        </thead>
        <tbody>
          {loading && items.length === 0 && (
            <tr><td colSpan={cols}><div className="empty">载入中…</div></td></tr>
          )}
          {!loading && items.length === 0 && (
            <tr>
              <td colSpan={cols}>
                <div className="empty">
                  {result === 'denied' ? '这段时间没有被拒绝的操作' : '没有符合条件的记录'}
                </div>
              </td>
            </tr>
          )}
          {items.map((it) => (
            <tr key={it.seq}>
              <td className="tnum">{new Date(it.createdAt).toLocaleString('zh-CN')}</td>
              {scope === 'admin' && (
                <td>
                  <div>{it.actorName || '—'}</div>
                  <div className="hint" style={{ fontSize: 11 }}>{it.actorType}</div>
                </td>
              )}
              <td>
                <div>{actionLabel(it.action)}</div>
                <div className="hint" style={{ fontSize: 11 }}>{it.action}</div>
              </td>
              <td style={{ fontSize: 12.5 }}>
                {it.objectName ? (
                  <Tooltip
                    wide
                    content={
                      <>
                        <div className="tip-t"><Icon name="file" size={14} /> {it.objectName}</div>
                        <div className="tip-r"><span>对象 ID</span><b className="mono">{it.objectId.slice(0, 8)}…</b></div>
                        <div className="tip-note">名称按日志发生时的对象解析；对象删除后仍显示名称，便于追溯。</div>
                      </>
                    }
                  >
                    <span style={{ color: 'var(--ink-2)' }}>{it.objectName}</span>
                  </Tooltip>
                ) : it.objectId ? (
                  <span className="mono dim" title={it.objectId}>{it.objectId.slice(0, 8)}…</span>
                ) : '—'}
              </td>
              <td>
                <span className={`badge ${resultBadgeClass(it.result)}`}>{resultText(it.result)}</span>
              </td>
              <td className="tnum hint">{it.ip || '—'}</td>
              <td>
                {it.detail && Object.keys(it.detail).length > 0 ? (
                  <details>
                    <summary className="hint" style={{ cursor: 'pointer' }}>查看</summary>
                    <pre className="preview-text" style={{ maxWidth: 420, maxHeight: 180, overflow: 'auto', fontSize: 11 }}>
                      {JSON.stringify(it.detail, null, 2)}
                    </pre>
                  </details>
                ) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="hint">共 {total} 条 · 第 {page} / {pages} 页</span>
        <div style={{ flex: 1 }} />
        <button className="ghost" disabled={page <= 1 || loading} onClick={() => setPage(page - 1)}>上一页</button>
        <button className="ghost" disabled={page >= pages || loading} onClick={() => setPage(page + 1)}>下一页</button>
      </div>
    </div>
  )
}
