import { useCallback, useEffect, useState } from 'react'
import { api, HttpError, type SpaceOverviewRow } from '../api'
import { Avatar, Icon, InfoDot, Tooltip, absTime, fmtSize } from '../components/ui'
import { SpaceTransferDialog } from '../components/SpaceTransfer'

// 空间台账：系统管理员在这里看"谁有空间、谁的空间快没人管了"。
//
// 刻意不提供"进入空间"的入口：管理角色管配置不管内容。
// 这一页要回答的是资产归属问题，不是"去看看里面写了什么"。
export function AdminSpaces({ meId, flash }: { meId: string; flash: (m: string) => void }) {
  const [rows, setRows] = useState<SpaceOverviewRow[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [xfer, setXfer] = useState<SpaceOverviewRow | null>(null)

  const load = useCallback(async () => {
    setLoading(true); setErr('')
    try {
      const d = await api<{ items: SpaceOverviewRow[] }>('/v1/admin/spaces')
      setRows(d.items ?? [])
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '读取空间台账失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const onlyOwner = rows.filter((r) => r.onlyOwner).length
  const orphanRisk = rows.filter((r) => r.onlyOwner && r.ownerStatus !== 'active').length

  return (
    <>
      <div className="spaces-sum">
        <span><b>{loading ? '—' : rows.length}</b> 个空间</span>
        <span className="dim">·</span>
        <span className={onlyOwner > 0 ? 'danger-text' : ''}>
          <b>{onlyOwner}</b> 个仅所有者可达
        </span>
        <InfoDot title="为什么这一页很重要">
          <p>
            空间的可达性靠授权条目：如果某个空间只有所有者本人的一条授权，那么这个人
            <b>一停用或离职，空间就再也没人能打开</b>——管理员也看不到它（管理角色不具备内容权限）。
          </p>
          <p>所以「仅所有者可达」这一列是离职风险的预警信号。建议给部门或角色也授一份，或定期移交。</p>
          <div className="pop-foot">这里只看元数据，看不到文件内容。移交请用行内按钮。</div>
        </InfoDot>
        <div className="grow" />
        <button className="ghost sm" onClick={() => void load()} disabled={loading}>
          <Icon name="history" size={13} /> 刷新
        </button>
      </div>

      {orphanRisk > 0 && (
        <div className="banner danger" style={{ marginBottom: 12 }}>
          <span className="ico"><Icon name="alert" size={15} /></span>
          <span>
            有 <b>{orphanRisk}</b> 个空间的所有者账号已停用或已删除，且没有其他授权人 ——
            这些空间现在<b>无人可管</b>。请尽快移交给可用成员（转给第三方无需确认）。
          </span>
        </div>
      )}

      {err && (
        <div className="banner danger" style={{ marginBottom: 12 }}>
          <span className="ico"><Icon name="alert" size={15} /></span>
          <span>{err}</span>
        </div>
      )}

      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>空间</th>
              <th style={{ width: 168 }}>所有者</th>
              <th style={{ width: 96 }}>授权条目</th>
              <th style={{ width: 150 }}>最近活动</th>
              <th style={{ width: 130 }}>状态</th>
              <th style={{ width: 96 }}>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <div className="cell-name">
                    <span className="ftype" style={{ width: 26, height: 26 }}><Icon name="folder" size={14} /></span>
                    <span className="nm">
                      <span>{r.name}</span>
                      <span className="sub">
                        {r.kind} · {fmtSize(r.usedBytes)}
                        {r.quotaBytes ? ` / ${fmtSize(r.quotaBytes)}` : ''} · 密级 {r.classification}
                      </span>
                    </span>
                  </div>
                </td>
                <td>
                  <span className="person">
                    <Avatar name={r.ownerName || '—'} size={22} />
                    <span className="nm">{r.ownerName || '已删除账号'}</span>
                  </span>
                </td>
                <td className="tnum">{r.granted}</td>
                <td className="hint" style={{ fontSize: 12.5 }}>
                  {r.lastActivity ? absTime(r.lastActivity) : '从未有内容变动'}
                </td>
                <td>
                  {r.pendingId ? (
                    <Tooltip
                      wide
                      content={
                        <>
                          <div className="tip-t"><Icon name="clock" size={14} /> 等待原所有者确认</div>
                          <div className="tip-r"><span>接收人</span><b>{r.pendingTo}</b></div>
                          <div className="tip-note">管理员把空间移给自己时，必须由原所有者点同意；7 天未处理自动失效。</div>
                        </>
                      }
                    >
                      <span className="badge warn">待确认</span>
                    </Tooltip>
                  ) : r.onlyOwner ? (
                    <Tooltip
                      wide
                      content={
                        <>
                          <div className="tip-t"><Icon name="alert" size={14} /> 仅所有者可达</div>
                          <div className="tip-note">
                            除所有者外没有任何用户/部门/角色/组授权。所有者一旦停用或离职，
                            这个空间将无人可进。
                          </div>
                        </>
                      }
                    >
                      <span className="badge danger">仅所有者</span>
                    </Tooltip>
                  ) : (
                    <span className="badge ok">已共享</span>
                  )}
                  {r.ownerStatus !== 'active' && (
                    <span className="badge plain" style={{ marginLeft: 4 }}>账号不可用</span>
                  )}
                </td>
                <td>
                  <button className="sm" onClick={() => setXfer(r)}>
                    <Icon name="share" size={13} /> 移交
                  </button>
                </td>
              </tr>
            ))}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={6} className="hint" style={{ padding: 24, textAlign: 'center' }}>还没有空间</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {xfer && (
        <SpaceTransferDialog
          spaceId={xfer.id}
          spaceName={xfer.name}
          ownerName={xfer.ownerName}
          meId={meId}
          isAdmin
          isOwner={xfer.ownerId === meId}
          onClose={() => setXfer(null)}
          onDone={(m) => { flash(m); void load() }}
        />
      )}
    </>
  )
}
