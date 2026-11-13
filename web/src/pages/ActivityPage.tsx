import { useEffect, useState } from 'react'
import ActivityTable from './ActivityTable'
import { navigate, filesPath } from '../router'
import { api, applyTheme, cycleTheme, fetchMe, type Me } from '../api'
import { Shell, type SpaceLite } from '../components/Shell'
import { Icon, InfoDot } from '../components/ui'

// 「我的活动」：用户自查。
//
// 为什么用户需要这个页面：文件被谁看过、外链是谁建的、口令是不是有人在试——
// 这些问题过去只能问管理员。让本人能自查，既减少管理员的重复答疑，
// 也让"我在什么时候做过什么"成为可核对的记录，而不是各说各话。

export default function ActivityPage() {
  const [me, setMe] = useState<Me | null>(null)
  const [spaces, setSpaces] = useState<SpaceLite[]>([])

  useEffect(() => {
    applyTheme()
    void fetchMe().then(setMe).catch(() => undefined)
    void api<{ items: SpaceLite[] }>('/v1/spaces').then((d) => setSpaces(d.items ?? [])).catch(() => undefined)
  }, [])

  return (
    <Shell
      me={me}
      spaces={spaces}
      onSpace={(id) => navigate(filesPath(id))}
      spaceName="我的活动"
      crumbs={[{ id: 'me', name: '操作记录' }]}
      onOpenAccount={() => navigate('/files')}
      theme={document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'}
      onToggleTheme={() => { cycleTheme() }}
      actions={<button className="sm" onClick={() => location.reload()}><Icon name="history" size={14} /> 刷新</button>}
    >
      <div className="content-head">
        <div className="ttl">
          <h1>我的活动</h1>
          <div className="sub">
            <span>只显示你自己的操作记录</span>
            <InfoDot title="这里记录什么、不记录什么">
              <p>记录：登录、预览与下载、分享创建与撤销、编辑保存、账号与权限变更。</p>
              <p>不记录：管理员对他人执行的操作（那是管理台的事）。正文内容不会被记录，只记录"对哪个对象做了什么"。</p>
              <div className="pop-foot">记录在动作发生时由服务端写入，客户端无法删除；口令与令牌一律脱敏。</div>
            </InfoDot>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <Icon name="clock" size={15} />
          <b style={{ fontSize: 13 }}>操作流水</b>
          <span className="hint">按时间倒序 · 可按动作、结果与时间范围筛选</span>
        </div>
        <div className="panel-body">
          <ActivityTable scope="me" />
        </div>
        <div className="panel-foot">
          记录由服务端写入，不可篡改；导出的 CSV 与页面看到的一致。
        </div>
      </div>
    </Shell>
  )
}
