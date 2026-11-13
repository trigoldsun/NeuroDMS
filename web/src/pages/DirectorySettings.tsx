import { useCallback, useEffect, useState } from 'react'
import {
  directoryRuns, getCapabilities, getDirectory, HttpError, saveDirectory, syncDirectory, testDirectory,
  type DirectoryConfig, type DirectoryProbe, type DirectoryRun,
} from '../api'

// 目录认证配置（PRD-IAM-11 / -20）。
//
// 设计上的两个约束直接体现在界面上：
//  1. 口令只写不读——所以"留空 = 沿用原口令"，并显示"已设置"。
//  2. 测试连接分三步返回（匿名 / 绑定 / 读目录）：只报一个 false 的话，
//     管理员无法判断是网不通、口令错、还是服务账号没有读权限。

const EMPTY: DirectoryConfig = {
  enabled: false,
  url: '',
  startTls: false,
  insecureSkipVerify: false,
  tlsName: '',
  bindDn: '',
  bindPassword: '',
  baseDn: '',
  userFilter: '',
  syncFilter: '',
  groupFilter: '',
  excludeAccounts: [],
  adMode: true,
  allowPlaintext: false,
  syncIntervalMinutes: 0,
}

function fmtTime(s: string): string {
  return new Date(s).toLocaleString('zh-CN')
}

function duration(r: DirectoryRun): string {
  if (!r.finishedAt) return r.status === 'running' ? '进行中' : '—'
  const ms = new Date(r.finishedAt).getTime() - new Date(r.startedAt).getTime()
  // 0 表示这条记录是"连接阶段就失败"时补写的，没有真实耗时（见 Sync.recordFailure）
  if (ms <= 0) return '—'
  if (ms < 1000) return `${ms} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.round(ms / 60_000)} min`
}

export default function DirectorySettings({ onFlash }: { onFlash: (m: string) => void }) {
  const [cfg, setCfg] = useState<DirectoryConfig>(EMPTY)
  const [runs, setRuns] = useState<DirectoryRun[]>([])
  const [probe, setProbe] = useState<DirectoryProbe | null>(null)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  // 档位是否含目录认证；加载失败按"支持"处理，避免把功能误藏。
  const [adAllowed, setAdAllowed] = useState(true)

  useEffect(() => {
    void getCapabilities()
      .then((c) => setAdAllowed(c.capabilities.ad))
      .catch(() => undefined)
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const [c, r] = await Promise.all([getDirectory(), directoryRuns(10)])
      // 口令永不回显；数组字段兜底成 []。
      // 后端曾把空数组序列化成 null，导致这里 .join() 抛错、整页空白（真实故障）。
      setCfg({
        ...EMPTY,
        ...c,
        bindPassword: '',
        excludeAccounts: Array.isArray(c.excludeAccounts) ? c.excludeAccounts : [],
      })
      setRuns(r.items ?? [])
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '读取目录配置失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  function patch(p: Partial<DirectoryConfig>) {
    setCfg((c) => ({ ...c, ...p }))
  }

  const plaintext = cfg.url.startsWith('ldap://') && !cfg.startTls

  async function onTest() {
    setBusy('test')
    setProbe(null)
    setErr('')
    try {
      setProbe(await testDirectory(cfg))
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '测试失败')
    } finally {
      setBusy('')
    }
  }

  async function onSave() {
    setBusy('save')
    setErr('')
    try {
      const saved = await saveDirectory(cfg)
      setCfg({ ...EMPTY, ...saved, bindPassword: '' })
      onFlash(saved.enabled ? '目录认证已保存并生效（下一次登录即按新配置校验）' : '已保存（未启用，域账号仍无法登录）')
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '保存失败')
    } finally {
      setBusy('')
    }
  }

  async function onSync(mode: 'full' | 'incremental') {
    setBusy(mode)
    setErr('')
    try {
      await syncDirectory(mode)
      onFlash(mode === 'full' ? '已开始全量同步，进度见下方记录' : '已开始增量同步，进度见下方记录')
      // 稍等再拉一次，让"进行中"这条记录能显示出来
      window.setTimeout(() => { void directoryRuns(10).then((r) => setRuns(r.items ?? [])).catch(() => {}) }, 1500)
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '触发同步失败')
    } finally {
      setBusy('')
    }
  }

  if (loading) return <div className="empty">载入中…</div>

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* 档位不支持时直接说明，而不是把整页藏掉：
          管理员找不到入口会去问客服"是不是系统坏了"，说清楚"需要升级"才是有效信息。 */}
      {!adAllowed && (
        <div className="card" style={{ margin: 0 }}>
          <strong>当前档位不支持目录认证</strong>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
            目录认证（LDAP / AD）属于专业版及以上能力。当前页面的配置不会生效，
            保存与同步请求会被服务端拒绝。如需使用请联系客户经理升级档位。
          </div>
        </div>
      )}
      {err && <div className="card empty error" style={{ margin: 0 }}>{err}</div>}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
          启用目录认证
        </label>
        <span className={`badge ${cfg.enabled ? 'ok' : 'plain'}`}>{cfg.enabled ? '已启用' : '未启用'}</span>
        <span className="badge plain">
          配置来源：{cfg.source === 'database' ? '数据库' : cfg.source === 'env' ? '环境变量' : '未配置'}
        </span>
        {cfg.source === 'env' && (
          <span className="hint">当前读的是环境变量配置；在此保存后以数据库配置为准。</span>
        )}
      </div>

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>连接</h3>
        <div className="field">
          <label htmlFor="dir-url">服务器地址</label>
          <input
            id="dir-url"
            placeholder="ldaps://dc1.example.com:636"
            value={cfg.url}
            onChange={(e) => patch({ url: e.target.value })}
          />
          <div className="hint">支持 ldap:// 与 ldaps://，端口仅 389 / 636 / 3268 / 3269。</div>
        </div>

        <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginTop: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input type="checkbox" checked={cfg.startTls} onChange={(e) => patch({ startTls: e.target.checked })} />
            使用 StartTLS（在 389 上升级加密）
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              type="checkbox"
              checked={cfg.insecureSkipVerify}
              onChange={(e) => patch({ insecureSkipVerify: e.target.checked })}
            />
            跳过证书校验（不推荐）
          </label>
        </div>

        {cfg.insecureSkipVerify && (
          <div className="error" style={{ marginTop: 8 }}>
            跳过校验等于放弃中间人防护：任何人都能冒充域控收走域口令。优先在下方粘贴企业 CA。
          </div>
        )}

        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-ca">企业 CA 证书（PEM，可选）</label>
          <textarea
            id="dir-ca"
            rows={3}
            placeholder={cfg.hasCa ? '已配置（留空表示保持不变）' : '-----BEGIN CERTIFICATE-----'}
            value={cfg.caPem ?? ''}
            onChange={(e) => patch({ caPem: e.target.value })}
            style={{ width: '100%', fontFamily: 'monospace', fontSize: 12 }}
          />
          <div className="hint">
            {cfg.hasCa ? '已配置 CA。如需更换，整段粘贴新的 PEM 覆盖即可。' : '域控使用企业 CA 时粘贴根证书，可避免"跳过校验"。'}
          </div>
        </div>

        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-tlsname">证书校验名（可选）</label>
          <input
            id="dir-tlsname"
            placeholder="DC1.example.com"
            value={cfg.tlsName}
            onChange={(e) => patch({ tlsName: e.target.value })}
          />
          <div className="hint">
            按 IP 连接而证书只有 DNS SAN 时填这里：仍然做真实校验，只是换个名字比对。
          </div>
        </div>
      </div>

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>服务账号</h3>
        <div className="field">
          <label htmlFor="dir-binddn">BindDN</label>
          <input
            id="dir-binddn"
            placeholder="CN=svc_docvault,OU=Service,DC=example,DC=com"
            value={cfg.bindDn}
            onChange={(e) => patch({ bindDn: e.target.value })}
          />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-bindpwd">口令</label>
          <input
            id="dir-bindpwd"
            type="password"
            autoComplete="new-password"
            placeholder={cfg.hasPassword ? '已设置（留空表示不修改）' : '未设置'}
            value={cfg.bindPassword ?? ''}
            onChange={(e) => patch({ bindPassword: e.target.value })}
          />
          <div className="hint">口令以密文保存，任何接口都不回显。留空保存＝沿用原口令。</div>
        </div>
      </div>

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>范围与过滤</h3>
        <div className="field">
          <label htmlFor="dir-basedn">BaseDN</label>
          <input
            id="dir-basedn"
            placeholder="DC=example,DC=com"
            value={cfg.baseDn}
            onChange={(e) => patch({ baseDn: e.target.value })}
          />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-userfilter">认证过滤器（必须含 %s）</label>
          <input
            id="dir-userfilter"
            placeholder="(&(objectClass=user)(sAMAccountName=%s))"
            value={cfg.userFilter}
            onChange={(e) => patch({ userFilter: e.target.value })}
          />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-syncfilter">同步过滤器（不能含 %s）</label>
          <input
            id="dir-syncfilter"
            placeholder="(&(objectClass=user)(objectCategory=person))"
            value={cfg.syncFilter}
            onChange={(e) => patch({ syncFilter: e.target.value })}
          />
          <div className="hint">AD 必须带 objectCategory=person，否则计算机账号会被当成用户同步进来。</div>
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-groupfilter">组过滤器</label>
          <input
            id="dir-groupfilter"
            placeholder="(objectClass=group)"
            value={cfg.groupFilter}
            onChange={(e) => patch({ groupFilter: e.target.value })}
          />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-exclude">排除账号（逗号分隔）</label>
          <input
            id="dir-exclude"
            placeholder="krbtgt, svc_backup"
            value={(cfg.excludeAccounts ?? []).join(', ')}
            onChange={(e) => patch({ excludeAccounts: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
          />
        </div>
      </div>

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>选项</h3>
        <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input type="checkbox" checked={cfg.adMode} onChange={(e) => patch({ adMode: e.target.checked })} />
            Active Directory 模式
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              type="checkbox"
              checked={cfg.allowPlaintext}
              onChange={(e) => patch({ allowPlaintext: e.target.checked })}
            />
            允许明文绑定（仅实验网）
          </label>
        </div>
        {plaintext && cfg.allowPlaintext && (
          <div className="error" style={{ marginTop: 8 }}>
            当前连接未加密，域口令会以明文经过网络。生产环境请给域控安装 LDAP 证书并改用 ldaps:// 或 StartTLS。
          </div>
        )}
        <div className="field" style={{ marginTop: 10 }}>
          <label htmlFor="dir-interval">自动同步间隔（分钟，0 = 只手动）</label>
          <input
            id="dir-interval"
            type="number"
            min={0}
            max={1440}
            value={cfg.syncIntervalMinutes}
            onChange={(e) => patch({ syncIntervalMinutes: Number(e.target.value) })}
            style={{ width: 140 }}
          />
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button onClick={() => void onTest()} disabled={busy !== ''}>
          {busy === 'test' ? '测试中…' : '测试连接'}
        </button>
        <button className="primary" onClick={() => void onSave()} disabled={busy !== ''}>
          {busy === 'save' ? '保存中…' : '保存'}
        </button>
        <div style={{ flex: 1 }} />
        <button className="ghost" onClick={() => void onSync('incremental')} disabled={busy !== '' || !cfg.enabled}>
          增量同步
        </button>
        <button className="ghost" onClick={() => void onSync('full')} disabled={busy !== '' || !cfg.enabled}>
          全量同步
        </button>
        <button className="ghost" onClick={() => void load()}>刷新记录</button>
      </div>

      {probe && (
        <div className="card pad">
          <h3 style={{ marginTop: 0 }}>测试结果</h3>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <span className={`badge ${probe.anonymous ? 'ok' : 'danger'}`}>
              网络/证书：{probe.anonymous ? '通' : '不通'}
            </span>
            <span className={`badge ${probe.bind ? 'ok' : probe.bindSkipped ? 'warn' : 'danger'}`}>
              服务账号绑定：{probe.bind ? '成功' : probe.bindSkipped ? '未测试' : '失败'}
            </span>
            <span className={`badge ${probe.baseRead ? 'ok' : 'warn'}`}>
              读取 BaseDN：{probe.baseRead ? '成功' : '未验证'}
            </span>
          </div>
          {probe.reason && <div className="hint" style={{ marginTop: 8 }}>{probe.reason}</div>}
          {!probe.baseRead && probe.bind && (
            <div className="hint" style={{ marginTop: 8 }}>
              绑定成功但读不到目录：检查服务账号是否被授予 BaseDN 的读取权限（多数现场卡在这一步）。
            </div>
          )}
        </div>
      )}

      <div className="card">
        <div style={{ padding: '12px 14px 0' }}>
          <h3 style={{ margin: 0 }}>同步记录</h3>
          <div className="hint">每次运行都会留下记录；连续失败通常是证书过期、网段不通或服务账号口令失效。</div>
        </div>
        <table>
          <thead>
            <tr>
              <th style={{ width: 160 }}>开始时间</th>
              <th style={{ width: 90 }}>耗时</th>
              <th style={{ width: 90 }}>状态</th>
              <th>看到 / 新增 / 更新 / 停用 / 恢复</th>
              <th style={{ width: 130 }}>跳过（同名冲突）</th>
              <th style={{ width: 150 }}>组 / 成员关系</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 ? (
              <tr><td colSpan={7}><div className="empty">还没有同步记录</div></td></tr>
            ) : runs.map((r) => (
              <tr key={r.id}>
                <td className="tnum">{fmtTime(r.startedAt)}</td>
                <td className="tnum">{duration(r)}</td>
                <td>
                  <span className={`badge ${r.status === 'ok' ? 'ok' : r.status === 'running' ? 'accent' : 'danger'}`}>
                    {r.status === 'ok' ? '成功' : r.status === 'running' ? '进行中' : '失败'}
                  </span>
                </td>
                <td className="tnum">
                  {r.usersSeen} / {r.usersCreated} / {r.usersUpdated} / {r.usersDisabled} / {r.usersRestored}
                </td>
                <td className="tnum">{r.groupsSynced} / {r.membersLinked}</td>
                <td className="tnum">
                  {r.conflicts > 0 ? (
                    <span className="badge warn" title={(r.conflictUsers ?? []).join('、')}>
                      {r.conflicts}
                    </span>
                  ) : '0'}
                </td>
                <td className="hint" style={{ fontSize: 12 }}>{r.error || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="hint" style={{ fontSize: 12 }}>
        顺序很重要：先「测试连接」→ 再「保存」→ 再「全量同步」建号 → 域账号才能登录。
        直接保存不同步的话，域账号会统一提示"用户名或密码错误"（服务端不区分账号不存在与口令错误）。
      </div>
    </div>
  )
}
