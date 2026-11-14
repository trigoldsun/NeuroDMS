import { useCallback, useEffect, useState } from 'react'
import {
  fetchMe, getMail, HttpError, saveMail, testMail,
  type MailConfig, type MailStatus,
} from '../api'

// 邮件服务配置（SMTP / Exchange Online）。
//
// 这一页要回答三个问题，顺序也按这个来：
//  1. 现在用哪个通道发信？（跟随平台默认 / 自有 SMTP / Exchange Online）
//  2. 参数对不对？（「发送测试」用提交的参数真发一封，不必先保存）
//  3. 最近发出去没有？（队列积压与失败原因；"用户说没收到"十有八九要看这里）
//
// 口令与客户端密钥只写不读：输入框永远空白，placeholder 说明"是否已保存"，
// 留空提交等于"沿用原值"。回显口令的代价是它会进浏览器缓存、录屏与工单截图。

const EMPTY: MailConfig = {
  mode: 'inherit',
  fromAddr: '',
  fromName: '',
  replyTo: '',
  smtpHost: '',
  smtpPort: 587,
  smtpTls: 'starttls',
  smtpUser: '',
  smtpPassword: '',
  smtpInsecure: false,
  smtpAllowPlaintext: false,
  graphTenantId: '',
  graphClientId: '',
  graphClientSecret: '',
  graphSender: '',
  graphLoginBase: '',
  graphBase: '',
}

function fmtTime(s?: string): string {
  return s ? new Date(s).toLocaleString('zh-CN') : '—'
}

export default function MailSettings({ onFlash }: { onFlash: (m: string) => void }) {
  const [cfg, setCfg] = useState<MailConfig>(EMPTY)
  const [status, setStatus] = useState<MailStatus | null>(null)
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [to, setTo] = useState('')
  const [result, setResult] = useState<{ ok: boolean; message: string; channel: string } | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const d = await getMail()
      setStatus(d)
      // 口令字段强制清空：后端本来就不回显，这里再兜一次，
      // 避免将来有人"顺手"把字段塞进响应后前端直接把密文显示出来
      setCfg({ ...EMPTY, ...d.config, smtpPassword: '', graphClientSecret: '' })
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '读取邮件配置失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  // 测试收件人默认填自己：管理员最想确认的是"我这台机器能不能发信"
  useEffect(() => {
    void fetchMe().then((m) => setTo((v) => v || m.email)).catch(() => undefined)
  }, [])

  function patch(p: Partial<MailConfig>) {
    setCfg((c) => ({ ...c, ...p }))
  }

  async function onSave() {
    setBusy('save')
    setErr('')
    try {
      await saveMail(cfg)
      onFlash(cfg.mode === 'inherit'
        ? '已保存：本租户跟随平台默认通道'
        : '已保存：本租户将使用自己的发件邮箱')
      await load()
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '保存失败')
    } finally {
      setBusy('')
    }
  }

  async function onTest() {
    setBusy('test')
    setErr('')
    setResult(null)
    try {
      const r = await testMail(cfg, to)
      setResult(r)
      // 测试结果也要刷新：服务端会把结论写回配置，回到页面时能直接看到
      window.setTimeout(() => { void load() }, 400)
    } catch (e) {
      setErr(e instanceof HttpError ? `${e.code}：${e.message}` : '测试失败')
    } finally {
      setBusy('')
    }
  }

  if (loading) return <div className="empty">载入中…</div>

  const env = status?.environment
  const outbox = status?.outbox
  const noChannelAtAll = cfg.mode === 'inherit' && env && !env.defaultConfigured
  const plaintextRisky = cfg.mode === 'smtp' && cfg.smtpTls === 'none'

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {err && <div className="card empty error" style={{ margin: 0 }}>{err}</div>}

      {noChannelAtAll && (
        <div className="card" style={{ margin: 0 }}>
          <strong>当前没有任何可用的邮件通道</strong>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
            本租户跟随平台默认，而平台没有配置默认通道（环境变量 DOCVAULT_SMTP_* 或 DOCVAULT_GRAPH_*）。
            此时验证码、外发分享邮件都发不出去。请在本页配置自有 SMTP 或 Exchange Online。
          </div>
        </div>
      )}

      {env && !env.secretKeyAvailable && (
        <div className="card" style={{ margin: 0 }}>
          <strong>未配置加密密钥，无法保存口令</strong>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>
            服务端没有设置 DOCVAULT_SECRET_KEY，邮件口令与客户端密钥无法加密落库。
            可先保存地址等非敏感参数，口令需由运维配置密钥后再填。
          </div>
        </div>
      )}

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>发信通道</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <input
              type="radio" name="mail-mode" checked={cfg.mode === 'inherit'}
              onChange={() => patch({ mode: 'inherit' })}
            />
            <span>
              跟随平台默认
              <span className="hint" style={{ display: 'block' }}>
                由部署时的环境变量决定。
                当前：{env?.defaultConfigured
                  ? `已配置（${env.defaultChannels.join(' + ') || '—'}）`
                  : '未配置'}
              </span>
            </span>
          </label>
          <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <input
              type="radio" name="mail-mode" checked={cfg.mode === 'smtp'}
              onChange={() => patch({ mode: 'smtp' })}
            />
            <span>
              SMTP 服务器
              <span className="hint" style={{ display: 'block' }}>
                通用方案：企业邮箱、内网中继、自建 Postfix 都用这条。
              </span>
            </span>
          </label>
          <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <input
              type="radio" name="mail-mode" checked={cfg.mode === 'graph'}
              onChange={() => patch({ mode: 'graph' })}
            />
            <span>
              Exchange Online / Microsoft 365
              <span className="hint" style={{ display: 'block' }}>
                走 Microsoft Graph 的 sendMail（应用权限 Mail.Send）。
                微软对 Exchange Online 的 SMTP AUTH 基本认证已排定停用（2026 年 12 月底起默认关闭），
                M365 邮箱请用这条，不要用「SMTP 服务器」+ 邮箱口令。
              </span>
            </span>
          </label>
        </div>
      </div>

      {cfg.mode === 'smtp' && (
        <div className="card pad">
          <h3 style={{ marginTop: 0 }}>SMTP 参数</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: 10, alignItems: 'center' }}>
            <label htmlFor="mail-smtp-host">服务器</label>
            <input
              id="mail-smtp-host" placeholder="smtp.example.com"
              value={cfg.smtpHost} onChange={(e) => patch({ smtpHost: e.target.value })}
            />
            <label htmlFor="mail-smtp-port">端口</label>
            <input
              id="mail-smtp-port" type="number" min={1} max={65535} style={{ width: 120 }}
              value={cfg.smtpPort} onChange={(e) => patch({ smtpPort: Number(e.target.value) })}
            />
            <label htmlFor="mail-smtp-tls">加密方式</label>
            <select
              id="mail-smtp-tls" style={{ width: 220 }}
              value={cfg.smtpTls} onChange={(e) => patch({ smtpTls: e.target.value as MailConfig['smtpTls'] })}
            >
              <option value="starttls">STARTTLS（587，推荐）</option>
              <option value="tls">隐式 TLS（465）</option>
              <option value="none">不加密</option>
            </select>
            <label htmlFor="mail-smtp-user">登录账号</label>
            <input
              id="mail-smtp-user" placeholder="留空表示中继不需要认证"
              value={cfg.smtpUser} onChange={(e) => patch({ smtpUser: e.target.value })}
            />
            <label htmlFor="mail-smtp-pass">口令</label>
            <input
              id="mail-smtp-pass" type="password" autoComplete="new-password"
              placeholder={cfg.hasSmtpPassword ? '已保存，留空表示不修改' : '未设置'}
              value={cfg.smtpPassword ?? ''} onChange={(e) => patch({ smtpPassword: e.target.value })}
            />
            <label htmlFor="mail-from">发件地址</label>
            <input
              id="mail-from" placeholder="noreply@example.com"
              value={cfg.fromAddr} onChange={(e) => patch({ fromAddr: e.target.value })}
            />
            <label htmlFor="mail-from-name">发件人显示名</label>
            <input
              id="mail-from-name"
              placeholder={status?.effectiveFromName || '留空 = 【系统名文档管理系统】'}
              value={cfg.fromName} onChange={(e) => patch({ fromName: e.target.value })}
            />
            <label htmlFor="mail-reply-to">回复地址</label>
            <input
              id="mail-reply-to" placeholder="可选，收件人点回复时的地址"
              value={cfg.replyTo} onChange={(e) => patch({ replyTo: e.target.value })}
            />
          </div>

          <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginTop: 10 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input
                type="checkbox" checked={cfg.smtpAllowPlaintext}
                onChange={(e) => patch({ smtpAllowPlaintext: e.target.checked })}
              />
              允许明文连接
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input
                type="checkbox" checked={cfg.smtpInsecure}
                onChange={(e) => patch({ smtpInsecure: e.target.checked })}
              />
              跳过证书校验（不推荐）
            </label>
          </div>
          {plaintextRisky && (
            <div className="hint" style={{ marginTop: 6 }}>
              {cfg.hasSmtpPassword || cfg.smtpPassword
                ? '不加密时邮箱口令会以明文过网：必须勾选「允许明文连接」才可保存，且只应用于内网中继。'
                : '不加密连接仅适用于内网中继；若需要登录认证，请改用 STARTTLS 或隐式 TLS。'}
            </div>
          )}
          {cfg.smtpInsecure && (
            <div className="error" style={{ marginTop: 6 }}>
              跳过校验等于放弃中间人防护：任何人都能冒充邮件服务器收走口令。
            </div>
          )}
        </div>
      )}

      {cfg.mode === 'graph' && (
        <div className="card pad">
          <h3 style={{ marginTop: 0 }}>Exchange Online（Microsoft Graph）</h3>
          <div className="hint" style={{ marginBottom: 8 }}>
            在 Azure AD（Entra ID）里注册应用 → 授予<b>应用权限</b> Mail.Send → 管理员同意 →
            创建客户端密钥。三个 ID 分别对应：目录（租户）ID、应用（客户端）ID、密钥值。
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: 10, alignItems: 'center' }}>
            <label htmlFor="mail-graph-tenant">目录（租户）ID</label>
            <input
              id="mail-graph-tenant" placeholder="00000000-0000-0000-0000-000000000000"
              value={cfg.graphTenantId} onChange={(e) => patch({ graphTenantId: e.target.value })}
            />
            <label htmlFor="mail-graph-client">应用（客户端）ID</label>
            <input
              id="mail-graph-client" placeholder="00000000-0000-0000-0000-000000000000"
              value={cfg.graphClientId} onChange={(e) => patch({ graphClientId: e.target.value })}
            />
            <label htmlFor="mail-graph-secret">客户端密钥</label>
            <input
              id="mail-graph-secret" type="password" autoComplete="new-password"
              placeholder={cfg.hasGraphSecret ? '已保存，留空表示不修改' : '未设置'}
              value={cfg.graphClientSecret ?? ''} onChange={(e) => patch({ graphClientSecret: e.target.value })}
            />
            <label htmlFor="mail-graph-sender">发件邮箱</label>
            <input
              id="mail-graph-sender" placeholder="noreply@yourcompany.com"
              value={cfg.graphSender} onChange={(e) => patch({ graphSender: e.target.value })}
            />
            <label htmlFor="mail-graph-reply">回复地址</label>
            <input
              id="mail-graph-reply" placeholder="可选"
              value={cfg.replyTo} onChange={(e) => patch({ replyTo: e.target.value })}
            />
          </div>
          <details style={{ marginTop: 10 }}>
            <summary className="hint" style={{ cursor: 'pointer' }}>高级：主权云 / 测试环境端点</summary>
            <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: 10, alignItems: 'center', marginTop: 8 }}>
              <label htmlFor="mail-graph-login">登录端点</label>
              <input
                id="mail-graph-login" placeholder="默认 https://login.microsoftonline.com"
                value={cfg.graphLoginBase} onChange={(e) => patch({ graphLoginBase: e.target.value })}
              />
              <label htmlFor="mail-graph-base">Graph 端点</label>
              <input
                id="mail-graph-base" placeholder="默认 https://graph.microsoft.com"
                value={cfg.graphBase} onChange={(e) => patch({ graphBase: e.target.value })}
              />
            </div>
            <div className="hint" style={{ marginTop: 6 }}>
              21Vianet 运营的 Microsoft 365 请填 login.chinacloudapi.cn 与 microsoftgraph.chinacloudapi.cn。
            </div>
          </details>
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <button className="primary" onClick={() => void onSave()} disabled={busy !== ''}>
          {busy === 'save' ? '保存中…' : '保存配置'}
        </button>
        <span className="hint">
          保存后立即生效（队列里的待发邮件也会按新配置发出）。
          {status?.config.updatedAt ? ` 上次修改：${fmtTime(status.config.updatedAt)}` : ''}
        </span>
      </div>

      <div className="card pad">
        <h3 style={{ marginTop: 0 }}>发送测试</h3>
        <div className="hint" style={{ marginBottom: 8 }}>
          使用<b>上方表单当前的参数</b>真发一封邮件（不必先保存）。收不到时先看垃圾箱，
          再确认发件域名的 SPF/DKIM 是否允许本服务器代发。
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            id="mail-test-to" style={{ width: 280 }} placeholder="收件邮箱"
            value={to} onChange={(e) => setTo(e.target.value)}
          />
          <button onClick={() => void onTest()} disabled={busy !== '' || !to.trim()}>
            {busy === 'test' ? '发送中…' : '发送测试邮件'}
          </button>
          {cfg.mode === 'inherit' && <span className="hint">将用平台默认通道发送</span>}
        </div>
        {result && (
          <div className={`banner ${result.ok ? 'ok' : 'danger'}`} style={{ marginTop: 10 }}>
            <span className="ico">{result.ok ? '✓' : '!'}</span>
            <span>
              通道 {result.channel}：{result.message}
            </span>
          </div>
        )}
        {status?.config.lastTestAt && (
          <div className="hint" style={{ marginTop: 8 }}>
            上次测试：{fmtTime(status.config.lastTestAt)} → {status.config.lastTestTo || '—'}
            {status.config.lastTestOk === true ? '（成功）' : status.config.lastTestOk === false
              ? `（失败：${status.config.lastTestError || '未知原因'}）` : ''}
          </div>
        )}
      </div>

      <div className="hint" style={{ marginTop: -6 }}>
        收件人在邮箱里看到的发件人是：<b>{status?.effectiveFromName || '—'}</b>
        {cfg.fromName ? '（本页已自定义）' : '（留空时自动使用「系统名称 + 文档管理系统」，系统名称在「系统设置 · 品牌与名称」里改）'}
      </div>

      {outbox && (
        <div className="card pad">
          <h3 style={{ marginTop: 0 }}>最近 7 天的发送情况</h3>
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', marginBottom: 8 }}>
            <span>24 小时已发 <b>{outbox.sent24h}</b></span>
            <span>待发 <b>{outbox.pending}</b></span>
            <span>失败待重试 <b>{outbox.failed}</b></span>
            <span>已终止 <b>{outbox.dead}</b></span>
          </div>
          {outbox.recent.length > 0 ? (
            <table>
              <thead><tr><th style={{ width: 200 }}>收件人</th><th style={{ width: 120 }}>用途</th><th>原因</th><th style={{ width: 160 }}>时间</th></tr></thead>
              <tbody>
                {outbox.recent.map((r, i) => (
                  <tr key={`${r.to}-${i}`}>
                    <td>{r.to}</td>
                    <td><span className="code">{r.purpose}</span></td>
                    <td style={{ color: 'var(--danger)' }}>{r.error || '—'}</td>
                    <td>{fmtTime(r.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="hint">没有失败记录。</div>
          )}
          <div className="hint" style={{ marginTop: 8 }}>
            失败会自动按 30 秒 → 1 分 → 2 分 … 重试，5 次后进入「已终止」（不再占用队列）。
            修好配置后，失败待重试的会自己发出去；已终止的需要重新触发业务动作。
          </div>
        </div>
      )}
    </div>
  )
}
