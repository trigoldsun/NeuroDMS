// 平台运营 · 表单类弹窗：开通租户 / 新建平台账号 / 重置口令 / 绑定域名
//
// 这些弹窗此前散在 Console.tsx 里、宽度靠 inline style 写死。
// 抽出来的直接好处：所有"提交前校验 + 失败留在弹窗内 + 成功后关闭"的流程只有一份，
// 不会出现某个弹窗忘了拦二次口令、或者把错误弹到身后页面上。

import { useState } from 'react'
import { PasswordPair, passwordPairError } from '../components/PasswordPair'
import { call } from './api'
import { Modal, Note } from './ui'

const EDITION_TEXT: Record<string, string> = {
  basic: '基础版',
  professional: '专业版',
  business: '旗舰版',
}

// 运营开单时看的是报价单，不是文档：把"这一档差在哪"直接摆在选项下面。
const EDITION_HINT: Record<string, string> = {
  basic: '无密级管控、无目录认证、无邮件外发 · 单文件 1GB · 保留 3 个版本',
  professional: '密级 0/3/4、目录认证、邮件外发 · 单文件 5GB · 保留 10 个版本',
  business: '密级 0–6 全档、目录认证、邮件外发、自定义域名 · 单文件 10GB · 保留 50 个版本',
}

function Foot(props: { form?: string; onCancel: () => void; busy: boolean; submit: string; busyText: string }) {
  return (
    <>
      <button type="button" onClick={props.onCancel} disabled={props.busy}>取消</button>
      {/* form 属性把按钮和表单关联起来：按钮在 .pf-modal-foot（固定），
          表单在 .pf-modal-body（可滚动）。此前按钮放在表单末尾，字段一多
          就被挤到折叠线以下——用户看不到「开通」按钮，以为这个弹窗
          只是填资料、没有提交动作。 */}
      <button className="primary" type="submit" form={props.form} disabled={props.busy}>
        {props.busy ? props.busyText : props.submit}
      </button>
    </>
  )
}

// CopyLine 复制一段交付说明。不做成"复制到剪贴板 + 弹提示"的黑盒：
// 复制失败时把文本本身显示出来，运营可以手工选中——比"复制失败"有用。
function CopyLine({ text }: { text: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle')
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('ok')
      window.setTimeout(() => setState('idle'), 1800)
    } catch {
      setState('fail')
    }
  }
  return (
    <div className="pf-form">
      <div className="pf-actions" style={{ justifyContent: 'flex-start' }}>
        <button type="button" onClick={() => void copy()}>
          {state === 'ok' ? '已复制' : '复制交付信息'}
        </button>
      </div>
      {state === 'fail' && (
        <pre style={{ margin: 0, fontFamily: 'var(--mono)', fontSize: 12, whiteSpace: 'pre-wrap' }}>{text}</pre>
      )}
    </div>
  )
}

// ---------------- 开通租户 ----------------

export function CreateTenant({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    slug: '', name: '', edition: 'basic', editionExpiresAt: '', trialDays: 0, contactEmail: '',
    adminUsername: 'admin', adminPassword: '', adminDisplayName: '',
  })
  // 确认值单独存，不进 f：请求体里只能有 adminPassword 一个口令字段。
  const [pw2, setPw2] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  // 开通成功后不立刻关闭：运营需要知道"要交付给客户什么"。
  // 以前是建完就关，结果常见问题是"租户建好了，谁去登录？账号叫什么？"
  const [done, setDone] = useState<null | { slug: string; admin: string }>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitted(true)
    const bad = passwordPairError(f.adminPassword, pw2)
    if (bad) { setErr(bad); return }
    setBusy(true)
    setErr('')
    try {
      const created = await call<{ slug?: string }>('/tenants', { method: 'POST', body: JSON.stringify(f) })
      setDone({ slug: created?.slug || f.slug, admin: f.adminUsername })
    } catch (e) {
      setErr(e instanceof Error ? e.message : '开通失败')
      // 错误提示在表单末尾，被折叠线挡住等于没提示：滚到底让它可见。
      window.requestAnimationFrame(() => {
        const body = document.querySelector('.pf-modal-body')
        if (body) body.scrollTop = body.scrollHeight
      })
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    const origin = window.location.origin
    const brief = [
      `系统地址：${origin}/login`,
      `组织标识：${done.slug}`,
      `管理员账号：${done.admin}`,
      '管理员口令：开通时由你设定的那一个（系统不回存明文）',
    ].join('\n')
    return (
      <Modal title="租户已开通" onClose={onDone} foot={<button className="primary" onClick={onDone}>完成</button>}>
        <div className="pf-form">
          <Note tone="ok" icon="shield">
            租户已创建，并已自动创建一个<b>系统管理员</b>账号。把下面四项交给客户即可登录。
          </Note>
          <dl className="pf-dl">
            <div><dt>系统地址</dt><dd className="mono">{origin}/login</dd></div>
            <div><dt>组织标识</dt><dd className="mono">{done.slug}</dd></div>
            <div><dt>管理员账号</dt><dd className="mono">{done.admin}</dd></div>
            <div><dt>管理员口令</dt><dd>上一步设定的口令</dd></div>
          </dl>          <Note>
            口令只在提交时传给服务端，<b>不会回显也不会存明文</b>。若已经记不清，
            请客户用该账号登录后到「系统设置 → 账号与安全」修改；客户无法登录时，
            只能由客户方另一位管理员重置。
          </Note>
          <Note>
            还要再加管理员？在租户端「系统设置 → 用户管理」新建成员时把
            <b>「初始角色」选成「系统管理员」</b>；已有成员则在行尾
            「更多操作 → 授予「系统管理员」」。
          </Note>
          <CopyLine text={brief} />
        </div>
      </Modal>
    )
  }

  return (
    <Modal
      title="开通租户"
      onClose={busy ? () => { /* 提交中不关闭，避免半途丢弃 */ } : onClose}
      foot={<Foot form="ct-form" onCancel={onClose} busy={busy} submit="开通" busyText="开通中…" />}
    >
      <form id="ct-form" className="pf-form" onSubmit={submit}>
        <div className="pf-grid2">
          <div className="field">
            <label htmlFor="ct-slug">租户标识（登录时使用）</label>
            <input
              id="ct-slug" value={f.slug} required placeholder="acme"
              pattern="[a-z0-9][a-z0-9-]{1,40}"
              onChange={(e) => setF({ ...f, slug: e.target.value.trim().toLowerCase() })}
            />
            <span className="hint">小写字母、数字、连字符，开通后不可改</span>
          </div>
          <div className="field">
            <label htmlFor="ct-name">租户名称</label>
            <input id="ct-name" value={f.name} required
              onChange={(e) => setF({ ...f, name: e.target.value })} />
            <span className="hint">客户看到的系统名称，可随时改</span>
          </div>
        </div>

        <div className="field">
          <label>档位</label>
          <div className="pf-choice">
            {(['basic', 'professional', 'business'] as const).map((e) => (
              <label key={e} className={f.edition === e ? 'on' : ''}>
                <input
                  type="radio" name="edition" value={e}
                  checked={f.edition === e}
                  onChange={() => setF({ ...f, edition: e })}
                />
                {EDITION_TEXT[e]}
              </label>
            ))}
          </div>
          <span className="hint">{EDITION_HINT[f.edition]}</span>
        </div>

        <div className="pf-grid2">
          <div className="field">
            <label htmlFor="ct-exp">档位到期日</label>
            <input id="ct-exp" type="date" value={f.editionExpiresAt}
              onChange={(e) => setF({ ...f, editionExpiresAt: e.target.value })} />
            <span className="hint">留空 = 不限期</span>
          </div>
          <div className="field">
            <label htmlFor="ct-trial">试用天数</label>
            <input id="ct-trial" type="number" min={0} max={365} value={f.trialDays}
              onChange={(e) => setF({ ...f, trialDays: Number(e.target.value) })} />
            <span className="hint">0 = 直接正式</span>
          </div>
        </div>

        {/* 管理员区块放在联系邮箱之前：这是开通时唯一**必填且不可后补**的信息。
            此前后面还跟着"联系邮箱"，口令框被推到折叠线以下，
            运营打开弹窗只看到联系邮箱，以为这个弹窗没有设置管理员的字段。 */}
        <div className="pf-section">
          <b>首个管理员</b>
          <span>开通后立即创建这个账号，并自动授予「系统管理员」——用它登录即可配置成员、品牌与策略。</span>
        </div>

        <div className="pf-grid2">
          <div className="field">
            <label htmlFor="ct-admin">管理员账号</label>
            <input id="ct-admin" value={f.adminUsername} required
              onChange={(e) => setF({ ...f, adminUsername: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="ct-admin-name">管理员显示名</label>
            <input id="ct-admin-name" value={f.adminDisplayName}
              placeholder="留空则与账号相同"
              onChange={(e) => setF({ ...f, adminDisplayName: e.target.value })} />
          </div>
        </div>

        <PasswordPair
          id="new-tenant-admin"
          label="管理员初始口令（至少 8 位）"
          value={f.adminPassword}
          onChange={(v) => setF({ ...f, adminPassword: v })}
          confirm={pw2}
          onConfirm={setPw2}
          submitted={submitted}
          disabled={busy}
          hint="两次输入必须一致，输入内容以 * 显示；交付后请让客户首次登录即修改。"
        />

        <div className="field">
          <label htmlFor="ct-mail">联系邮箱（可选）</label>
          <input id="ct-mail" type="email" value={f.contactEmail}
            placeholder="用于续费与故障通知"
            onChange={(e) => setF({ ...f, contactEmail: e.target.value })} />
        </div>

        {err && <Note tone="danger">{err}</Note>}
      </form>
    </Modal>
  )
}

// ---------------- 新建平台账号 ----------------

export function CreatePlatUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ email: '', displayName: '', role: 'readonly', password: '' })
  const [pw2, setPw2] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitted(true)
    const bad = passwordPairError(f.password, pw2)
    if (bad) { setErr(bad); return }
    setBusy(true)
    setErr('')
    try {
      await call('/users', { method: 'POST', body: JSON.stringify(f) })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '创建失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title="新建平台账号"
      onClose={onClose}
      narrow
      foot={<Foot form="pu-form" onCancel={onClose} busy={busy} submit="创建" busyText="创建中…" />}
    >
      <form id="pu-form" className="pf-form" onSubmit={submit}>
        <div className="field">
          <label htmlFor="pu-mail">邮箱（登录用）</label>
          <input id="pu-mail" type="email" required value={f.email}
            onChange={(e) => setF({ ...f, email: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="pu-name">姓名</label>
          <input id="pu-name" value={f.displayName}
            onChange={(e) => setF({ ...f, displayName: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="pu-role">角色</label>
          <select id="pu-role" value={f.role}
            onChange={(e) => setF({ ...f, role: e.target.value })}>
            <option value="readonly">只读（排查问题用，不能变更）</option>
            <option value="ops">可操作（开通租户、改配额、切开关）</option>
          </select>
          <span className="hint">只读角色在服务端被拒，不是只把按钮变灰</span>
        </div>
        <PasswordPair
          id="new-plat-user"
          label="初始口令（至少 8 位）"
          value={f.password}
          onChange={(v) => setF({ ...f, password: v })}
          confirm={pw2}
          onConfirm={setPw2}
          submitted={submitted}
          disabled={busy}
        />
        {err && <Note tone="danger">{err}</Note>}
      </form>
    </Modal>
  )
}

// ---------------- 重置平台账号口令 ----------------

export function ResetPlatPassword({ user, onClose, onDone }:
  { user: { id: string; email: string }; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitted(true)
    const bad = passwordPairError(pw, pw2)
    if (bad) { setErr(bad); return }
    setBusy(true)
    setErr('')
    try {
      await call(`/users/${user.id}/password`, { method: 'POST', body: JSON.stringify({ password: pw }) })
      onDone()
    } catch (e) {
      setErr(e instanceof Error ? e.message : '重置失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={`重置 ${user.email} 的口令`}
      onClose={onClose}
      narrow
      foot={<Foot form="rp-form" onCancel={onClose} busy={busy} submit="确认重置" busyText="重置中…" />}
    >
      <form id="rp-form" className="pf-form" onSubmit={submit}>
        <PasswordPair
          id="reset-plat-user"
          label="新口令（至少 8 位）"
          value={pw}
          onChange={setPw}
          confirm={pw2}
          onConfirm={setPw2}
          submitted={submitted}
          disabled={busy}
          autoFocus
        />
        <Note icon="alert">重置会立即吊销该账号的全部平台会话，旧口令同时失效。</Note>
        {err && <Note tone="danger">{err}</Note>}
      </form>
    </Modal>
  )
}

// ---------------- 绑定域名（替代 window.prompt + alert） ----------------

export type DnsRecord = { type: string; name: string; value: string }

export function AddDomainModal({ slug, onClose, onAdded }:
  { slug: string; onClose: () => void; onAdded: (host: string, rec: DnsRecord) => void }) {
  const [host, setHost] = useState('')
  const [primary, setPrimary] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const data = await call<{ dns: DnsRecord }>(`/tenants/${slug}/domains`, {
        method: 'POST',
        body: JSON.stringify({ host: host.trim().toLowerCase(), primary }),
      })
      // host 一并回传：DNS 记录里没有"绑的是哪个域名"，只靠记录名反推会出错
      onAdded(host.trim().toLowerCase(), data.dns)
    } catch (e) {
      setErr(e instanceof Error ? e.message : '绑定失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title="绑定自有域名"
      onClose={onClose}
      narrow
      foot={
        <>
          <button type="button" onClick={onClose} disabled={busy}>取消</button>
          <button className="primary" type="submit" form="ad-form" disabled={busy}>
            {busy ? '绑定中…' : '绑定并获取 DNS 记录'}
          </button>
        </>
      }
    >
      <form id="ad-form" className="pf-form" onSubmit={submit}>
        <div className="field">
          <label htmlFor="ad-host">域名</label>
          <input
            id="ad-host" required value={host}
            placeholder="docs.example.com"
            onChange={(e) => setHost(e.target.value)}
          />
          {/* 这一段是此前 window.prompt 完全无法承载的部分：
              客户最常填错的就是把协议和端口一起粘进来。 */}
          <span className="hint">
            只填主机名，不要带 <code>https://</code>、路径或端口。
          </span>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13, fontWeight: 400 }}>
          <input type="checkbox" checked={primary} onChange={(e) => setPrimary(e.target.checked)} />
          设为主域名（同一租户只应有一个）
        </label>
        {err && <Note tone="danger">{err}</Note>}
      </form>
    </Modal>
  )
}

// ---------------- DNS 记录展示（替代 window.alert） ----------------

export function DnsModal({ host, rec, onClose }:
  { host: string; rec: DnsRecord; onClose: () => void }) {
  const [copied, setCopied] = useState('')
  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(label)
      window.setTimeout(() => setCopied(''), 1600)
    } catch {
      setCopied('')
    }
  }
  return (
    <Modal
      title="完成域名归属验证"
      onClose={onClose}
      narrow
      foot={<button className="primary" onClick={onClose}>知道了</button>}
    >
      <div className="pf-form">
        <Note icon="alert">
          请先在 DNS 服务商处添加下面这条记录，生效后回到详情页点「验证归属」。
          记录未生效时验证会失败，这是正常的，不是系统故障。
        </Note>
        <div className="pf-dl" style={{ gridTemplateColumns: '1fr' }}>
          <div>
            <dt>记录类型</dt>
            <dd className="mono">{rec.type}</dd>
          </div>
          <div>
            <dt>主机记录</dt>
            <dd className="mono" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ overflowWrap: 'anywhere' }}>{rec.name}</span>
              <button className="sm" type="button" onClick={() => void copy(rec.name, 'name')}>
                {copied === 'name' ? '已复制' : '复制'}
              </button>
            </dd>
          </div>
          <div>
            <dt>记录值</dt>
            <dd className="mono" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ overflowWrap: 'anywhere' }}>{rec.value}</span>
              <button className="sm" type="button" onClick={() => void copy(rec.value, 'value')}>
                {copied === 'value' ? '已复制' : '复制'}
              </button>
            </dd>
          </div>
        </div>
        <div className="hint">
          域名「{host}」在验证通过前不会对外提供访问。
        </div>
      </div>
    </Modal>
  )
}
