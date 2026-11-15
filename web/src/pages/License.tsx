// 本地版许可证（docs/47 §4.5）。
//
// 这一页存在的唯一理由是让客户**自助完成激活**：把实例指纹发给我们、
// 拿到一串许可证、粘进来。所以顺序就是按这个流程排的。
//
// 云端版打开这一页应该看到"无需许可证"，而不是一个空的输入框——
// 让客户以为"没激活就不能用"，会变成一次无谓的工单。

import { useCallback, useEffect, useState } from 'react'
import { applyLicense, getLicenseStatus, HttpError, type LicenseStatus } from '../api'

const editionText: Record<string, string> = {
  basic: '基础版',
  professional: '专业版',
  business: '旗舰版',
}

export default function License() {
  const [st, setSt] = useState<LicenseStatus | null>(null)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState(false)

  const load = useCallback(async () => {
    try {
      setSt(await getLicenseStatus())
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '读取许可证状态失败')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function submit() {
    if (!input.trim()) return
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      const r = await applyLicense(input.trim())
      setMsg(`许可证已生效：${r.customer}（${editionText[r.edition] ?? r.edition}，${r.licenseId}）`)
      setInput('')
      await load()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '应用失败')
    } finally {
      setBusy(false)
    }
  }

  async function copyId() {
    if (!st?.instanceId) return
    try {
      await navigator.clipboard.writeText(st.instanceId)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // 非 HTTPS 或浏览器拒绝时静默：下面照样能看到完整字符串，手动选中即可。
    }
  }

  if (!st) {
    return <div className="card pad">{err || '加载中…'}</div>
  }

  // 云端版：没有公钥，也不需要许可证。直接说清楚，别摆一个用不上的输入框。
  if (!st.enabled && !st.present) {
    return (
      <div className="card pad">
        <b>本实例是云端版，无需许可证</b>
        <div className="hint" style={{ marginTop: 8 }}>{st.reason}</div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {err && <div className="card pad error">{err}</div>}
      {msg && <div className="card pad">{msg}</div>}

      <div className="card pad">
        <div className="card-head">
          <b>授权状态</b>
          <span className={`badge ${st.valid ? 'ok' : st.present ? 'danger' : 'plain'}`}>
            {st.valid ? '已授权' : st.present ? '许可证无效' : '未导入'}
          </span>
        </div>
        <div className="hint" style={{ marginTop: 8 }}>{st.reason}</div>
        {st.present && (
          <div className="tablewrap" style={{ marginTop: 10 }}>
            <table>
              <tbody>
                <tr><th style={{ width: 140 }}>许可证号</th><td>{st.licenseId || '—'}</td></tr>
                <tr><th>客户</th><td>{st.customer || '—'}</td></tr>
                <tr><th>档位</th><td>{editionText[st.edition ?? ''] ?? st.edition ?? '—'}</td></tr>
                <tr>
                  <th>席位</th>
                  <td>{st.seats && st.seats > 0 ? `${st.seats} 个` : '不限'}</td>
                </tr>
                <tr>
                  <th>到期</th>
                  <td>{st.expiresAt ? new Date(st.expiresAt).toLocaleDateString() : '永久'}</td>
                </tr>
                <tr>
                  <th>能力</th>
                  <td>
                    {st.capabilities?.includes('*')
                      ? '全部功能'
                      : (st.capabilities?.join('、') || '—')}
                  </td>
                </tr>
                {st.appliedAt && (
                  <tr><th>导入时间</th><td>{new Date(st.appliedAt).toLocaleString()}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {st.enabled && !st.present && (
          <div className="hint" style={{ marginTop: 8 }}>
            本实例已具备许可证校验能力，但还没有导入许可证。导入后档位会按许可证自动设置。
          </div>
        )}
      </div>

      <div className="card pad">
        <b>第 1 步：把实例指纹发给厂商</b>
        <div className="hint" style={{ margin: '8px 0' }}>
          许可证绑定这个指纹，换机器需要重新申请。它不含任何业务数据，可以安全外发。
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <code
            style={{
              padding: '6px 10px', background: 'var(--surface-2, #f4f4f2)',
              borderRadius: 6, wordBreak: 'break-all', flex: '1 1 320px',
            }}
          >
            {st.instanceId || '（读取失败）'}
          </code>
          <button onClick={() => void copyId()} disabled={!st.instanceId}>
            {copied ? '已复制' : '复制'}
          </button>
        </div>
      </div>

      <div className="card pad">
        <b>第 2 步：粘贴许可证</b>
        <div className="hint" style={{ margin: '8px 0' }}>
          厂商会给你一串形如 <code>xxxx.yyyy</code> 的文本。粘贴后点「导入」。
          导入只会改变本实例的档位，不会删除或改动任何文件与用户。
        </div>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={5}
          spellCheck={false}
          placeholder="粘贴许可证内容"
          style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12, width: '100%' }}
        />
        <div style={{ marginTop: 10 }}>
          <button className="primary" disabled={busy || !input.trim()} onClick={() => void submit()}>
            {busy ? '校验中…' : '导入'}
          </button>
        </div>
        <div className="hint" style={{ marginTop: 8 }}>
          导入时会验签。若提示「与本实例指纹不匹配」，说明这串许可证是给别的机器签的，
          请用上面的指纹重新申请。
        </div>
      </div>
    </div>
  )
}
