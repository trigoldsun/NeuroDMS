// 集成与凭证（docs/49）。
//
// 页面结构由后端的两份"数据"驱动：
//   kinds     —— 有哪些能力域、哪些能在这里配（available/external/planned）
//   providers —— 每个能力域下有哪些厂商、字段 schema 是什么
// 所以新增一家短信厂商，这里一行都不用改。
//
// 三条界面纪律：
//  1. 密钥输入框永远 type=password，且**只写不读**：已保存的显示"留空沿用"；
//  2. "设生效"是独立动作，保存不会偷偷切换线上通道；
//  3. 自检失败按后端给的分类码展示，不把上游原文糊到界面上。

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  activateIntegration, deleteIntegration, getIntegrationKinds, listIntegrations,
  saveIntegration, testIntegration,
  HttpError, type IntegrationKind, type IntegrationProvider, type IntegrationSettings,
  type IntegrationTestResult,
} from '../api'
import { navigate } from '../router'

type Draft = { config: Record<string, string>; secrets: Record<string, string> }

export default function Integrations() {
  const [kinds, setKinds] = useState<IntegrationKind[]>([])
  const [kind, setKind] = useState('sms')
  const [providers, setProviders] = useState<IntegrationProvider[]>([])
  const [saved, setSaved] = useState<Record<string, IntegrationSettings>>({})
  const [drafts, setDrafts] = useState<Record<string, Draft>>({})
  const [secretAvailable, setSecretAvailable] = useState(true)
  // 平台默认通道是否装配（仅 sms）：租户四家全"未配置"时，短信其实仍可能能发。
  const [platformFallback, setPlatformFallback] = useState(false)
  const [results, setResults] = useState<Record<string, IntegrationTestResult>>({})
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const current = useMemo(() => kinds.find((k) => k.kind === kind), [kinds, kind])

  useEffect(() => {
    getIntegrationKinds()
      .then((r) => setKinds(r.items))
      .catch((e) => setErr(e instanceof HttpError ? e.message : '读取能力域失败'))
  }, [])

  const loadKind = useCallback(async (k: string) => {
    setErr('')
    setMsg('')
    try {
      const r = await listIntegrations(k)
      const map: Record<string, IntegrationSettings> = {}
      for (const it of r.items) map[it.provider] = it
      setSaved(map)
      setProviders(r.providers ?? [])
      setSecretAvailable(r.secretAvailable)
      setPlatformFallback(!!r.platformFallback)
      // 用已保存的非密字段回填；密钥永远留空
      const d: Record<string, Draft> = {}
      for (const p of r.providers ?? []) {
        d[p.code] = { config: { ...(map[p.code]?.config ?? {}) }, secrets: {} }
      }
      setDrafts(d)
      setResults({})
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '读取配置失败')
    }
  }, [])

  useEffect(() => { void loadKind(kind) }, [kind, loadKind])

  function setField(provider: string, key: string, value: string, secret: boolean) {
    setDrafts((d) => {
      const cur = d[provider] ?? { config: {}, secrets: {} }
      const next: Draft = {
        config: { ...cur.config },
        secrets: { ...cur.secrets },
      }
      if (secret) next.secrets[key] = value
      else next.config[key] = value
      return { ...d, [provider]: next }
    })
  }

  async function onSave(p: IntegrationProvider) {
    const d = drafts[p.code] ?? { config: {}, secrets: {} }
    setBusy(`save:${p.code}`)
    setErr('')
    setMsg('')
    try {
      // active 不传：保存只保存，切换生效要显式点"设为生效"
      await saveIntegration(p.kind, p.code, { config: d.config, secrets: d.secrets })
      setMsg(`已保存「${p.name}」`)
      await loadKind(kind)
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '保存失败')
    } finally {
      setBusy('')
    }
  }

  async function onTest(p: IntegrationProvider) {
    setBusy(`test:${p.code}`)
    setErr('')
    setMsg('')
    try {
      const r = await testIntegration(p.kind, p.code)
      setResults((s) => ({ ...s, [p.code]: r }))
      await loadKind(kind)
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '测试失败')
    } finally {
      setBusy('')
    }
  }

  async function onActivate(p: IntegrationProvider) {
    setBusy(`act:${p.code}`)
    setErr('')
    setMsg('')
    try {
      await activateIntegration(p.kind, p.code)
      setMsg(`「${p.name}」已成为当前生效通道`)
      await loadKind(kind)
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '切换失败')
    } finally {
      setBusy('')
    }
  }

  async function onDelete(p: IntegrationProvider) {
    if (!window.confirm(`删除「${p.name}」的配置？已保存的密钥会一并删除。`)) return
    setBusy(`del:${p.code}`)
    setErr('')
    setMsg('')
    try {
      await deleteIntegration(p.kind, p.code)
      setMsg(`已删除「${p.name}」`)
      await loadKind(kind)
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '删除失败')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="grid">
      <div className="card" style={{ padding: 16 }}>
        <h3 style={{ marginTop: 0 }}>集成与凭证</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          第三方服务的凭证由客户自行准备，本系统只负责加密保存与连通性自检。
          密钥字段只写不读：保存后页面上不会再显示原值，留空表示沿用已保存的密钥。
        </p>
        {!secretAvailable && (
          <div className="card" style={{ padding: 12, borderColor: 'var(--warn-line)', marginBottom: 12 }}>
            <b>未配置加密密钥</b>
            <div className="hint" style={{ marginTop: 4 }}>
              服务端没有设置 <code>DOCVAULT_SECRET_KEY</code>，密钥类字段无法保存。
              可以先保存签名、模板等非密参数，密钥需运维配置密钥后再填。
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {kinds.map((k) => (
            <button
              key={k.kind}
              className={kind === k.kind ? 'primary' : ''}
              onClick={() => setKind(k.kind)}
              title={k.description}
            >
              {k.name}
            </button>
          ))}
        </div>

        {msg && <div className="hint" style={{ marginBottom: 10 }}>{msg}</div>}

        {kind === 'sms' && platformFallback && !Object.values(saved).some((s) => s.active) && (
          <div className="card" style={{ padding: 12, marginBottom: 12 }}>
            <b>当前生效通道：平台默认通道</b>
            <div className="hint" style={{ marginTop: 4 }}>
              下面四家是<strong>租户自有</strong>通道，全部未配置时系统会走平台默认通道发送。
              也就是说：这里显示"未配置"<strong>不等于</strong>短信不可用。
              要确认实际可用性，请用「测试发送」，或直接观察一次发码结果。
            </div>
          </div>
        )}
        {err && <div className="error-text" style={{ marginBottom: 10 }}>{err}</div>}

        {current && current.status !== 'available' && (
          <div className="card" style={{ padding: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <b>{current.name}</b>
              <span className={`badge ${current.status === 'external' ? 'plain' : 'warn'}`}>
                {current.status === 'external' ? '有专用页面' : '尚未接入'}
              </span>
            </div>
            <p className="hint" style={{ marginBottom: 10 }}>{current.description}</p>
            {current.status === 'external' && current.pagePath && (
              <button className="primary" onClick={() => navigate(current.pagePath!)}>
                前往配置
              </button>
            )}
            {current.status === 'planned' && (
              <div className="hint">
                本期不在此页配置：保存了也不会影响实际行为，所以只做说明，不给假开关。
              </div>
            )}
          </div>
        )}

        {current?.status === 'available' && providers.length === 0 && (
          <div className="hint">该能力域暂无可用通道。</div>
        )}

        {current?.status === 'available' && providers.map((p) => {
          const s = saved[p.code]
          const d = drafts[p.code] ?? { config: {}, secrets: {} }
          const r = results[p.code]
          return (
            <div className="card" key={p.code} style={{ padding: 16, marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <b>{p.name}</b>
                {p.mode === 'managed' && <span className="badge teal">云端生成核验</span>}
                {p.mode === 'local' && <span className="badge plain">本地生成核验</span>}
                {s?.active
                  ? <span className="badge ok">当前生效</span>
                  : s ? <span className="badge plain">已配置</span>
                  : <span className="badge plain">未配置</span>}
                {s?.lastTestOk === true && <span className="badge ok">自检通过</span>}
                {s?.lastTestOk === false && <span className="badge danger">自检失败</span>}
                {p.docsUrl && (
                  <a className="hint" href={p.docsUrl} target="_blank" rel="noreferrer"
                    style={{ marginLeft: 'auto' }}>官方文档</a>
                )}
              </div>

              {p.notes && p.notes.length > 0 && (
                <ul className="hint" style={{ margin: '8px 0 4px 18px', padding: 0 }}>
                  {p.notes.map((n) => <li key={n}>{n}</li>)}
                </ul>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 12, marginTop: 10 }}>
                {p.fields.map((f) => {
                  const isSecret = f.secret
                  const value = isSecret ? (d.secrets[f.key] ?? '') : (d.config[f.key] ?? '')
                  const already = !!s?.hasSecret?.[f.key]
                  return (
                    <div className="field" key={f.key}>
                      <label htmlFor={`${p.code}-${f.key}`}>
                        {f.label}{f.required ? ' *' : ''}
                      </label>
                      <input
                        id={`${p.code}-${f.key}`}
                        type={isSecret ? 'password' : 'text'}
                        value={value}
                        placeholder={isSecret && already ? '已保存，留空沿用' : (f.placeholder ?? '')}
                        onChange={(e) => setField(p.code, f.key, e.target.value, isSecret)}
                        autoComplete={isSecret ? 'new-password' : 'off'}
                        spellCheck={false}
                        autoCorrect="off"
                        autoCapitalize="off"
                      />
                      {f.help && <span className="hint">{f.help}</span>}
                    </div>
                  )
                })}
              </div>

              {r && (
                <div className="card" style={{ padding: 12, marginTop: 12 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className={`badge ${r.ok ? 'ok' : 'danger'}`}>
                      {r.ok ? '连接成功' : '未通过'}
                    </span>
                    <span className="hint">{r.message}</span>
                  </div>
                  {!r.ok && r.hint && <div className="hint" style={{ marginTop: 6 }}>{r.hint}</div>}
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
                <button className="primary" disabled={busy !== ''} onClick={() => void onSave(p)}>
                  {busy === `save:${p.code}` ? '保存中…' : '保存'}
                </button>
                <button disabled={busy !== '' || !s} onClick={() => void onTest(p)}
                  title={s ? '按当前配置真连一次' : '请先保存配置'}>
                  {busy === `test:${p.code}` ? '测试中…' : '测试连接'}
                </button>
                {s && !s.active && (
                  <button disabled={busy !== ''} onClick={() => void onActivate(p)}>
                    {busy === `act:${p.code}` ? '切换中…' : '设为生效'}
                  </button>
                )}
                {s && (
                  <button className="ghost" disabled={busy !== ''} onClick={() => void onDelete(p)}>
                    {busy === `del:${p.code}` ? '删除中…' : '删除配置'}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
