// 自定义域名与证书（docs/47 §4.6、docs/51）。
//
// 这个页面要能独立回答三个问题，否则实施必然来问：
//   1. 我还差哪一步？（绑域名 → 配 TXT → 验证 → 配证书）
//   2. 为什么自动签发点了没用？（模式为 off 时说明"该由谁托管"）
//   3. 这张证书到期了谁负责？（手工 vs 自动，责任主体不同）
//
// 所以每一行都按"状态 + 下一步"排版，而不是把所有按钮平铺出来。

import { useCallback, useEffect, useState } from 'react'
import {
  addDomain, deleteDomain, deleteDomainCert, finishCertificate, issueCertificate,
  listDomains, uploadDomainCert, verifyDomain,
  HttpError, type AcmeStatus, type DnsRecord, type DomainItem,
} from '../api'

export default function Domains() {
  const [items, setItems] = useState<DomainItem[]>([])
  const [acme, setAcme] = useState<AcmeStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const [host, setHost] = useState('')
  const [primary, setPrimary] = useState(false)
  const [challenge, setChallenge] = useState<DnsRecord | null>(null)

  const [certHost, setCertHost] = useState('')
  const [certPem, setCertPem] = useState('')
  const [keyPem, setKeyPem] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await listDomains()
      setItems(r.items ?? [])
      setAcme(r.acme ?? null)
      setErr('')
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '读取域名失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function run(key: string, fn: () => Promise<string>) {
    setBusy(key)
    setErr('')
    setMsg('')
    try {
      setMsg(await fn())
      await load()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '操作失败')
    } finally {
      setBusy('')
    }
  }

  async function onAdd(e: React.FormEvent) {
    e.preventDefault()
    const h = host.trim().toLowerCase()
    if (!h) return
    setBusy('add')
    setErr('')
    setMsg('')
    try {
      const r = await addDomain(h, primary)
      // 绑完立刻把"该配什么"摆出来，不让人去翻文档
      setChallenge({
        host: r.host, type: r.dns.type, name: r.dns.name, value: r.dns.value,
        note: '添加 TXT 记录后等待 1–10 分钟，再点「验证归属」。',
      })
      setHost('')
      setPrimary(false)
      await load()
    } catch (e) {
      setErr(e instanceof HttpError ? e.message : '绑定失败')
    } finally {
      setBusy('')
    }
  }

  // 证书剩余天数：临近到期要把"谁负责续期"说清楚。
  function daysLeft(iso?: string): number | null {
    if (!iso) return null
    const ms = new Date(iso).getTime() - Date.now()
    return Math.floor(ms / 86400000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {err && <div className="card pad error">{err}</div>}
      {msg && <div className="card pad">{msg}</div>}

      <div className="card pad">
        <div className="card-head">
          <div>
            <b>自动签发（ACME）</b>
            <div className="hint" style={{ marginTop: 4 }}>
              {acme ? acme.reason : '未读取到状态'}
            </div>
          </div>
          {acme && (
            <span className={'badge ' + (acme.available ? 'ok' : 'plain')}>
              {acme.available ? (acme.staging ? '已启用（测试目录）' : '已启用') : '未启用'}
            </span>
          )}
        </div>
        {acme?.staging && (
          <div className="hint" style={{ marginTop: 8 }}>
            当前使用 Let's Encrypt <b>测试目录</b>：签出的证书不被浏览器信任，只用于联调。
            正式环境请把 DOCVAULT_ACME_DIRECTORY 留空（用生产目录）。
          </div>
        )}
        {acme?.mode === 'dns01' && (
          <div className="hint" style={{ marginTop: 8 }}>
            DNS-01 手动模式<b>不会自动续期</b>：证书到期前需要你重新点一次签发、加一条新的 TXT。
          </div>
        )}
      </div>

      <form className="card pad" onSubmit={onAdd}>
        <div className="card-head" style={{ marginBottom: 10 }}>
          <b>绑定域名</b>
          <span className="hint">只填主机名，不填协议与端口</span>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="field" style={{ flex: '1 1 260px' }}>
            <label htmlFor="dv-host">域名</label>
            <input
              id="dv-host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="docs.example.com"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
            />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={primary}
              onChange={(e) => setPrimary(e.target.checked)}
              style={{ width: 'auto' }}
            />
            设为主域名
          </label>
          <button className="primary" disabled={busy === 'add' || !host.trim()}>
            {busy === 'add' ? '绑定中…' : '绑定'}
          </button>
        </div>
        <div className="hint" style={{ marginTop: 8 }}>
          绑定本身不生效：必须先证明域名归你（下一行的 TXT 记录），验证通过后才会被解析到本系统。
        </div>
      </form>

      {challenge && (
        <div className="card pad">
          <div className="card-head">
            <b>第 1 步：证明域名归属</b>
            <button className="ghost" onClick={() => setChallenge(null)}>收起</button>
          </div>
          <div className="hint" style={{ margin: '8px 0' }}>
            在 <b>{challenge.host}</b> 的 DNS 服务商处添加一条记录：
          </div>
          <div className="tablewrap">
            <table>
              <thead>
                <tr><th>类型</th><th>主机记录</th><th>记录值</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>{challenge.type}</code></td>
                  <td><code>{challenge.name}</code></td>
                  <td style={{ wordBreak: 'break-all' }}><code>{challenge.value}</code></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="hint" style={{ marginTop: 8 }}>{challenge.note}</div>
        </div>
      )}

      {certHost && (
        <div className="card pad">
          <div className="card-head">
            <b>上传证书：{certHost}</b>
            <button className="ghost" onClick={() => { setCertHost(''); setCertPem(''); setKeyPem('') }}>
              取消
            </button>
          </div>
          <div className="field" style={{ marginTop: 8 }}>
            <label htmlFor="cert-pem">证书（PEM，含中间证书）</label>
            <textarea
              id="cert-pem"
              value={certPem}
              onChange={(e) => setCertPem(e.target.value)}
              rows={6}
              placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
              style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}
              spellCheck={false}
            />
          </div>
          <div className="field" style={{ marginTop: 8 }}>
            <label htmlFor="key-pem">私钥（PEM）</label>
            <textarea
              id="key-pem"
              value={keyPem}
              onChange={(e) => setKeyPem(e.target.value)}
              rows={6}
              placeholder={'-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'}
              style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}
              spellCheck={false}
            />
          </div>
          <div className="hint" style={{ marginTop: 8 }}>
            私钥会加密保存，保存后界面不再显示，也不会出现在审计日志里。
            上传的证书<b>不会被自动续期</b>——到期前请自行更换。
          </div>
          <div style={{ marginTop: 10 }}>
            <button
              className="primary"
              disabled={busy === 'cert' || !certPem.trim() || !keyPem.trim()}
              onClick={() => void run('cert', async () => {
                const info = await uploadDomainCert(certHost, certPem, keyPem)
                setCertHost('')
                setCertPem('')
                setKeyPem('')
                return `证书已保存，有效期至 ${new Date(info.notAfter).toLocaleString()}`
              })}
            >
              {busy === 'cert' ? '保存中…' : '保存证书'}
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-head" style={{ padding: '12px 16px 0' }}>
          <b>已绑定域名</b>
          <span className="hint">{items.length} 个</span>
        </div>
        {loading ? (
          <div className="hint" style={{ padding: 16 }}>加载中…</div>
        ) : items.length === 0 ? (
          <div className="hint" style={{ padding: 16 }}>
            还没有绑定域名。用本系统的默认地址同样可以使用；绑定自有域名是为了让链接显示成你自己的品牌。
          </div>
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>域名</th><th>归属</th><th>证书</th><th>到期</th><th style={{ width: 360 }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((d) => {
                  const left = daysLeft(d.certNotAfter)
                  return (
                    <tr key={d.host}>
                      <td>
                        <div><b>{d.host}</b></div>
                        {d.primary && <span className="badge brand">主域名</span>}
                        {d.acmePending && <span className="badge warn">待完成签发</span>}
                      </td>
                      <td>
                        {d.verified
                          ? <span className="badge ok">已验证</span>
                          : <span className="badge plain">待验证</span>}
                      </td>
                      <td>
                        {d.hasCert ? (
                          <span className={'badge ' + (d.certSource === 'acme' ? 'teal' : 'violet')}>
                            {d.certSource === 'acme' ? '自动签发' : '手工上传'}
                          </span>
                        ) : <span className="hint">无</span>}
                      </td>
                      <td>
                        {d.certNotAfter ? (
                          <span className={left !== null && left < 15 ? 'badge warn' : ''}>
                            {new Date(d.certNotAfter).toLocaleDateString()}
                            {left !== null && ` (${left} 天)`}
                          </span>
                        ) : <span className="hint">—</span>}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {!d.verified && (
                            <button
                              disabled={busy === 'verify-' + d.host}
                              onClick={() => void run('verify-' + d.host, async () => {
                                await verifyDomain(d.host)
                                return `${d.host} 已验证`
                              })}
                            >
                              验证归属
                            </button>
                          )}
                          {d.verified && acme?.available && (
                            <button
                              disabled={busy === 'issue-' + d.host}
                              onClick={() => void run('issue-' + d.host, async () => {
                                const r = await issueCertificate(d.host)
                                if (r.issued) return `${d.host} 证书已签发`
                                if (r.dns) {
                                  setChallenge(r.dns)
                                  return '已生成 TXT 记录：请按上方提示添加后点「完成签发」'
                                }
                                return '已提交签发'
                              })}
                            >
                              {d.acmePending ? '继续签发' : '自动签发'}
                            </button>
                          )}
                          {d.acmePending && (
                            <button
                              disabled={busy === 'finish-' + d.host}
                              onClick={() => void run('finish-' + d.host, async () => {
                                await finishCertificate(d.host)
                                return `${d.host} 证书已签发`
                              })}
                            >
                              完成签发
                            </button>
                          )}
                          <button onClick={() => { setCertHost(d.host); setCertPem(''); setKeyPem('') }}>
                            上传证书
                          </button>
                          {d.hasCert && (
                            <button
                              disabled={busy === 'delcert-' + d.host}
                              onClick={() => void run('delcert-' + d.host, async () => {
                                await deleteDomainCert(d.host)
                                return `已删除 ${d.host} 的证书`
                              })}
                            >
                              删除证书
                            </button>
                          )}
                          <button
                            className="ghost"
                            disabled={busy === 'del-' + d.host}
                            onClick={() => {
                              if (!confirm(`解绑 ${d.host}？解绑后该地址将无法访问本系统（证书一并删除）。`)) return
                              void run('del-' + d.host, async () => {
                                await deleteDomain(d.host)
                                return `已解绑 ${d.host}`
                              })
                            }}
                          >
                            解绑
                          </button>
                        </div>
                        {d.acmeError && (
                          <div className="hint" style={{ marginTop: 6 }}>
                            上次签发失败：{d.acmeError}
                          </div>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="hint">
        说明：绑定域名后，浏览器地址会保持你自己的域名，但<b>证书</b>仍然需要单独准备——
        可以用下面的「自动签发」（域名直连本机、80/443 可达时可用），也可以上传已有证书。
        走反向代理或边缘隧道的部署，证书通常在代理那一层终止，本页只需绑定域名。
      </div>
    </div>
  )
}
