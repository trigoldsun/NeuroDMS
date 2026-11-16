const fs = require('fs')
const load = (p) => fs.readFileSync(p, 'utf8')
const save = (p, s) => fs.writeFileSync(p, s)

// ---------- CHANGELOG ----------
let c = load('CHANGELOG.md')
const eolC = c.includes('\r\n') ? '\r\n' : '\n'
const rowAnchor = '| 1.9.0 | 2026-11-15 | 小程序纳入主仓库：一致性整改 + 搜索/最近访问/提醒 |'
if (!c.includes(rowAnchor)) throw new Error('changelog row anchor')
c = c.replace(rowAnchor, '| 1.10.0 | 2026-11-16 | 审批提醒可配置：模板字段映射与跳转版本 |' + eolC + rowAnchor)

const bodyAnchor = '## 1.9.0 — 2026-11-15 · 小程序与主项目一致性（含搜索、最近访问、审批提醒）'
if (!c.includes(bodyAnchor)) throw new Error('changelog body anchor')
c = c.replace(bodyAnchor, [
  '## 1.10.0 — 2026-11-16 · 审批提醒配置化（模板字段映射、跳转版本）',
  '',
  '- **模板字段可配置**：新增 `DOCVAULT_WX_TODO_FIELDS`（`字段名=语义键` 映射）。原先字段名写死 `thing1/thing2/time3/phrase4`，客户所选模板字段不同时必然 47003（授权成功、余额扣了、消息不到）。',
  '- **跳转版本可配置**：新增 `DOCVAULT_WX_MP_STATE`（`developer`/`trial`/`formal`）。开发与体验阶段配错会跳到线上正式版（打不开或看到旧代码）。',
  '- **配错拒绝启动**：映射与版本在启动时校验，缺等号、语义键拼错、同一语义用两次、非法版本值都会打印原因并退出，不再留到"发了但收不到"才暴露。',
  '- **按字段类型截断**：`thing` 20 字、`phrase` 5 字、`name` 10 字、`character_string` 32 字符，避免长文件名触发 47003。',
  '',
  '---',
  '',
  bodyAnchor,
].join(eolC))
save('CHANGELOG.md', c)
console.log('changelog ok')

// ---------- 主文档 8.1 / 8.2 ----------
const pm = 'docs/NeuroDMS-技术文档-v1.10.0.md'
let m = load(pm)
const eolM = m.includes('\r\n') ? '\r\n' : '\n'
const tAnchor = '| 1.9.0 | 2026-11-15 | 小程序纳入主仓库：5 处不一致整改 + 搜索/最近访问/审批提醒 |'
if (!m.includes(tAnchor)) throw new Error('8.1 row anchor')
m = m.replace(tAnchor, '| 1.10.0 | 2026-11-16 | 审批提醒配置化：模板字段映射与跳转版本 |' + eolM + tAnchor)

const bAnchor = '#### 1.9.0 · 2026-11-15 · 小程序与主项目一致性'
if (!m.includes(bAnchor)) throw new Error('8.2 anchor')
m = m.replace(bAnchor, [
  '#### 1.10.0 · 2026-11-16 · 审批提醒配置化',
  '',
  '- **模板字段可配置**：`DOCVAULT_WX_TODO_FIELDS`（字段名=语义键）。字段写死时，客户换一个模板就 47003，',
  '  现象是"授权成功、余额扣了、消息不到"——最难查的一类。',
  '- **跳转版本可配置**：`DOCVAULT_WX_MP_STATE`（developer/trial/formal）；否则开发阶段点通知跳到线上正式版。',
  '- **配错拒绝启动**：映射与版本在装配前校验，非法值打印原因并 `exit 2`。',
  '- **按字段类型截断**：thing 20 / phrase 5 / name 10 / character_string 32 字符。',
  '- 验证：`go test ./internal/mpmsg` 8 条（含自定义字段报文、截断边界、非法映射拒绝）。',
  '',
  '',
  bAnchor,
].join(eolM))
save(pm, m)
console.log('8.1/8.2 ok')

// ---------- 索引变更记录 ----------
const pi = 'docs/README-文档索引与评审说明-v1.10.0.md'
let i = load(pi)
const eolI = i.includes('\r\n') ? '\r\n' : '\n'
const iAnchor = '| V1.9.0 | 2026-11-15 |'
if (!i.includes(iAnchor)) throw new Error('index anchor')
i = i.replace(iAnchor, '| V1.10.0 | 2026-11-16 | 审批提醒配置化：`DOCVAULT_WX_TODO_FIELDS`（模板字段映射）与 `DOCVAULT_WX_MP_STATE`（跳转版本）；配错在启动时拒绝，避免 47003 伪装成"收不到"（31 §14、6.18）|' + eolI + iAnchor)
save(pi, i)
console.log('index ok')
