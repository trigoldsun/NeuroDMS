const fs = require('fs')

function load(p) { return fs.readFileSync(p, 'utf8') }
function save(p, s) { fs.writeFileSync(p, s) }

// ---------- 1. 全文替换版本号与文件名引用 ----------
const files = [
  'docs/29-用户手册-场景操作-v1.10.0.md',
  'docs/30-用户手册-角色能力-v1.10.0.md',
  'docs/31-管理员手册-租户与系统配置-v1.10.0.md',
  'docs/59-小程序与主项目一致性核查-v1.10.0.md',
  'docs/E2E-验收用例与报告-v1.10.0.md',
  'docs/NeuroDMS-技术文档-v1.10.0.md',
  'docs/README-文档索引与评审说明-v1.10.0.md',
  'docs/versions.lock.md',
  'docs/html/admin.html',
  'docs/html/index.html',
  'docs/html/roles.html',
  'docs/html/scenarios.html',
]
for (const f of files) {
  let s = load(f)
  s = s.split('V1.9.0').join('V1.10.0')
  s = s.split('v1.9.0').join('v1.10.0')
  save(f, s)
}
console.log('version refs replaced')

// ---------- 2. 31 手册 §14：补两项配置 ----------
const p31 = 'docs/31-管理员手册-租户与系统配置-v1.10.0.md'
let s31 = load(p31)
const eol31 = s31.includes('\r\n') ? '\r\n' : '\n'

const rowAnchor = '| 订阅消息模板字段 | 微信公众平台 → 订阅消息 | 字段不匹配微信返回 47003，提醒发不出（业务不受影响） |'
if (!s31.includes(rowAnchor)) throw new Error('31 row anchor missing')
s31 = s31.replace(rowAnchor,
  '| 订阅消息模板字段 | 微信公众平台 → 订阅消息 | 字段不匹配微信返回 47003，提醒发不出（业务不受影响） |' + eol31 +
  '| `DOCVAULT_WX_TODO_FIELDS` | 服务端环境变量 | 模板字段名与默认四字段不同时**必须**配；不配会 47003（授权成功、余额扣了、消息不到） |' + eol31 +
  '| `DOCVAULT_WX_MP_STATE` | 服务端环境变量 | 决定点通知跳到哪个版本：`developer`/`trial`/`formal`；配错会跳到线上正式版（打不开或看到旧代码） |')

const tableAnchor = '模板字段约定（当前实现固定读这四个）：'
if (!s31.includes(tableAnchor)) throw new Error('31 table anchor missing')
s31 = s31.replace(tableAnchor, '默认模板字段（`DOCVAULT_WX_TODO_FIELDS` 留空时使用；实际以你选的模板为准）：')

const afterTable = '> 三项微信配置缺任意一项，`/v1/mp/config` 就返回 `enabled=false`，小程序**不渲染**提醒入口。'
if (!s31.includes(afterTable)) throw new Error('31 note anchor missing')
s31 = s31.replace(afterTable,
  '配置写法：`字段名=语义键`，逗号分隔。语义键固定四个：`name`（文件名称）、`requester`（申请人）、' + eol31 +
  '`time`（申请时间）、`status`（状态，当前固定"待审批"）。例如你选的模板字段是' + eol31 +
  '`character_string1/name2/time3/phrase4`，就配：' + eol31 + eol31 +
  '```' + eol31 +
  'DOCVAULT_WX_TODO_FIELDS=character_string1=name,name2=requester,time3=time,phrase4=status' + eol31 +
  '```' + eol31 + eol31 +
  '**必须与该模板的字段逐个对应**：少一个字段微信不补，多一个字段微信直接拒绝。' + eol31 +
  '服务启动时会校验这份映射，写错（缺等号、语义键拼错、同一语义用两次）会**拒绝启动**并打印原因——' + eol31 +
  '不会等到"用户授权成功却收不到消息"才暴露。' + eol31 + eol31 +
  '> 三项微信配置缺任意一项，`/v1/mp/config` 就返回 `enabled=false`，小程序**不渲染**提醒入口。')
save(p31, s31)
console.log('31 patched')

// ---------- 3. 主文档 6.18：修正"字段固定"的说法 ----------
const pm = 'docs/NeuroDMS-技术文档-v1.10.0.md'
let sm = load(pm)
const eolM = sm.includes('\r\n') ? '\r\n' : '\n'
const oldLine = '审批提醒的实现约定（`internal/mpmsg` + 迁移 0059）：'
if (!sm.includes(oldLine)) throw new Error('master anchor missing')
sm = sm.replace(oldLine,
  '审批提醒的实现约定（`internal/mpmsg` + 迁移 0059）：' + eolM + eolM +
  '- **模板字段可配置**（1.10.0）：`DOCVAULT_WX_TODO_FIELDS` 声明「字段名=语义键」，' + eolM +
  '  缺省为 `thing1/thing2/time3/phrase4`；写错在启动时被拒（否则 47003 会伪装成"授权成功但收不到"）；' + eolM +
  '- **跳转版本可配置**（1.10.0）：`DOCVAULT_WX_MP_STATE=developer|trial|formal`，' + eolM +
  '  开发/体验阶段配错会跳到线上正式版；')
save(pm, sm)
console.log('master patched')

// ---------- 4. html §14 与主文档同步 ----------
const ph = 'docs/html/admin.html'
let sh = load(ph)
const rowH = '<tr><td>订阅消息模板字段</td><td>微信公众平台 → 订阅消息</td><td>字段不匹配微信返回 47003，提醒发不出（业务不受影响）</td></tr>'
if (!sh.includes(rowH)) throw new Error('html row anchor missing')
sh = sh.replace(rowH, rowH +
  '<tr><td><code>DOCVAULT_WX_TODO_FIELDS</code></td><td>服务端环境变量</td><td>模板字段名与默认四字段不同时<b>必须</b>配；不配会 47003（授权成功、余额扣了、消息不到）</td></tr>' +
  '<tr><td><code>DOCVAULT_WX_MP_STATE</code></td><td>服务端环境变量</td><td>点通知跳转的版本：<code>developer</code>/<code>trial</code>/<code>formal</code>；配错会跳到线上正式版</td></tr>')
const noteH = '<p>小程序源码随主仓库发版'
if (!sh.includes(noteH)) throw new Error('html note anchor missing')
sh = sh.replace('<thead><tr><th>模板字段</th><th>含义</th><th>示例</th></tr></thead>',
  '<thead><tr><th>默认模板字段</th><th>含义（语义键）</th><th>示例</th></tr></thead>')
sh = sh.replace('<tr><td><code>thing1</code></td><td>文件名称（≤20 字，超出截断）</td>',
  '<tr><td><code>thing1</code></td><td>文件名称（语义键 <code>name</code>；≤20 字截断）</td>')
sh = sh.replace('<tr><td><code>thing2</code></td><td>申请人</td>', '<tr><td><code>thing2</code></td><td>申请人（<code>requester</code>）</td>')
sh = sh.replace('<tr><td><code>time3</code></td><td>申请时间</td>', '<tr><td><code>time3</code></td><td>申请时间（<code>time</code>）</td>')
sh = sh.replace('<tr><td><code>phrase4</code></td><td>状态</td>', '<tr><td><code>phrase4</code></td><td>状态（<code>status</code>；≤5 字）</td>')
sh = sh.replace(noteH,
  '<p><b>字段名可配置</b>：你选的模板字段若不是上面四个，用 <code>DOCVAULT_WX_TODO_FIELDS=字段名=语义键,…</code> 声明映射（语义键只有 name / requester / time / status）。' +
  '写错（缺等号、键拼错、同一语义用两次）服务会<b>拒绝启动</b>并打印原因，避免"授权成功却收不到"。</p>\n\n    ' + noteH)
save(ph, sh)
console.log('html patched')
