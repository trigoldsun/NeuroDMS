#!/usr/bin/env node
// 小程序链路验收：把小程序**逐页发出的请求**在 HTTP 层原样回放一遍。
//
// 为什么单独一套：主验收脚本（scripts/e2e/run.mjs）走的是网页端路径（tenantSlug+username），
// 而小程序走的是 account 单字段 + channel=mp，并且依赖"手机号已验证"这道闸门。
// 两条通道的入参不同，用网页端用例代替等于没测小程序。
//
// 设计：
//   1. 自建临时租户（business 档），结束后删除；失败保留现场并打印 slug。
//   2. 手机号验证状态用 SQL 直写——真实流程是收短信，自动化收不到。
//      这是**仅限测试开通**的旁路，不会进入任何业务代码路径。
//   3. 每一步断言都打印期望/实际，报告直接引用这段输出。
//   4. 只走公开接口（除第 2 条的手机号盖章）。
//
// 用法：
//   node scripts/e2e/miniprogram.mjs              # 全流程 + 收尾
//   node scripts/e2e/miniprogram.mjs --keep       # 保留租户（复跑调试）
//   node scripts/e2e/miniprogram.mjs --keep-going # 失败不停
//   BASE=http://127.0.0.1:18090 node scripts/e2e/miniprogram.mjs
//
// 凭据从 docker/.env 读取（DOCVAULT_PLATFORM_ADMIN / _PASSWORD），不落盘、不打印。

import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'

const BASE = process.env.BASE || 'http://127.0.0.1:18090'
const KEEP = process.argv.includes('--keep')
const KEEP_GOING = process.argv.includes('--keep-going')
// --prepare：只开通租户并铺好数据（空间/目录/文件/待审申请），保留现场供开发者工具/真机手工走一遍。
// --drop <slug>：删掉 --prepare 留下的租户。
const PREPARE = process.argv.includes('--prepare')
const dropIdx = process.argv.indexOf('--drop')

const results = []
let failed = 0
let paToken = ''
let tenantToken = ''
const ctx = {}

function log(s = '') { process.stdout.write(s + '\n') }

function env(key) {
  const raw = readFileSync(new URL('../../docker/.env', import.meta.url), 'utf8')
  const line = raw.split(/\r?\n/).find((l) => l.startsWith(key + '='))
  if (!line) throw new Error('docker/.env 缺少 ' + key)
  return line.slice(key.length + 1).replace(/^["']|["']$/g, '')
}

function pg(sql) {
  const user = env('POSTGRES_USER')
  const db = env('POSTGRES_DB')
  return execFileSync('docker', ['exec', 'docvault-postgres', 'psql', '-U', user, '-d', db, '-Atc', sql], {
    encoding: 'utf8',
  }).trim()
}

async function req(method, path, { token, body, form, raw = false, headers: extra = {} } = {}) {
  const headers = { ...extra }
  if (token) headers.authorization = 'Bearer ' + token
  let payload
  if (form) payload = form
  else if (body !== undefined) {
    headers['content-type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(BASE + path, { method, headers, body: payload })
  const text = await res.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch { /* 二进制/纯文本 */ }
  if (raw) return { status: res.status, text, json, headers: res.headers }
  return { status: res.status, text, json }
}

function ok(r, expect = 200) {
  if (r.status !== expect) {
    const e = new Error(`HTTP ${r.status}（期望 ${expect}）：${r.text.slice(0, 300)}`)
    e.response = r
    throw e
  }
  return r.json?.data
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg)
}

async function withRetry(fn, tries = 4, waitMs = 3000) {
  let last
  for (let i = 0; i < tries; i++) {
    const r = await fn()
    if (r.status !== 429) return r
    last = r
    await new Promise((res) => setTimeout(res, waitMs))
  }
  return last
}

async function step(id, name, fn) {
  process.stdout.write(`\n[${id}] ${name}\n`)
  try {
    await fn()
    results.push({ id, name, ok: true })
    log('  ✅ PASS')
  } catch (e) {
    failed++
    results.push({ id, name, ok: false, err: e.message })
    log('  ❌ FAIL: ' + e.message)
    if (!KEEP_GOING) {
      log('\n失败即停（--keep-going 可继续）。')
      await cleanup()
      summary()
      process.exit(1)
    }
  }
}

function summary() {
  const pass = results.filter((r) => r.ok).length
  log('\n──────── 汇总 ────────')
  for (const r of results) log(`${r.ok ? '✅' : '❌'} ${r.id} ${r.name}${r.ok ? '' : ' — ' + r.err}`)
  log(`\n通过 ${pass}/${results.length}`)
  if (failed) log(`租户保留：${ctx.slug}（排查完请手工删除）`)
}

async function cleanup() {
  if (!ctx.slug || !paToken || KEEP) return
  if (failed) {
    log(`\n测试失败：保留租户 ${ctx.slug} 以便复跑`)
    return
  }
  const r = await req('DELETE', `/v1/platform/tenants/${ctx.slug}`, { token: paToken })
  log(`\n清理：删除临时租户 ${ctx.slug} → HTTP ${r.status}`)
}

// ---------------- 平台侧：开一个能手写手机号的临时租户 ----------------

if (dropIdx > 0) {
  const slug = process.argv[dropIdx + 1]
  if (!slug) { log('用法：--drop <slug>'); process.exit(2) }
  const d = ok(await req('POST', '/v1/platform/auth/login', {
    body: { email: env('DOCVAULT_PLATFORM_ADMIN'), password: env('DOCVAULT_PLATFORM_ADMIN_PASSWORD') },
  }))
  const r = await req('DELETE', `/v1/platform/tenants/${slug}`, { token: d.accessToken })
  log(`删除 ${slug} → HTTP ${r.status}${r.status === 200 ? '' : ' ' + r.text.slice(0, 200)}`)
  process.exit(r.status === 200 ? 0 : 1)
}

await step('MP01', '平台账号登录', async () => {
  const d = ok(await req('POST', '/v1/platform/auth/login', {
    body: { email: env('DOCVAULT_PLATFORM_ADMIN'), password: env('DOCVAULT_PLATFORM_ADMIN_PASSWORD') },
  }))
  assert(d?.accessToken, '未返回 accessToken')
  paToken = d.accessToken
})

await step('MP02', '开通临时租户（business，含首管理员）', async () => {
  const slug = 'mpx' + Date.now().toString(36)
  const d = ok(await withRetry(() => req('POST', '/v1/platform/tenants', {
    token: paToken,
    body: {
      slug, name: '小程序链路验收', edition: 'business',
      adminUsername: 'admin', adminPassword: 'mp-pass-12345', adminDisplayName: '小程序验收',
    },
  })))
  ctx.slug = slug
  ctx.tenantId = d.tenantId
  log(`  slug=${slug}`)
})

await step('MP03', '标记手机号已验证（小程序通道的唯一凭据闸门）', async () => {
  // 真实流程：网页端绑定 → 收短信 → 校验。自动化收不到短信，测试开通走 SQL 旁路。
  const rows = pg(`update app_user u set phone='+8613800138000', phone_verified_at=now(), phone_source='self'
     from tenant t where t.id=u.tenant_id and t.slug='${ctx.slug}' and u.username='admin' returning u.id`)
  assert(rows, '未能标记手机号')
  ctx.adminId = rows.split('\n')[0].trim()
  log(`  手机号 +8613800138000 / 已验证 / userId=${ctx.adminId}`)
})

await step('MP04', '小程序口令登录（account + channel=mp）', async () => {
  const d = ok(await withRetry(() => req('POST', '/v1/auth/login', {
    body: { account: 'admin@' + ctx.slug, password: 'mp-pass-12345', channel: 'mp' },
  })))
  assert(d?.accessToken && d?.refreshToken, '未签发令牌')
  tenantToken = d.accessToken
  ctx.refresh = d.refreshToken
})

await step('MP05', '/v1/me 返回小程序依赖的四个字段', async () => {
  const d = ok(await req('GET', '/v1/me', { token: tenantToken }))
  assert(d.phoneVerified === true, `phoneVerified 应为 true，实际 ${d.phoneVerified}`)
  // 掩码形如 138****8000：只保留首 3 后 4，中间四位打码
  assert(/^\d{3}\*{4}\d{4}$/.test(String(d.phoneMasked || '')), `phoneMasked 格式异常：${d.phoneMasked}`)
  assert(Array.isArray(d.roles) && d.roles.includes('sysadmin'), `roles 应含 sysadmin，实际 ${JSON.stringify(d.roles)}`)
  assert(d.classification === 6, `首管理员密级应为档位上限 6，实际 ${d.classification}`)
  assert(d.tenantSlug === ctx.slug, `tenantSlug 应为 ${ctx.slug}，实际 ${d.tenantSlug}`)
})

await step('MP06', '密级定义（小程序文案的唯一来源）', async () => {
  const d = ok(await req('GET', '/v1/classifications', { token: tenantToken }))
  const items = d.items || []
  assert(items.length === 7, `应有 7 档，实际 ${items.length}`)
  assert(items.every((x) => typeof x.level === 'number' && !!x.name), '每档必须有 level 与 name')
  ctx.levelNames = items.map((x) => x.name)
  log(`  ${ctx.levelNames.join(' / ')}`)
})

await step('MP07', '租户品牌（标题/名称/图标三要素）', async () => {
  const d = ok(await req('GET', '/v1/tenant/branding?slug=' + ctx.slug))
  assert(d.productName, 'productName 为空')
  ctx.productName = d.productName
  log(`  productName=${d.productName} logo=${d.logoUrl || '（无）'}`)
})

await step('MP08', '内容：建空间 → 建目录 → 传文件', async () => {
  const sp = ok(await req('POST', '/v1/spaces', { token: tenantToken, body: { kind: 'project', name: '小程序验收空间' } }))
  ctx.spaceId = sp.spaceId
  const fd = ok(await req('POST', `/v1/spaces/${ctx.spaceId}/folders`, {
    token: tenantToken, body: { name: '合同' },
  }))
  ctx.folderId = fd.nodeId || fd.folderId
  const form = new FormData()
  form.append('file', new Blob(['小程序链路验收文件\n第二行\n'], { type: 'text/plain' }), '验收说明.txt')
  form.append('parentId', ctx.folderId)
  const up = ok(await req('POST', `/v1/spaces/${ctx.spaceId}/files`, { token: tenantToken, form }))
  ctx.fileId = up.nodeId || up.id
  assert(ctx.fileId, '上传未返回 nodeId')
})

await step('MP09', '文件页：空间列表与根目录列表（列表永不为 null）', async () => {
  const sp = ok(await req('GET', '/v1/spaces', { token: tenantToken }))
  assert(Array.isArray(sp.items), `space.items 应为数组，实际 ${typeof sp.items}`)
  assert(sp.items.some((x) => x.id === ctx.spaceId), '新空间不在列表里')
  const nodes = ok(await req('GET', `/v1/spaces/${ctx.spaceId}/nodes`, { token: tenantToken }))
  assert(Array.isArray(nodes.items), 'nodes.items 应为数组')
  assert(nodes.items.some((x) => x.id === ctx.folderId), '根目录里找不到「合同」')
  const inner = ok(await req('GET', `/v1/spaces/${ctx.spaceId}/nodes?parentId=${ctx.folderId}`, { token: tenantToken }))
  const f = (inner.items || []).find((x) => x.id === ctx.fileId)
  assert(f, '目录里找不到刚上传的文件')
  assert(f.kind === 'file' && typeof f.size === 'number', `文件行字段异常：${JSON.stringify(f).slice(0, 160)}`)
  ctx.fileName = f.name
})

await step('MP10', '节点元信息 + 预览（走 preview 不是 content）', async () => {
  const meta = ok(await req('GET', `/v1/nodes/${ctx.fileId}`, { token: tenantToken }))
  assert(meta.name === ctx.fileName, `名称不一致：${meta.name} vs ${ctx.fileName}`)
  assert(typeof meta.versionNo === 'number', `versionNo 缺失：${JSON.stringify(meta).slice(0, 120)}`)
  const pv = await req('GET', `/v1/nodes/${ctx.fileId}/preview`, { token: tenantToken, raw: true })
  assert(pv.status === 200, `预览应 200，实际 ${pv.status}`)
  assert(pv.text.includes('小程序链路验收文件'), '预览内容与上传内容不一致')
  // 审计：预览必须留痕（"谁在什么时候看了哪份文件"）
  const act = ok(await req('GET', '/v1/me/activity?size=20', { token: tenantToken }))
  assert(Array.isArray(act.items), 'activity.items 应为数组')
  assert(act.items.some((x) => String(x.objectId || '') === ctx.fileId), '预览后最近活动里没有该文件')
})

await step('MP11', '搜索（文件页顶部新入口）', async () => {
  const d = ok(await req('GET', '/v1/search?q=' + encodeURIComponent('验收') + '&limit=20', { token: tenantToken }))
  assert(Array.isArray(d.items), 'search.items 应为数组')
  assert(d.items.some((x) => x.nodeId === ctx.fileId), '搜索没有命中刚上传的文件')
  const none = ok(await req('GET', '/v1/search?q=' + encodeURIComponent('zzz-不该命中'), { token: tenantToken }))
  assert(none.items.length === 0, `无关键词应 0 条，实际 ${none.items.length}`)
  assert(none.truncated === false, '无结果时 truncated 应为 false')
})

await step('MP12', '待办：他人发起、指定我为审批人', async () => {
  const m = ok(await req('POST', '/v1/admin/members', {
    token: tenantToken,
    body: { username: 'mprequester', displayName: '小程序申请人', password: 'mp-req-pass-1', classification: 3 },
  }))
  ctx.requesterId = m.id
  const g = await req('POST', '/v1/acl', {
    token: tenantToken,
    body: { objectType: 'space', objectId: ctx.spaceId, subjectType: 'user', subjectId: m.id, preset: 'owner' },
  })
  assert(g.status === 200, `授权失败 HTTP ${g.status}: ${g.text.slice(0, 200)}`)
  const login = ok(await withRetry(() => req('POST', '/v1/auth/login', {
    body: { tenantSlug: ctx.slug, username: 'mprequester', password: 'mp-req-pass-1' },
  })))
  const sh = await req('POST', '/v1/shares', {
    token: login.accessToken,
    body: {
      kind: 'link', objectType: 'node', objectId: ctx.fileId,
      requireApproval: true, approverId: ctx.adminId, expiresInHours: 24,
    },
  })
  assert(sh.status === 200, `建申请失败 HTTP ${sh.status}: ${sh.text.slice(0, 200)}`)
  ctx.shareId = sh.json?.data?.shareId
  assert(ctx.shareId, '未返回 shareId')
  // 手动勾选"需要审批"时，服务端必须采纳指定审批人并落库；
  // 落空就是一条 pending 却无人可批的死链（1.11.2 修复前正是如此）。
  assert(sh.json?.data?.approver?.id === ctx.adminId,
    '响应应回显审批人，实际 ' + JSON.stringify(sh.json?.data?.approver || null))
})

await step('MP12b', '勾选需要审批但未指定审批人：必须 400，不得生成死链', async () => {
  const login = ok(await withRetry(() => req('POST', '/v1/auth/login', {
    body: { tenantSlug: ctx.slug, username: 'mprequester', password: 'mp-req-pass-1' },
  })))
  const r = await req('POST', '/v1/shares', {
    token: login.accessToken,
    body: { kind: 'link', objectType: 'node', objectId: ctx.fileId, requireApproval: true, expiresInHours: 24 },
  })
  assert(r.status === 400, '缺审批人应 400，实际 ' + r.status + ' ' + r.text.slice(0, 120))
  assert(r.json?.code === 'APPROVER_REQUIRED', '错误码应为 APPROVER_REQUIRED，实际 ' + r.json?.code)
})

if (PREPARE) {
  // 停在"有数据、有待审申请"的状态，把凭据打到 stdout（人工/自动化都从这里取）。
  log('\n──────── 已准备就绪（--prepare）────────')
  log(JSON.stringify({
    base: BASE,
    slug: ctx.slug,
    account: 'admin@' + ctx.slug,
    password: 'mp-pass-12345',
    spaceId: ctx.spaceId,
    folderId: ctx.folderId,
    fileId: ctx.fileId,
    shareId: ctx.shareId,
    productName: ctx.productName,
    levelNames: ctx.levelNames,
  }, null, 2))
  log(`\n用完删除：node scripts/e2e/miniprogram.mjs --drop ${ctx.slug}`)
  process.exit(0)
}

await step('MP13', '审批页：待办列表字段齐全（stage 枚举必须是 none|first|owner|done）', async () => {
  const d = ok(await req('GET', '/v1/shares/pending', { token: tenantToken }))
  const item = (d.items || []).find((x) => x.shareId === ctx.shareId)
  assert(item, '待办里找不到刚发起的申请')
  assert(typeof item.name === 'string' && item.name, 'name 缺失')
  assert(typeof item.creator === 'string' && item.creator, 'creator 缺失')
  assert(typeof item.classification === 'number', 'classification 缺失')
  assert(['none', 'first', 'owner', 'done'].includes(item.stage), `stage 非法：${item.stage}`)
  assert(!!item.createdAt, 'createdAt 缺失')
  assert(!!item.approverName, 'approverName 不能为空（空值说明这条 pending 无人可批）')
  ctx.stage = item.stage
  log(`  stage=${item.stage} classification=${item.classification} creator=${item.creator}`)
})

await step('MP14', '审批详情：通过后待办清空', async () => {
  const r = await req('POST', `/v1/shares/${ctx.shareId}/approve`, { token: tenantToken, body: { approve: true } })
  assert(r.status === 200, `审批失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
  const d = ok(await req('GET', '/v1/shares/pending', { token: tenantToken }))
  assert(!(d.items || []).some((x) => x.shareId === ctx.shareId), '通过后仍在待办里')
})

await step('MP15', '令牌刷新与退出（401 自动刷新一次的单飞路径）', async () => {
  const d = ok(await req('POST', '/v1/auth/refresh', { body: { refreshToken: ctx.refresh } }))
  assert(d?.accessToken, '刷新未返回 accessToken')
  tenantToken = d.accessToken
  ctx.refresh = d.refreshToken || ctx.refresh
  ok(await req('POST', '/v1/auth/logout', { token: tenantToken, body: { refreshToken: ctx.refresh } }))
})

await step('MP16', 'MFA 账号：没有可投递邮箱时 fail-closed（不签发令牌、不泄露口令对错）', async () => {
  const m = ok(await req('POST', '/v1/admin/members', {
    token: (await loginAsAdmin()).accessToken,
    body: { username: 'mpmfa', displayName: '小程序MFA', password: 'mp-mfa-pass-1', classification: 3 },
  }))
  assert(m.id, '建号失败')
  pg(`update app_user set phone='+8613800138001', phone_verified_at=now(), phone_source='self', mfa_required=true
      from tenant t where t.id=app_user.tenant_id and t.slug='${ctx.slug}' and app_user.username='mpmfa'`)
  const r = await req('POST', '/v1/auth/login', {
    body: { account: 'mpmfa@' + ctx.slug, password: 'mp-mfa-pass-1', channel: 'mp' },
  })
  // 二次验证走邮件；账号没配邮箱时服务端拒绝登录（fail-closed），而不是"跳过二次验证"。
  // 正路径（202 → 输码 → 令牌）需要真实邮箱通道，这里只锁住"不会误放行"与"不签发令牌"。
  assert(r.status === 403, `应 403 fail-closed，实际 ${r.status}: ${r.text.slice(0, 160)}`)
  assert(r.json?.code === 'ACCOUNT_DISABLED', `错误码应为 ACCOUNT_DISABLED，实际 ${r.json?.code}`)
  assert(!r.json?.data?.accessToken, '失败不应签发令牌')
})

await step('MP17', '伪造 MFA 挑战不能换令牌', async () => {
  const r = await req('POST', '/v1/auth/mfa/verify', { body: { challenge: 'forged.challenge.value', code: '000000' } })
  assert(r.status >= 400 && r.status < 500, `伪造挑战应 4xx，实际 ${r.status}`)
  assert(!r.json?.data?.accessToken, '失败不应签发令牌')
})

await step('MP18', '提醒能力随配置翻转：未配置时隐藏入口，已配置时下发模板且伪造 code 被拒', async () => {
  const tk = (await loginAsAdmin()).accessToken
  const d = ok(await req('GET', '/v1/mp/config', { token: tk }))
  assert(typeof d.enabled === 'boolean', 'enabled 必须是布尔，实际 ' + typeof d.enabled)
  assert(d.openidBound === false, '新租户账号不应已绑定 openid')

  if (!d.enabled) {
    // 未配置 DOCVAULT_WX_*：入口整体隐藏，绑定接口必须 501 而不是静默成功
    assert(d.todoSubscribeTemplateId === '', '未启用时不应下发模板，实际 ' + d.todoSubscribeTemplateId)
    const b = await req('POST', '/v1/mp/bind', { token: tk, body: { code: 'x' } })
    assert(b.status === 501, '未配置时绑定应 501 NOT_CONFIGURED，实际 ' + b.status)
    assert(b.json?.code === 'NOT_CONFIGURED', '错误码应为 NOT_CONFIGURED，实际 ' + b.json?.code)
  } else {
    // 已配置：必须下发模板 ID；伪造 code 会被微信拒绝（证明真的在调微信）
    assert(String(d.todoSubscribeTemplateId).length > 10, '启用时必须下发模板 ID，实际 ' + d.todoSubscribeTemplateId)
    log('  模板=' + d.todoSubscribeTemplateId)
    const b = await req('POST', '/v1/mp/bind', { token: tk, body: { code: 'fake-code-for-e2e' } })
    assert(b.status === 400, '伪造 code 应 400，实际 ' + b.status)
    assert(b.json?.code === 'MP_BIND_FAILED', '错误码应为 MP_BIND_FAILED，实际 ' + b.json?.code)
  }
})

async function loginAsAdmin() {
  return ok(await withRetry(() => req('POST', '/v1/auth/login', {
    body: { account: 'admin@' + ctx.slug, password: 'mp-pass-12345', channel: 'mp' },
  })))
}

await cleanup()
summary()
if (failed) process.exit(1)
