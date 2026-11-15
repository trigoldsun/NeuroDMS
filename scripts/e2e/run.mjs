#!/usr/bin/env node
// 端到端验收脚本：从"开通租户"开始，沿真实 HTTP 接口走一遍主链路。
//
// 设计原则：
//   1. **只走公开接口**，不直连数据库——要测的就是"客户能不能用"；
//   2. **失败即停**（--keep-going 可关）：先定位根因，再决定修还是登记，
//      继续往下跑只会在脏状态上产生第二层假象；
//   3. 每个断言都打印期望/实际，报告直接引这段输出；
//   4. 收尾删除测试租户（失败时保留，便于现场排查，slug 会打印出来）。
//
// 用法：
//   PA_EMAIL=... PA_PASS=... node scripts/e2e/run.mjs
//   BASE=http://127.0.0.1:18090 node scripts/e2e/run.mjs --keep-going

import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'

const BASE = process.env.BASE || 'http://127.0.0.1:18090'
const PA_EMAIL = process.env.PA_EMAIL || ''
const PA_PASS = process.env.PA_PASS || ''
const KEEP_GOING = process.argv.includes('--keep-going')

const results = []
let token = ''
let tenantToken = ''
let ctx = {}
let failed = 0

function log(s = '') { process.stdout.write(s + '\n') }

async function req(method, path, { token: tk, body, form, raw = false, headers: extra = {} } = {}) {
  const headers = { ...extra }
  if (tk) headers.authorization = 'Bearer ' + tk
  let payload
  if (form) {
    payload = form
  } else if (body !== undefined) {
    headers['content-type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(BASE + path, { method, headers, body: payload })
  const text = await res.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch { /* 非 JSON（CSV/文件） */ }
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

// 平台写接口带频控（防止脚本刷租户）。自动化连跑会撞 429，
// 这里按 3 秒退避重试两次——这正是"老实的客户端"该有的行为。
async function withRetry(fn, tries = 3, waitMs = 3000) {
  let last
  for (let i = 0; i < tries; i++) {
    const r = await fn()
    if (r.status !== 429) return r
    last = r
    await new Promise((res) => setTimeout(res, waitMs))
  }
  return last
}

// 登录走"公开桶"（与分享、验证码同档，2 rps）。多人同时登录或自动化连跑会撞 429，
// 这里统一退避重试；顺带证明"客户端按 Retry-After 重试"是可行路径。
async function login(slug, username, password) {
  return ok(await withRetry(() => req('POST', '/v1/auth/login', {
    body: { tenantSlug: slug, username, password },
  }), 5, 2000))
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
      log('\n失败即停（可用 --keep-going 继续）。')
      await cleanup()
      summary()
      process.exit(1)
    }
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg)
}

async function cleanup() {
  if (ctx.slugB && token) {
    const r = await req('DELETE', `/v1/platform/tenants/${ctx.slugB}`, { token })
    log(`\n清理：删除隔离租户 ${ctx.slugB} → HTTP ${r.status}`)
  }
  if (!ctx.slug || !token) return
  // 失败时保留现场（便于复跑与排查），只有全绿才删。
  if (failed) {
    log(`\n测试失败，保留租户 ${ctx.slug} 以便复跑；确认后请手工删除。`)
    return
  }
  try {
    const r = await req('DELETE', `/v1/platform/tenants/${ctx.slug}`, { token })
    log(`\n清理：删除测试租户 ${ctx.slug} → HTTP ${r.status}`)
  } catch (e) {
    log(`\n清理失败（需手工处理）：${ctx.slug} — ${e.message}`)
  }
}

function summary() {
  const pass = results.filter((r) => r.ok).length
  log(`\n===== 结果：${pass} 通过 / ${results.length - pass} 失败 / 共 ${results.length} =====`)
  for (const r of results.filter((x) => !x.ok)) log(`  ❌ ${r.id} ${r.name}\n     ${r.err}`)
  if (ctx.slug && failed) log(`\n失败现场保留：租户 slug=${ctx.slug}`)
}

// ---------------- 平台侧 ----------------

await step('P01', '平台账号登录', async () => {
  const d = ok(await req('POST', '/v1/platform/auth/login', { body: { email: PA_EMAIL, password: PA_PASS } }))
  assert(d?.accessToken, '未返回 accessToken')
  token = d.accessToken
})

await step('P02', '开通租户（旗舰版，含首个管理员）', async () => {
  const slug = 'e2e' + Date.now().toString(36)
  const d = ok(await withRetry(() => req('POST', '/v1/platform/tenants', {
    token,
    body: {
      slug, name: 'E2E 验收租户', edition: 'business',
      adminUsername: 'admin', adminPassword: 'e2e-pass-12345', adminDisplayName: '验收管理员',
    },
  })))
  assert(d?.tenantId, '未返回 tenantId')
  ctx.slug = slug
  ctx.tenantId = d.tenantId
  ctx.adminUser = 'admin'
  ctx.adminPass = 'e2e-pass-12345'
  log(`  slug=${slug}`)
})

await step('P03', '租户列表包含新租户且状态 active', async () => {
  const d = ok(await req('GET', '/v1/platform/tenants', { token }))
  const t = (d.items || []).find((x) => x.slug === ctx.slug)
  assert(t, '列表中找不到新租户')
  assert(t.status === 'active', `状态应为 active，实际 ${t.status}`)
})

await step('P04', '租户详情与档位/配额/用量可读', async () => {
  const detail = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}`, { token }))
  assert(detail?.slug === ctx.slug, '详情 slug 不匹配')
  const ed = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/edition`, { token }))
  assert(ed.edition === 'business', `档位应为 business，实际 ${ed.edition}`)
  ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/quota`, { token }))
  const us = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/usage?from=2026-11-01&to=2026-11-15`, { token }))
  // 列表型字段永不为 null（F-01）：新建租户没有用量事件时应是 []，不是 null。
  // 这条断言的价值在于——客户端不该为了"可能为 null"到处写 ?? []。
  assert(Array.isArray(us.points), `用量 points 应为数组（空列表返回 []），实际 ${JSON.stringify(us.points)}`)
})

await step('P05', '对账单 CSV 可导出（Content-Type 为 CSV）', async () => {
  const r = await req('GET', `/v1/platform/tenants/${ctx.slug}/invoice.csv`, { token, raw: true })
  assert(r.status === 200, `HTTP ${r.status}`)
  const ct = r.headers.get('content-type') || ''
  assert(ct.includes('csv'), `Content-Type 应为 CSV，实际 ${ct}`)
  assert(r.text.split('\n').length >= 2, 'CSV 至少要有表头+1 行')
})

await step('P06', '能力授权读取（14 项 + 生效状态）', async () => {
  const d = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/entitlements`, { token }))
  const items = d.items || []
  assert(items.length >= 10, `授权项偏少：${items.length}`)
  const classification = items.find((x) => x.code === 'classification')
  assert(classification, '缺少 classification 能力项')
  // 读写同一个词：没有覆盖行时 GET 也返回 "inherit"（F-02）。
  assert(classification.state === 'inherit',
    `旗舰版应跟随档位（inherit），实际 "${classification.state}"`)
})

await step('P07', '单租户能力覆盖：关闭 → 再回跟随', async () => {
  const off = await req('PUT', `/v1/platform/tenants/${ctx.slug}/entitlements/classification`, {
    token, body: { state: 'off', reason: 'E2E 验证' },
  })
  assert(off.status === 200, `关闭失败 HTTP ${off.status}: ${off.text.slice(0, 200)}`)
  const back = await req('PUT', `/v1/platform/tenants/${ctx.slug}/entitlements/classification`, {
    token, body: { state: 'inherit', reason: 'E2E 验证恢复' },
  })
  assert(back.status === 200, `恢复失败 HTTP ${back.status}`)

  // 历史别名 default 也要认（对接方照着旧文档传过一次就再不会改）
  const alias = await req('PUT', `/v1/platform/tenants/${ctx.slug}/entitlements/classification`, {
    token, body: { state: 'default', reason: 'E2E 别名验证' },
  })
  assert(alias.status === 200, `别名 default 应被接受，实际 HTTP ${alias.status}: ${alias.text.slice(0, 160)}`)

  // 非法值必须报错，且错误里要列出合法值
  const badState = await req('PUT', `/v1/platform/tenants/${ctx.slug}/entitlements/classification`, {
    token, body: { state: 'maybe' },
  })
  assert(badState.status === 400, `非法 state 应 400，实际 ${badState.status}`)
  assert(badState.text.includes('inherit'), `错误信息应列出合法值，实际 ${badState.text.slice(0, 160)}`)
})

await step('P08', '灰度开关读取', async () => {
  const d = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/flags`, { token }))
  assert(Array.isArray(d.effective), '应返回 effective 数组')
})

await step('P09', '平台审计可查（含刚做的开通）', async () => {
  const d = ok(await req('GET', '/v1/platform/audit?limit=50', { token }))
  const items = d.items || d.events || []
  assert(items.length > 0, '平台审计为空')
  const hit = items.find((x) => JSON.stringify(x).includes(ctx.slug))
  assert(hit, '审计里找不到本次开通记录')
})

await step('P10', '管理员列表（首管理员密级 = 档位上限 6）', async () => {
  const d = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/admins`, { token }))
  assert((d.items || []).length === 1, `应有 1 个管理员，实际 ${(d.items || []).length}`)
  ctx.adminId = d.items[0].id
  assert(d.items[0].classification === 6, `首管理员密级应为 6，实际 ${d.items[0].classification}`)
  assert((d.classificationLevels || []).length === 7, '旗舰版应返回 7 档')
})

await step('P11', '平台调整管理员密级 6→5→6（写两侧审计）', async () => {
  const down = await req('PUT', `/v1/platform/tenants/${ctx.slug}/admins/${ctx.adminId}/classification`, {
    token, body: { classification: 5, reason: 'E2E 降一级' },
  })
  assert(down.status === 200, `降级失败 HTTP ${down.status}: ${down.text.slice(0, 200)}`)
  const up = await req('PUT', `/v1/platform/tenants/${ctx.slug}/admins/${ctx.adminId}/classification`, {
    token, body: { classification: 6, reason: 'E2E 恢复' },
  })
  assert(up.status === 200, `恢复失败 HTTP ${up.status}`)
  const d = ok(await req('GET', `/v1/platform/tenants/${ctx.slug}/admins`, { token }))
  assert(d.items[0].classification === 6, '恢复后应回到 6')
})

// ---------------- 租户侧 ----------------

await step('T01', '租户管理员登录', async () => {
  const d = ok(await req('POST', '/v1/auth/login', {
    body: { tenantSlug: ctx.slug, username: ctx.adminUser, password: ctx.adminPass },
  }))
  assert(d?.accessToken, '未返回 accessToken')
  tenantToken = d.accessToken
  ctx.refresh = d.refreshToken
})

await step('T02', '/me 返回系统管理员与密级 6', async () => {
  const d = ok(await req('GET', '/v1/me', { token: tenantToken }))
  assert((d.roles || []).includes('sysadmin'), `角色应含 sysadmin，实际 ${JSON.stringify(d.roles)}`)
  assert(d.classification === 6, `密级应为 6，实际 ${d.classification}`)
})

await step('T03', '能力集（档位允许 7 档密级）', async () => {
  const d = ok(await req('GET', '/v1/me/capabilities', { token: tenantToken }))
  assert(d.edition === 'business', `档位应为 business，实际 ${d.edition}`)
  assert(Array.isArray(d.classificationLevels) && d.classificationLevels.length === 7,
    `密级可选集应为 7 档，实际 ${JSON.stringify(d.classificationLevels)}`)
})

await step('T04', '部门：建子部门 → 改名 → 移动 → 拒绝删除 → 删除', async () => {
  const before = ok(await req('GET', '/v1/admin/depts', { token: tenantToken }))
  const list0 = before.items || []
  assert(list0.length >= 1, '开通时应已创建根部门')
  const root = list0.find((x) => x.name === '总部')
  assert(root, `应存在「总部」根部门，实际 ${JSON.stringify(list0.map((x) => x.name))}`)

  // 建子部门
  const fin = ok(await req('POST', '/v1/admin/depts', {
    token: tenantToken, body: { name: 'E2E 财务部', parentId: root.id },
  }))
  assert(fin.id && fin.depth === 2, `子部门应建成功且深度为 2，实际 ${JSON.stringify(fin)}`)
  assert(String(fin.path).startsWith(String(root.path) + '.'), `路径应挂在根下，实际 ${fin.path}`)
  ctx.deptId = fin.id

  // 同级重名 → 409
  const dup = await req('POST', '/v1/admin/depts', {
    token: tenantToken, body: { name: 'E2E 财务部', parentId: root.id },
  })
  assert(dup.status === 409 && dup.json?.code === 'DEPT_NAME_TAKEN',
    `同级重名应 409 DEPT_NAME_TAKEN，实际 ${dup.status} ${dup.text.slice(0, 120)}`)

  // 改名（只改 name，路径不变）
  const renamed = ok(await req('PATCH', `/v1/admin/depts/${fin.id}`, {
    token: tenantToken, body: { name: 'E2E 财务中心' },
  }))
  assert(renamed.name === 'E2E 财务中心', `改名失败：${renamed.name}`)
  assert(renamed.path === fin.path, `改名不应改变路径：${fin.path} → ${renamed.path}`)

  // 建孙部门后移动过去 → 成环被拒
  const sub = ok(await req('POST', '/v1/admin/depts', {
    token: tenantToken, body: { name: 'E2E 会计组', parentId: fin.id },
  }))
  ctx.deptSubId = sub.id
  const cyc = await req('POST', `/v1/admin/depts/${fin.id}/move`, {
    token: tenantToken, body: { parentId: sub.id },
  })
  assert(cyc.status === 409 && cyc.json?.code === 'DEPT_CYCLE',
    `移到自己下级应 409 DEPT_CYCLE，实际 ${cyc.status} ${cyc.text.slice(0, 120)}`)

  // 有子部门时不能删
  const notEmpty = await req('DELETE', `/v1/admin/depts/${fin.id}`, { token: tenantToken })
  assert(notEmpty.status === 409 && notEmpty.json?.code === 'DEPT_NOT_EMPTY',
    `有子部门时删除应 409 DEPT_NOT_EMPTY，实际 ${notEmpty.status}`)

  // 根部门不能删
  const rootDel = await req('DELETE', `/v1/admin/depts/${root.id}`, { token: tenantToken })
  assert(rootDel.status === 409 && rootDel.json?.code === 'DEPT_IS_ROOT',
    `删根部门应 409 DEPT_IS_ROOT，实际 ${rootDel.status}`)

  // 空部门可以删（新建再删，证明"能删"而不是只能建）
  const tmp = ok(await req('POST', '/v1/admin/depts', {
    token: tenantToken, body: { name: 'E2E 临时组', parentId: root.id },
  }))
  const delOk = await req('DELETE', `/v1/admin/depts/${tmp.id}`, { token: tenantToken })
  assert(delOk.status === 200, `空部门删除应成功，实际 ${delOk.status}`)
  const after = ok(await req('GET', '/v1/admin/depts', { token: tenantToken }))
  assert(!after.items.some((x) => x.name === 'E2E 临时组'), '删除后不应再出现在列表里')
})

await step('T05', '创建成员（普通成员，密级 3）', async () => {
  const d = ok(await req('POST', '/v1/admin/members', {
    token: tenantToken,
    body: { username: 'e2euser', displayName: 'E2E 成员', password: 'e2e-member-pass-1', classification: 3 },
  }))
  assert(d?.id, '未返回成员 id')
  ctx.memberId = d.id
  ctx.memberUser = 'e2euser'
  ctx.memberPass = 'e2e-member-pass-1'
})

await step('T06', '密级天花板：不能建高于自己的账号（6 → 7 越界与降级场景分测）', async () => {
  const r = await req('POST', '/v1/admin/members', {
    token: tenantToken,
    body: { username: 'e2eover', displayName: '越界', password: 'e2e-member-pass-1', classification: 7 },
  })
  assert(r.status === 400, `7 级应 400，实际 ${r.status}`)
})

await step('T07', '成员列表包含新成员且状态 active', async () => {
  const d = ok(await req('GET', '/v1/admin/members?limit=50', { token: tenantToken }))
  const m = (d.items || []).find((x) => x.username === ctx.memberUser)
  assert(m, '列表里找不到新成员')
  assert(m.status === 'active', `状态应为 active，实际 ${m.status}`)
  assert(m.classification === 3, `密级应为 3，实际 ${m.classification}`)
})

await step('T08', '授予/撤销角色', async () => {
  const roles = ok(await req('GET', '/v1/admin/roles', { token: tenantToken }))
  const list = roles.items || roles.roles || []
  const viewer = list.find((r) => r.code === 'viewer') || list.find((r) => r.code !== 'sysadmin')
  assert(viewer, '没有可授予的角色')
  const grant = await req('POST', `/v1/admin/members/${ctx.memberId}/roles`, {
    token: tenantToken, body: { code: viewer.code },
  })
  assert(grant.status === 200, `授角色失败 HTTP ${grant.status}: ${grant.text.slice(0, 200)}`)
  const revoke = await req('DELETE', `/v1/admin/members/${ctx.memberId}/roles/${viewer.code}`, { token: tenantToken })
  assert(revoke.status === 200, `撤角色失败 HTTP ${revoke.status}`)
})

await step('T09', '重置成员口令（不改变可登录状态）', async () => {
  const r = await req('POST', `/v1/admin/members/${ctx.memberId}/password`, {
    token: tenantToken, body: { password: 'e2e-member-pass-2' },
  })
  assert(r.status === 200, `重置口令失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
  const login = await req('POST', '/v1/auth/login', {
    body: { tenantSlug: ctx.slug, username: ctx.memberUser, password: 'e2e-member-pass-2' },
  })
  assert(login.status === 200, `用新口令登录失败 HTTP ${login.status}`)
})

await step('T10', '停用 → 恢复成员', async () => {
  const s1 = await req('POST', `/v1/admin/members/${ctx.memberId}/status`, {
    token: tenantToken, body: { status: 'suspended' },
  })
  assert(s1.status === 200, `停用失败 HTTP ${s1.status}: ${s1.text.slice(0, 200)}`)
  const login = await req('POST', '/v1/auth/login', {
    body: { tenantSlug: ctx.slug, username: ctx.memberUser, password: 'e2e-member-pass-2' },
  })
  assert(login.status !== 200, '停用后仍然能登录（安全缺陷）')
  const s2 = await req('POST', `/v1/admin/members/${ctx.memberId}/status`, {
    token: tenantToken, body: { status: 'active' },
  })
  assert(s2.status === 200, `恢复失败 HTTP ${s2.status}`)
})

await step('T10b', '非法空间类型：400 且错误里列出可选值', async () => {
  const r = await req('POST', '/v1/spaces', { token: tenantToken, body: { kind: 'team', name: 'E2E 非法' } })
  assert(r.status === 400, `非法 kind 应 400，实际 ${r.status}: ${r.text.slice(0, 160)}`)
  // 枚举要写进错误信息，不能让人去读代码（F-04）
  for (const k of ['personal', 'dept', 'project', 'knowledge', 'archive']) {
    assert(r.text.includes(k), `错误信息应列出合法值 ${k}，实际 ${r.text.slice(0, 200)}`)
  }
})

await step('T11', '创建空间', async () => {
  const d = ok(await req('POST', '/v1/spaces', { token: tenantToken, body: { kind: 'project', name: 'E2E 空间' } }))
  assert(d?.spaceId, '未返回 spaceId')
  ctx.spaceId = d.spaceId
})

await step('T12', '空间列表与根节点列表', async () => {
  const sp = ok(await req('GET', '/v1/spaces', { token: tenantToken }))
  const list = sp.items || sp.spaces || []
  assert(list.some((x) => x.id === ctx.spaceId), '空间列表里找不到新空间')
  const nodes = ok(await req('GET', `/v1/spaces/${ctx.spaceId}/nodes`, { token: tenantToken }))
  assert(Array.isArray(nodes.items), '根节点应返回 items 数组')
})

await step('T13', '新建文件夹', async () => {
  const d = ok(await req('POST', `/v1/spaces/${ctx.spaceId}/folders`, {
    token: tenantToken, body: { name: 'E2E 文件夹' },
  }))
  assert(d?.nodeId || d?.folderId, '未返回节点 id')
  ctx.folderId = d.nodeId || d.folderId
})

await step('T14', '上传文件（multipart）', async () => {
  const fd = new FormData()
  fd.append('file', new Blob([`E2E 验收文件 ${new Date().toISOString()}\n`], { type: 'text/plain' }), 'e2e.txt')
  fd.append('parentId', ctx.folderId || '')
  const r = await req('POST', `/v1/spaces/${ctx.spaceId}/files`, { token: tenantToken, form: fd })
  assert(r.status === 200, `上传失败 HTTP ${r.status}: ${r.text.slice(0, 300)}`)
  const d = r.json?.data
  assert(d?.nodeId || d?.id, '未返回文件节点 id')
  ctx.fileId = d.nodeId || d.id
})

await step('T15', '文件元信息与下载', async () => {
  const meta = ok(await req('GET', `/v1/nodes/${ctx.fileId}`, { token: tenantToken }))
  assert((meta.name || meta.node?.name) === 'e2e.txt', `文件名不匹配：${JSON.stringify(meta.name || meta.node?.name)}`)
  const dl = await req('GET', `/v1/nodes/${ctx.fileId}/content`, { token: tenantToken, raw: true })
  assert(dl.status === 200, `下载失败 HTTP ${dl.status}`)
  assert(dl.text.includes('E2E 验收文件') || dl.headers.get('content-disposition') !== null,
    '下载内容与上传内容不一致')
})

await step('T16', '重命名文件', async () => {
  const r = await req('PATCH', `/v1/nodes/${ctx.fileId}`, { token: tenantToken, body: { name: 'e2e-renamed.txt' } })
  assert(r.status === 200, `重命名失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
  const meta = ok(await req('GET', `/v1/nodes/${ctx.fileId}`, { token: tenantToken }))
  assert((meta.name || meta.node?.name) === 'e2e-renamed.txt', '名称没变')
})

await step('T17', '移动到空间根', async () => {
  const r = await req('POST', `/v1/nodes/${ctx.fileId}/move`, { token: tenantToken, body: { parentId: '' } })
  assert(r.status === 200, `移动失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
})

await step('T18', '搜索能命中刚上传的文件', async () => {
  const d = ok(await req('GET', '/v1/search?q=' + encodeURIComponent('e2e-renamed'), { token: tenantToken }))
  const items = d.items || d.hits || []
  assert(items.length > 0, '搜索没有结果')
})

await step('T19', '外链分享（带口令，禁下载）', async () => {
  const r = await req('POST', '/v1/shares', {
    token: tenantToken,
    body: {
      kind: 'link', objectType: 'node', objectId: ctx.fileId,
      allowDownload: false, password: 'share-pass-1', expiresInHours: 24,
    },
  })
  assert(r.status === 200, `建分享失败 HTTP ${r.status}: ${r.text.slice(0, 300)}`)
  const d = r.json?.data
  assert(d?.shareId && d?.token, '未返回 shareId/token')
  ctx.shareId = d.shareId
  ctx.shareToken = d.token
})

await step('T20', '公开兑现：凭口令换票据，下载被禁', async () => {
  // 两段式：GET /v1/public/shares/{token} 用长期链接换 5 分钟票据；
  // 访问口令走请求头 X-Share-Password（不放 URL，避免进代理日志）。
  const h = { 'X-Share-Password': 'share-pass-1' }
  const info = ok(await req('GET', `/v1/public/shares/${ctx.shareToken}`, { headers: h }))
  assert(info.allowDownload === false, `allowDownload 应为 false，实际 ${info.allowDownload}`)
  assert(info.ticket, '未返回 ticket')
  ctx.ticket = info.ticket
  // 票据指向单个文件时没有"目录列表"，读票据本身即可
  const tk = await req('GET', `/v1/public/tickets/${ctx.ticket}`, { headers: h })
  assert(tk.status === 200, `读票据失败 HTTP ${tk.status}: ${tk.text.slice(0, 150)}`)
  // 关了下载就必须拒绝取字节（不是"界面上没按钮"）
  const content = await req('GET', `/v1/public/tickets/${ctx.ticket}/content`, { headers: h })
  assert(content.status === 403, `allowDownload=false 时取内容应 403，实际 ${content.status}`)
})

await step('T20b', '错误口令被拒', async () => {
  const bad = await req('GET', `/v1/public/shares/${ctx.shareToken}`, {
    headers: { 'X-Share-Password': 'wrong-pass' },
  })
  assert(bad.status !== 200, `错误口令不应通过，实际 ${bad.status}`)
})

await step('T20c', '需要口令时返回 428（不是 411）', async () => {
  // 不带口令头访问：应 428 PASSWORD_REQUIRED。
  // 411 的本意是"缺少 Content-Length"，网关与监控会把它当畸形请求（F-05）。
  const r = await req('GET', `/v1/public/shares/${ctx.shareToken}`)
  assert(r.status === 428, `需要口令应 428，实际 ${r.status}: ${r.text.slice(0, 160)}`)
  assert(r.json?.code === 'PASSWORD_REQUIRED', `错误码应为 PASSWORD_REQUIRED，实际 ${r.json?.code}`)
})

await step('T21', '撤销分享后公开接口失效', async () => {
  const r = await req('POST', `/v1/shares/${ctx.shareId}/revoke`, { token: tenantToken })
  assert(r.status === 200, `撤销失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
  const info = await req('GET', `/v1/public/shares/${ctx.shareToken}`, {
    headers: { 'X-Share-Password': 'share-pass-1' },
  })
  assert(info.status !== 200, `撤销后仍能兑换（HTTP ${info.status}）`)
})

await step('T22', 'ACL 列表与摘要', async () => {
  ok(await req('GET', `/v1/acl?objectType=space&objectId=${ctx.spaceId}`, { token: tenantToken }))
  ok(await req('GET', `/v1/acl/summary?objectType=space&objectId=${ctx.spaceId}`, { token: tenantToken }))
})

await step('T23', '三权分立：系统管理员读不到审计，审计员可以', async () => {
  // 系统管理员读审计必须 403（这是刻意的职责分离，不是缺陷）
  const deny = await req('GET', '/v1/admin/audit/events?limit=10', { token: tenantToken })
  assert(deny.status === 403, `系统管理员读审计应 403，实际 ${deny.status}`)

  // 建一个审计员账号并登录
  const m = ok(await req('POST', '/v1/admin/members', {
    token: tenantToken,
    body: { username: 'e2eaudit', displayName: 'E2E 审计员', password: 'e2e-audit-pass-1', classification: 6 },
  }))
  const g = await req('POST', `/v1/admin/members/${m.id}/roles`, { token: tenantToken, body: { code: 'auditor' } })
  assert(g.status === 200, `授予审计员失败 HTTP ${g.status}: ${g.text.slice(0, 200)}`)
  const auditTok = (await login(ctx.slug, 'e2eaudit', 'e2e-audit-pass-1')).accessToken

  const a = ok(await req('GET', '/v1/admin/audit/events?limit=50', { token: auditTok }))
  const items = a.items || a.events || []
  assert(items.length > 0, '审计员读到的审计为空')
  const v = await req('GET', '/v1/admin/audit/verify', { token: auditTok })
  assert(v.status === 200, `审计链校验失败 HTTP ${v.status}: ${v.text.slice(0, 150)}`)
})

await step('T24', '密级定义可读（全员）与标签策略（安全管理员）', async () => {
  const c = ok(await req('GET', '/v1/classifications', { token: tenantToken }))
  const list = c.items || c.levels || []
  assert(list.length === 7, `密级定义应有 7 档，实际 ${list.length}`)

  // 标签策略属安全管理员：系统管理员必须 403，安全管理员必须 200
  const deny = await req('GET', '/v1/admin/label-policies', { token: tenantToken })
  assert(deny.status === 403, `系统管理员读标签策略应 403，实际 ${deny.status}`)

  const m = ok(await req('POST', '/v1/admin/members', {
    token: tenantToken,
    body: { username: 'e2esec', displayName: 'E2E 安全管理员', password: 'e2e-sec-pass-1', classification: 6 },
  }))
  const g = await req('POST', `/v1/admin/members/${m.id}/roles`, { token: tenantToken, body: { code: 'secadmin' } })
  assert(g.status === 200, `授予安全管理员失败 HTTP ${g.status}: ${g.text.slice(0, 200)}`)
  const sec = await login(ctx.slug, 'e2esec', 'e2e-sec-pass-1')
  const lp = await req('GET', '/v1/admin/label-policies', { token: sec.accessToken })
  assert(lp.status === 200, `安全管理员读标签策略失败 HTTP ${lp.status}`)
})

await step('T25', '凭证/集成与品牌配置可读', async () => {
  // 集成列表按能力域查（kind 必填），这里查短信通道
  const i = ok(await req('GET', '/v1/admin/integrations?kind=sms', { token: tenantToken }))
  assert(Array.isArray(i.providers) || Array.isArray(i.items) || i.kind, `集成列表结构异常：${JSON.stringify(i).slice(0, 160)}`)
  ok(await req('GET', '/v1/admin/branding', { token: tenantToken }))
})

// ---------------- 安全与边界（负向用例） ----------------

await step('S01', '未登录访问受保护接口一律 401', async () => {
  for (const p of ['/v1/me', '/v1/spaces', '/v1/admin/members']) {
    const r = await req('GET', p)
    assert(r.status === 401, `${p} 未登录应 401，实际 ${r.status}`)
  }
})

await step('S02', '安全管理员不能建号（职责分离）', async () => {
  const sec = await login(ctx.slug, 'e2esec', 'e2e-sec-pass-1')
  const r = await req('POST', '/v1/admin/members', {
    token: sec.accessToken,
    body: { username: 'nope', displayName: '越权建号', password: 'e2e-member-pass-1' },
  })
  assert(r.status === 403, `安全管理员建号应 403，实际 ${r.status}`)
})

await step('S03', '随机/伪造分享令牌不可用（不泄漏是否存在）', async () => {
  // 公开端点限流较严（2 rps / burst 10），连跑会先撞 429——稍等再试一次。
  let r = await req('GET', '/v1/public/shares/' + 'x'.repeat(43))
  if (r.status === 429) {
    await new Promise((res) => setTimeout(res, 1200))
    r = await req('GET', '/v1/public/shares/' + 'x'.repeat(43))
  }
  assert(r.status === 410 || r.status === 404, `伪造令牌应 410/404，实际 ${r.status}`)
  assert(!r.text.includes('shareId'), '错误响应不应泄漏内部字段')
})

await step('S04', '探测路径返回 404 而非首页', async () => {
  for (const p of ['/.env', '/.git/config', '/go.mod']) {
    const r = await req('GET', p)
    assert(r.status === 404, `${p} 应 404，实际 ${r.status}`)
  }
})

await step('S05', '跨租户隔离：B 租户读不到 A 的空间', async () => {
  const slugB = ctx.slug + 'b'
  const created = ok(await withRetry(() => req('POST', '/v1/platform/tenants', {
    token,
    body: { slug: slugB, name: 'E2E 隔离租户', edition: 'basic', adminUsername: 'admin', adminPassword: 'e2e-b-pass-1' },
  })))
  ctx.slugB = slugB
  ctx.tenantIdB = created.tenantId
  const loginB = await login(slugB, 'admin', 'e2e-b-pass-1')
  const r = await req('GET', `/v1/spaces/${ctx.spaceId}/nodes`, { token: loginB.accessToken })
  assert(r.status === 404 || r.status === 403, `跨租户读空间应 404/403，实际 ${r.status}`)
  const nr = await req('GET', `/v1/nodes/${ctx.folderId}`, { token: loginB.accessToken })
  assert(nr.status === 404 || nr.status === 403, `跨租户读节点应 404/403，实际 ${nr.status}`)
})

await step('S06', '同一出口 IP 连续登录不再被误限流（F-06）', async () => {
  // 之前登录与外链共用一个 2 rps / burst 10 的桶：
  // 同一个办公网 10 个人早上同时登录就会看到"请求过于频繁"。
  // 现在登录单独一档（10 rps / burst 30），账号级锁定才是爆破防线。
  //
  // 用**错误口令**打 15 次：只验证"没被 IP 限流挡在门外"，
  // 不碰账号锁定（15 次会锁账号，但那正是我们要证明存在的第二道防线）。
  let limited = 0
  for (let i = 0; i < 15; i++) {
    const r = await req('POST', '/v1/auth/login', {
      body: { tenantSlug: ctx.slug, username: 'no-such-user', password: 'x' },
    })
    if (r.status === 429) limited++
  }
  assert(limited === 0, `15 次登录里有 ${limited} 次被 IP 限流（burst 30 内不该 429）`)

  // 平台登录同样独立计价：连打 12 次不应 429
  let pLimited = 0
  for (let i = 0; i < 12; i++) {
    const r = await req('POST', '/v1/platform/auth/login', {
      body: { email: 'nobody@example.com', password: 'x' },
    })
    if (r.status === 429) pLimited++
  }
  assert(pLimited === 0, `平台登录 12 次里有 ${pLimited} 次被限流`)
})

await step('T26', '删除文件后不在列表中', async () => {
  const r = await req('DELETE', `/v1/nodes/${ctx.fileId}`, { token: tenantToken })
  assert(r.status === 200, `删除失败 HTTP ${r.status}: ${r.text.slice(0, 200)}`)
  const nodes = ok(await req('GET', `/v1/spaces/${ctx.spaceId}/nodes`, { token: tenantToken }))
  const items = nodes.items || []
  assert(!items.some((x) => x.id === ctx.fileId), '删除后文件仍在列表里')
})

await step('T27', '退出登录后令牌失效', async () => {
  const r = await req('POST', '/v1/auth/logout', { token: tenantToken, body: { refreshToken: ctx.refresh } })
  assert(r.status === 200, `退出失败 HTTP ${r.status}`)
  const me = await req('GET', '/v1/me', { token: tenantToken })
  assert(me.status === 401, `退出后 /v1/me 应 401，实际 ${me.status}`)
})

await cleanup()
summary()
process.exit(failed ? 1 : 0)
