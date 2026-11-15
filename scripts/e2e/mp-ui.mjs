#!/usr/bin/env node
// 小程序 UI 链路自动化：在微信开发者工具里把真实页面点一遍。
//
// 与 scripts/e2e/miniprogram.mjs 的分工：
//   - 那边是 HTTP 契约（请求/响应对不对）；
//   - 这边是**页面行为**（点击是否生效、跳转是否正确、文案是否来自服务端）。
// 只看其中一边都会漏掉一整类问题：数据对了但显示错、接口对了但点了没反应。
//
// 前置：
//   1. 开发者工具已登录，且用自动化端口启动：
//        cli auto --project <repo>/miniprogram --auto-port 9420
//   2. 安装驱动（不入库，随便一个目录即可）：
//        mkdir -p /tmp/mpui && cd /tmp/mpui && npm i miniprogram-automator
//      然后**在该目录**执行本脚本（驱动从 cwd 解析）。
//   3. 有可用的测试账号与待审数据：
//        node scripts/e2e/miniprogram.mjs --prepare   # 打印 account/password
//
// 用法：
//   MP_ACCOUNT=admin@mpxxxx MP_PASSWORD=mp-pass-12345 node scripts/e2e/mp-ui.mjs
//
// 说明：这是开发者工具（真机同级渲染），不是真机本体。真机还需扫"预览二维码"，
// 且必须先在小程序后台登记 request/downloadFile 合法域名（工具可以关校验，真机不能）。

import { createRequire } from 'node:module'

const require = createRequire(process.cwd() + '/')
const automator = require('miniprogram-automator')

const ACCOUNT = process.env.MP_ACCOUNT || ''
const PASSWORD = process.env.MP_PASSWORD || ''
const WS = process.env.MP_WS || 'ws://127.0.0.1:9420'

let bad = 0
const pass = (m) => console.log('  ✓ ' + m)
const fail = (m) => { console.error('  ✗ ' + m); bad++ }
const assert = (cond, msg) => (cond ? pass(msg) : fail(msg))

async function waitFor(fn, ms = 15000, label = '条件') {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) {
    try {
      if (await fn()) return true
    } catch (e) {
      // 页面切换瞬间对非栈顶页面取数据会抛错，属于时序噪声：继续等
    }
    await new Promise((r) => setTimeout(r, 300))
  }
  throw new Error('等待超时：' + label)
}

async function main() {
  if (!ACCOUNT || !PASSWORD) throw new Error('需要 MP_ACCOUNT / MP_PASSWORD')
  const mp = await automator.connect({ wsEndpoint: WS })
  const logs = []
  mp.on('console', (m) => logs.push(m))

  await mp.callWxMethod('clearStorageSync')
  let page = await mp.reLaunch('/pages/login/login')
  await waitFor(async () => (await mp.currentPage()).path === 'pages/login/login', 15000, '登录页')

  // ---- 登录 ----
  const inputs = await page.$$('.input')
  assert(inputs.length === 2, `登录页账号模式应有 2 个输入框，实际 ${inputs.length}`)
  await inputs[0].input(ACCOUNT)
  await inputs[1].input(PASSWORD)
  await (await page.$('.btn-primary')).tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/files/files', 30000, '进入文件页')
  pass('账号口令登录 → 跳转文件页')

  // ---- 文件页：搜索入口 + 最近访问 + 列表 ----
  page = await mp.currentPage()
  await waitFor(async () => (await page.data('state')) !== 'loading', 25000, '文件列表加载')
  assert((await page.data('state')) === 'ready', '文件页状态应为 ready')
  assert(!!(await page.$('.searchbar')), '文件页应有搜索入口')
  const nodes = await page.data('nodes')
  assert(Array.isArray(nodes) && nodes.length >= 1, `根目录应有内容，实际 ${nodes && nodes.length}`)
  const folder = nodes.find((n) => n.isFolder)
  assert(!!folder, '根目录应有「合同」目录')
  assert(/（\d 级）$/.test(String(folder.classLabel)), `密级文案格式：${folder.classLabel}`)

  // ---- 搜索 ----
  await (await page.$('.searchbar')).tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/search/search', 15000, '搜索页')
  const sp = await mp.currentPage()
  await (await sp.$('.input')).input('验收')
  await waitFor(async () => ['ready', 'empty'].includes(await sp.data('state')), 20000, '搜索结果')
  const hits = await sp.data('items')
  assert((await sp.data('state')) === 'ready' && hits.length >= 1, `搜索应有结果，实际 ${hits.length}`)
  await (await sp.$('.row')).tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/preview/preview', 15000, '搜索进预览')
  const pv = await mp.currentPage()
  await waitFor(async () => !!String(await pv.data('textContent')), 25000, '预览文本加载')
  assert(String(await pv.data('textContent')).includes('小程序链路验收'), '预览内容与文件内容一致')
  await mp.navigateBack()
  await mp.navigateBack()

  // ---- 目录 → 文件 → 预览（返回文件页后走目录路径） ----
  page = await mp.currentPage()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/files/files', 15000, '回到文件页')
  await waitFor(async () => ((await page.data('nodes')) || []).length > 0, 20000, '列表恢复')
  await (await page.$('.row')).tap()
  await waitFor(async () => ((await page.data('nodes')) || []).some((n) => !n.isFolder), 15000, '进入目录')
  const inner = await page.data('nodes')
  const rows = await page.$$('.row')
  await rows[inner.findIndex((n) => !n.isFolder)].tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/preview/preview', 15000, '目录进预览')
  pass('目录 → 文件 → 预览')
  await mp.navigateBack()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/files/files', 15000, '返回文件页')

  // 最近访问：预览过之后应出现（服务端活动日志）
  await waitFor(async () => ((await page.data('recent')) || []).length > 0, 20000, '最近访问有数据')
  const recent = await page.data('recent')
  assert(recent.length >= 1, `最近访问应有记录，实际 ${recent.length}`)
  assert(recent[0].id && recent[0].name, '最近访问条目要有 id 与名称')

  // ---- 审批 ----
  const ap = await mp.switchTab('/pages/approvals/approvals')
  await waitFor(async () => (await ap.data('state')) === 'ready', 25000, '待办加载')
  const items = await ap.data('items')
  assert(items.length >= 1, `待办应有 1 条，实际 ${items.length}`)
  assert(items[0].stageText === '待审批人处理', `阶段文案应为「待审批人处理」，实际「${items[0].stageText}」`)
  // 未配置微信通道 → 提醒入口必须不存在（不是显示一个点了报错的按钮）
  assert(!(await ap.$('.remind')), '未配置订阅消息通道时不应出现提醒入口')

  await mp.mockWxMethod('showModal', { confirm: true, cancel: false })
  await (await ap.$('.row')).tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/approval/approval', 15000, '审批详情')
  const dt = await mp.currentPage()
  await waitFor(async () => (await dt.data('state')) === 'ready', 20000, '审批详情加载')
  assert(!!(await dt.data('item')), '审批详情缺少主体信息')
  await (await dt.$('.btn-primary')).tap()
  // 通过后会自动返回列表：这里每轮都取当前页面，不能复用列表页句柄
  await waitFor(async () => {
    const cur = await mp.currentPage()
    return cur.path === 'pages/approvals/approvals' && (await cur.data('state')) === 'empty'
  }, 25000, '通过后待办清空')
  pass('通过后待办清空')

  // ---- 我的 ----
  const me = await mp.switchTab('/pages/me/me')
  await waitFor(async () => !!(await me.data('me')), 20000, '我的页加载')
  assert((await me.data('phoneVerified')) === true, '手机号应显示已验证')
  assert(String(await me.data('classLabel')).indexOf('级') > 0, `密级文案：${await me.data('classLabel')}`)

  await mp.mockWxMethod('showModal', { confirm: true, cancel: false })
  await (await me.$('.btn-danger')).tap()
  await waitFor(async () => (await mp.currentPage()).path === 'pages/login/login', 25000, '退出回登录页')
  pass('退出登录回登录页')

  const errs = logs.filter((l) => /error|Error/i.test(l.args ? l.args.join(' ') : String(l)))
  assert(errs.length === 0, `控制台无错误（发现 ${errs.length} 条）`)

  await mp.disconnect()
}

main().then(() => {
  console.log(bad === 0 ? '\nUI 链路全部通过' : `\n有 ${bad} 个问题`)
  process.exitCode = bad ? 1 : 0
}).catch((e) => {
  console.error('\n自动化失败：', e.message)
  process.exitCode = 1
})
