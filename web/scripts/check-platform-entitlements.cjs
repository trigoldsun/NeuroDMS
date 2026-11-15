// 平台运营台「能力授权」页的 UI 回归检查（docs/51 §10）。
//
// 覆盖一个真实缺陷（1.3.2）：租户详情当时是**全屏遮罩 + 右侧抽屉**，渲染条件
// 只判断"有没有 selected"，不判断当前页签。于是点了能力授权页里的租户，
// 遮罩就把矩阵盖住，关掉还会跳去「租户」页签。
//
// 1.4.0 起详情改为**整页**（/platform/tenants/{slug}），抽屉与遮罩已移除。
// 本脚本随之把"抽屉必须仍然工作"改为"详情必须是整页且无遮罩"——
// 防回归的目标没变：**能力授权页永远不能被任何浮层挡住**。
//
// 判据不靠"看起来像"，都是可量化的：
//   1. 能力授权页：无遮罩/抽屉、中心点非 fixed 浮层、按钮 trial click 不被拦截；
//   2. 租户页签：抽屉**仍要**正常出现（别把对的改坏），关闭后回列表；
//   3. 页签切换后地址正确（/platform/entitlements → /platform/entitlements/<slug>）。
//
// 用法：
//   PLAT_TOKEN=<平台令牌> node web/scripts/check-platform-entitlements.cjs [slug]
// 需要 web 目录下已安装 playwright（可选 CHROME 指定本机 chromium 可执行文件）。
const { chromium } = require('playwright')

const BASE = process.env.BASE || 'https://ndms.neurongene.cn'
const TOKEN = process.env.PLAT_TOKEN
const SLUG = process.env.SLUG || process.argv[2] || 'demo'
const EXE = process.env.CHROME ||
  'C://Users//sunxi//AppData//Local//ms-playwright//chromium-1228//chrome-win64//chrome.exe'

const results = []
function check(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`)
}

;(async () => {
  if (!TOKEN) {
    console.error('缺少 PLAT_TOKEN')
    process.exit(1)
  }
  const browser = await chromium.launch({ executablePath: EXE })
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  await page.addInitScript((t) => {
    try { sessionStorage.setItem('plat.token', t) } catch (e) { /* ignore */ }
  }, TOKEN)

  // ---- 1. 能力授权页：不能被遮罩挡住 ----
  await page.goto(`${BASE}/platform/entitlements/${SLUG}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1000)
  const ent = await page.evaluate(() => {
    const center = document.elementFromPoint(window.innerWidth / 2, window.innerHeight / 2)
    const tabOn = document.querySelector('.pf-nav-item.on')
    return {
      hasBackdrop: !!document.querySelector('.drawer-backdrop'),
      hasDrawer: !!document.querySelector('aside.drawer'),
      hasModalMask: !!document.querySelector('.modal-mask'),
      centerFixed: center ? getComputedStyle(center).position === 'fixed' : false,
      rows: document.querySelectorAll('table tbody tr').length,
      path: location.pathname,
      tab: tabOn ? tabOn.textContent.trim() : '',
    }
  })
  check('能力授权页无遮罩', !ent.hasBackdrop && !ent.hasModalMask)
  check('能力授权页无抽屉', !ent.hasDrawer)
  check('中心点不是浮层', !ent.centerFixed)
  check('矩阵已渲染', ent.rows > 0, `rows=${ent.rows}`)
  check('地址与页签正确', ent.path === `/platform/entitlements/${SLUG}` && ent.tab.includes('能力授权'),
    `${ent.path} / ${ent.tab}`)

  // trial click：只做命中检测，不派发事件，不改线上授权
  let clickable = false
  try {
    await page.locator('table tbody tr button', { hasText: '开通' }).first()
      .click({ trial: true, timeout: 3000 })
    clickable = true
  } catch (e) {
    console.log('      click error:', String(e.message || e).split('\n')[0])
  }
  check('首行「开通」可点击（未被遮挡）', clickable)

  // ---- 2. 租户详情：必须是整页，且不带任何遮罩 ----
  await page.goto(`${BASE}/platform/tenants/${SLUG}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1000)
  const detail = await page.evaluate(() => {
    const center = document.elementFromPoint(window.innerWidth / 2, window.innerHeight / 2)
    return {
      hasDrawer: !!document.querySelector('aside.drawer'),
      hasBackdrop: !!document.querySelector('.drawer-backdrop'),
      hasMask: !!document.querySelector('.pf-modal-mask, .modal-mask'),
      columns: document.querySelector('.pf-detail')
        ? getComputedStyle(document.querySelector('.pf-detail')).gridTemplateColumns.split(' ').length : 0,
      centerFixed: center ? getComputedStyle(center).position === 'fixed' : false,
      title: (document.querySelector('.pf-pagehead h1') || {}).textContent || '',
    }
  })
  check('租户详情为整页且无遮罩', !detail.hasDrawer && !detail.hasBackdrop && !detail.hasMask,
    `title=${detail.title}`)
  check('租户详情为两列布局', detail.columns === 2, `${detail.columns} 列`)
  check('详情页中心不是浮层', !detail.centerFixed)

  await page.locator('button', { hasText: '返回列表' }).first().click()
  await page.waitForTimeout(600)
  const closed = await page.evaluate(() => ({
    path: location.pathname,
    hasDrawer: !!document.querySelector('aside.drawer'),
    hasDetail: !!document.querySelector('.pf-detail'),
  }))
  check('返回列表后回到租户页签', closed.path === '/platform/tenants' && !closed.hasDetail, closed.path)

  // ---- 3. 页签切换：从租户页签点「能力授权」，再点租户 ----
  await page.locator('.pf-nav-item', { hasText: '能力授权' }).click()
  await page.waitForTimeout(700)
  const listPath = await page.evaluate(() => location.pathname)
  check('切到能力授权先看列表', listPath === '/platform/entitlements', listPath)

  const pick = page.locator('button', { hasText: '演示' }).first()
  if (await pick.count()) {
    await pick.click()
    // 矩阵是点开后才拉取的，等行真的出现，不要用固定 sleep 猜时间
    await page.waitForSelector('table tbody tr', { timeout: 5000 }).catch(() => {})
    await page.waitForTimeout(200)
    const picked = await page.evaluate(() => ({
      path: location.pathname,
      hasDrawer: !!document.querySelector('aside.drawer'),
      rows: document.querySelectorAll('table tbody tr').length,
    }))
    check('从列表选租户后仍无抽屉', !picked.hasDrawer && picked.rows > 0,
      `${picked.path} rows=${picked.rows}`)
  }

  await browser.close()
  const failed = results.filter((r) => !r.ok)
  console.log(`\n${results.length - failed.length}/${results.length} 通过`)
  if (failed.length) process.exit(2)
})()
