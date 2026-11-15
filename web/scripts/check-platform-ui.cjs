// 平台运营控制台 · 桌面布局与关键入口回归（docs/53）
//
// 背景：运营台此前用的布局类（.layout / .sidebar / .brand …）在 styles.css 里
// 根本不存在，实测 computed style 是 layout=block、sidebar=1600px、整页 1836px 高
// —— 侧栏变成页面顶部一条竖排按钮列表，看起来像手机网页。
// 这个脚本把"像桌面后台"变成可量化的断言，避免以后某次改动又把它悄悄打回去。
//
// 覆盖：骨架栅格 / 无整页纵向溢出 / 无遮罩浮层 / 五个页签无横向溢出 /
//      能力矩阵 / 详情两列 / 租户审计按需加载 / 对账单导出 / 登录页对比度 / 暗色 / 窄屏。
//
// 用法：
//   PLAT_TOKEN=<平台令牌> node web/scripts/check-platform-ui.cjs [slug]
// 需要 web 目录下已安装 playwright（可用 CHROME 指定本机 chromium 可执行文件）。
//
// 说明：租户审计那一项会**真实读取一次**，平台读取会在目标租户的审计链里
// 留下一条 platform.access —— 这是后端刻意的可核查性设计，不是脚本的副作用。

const { chromium } = require('playwright')

const BASE = process.env.BASE || 'https://ndms.neurongene.cn'
const TOKEN = process.env.PLAT_TOKEN
const SLUG = process.env.SLUG || process.argv[2] || 'demo'
const EXE = process.env.CHROME ||
  'C:\\Users\\sunxi\\AppData\\Local\\ms-playwright\\chromium-1228\\chrome-win64\\chrome.exe'

const results = []
function check(name, ok, detail) {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`)
}

async function newAuthedPage(browser, width, height, dark) {
  const ctx = await browser.newContext({ viewport: { width, height }, acceptDownloads: true })
  const page = await ctx.newPage()
  await page.addInitScript(({ t, d }) => {
    try {
      sessionStorage.setItem('plat.token', t)
      if (d) localStorage.setItem('dv.theme', 'dark')
    } catch (e) { /* ignore */ }
  }, { t: TOKEN, d: dark })
  return { ctx, page }
}

;(async () => {
  if (!TOKEN) {
    console.error('缺少 PLAT_TOKEN')
    process.exit(1)
  }
  const browser = await chromium.launch({ executablePath: EXE })

  // ---------------- 1. 骨架与列表页 ----------------
  const { ctx, page } = await newAuthedPage(browser, 1600, 1000, false)
  await page.goto(`${BASE}/platform/tenants`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(800)

  const layout = await page.evaluate(() => {
    const el = (s) => document.querySelector(s)
    const cs = (s, k) => { const e = el(s); return e ? getComputedStyle(e)[k] : 'n/a' }
    const center = document.elementFromPoint(window.innerWidth / 2, window.innerHeight / 2)
    return {
      shellDisplay: cs('.pf-shell', 'display'),
      sideW: el('.pf-side') ? Math.round(el('.pf-side').getBoundingClientRect().width) : 0,
      docScrollH: document.documentElement.scrollHeight,
      docScrollW: document.documentElement.scrollWidth,
      winW: window.innerWidth,
      winH: window.innerHeight,
      hasBackdrop: !!document.querySelector('.drawer-backdrop, .modal-mask, aside.drawer'),
      centerFixed: center ? getComputedStyle(center).position === 'fixed' : false,
      rows: document.querySelectorAll('tbody tr').length,
    }
  })

  check('骨架是两列栅格', layout.shellDisplay === 'grid', layout.shellDisplay)
  check('侧栏固定 240px（不是整行宽）', layout.sideW === 240, `${layout.sideW}px`)
  check('列表页无整页纵向溢出', layout.docScrollH <= layout.winH + 2,
    `${layout.docScrollH} / ${layout.winH}`)
  check('列表页无横向溢出', layout.docScrollW <= layout.winW, `${layout.docScrollW} / ${layout.winW}`)
  check('无全屏遮罩/抽屉', !layout.hasBackdrop)
  check('屏幕中心不是浮层', !layout.centerFixed)
  check('租户表已渲染', layout.rows > 0, `rows=${layout.rows}`)

  // ---------------- 2. 五个页签都能渲染且不溢出 ----------------
  for (const [key, label] of [
    ['entitlements', '能力授权'],
    ['usage', '用量与对账'],
    ['flags', '灰度开关'],
    ['users', '平台账号'],
    ['audit', '平台审计'],
  ]) {
    await page.goto(`${BASE}/platform/${key}`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(600)
    const r = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
      hasShell: !!document.querySelector('.pf-shell'),
    }))
    check(`页签「${label}」渲染且无横向溢出`, r.hasShell && !r.overflow)
  }

  // ---------------- 3. 能力授权矩阵 ----------------
  await page.goto(`${BASE}/platform/entitlements/${SLUG}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(900)
  const ent = await page.evaluate(() => {
    const th = [...document.querySelectorAll('thead th')].map((x) => x.textContent.trim())
    return {
      cols: th,
      rows: document.querySelectorAll('tbody tr').length,
      sticky: !!document.querySelector('td.pf-sticky'),
      hasDrawer: !!document.querySelector('.drawer-backdrop, aside.drawer'),
    }
  })
  check('矩阵列完整', ['能力', '基础', '专业', '旗舰', '当前', '到期', '覆盖'].every((c) => ent.cols.includes(c)),
    ent.cols.join('|'))
  check('矩阵有数据行', ent.rows > 0, `rows=${ent.rows}`)
  check('操作列固定在右侧', ent.sticky)
  check('授权页无抽屉/遮罩', !ent.hasDrawer)

  // ---------------- 4. 租户详情 ----------------
  await page.goto(`${BASE}/platform/tenants/${SLUG}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(1000)
  const det = await page.evaluate(() => {
    const d = document.querySelector('.pf-detail')
    return {
      cols: d ? getComputedStyle(d).gridTemplateColumns.split(' ').length : 0,
      panels: document.querySelectorAll('.pf-panel').length,
      overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
      hasBackdrop: !!document.querySelector('.drawer-backdrop, aside.drawer'),
    }
  })
  check('详情页为两列布局', det.cols === 2, `${det.cols} 列`)
  check('详情页面板已渲染', det.panels >= 4, `panels=${det.panels}`)
  check('详情页无横向溢出', !det.overflow)
  check('详情页无遮罩抽屉', !det.hasBackdrop)

  // 租户审计：点之前不该有数据（避免每次进详情都刷客户审计链）
  const auditPanel = page.locator('.pf-panel', { hasText: '租户最近操作' }).first()
  const before = await auditPanel.locator('.pf-row').count()
  check('租户审计默认不加载', before === 0, `rows=${before}`)
  await auditPanel.locator('button', { hasText: '读取' }).click()
  await page.waitForTimeout(1600)
  const after = await auditPanel.locator('.pf-row').count()
  check('租户审计按需可读', after > 0, `rows=${after}`)

  // 对账单导出
  let dlName = ''
  try {
    const [dl] = await Promise.all([
      page.waitForEvent('download', { timeout: 15000 }),
      page.locator('button', { hasText: '导出对账单' }).first().click(),
    ])
    dlName = dl.suggestedFilename()
    await dl.saveAs(`scripts/_invoice-${SLUG}.csv`)
  } catch (e) {
    console.log('      download error:', String(e.message).split('\n')[0])
  }
  check('对账单可导出 CSV', /^usage-.+-\d{4}-\d{2}\.csv$/.test(dlName), dlName)

  await ctx.close()

  // ---------------- 5. 登录页与暗色 ----------------
  const anonCtx = await browser.newContext({ viewport: { width: 1600, height: 1000 } })
  const anon = await anonCtx.newPage()
  await anon.goto(`${BASE}/platform/login`, { waitUntil: 'networkidle' })
  const h1Color = await anon.evaluate(() => {
    const el = document.querySelector('.pf-login-aside h1')
    return el ? getComputedStyle(el).color : ''
  })
  // 深底上的标题必须是浅色：此前被全局 h1{color:var(--ink)} 覆盖成近黑，几乎不可读
  const rgb = (h1Color.match(/\d+/g) || []).map(Number)
  const bright = rgb.length === 3 && (rgb[0] + rgb[1] + rgb[2]) / 3 > 180
  check('登录页标题在深底上为浅色', bright, h1Color)
  await anon.screenshot({ path: 'scripts/_ui-login.png' })
  await anonCtx.close()

  const dark = await newAuthedPage(browser, 1400, 900, true)
  await dark.page.goto(`${BASE}/platform/tenants`, { waitUntil: 'networkidle' })
  await dark.page.waitForTimeout(600)
  const darkInfo = await dark.page.evaluate(() => {
    const on = document.querySelector('.pf-nav-item.on')
    const bg = on ? getComputedStyle(on).backgroundColor : ''
    return { bg, overflow: document.documentElement.scrollWidth > window.innerWidth + 1 }
  })
  check('暗色下当前页签有独立底色', darkInfo.bg !== 'rgba(0, 0, 0, 0)' && darkInfo.bg !== '', darkInfo.bg)
  check('暗色无横向溢出', !darkInfo.overflow)
  await dark.page.screenshot({ path: 'scripts/_ui-dark.png' })
  await dark.ctx.close()

  // ---------------- 6. 窄屏 ----------------
  const narrow = await newAuthedPage(browser, 820, 900, false)
  await narrow.page.goto(`${BASE}/platform/tenants`, { waitUntil: 'networkidle' })
  await narrow.page.waitForTimeout(700)
  const nr = await narrow.page.evaluate(() => {
    const nav = document.querySelector('.pf-nav')
    const tw = document.querySelector('.pf-tablewrap')
    return {
      navDir: nav ? getComputedStyle(nav).flexDirection : '',
      tableScrollable: !!tw && tw.scrollWidth > tw.clientWidth,
      overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
    }
  })
  check('窄屏导航转为横向', nr.navDir === 'row', nr.navDir)
  check('窄屏表格可横向滚动', nr.tableScrollable)
  check('窄屏页面无横向溢出', !nr.overflow)
  await narrow.page.screenshot({ path: 'scripts/_ui-narrow.png' })
  await narrow.ctx.close()

  await browser.close()
  const bad = results.filter((r) => !r.ok)
  console.log(`\n${results.length - bad.length}/${results.length} 通过`)
  if (bad.length) process.exit(2)
})()
