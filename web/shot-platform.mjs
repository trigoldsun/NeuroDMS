import { chromium } from 'playwright'
import fs from 'node:fs'

const BASE = 'http://127.0.0.1:18090'
const env = Object.fromEntries(
  fs.readFileSync('../docker/.env', 'utf8').split('\n')
    .filter((l) => l.includes('=') && !l.startsWith('#'))
    .map((l) => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim()] }),
)
const out = '../docs/screenshots/ui'
fs.mkdirSync(out, { recursive: true })

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page = await ctx.newPage()
page.on('pageerror', (e) => console.log('PAGEERROR:', e.message))

await page.goto(BASE + '/platform', { waitUntil: 'networkidle' })
await page.screenshot({ path: `${out}/11-platform-login.png` })

await page.fill('#email', env.DOCVAULT_PLATFORM_ADMIN)
await page.fill('#pass', env.DOCVAULT_PLATFORM_ADMIN_PASSWORD)
await page.click('button[type=submit]')
await page.waitForTimeout(2200)
await page.screenshot({ path: `${out}/12-platform-tenants.png` })

// 打开首个租户详情
const detail = page.locator('tbody tr button', { hasText: '详情' }).first()
if (await detail.count()) {
  await detail.click()
  await page.waitForTimeout(1200)
  await page.screenshot({ path: `${out}/13-platform-tenant-drawer.png` })
  await page.locator('.drawer button', { hasText: '关闭' }).click()
  await page.waitForTimeout(400)
}

// 开通租户弹窗
await page.locator('button', { hasText: '开通租户' }).click()
await page.waitForTimeout(600)
await page.screenshot({ path: `${out}/14-platform-create.png` })
await page.locator('.modal button', { hasText: '取消' }).click()
await page.waitForTimeout(300)

// 用量与对账
await page.locator('nav button', { hasText: '用量与对账' }).click()
await page.waitForTimeout(400)
await page.locator('button', { hasText: '对账检查' }).click()
await page.waitForTimeout(1500)
await page.screenshot({ path: `${out}/15-platform-reconcile.png` })

// 灰度开关
await page.locator('nav button', { hasText: '灰度开关' }).click()
await page.waitForTimeout(700)
await page.screenshot({ path: `${out}/16-platform-flags.png` })

// 平台审计
await page.locator('nav button', { hasText: '平台审计' }).click()
await page.waitForTimeout(700)
await page.screenshot({ path: `${out}/17-platform-audit.png` })

await browser.close()
console.log('done')
