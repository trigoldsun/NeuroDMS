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
const PASS = env.DOCVAULT_DEV_ADMIN_PASSWORD || ''

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH })

async function login(page, user) {
  await page.goto(BASE + '/login', { waitUntil: 'networkidle' })
  await page.fill('#tenant', env.DOCVAULT_DEV_TENANT || 'demo')
  await page.fill('#user', user)
  await page.fill('#pass', PASS)
  await page.click('button[type=submit]')
  await page.waitForTimeout(2500)
}

const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page = await ctx.newPage()
page.on('pageerror', (e) => console.log('PAGEERROR:', e.message))

await page.goto(BASE + '/login', { waitUntil: 'networkidle' })
await page.screenshot({ path: `${out}/01-login.png` })

await login(page, 'admin')
await page.waitForTimeout(1200)

// 找到有内容的空
const spaceBtns = page.locator('.space-item')
for (let i = 0; i < (await spaceBtns.count()); i++) {
  if (await page.locator('tbody tr').count() > 0) break
  await spaceBtns.nth(i).click()
  await page.waitForTimeout(800)
}
await page.waitForTimeout(500)
await page.screenshot({ path: `${out}/02-files.png` })

const boxes = page.locator('tbody input[type=checkbox]')
if (await boxes.count()) {
  await boxes.nth(1).check()
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${out}/03-batch.png` })
  await boxes.nth(1).uncheck()
}

const search = page.locator('.search input')
await search.fill('pdf')
await page.waitForTimeout(1000)
await page.screenshot({ path: `${out}/04-search.png` })
await search.fill('')
await page.waitForTimeout(300)

const row = page.locator('tbody tr', { hasText: 'contract-2026.pdf' })
if (await row.count()) {
  await row.first().locator('button', { hasText: '预览' }).click()
  await page.waitForTimeout(3000)
  await page.screenshot({ path: `${out}/05-preview-watermark.png` })
  await page.keyboard.press('Escape')
  await page.waitForTimeout(500)

  await row.first().locator('button', { hasText: '定密' }).click()
  await page.waitForTimeout(700)
  await page.screenshot({ path: `${out}/06-class.png` })
  await page.keyboard.press('Escape')
  await page.locator('.drawer button', { hasText: '关闭' }).click().catch(() => {})
  await page.waitForTimeout(400)
}

await page.evaluate(() => localStorage.setItem('dv.theme', 'dark'))
await page.reload({ waitUntil: 'networkidle' })
await page.waitForTimeout(1400)
await page.screenshot({ path: `${out}/07-dark.png` })
await page.evaluate(() => localStorage.setItem('dv.theme', 'light'))

// 管理台（sysadmin + secadmin）
await page.goto(BASE + '/admin', { waitUntil: 'networkidle' })
await page.waitForTimeout(1600)
await page.screenshot({ path: `${out}/08-admin-overview.png` })

const tabs = page.locator('.tabs button')
const n = await tabs.count()
console.log('tabs:', n, await tabs.allInnerTexts())
for (let i = 0; i < n; i++) {
  const label = (await tabs.nth(i).innerText()).trim()
  await tabs.nth(i).click()
  await page.waitForTimeout(1000)
  const safe = label.replace(/[^\u4e00-\u9fa5a-z0-9]/gi, '')
  await page.screenshot({ path: `${out}/09-${i + 1}-${safe}.png` })
}

// 审计员视角
const ctx2 = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page2 = await ctx2.newPage()
page2.on('pageerror', (e) => console.log('PAGEERROR2:', e.message))
await login(page2, 'auditor')
await page2.goto(BASE + '/admin', { waitUntil: 'networkidle' })
await page2.waitForTimeout(1800)
await page2.screenshot({ path: `${out}/10-auditor.png` })

await browser.close()
console.log('done:', fs.readdirSync(out).join(', '))
