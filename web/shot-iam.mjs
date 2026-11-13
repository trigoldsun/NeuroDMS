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

// 租户端：acme 管理员 → 治理台 → 成员与角色
await page.goto(BASE + '/login', { waitUntil: 'networkidle' })
await page.fill('#tenant', 'acme')
await page.fill('#user', 'admin')
await page.fill('#pass', 'acme-init-pass-1')
await page.click('button[type=submit]')
await page.waitForTimeout(2200)
await page.goto(BASE + '/admin', { waitUntil: 'networkidle' })
await page.waitForTimeout(1200)
await page.locator('.tabs button', { hasText: '成员与角色' }).click()
await page.waitForTimeout(1500)
await page.screenshot({ path: `${out}/18-members.png` })

// 新建成员弹窗
await page.locator('button', { hasText: '新建成员' }).click()
await page.waitForTimeout(600)
await page.screenshot({ path: `${out}/19-member-create.png` })
await page.locator('.modal button', { hasText: '取消' }).click()
await page.waitForTimeout(300)

// 平台端：平台账号
const ctx2 = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const p2 = await ctx2.newPage()
p2.on('pageerror', (e) => console.log('PAGEERROR2:', e.message))
await p2.goto(BASE + '/platform', { waitUntil: 'networkidle' })
await p2.fill('#email', env.DOCVAULT_PLATFORM_ADMIN)
await p2.fill('#pass', env.DOCVAULT_PLATFORM_ADMIN_PASSWORD)
await p2.click('button[type=submit]')
await p2.waitForTimeout(2200)
await p2.locator('nav button', { hasText: '平台账号' }).click()
await p2.waitForTimeout(1000)
await p2.screenshot({ path: `${out}/20-platform-users.png` })

await browser.close()
console.log('done')
