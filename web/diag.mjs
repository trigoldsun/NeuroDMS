import { chromium } from 'playwright'
import fs from 'node:fs'

const BASE = 'http://127.0.0.1:18090'
const env = Object.fromEntries(
  fs.readFileSync('../docker/.env', 'utf8').split('\n')
    .filter((l) => l.includes('=') && !l.startsWith('#'))
    .map((l) => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim()] }),
)
const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
page.on('pageerror', (e) => console.log('PAGEERROR:', e.message))
page.on('console', (m) => { if (m.type() === 'error') console.log('CONSOLE:', m.text()) })

await page.goto(BASE + '/login', { waitUntil: 'networkidle' })
await page.fill('#tenant', env.DOCVAULT_DEV_TENANT || 'demo')
await page.fill('#user', env.DOCVAULT_DEV_ADMIN || 'admin')
await page.fill('#pass', env.DOCVAULT_DEV_ADMIN_PASSWORD || '')
await page.click('button[type=submit]')
await page.waitForTimeout(3000)
console.log('URL:', page.url())
console.log('BODY:', (await page.locator('body').innerText()).slice(0, 300).replace(/\n/g, ' | '))
await browser.close()
