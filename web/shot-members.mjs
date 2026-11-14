import { chromium } from 'playwright'
import fs from 'node:fs'
const BASE = 'http://127.0.0.1:18090'
const env = Object.fromEntries(fs.readFileSync('../docker/.env','utf8').split('\n').filter(l=>l.includes('=')&&!l.startsWith('#')).map(l=>{const i=l.indexOf('=');return [l.slice(0,i).trim(),l.slice(i+1).trim()]}))
const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 980 } })
const page = await ctx.newPage()
const errs = []
page.on('pageerror', e => errs.push(e.message))
page.on('console', m => { if (m.type() === 'error') errs.push(m.text()) })

await page.goto(BASE + '/login', { waitUntil: 'networkidle' })
await page.fill('#tenant', env.DOCVAULT_DEV_TENANT)
await page.fill('#user', env.DOCVAULT_DEV_ADMIN)
await page.fill('#pass', env.DOCVAULT_DEV_ADMIN_PASSWORD)
await page.click('button[type=submit]')
await page.waitForTimeout(2200)

await page.goto(BASE + '/admin/members', { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
console.log('ROWS:', await page.locator('tbody tr').count())
console.log('LIST_HINT:', (await page.locator('tbody tr').first().innerText()).replace(/\s+/g,' ').slice(0,140))
await page.screenshot({ path: 'C:/tmp/m-list.png' })

// 新建
await page.getByRole('button', { name: '新建成员' }).click()
await page.waitForTimeout(600)
const hasPhone = await page.locator('input[placeholder="13800138000"]').count()
console.log('CREATE_PHONE_INPUT:', hasPhone)
console.log('CREATE_HINT:', (await page.locator('.modal-body').innerText()).includes('待验证'))
await page.screenshot({ path: 'C:/tmp/m-create.png' })
await page.getByRole('button', { name: '关闭' }).click()
await page.waitForTimeout(400)

// 编辑第一行
await page.locator('tbody tr').first().getByRole('button', { name: '编辑' }).click()
await page.waitForTimeout(700)
console.log('EDIT_PHONE_ROW:', await page.locator('.phone-row').count())
console.log('EDIT_TEXT:', (await page.locator('.modal-body').innerText()).replace(/\s+/g,' ').slice(0,200))
await page.screenshot({ path: 'C:/tmp/m-edit.png' })
console.log('ERRORS:', JSON.stringify(errs.slice(0,3)))
await browser.close()
