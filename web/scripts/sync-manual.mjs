// 把手册（docs/html）复制到 web/public/manual，让应用自己托管它。
//
// 为什么不再"另开一个静态站"：手册要出现在登录后的工作台，而工作台是登录态页面。
// 让手册与应用同源，用户点开就是同一套会话与同一套 CSP；
// 若挂到另一个域名，既有跨域问题，也会在私有化环境里少一个"必须部署的东西"。
//
// 只复制产物（html/css/js/图片），不复制源 markdown：
// 手册的可读版本以 docs/html 为准，md 是编辑稿，不该出现在前端产物里。

import { cp, mkdir, readdir, rm, stat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = resolve(here, '../../docs/html')
const dest = resolve(here, '../public/manual')

const KEEP = new Set(['.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.webp', '.ico', '.woff2'])

async function exists(p) {
  try {
    await stat(p)
    return true
  } catch {
    return false
  }
}

let copied = 0

async function copyTree(from, to) {
  await mkdir(to, { recursive: true })
  for (const ent of await readdir(from, { withFileTypes: true })) {
    const s = join(from, ent.name)
    const d = join(to, ent.name)
    if (ent.isDirectory()) {
      await copyTree(s, d)
      continue
    }
    const dot = ent.name.lastIndexOf('.')
    const ext = dot >= 0 ? ent.name.slice(dot).toLowerCase() : ''
    if (!KEEP.has(ext)) continue
    await cp(s, d)
    copied++
  }
}

if (!(await exists(src))) {
  // 缺手册不该让前端构建失败：它只是界面上的一个入口，不是运行前提。
  console.warn(`[manual] 未找到 ${src}，跳过手册同步`)
  process.exit(0)
}

await rm(dest, { recursive: true, force: true })
await copyTree(src, dest)

// 目录页必须存在，否则 /manual/ 会落到 SPA 回退上（打开的是应用而不是手册）
if (!(await exists(join(dest, 'index.html')))) {
  console.warn('[manual] docs/html 缺少 index.html：/manual/ 将无法作为手册首页')
}

console.log(`[manual] 已同步 ${copied} 个文件 → web/public/manual`)
