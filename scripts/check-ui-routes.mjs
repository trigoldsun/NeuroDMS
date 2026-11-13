// 交互约定检查：界面状态必须反映在地址栏。
//
// 背景：同一类问题被反复提出过两次——
//   · docs/11：文件空间与目录是组件内 state，URL 恒为 /files，刷新回首页；
//   · 本次：运营台五个页签与租户详情都是 state，地址恒为 platform.html，
//     刷新回第一页、后退无效、"帮我看下 acme 的配额"只能靠口述。
//
// 两次的根因完全相同：原则只在被点到的那一个页面落实了，没有变成机器检查。
// 这个脚本就是把原则变成检查，避免第三次。
//
// 检查三条（只查可静态判定的，宁可少查也不误报）：
//   1. 用 useState 表示"当前页签"（变量名含 tab）；
//   2. 调用 setTab / setActiveTab 这类纯内存切换；
//   3. 页面里有页签导航（className="tabs"）却没有引入路由内核。
//
// 用法：node scripts/check-ui-routes.mjs
// 退出码 1 表示发现违反约定的写法。

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const SRC = join(ROOT, 'web', 'src')

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === 'dist') continue
      walk(p, out)
    } else if (p.endsWith('.tsx') || p.endsWith('.ts')) {
      out.push(p)
    }
  }
  return out
}

// 只看页面与平台目录：工具函数不可能定义页签
const files = walk(SRC).filter((f) => f.includes('pages') || f.includes('platform'))

const problems = []

for (const file of files) {
  const src = readFileSync(file, 'utf8')
  const rel = file.slice(ROOT.length).replace(/\\/g, '/')

  // 例外必须写明理由，而不是默默放过。
  // 目前唯一合理的场景是"浮层内部的临时分栏"：它随浮层一起关闭，
  // 不存在收藏/分享/后退回到这一栏的诉求。主菜单、列表、详情一律不适用。
  if (/ui-route-exempt\s*:\s*\S/.test(src)) continue

  // 1. useState 表示当前页签
  const stateTab = /const\s*\[\s*\w*[Tt]ab\w*\s*,\s*set\w+\s*\]\s*=\s*useState/.exec(src)
  if (stateTab) {
    problems.push(`${rel}：用 useState 表示当前页签（${stateTab[0].trim()}）——页签应来自地址栏`)
  }

  // 2. 纯内存切换
  const setter = /\bset(Active)?Tab\s*\(/.exec(src)
  if (setter) {
    problems.push(`${rel}：调用了 ${setter[0].replace('(', '')}() —— 切换页签必须走 navigate，否则地址不变`)
  }

  // 3. 有页签导航但没有路由内核
  const hasNav = /className="tabs"|className=\{`tabs/.test(src)
  const hasRouter = /from\s+['"][^'"]*router['"]/.test(src)
  if (hasNav && !hasRouter) {
    problems.push(`${rel}：有页签导航却未引入路由内核——每个页签必须有独立地址`)
  }
}

if (problems.length === 0) {
  console.log(`✓ ${files.length} 个页面文件，未发现"状态不进地址"的写法`)
  process.exit(0)
}

console.log('发现不符合交互约定的写法：')
for (const p of problems) console.log('  · ' + p)
console.log('')
console.log('约定见 docs/24-交互约定-地址即状态.md。')
process.exit(1)
