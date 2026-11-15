// 小程序门禁：把"人工比对"变成"提交前必然执行的检查"。
//
// 背景：小程序曾经是一个独立目录（版本号 2.0.0、不在主仓库、没有任何门禁），
// 结果是与主项目漂移了四处都没人发现（见 docs/59）。这份脚本把当时靠人眼
// 发现的问题逐条变成断言：
//   1. 版本号必须等于产品 VERSION（不再各写各的）；
//   2. 调用的 /v1 路径必须在后端路由表里存在（不存在就是点了 404）；
//   3. 密级名称不许写死（租户可改名，写死就会出现两种叫法）；
//   4. 审批阶段不许判 'approver'（库里只有 none|first|owner|done）；
//   5. 导航栏必须允许被租户品牌覆盖（页面 json 要有静态兜底标题）；
//   6. 本地域名校验必须保持开启（关掉就发现不了"合法域名没登记"）。
//
// 用法：node scripts/check-miniprogram.mjs

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const MP = join(ROOT, 'miniprogram')

let bad = 0
const err = (m) => { console.error('✗', m); bad += 1 }
const ok = (m) => console.log('✓', m)

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === '.git') continue
      walk(p, out)
    } else {
      out.push(p)
    }
  }
  return out
}

if (!existsSync(MP)) {
  err('miniprogram/ 目录不存在')
  process.exit(1)
}
const files = walk(MP)
const rel = (f) => f.slice(MP.length + 1).replace(/\\/g, '/')

/* ---------- 1. 版本号与产品一致 ---------- */
const product = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim()
const cfgSrc = readFileSync(join(MP, 'utils/config.js'), 'utf8')
const v = cfgSrc.match(/VERSION:\s*'([^']+)'/)
if (!v) err('utils/config.js 缺少 VERSION')
else if (v[1] !== product) err(`小程序版本 ${v[1]} 与产品版本 ${product} 不一致（发版时两者必须同时改）`)
else ok(`版本跟随产品：${product}`)

/* ---------- 2. 调用的接口必须存在 ---------- */
const backend = []
for (const f of walk(join(ROOT, 'internal/httpapi'))) {
  if (!f.endsWith('.go') || f.endsWith('_test.go')) continue
  const src = readFileSync(f, 'utf8')
  for (const m of src.matchAll(/HandleFunc\("([A-Z]+)\s+(\/v1\/[^"]+)"/g)) {
    backend.push(m[2].split('?')[0].split('/').filter(Boolean))
  }
}
// 行内拼接的路径：把同一行里以 /v1 开头的字面量按顺序拼起来，取其中的固定段。
const calls = []
for (const f of files) {
  if (!f.endsWith('.js') || rel(f).startsWith('scripts/')) continue
  const lines = readFileSync(f, 'utf8').split(/\r?\n/)
  lines.forEach((line, i) => {
    if (!/path:|\bdownload\(|request\(/.test(line)) return
    const lits = [...line.matchAll(/'(\/v1[^']*)'/g)].map((m) => m[1])
    if (!lits.length) return
    const joined = lits.join('')
    const segs = joined.split('?')[0].split('/').filter((s) => s && !s.includes('+'))
    calls.push({ segs, where: `${rel(f)}:${i + 1}`, raw: joined })
  })
}
let missing = 0
for (const c of calls) {
  const hit = backend.some((bs) => {
    let i = 0
    for (const s of bs) {
      if (s.startsWith('{')) continue
      if (i < c.segs.length && c.segs[i] === s) i += 1
    }
    return i === c.segs.length
  })
  if (!hit) { err(`${c.where} 调用的 ${c.raw} 在后端没有对应路由`); missing += 1 }
}
if (!missing) ok(`接口存在性：${calls.length} 处调用全部命中后端路由`)

/* ---------- 3. 密级名称不许写死 ---------- */
const HARDCODED = ['公开', '内部', '敏感', '秘密', '机密', '绝密', '核心']
let hard = 0
for (const f of files) {
  if (!/\.(js|wxml)$/.test(f) || rel(f).startsWith('scripts/')) continue
  // 先把注释剥掉：解释性文字里出现「机密」是正常的，写死的是字符串字面量
  const src = readFileSync(f, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/^\s*\/\/.*$/gm, '')
  for (const w of HARDCODED) {
    // 允许出现在注释里（解释性文字），只拦字符串字面量
    const re = new RegExp(`['"\`][^'"\`]*${w}[^'"\`]*['"\`]`)
    if (re.test(src)) { err(`${rel(f)} 写死了密级名称「${w}」，应取自 /v1/classifications`); hard += 1 }
  }
}
if (!hard) ok('密级名称：没有写死的名称')

/* ---------- 4. 审批阶段枚举 ---------- */
const clsSrc = readFileSync(join(MP, 'utils/classify.js'), 'utf8')
for (const st of ["'first'", "'owner'", "'done'", "'none'"]) {
  if (!clsSrc.includes(st)) err(`utils/classify.js 未处理阶段 ${st}（库里只允许 none|first|owner|done）`)
}
if (/=== 'approver'/.test(clsSrc)) err("utils/classify.js 仍判断 'approver'（这个值永远不会出现）")
else ok('审批阶段：只认库里的四个值')

/* ---------- 5. 标题可被租户覆盖 ---------- */
const appJSON = JSON.parse(readFileSync(join(MP, 'app.json'), 'utf8'))
const fallback = cfgSrc.match(/PRODUCT_FALLBACK:\s*'([^']+)'/)
if (!fallback) err('utils/config.js 缺少 PRODUCT_FALLBACK')
else if (appJSON.window.navigationBarTitleText !== fallback[1]) {
  err(`app.json 标题「${appJSON.window.navigationBarTitleText}」与 PRODUCT_FALLBACK「${fallback[1]}」不一致`)
}
for (const pg of appJSON.pages) {
  const j = join(MP, pg + '.json')
  if (!existsSync(j)) { err(`缺 ${pg}.json`); continue }
  const t = JSON.parse(readFileSync(j, 'utf8')).navigationBarTitleText
  if (!t) err(`${pg}.json 缺 navigationBarTitleText（运行时会先闪空标题）`)
  const js = readFileSync(join(MP, pg + '.js'), 'utf8')
  if (!/applyTitle\(/.test(js)) err(`${pg}.js 没有调用 meta.applyTitle，标题不会跟随租户品牌`)
}
ok('导航栏标题：静态兜底 + 运行时覆盖')

/* ---------- 6. 本地域名校验保持开启 ---------- */
const proj = JSON.parse(readFileSync(join(MP, 'project.config.json'), 'utf8'))
if (proj.setting?.urlCheck !== true) {
  err('project.config.json 的 urlCheck 必须为 true：关掉就发现不了"合法域名未登记"，真机才会暴露')
} else ok('域名校验：开启（本地可用 project.private.config.json 覆盖）')

/* ---------- 7. 自带自检与单测 ---------- */
try {
  execFileSync(process.execPath, [join(MP, 'scripts/check.js')], { stdio: 'pipe' })
  ok('静态自检 scripts/check.js')
} catch (e) {
  err('scripts/check.js 未通过：\n' + (e.stdout?.toString() || e.message))
}
try {
  execFileSync(process.execPath, [join(MP, 'scripts/test.js')], { stdio: 'pipe' })
  ok('单元测试 scripts/test.js')
} catch (e) {
  err('scripts/test.js 未通过：\n' + (e.stdout?.toString() || e.message))
}

console.log(bad === 0 ? '\n小程序门禁全部通过' : `\n小程序门禁有 ${bad} 个问题`)
process.exitCode = bad ? 1 : 0
