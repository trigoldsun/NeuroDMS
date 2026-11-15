// 静态自检（Node 环境，不需要开发者工具）。
//
// 用法：node scripts/check.js
//
// 检查的是"开发者工具不会替你拦下、但真机会崩"的那一类问题：
//   - JSON 里的注释与尾逗号（工具能宽容，真机不能）
//   - 页面三件套缺失、usingComponents 指向不存在的组件
//   - WXML 用了小程序不支持的语法（可选链、空值合并、箭头函数）
//   - 绑定了不存在的事件处理函数（点了没反应，最难查）
//   - 引用了已删除的旧模块 / tabBar 图标缺失
const fs = require('fs')
const path = require('path')

const ROOT = path.join(__dirname, '..')
let bad = 0
const err = (m) => { console.error('✗', m); bad += 1 }
const ok = (m) => console.log('✓', m)

function readJSON(p) {
  const raw = fs.readFileSync(p, 'utf8')
  if (/\/\/|\/\*/.test(raw)) err(p + ' 含注释')
  if (/,\s*[}\]]/.test(raw)) err(p + ' 含尾逗号')
  try {
    return JSON.parse(raw)
  } catch (e) {
    err(p + ' JSON 解析失败: ' + e.message)
    return null
  }
}

function walk(dir, ext, out) {
  const acc = out || []
  for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
    if (f.name === 'node_modules' || f.name === '.git' || f.name === 'scripts') continue
    const p = path.join(dir, f.name)
    if (f.isDirectory()) walk(p, ext, acc)
    else if (f.name.endsWith(ext)) acc.push(p)
  }
  return acc
}

/* ---------- 1. JSON ---------- */
const jsons = walk(ROOT, '.json')
for (const f of jsons) readJSON(f)
ok('JSON 严格性（' + jsons.length + ' 个文件）')

/* ---------- 2. 页面与组件 ---------- */
const app = readJSON(path.join(ROOT, 'app.json'))
if (!app) process.exit(1)
for (const pg of app.pages) {
  for (const ext of ['js', 'wxml', 'json']) {
    if (!fs.existsSync(path.join(ROOT, pg + '.' + ext))) err('缺文件 ' + pg + '.' + ext)
  }
  const j = readJSON(path.join(ROOT, pg + '.json')) || {}
  for (const [name, p] of Object.entries(j.usingComponents || {})) {
    const target = p.startsWith('/') ? path.join(ROOT, p.slice(1)) : path.join(ROOT, pg, '..', p)
    if (!fs.existsSync(path.resolve(target) + '.wxml')) err(pg + ' 引用组件不存在: ' + p)
  }
}
ok('页面三件套与组件引用（' + app.pages.length + ' 页）')

/* ---------- 3. tabBar ---------- */
for (const item of (app.tabBar && app.tabBar.list) || []) {
  if (!app.pages.includes(item.pagePath)) err('tabBar 页面未注册: ' + item.pagePath)
  for (const k of ['iconPath', 'selectedIconPath']) {
    if (item[k] && !fs.existsSync(path.join(ROOT, item[k]))) err('tabBar 图标缺失: ' + item[k])
  }
}
if (!app.tabBar || app.tabBar.list.length !== 3) err('底部应为 3 个页签（文件/审批/我的）')
ok('tabBar 配置与图标')

/* ---------- 4. WXML ---------- */
const wxmls = walk(ROOT, '.wxml')
for (const f of wxmls) {
  const s = fs.readFileSync(f, 'utf8')
  if (/\?\./.test(s)) err(f + ' 使用了可选链 ?.')
  if (/\?\?/.test(s)) err(f + ' 使用了 ??')
  if (/=>/.test(s)) err(f + ' 出现箭头函数')
  const open = (s.match(/\{\{/g) || []).length
  const close = (s.match(/\}\}/g) || []).length
  if (open !== close) err(f + ' 插值括号不配对 ' + open + '/' + close)
}
ok('WXML 语法（' + wxmls.length + ' 个文件）')

/* ---------- 5. 标签闭合 ---------- */
for (const f of wxmls) {
  const raw = fs.readFileSync(f, 'utf8')
  const s = raw.replace(/<!--[\s\S]*?-->/g, '')
  const stack = []
  let broken = false
  const re = /<(\/?)([a-zA-Z][\w-]*)([^>]*?)(\/?)>/g
  let m
  while ((m = re.exec(s))) {
    const closing = m[1]
    const name = m[2]
    const selfClose = m[4]
    if (closing) {
      if (stack.pop() !== name) {
        err(f + ' 标签不匹配：</' + name + '>')
        broken = true
        break
      }
    } else if (!selfClose) {
      stack.push(name)
    }
  }
  if (!broken && stack.length) err(f + ' 未闭合标签 ' + stack.join(','))
}
ok('WXML 标签闭合')

/* ---------- 6. 事件绑定 ---------- */
for (const f of wxmls) {
  const js = f.replace(/\.wxml$/, '.js')
  if (!fs.existsSync(js)) { err(f + ' 缺少同名 js'); continue }
  const code = fs.readFileSync(js, 'utf8')
  const s = fs.readFileSync(f, 'utf8')
  const handlers = [...s.matchAll(/bind(?:tap|input|change|longpress|confirm)="([A-Za-z0-9_]+)"/g)].map((m) => m[1])
  for (const h of new Set(handlers)) {
    if (!new RegExp('\\b' + h + '\\s*\\(').test(code) && !new RegExp(h + '\\s*[:=]').test(code)) {
      err(f + ' 绑定的事件处理函数不存在: ' + h)
    }
  }
}
ok('事件绑定')

/* ---------- 7. 旧模块残留 ---------- */
const removed = ['services/store', 'services/session', 'services/files', 'services/shares', 'utils/preview']
for (const f of walk(ROOT, '.js')) {
  const s = fs.readFileSync(f, 'utf8')
  for (const r of removed) {
    if (new RegExp("require\\([^)]*" + r.replace('/', '\\/') + "[^)]*\\)").test(s)) {
      err(path.basename(f) + ' 仍引用已删除模块 ' + r)
    }
  }
  // 小程序低版本基础库对可选链支持不稳，统一不用
  if (/\?\./.test(s)) err(path.basename(f) + ' 使用了可选链 ?.')
}
ok('旧模块残留检查')

/* ---------- 8. 运行时配置 ---------- */
const cfg = fs.readFileSync(path.join(ROOT, 'utils/config.js'), 'utf8')
if (!/BASE_URL:\s*'https?:\/\//.test(cfg)) err('utils/config.js 的 BASE_URL 未配置')
if (!/CHANNEL:\s*'mp'/.test(cfg)) err('utils/config.js 的 CHANNEL 必须为 mp')
ok('运行时配置')

console.log(bad === 0 ? '\n全部通过' : '\n有 ' + bad + ' 个问题')
process.exitCode = bad ? 1 : 0
