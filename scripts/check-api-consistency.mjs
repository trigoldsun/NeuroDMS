// 前后端接口一致性检查。
//
// 目的：找出三类问题
//   1. 前端调用了后端不存在的路径（点了就 404）；
//   2. 后端有路由但前端完全没有入口（孤儿接口，通常是重构后忘了删）；
//   3. 前端用的是动态前缀（`'/v1/platform' + path`），无法静态判定，单独列出。
//
// 用法：node scripts/check-api-consistency.mjs
//
// 为什么不用正则一把梭：路径里会出现 `${encodeURIComponent(x.y)}` 这种嵌套括号，
// 正则会在第一个 `)` 处截断，把正确路径误报成"不存在"。这里按括号深度扫描。

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, extname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === 'dist') continue
      walk(p, out)
    } else {
      out.push(p)
    }
  }
  return out
}

// ---------- 后端路由 ----------
const backend = []
for (const f of walk(join(ROOT, 'internal/httpapi'))) {
  if (!f.endsWith('.go') || f.endsWith('_test.go')) continue
  const src = readFileSync(f, 'utf8')
  for (const m of src.matchAll(/HandleFunc\("([A-Z]+)\s+(\/v1\/[^"]+)"/g)) {
    backend.push({
      method: m[1],
      norm: m[2].replace(/\{[^}]+\}/g, '{}').replace(/\/$/, ''),
      file: f.replace(ROOT, ''),
    })
  }
}

// ---------- 前端调用 ----------
// 从 `/v1/` 开始逐字符扫描：`${` 进入模板表达式并计数括号，
// 遇到空白/引号/反引号/逗号/分号/`)` 即路径结束。
function extractPaths(line) {
  const out = []
  let i = 0
  while (i < line.length) {
    const start = line.indexOf('/v1/', i)
    if (start < 0) break
    let j = start
    let depth = 0
    let path = ''
    while (j < line.length) {
      const ch = line[j]
      if (ch === '$' && line[j + 1] === '{') {
        depth = 1
        j += 2
        while (j < line.length && depth > 0) {
          if (line[j] === '{') depth++
          else if (line[j] === '}') depth--
          j++
        }
        path += '{}'
        continue
      }
      if (/[\s'"`,;)\]]/.test(ch)) break
      path += ch
      j++
    }
    out.push(path)
    i = j > start ? j : start + 1
  }
  return out
}

const frontend = []
for (const f of walk(join(ROOT, 'web/src'))) {
  if (!['.ts', '.tsx'].includes(extname(f))) continue
  const src = readFileSync(f, 'utf8')
  src.split('\n').forEach((line, idx) => {
    const trimmed = line.trim()
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return
    // 字符串判断不是调用：startsWith/includes/indexOf 后面跟的路径只是匹配规则
    if (/\b(startsWith|includes|indexOf|endsWith)\s*\(/.test(line)) return
    for (let p of extractPaths(line)) {
      p = p.split('?')[0].replace(/\/+$/, '')
      if (!p || p === '/v1') continue
      frontend.push({ norm: p, file: f.replace(ROOT, ''), line: idx + 1, snippet: trimmed.slice(0, 110) })
    }
  })
}

// ---------- 匹配 ----------
const exact = new Set(backend.map((b) => b.norm))
// 动态前缀：前端只写了 `/v1/platform`，实际路径是拼出来的
const prefixes = [...new Set(frontend.map((f) => f.norm))].filter((p) =>
  backend.some((b) => b.norm.startsWith(p + '/') || b.norm.startsWith(p)),
)

const missing = []
const covered = new Set()
for (const fe of frontend) {
  if (exact.has(fe.norm)) {
    covered.add(fe.norm)
    continue
  }
  // 动态前缀（'/v1/platform' + path）：无法静态判定，按前缀覆盖处理，不算缺失
  if (prefixes.includes(fe.norm)) {
    covered.add(fe.norm)
    continue
  }
  // 前端路径以某条后端路由为前缀，且剩余部分不是新的路径段（查询串被拼进来的情况）
  const asPrefixHit = [...exact].some(
    (b) => fe.norm.startsWith(b) && !fe.norm.slice(b.length).startsWith('/'),
  )
  if (asPrefixHit) {
    covered.add(fe.norm)
    continue
  }
  missing.push(fe)
}

const orphans = backend.filter((b) => {
  if (covered.has(b.norm)) return false
  // 被动态前缀覆盖的（如 /v1/platform/...）不算孤儿
  return !prefixes.some((p) => p.length >= 8 && (b.norm === p || b.norm.startsWith(p + '/') || b.norm.startsWith(p)))
})

const uniq = (arr, key) => {
  const seen = new Set()
  return arr.filter((x) => {
    const k = key(x)
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}

const missingU = uniq(missing, (x) => x.norm)
const orphanU = uniq(orphans, (x) => x.method + ' ' + x.norm)
const prefixU = uniq(
  frontend.filter((f) => !exact.has(f.norm) && prefixes.includes(f.norm)),
  (x) => x.norm,
)

console.log(`后端路由：${backend.length} 条（唯一路径 ${exact.size}）`)
console.log(`前端调用：${frontend.length} 处（唯一路径 ${new Set(frontend.map((f) => f.norm)).size}）`)
console.log('')

if (missingU.length === 0) {
  console.log('✓ 前端调用的路径全部能在后端找到')
} else {
  console.log(`✗ 前端调用但后端不存在（${missingU.length} 个）：`)
  for (const m of missingU) console.log(`  ${m.norm}\n     ${m.file}:${m.line}  ${m.snippet}`)
}

console.log('')
if (prefixU.length > 0) {
  console.log('· 动态前缀（无法静态判定，已按前缀覆盖）：')
  for (const p of prefixU) console.log(`  ${p.norm}   ${p.file}:${p.line}`)
  console.log('')
}

if (orphanU.length === 0) {
  console.log('✓ 没有无前端入口的孤立接口')
} else {
  console.log(`· 后端有路由、前端未见调用（${orphanU.length} 条，需确认是脚本/第三方/待接入）：`)
  for (const o of orphanU) console.log(`  ${o.method} ${o.norm}   (${o.file})`)
}

process.exitCode = missingU.length > 0 ? 1 : 0
