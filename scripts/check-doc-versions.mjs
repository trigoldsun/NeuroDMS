#!/usr/bin/env node
// 文档版本一致性门禁：所有文档的版本必须等于产品版本（仓库根 VERSION）。
//
// 为什么要机器校验：这条规则已经人工重演过三次（手册跳到 V2.x、手册与产品脱节、
// 各设计文档各写各的 v1.0/v1.1）。靠记性必然再犯，所以把"版本只有一处事实源"
// 变成可执行断言——发版只改 VERSION，谁漏改谁在这里失败。
//
// 校验范围（三处必须同源）：
//   1. docs/*.md 的**文件名后缀** -v<VER>.md 与头部 `版本：V<VER>`
//   2. docs/html/*.html 的版本 chip / 页脚
//   3. 索引与主文档存在、且索引的章节表与主文档的章节数一致
//
// 豁免（历史快照与对外材料，改了等于伪造历史）：
//   docs/archive/、docs/phase2/、docs/releases/、docs/deck、
//   docs/37-版本发布-V1.0.0-与回退手册.md、CHANGELOG.md、docs/versions.lock.md（无编号前缀）

import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const root = process.cwd()
const VER = readFileSync(join(root, 'VERSION'), 'utf8').trim()
const TAG = `V${VER}`

// 不改名、仍需校验头部版本的文件
const KEEP_NAME = new Set(['versions.lock.md'])
// 历史快照：连头部版本都不校验（它记录的是 V1.0.0，改了等于伪造历史）
const HISTORICAL = new Set(['37-版本发布-V1.0.0-与回退手册.md'])

const problems = []
const fail = (m) => problems.push(m)

// ---------- 1. docs/*.md ----------
const docsDir = join(root, 'docs')
const mdFiles = readdirSync(docsDir).filter((f) => f.endsWith('.md') && !f.startsWith('.'))
let checked = 0

for (const f of mdFiles) {
  if (HISTORICAL.has(f)) continue
  if (!KEEP_NAME.has(f)) {
    checked++
    if (!f.endsWith(`-v${VER}.md`)) fail(`docs/${f}：文件名版本不是 -v${VER}.md`)
  }
  const head = readFileSync(join(docsDir, f), 'utf8').split('\n').slice(0, 20).join('\n')
  const ok = head.includes(`版本：${TAG}`) || new RegExp(`^\\|\\s*版本\\s*\\|\\s*${TAG}`, 'm').test(head)
  if (!ok) fail(`docs/${f}：头部 20 行内没有「版本：${TAG}」或「| 版本 | ${TAG} …」`)
}

// ---------- 2. 网页版手册 ----------
const htmlDir = join(docsDir, 'html')
const htmls = readdirSync(htmlDir).filter((f) => f.endsWith('.html'))
for (const f of htmls) {
  if (!readFileSync(join(htmlDir, f), 'utf8').includes(TAG)) {
    fail(`docs/html/${f}：未出现版本 ${TAG}（chip 或页脚）`)
  }
}

// ---------- 3. 主文档与索引 ----------
const masterName = `NeuroDMS-技术文档-v${VER}.md`
let masterChapters = 0
try {
  const body = readFileSync(join(docsDir, masterName), 'utf8')
  if (!body.includes(`版本：${TAG}`)) fail(`docs/${masterName}：头部缺少「版本：${TAG}」`)
  masterChapters = (body.match(/^### \d+\.\d+ /gm) || []).length
  if (!masterChapters) fail(`docs/${masterName}：没有解析到任何「### X.Y」章节，文件可能被破坏`)
} catch {
  fail(`docs/${masterName}：主文档不存在（整合或改名后忘记同步？）`)
}

const indexName = `README-文档索引与评审说明-v${VER}.md`
try {
  const idx = readFileSync(join(docsDir, indexName), 'utf8')
  if (!idx.includes(`版本：${TAG}`)) fail(`docs/${indexName}：头部缺少「版本：${TAG}」`)
  const idxChapters = (idx.match(/^\| \d+\.\d+ \|/gm) || []).length
  if (masterChapters && idxChapters !== masterChapters) {
    fail(`docs/${indexName}：章节表 ${idxChapters} 行，主文档 ${masterChapters} 章——索引没跟着主文档更新`)
  }
} catch {
  fail(`docs/${indexName}：索引文件不存在`)
}

// ---------- 输出 ----------
console.log(
  `产品版本 ${VER}；docs/*.md ${checked} 份（另 ${mdFiles.length - checked} 份豁免改名）、` +
    `网页版 ${htmls.length} 份、主文档 ${masterChapters} 章`
)
if (problems.length) {
  console.error('文档版本/结构不一致：')
  for (const p of problems) console.error('  - ' + p)
  console.error(`\n修复：把版本改成 ${TAG}（改 VERSION 时一并改），或按索引 §5「归档与历史」登记例外。`)
  process.exit(1)
}
console.log('OK：文件名 / 头部 / 网页版 / 主文档 / 索引 五处一致')
