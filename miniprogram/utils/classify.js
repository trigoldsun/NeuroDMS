// 密级与审批阶段的展示字典。
//
// 为什么不在代码里写死密级名称：主项目从 1.4 起允许租户在「密级定义」里
// 逐级改名（GET /v1/classifications）。名称写死的结果是同一个人在网页端
// 看到"商密A"、在小程序里看到"秘密"——同一个 5 级文件两种叫法。
// 所以名称一律来自服务端，本文件只保留**取不到时**的等级数字兜底。
const STORE_KEY = 'dv_mp_class_labels'

// names 按 level 索引；未加载时为空数组。
let names = []

function setLabels(list) {
  // 按 level 直接落位，不能"排序后取第 n 个"：服务端可能只返回部分档位，
  // 那样 1 级会拿到 3 级的名称，比不显示更糟。
  const arr = []
  for (const x of list || []) {
    if (!x || typeof x.level !== 'number' || !x.name) continue
    arr[x.level] = x.name
  }
  names = arr
  try {
    wx.setStorageSync(STORE_KEY, names)
  } catch (e) { /* 存储满/被清理都不影响本次会话 */ }
}

// loadCached 在冷启动时把上次的名称读回来，避免首屏出现"3 级"再跳变。
function loadCached() {
  try {
    const v = wx.getStorageSync(STORE_KEY)
    if (Array.isArray(v)) names = v
  } catch (e) { /* 忽略 */ }
  return names
}

function nameOf(level) {
  const lv = Math.max(0, Math.min(6, Number(level) || 0))
  return names[lv] || ''
}

// label 形如「机密（4 级）」；名称未知时只显示等级，不编造名称。
function label(level) {
  const lv = Math.max(0, Math.min(6, Number(level) || 0))
  const n = names[lv]
  return n ? n + '（' + lv + ' 级）' : lv + ' 级'
}

function tone(level) {
  const lv = Math.max(0, Math.min(6, Number(level) || 0))
  return 'c' + lv
}

// 审批阶段：取值由数据库约束（none|first|owner|done）决定。
// 早先这里判的是 'approver'——那个值永远不会出现，导致首段一律显示"审批中"。
function stageLabel(stage) {
  if (stage === 'first') return '待审批人处理'
  if (stage === 'owner') return '待所有者确认'
  if (stage === 'done') return '已完成'
  if (stage === 'none') return '无需审批'
  return '—'
}

module.exports = { label, tone, stageLabel, setLabels, loadCached, nameOf }
