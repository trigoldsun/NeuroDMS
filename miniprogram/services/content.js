// 文件与空间：只读浏览（空间 → 目录 → 文件）。
//
// 这一版小程序不做上传与新建，所以这里没有写路径；
// 需要写操作时应当调用同一套 /v1/spaces/* 接口，而不是另开一套。
const { request, download } = require('../utils/request')

function listSpaces() {
  return request({ path: '/v1/spaces' }).then(function (d) {
    return d.items || []
  })
}

function listNodes(spaceId, parentId) {
  const q = parentId ? '?parentId=' + encodeURIComponent(parentId) : ''
  return request({ path: '/v1/spaces/' + spaceId + '/nodes' + q }).then(function (d) {
    return d.items || []
  })
}

function nodeMeta(id) {
  return request({ path: '/v1/nodes/' + id })
}

// previewPath 走预览接口而不是下载接口：
// 预览只要求 Preview 位，且服务端会叠加溯源水印（PDF）；
// 下载接口要求 Download 位，用它做预览等于用更高的权限看同一份文件。
function previewPath(id) {
  return '/v1/nodes/' + id + '/preview'
}

function fetchPreview(id) {
  return download(previewPath(id))
}

// search 全文搜索（服务端逐条判可见性，前端只负责展示）。
//
// q 至少 1 个字符、最长 128；结果里 truncated=true 表示"命中太多被截断"，
// 界面上要说清楚，否则用户会以为组织里只有这么多文件。
function search(q, limit) {
  const query = String(q || '').trim()
  if (!query) return Promise.resolve({ items: [], count: 0, truncated: false })
  const n = limit || 20
  return request({
    path: '/v1/search?q=' + encodeURIComponent(query) + '&limit=' + n
  }).then(function (d) {
    return { items: d.items || [], count: d.count || 0, truncated: !!d.truncated }
  })
}

// recent 最近访问：从"我的活动"里取预览/下载记录，按对象去重。
//
// 为什么不在本地记：本地记录只覆盖这台设备，换手机就没了；
// 服务端的活动日志本来就是"我做过什么"的权威来源，且已经做过脱敏。
const RECENT_ACTIONS = { 'node.preview': '预览', 'node.download': '下载' }

function recent(limit) {
  return request({ path: '/v1/me/activity?size=30' }).then(function (d) {
    const seen = {}
    const out = []
    for (const x of d.items || []) {
      const act = RECENT_ACTIONS[x.action]
      if (!act) continue
      if (x.result && x.result !== 'ok') continue
      if (!x.objectId || seen[x.objectId]) continue
      seen[x.objectId] = true
      out.push({ id: x.objectId, name: x.objectName || '（已删除或无权查看）', actionText: act, createdAt: x.createdAt })
      if (out.length >= (limit || 5)) break
    }
    return out
  })
}

module.exports = { listSpaces, listNodes, nodeMeta, fetchPreview, previewPath, search, recent }
