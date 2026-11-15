// 展示格式化。
// 只放纯函数，不碰 wx API —— 这样这些函数也能在 Node 里直接跑测试。

function pad(n) {
  return n < 10 ? '0' + n : '' + n
}

// size：与文档中心一致，1024 进制，保留一位小数
function size(bytes) {
  const n = Number(bytes) || 0
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

function absTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return (
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes())
  )
}

// relTime：列表里用相对时间，详情里用绝对时间（两者回答的问题不同）
function relTime(iso) {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (isNaN(t)) return '—'
  const diff = Date.now() - t
  const min = Math.round(diff / 60000)
  if (min < 1) return '刚刚'
  if (min < 60) return min + ' 分钟前'
  const h = Math.round(min / 60)
  if (h < 24) return h + ' 小时前'
  const day = Math.round(h / 24)
  if (day < 30) return day + ' 天前'
  return absTime(iso).slice(0, 10)
}

module.exports = { size, absTime, relTime }
