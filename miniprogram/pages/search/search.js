// 搜索：按文件名找文件（GET /v1/search）。
//
// 三条必须在移动端处理掉的细节：
//   1. 输入防抖（300ms）——每敲一个字就发请求，4 个字就是 4 次往返；
//   2. 竞态丢弃——先发的慢请求后到，会把新关键词的结果覆盖成旧结果，
//      所以每次请求带序号，只认最新那次；
//   3. 空结果与"被截断"分开说——否则用户以为组织里只有 20 个文件。
const auth = require('../../services/auth')
const content = require('../../services/content')
const meta = require('../../services/meta')
const fmt = require('../../utils/format')

const DEBOUNCE_MS = 300

Page({
  data: {
    q: '',
    state: 'idle', // idle | loading | ready | empty | error
    items: [],
    truncated: false,
    errText: '',
    focused: true
  },

  onLoad(options) {
    meta.applyTitle('搜索')
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    this.seq = 0
    // 支持从别处带关键词进来（例如以后的"按标签查"）
    const q = (options && options.q) || ''
    if (q) {
      this.setData({ q: q })
      this.run(q)
    }
  },

  onUnload() {
    if (this.timer) clearTimeout(this.timer)
  },

  onInput(e) {
    const q = e.detail.value
    this.setData({ q: q })
    if (this.timer) clearTimeout(this.timer)
    if (!q.trim()) {
      this.seq++ // 让在途请求作废
      this.setData({ state: 'idle', items: [], truncated: false, errText: '' })
      return
    }
    this.setData({ state: 'loading' })
    this.timer = setTimeout(() => this.run(q), DEBOUNCE_MS)
  },

  onConfirm() {
    if (this.timer) clearTimeout(this.timer)
    if (this.data.q.trim()) this.run(this.data.q)
  },

  onClear() {
    if (this.timer) clearTimeout(this.timer)
    this.seq++
    this.setData({ q: '', state: 'idle', items: [], truncated: false, errText: '' })
  },

  run(q) {
    const mine = ++this.seq
    this.setData({ state: 'loading', errText: '' })
    content.search(q, 30).then((r) => {
      if (mine !== this.seq) return // 已有更新的关键词，丢弃这次结果
      const items = r.items.map((x) => ({
        id: x.nodeId,
        name: x.name,
        isFolder: x.kind === 'folder',
        extText: x.kind === 'folder' ? 'DIR' : String(x.ext || '').toUpperCase().slice(0, 4),
        sizeText: x.kind === 'folder' ? '' : fmt.size(x.sizeBytes),
        timeText: fmt.relTime(x.updatedAt)
      }))
      this.setData({
        items: items,
        truncated: r.truncated,
        state: items.length ? 'ready' : 'empty'
      })
    }).catch((err) => {
      if (mine !== this.seq) return
      if (err && err.status === 401) {
        wx.reLaunch({ url: '/pages/login/login' })
        return
      }
      this.setData({ state: 'error', errText: (err && err.message) || '搜索失败，请稍后重试' })
    })
  },

  onOpen(e) {
    const id = e.currentTarget.dataset.id
    const item = this.data.items.filter((x) => x.id === id)[0]
    if (!item) return
    // 目录在搜索结果里也返回；这一版搜索页不下钻目录，明确提示而不是点了没反应
    if (item.isFolder) {
      wx.showToast({ title: '请到文件页进入该目录', icon: 'none' })
      return
    }
    wx.navigateTo({
      url: '/pages/preview/preview?id=' + id + '&name=' + encodeURIComponent(item.name)
    })
  }
})
