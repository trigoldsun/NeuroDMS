// 文件：真实数据（GET /v1/spaces → GET /v1/spaces/{id}/nodes）。
//
// 只读浏览：点目录进下一层，点文件进预览。上传/新建属于写功能，这一版不做——
// 但"只读"要在界面上说清楚，否则用户会以为是加载失败。
const auth = require('../../services/auth')
const content = require('../../services/content')
const meta = require('../../services/meta')
const fmt = require('../../utils/format')
const cls = require('../../utils/classify')

const SPACE_KEY = 'dv_mp_space'

function viewNode(n) {
  const isFolder = n.kind === 'folder'
  const ext = (n.name || '').split('.').pop().toLowerCase()
  return {
    id: n.id,
    name: n.name,
    isFolder: isFolder,
    extText: isFolder ? 'DIR' : (ext.length <= 4 ? ext.toUpperCase() : 'FILE'),
    sizeText: isFolder ? '' : fmt.size(n.size),
    timeText: fmt.relTime(n.updatedAt),
    classLabel: cls.label(n.classification),
    classTone: cls.tone(n.classification),
    ownerName: (n.owner && n.owner.name) || ''
  }
}

Page({
  data: {
    state: 'loading',
    errText: '',
    me: null,
    spaces: [],
    spaceId: '',
    spaceName: '',
    path: [],
    nodes: [],
    parentId: '',
    // 最近访问只在空间根目录展示：进到子目录后它是干扰，不是帮助
    recent: [],
    recentLoading: false
  },

  onShow() {
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    meta.applyTitle('文件')
    this.setData({ me: auth.cachedMe() || {} })
    if (!this.data.spaces.length) this.loadSpaces()
    else this.loadNodes()
    if (!this.data.path.length) this.loadRecent()
  },

  // 最近访问来自服务端活动日志（同一账号换设备也在）。失败静默：
  // 它只是入口，取不到不该让整页变成错误态。
  loadRecent() {
    this.setData({ recentLoading: true })
    content.recent(5).then((list) => {
      this.setData({
        recent: list.map((x) => ({
          id: x.id, name: x.name, actionText: x.actionText, timeText: fmt.relTime(x.createdAt)
        })),
        recentLoading: false
      })
    }).catch(() => {
      this.setData({ recent: [], recentLoading: false })
    })
  },

  goSearch() {
    wx.navigateTo({ url: '/pages/search/search' })
  },

  onRecent(e) {
    const id = e.currentTarget.dataset.id
    const item = this.data.recent.filter((x) => x.id === id)[0]
    if (!item) return
    wx.navigateTo({
      url: '/pages/preview/preview?id=' + id + '&name=' + encodeURIComponent(item.name)
    })
  },

  onPullDownRefresh() {
    const done = () => wx.stopPullDownRefresh()
    if (!this.data.spaces.length) this.loadSpaces(done)
    else this.loadNodes(done)
  },

  loadSpaces(done) {
    this.setData({ state: 'loading', errText: '' })
    content.listSpaces().then((list) => {
      const spaces = list.map((s) => ({ id: s.id, name: s.name }))
      if (!spaces.length) {
        this.setData({ spaces: [], state: 'empty' })
        if (done) done()
        return
      }
      const saved = wx.getStorageSync(SPACE_KEY)
      const pick = spaces.filter((s) => s.id === saved)[0] || spaces[0]
      this.setData({ spaces: spaces, spaceId: pick.id, spaceName: pick.name, path: [] })
      this.loadNodes(done)
    }).catch((err) => {
      this.setData({ state: 'error', errText: this.errText(err) })
      if (done) done()
    })
  },

  loadNodes(done) {
    const spaceId = this.data.spaceId
    if (!spaceId) { this.setData({ state: 'empty' }); return }
    const path = this.data.path
    const parentId = path.length ? path[path.length - 1].id : ''
    this.setData({ state: 'loading', errText: '', parentId: parentId })
    content.listNodes(spaceId, parentId).then((items) => {
      const nodes = items.map(viewNode)
      // 目录在前、文件在后；同类按名称排。服务端按更新时间返回，
      // 对"找文件"来说，把目录混在文件中间会让手指多点好几次。
      nodes.sort((a, b) => {
        if (a.isFolder !== b.isFolder) return a.isFolder ? -1 : 1
        return a.name.localeCompare(b.name)
      })
      this.setData({ nodes: nodes, state: nodes.length ? 'ready' : 'empty' })
      if (done) done()
    }).catch((err) => {
      if (err.status === 401) {
        wx.reLaunch({ url: '/pages/login/login' })
        return
      }
      this.setData({ state: 'error', errText: this.errText(err) })
      if (done) done()
    })
  },

  errText(err) {
    if (!err) return '读取失败'
    if (err.status === 403) return err.message || '没有查看这个空间的权限'
    if (err.status === 404) return '空间或目录不存在'
    return err.message || '读取失败，请稍后重试'
  },

  onSpace(e) {
    const id = e.currentTarget.dataset.id
    if (id === this.data.spaceId) return
    const sp = this.data.spaces.filter((s) => s.id === id)[0]
    wx.setStorageSync(SPACE_KEY, id)
    this.setData({ spaceId: id, spaceName: sp ? sp.name : '', path: [] })
    this.loadNodes()
  },

  // 目录与文件共用一个点击入口：WXML 里动态绑定事件名（bindtap="{{...}}"）
  // 在部分基础库上不生效，点击会"什么都不发生"。按数据分流最稳。
  onRow(e) {
    const id = e.currentTarget.dataset.id
    const node = this.data.nodes.filter((n) => n.id === id)[0]
    if (!node) return
    if (node.isFolder) {
      this.setData({ path: this.data.path.concat([{ id: node.id, name: node.name }]) })
      this.loadNodes()
      return
    }
    wx.navigateTo({
      url: '/pages/preview/preview?id=' + node.id + '&name=' + encodeURIComponent(node.name)
    })
  },

  onCrumb(e) {
    const idx = Number(e.currentTarget.dataset.index)
    // index=-1 表示回到空间根；其余表示回退到第 idx 个目录
    this.setData({ path: idx < 0 ? [] : this.data.path.slice(0, idx + 1) })
    this.loadNodes()
    if (idx < 0) this.loadRecent()
  },

  onRetry() {
    if (!this.data.spaces.length) this.loadSpaces()
    else this.loadNodes()
  }
})
