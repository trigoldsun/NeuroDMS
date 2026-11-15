// 预览：从 /v1/nodes/{id}/preview 取内容，再按类型交给微信的渲染能力。
//
// 为什么不用 <image src> 直接指后端地址：图片标签不能带 Authorization，
// 必须先下载到临时文件再用本地路径。PDF / Office 同理——openDocument
// 只接受本地路径。
const auth = require('../../services/auth')
const content = require('../../services/content')
const fmt = require('../../utils/format')
const cls = require('../../utils/classify')
const meta = require('../../services/meta')

const IMAGE = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp']
const TEXT = ['txt', 'md', 'csv', 'log', 'json']
const OFFICE = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']

function extOf(name) {
  const s = String(name || '')
  const i = s.lastIndexOf('.')
  return i > 0 ? s.slice(i + 1).toLowerCase() : ''
}

Page({
  data: {
    state: 'loading',
    errText: '',
    file: null,
    kind: '',
    imagePath: '',
    textContent: '',
    opening: false
  },

  onLoad(options) {
    this.id = options.id || ''
    meta.applyTitle('预览')
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    this.load()
  },

  load() {
    this.setData({ state: 'loading', errText: '' })
    content.nodeMeta(this.id).then((n) => {
      const ext = extOf(n.name)
      const kind = IMAGE.indexOf(ext) >= 0 ? 'image'
        : TEXT.indexOf(ext) >= 0 ? 'text'
          : OFFICE.indexOf(ext) >= 0 ? 'office' : 'other'
      const view = {
        id: n.id,
        name: n.name,
        ext: ext.toUpperCase(),
        sizeText: fmt.size(n.size),
        updatedText: fmt.absTime(n.updatedAt),
        ownerName: (n.owner && n.owner.name) || '',
        classLabel: cls.label(n.classification),
        classTone: cls.tone(n.classification),
        versionNo: n.versionNo
      }
      this.setData({ state: 'ready', file: view, kind: kind })
      if (kind === 'image') this.loadImage()
      if (kind === 'text') this.loadText()
    }).catch((err) => {
      this.fail(err)
    })
  },

  // 403/404 不弹 toast，而是整页说明"为什么打不开、该找谁"：
  // 密级不足在小程序里同样会发生，一句"加载失败"帮不上忙。
  fail(err) {
    if (err && err.status === 401) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    const msg = (err && err.message) || '文件打开失败'
    this.setData({ state: 'error', errText: msg })
  },

  loadImage() {
    content.fetchPreview(this.id).then((path) => {
      this.setData({ imagePath: path })
    }).catch((err) => {
      this.setData({ state: 'error', errText: (err && err.message) || '图片读取失败' })
    })
  },

  loadText() {
    content.fetchPreview(this.id).then((path) => {
      wx.getFileSystemManager().readFile({
        filePath: path,
        encoding: 'utf8',
        success: (res) => this.setData({ textContent: res.data }),
        fail: () => this.setData({ state: 'error', errText: '文本内容读取失败' })
      })
    }).catch((err) => {
      this.setData({ state: 'error', errText: (err && err.message) || '文本读取失败' })
    })
  },

  onTapImage() {
    if (!this.data.imagePath) return
    wx.previewImage({ current: this.data.imagePath, urls: [this.data.imagePath] })
  },

  onOpenDocument() {
    if (this.data.opening) return
    this.setData({ opening: true })
    const ext = (this.data.file && this.data.file.ext || '').toLowerCase()
    content.fetchPreview(this.id).then((path) => {
      wx.openDocument({
        filePath: path,
        fileType: ext,
        // 关掉右上角菜单：减少"顺手另存/转发"，与网页端的策略保持一致
        showMenu: false,
        success: () => this.setData({ opening: false }),
        fail: (e) => {
          this.setData({ opening: false })
          wx.showModal({
            title: '无法打开',
            content: '微信内置文档组件不支持该格式或文件已损坏。' + (e && e.errMsg ? '\n' + e.errMsg : ''),
            showCancel: false
          })
        }
      })
    }).catch((err) => {
      this.setData({ opening: false })
      wx.showModal({ title: '打开失败', content: (err && err.message) || '请稍后重试', showCancel: false })
    })
  }
})
