// 审批：待我审批的分享申请。
//
// 列表只展示服务端返回的字段；能不能批由服务端判定（ManageACL + 指定审批人）。
// 点条目进详情，详情页从 globalData 取当前项，避免再查一个不存在的单条接口。
const auth = require('../../services/auth')
const approvals = require('../../services/approvals')
const fmt = require('../../utils/format')
const cls = require('../../utils/classify')
const meta = require('../../services/meta')
const mp = require('../../services/mp')

function view(x) {
  return {
    id: x.shareId,
    name: x.name,
    creator: x.creator || '未知',
    classLabel: cls.label(x.classification),
    classTone: cls.tone(x.classification),
    stageText: cls.stageLabel(x.stage),
    createdText: fmt.relTime(x.createdAt),
    expireText: x.expiresAt ? fmt.absTime(x.expiresAt) : '',
    approverName: x.approverName || '',
    ownerName: x.ownerApproverName || ''
  }
}

Page({
  data: {
    state: 'loading',
    errText: '',
    items: [],
    // 提醒：未配置通道时 enabled=false，整块入口不出现
    remind: { enabled: false, templateId: '', remaining: 0, bound: false },
    remindBusy: false
  },

  onShow() {
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    meta.applyTitle('审批')
    // 密级名称可能刚在网页端改过：先刷新再渲染，避免列表里出现旧名称
    meta.loadClassLabels().then(() => this.load(), () => this.load())
    this.loadRemind()
  },

  loadRemind() {
    return meta.loadMpConfig().then((c) => {
      this.setData({
        remind: {
          enabled: !!(c && c.enabled),
          templateId: (c && c.todoSubscribeTemplateId) || '',
          remaining: (c && c.remaining) || 0,
          bound: !!(c && c.openidBound)
        }
      })
    }).catch(() => {})
  },

  // 微信订阅消息是一次性的：授权一次只能发一条。
  // 所以按钮文案是"开启提醒（1 条）"，不能写"永久开启"——那是在承诺做不到的事。
  onEnableRemind() {
    if (this.data.remindBusy) return
    const templateId = this.data.remind.templateId
    if (!templateId) return
    this.setData({ remindBusy: true })
    mp.askSubscribe(templateId).then((result) => {
      if (result !== 'accept') {
        this.setData({ remindBusy: false })
        wx.showToast({ title: '未开启，不影响审批', icon: 'none' })
        return
      }
      return mp.grant(templateId).then((d) => {
        this.setData({
          remindBusy: false,
          'remind.remaining': (d && d.remaining) || this.data.remind.remaining + 1
        })
        wx.showToast({ title: '已开启，下一条申请会通知你', icon: 'none' })
      })
    }).catch((err) => {
      this.setData({ remindBusy: false })
      wx.showModal({
        title: '提醒没开起来',
        content: (err && err.message) || '请稍后重试；审批本身不受影响。',
        showCancel: false
      })
    })
  },

  onPullDownRefresh() {
    this.load(() => wx.stopPullDownRefresh())
  },

  load(done) {
    this.setData({ state: 'loading', errText: '' })
    approvals.pending().then((list) => {
      const items = list.map(view)
      this.setData({ items: items, state: items.length ? 'ready' : 'empty' })
      this.syncBadge(items.length)
      if (done) done()
    }).catch((err) => {
      if (err.status === 401) {
        wx.reLaunch({ url: '/pages/login/login' })
        return
      }
      this.setData({ state: 'error', errText: (err && err.message) || '读取待办失败' })
      if (done) done()
    })
  },

  // 角标是"有事等我"的第二处提示：用户停在文件页也能看见
  syncBadge(n) {
    if (n > 0) wx.setTabBarBadge({ index: 1, text: String(n) })
    else wx.removeTabBarBadge({ index: 1 })
  },

  onOpen(e) {
    const id = e.currentTarget.dataset.id
    const item = this.data.items.filter((x) => x.id === id)[0]
    getApp().globalData.pendingShare = item || null
    wx.navigateTo({ url: '/pages/approval/approval?id=' + id })
  },

  onRetry() { this.load() }
})
