// 审批详情：通过 / 驳回。
//
// 当前服务端接口只收 {approve: boolean}，没有"审批意见"字段——
// 所以这里不做意见输入框：一个填了也不会保存的输入框，比没有更糟。
const auth = require('../../services/auth')
const approvals = require('../../services/approvals')
const fmt = require('../../utils/format')
const cls = require('../../utils/classify')
const meta = require('../../services/meta')

Page({
  data: {
    state: 'loading',
    errText: '',
    item: null,
    busy: false
  },

  onLoad(options) {
    this.id = options.id || ''
    meta.applyTitle('审批详情')
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    this.load()
  },

  load() {
    const cached = getApp().globalData.pendingShare
    if (cached && cached.id === this.id) {
      this.setData({ state: 'ready', item: cached })
      return
    }
    // 直接从分享卡片/历史进入：重新拉一次待办再按 id 找
    this.setData({ state: 'loading' })
    approvals.pending().then((list) => {
      const hit = list.map((x) => ({
        id: x.shareId,
        name: x.name,
        creator: x.creator || '未知',
        classLabel: cls.label(x.classification),
        classTone: cls.tone(x.classification),
        stageText: cls.stageLabel(x.stage),
        createdText: fmt.absTime(x.createdAt),
        expireText: x.expiresAt ? fmt.absTime(x.expiresAt) : '',
        approverName: x.approverName || '',
        ownerName: x.ownerApproverName || ''
      })).filter((x) => x.id === this.id)[0]
      if (!hit) {
        this.setData({ state: 'error', errText: '这条申请已处理或不属于你' })
        return
      }
      this.setData({ state: 'ready', item: hit })
    }).catch((err) => {
      this.setData({ state: 'error', errText: (err && err.message) || '读取失败' })
    })
  },

  onApprove() { this.decide(true) },
  onReject() { this.decide(false) },

  decide(approve) {
    if (this.data.busy) return
    wx.showModal({
      title: approve ? '通过这条外发申请？' : '驳回这条外发申请？',
      content: approve
        ? '通过后，发起人会拿到一条限时外链，访问范围按申请时的设置生效。'
        : '驳回后申请人需要重新发起。',
      confirmText: approve ? '通过' : '驳回',
      confirmColor: approve ? '#0f5c40' : '#a93b2c',
      success: (r) => {
        if (!r.confirm) return
        this.setData({ busy: true })
        approvals.decide(this.id, approve).then(() => {
          this.setData({ busy: false })
          wx.showToast({ title: approve ? '已通过' : '已驳回', icon: 'success' })
          getApp().globalData.pendingShare = null
          setTimeout(() => wx.navigateBack(), 700)
        }).catch((err) => {
          this.setData({ busy: false })
          wx.showModal({
            title: '处理失败',
            content: (err && err.message) || '请稍后重试',
            showCancel: false
          })
        })
      }
    })
  }
})
