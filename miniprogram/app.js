// 应用入口。
//
// 不在这里强制跳登录：首页（文件）与「我的」都会自己检查会话并 reLaunch。
// 放在 onLaunch 里跳，会与页面自身的 onShow 抢时序，出现过"刚进登录页又被拉回首页"。
const auth = require('./services/auth')
const meta = require('./services/meta')
const cls = require('./utils/classify')

App({
  globalData: {
    me: null,
    // 审批详情从列表进入；列表把选中项放这里，避免详情页再查一次无 id 的接口。
    pendingShare: null
  },

  onLaunch() {
    this.globalData.me = auth.cachedMe()
    // 密级名称与品牌先读缓存：首屏不闪，随后各页面按需再拉一次覆盖。
    cls.loadCached()
    meta.loadBranding('')
  }
})
