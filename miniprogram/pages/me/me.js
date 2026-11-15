// 我的：账号信息 + 退出登录。
//
// 账号相关的设置集中在这一页：组织、账号、手机号、密级、角色、退出。
// 手机号换绑仍在网页端完成——换绑要"当前口令 + 新号码验证码"，
// 把两步挤进手机小键盘不划算，网页端已有完整的账号安全入口。
const auth = require('../../services/auth')
const cfg = require('../../utils/config')
const cls = require('../../utils/classify')
const meta = require('../../services/meta')

Page({
  data: {
    me: null,
    initial: '·',
    classLabel: '',
    classTone: '',
    rolesText: '',
    phoneText: '',
    phoneVerified: false,
    serverHost: '',
    version: cfg.VERSION,
    busy: false
  },

  onShow() {
    if (!auth.hasSession()) {
      wx.reLaunch({ url: '/pages/login/login' })
      return
    }
    meta.applyTitle('我的')
    this.apply(auth.cachedMe())
    // 缓存先显示，随后用服务端结果覆盖：手机号/角色可能在网页端刚改过
    auth.me().then((me) => this.apply(me)).catch((err) => {
      if (err && err.status === 401) wx.reLaunch({ url: '/pages/login/login' })
    })
  },

  apply(me) {
    if (!me) return
    this.setData({
      me: me,
      initial: (me.displayName || me.username || '·').slice(0, 1),
      classLabel: cls.label(me.classification),
      classTone: cls.tone(me.classification),
      rolesText: (me.roles || []).length ? me.roles.join(' · ') : '普通成员',
      phoneText: me.phoneMasked || '未绑定',
      phoneVerified: !!me.phoneVerified,
      serverHost: cfg.BASE_URL.replace(/^https?:\/\//, '')
    })
  },

  onPhoneHelp() {
    wx.showModal({
      title: '手机号',
      content: '手机号用于小程序登录，必须经过验证。绑定或换绑请在网页端：右上角账户 →「手机号」。\n\n换绑需要当前口令 + 新号码验证码，两道都不能省。',
      showCancel: false
    })
  },

  onAbout() {
    const me = this.data.me || {}
    wx.showModal({
      title: '关于',
      content: '文档中心小程序 ' + cfg.VERSION +
        '\n服务：' + this.data.serverHost +
        '\n组织：' + (me.tenantName || me.tenantSlug || '—') +
        '\n\n预览与审批都会写入审计，可在网页端查看。',
      showCancel: false
    })
  },

  onLogout() {
    if (this.data.busy) return
    wx.showModal({
      title: '退出登录',
      content: '会通知服务端吊销本次会话，并清除本机令牌。',
      confirmText: '退出',
      confirmColor: '#a93b2c',
      success: (r) => {
        if (!r.confirm) return
        this.setData({ busy: true })
        auth.logout().then(() => {
          this.setData({ busy: false })
          wx.reLaunch({ url: '/pages/login/login' })
        })
      }
    })
  }
})
