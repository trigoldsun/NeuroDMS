// 登录：账号密码 / 手机号密码 / 手机号验证码 + 二次验证。
//
// 三个入口共用同一套服务端接口，差别只在 account 填什么：
//   account  => username 或 username@tenant
//   phone    => +86 手机号（服务端按号码定位账号）
// 小程序通道带 channel=mp，服务端会额外要求"手机号已验证"——
// 这道闸门在服务端，前端只是提前把话说清楚。
//
// 二次验证（mfa_required 账号）：服务端先返回 202 + challenge，验证码发到
// 账号登记邮箱；拿到 code 后再调 /v1/auth/mfa/verify 换令牌。
// 202 不能当成功处理——那样会保存空令牌，用户看到的是"登录已过期"。
const auth = require('../../services/auth')
const meta = require('../../services/meta')
const mp = require('../../services/mp')
const cfg = require('../../utils/config')

const MODES = [
  { key: 'account', label: '账号密码' },
  { key: 'phone', label: '手机号密码' },
  { key: 'sms', label: '手机号验证码' }
]

Page({
  data: {
    modes: MODES,
    mode: 'account',
    brandName: cfg.PRODUCT_FALLBACK,
    brandInitial: cfg.PRODUCT_FALLBACK.slice(0, 1),
    account: '',
    phone: '',
    password: '',
    code: '',
    sentTo: '',
    countdown: 0,
    err: '',
    errHint: '',
    busy: false,
    // mfa 非空表示进入二次验证步骤：challenge 交回服务端，sentTo 是掩码后的邮箱
    mfa: null,
    mfaCode: '',
    mfaBusy: false
  },

  onLoad() {
    meta.applyTitle()
    const name = meta.productName()
    this.setData({ brandName: name, brandInitial: name.slice(0, 1) })
    // 已登录直接进主界面；令牌失效则留在本页（不弹错误，用户本来就是要登录）
    if (auth.hasSession()) {
      auth.bootstrap().then((me) => {
        return meta.sync(me && me.tenantSlug).then(() => {
          wx.switchTab({ url: '/pages/files/files' })
        })
      }).catch(() => {})
    }
  },

  onUnload() {
    this.stopTimer()
  },

  onMode(e) {
    const mode = e.currentTarget.dataset.mode
    if (mode === this.data.mode) return
    this.setData({ mode: mode, err: '', errHint: '' })
  },

  onAccount(e) { this.setData({ account: e.detail.value, err: '' }) },
  onPhone(e) { this.setData({ phone: e.detail.value, err: '' }) },
  onPassword(e) { this.setData({ password: e.detail.value, err: '' }) },
  onCode(e) { this.setData({ code: e.detail.value, err: '' }) },
  onMfaCode(e) { this.setData({ mfaCode: e.detail.value, err: '' }) },

  // 只做"看起来像手机号"的校验，真正的判定在服务端：
  // 前端放宽一点，才能把"号码格式不对"和"号码未登记"两类问题分开提示。
  looksPhone(v) {
    return /^1[3-9]\d{9}$/.test(String(v || '').replace(/[\s-]/g, ''))
  },

  onSendCode() {
    const phone = this.data.phone
    if (!this.looksPhone(phone)) {
      this.setData({ err: '请填写 11 位手机号' })
      return
    }
    if (this.data.countdown > 0 || this.data.busy) return
    this.setData({ busy: true, err: '', errHint: '' })
    auth.sendSms(phone).then((r) => {
      this.setData({ busy: false, sentTo: r.sentTo || phone, code: '' })
      this.startTimer(r.retryAfter || 60)
      wx.showToast({ title: '验证码已发送', icon: 'none' })
    }).catch((err) => {
      this.setData({ busy: false })
      this.handleError(err)
    })
  },

  startTimer(seconds) {
    this.stopTimer()
    this.setData({ countdown: seconds })
    this.timer = setInterval(() => {
      const n = this.data.countdown - 1
      if (n <= 0) {
        this.stopTimer()
        this.setData({ countdown: 0 })
        return
      }
      this.setData({ countdown: n })
    }, 1000)
  },

  stopTimer() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
  },

  onSubmit() {
    if (this.data.busy) return
    const mode = this.data.mode
    let p
    if (mode === 'account') {
      if (!this.data.account.trim()) { this.setData({ err: '请填写账号' }); return }
      if (!this.data.password) { this.setData({ err: '请填写口令' }); return }
      p = auth.loginPassword(this.data.account.trim(), this.data.password)
    } else if (mode === 'phone') {
      if (!this.looksPhone(this.data.phone)) { this.setData({ err: '请填写 11 位手机号' }); return }
      if (!this.data.password) { this.setData({ err: '请填写口令' }); return }
      p = auth.loginPassword(this.data.phone, this.data.password)
    } else {
      if (!this.looksPhone(this.data.phone)) { this.setData({ err: '请填写 11 位手机号' }); return }
      if (!this.data.code) { this.setData({ err: '请填写验证码' }); return }
      p = auth.loginSms(this.data.phone, this.data.code)
    }

    this.setData({ busy: true, err: '', errHint: '' })
    p.then(() => this.enter())
      .catch((err) => {
        this.setData({ busy: false })
        this.handleError(err)
      })
  },

  // 二次验证：用 challenge + 邮箱验证码换令牌
  onSubmitMfa() {
    if (this.data.mfaBusy) return
    if (!this.data.mfaCode) { this.setData({ err: '请填写验证码' }); return }
    this.setData({ mfaBusy: true, err: '' })
    auth.mfaVerify(this.data.mfa.challenge, this.data.mfaCode)
      .then(() => this.enter())
      .catch((err) => {
        this.setData({ mfaBusy: false })
        this.handleError(err)
      })
  },

  onCancelMfa() {
    this.setData({ mfa: null, mfaCode: '', err: '', errHint: '' })
  },

  // enter 登录成功后的收尾：拉当前用户 → 同步租户元数据 → 进首页。
  // 元数据失败不阻塞登录（只影响展示），所以单独兜住。
  enter() {
    return auth.me().then((me) => {
      getApp().globalData.me = me
      return meta.sync(me && me.tenantSlug).then(() => me, () => me)
    }).then((me) => {
      // 绑定 openid 只在通道已配置时有意义；失败不影响登录
      if (meta.subscribeTemplateId()) mp.bind().catch(() => {})
      return me
    }).then(() => {
      this.setData({ busy: false, mfaBusy: false })
      wx.switchTab({ url: '/pages/files/files' })
    })
  },

  handleError(err) {
    const code = err && err.code
    // 口令正确但账号开了二次验证：服务端返回 202 + challenge，
    // 验证码已发到登记邮箱。这里切到验证码输入，而不是报"登录失败"。
    if (code === 'MFA_REQUIRED' && err.mfa && err.mfa.challenge) {
      this.setData({ mfa: err.mfa, mfaCode: '', busy: false, err: '', errHint: '' })
      return
    }
    if (code === 'CODE_INVALID' || code === 'CHALLENGE_STALE') {
      this.setData({
        mfaBusy: false,
        err: err.message || '验证码不正确或已失效',
        errHint: code === 'CHALLENGE_STALE' ? '验证会话已失效，请返回重新登录' : ''
      })
      return
    }
    if (code === 'AMBIGUOUS_ACCOUNT') {
      this.setData({
        err: '该账号属于多个组织',
        errHint: '请用「账号@组织标识」的格式重新输入，例如 zhangsan@demo'
      })
      return
    }
    if (code === 'PHONE_NOT_REGISTERED') {
      wx.showModal({
        title: '需要先登记手机号',
        content: '小程序只允许已登记并验证手机号的账号登录。请先在网页端登录 → 右上角账户 →「手机号」，完成绑定后再回来。',
        showCancel: false,
        confirmText: '知道了'
      })
      return
    }
    if (code === 'SMS_RATE_LIMITED') {
      this.startTimer(err.retryAfter || 60)
      this.setData({ err: err.message || '发送过于频繁，请稍后再试' })
      return
    }
    if (code === 'SMS_NOT_CONFIGURED') {
      wx.showModal({
        title: '短信登录未开通',
        content: '该组织尚未配置短信认证服务。请改用账号密码登录，或联系管理员。',
        showCancel: false
      })
      return
    }
    if (code === 'SMS_UNAVAILABLE') {
      this.setData({ err: '短信服务暂不可用，请稍后重试或改用账号密码' })
      return
    }
    if (code === 'NETWORK') {
      this.setData({ err: '网络不可用，请检查网络后重试' })
      return
    }
    this.setData({ err: (err && err.message) || '登录失败，请重试' })
  }
})
