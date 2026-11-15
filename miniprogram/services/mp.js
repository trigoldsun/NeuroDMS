// 小程序专属能力：绑定 openid、申请审批提醒。
//
// 微信的订阅消息是"一次性"的：用户每点一次授权，服务端只能发一条。
// 所以这里不做"永久开启"的承诺，界面文案必须说清"每次授权一条"。
//
// 三条边界：
//   1. openid 只由服务端用 wx.login 的 code 换，客户端不上报 openid；
//   2. 未配置通道（enabled=false）时整个入口隐藏，不做"点了报错"的按钮；
//   3. 授权失败（用户点拒绝）不是错误，只是不发提醒，不要弹错误框。
const { request } = require('../utils/request')

// bind 把当前微信绑定到账号。失败不阻塞任何主流程。
function bind() {
  return new Promise(function (resolve, reject) {
    wx.login({
      success: function (r) {
        if (!r.code) {
          reject(new Error('微信登录失败'))
          return
        }
        request({ path: '/v1/mp/bind', method: 'POST', data: { code: r.code } })
          .then(resolve)
          .catch(reject)
      },
      fail: function () { reject(new Error('微信登录失败')) }
    })
  })
}

// askSubscribe 弹微信授权框。返回 'accept' | 'reject' | 'ban' | ''。
function askSubscribe(templateId) {
  return new Promise(function (resolve) {
    if (!templateId) {
      resolve('')
      return
    }
    wx.requestSubscribeMessage({
      tmplIds: [templateId],
      success: function (r) {
        resolve((r && r[templateId]) || '')
      },
      fail: function () { resolve('') }
    })
  })
}

// grant 把一次授权登记到服务端（余额 +1）。
function grant(templateId) {
  return request({
    path: '/v1/mp/subscribe',
    method: 'POST',
    data: { templateId: templateId, count: 1 }
  })
}

module.exports = { bind, askSubscribe, grant }
