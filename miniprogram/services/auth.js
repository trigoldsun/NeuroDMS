// 认证：三种登录方式 + 当前用户 + 退出。
//
// 三种方式共用同一个服务端入口 /v1/auth/login（账号密码、手机号密码）
// 或 /v1/auth/sms/*（手机号验证码），差别只在 account 字段填什么。
// 小程序通道必须带 channel='mp'：服务端据此要求"手机号已验证"。
const { request, saveTokens, clearTokens, saveMe, cachedMe, hasSession, tokens } = require('../utils/request')
const cfg = require('../utils/config')

function loginPassword(account, password) {
  return request({
    path: '/v1/auth/login',
    method: 'POST',
    auth: false,
    data: { account: account, password: password, channel: cfg.CHANNEL }
  }).then(function (d) {
    saveTokens(d)
    return d
  })
}

function sendSms(account) {
  return request({
    path: '/v1/auth/sms/send',
    method: 'POST',
    auth: false,
    data: { account: account }
  })
}

// mfaVerify 完成二次验证并落令牌。
//
// challenge 由服务端在 202 里下发（签名后的短期凭据），code 由服务端发到
// 账号登记邮箱。这两者缺一不可：只有 code 不知道是谁的，只有 challenge 进不去。
function mfaVerify(challenge, code) {
  return request({
    path: '/v1/auth/mfa/verify',
    method: 'POST',
    auth: false,
    data: { challenge: challenge, code: code }
  }).then(function (d) {
    saveTokens(d)
    return d
  })
}

function loginSms(account, code) {
  return request({
    path: '/v1/auth/sms/login',
    method: 'POST',
    auth: false,
    data: { account: account, code: code }
  }).then(function (d) {
    saveTokens(d)
    return d
  })
}

function me() {
  return request({ path: '/v1/me' }).then(function (m) {
    saveMe(m)
    return m
  })
}

function logout() {
  const rt = tokens().refresh
  // 先让服务端吊销会话；失败也清本地——退出登录不能被网络问题卡住
  return request({
    path: '/v1/auth/logout', method: 'POST', data: { refreshToken: rt }
  }).catch(function () {}).then(function () {
    clearTokens()
  })
}

// bootstrap 冷启动判断：有令牌就拉一次 /v1/me 验证是否仍有效。
function bootstrap() {
  if (!hasSession()) return Promise.resolve(null)
  return me().catch(function (err) {
    clearTokens()
    throw err
  })
}

module.exports = {
  loginPassword, sendSms, loginSms, mfaVerify, me, logout, bootstrap, cachedMe, hasSession
}
