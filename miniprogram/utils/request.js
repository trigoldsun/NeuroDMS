// 网络层：令牌、刷新、统一错误。
//
// 为什么令牌放在本地存储而不是 globalData：小程序随时可能被系统回收内存，
// globalData 会丢，用户表现为"切出去一会儿回来就要重新登录"。
const cfg = require('./config')

const ACCESS_KEY = 'dv_mp_access'
const REFRESH_KEY = 'dv_mp_refresh'
const ME_KEY = 'dv_mp_me'

// ApiError 保留 code：页面按 code 决定提示方式（如 AMBIGUOUS_ACCOUNT 要引导改写账号）。
class ApiError extends Error {
  constructor(code, message, status, hint, retryAfter) {
    super(message || '请求失败')
    this.code = code || 'ERROR'
    this.status = status || 0
    this.hint = hint || ''
    this.retryAfter = retryAfter || 0
  }
}

function tokens() {
  return {
    access: wx.getStorageSync(ACCESS_KEY) || '',
    refresh: wx.getStorageSync(REFRESH_KEY) || ''
  }
}

function saveTokens(t) {
  if (t && t.accessToken) wx.setStorageSync(ACCESS_KEY, t.accessToken)
  if (t && t.refreshToken) wx.setStorageSync(REFRESH_KEY, t.refreshToken)
}

function clearTokens() {
  wx.removeStorageSync(ACCESS_KEY)
  wx.removeStorageSync(REFRESH_KEY)
  wx.removeStorageSync(ME_KEY)
}

function hasSession() {
  return !!tokens().access
}

function saveMe(me) {
  wx.setStorageSync(ME_KEY, me)
}

function cachedMe() {
  return wx.getStorageSync(ME_KEY) || null
}

// 刷新令牌。多个并发请求同时 401 时只发一次刷新，否则后到的请求会拿着
// 已经被轮换掉的旧令牌，把一个正常会话判成重放（服务端会直接吊销）。
let refreshing = null
function refreshTokens() {
  if (refreshing) return refreshing
  const rt = tokens().refresh
  if (!rt) return Promise.reject(new ApiError('SESSION_INVALID', '登录已过期', 401))
  refreshing = new Promise(function (resolve, reject) {
    wx.request({
      url: cfg.BASE_URL + '/v1/auth/refresh',
      method: 'POST',
      header: { 'content-type': 'application/json', accept: 'application/json' },
      data: { refreshToken: rt },
      success: function (res) {
        const body = res.data || {}
        if (res.statusCode === 200 && body.data) {
          saveTokens(body.data)
          resolve(body.data)
          return
        }
        clearTokens()
        reject(new ApiError(body.code || 'SESSION_INVALID', body.message || '登录已过期', res.statusCode))
      },
      fail: function () {
        reject(new ApiError('NETWORK', '网络不可用，请检查网络后重试', 0))
      },
      complete: function () { refreshing = null }
    })
  })
  return refreshing
}

// request 统一处理：附加令牌、解析 data、401 自动刷新一次、错误转 ApiError。
function request(opts) {
  const opt = opts || {}
  const retried = !!opt._retried
  const header = Object.assign(
    { 'content-type': 'application/json', accept: 'application/json' },
    opt.header || {},
  )
  if (opt.auth !== false) {
    const t = tokens().access
    if (t) header.Authorization = 'Bearer ' + t
  }
  return new Promise(function (resolve, reject) {
    wx.request({
      url: cfg.BASE_URL + opt.path,
      method: opt.method || 'GET',
      data: opt.data,
      header: header,
      success: function (res) {
        const body = res.data || {}
        // 202 = "口令已通过，还差一步"（服务端二次验证挑战）。
        // 它落在 2xx 里，但**没有任何令牌**：当成成功就会保存空令牌，
        // 紧接着 /v1/me 401 → 界面提示变成"登录已过期"，
        // 用户看到的原因与事实完全无关。必须先转成结构化错误。
        if (res.statusCode === 202 && body.data && body.data.mfaRequired) {
          const e = new ApiError('MFA_REQUIRED', '需要二次验证', 202)
          e.mfa = body.data
          reject(e)
          return
        }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body.data !== undefined ? body.data : body)
          return
        }
        // 令牌过期：刷新一次再重试；刷新失败就交给页面跳登录
        if (res.statusCode === 401 && !retried && opt.auth !== false && tokens().refresh) {
          refreshTokens()
            .then(function () { return request(Object.assign({}, opt, { _retried: true })) })
            .then(resolve)
            .catch(reject)
          return
        }
        if (res.statusCode === 401) clearTokens()
        const ra = Number(res.header && (res.header['Retry-After'] || res.header['retry-after']))
        reject(new ApiError(body.code, body.message, res.statusCode, body.hint, isNaN(ra) ? 0 : ra))
      },
      fail: function () {
        reject(new ApiError('NETWORK', '网络不可用，请检查网络后重试', 0))
      }
    })
  })
}

// download 带令牌下载到临时文件。
//
// <image> 与 wx.downloadFile 的差别就在 header：前者不能带 Authorization，
// 所以预览一律先下载，再用本地临时路径渲染。
function download(path, retried) {
  const t = tokens().access
  return new Promise(function (resolve, reject) {
    wx.downloadFile({
      url: cfg.BASE_URL + path,
      header: t ? { Authorization: 'Bearer ' + t } : {},
      success: function (res) {
        if (res.statusCode === 200) {
          resolve(res.tempFilePath)
          return
        }
        if (res.statusCode === 401 && !retried && tokens().refresh) {
          refreshTokens()
            .then(function () { return download(path, true) })
            .then(resolve)
            .catch(reject)
          return
        }
        if (res.statusCode === 401) clearTokens()
        reject(new ApiError('DOWNLOAD_FAILED', '文件打开失败（' + res.statusCode + '）', res.statusCode))
      },
      fail: function () {
        reject(new ApiError('NETWORK', '网络不可用，无法读取文件', 0))
      }
    })
  })
}

module.exports = {
  ApiError, request, download, tokens, saveTokens, clearTokens, hasSession,
  saveMe, cachedMe, refreshTokens
}
