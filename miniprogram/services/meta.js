// 租户元数据：品牌、密级名称、小程序能力开关。
//
// 这三样都是"服务端说是什么就是什么"，前端只负责缓存与展示：
//   - 品牌：productName / 主色 / logo（1.7.1 起网页端三要素统一到租户）
//   - 密级名称：租户可在「密级定义」里改名
//   - 能力：订阅消息模板是否已配置（未配置就不显示入口）
//
// 缓存的意义是首屏不闪：冷启动先读上次的值，再拉一次覆盖。
const { request } = require('../utils/request')
const cfg = require('../utils/config')
const cls = require('../utils/classify')

const BRAND_KEY = 'dv_mp_branding'
const MP_KEY = 'dv_mp_mpconfig'

let branding = null
let mpCfg = null

function cachedBranding() {
  try {
    if (!branding) branding = wx.getStorageSync(BRAND_KEY) || null
  } catch (e) { /* 忽略 */ }
  return branding
}

// productName 是导航栏标题、登录页品牌、关于弹窗的唯一来源。
// 未登录时只能给产品兜底名（多租户同一域名，登录前无法确定组织）。
function productName() {
  const b = cachedBranding()
  return (b && b.productName) || cfg.PRODUCT_FALLBACK
}

// applyTitle 统一设置导航栏标题。
//
// 每个页面 onShow 都要调：wx.setNavigationBarTitle 只作用于**当前**页面，
// 新开页面会退回 app.json / 页面 json 里的静态值。放在这里而不是各页面各写一遍，
// 是为了让"漏改一页就露出厂商名"这件事不会发生。
//
// 形如「森莘创新 · 文件」：品牌在前（三要素之一），页面语境在后。
// 只写品牌会让三个页签看起来一样，只写页面名则丢掉租户标识。
function applyTitle(suffix) {
  const name = productName()
  wx.setNavigationBarTitle({ title: suffix ? name + ' · ' + suffix : name })
}

// loadBranding 拉租户品牌并缓存。slug 为空时用已缓存的。
function loadBranding(slug) {
  if (!slug) return Promise.resolve(cachedBranding())
  return request({ path: '/v1/tenant/branding?slug=' + encodeURIComponent(slug), auth: false })
    .then(function (d) {
      branding = d || null
      try { wx.setStorageSync(BRAND_KEY, branding) } catch (e) { /* 忽略 */ }
      applyTitle()
      return branding
    })
    .catch(function () { return cachedBranding() })
}

// loadClassLabels 拉密级名称。失败时保留上次缓存（不退回硬编码名称）。
function loadClassLabels() {
  return request({ path: '/v1/classifications' })
    .then(function (d) {
      cls.setLabels(d.items || [])
      return d.items || []
    })
    .catch(function () { return [] })
}

function loadMpConfig() {
  return request({ path: '/v1/mp/config', auth: true })
    .then(function (d) {
      mpCfg = d || null
      try { wx.setStorageSync(MP_KEY, mpCfg) } catch (e) { /* 忽略 */ }
      return mpCfg
    })
    .catch(function () {
      try { mpCfg = wx.getStorageSync(MP_KEY) || null } catch (e) { mpCfg = null }
      return mpCfg
    })
}

function subscribeTemplateId() {
  if (!mpCfg) {
    try { mpCfg = wx.getStorageSync(MP_KEY) || null } catch (e) { mpCfg = null }
  }
  return (mpCfg && mpCfg.todoSubscribeTemplateId) || ''
}

// sync 在登录成功后调用一次：品牌 + 密级 + 小程序配置。
// 任何一项失败都不阻塞登录——它们只影响展示，不影响权限。
function sync(slug) {
  return Promise.all([loadBranding(slug), loadClassLabels(), loadMpConfig()])
}

module.exports = {
  productName, applyTitle, loadBranding, loadClassLabels, loadMpConfig,
  subscribeTemplateId, sync, cachedBranding
}
