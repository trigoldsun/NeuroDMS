// 站点图标（浏览器标签页 / 收藏夹 / 移动端主屏）。
//
// **适用范围（2026-11-15 定稿）**：
//   登录后（Shell 内）→ 跟随当前租户图标；
//   未登录 / 登录态失效 → 一律产品图标（`/favicon.svg`）。
// 登录页 `/login` 与外部分享页 `/s/{token}` **固定产品图标**：它们面向"还没证明身份"的人，
// 标签页上挂客户标识会让人误以为已经进了系统（也容易被拿来做仿冒）。
// 分享页页眉仍显示租户图标——那是内容品牌，和"浏览器窗口的身份标识"不是一回事。
//
// 为什么必须在浏览器里换：index.html 是**一份构建产物服务所有租户**，
// 服务端渲染时并不知道这次访问属于谁（同一域名、靠 slug 区分）。
// 所以先显示内置图标，等公开品牌接口回来后替换 <link rel="icon">。
//
// 缓存边界：logoUrl 自带 ?v=<内容指纹>，换图标时 URL 本身会变，不需要额外破缓存。
// 但 Chrome 的 favicon 缓存在独立数据库里，清站点缓存也未必清掉——
// 同一 URL 换图可能几小时不生效，这是浏览器行为，只能靠换 URL 规避。

import { getAccess } from './api'

export type BrandIcon = { logoUrl?: string; logoMime?: string } | null | undefined

/** 内置图标：没有自定义品牌时的兜底（web/public/favicon.svg）。 */
const DEFAULT_ICON = '/favicon.svg'
const DEFAULT_MIME = 'image/svg+xml'

/** 已生效的图标地址。重复调用（Shell 重渲染、事件广播）时不必重建 link。 */
let applied = ''

/**
 * 把图标换成 href。
 *
 * 采用"删掉旧的、插入新的"而不是改属性：Chrome 对同一 link 元素的 href 变更
 * 响应很迟钝（经常要等下一次导航），换元素才会立刻重新拉图。
 * 中间不会有白图标——浏览器在拿到新图之前继续显示旧的。
 */
function setIcon(href: string, type: string) {
  if (applied === href) return
  applied = href
  document.head
    .querySelectorAll('link[rel="icon"], link[rel="shortcut icon"]')
    .forEach((n) => n.remove())
  const el = document.createElement('link')
  el.rel = 'icon'
  el.type = type
  el.href = href
  document.head.appendChild(el)
}

function dropAppleTouch() {
  document.head.querySelectorAll('link[rel="apple-touch-icon"]').forEach((n) => n.remove())
}

/**
 * 让站点图标跟随租户品牌。
 *
 * 传入空品牌（未登录页、租户还没上传图标）时回到内置图标；
 * 传入自定义图标时同时更新 apple-touch-icon（仅在 PNG 时——
 * iOS 主屏图标不支持 SVG/WebP，塞进去只会得到一个空白方块）。
 */
export function applyFavicon(brand: BrandIcon) {
  if (typeof document === 'undefined') return
  // 没有登录态就不可能"当前租户"：即便调用方传了品牌，也退回产品图标。
  // 这道闸是给未来的调用点兜底的——登录页/分享页/登出/令牌失效最终都归到这里。
  if (!getAccess()) {
    applyProductFavicon()
    return
  }
  const url = String(brand?.logoUrl ?? '').trim()
  const mime = String(brand?.logoMime ?? '').trim()

  if (!url) {
    setIcon(DEFAULT_ICON, DEFAULT_MIME)
    // 不清掉会留下上一个租户的图标：同一台机器切换组织时，
    // 主屏上还挂着"A 公司的标"，是最容易引起误解的一种残留。
    dropAppleTouch()
    return
  }

  setIcon(url, mime || 'image/png')
  if (mime === 'image/png') {
    let el = document.head.querySelector<HTMLLinkElement>('link[rel="apple-touch-icon"]')
    if (!el) {
      el = document.createElement('link')
      el.rel = 'apple-touch-icon'
      document.head.appendChild(el)
    }
    if (el.getAttribute('href') !== url) el.href = url
  } else {
    dropAppleTouch()
  }
}

/**
 * 回到产品图标（内置 `/favicon.svg`）。
 *
 * 三个时刻必须调用：登录页挂载、登出/令牌失效、离开站内页面。
 * 少一处就会留上一个租户的图标——同机切换组织时最容易被误认成"进错系统"。
 */
export function applyProductFavicon() {
  if (typeof document === 'undefined') return
  setIcon(DEFAULT_ICON, DEFAULT_MIME)
  dropAppleTouch()
}

// 令牌被清掉 = 登录态失效（自动刷新失败、主动退出、后端 401）。
// api.ts 在 clearTokens 里广播这个事件，这里统一回退，避免每个页面各写一遍。
if (typeof window !== 'undefined') {
  window.addEventListener('dv-auth-lost', () => applyProductFavicon())
}
