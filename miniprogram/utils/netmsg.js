// 把 wx.request 的失败原因翻译成"用户能照着做"的提示。
//
// 为什么需要它：微信只给一句 errMsg（如 `request:fail url not in domain list`），
// 而不同原因的处理方式完全不同——域名没登记要找管理员改后台，网络差要换网络，
// 证书异常要联系运维。以前统一显示"网络不可用，请检查网络后重试"，
// 用户唯一能做的就是重试，而重试永远不会好。
//
// 纯函数（不碰 wx API），可在 Node 里直接测。
const MAX_DETAIL = 40

function hostOf(baseUrl) {
  return String(baseUrl || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '')
}

function clip(s) {
  const t = String(s || '').trim()
  return t.length > MAX_DETAIL ? t.slice(0, MAX_DETAIL) + '…' : t
}

// describe 返回 { text, hint }；非网络类错误返回 null，调用方沿用原逻辑。
function describe(err, baseUrl) {
  if (!err || err.code !== 'NETWORK') return null
  const d = String(err.detail || '')
  const host = hostOf(baseUrl)

  if (/not in domain list|合法域名|domain list/i.test(d)) {
    return {
      text: '服务地址未加入小程序合法域名',
      hint: '请管理员在微信公众平台「开发管理 → 服务器域名」把 ' + (host || '本服务域名') +
        ' 加入 request 与 downloadFile。开发者工具可以关掉域名校验，真机不行。'
    }
  }
  if (/timeout|超时/i.test(d)) {
    return {
      text: '请求超时',
      hint: '检查手机网络（4G/Wi-Fi、是否开了代理或 VPN）后重试。'
    }
  }
  if (/ssl|certificate|证书/i.test(d)) {
    return {
      text: '服务器证书校验失败',
      hint: '证书可能已过期，或手机系统时间不正确。请先校准时间，仍不行联系管理员。'
    }
  }
  if (/ERR_CONNECTION|ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED|ERR_ADDRESS_UNREACHABLE|ERR_NETWORK_CHANGED/i.test(d)) {
    return {
      text: '无法连接到服务器',
      hint: '检查是否处于飞行模式、弱网或企业网络限制；换一个网络再试。'
    }
  }
  return {
    text: '网络不可用',
    hint: d ? '原因：' + clip(d) : '请检查网络后重试；若持续失败，把这条提示发给管理员。'
  }
}

module.exports = { describe, hostOf }
