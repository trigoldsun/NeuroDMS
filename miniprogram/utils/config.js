// 运行时配置。
//
// BASE_URL 必须与微信公众平台「开发管理 → 服务器域名 → request 合法域名」
// 里登记的域名一致（downloadFile 也要登记），否则真机会直接拒绝请求——
// 开发者工具可以靠 project.private.config.json 关掉校验，真机没有这个开关。
// 本地联调：改成 http://127.0.0.1:18090，并在私有配置里关掉「校验合法域名」。
module.exports = {
  BASE_URL: 'https://ndms.neurongene.cn',
  // 服务端据此判断"是不是小程序通道"：只有已验证手机号的账号才能进。
  CHANNEL: 'mp',
  VERSION: '1.9.0',
  // 登录前的兜底名称：同一域名下是多租户，未登录时无法知道属于哪个组织，
  // 所以这里只能给一个与租户无关的产品名。登录拿到 tenantSlug 之后，
  // 一律用 /v1/tenant/branding 的 productName 覆盖（见 services/meta.js）。
  PRODUCT_FALLBACK: '文档中心'
}
