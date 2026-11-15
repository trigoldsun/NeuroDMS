// 纯逻辑单元测试（Node 直接跑，不需要开发者工具）。
//
// 为什么要有这一层：小程序的很多缺陷不是"报错"，而是"看起来成功了"——
// 202 被当成 200、密级名称写死、阶段枚举判错值。这类问题在真机上表现为
// 提示语与事实不符，靠肉眼回归几乎发现不了，只能用断言钉住。
//
// 用法：node scripts/test.js
let bad = 0
function eq(actual, expected, msg) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    console.log('  ✓ ' + msg)
  } else {
    console.error('  ✗ ' + msg + '\n     期望 ' + JSON.stringify(expected) + ' 实际 ' + JSON.stringify(actual))
    bad++
  }
}
function ok(cond, msg) {
  if (cond) console.log('  ✓ ' + msg)
  else { console.error('  ✗ ' + msg); bad++ }
}

/* ---------- 1. wx 运行时替身 ---------- */
const storage = {}
let nextResponse = null
globalThis.wx = {
  getStorageSync: (k) => (k in storage ? storage[k] : ''),
  setStorageSync: (k, v) => { storage[k] = v },
  removeStorageSync: (k) => { delete storage[k] },
  request: (opt) => { setTimeout(() => opt.success(nextResponse), 0) },
  downloadFile: (opt) => { setTimeout(() => opt.success({ statusCode: 200, tempFilePath: '/tmp/x' }), 0) },
  setNavigationBarTitle: () => {},
}

const fmt = require('../utils/format')
const cls = require('../utils/classify')
const { request } = require('../utils/request')

/* ---------- 2. 展示格式化 ---------- */
eq(fmt.size(0), '0 B', 'size 0')
eq(fmt.size(2048), '2.0 KB', 'size 2KB')
eq(fmt.size(5 * 1024 * 1024), '5.0 MB', 'size 5MB')
eq(fmt.absTime(''), '—', '空时间显示破折号而不是 Invalid Date')
ok(fmt.relTime(new Date().toISOString()) === '刚刚', 'relTime 刚发生')

/* ---------- 3. 密级：名称必须来自服务端 ---------- */
eq(cls.label(3), '3 级', '未加载名称时不编造名称，只显示等级')
cls.setLabels([
  { level: 0, name: '公开' }, { level: 3, name: '商密A' }, { level: 6, name: '核心' },
])
eq(cls.label(3), '商密A（3 级）', '租户改名后按服务端名称显示')
eq(cls.label(1), '1 级', '服务端没给的档位不借用别的名称')
eq(cls.nameOf(6), '核心', 'nameOf 取名称')
cls.loadCached()
eq(cls.label(3), '商密A（3 级）', '冷启动从缓存恢复名称')

/* ---------- 4. 审批阶段：只认库里的四个值 ---------- */
eq(cls.stageLabel('first'), '待审批人处理', 'first = 待审批人处理')
eq(cls.stageLabel('owner'), '待所有者确认', 'owner = 待所有者确认')
eq(cls.stageLabel('done'), '已完成', 'done = 已完成')
eq(cls.stageLabel('none'), '无需审批', 'none = 无需审批')
eq(cls.stageLabel('approver'), '—', '不存在的 approver 不给假文案')

/* ---------- 5. 202 不是成功 ---------- */
async function testMfa() {
  nextResponse = {
    statusCode: 202,
    data: { data: { mfaRequired: true, challenge: 'ch-1', sentTo: 'a***@b.com', expiresIn: 300 } },
  }
  let err = null
  try {
    await request({ path: '/v1/auth/login', method: 'POST', auth: false, data: {} })
  } catch (e) { err = e }
  ok(!!err, '202 不 resolve（否则会保存空令牌）')
  eq(err && err.code, 'MFA_REQUIRED', '202 必须映射为 MFA_REQUIRED')
  eq(err && err.mfa && err.mfa.challenge, 'ch-1', 'challenge 要带到上层')
  eq(err && err.mfa && err.mfa.sentTo, 'a***@b.com', 'sentTo 要带到上层')

  nextResponse = { statusCode: 200, data: { data: { accessToken: 't', refreshToken: 'r' } } }
  const d = await request({ path: '/v1/auth/login', method: 'POST', auth: false, data: {} })
  eq(d.accessToken, 't', '正常 200 仍然直接返回 data')

  nextResponse = { statusCode: 403, data: { code: 'PHONE_NOT_REGISTERED', message: '未登记手机号' } }
  let e2 = null
  try { await request({ path: '/v1/auth/login', method: 'POST', auth: false, data: {} }) } catch (e) { e2 = e }
  eq(e2 && e2.code, 'PHONE_NOT_REGISTERED', '错误码原样透传给页面')
  eq(e2 && e2.status, 403, 'HTTP 状态保留')
}

testMfa().then(() => {
  console.log(bad === 0 ? '\n全部通过' : '\n有 ' + bad + ' 个问题')
  process.exitCode = bad ? 1 : 0
})
