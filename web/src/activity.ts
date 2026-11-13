// 日志页的展示层映射：动作代码 → 中文、分组 → 选项。
//
// 放在单独文件里而不是塞进页面：管理台与「我的活动」两处都要用，
// 各写一份必然出现"同一个动作在两个页面叫不同名字"。

export type GroupOption = { value: string; label: string }

// ACTION_LABELS 只覆盖常见动作。刻意不做"未知动作猜翻译"：
// 猜错比露出原始代码更糟——运维排查时要的是可 grep 的动作名。
const ACTION_LABELS: Record<string, string> = {
  'auth.login': '登录',
  'auth.logout': '退出登录',
  'auth.mfa': '二次验证',

  'node.upload': '上传',
  'node.download': '下载',
  'node.preview': '预览',
  'node.rename': '重命名',
  'node.delete': '删除',
  'node.move': '移动',
  'folder.create': '新建目录',
  'space.create': '新建空间',
  'batch.move': '批量移动',
  'batch.download': '批量下载',
  'version.set_effective': '设为当前版本',

  'share.create': '创建分享',
  'share.revoke': '撤销分享',
  'share.redeem': '打开分享',
  'share.external': '外发分享',
  'share.approve': '外发审批',
  'share.internal': '内部分享',

  'office.save': '编辑保存',
  'office.callback': '编辑回调',
  'preview.watermark': '水印预览',

  'upload.session.create': '创建上传会话',
  'upload.session.complete': '完成上传',
  'upload.session.abort': '取消上传',

  'profile.email.request': '申请换绑邮箱',
  'profile.email.confirm': '确认换绑邮箱',
  'account.self_delete': '注销账号',

  'admin.member.create': '新建成员',
  'admin.member.update': '修改成员',
  'admin.member.status': '启用/停用成员',
  'admin.member.password': '重置口令',
  'admin.member.delete': '删除成员',
  'admin.role.grant': '授予角色',
  'admin.role.revoke': '撤销角色',
  'admin.user.expiry': '设置账号有效期',
  'admin.user.delete': '删除账号',
  'admin.denied': '拒绝管理访问',

  'acl.grant': '授予权限',
  'acl.revoke': '撤销权限',
  'acl.update': '修改权限',
  'acl.inheritance': '继承设置',

  'classification.set': '设置密级',
  'classification.label.set': '设置标签',
  'classification.label_policy.set': '标签策略',
  'classification.request_down': '申请降密',
  'classification.decide': '密级审批',

  'tenant.policy.update': '系统策略',
  'tenant.branding.update': '品牌设置',
  'platform.access': '平台访问',
}

export function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action
}

// 用户日志的分组：只列用户自己会产生动作的类别。
export const USER_GROUPS: GroupOption[] = [
  { value: '', label: '全部动作' },
  { value: 'auth', label: '登录认证' },
  { value: 'file', label: '文件操作' },
  { value: 'share', label: '分享与外发' },
  { value: 'office', label: '预览与编辑' },
  { value: 'account', label: '账号设置' },
]

// 管理日志的分组：按"治理领域"而不是按代码前缀，
// 管理员关心的是"谁改了权限"，不是"acl. 开头的有哪些"。
export const ADMIN_GROUPS: GroupOption[] = [
  { value: '', label: '全部动作' },
  { value: 'member', label: '成员与角色' },
  { value: 'acl', label: '权限与密级' },
  { value: 'share', label: '外发审批' },
  { value: 'system', label: '系统配置' },
]

export const RESULT_OPTIONS = [
  { value: '', label: '全部结果' },
  { value: 'ok', label: '成功' },
  { value: 'denied', label: '被拒绝' },
  { value: 'error', label: '异常' },
]

export function resultBadgeClass(r: string): string {
  return r === 'ok' ? 'ok' : r === 'denied' ? 'danger' : 'warn'
}

export function resultText(r: string): string {
  return r === 'ok' ? '成功' : r === 'denied' ? '拒绝' : '异常'
}
