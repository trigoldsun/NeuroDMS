import { Icon } from './ui'

// 审计明细的渲染器。
//
// 为什么单独做一个组件：同一份 detail 会出现在两个地方——管理台「审计日志」
// 与「操作日志」页。以前操作日志直接 JSON.stringify，管理员看到的是
// {"before":{"maxUploadMB":100},"after":{"maxUploadMB":200}}，
// 这不是给审计员看的东西：它要回答的是"谁把哪个参数从多少改到多少"。
//
// 两条渲染规则：
//   1. 有 before/after 时按"字段 / 改前 / 改后"排成表格，变化行高亮；
//   2. 其余键（含没有 before/after 的动作）按"字段：值"逐行列出。
// 所有键都翻译成中文标签，查不到的键原样显示——宁可露出原键名，
// 也不能因为漏配翻译就让一条记录变成空白。

type Dict = Record<string, unknown>

const FIELD_LABELS: Record<string, string> = {
  // 品牌
  productName: '系统名称',
  primaryColor: '主色',
  accentColor: '辅色',
  footerText: '页脚文案',
  privacyUrl: '隐私政策链接',
  logoChanged: '更换了 Logo',
  // 策略
  shareDefaultExpireDays: '外链默认有效期',
  maxUploadMB: '单文件上传上限',
  auditRetentionDays: '日志保留期',
  versionKeep: '历史版本保留数',
  uploadTimeoutSeconds: '上传超时',
  allowedExts: '允许的扩展名',
  // 邮件
  mode: '发信模式',
  fromAddr: '发件地址',
  fromName: '发件人显示名',
  replyTo: '回复地址',
  smtpHost: 'SMTP 主机',
  smtpPort: 'SMTP 端口',
  smtpTls: 'SMTP 加密',
  smtpUserChanged: 'SMTP 账号更换',
  smtpPasswordChanged: 'SMTP 口令更换',
  smtpInsecure: '跳过证书校验',
  smtpAllowPlaintext: '允许明文连接',
  graphTenantId: '目录（租户）ID',
  graphClientId: '应用（客户端）ID',
  graphSecretChanged: '客户端密钥更换',
  graphSender: 'Graph 发件邮箱',
  graphLoginBase: '登录端点',
  graphBase: 'Graph 端点',
  // 目录认证
  enabled: '启用',
  url: '目录地址',
  startTls: 'StartTLS',
  insecureSkipVerify: '跳过证书校验',
  tlsName: 'TLS 主机名',
  bindDn: '绑定账号',
  bindPasswordChanged: '域口令更换',
  baseDn: '搜索基准 DN',
  userFilter: '用户过滤',
  syncFilter: '同步过滤',
  groupFilter: '组过滤',
  excludeAccounts: '排除账号',
  adMode: 'AD 模式',
  allowPlaintext: '允许明文',
  syncIntervalMinutes: '同步间隔',
  caChanged: '更换了 CA 证书',
  host: '主机',
  port: '端口',
  plaintext: '明文连接',
  // 成员与账号
  classification: '密级',
  ceiling: '权限档位上限',
  deptId: '部门',
  mfaRequired: '强制二次验证',
  status: '状态',
  expiresAt: '账号有效期',
  sessionsRevoked: '已吊销会话',
  // 权限
  preset: '权限档位',
  aceId: '权限条目',
  expiresInHours: '有效小时数',
  clearExpiry: '清除到期时间',
  reason: '原因',
  // 密级定义
  level: '密级等级',
  name: '名称',
  description: '说明',
  ownerApproval: '外发需所有者确认',
  minLevel: '最低密级',
  label: '标签',
  // 分享
  shareId: '分享',
  maxUses: '最大使用次数',
  toLevel: '目标密级',
  fromLevel: '原密级',
  approve: '审批结论',
  newLevel: '新密级',
  note: '审批意见',
  requestId: '申请单',
  objectClass: '对象密级',
  notifyEmails: '通知邮箱',
  allowDownload: '允许下载原件',
  allowSave: '允许保存副本',
  allowPrint: '允许打印',
}

const UNITS: Record<string, string> = {
  maxUploadMB: ' MB',
  shareDefaultExpireDays: ' 天',
  auditRetentionDays: ' 天',
  versionKeep: ' 个',
  uploadTimeoutSeconds: ' 秒',
  syncIntervalMinutes: ' 分钟',
  minLevel: ' 级',
}

const STATUS_TEXT: Record<string, string> = {
  active: '正常',
  disabled: '已停用',
  suspended: '已挂起',
  inherit: '跟随平台默认',
  smtp: 'SMTP 服务器',
  graph: 'Exchange Online（Graph）',
  none: '不使用',
  starttls: 'STARTTLS',
  tls: '隐式 TLS',
  private: '仅本人',
  read: '只读',
  write: '读写',
  manage: '可管理',
  owner: '所有者',
}

/** 把任意值转成一行可读文本。 */
export function valueText(key: string, v: unknown): string {
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v === 'boolean') return v ? '是' : '否'
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.map((x) => String(x)).join('、')
  if (typeof v === 'object') return JSON.stringify(v)
  if (typeof v === 'number') return String(v) + (UNITS[key] ?? '')
  const s = String(v)
  if (key === 'status' || key === 'mode' || key === 'preset' || key === 'smtpTls') {
    return STATUS_TEXT[s] ? `${STATUS_TEXT[s]}` : s
  }
  if (key === 'expiresAt') {
    const d = new Date(s)
    if (!Number.isNaN(d.getTime())) return d.toLocaleString('zh-CN')
  }
  const unit = UNITS[key]
  // 数字形式的字符串也补单位：JSON 里偶尔会以字符串传来
  if (unit && /^-?\d+(\.\d+)?$/.test(s)) return s + unit
  return s
}

export function fieldLabel(key: string): string {
  return FIELD_LABELS[key] ?? key
}

const META_KEYS = new Set(['before', 'after', 'changed'])

/**
 * changeSummary 生成一句话摘要，用于表格行内直接看到"从多少改到多少"。
 *
 * 只取前两项：行内空间有限，全量明细交给展开后的表格。
 * 返回空串表示这条记录没有参数变更（例如登录、预览这类动作）。
 */
export function changeSummary(detail?: Dict): string {
  if (!detail) return ''
  const before = detail.before as Dict | undefined
  const after = detail.after as Dict | undefined
  if (!before && !after) return ''
  const changed = Array.isArray(detail.changed) ? (detail.changed as string[]) : []
  if (changed.length === 0) return '无字段变化'
  const parts = changed.slice(0, 2).map(
    (k) => `${fieldLabel(k)} ${valueText(k, before?.[k])} → ${valueText(k, after?.[k])}`,
  )
  return parts.join('；') + (changed.length > 2 ? ` 等 ${changed.length} 项` : '')
}

/**
 * AuditDetail 渲染一条审计事件的 detail。
 *
 * `compact` 用于表格里的展开行（字号更小、间距更紧）。
 */
export default function AuditDetail({ detail, compact }: { detail?: Dict; compact?: boolean }) {
  if (!detail) return null
  const changed = Array.isArray(detail.changed) ? (detail.changed as string[]) : null
  const before = (detail.before ?? null) as Dict | null
  const after = (detail.after ?? null) as Dict | null
  const extras = Object.keys(detail).filter((k) => !META_KEYS.has(k))

  const hasDiff = !!(before || after)

  return (
    <div className={`audit-detail${compact ? ' compact' : ''}`}>
      {hasDiff && (
        <table className="diff">
          <thead>
            <tr>
              <th style={{ width: 180 }}>字段</th>
              <th style={{ width: '40%' }}>改前</th>
              <th>改后</th>
            </tr>
          </thead>
          <tbody>
            {(changed ?? Object.keys(after ?? before ?? {})).length === 0 ? (
              <tr>
                <td colSpan={3} className="dim">本次提交没有任何字段变化（原样保存）。</td>
              </tr>
            ) : (
              (changed ?? Object.keys(after ?? before ?? {})).map((k) => (
                <tr key={k}>
                  <td>{fieldLabel(k)}</td>
                  <td className="old">{valueText(k, before?.[k])}</td>
                  <td className="new">
                    <span className="arrow"><Icon name="arrowRight" size={12} /></span>
                    {valueText(k, after?.[k])}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}

      {extras.length > 0 && (
        <div className="extras">
          {extras.map((k) => (
            <div className="kv" key={k}>
              <span>{fieldLabel(k)}</span>
              <b>{valueText(k, detail[k])}</b>
            </div>
          ))}
        </div>
      )}

      {!hasDiff && extras.length === 0 && <div className="dim">这条记录没有附加参数。</div>}
    </div>
  )
}
