// 平台运营台的数据形状。
//
// 集中一处的原因：详情页与列表页读同一批实体，类型散开后会悄悄分叉
// （列表里 plan 有值、详情里没有，最终表现是"某列偶尔空白"）。

export type Tenant = {
  slug: string
  name: string
  status: string
  edition: string
  editionExpiresAt: string | null
  createdAt: string
  trialEndsAt: string | null
  suspendedAt: string | null
  retentionUntil: string | null
  contactEmail: string
  users: number
  storageBytes: number
  files: number
}

export type Quota = {
  maxUsers: number | null
  maxStorageBytes: number | null
  maxTranscodeSeconds: number | null
  maxApiCallsDay: number | null
  onExceed: string
}

export type Flag = {
  code: string
  description: string
  defaultEnabled: boolean
  rolloutPercent: number
}

// 租户级开关的求值结果。
// 接口返回的 effective 已包含"来源"，界面必须用它解释状态：
// 只显示 enabled 的话，运营看到某个能力关了却找不到是谁关的。
export type TenantFlag = {
  code: string
  description: string
  enabled: boolean
  source: 'default' | 'rollout' | 'override' | string
  defaultEnabled: boolean
  rolloutPercent: number
}
export type TenantFlagResp = { slug: string; overrides: unknown[]; effective: TenantFlag[] }

export type UsagePoint = { day: string; metric: string; quantity: number }

export type Domain = {
  host: string
  primary: boolean
  verified: boolean
  hasCert: boolean
  certNotAfter: string | null
}

export type EditionChange = {
  fromEdition: string
  toEdition: string
  reason: string
  operator: string
  createdAt: string
}

export type EditionInfo = {
  tenantId: string
  edition: string
  expiresAt: string | null
  changes: EditionChange[] | null
}

export type Drift = {
  slug: string
  storageRecorded: number
  storageActual: number
  storageDrift: number
  usersRecorded: number
  usersActual: number
  usersDrift: number
}

export type AuditEvent = {
  id: number
  actor: string
  action: string
  target: string
  result: string
  ip: string
  createdAt: string
}

export type PlatUser = {
  id: string
  email: string
  displayName: string
  role: 'ops' | 'readonly'
  status: 'active' | 'suspended'
  createdAt: string
  lastLoginAt: string | null
}

export type Me = { email: string; role: string; canWrite: boolean; static: boolean }

export const EDITION_TEXT: Record<string, string> = {
  basic: '基础版',
  professional: '专业版',
  // 对外显示名统一为「旗舰版」；枚举值仍是 business（数据库零迁移，见 docs/47 §4.3）。
  business: '旗舰版',
}

export const STATUS_TEXT: Record<string, string> = {
  active: '正常',
  trial: '试用',
  readonly: '只读',
  suspended: '已停用',
  deleted: '已删除',
}

export function flagSourceText(f: TenantFlag): string {
  switch (f.source) {
    case 'override':
      return '本租户单独设置'
    case 'rollout':
      return f.rolloutPercent <= 0
        ? '平台已暂停（放量 0%）'
        : `平台放量 ${f.rolloutPercent}%`
    default:
      return '跟随平台默认'
  }
}

export function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function fmtTime(s: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('zh-CN', { hour12: false })
}

export function fmtDate(s: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleDateString('zh-CN')
}
