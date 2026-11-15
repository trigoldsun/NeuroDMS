// 平台控制台的 API 封装。
//
// 令牌存在 sessionStorage（不是 localStorage）：
//   平台权限影响全体租户，关掉标签页就该失效；
//   localStorage 会让它在共用电脑上一直留着。

export const TOKEN_KEY = 'plat.token'

export class ApiError extends Error {
  code: string
  status: number
  // 部分错误带结构化明细（如降档被拒时的受影响对象清单）
  data?: unknown
  constructor(status: number, code: string, message: string, data?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.data = data
  }
}

export function token(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? ''
}

// 401 时的回调：清令牌只是"凭证没了"，界面还得真的回到登录态。
// 只清不通知，页面会停在"看起来已登录"的空壳上，之后每个操作都报
// "会话已过期"，用户不知道该怎么办（此前就是这个问题）。
let unauthorizedHandler: (() => void) | null = null

export function onUnauthorized(fn: (() => void) | null) {
  unauthorizedHandler = fn
}

export async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch('/v1/platform' + path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
      ...(init?.headers ?? {}),
    },
  })
  if (resp.status === 401) {
    sessionStorage.removeItem(TOKEN_KEY)
    unauthorizedHandler?.()
    throw new ApiError(401, 'UNAUTHORIZED', '会话已过期，请重新登录')
  }
  const body = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    throw new ApiError(resp.status, body.code ?? 'ERROR', body.message ?? '请求失败', body.data)
  }
  return (body.data ?? body) as T
}

// ---------------- 能力授权（docs/47） ----------------

export type EntitlementDef = {
  code: string
  name: string
  description: string
  basicDefault: boolean
  proDefault: boolean
  flagshipDefault: boolean
  tenantSettable: boolean
  platformLockable: boolean
  metered: boolean
  requires?: string[]
  sort: number
}

export type EntitlementItem = EntitlementDef & {
  state: '' | 'on' | 'off'
  reason: string
  expiresAt?: string
  updatedBy: string
  locked: boolean
  lockReason: string
  expired: boolean
}

export function listEntitlementDefs(): Promise<{ items: EntitlementDef[]; count: number }> {
  return call('/entitlements')
}

export function listTenantEntitlements(slug: string): Promise<{
  items: EntitlementItem[]
  count: number
  edition: string
}> {
  return call(`/tenants/${encodeURIComponent(slug)}/entitlements`)
}

// setEntitlement 的 state 只能是 inherit / on / off。
// expiresAt: undefined=默认（on 90 天）、"never"=长期、RFC3339=指定时间。
export function setEntitlement(
  slug: string, code: string,
  body: { state: 'inherit' | 'on' | 'off'; reason?: string; expiresAt?: string },
): Promise<unknown> {
  return call(`/tenants/${encodeURIComponent(slug)}/entitlements/${encodeURIComponent(code)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
}

export function lockEntitlement(
  code: string, locked: boolean, reason?: string,
): Promise<unknown> {
  return call(`/entitlements/${encodeURIComponent(code)}/lock`, {
    method: 'POST',
    body: JSON.stringify({ locked, reason }),
  })
}
