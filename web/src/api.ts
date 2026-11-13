// 统一的 API 客户端：集中处理令牌、错误信封与 401 跳转。
// 页面里不直接调 fetch，避免每个页面各写一套错误处理。

import { sha256File } from './sha256'

export type ApiError = { code: string; message: string; requestId?: string }

const ACCESS_KEY = 'dv.access'
const REFRESH_KEY = 'dv.refresh'

export function getAccess(): string | null {
  return localStorage.getItem(ACCESS_KEY)
}
export function getRefresh(): string | null {
  return localStorage.getItem(REFRESH_KEY)
}
export function setTokens(access: string, refresh: string) {
  localStorage.setItem(ACCESS_KEY, access)
  localStorage.setItem(REFRESH_KEY, refresh)
}
export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

async function parse(resp: Response): Promise<unknown> {
  const text = await resp.text()
  try {
    return text ? JSON.parse(text) : {}
  } catch {
    return { code: 'BAD_JSON', message: text.slice(0, 200) }
  }
}

export class HttpError extends Error {
  code: string
  status: number
  // hint 是服务端给出的"下一步怎么做"（口令过期要去改密、没同步要找管理员…）。
  // 单独一个字段而不是拼进 message：界面要把"哪里错了"和"该做什么"分两行显示。
  hint?: string
  // data 是服务端附带的机器可读载荷（如"名下还有哪些空间"的清单）。
  // 只放进 message 会变成一句没法操作的描述，界面需要拿到结构化数据。
  data?: unknown
  constructor(status: number, code: string, message: string, hint?: string, data?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.hint = hint
    this.data = data
  }
}

// 刷新令牌只允许并发一次：多个 401 同时到达时共用同一个刷新请求，
// 否则会互相把对方的刷新令牌用掉（旋转后旧令牌立即失效）。
let refreshing: Promise<boolean> | null = null

async function tryRefresh(): Promise<boolean> {
  const refresh = getRefresh()
  if (!refresh) return false
  if (refreshing) return refreshing
  refreshing = (async () => {
    try {
      const resp = await fetch('/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refresh }),
      })
      if (!resp.ok) return false
      const body = (await parse(resp)) as { data?: { accessToken: string; refreshToken: string } }
      if (!body.data) return false
      setTokens(body.data.accessToken, body.data.refreshToken)
      return true
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
  retry = true,
): Promise<T> {
  const headers = new Headers(init.headers)
  const access = getAccess()
  if (access) headers.set('Authorization', `Bearer ${access}`)

  const resp = await fetch(path, { ...init, headers })

  // 认证端点不能走"刷新令牌 → 失败就跳登录页"这条通用分支：
  // 登录失败本身就是 401，走进去会被改写成"登录已过期"，
  // 用户永远看不到"口令不正确/账号已锁定"这类真正有用的原因。
  const isAuthPath = path.startsWith('/v1/auth/')
  if (resp.status === 401 && retry && !isAuthPath) {
    if (await tryRefresh()) return api<T>(path, init, false)
    clearTokens()
    if (!location.pathname.startsWith('/login')) {
      location.assign('/login?redirect=' + encodeURIComponent(location.pathname))
    }
    throw new HttpError(401, 'UNAUTHENTICATED', '登录已过期')
  }

  const body = (await parse(resp)) as { code?: string; message?: string; hint?: string; data?: unknown }
  if (!resp.ok) {
    throw new HttpError(resp.status, body.code ?? 'ERROR', body.message ?? '请求失败', body.hint, body.data)
  }
  return body.data as T
}

// Capabilities 是租户当前档位的能力集。
//
// 只用于界面显隐：真正拦住越权的是服务端写入口。
// 拉取失败时前端应按"全部可见"降级，而不是把功能全藏起来——
// 藏错了客户会以为功能没了，点开了 403 至少还能看到明确原因。
export type Capabilities = {
  edition: string
  declaredEdition: string
  editionName: string
  expiresAt: string | null
  grace: boolean
  expired: boolean
  capabilities: {
    classification: boolean
    ad: boolean
    shareMail: boolean
    customDomain: boolean
  }
  classificationLevels: number[] | null
  limits: {
    versionKeep: number
    maxUploadMB: number
    // 服务端允许的单次上传读取时长；前端据此给"网络慢"的判定，两边必须同源
    uploadTimeoutSeconds: number
    // null 表示不限制；空数组在后端不会出现（空=不限）
    allowedExts: string[] | null
  }
}

export async function getCapabilities(): Promise<Capabilities> {
  return api<Capabilities>('/v1/me/capabilities')
}

export async function apiUpload<T = unknown>(path: string, form: FormData): Promise<T> {
  return api<T>(path, { method: 'POST', body: form })
}

// 下载需要带 Authorization 头，无法用 <a href> 直接开，
// 因此取回 blob 再触发本地下载。
export async function downloadNode(nodeId: string, filename: string) {
  const resp = await fetch(`/v1/nodes/${nodeId}/content`, {
    headers: { Authorization: `Bearer ${getAccess()}` },
  })
  if (!resp.ok) throw new HttpError(resp.status, 'DOWNLOAD_FAILED', '下载失败')
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// downloadVersion 下载指定版本，不改变当前版本。
//
// 文件名插入版本号：同一文件下载多个版本时，浏览器默认会存成"报告 (1).txt"，
// 事后分不清是第几版，回退排查时很容易拷错文件。
export async function downloadVersion(nodeId: string, versionNo: number, filename: string) {
  const resp = await fetch(`/v1/nodes/${nodeId}/versions/${versionNo}/download`, {
    headers: { Authorization: `Bearer ${getAccess()}` },
  })
  if (!resp.ok) {
    const body = (await parse(resp)) as { code?: string; message?: string }
    throw new HttpError(resp.status, body.code ?? 'DOWNLOAD_FAILED', body.message ?? '下载失败')
  }
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const dot = filename.lastIndexOf('.')
  const out = dot > 0
    ? `${filename.slice(0, dot)}.v${versionNo}${filename.slice(dot)}`
    : `${filename}.v${versionNo}`
  const a = document.createElement('a')
  a.href = url
  a.download = out
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// fetchBlob 取回二进制并生成可回收的对象 URL。
//
// 为什么不直接用 <img src="/v1/...">：预览与下载都需要 Authorization 头，
// 浏览器导航不会带自定义头；把令牌塞进查询串会进访问日志与浏览器历史。
export async function fetchBlob(path: string): Promise<{ url: string; type: string; revoke: () => void }> {
  const resp = await fetch(path, { headers: { Authorization: `Bearer ${getAccess()}` } })
  if (!resp.ok) {
    const body = (await parse(resp)) as { code?: string; message?: string }
    throw new HttpError(resp.status, body.code ?? 'FETCH_FAILED', body.message ?? '读取内容失败')
  }
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  return { url, type: resp.headers.get('Content-Type') ?? blob.type, revoke: () => URL.revokeObjectURL(url) }
}

// postJSON 是最常用的写操作形态，抽出来避免每个页面重复写 headers。
export function postJSON<T = unknown>(path: string, body: unknown): Promise<T> {
  return api<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export function patchJSON<T = unknown>(path: string, body: unknown): Promise<T> {
  return api<T>(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export function del<T = unknown>(path: string): Promise<T> {
  return api<T>(path, { method: 'DELETE' })
}

// ---------------- M2 能力封装 ----------------

export type Me = {
  userId: string
  tenantId: string
  username: string
  displayName: string
  email: string
  classification: number
  ceiling: number
  roles: string[]
}

export function fetchMe(): Promise<Me> {
  return api<Me>('/v1/me')
}

export type SearchHit = {
  nodeId: string
  spaceId: string
  name: string
  kind: 'folder' | 'file'
  ext: string
  sizeBytes: number
  updatedAt: string
}

export async function searchNodes(q: string, limit = 20): Promise<SearchHit[]> {
  const data = await api<{ items: SearchHit[] }>(
    `/v1/search?q=${encodeURIComponent(q)}&limit=${limit}`,
  )
  return data.items ?? []
}

// 批量下载走整批预检：后端只要有一个对象无权就会整批拒绝，
// 因此这里不能"部分成功"，失败时直接抛出即可。
export async function downloadBatch(ids: string[]): Promise<void> {
  const resp = await fetch('/v1/batch/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getAccess()}` },
    body: JSON.stringify({ nodeIds: ids }),
  })
  if (!resp.ok) {
    const body = (await parse(resp)) as { code?: string; message?: string }
    throw new HttpError(resp.status, body.code ?? 'BATCH_FAILED', body.message ?? '批量下载失败')
  }
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `文档-${new Date().toISOString().slice(0, 10)}.zip`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// 分片大小 1MB。
//
// 两次调小的原因不同：
//   · 8MB → 2MB：8MB 在 250 Kbps 上行下要 260 秒，必然撞上网关 100 秒上限；
//   · 2MB → 1MB：XHR 的 upload.onprogress 反映的是"写入内核缓冲"的进度，
//     2MB 的片会被内核一次吞下、进度瞬间到 100%，随后长时间不动。
//     也就是说片内进度不可信，只能靠"片完成"推进；那颗粒度就由分片大小决定。
//     1MB 在慢速上行下约 12 秒一格，配合"已传 x/y MB"的数字，能看出在动。
//     再小会让超大文件的分片数过多（1GB/0.5MB = 2000 个请求），1MB 是折中。
const CHUNK = 1 * 1024 * 1024

export type UploadPhase = 'hash' | 'upload'
// pct 恒为 0..99，100 只在 complete 成功后给一次。
// sentBytes/part 用于展示"已传多少、第几片"——比百分比更可信，
// 因为它是按片累加的确定值，不依赖浏览器的缓冲进度。
export type UploadProgress = {
  phase: UploadPhase
  pct: number
  sentBytes?: number
  totalBytes?: number
  part?: number
  parts?: number
}
export type UploadResult = { nodeId: string; deduped: boolean; resumed: boolean }

// xhrSend 用 XHR 而不是 fetch：fetch 拿不到上传进度。
// 进度是这次需求的核心之一，而 fetch 的 ReadableStream 上传侧至今没有稳定可用的进度事件。
function xhrSend(
  method: string,
  url: string,
  body: XMLHttpRequestBodyInit,
  onSent?: (frac: number) => void,
  signal?: AbortSignal,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open(method, url, true)
    const token = getAccess()
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    // FormData 不能手设 Content-Type：浏览器要自己带 boundary
    if (typeof body === 'string') xhr.setRequestHeader('Content-Type', 'application/json')
    else if (body instanceof Blob) xhr.setRequestHeader('Content-Type', 'application/octet-stream')

    // 取消：中止请求但**不删除服务端已收的分片**。
    // 保留分片是刻意的——用户点了取消，过一会儿又想传，可以接着传而不是从头来。
    if (signal) {
      if (signal.aborted) {
        reject(new HttpError(0, 'CANCELED', '已取消'))
        return
      }
      signal.addEventListener('abort', () => xhr.abort(), { once: true })
    }

    xhr.upload.onprogress = (e) => {
      if (onSent && e.lengthComputable) onSent(e.total > 0 ? e.loaded / e.total : 1)
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.responseText)
        return
      }
      let code = 'ERROR'
      let msg = '上传失败'
      try {
        const b = JSON.parse(xhr.responseText) as { code?: string; message?: string }
        code = b.code ?? code
        msg = b.message ?? msg
      } catch {
        /* 非 JSON（网关错误页）时保留默认文案 */
      }
      reject(new HttpError(xhr.status, code, msg))
    }
    xhr.onabort = () => reject(new HttpError(0, 'CANCELED', '已取消'))
    xhr.onerror = () =>
      reject(new HttpError(0, 'NETWORK', '网络中断。重新选择同一文件可从断点继续'))
    xhr.ontimeout = () => reject(new HttpError(0, 'TIMEOUT', '上传超时'))
    xhr.send(body)
  })
}

// partLen 是第 i 片（从 1 开始）的字节数。
function partLen(i: number, partSize: number, total: number): number {
  const start = (i - 1) * partSize
  return Math.max(0, Math.min(i * partSize, total) - start)
}

// uploadFile 按大小自动选择通道：
//   ≤ 8MB 走一次性 multipart（一次请求，简单可靠）；
//   > 8MB 走分片 + 秒传 + 断点续传。
//
// 续传不是靠前端记住 uploadId：会话由服务端按 (用户, 内容哈希, 大小, 目标目录, 名称) 复用。
// 所以刷新页面、换标签页、甚至换台机器，重新选择同一个文件都会自动接上——
// 前端存 localStorage 的做法在换设备或清缓存后就失效了。
export async function uploadFile(
  file: File,
  spaceId: string,
  parentId: string,
  onProgress?: (p: UploadProgress) => void,
  signal?: AbortSignal,
): Promise<UploadResult> {
  if (file.size <= CHUNK) {
    const form = new FormData()
    form.append('file', file)
    if (parentId) form.append('parentId', parentId)
    const text = await xhrSend('POST', `/v1/spaces/${spaceId}/files`, form, (f) =>
      onProgress?.({ phase: 'upload', pct: Math.round(f * 100) }),
      signal,
    )
    onProgress?.({ phase: 'upload', pct: 100 })
    const data = JSON.parse(text) as { data?: { nodeId?: string }; nodeId?: string }
    const nodeId = data.data?.nodeId ?? data.nodeId ?? ''
    if (!nodeId) throw new HttpError(500, 'UPLOAD_RESULT', '服务端未返回节点')
    return { nodeId, deduped: false, resumed: false }
  }

  const hash = await sha256File(file, (f) =>
    onProgress?.({ phase: 'hash', pct: Math.round(f * 100) }),
    signal,
  )

  const created = await postJSON<{
    uploadId?: string
    deduped?: boolean
    nodeId?: string
    partSize?: number
    receivedParts?: number[]
    resumed?: boolean
  }>('/v1/uploads', {
    spaceId, parentId, name: file.name, sizeBytes: file.size, sha256: hash, partSize: CHUNK,
  })

  if (created.deduped && created.nodeId) {
    onProgress?.({ phase: 'upload', pct: 100 })
    return { nodeId: created.nodeId, deduped: true, resumed: false }
  }
  const uploadId = created.uploadId
  if (!uploadId) throw new HttpError(500, 'UPLOAD_INIT', '创建上传会话失败')

  // 分片边界以服务端为准：会话里存的是创建时的值，客户端换了 CHUNK 也不会错位
  const partSize = created.partSize && created.partSize > 0 ? created.partSize : CHUNK
  const received = new Set(created.receivedParts ?? [])
  const parts = Math.max(1, Math.ceil(file.size / partSize))

  let sentBytes = 0
  for (const p of received) sentBytes += partLen(p, partSize, file.size)

  const report = (inPart: number, idx: number) => {
    const bytes = Math.min(file.size, sentBytes + inPart * partLen(idx, partSize, file.size))
    // 99 封顶：complete 还要落库、建版本、清理旧版本，别让进度条先到 100 再卡住
    onProgress?.({
      phase: 'upload',
      pct: Math.min(99, Math.round((bytes / file.size) * 99)),
      sentBytes: Math.round(bytes),
      totalBytes: file.size,
      part: idx,
      parts,
    })
  }

  // 续传时先报一次现状：用户重选文件后应立即看到"已传 x/y"，而不是从 0 开始跳
  report(0, Math.min(parts, 1))

  for (let i = 1; i <= parts; i++) {
    if (signal?.aborted) throw new HttpError(0, 'CANCELED', '已取消')
    if (received.has(i)) {
      report(1, i)
      continue
    }
    const start = (i - 1) * partSize
    const end = Math.min(i * partSize, file.size)
    await xhrSend(
      'PUT',
      `/v1/uploads/${uploadId}/parts/${i}`,
      file.slice(start, end),
      (f) => report(f, i),
      signal,
    )
    sentBytes += end - start
    report(1, i)
  }

  const done = await postJSON<{ nodeId: string }>(`/v1/uploads/${uploadId}/complete`, {})
  onProgress?.({ phase: 'upload', pct: 100 })
  return { nodeId: done.nodeId, deduped: false, resumed: !!created.resumed }
}


// ---------------- 主题 ----------------

const THEME_KEY = 'dv.theme'
export type ThemeMode = 'light' | 'dark' | 'auto'

export function currentTheme(): ThemeMode {
  const v = localStorage.getItem(THEME_KEY)
  return v === 'light' || v === 'dark' ? v : 'auto'
}

export function applyTheme(mode: ThemeMode = currentTheme()) {
  const dark =
    mode === 'dark' ||
    (mode === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  localStorage.setItem(THEME_KEY, mode)
}

export function cycleTheme(): ThemeMode {
  const order: ThemeMode[] = ['auto', 'light', 'dark']
  const next = order[(order.indexOf(currentTheme()) + 1) % order.length]
  applyTheme(next)
  return next
}

// ---------------- 会话与账号生命周期 ----------------

// logout 先让服务端吊销刷新令牌，再清本地令牌。
//
// 顺序不能反：先清本地就再也没有凭证去调登出接口，服务端那条会话会一直留到
// 刷新令牌过期为止——共用电脑上这就是"退出了但别人还能续上"。
// 网络失败时仍然清本地并跳转：本地必须退出，服务端那条会话由 TTL 兜底。
export async function logout(): Promise<void> {
  const refresh = getRefresh()
  try {
    if (refresh) await postJSON('/v1/auth/logout', { refreshToken: refresh })
  } catch {
    // 忽略：登出不该因为网络问题把用户卡在已登录界面
  } finally {
    clearTokens()
    location.assign('/login')
  }
}

export type HandoverCandidate = { id: string; username: string; displayName: string }

export type HandoverSummary = {
  spaces: number
  nodes: number
  grants: number
  revokedShares: number
}

export function handoverCandidates(q = ''): Promise<HandoverCandidate[]> {
  return api<{ items: HandoverCandidate[] }>(
    `/v1/me/handover-candidates?q=${encodeURIComponent(q)}`,
  ).then((d) => d.items ?? [])
}

export function deletionPreview(): Promise<HandoverSummary> {
  return api<HandoverSummary>('/v1/me/account/deletion-preview')
}

export type SelfDeleteResult = {
  deleted: boolean
  handedOverSpaces: number
  handedOverNodes: number
  handedOverGrants: number
  revokedShares: number
  sessionsInvalidated: boolean
}

export function deleteAccount(successorId: string, confirm: string): Promise<SelfDeleteResult> {
  return postJSON<SelfDeleteResult>('/v1/me/account/delete', { successorId, confirm })
}

// ---------------- 操作日志（我的活动 / 管理日志）----------------
//
// 两类日志共用同一套查询参数与响应结构，差别只在可见范围：
// 用户侧由服务端强制 actor=自己，管理侧按角色收敛动作前缀。

export type ActivityItem = {
  seq: number
  actorId: string
  actorName?: string
  actorType: string
  action: string
  objectId: string
  // 服务端顺带解析的对象名称（文件/目录/空间）。对象已删除时仍给名称，
  // 日志要能回答"当时我对什么做了什么"；查不到时前端退回 id 前 8 位。
  objectName?: string
  result: string
  ip: string
  requestId: string
  createdAt: string
  detail?: Record<string, unknown>
}

export type ActivityPage = {
  items: ActivityItem[]
  total: number
  page: number
  size: number
}

export type ActivityFilter = {
  group?: string
  result?: string
  action?: string
  actorId?: string
  from?: string
  to?: string
  page?: number
  size?: number
}

export function activityQuery(f: ActivityFilter): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  }
  return q.toString()
}

export function myActivity(f: ActivityFilter): Promise<ActivityPage> {
  return api<ActivityPage>(`/v1/me/activity?${activityQuery(f)}`)
}

export function adminActivity(f: ActivityFilter): Promise<ActivityPage> {
  return api<ActivityPage>(`/v1/admin/activity?${activityQuery(f)}`)
}

// exportActivity 走 fetch 而不是直接打开链接：导出接口要求 Bearer 令牌，
// window.open 不会带上 Authorization，用户只会拿到一个 401 的 JSON。
export async function exportActivity(scope: 'me' | 'admin', f: ActivityFilter): Promise<void> {
  const bucket = scope === 'me' ? '/v1/me/activity/export.csv' : '/v1/admin/activity/export.csv'
  const blob = await fetchBlob(`${bucket}?${activityQuery(f)}`)
  const a = document.createElement('a')
  a.href = blob.url
  a.download = `activity-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  // 立刻 revoke 会让部分浏览器下载中断，等一会儿再释放
  window.setTimeout(blob.revoke, 4000)
}

// ---------------- 目录认证（LDAP / AD） ----------------
//
// 口令是单向的：读取接口只回 hasPassword，保存时留空表示"沿用原口令"。
// 因此这里刻意把 bindPassword 设为可选，避免调用方误以为能读回来。

export type DirectoryConfig = {
  enabled: boolean
  url: string
  startTls: boolean
  insecureSkipVerify: boolean
  caPem?: string
  tlsName: string
  bindDn: string
  bindPassword?: string
  baseDn: string
  userFilter: string
  syncFilter: string
  groupFilter: string
  excludeAccounts: string[]
  adMode: boolean
  allowPlaintext: boolean
  syncIntervalMinutes: number
  source?: 'database' | 'env' | 'none'
  hasPassword?: boolean
  hasCa?: boolean
  updatedAt?: string
}

export type DirectoryProbe = {
  anonymous: boolean
  bind: boolean
  // 没填 BindDN 时服务端会跳过绑定；不能用"绑定失败"表达，否则像是口令错
  bindSkipped?: boolean
  baseRead: boolean
  reason?: string
}

export type DirectoryRun = {
  id: string
  startedAt: string
  finishedAt?: string
  status: 'running' | 'ok' | 'failed'
  watermark: string
  usersSeen: number
  usersCreated: number
  usersUpdated: number
  usersDisabled: number
  usersRestored: number
  groupsSynced: number
  membersLinked: number
  conflicts: number
  conflictUsers: string[]
  error?: string
}

export function getDirectory(): Promise<DirectoryConfig> {
  return api<DirectoryConfig>('/v1/admin/directory')
}

export function saveDirectory(cfg: DirectoryConfig): Promise<DirectoryConfig> {
  return api<DirectoryConfig>('/v1/admin/directory', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg),
  })
}

export function testDirectory(cfg: DirectoryConfig): Promise<DirectoryProbe> {
  return postJSON<DirectoryProbe>('/v1/admin/directory/test', cfg)
}

export function syncDirectory(mode: 'full' | 'incremental'): Promise<{ accepted: boolean }> {
  return postJSON<{ accepted: boolean }>('/v1/admin/directory/sync', { mode })
}

export function directoryRuns(limit = 20): Promise<{ items: DirectoryRun[] }> {
  return api<{ items: DirectoryRun[] }>(`/v1/admin/directory/runs?limit=${limit}`)
}

// ---------------- 空间移交 ----------------

export type TransferRequest = {
  id: string
  spaceId: string
  spaceName: string
  fromUserId: string
  fromName: string
  toUserId: string
  toName: string
  initiatedBy: string
  initiatorName: string
  mode: 'owner' | 'admin' | 'admin_to_self'
  status: 'pending' | 'approved' | 'rejected' | 'cancelled' | 'expired'
  reason: string
  createdAt: string
  expiresAt: string
  decidedAt?: string | null
}

export type SpaceOverviewRow = {
  id: string
  name: string
  kind: string
  ownerId: string
  ownerName: string
  ownerStatus: string
  classification: number
  usedBytes: number
  quotaBytes: number | null
  createdAt: string
  lastActivity?: string | null
  granted: number
  onlyOwner: boolean
  pendingId?: string
  pendingTo?: string
  pendingUntil?: string
}

export type TransferResult = { done?: boolean; pending?: boolean; request?: TransferRequest }
