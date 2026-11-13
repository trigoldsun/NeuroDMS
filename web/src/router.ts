// 极简路由内核：地址栏是唯一真源，组件只读取它。
//
// 为什么单独成文件而不是放在 App.tsx：App 需要 import 各页面，各页面又需要 navigate，
// 放在一起就形成循环依赖。函数声明虽然会被提升、多数情况下也能跑，
// 但一旦某个页面在module 初始化阶段就调用 navigate，拿到的仍是未初始化的绑定。
// 单独一个没有依赖的模块，是唯一不会出问题的位置。

const listeners = new Set<() => void>()

export function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => { listeners.delete(cb) }
}

export function currentPath(): string {
  return window.location.pathname + window.location.search
}

function emit() {
  for (const l of listeners) l()
}

window.addEventListener('popstate', emit)

// navigate 是应用内唯一的跳转入口。
// 用 pushState 而不是 location.assign：后者会整页重载，丢掉已加载的空间列表与内存状态。
export function navigate(to: string, replace = false): void {
  if (to === currentPath()) return
  if (replace) window.history.replaceState(null, '', to)
  else window.history.pushState(null, '', to)
  emit()
}

// filesPath 生成目录地址。folderId 为空表示空间根目录。
export function filesPath(spaceId: string, folderId?: string | null): string {
  if (!spaceId) return '/files'
  return folderId ? `/files/${spaceId}/${folderId}` : `/files/${spaceId}`
}

// adminPath 生成管理台页签地址。
//
// 页签必须进地址栏：之前切页签只改组件 state，刷新就回"概览"，
// 也没法把"审计日志"这一页直接发给同事。
export function adminPath(tab: string): string {
  return tab ? `/admin/${tab}` : '/admin'
}

export function previewPath(nodeId: string): string {
  return `/preview/${nodeId}`
}
