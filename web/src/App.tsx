import { useSyncExternalStore } from 'react'
import Login from './pages/Login'
import Home from './pages/Home'
import Approvals from './pages/Approvals'
import Files from './pages/Files'
import ShareView from './pages/ShareView'
import EditPage from './pages/EditPage'
import PreviewPage from './pages/PreviewPage'
import Admin from './pages/Admin'
import ActivityPage from './pages/ActivityPage'
import { getAccess } from './api'
import { currentPath, subscribe } from './router'
import ErrorBoundary from './ErrorBoundary'

// 极简路由：按 pathname 分发（内核在 router.ts）。
//
// 关键约束：路由必须反映在地址栏里。
// 之前空间/目录只是组件内部 state，URL 永远是 /files，一刷新就回首页——
// 用户既不能分享"某一层目录"的链接，也不能用浏览器后退。
// 现在：/files/{spaceId}/{folderId}，每一层都是可收藏、可分享的真实地址。

function parseFilesPath(path: string): { spaceId: string; folderId: string } {
  const parts = path.split('/').filter(Boolean) // ["files", spaceId, folderId]
  return { spaceId: parts[1] ?? '', folderId: parts[2] ?? '' }
}

export default function App() {
  // 包一层错误边界：某个页面抛错时显示可读提示，而不是整页黑屏
  return (
    <ErrorBoundary>
      <Routes />
    </ErrorBoundary>
  )
}

function Routes() {
  const loc = useSyncExternalStore(subscribe, currentPath, currentPath)
  const path = loc.split('?')[0]

  if (path.startsWith('/s/')) {
    return <ShareView token={path.slice(3)} />
  }
  if (path === '/login') {
    return <Login />
  }
  // 其余路径都要求登录
  if (!getAccess()) {
    location.assign('/login?redirect=' + encodeURIComponent(loc))
    return null
  }
  if (path.startsWith('/edit/')) {
    return <EditPage nodeId={path.slice('/edit/'.length)} />
  }
  if (path.startsWith('/preview/')) {
    return <PreviewPage nodeId={path.slice('/preview/'.length)} />
  }
  if (path === '/admin' || path.startsWith('/admin/')) {
    return <Admin tab={path.replace('/admin', '').replace('/', '')} />
  }
  if (path === '/approvals') {
    return <Approvals />
  }
  if (path === '/activity') {
    return <ActivityPage />
  }
  // 登录后先到工作台：文件页只回答"这个目录里有什么"，
  // 回答不了"我今天该做什么、最近在弄什么"。
  if (path === '/home' || path === '/') {
    return <Home />
  }

  const { spaceId, folderId } = parseFilesPath(path)
  return <Files spaceId={spaceId} folderId={folderId} />
}
