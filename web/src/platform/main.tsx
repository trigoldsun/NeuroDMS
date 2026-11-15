import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import Console from './Console'
import '../styles.css'
// 运营台专用布局：pf- 命名空间，与租户端样式互不影响（见文件头说明）
import './platform.css'
import { applyTheme } from '../api'

applyTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Console />
  </StrictMode>,
)
