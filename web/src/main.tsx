import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles.css'
import { applyTheme, currentTheme } from './api'

// 在首屏渲染前定主题：放到组件里会因为先渲染再套用而闪一下白底
applyTheme()
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (currentTheme() === 'auto') applyTheme('auto')
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
