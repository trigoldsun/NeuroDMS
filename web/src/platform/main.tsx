import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import Console from './Console'
import '../styles.css'
import { applyTheme } from '../api'

applyTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Console />
  </StrictMode>,
)
