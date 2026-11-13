import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 开发期把 API 代理到本地后端，避免前端处理跨域。
// 生产由 Go 服务直接托管 web/dist，同源无跨域问题。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/v1': 'http://127.0.0.1:18090',
      '/s': 'http://127.0.0.1:18090',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      // 两个入口：租户端（index）与平台运营端（platform）。
      // 分成两个 bundle 而不是靠前端路由区分——平台页面的产物里
      // 根本不存在租户 API 的调用代码，降低"用错令牌"的可能。
      input: {
        main: 'index.html',
        platform: 'platform.html',
      },
    },
  },
})
