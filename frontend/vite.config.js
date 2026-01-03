import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3000,
    proxy: {
      // Proxy OpenAPI spec (Swagger UI fetches this without /api prefix)
      '/openapi.json': {
        target: 'http://localhost:8000',
        changeOrigin: true
      },
      // Proxy all /api requests to backend
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            // Tell FastAPI it's behind /api prefix
            proxyReq.setHeader('X-Forwarded-Prefix', '/api')
          })
        }
      }
    }
  }
})
