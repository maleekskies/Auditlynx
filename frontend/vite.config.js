import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxies /api requests to the FastAPI backend during local dev so the
// frontend can call fetch('/api/...') without CORS or hardcoded hosts.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
