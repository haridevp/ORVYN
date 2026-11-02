import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// base: './' ensures relative asset paths work anywhere (GitHub Pages repo subpaths,
// custom domains, and local preview servers) without 404s.
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      '/scan': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/scans': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/health': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/environment': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/target': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/mcp': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/templates': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/reports': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
      '/architecture': process.env.BACKEND_URL || 'http://127.0.0.1:8000',
    }
  }
})
