import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// base: '/' assumes the custom domain attached to GitHub Pages (serves from
// the domain root). If you deploy to the default <org>.github.io/<repo>/
// URL instead, change this to '/AI-Automated-Penetration-Testing/'.
export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/scan': 'http://backend:8000',
      '/health': 'http://backend:8000',
      '/architecture': 'http://backend:8000',
    }
  }
})
