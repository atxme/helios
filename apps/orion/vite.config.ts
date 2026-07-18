import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Configuration Vite pour Tauri : port fixe 1420, pas de masquage d'erreurs.
// Aucune proxy /api ici — contrairement à l'app web de heliosd, le client ne
// parle pas à un serveur web pour se connecter : c'est le backend Rust (Tauri)
// qui monte WireGuard. La télémétrie heliosd (post-tunnel) est gérée côté Rust.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
})
