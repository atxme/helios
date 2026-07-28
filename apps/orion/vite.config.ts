import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite configuration for Tauri: fixed port 1420, no error masking.
// No /api proxy here — unlike heliosd's web app, the client doesn't talk to
// a web server to connect: it's the Rust backend (Tauri) that mounts
// WireGuard. heliosd telemetry (post-tunnel) is handled on the Rust side.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
})
