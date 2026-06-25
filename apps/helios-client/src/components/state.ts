import type { TunnelState } from '../types'

export interface StateMeta {
  label: string
  color: string
  glow: string
  /** true si le tunnel achemine le trafic (kill-switch levé). */
  active: boolean
  /** true si une transition est en cours. */
  transitioning: boolean
}

// Couleurs alignées sur l'ancien client egui (palette Helios).
const UP = '#28e4a0'
const TRANSIT = '#ffb347'
const FAIL = '#ff5757'
const DOWN = '#828282'

export function stateMeta(state: TunnelState): StateMeta {
  switch (state) {
    case 'up':
      return { label: 'Connecté', color: UP, glow: 'shadow-neon-emerald', active: true, transitioning: false }
    case 'rekeying':
      return { label: 'Renégociation', color: UP, glow: 'shadow-neon-emerald', active: true, transitioning: false }
    case 'connecting':
      return { label: 'Connexion…', color: TRANSIT, glow: 'shadow-neon-amber', active: false, transitioning: true }
    case 'captive_portal':
      return { label: 'Portail captif', color: TRANSIT, glow: 'shadow-neon-amber', active: false, transitioning: true }
    case 'failed':
      return { label: 'Échec', color: FAIL, glow: '', active: false, transitioning: false }
    case 'down':
    default:
      return { label: 'Déconnecté', color: DOWN, glow: '', active: false, transitioning: false }
  }
}

export function elapsed(upSince: number | null, now: number): string | null {
  if (upSince === null) return null
  const s = Math.max(0, Math.floor((now - upSince) / 1000))
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s / 60) % 60))}:${pad(s % 60)}`
}

export function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} KB/s`
  return `${bps} B/s`
}
