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

/**
 * Posture de sécurité réelle du poste — distincte de l'état du tunnel.
 *
 * Orion est délibérément **fail-open** (ADR-001 §3 bis) : pas de pare-feu, pas
 * de WFP. Sa protection tient à une invariante de cycle de vie — l'adaptateur
 * WireGuard, qui capte `0.0.0.0/0`, n'est jamais démonté sur échec, seulement
 * sur déconnexion explicite. Tant qu'il est monté, WireGuard **jette** les
 * paquets faute de handshake ; il n'y a pas de fuite.
 *
 * C'est contre-intuitif et l'IHM doit le dire : « Échec » avec l'adaptateur
 * monté n'est pas une situation exposée. Sans cette distinction, un utilisateur
 * voit une erreur rouge et démonte l'adaptateur « pour réessayer proprement » —
 * geste qui le fait précisément fuir en clair.
 */
export type Posture = 'protected' | 'held' | 'exposed'

export interface PostureMeta {
  posture: Posture
  label: string
  detail: string
  color: string
}

const HELD = '#7dd3fc'
const EXPOSED = '#ff8f57'

export function postureMeta(state: TunnelState, adapterUp: boolean): PostureMeta {
  if (!adapterUp) {
    return {
      posture: 'exposed',
      label: 'Trafic en clair',
      detail: 'Adaptateur démonté : le trafic emprunte la route par défaut, hors tunnel.',
      color: EXPOSED,
    }
  }
  if (state === 'up') {
    return {
      posture: 'protected',
      label: 'Trafic dans le tunnel',
      detail: 'Handshake frais, adaptateur monté. Tout passe par la gateway.',
      color: UP,
    }
  }
  return {
    posture: 'held',
    label: 'Trafic retenu',
    detail:
      'Adaptateur monté sans handshake : WireGuard jette les paquets. Rien ne fuit — ne pas démonter.',
    color: HELD,
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
