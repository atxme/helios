import type { TunnelState } from '../types'

export interface StateMeta {
  label: string
  /** Teinte lisible — texte et bordures. Tient le ratio AA sur le fond papier. */
  color: string
  /** Teinte vive — graphiques uniquement (orbe, pastilles, courbes). */
  accent: string
  /** true si le tunnel achemine le trafic (kill-switch levé). */
  active: boolean
  /** true si une transition est en cours. */
  transitioning: boolean
}

/**
 * Couleurs d’état — calibrées pour le fond papier du thème.
 *
 * Elles ne viennent volontairement pas de la palette MUI : elles portent un sens
 * de sécurité, pas une intention décorative. Les changer, c’est changer ce que
 * l’utilisateur croit de sa protection.
 *
 * **Deux niveaux, et c’est une contrainte, pas un caprice.** Un vert ou un jaune
 * assez vifs pour animer un graphique tombent sous le ratio AA dès qu’ils
 * portent du texte sur blanc. On sépare donc : `color` énonce, `accent` éclaire.
 * Aucun texte ne doit utiliser `accent`.
 */
const UP = '#0B6B4E'
const UP_VIVID = '#12B981'
const TRANSIT = '#A16207'
const TRANSIT_VIVID = '#F5B301'
const FAIL = '#9B2C2C'
const FAIL_VIVID = '#EF4444'
const DOWN = '#5A6B65'
const DOWN_VIVID = '#94A8A1'

export function stateMeta(state: TunnelState): StateMeta {
  switch (state) {
    case 'up':
      return { label: 'Connecté', color: UP, accent: UP_VIVID, active: true, transitioning: false }
    case 'connecting':
      return {
        label: 'Connexion…',
        color: TRANSIT,
        accent: TRANSIT_VIVID,
        active: false,
        transitioning: true,
      }
    case 'captive_portal':
      return {
        label: 'Portail captif',
        color: TRANSIT,
        accent: TRANSIT_VIVID,
        active: false,
        transitioning: true,
      }
    case 'failed':
      return {
        label: 'Échec',
        color: FAIL,
        accent: FAIL_VIVID,
        active: false,
        transitioning: false,
      }
    case 'down':
    default:
      return {
        label: 'Déconnecté',
        color: DOWN,
        accent: DOWN_VIVID,
        active: false,
        transitioning: false,
      }
  }
}

/**
 * Posture de sécurité réelle du poste — distincte de l’état du tunnel.
 *
 * Orion est délibérément **fail-open** (ADR-001 §3 bis) : pas de pare-feu, pas
 * de WFP. Sa protection tient à une invariante de cycle de vie — l’adaptateur
 * WireGuard, qui capte `0.0.0.0/0`, n’est jamais démonté sur échec, seulement
 * sur déconnexion explicite. Tant qu’il est monté, WireGuard **jette** les
 * paquets faute de handshake ; il n’y a pas de fuite.
 *
 * C’est contre-intuitif et l’IHM doit le dire : « Échec » avec l’adaptateur
 * monté n’est pas une situation exposée. Sans cette distinction, un utilisateur
 * voit une erreur rouge et démonte l’adaptateur « pour réessayer proprement » —
 * geste qui le fait précisément fuir en clair.
 *
 * C’est pourquoi `detail` n’est affiché que sur `held` et `exposed` : là où la
 * lecture spontanée est fausse. Sur `protected`, l’état parle de lui-même — la
 * pastille de l’en-tête suffit, un bandeau de plus ne dirait rien de neuf.
 */
export type Posture = 'protected' | 'held' | 'exposed'

export interface PostureMeta {
  posture: Posture
  label: string
  detail: string
  color: string
  accent: string
}

const HELD = '#2F5D8A'
const HELD_VIVID = '#3B82F6'
const EXPOSED = '#A8501B'
const EXPOSED_VIVID = '#F97316'

export function postureMeta(state: TunnelState, adapterUp: boolean): PostureMeta {
  if (!adapterUp) {
    return {
      posture: 'exposed',
      label: 'Trafic en clair',
      detail: 'Le trafic sort hors tunnel.',
      color: EXPOSED,
      accent: EXPOSED_VIVID,
    }
  }
  if (state === 'up') {
    return {
      posture: 'protected',
      label: 'Trafic dans le tunnel',
      detail: 'Tout passe par la gateway.',
      color: UP,
      accent: UP_VIVID,
    }
  }
  return {
    posture: 'held',
    label: 'Trafic retenu',
    detail: 'WireGuard retient les paquets. Rien ne fuit — ne pas démonter.',
    color: HELD,
    accent: HELD_VIVID,
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
