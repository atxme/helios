import type { ClientProfile, PskKind, TunnelState } from '../types'

export interface StateMeta {
  label: string
  /** Readable tint — text and borders. Holds the AA ratio on the paper background. */
  color: string
  /** Vivid tint — graphics only (orb, chips, curves). */
  accent: string
  /** true if the tunnel is carrying traffic (kill-switch lifted). */
  active: boolean
  /** true if a transition is in progress. */
  transitioning: boolean
}

/**
 * State colors — calibrated for the theme's paper background.
 *
 * They deliberately don't come from the MUI palette: they carry a security
 * meaning, not a decorative intent. Changing them changes what the user
 * believes about their protection.
 *
 * **Two levels, and it's a constraint, not a whim.** A green or yellow vivid
 * enough to animate a chart falls below the AA ratio as soon as it carries
 * text on white. So we separate: `color` states, `accent` illuminates. No
 * text should ever use `accent`.
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
 * The machine's actual security posture — distinct from the tunnel state.
 *
 * Orion is deliberately **fail-open** (ADR-001 §3 bis): no firewall, no WFP.
 * Its protection relies on a lifecycle invariant — the WireGuard adapter,
 * which captures `0.0.0.0/0`, is never unmounted on failure, only on
 * explicit disconnection. As long as it's mounted, WireGuard **drops**
 * packets for lack of a handshake; there is no leak.
 *
 * This is counter-intuitive and the UI must say so: "Failed" with the
 * adapter mounted is not an exposed situation. Without this distinction, a
 * user sees a red error and unmounts the adapter "to retry cleanly" — a
 * gesture that precisely makes it leak in clear.
 *
 * This is why `detail` is only shown on `held` and `exposed`: where the
 * spontaneous reading is wrong. On `protected`, the state speaks for
 * itself — the header chip is enough, one more banner would say nothing new.
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
      label: 'Exposé',
      detail: 'Adaptateur démonté : le trafic sort hors tunnel.',
      color: EXPOSED,
      accent: EXPOSED_VIVID,
    }
  }
  if (state === 'up') {
    return {
      posture: 'protected',
      label: 'Protégé',
      detail: 'Handshake frais : tout passe par la gateway.',
      color: UP,
      accent: UP_VIVID,
    }
  }
  return {
    posture: 'held',
    label: 'Retenu',
    detail: 'WireGuard retient les paquets. Rien ne fuit — ne pas démonter.',
    color: HELD,
    accent: HELD_VIVID,
  }
}

/**
 * Nature of the `PresharedKey` slot's protection, as it should be displayed.
 *
 * **A PSK is not a PQC PSK**, and the UI must not confuse them: the first is
 * a secret copied by hand, shared out of band, that never rotates and whose
 * presence *disables* ML-KEM negotiation; the second is derived from an
 * ML-KEM-768 exchange replayed on every connection. Both hold up against
 * "harvest now, decrypt later" — calling the first one "post-quantum" wasn't
 * wrong, it was imprecise, and the imprecision hid that no rotation happens.
 *
 * **The profile alone isn't enough to decide**, in both directions: the PQC
 * PSK is never written there (a perfectly established PQC tunnel shows
 * `preshared_key: null`), and a filled-in `preshared_key` always denotes a
 * static PSK. It's the core's `protection` event that is authoritative; the
 * profile only serves to announce what's *expected* while the connection
 * hasn't decided yet.
 */
export type ProtectionTone = 'pqc' | 'static' | 'classic' | 'pending'

export interface ProtectionMeta {
  tone: ProtectionTone
  /** Short chip label. */
  label: string
  /** Tooltip sentence: what it protects, and at what cost. */
  detail: string
}

const PQC_DETAIL =
  'Secret ML-KEM-768 négocié à cette connexion et posé dans le slot PresharedKey. ' +
  'Il est renouvelé au prochain montage : un trafic enregistré aujourd’hui reste ' +
  'illisible pour un adversaire quantique.'

const STATIC_DETAIL =
  'PSK statique inscrit au profil, partagé hors bande. Il protège du « récolter ' +
  'maintenant, déchiffrer plus tard », mais il ne tourne jamais et sa présence ' +
  'désactive la négociation ML-KEM. Les deux pairs doivent porter la même valeur.'

const CLASSIC_DETAIL =
  'Aucun PSK : la confidentialité repose sur Curve25519 seul, cassable par un ' +
  'adversaire quantique qui aurait enregistré le trafic.'

export function protectionMeta(
  profile: ClientProfile | null,
  observed: PskKind | null,
  state: TunnelState,
): ProtectionMeta {
  if (observed === 'ml_kem') return { tone: 'pqc', label: 'PSK PQC · ML-KEM-768', detail: PQC_DETAIL }
  if (observed === 'static') return { tone: 'static', label: 'PSK statique', detail: STATIC_DETAIL }
  if (observed === 'none') return { tone: 'classic', label: 'Sans PSK', detail: CLASSIC_DETAIL }

  // Nothing observed: we announce the wait, never the acquired state. A
  // profile that *can* obtain a PQC PSK doesn't have it yet.
  const staticPsk = Boolean(profile?.preshared_key?.trim())
  if (staticPsk) return { tone: 'static', label: 'PSK statique', detail: STATIC_DETAIL }

  if (profile?.heliosd_url?.trim()) {
    const meta = stateMeta(state)
    return meta.active || meta.transitioning
      ? { tone: 'pending', label: 'PSK PQC — négociation…', detail: PQC_DETAIL }
      : { tone: 'pending', label: 'PSK PQC à la connexion', detail: PQC_DETAIL }
  }

  return { tone: 'classic', label: 'Sans PSK', detail: CLASSIC_DETAIL }
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
