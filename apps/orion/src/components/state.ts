import type { ClientProfile, ProtectionMode, PskKind, TunnelState } from '../types'

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
 * which captures `0.0.0.0/0, ::/0` by default, is never unmounted on failure,
 * only on explicit disconnection. As long as it's mounted, WireGuard **drops**
 * what it captures for lack of a handshake; there is no leak. A profile still
 * holding the old `0.0.0.0/0` alone lets IPv6 out regardless — the posture
 * panel warns on it (`ipv6_uncaptured_full_tunnel`).
 *
 * This is counter-intuitive and the UI must say so: a tunnel that is gone with
 * the adapter still mounted is not an exposed situation — it is a machine whose
 * traffic goes nowhere at all. Saying only "disconnected" would leave the user
 * hunting for a network failure that isn't one, so the posture names the
 * adapter and the two ways out.
 *
 * This is why `detail` is only shown on `blocked` and `exposed`: where the
 * spontaneous reading is wrong. On `protected`, the state speaks for
 * itself — the header chip is enough, one more banner would say nothing new.
 */
export type Posture = 'protected' | 'blocked' | 'exposed'

export interface PostureMeta {
  posture: Posture
  label: string
  detail: string
  color: string
  accent: string
}

const BLOCKED = '#2F5D8A'
const BLOCKED_VIVID = '#3B82F6'
const EXPOSED = '#A8501B'
const EXPOSED_VIVID = '#F97316'

export function postureMeta(state: TunnelState, adapterUp: boolean): PostureMeta {
  if (!adapterUp) {
    return {
      posture: 'exposed',
      label: 'Exposé',
      detail: 'Trafic hors tunnel.',
      color: EXPOSED,
      accent: EXPOSED_VIVID,
    }
  }
  if (state === 'up') {
    return {
      posture: 'protected',
      label: 'Protégé',
      // "Tout" would be a word too many: DNS queries leave outside the
      // tunnel, a documented limit the posture panel states in full.
      detail: 'Trafic routé par la gateway.',
      color: UP,
      accent: UP_VIVID,
    }
  }
  return {
    posture: 'blocked',
    label: 'Trafic bloqué',
    detail: 'Tunnel inactif. Reconnectez-vous ou déconnectez.',
    color: BLOCKED,
    accent: BLOCKED_VIVID,
  }
}

/**
 * Nature of the `PresharedKey` slot's protection, as it should be displayed.
 *
 * **A PSK is not a PQC PSK**, and the UI must not confuse them: the first is
 * a secret copied by hand, shared out of band, that never rotates and whose
 * presence *disables* ML-KEM negotiation; the second is derived from an
 * ML-KEM-1024 exchange replayed on every connection. Both hold up against
 * "harvest now, decrypt later" — calling the first one "post-quantum" wasn't
 * wrong, it was imprecise, and the imprecision hid that no rotation happens.
 *
 * **The profile alone isn't enough to decide**, in both directions: the PQC
 * PSK is never written there (a perfectly established PQC tunnel shows
 * `preshared_key: null`), and a filled-in `preshared_key` always denotes a
 * static PSK. It's the core's `protection` event that is authoritative; the
 * profile only serves to announce what's *expected* while the connection
 * hasn't decided yet.
 *
 * What the profile *does* say, when it carries a `key_negotiation` block, is
 * the mode about to be requested. Helios never substitutes another one, so
 * that mode is a sound announcement — but it is still an announcement, and
 * it is displayed as pending until the event confirms it.
 */
export type ProtectionTone = 'pqc' | 'static' | 'classic' | 'pending'

export interface ProtectionMeta {
  tone: ProtectionTone
  /** Short chip label. */
  label: string
  /** Tooltip sentence: what it protects, and at what cost. */
  detail: string
}

/**
 * # Une ligne, pas un paragraphe
 *
 * Ces textes tenaient en quatre lignes chacun et expliquaient le « récolter
 * maintenant, déchiffrer plus tard ». Une infobulle n'est pas l'endroit où
 * l'on apprend la cryptographie post-quantique : elle nomme ce qui protège le
 * tunnel à cet instant. Le raisonnement, lui, vit dans les ADR.
 *
 * Le seul écart conservé est celui qui change une propriété de sécurité :
 * négocié **avant** le premier handshake ou obtenu **après** le montage. Le
 * reste est du commentaire.
 */
const PQC_DETAIL = 'PSK renouvelé à chaque connexion.'

const PQC_NEGOTIATED_DETAIL = 'PSK négocié avant le premier handshake, renouvelé à chaque connexion.'

const PQC_UPGRADED_DETAIL = 'PSK obtenu après le montage : le premier handshake a eu lieu sans lui.'

const STATIC_DETAIL = 'PSK fixe du profil, transmis hors bande. Il n’est jamais renouvelé.'

const CLASSIC_DETAIL = 'Aucun PSK : Curve25519 seul.'

export function protectionMeta(
  profile: ClientProfile | null,
  observed: PskKind | null,
  // Kept in the signature though the pending label no longer varies with it:
  // callers pass the tunnel state, and removing it would churn every call site
  // for a parameter the next wording change is likely to want back.
  _state?: TunnelState,
): ProtectionMeta {
  if (observed === 'ml_kem') {
    return profile?.key_negotiation
      ? { tone: 'pqc', label: 'ML-KEM', detail: PQC_NEGOTIATED_DETAIL }
      : { tone: 'pqc', label: 'ML-KEM après tunnel', detail: PQC_UPGRADED_DETAIL }
  }
  if (observed === 'static') return { tone: 'static', label: 'PSK', detail: STATIC_DETAIL }
  if (observed === 'none') return { tone: 'classic', label: 'Classique', detail: CLASSIC_DETAIL }

  // Nothing observed: we announce the wait, never the acquired state. A
  // profile that *can* obtain an ML-KEM key doesn't have it yet. The ellipsis
  // carries that on its own — spelling out "à la connexion" made the chip
  // longer than the fact it states.
  const pending = (label: string, detail: string): ProtectionMeta => ({
    tone: 'pending',
    label: `${label}…`,
    detail,
  })

  // The negotiated mode is authoritative over every other clue: it is what
  // the client is about to ask for, and the gateway substitutes nothing.
  const negotiated = profile?.key_negotiation
  if (negotiated) {
    if (negotiated.mode === 'ml_kem') return pending('ML-KEM', PQC_DETAIL)
    if (negotiated.mode === 'static_psk') {
      return { tone: 'static', label: 'PSK', detail: STATIC_DETAIL }
    }
    return { tone: 'classic', label: 'Classique', detail: CLASSIC_DETAIL }
  }

  // The presence flag, not the value: the profile no longer carries either
  // secret across the IPC (ADR-006 §5). Presence is all this ever needed.
  if (profile?.has_static_psk) {
    return { tone: 'static', label: 'PSK', detail: STATIC_DETAIL }
  }

  if (profile?.heliosd_url?.trim()) return pending('ML-KEM', PQC_DETAIL)

  return { tone: 'classic', label: 'Classique', detail: CLASSIC_DETAIL }
}

/**
 * The negotiable modes, from weakest to strongest.
 *
 * The order isn't decorative: it's the one the gateway enforces
 * (`static_psk < ml_kem`), and the screen derives from it what a profile may
 * still choose.
 *
 * There is no `classic` here, and it is not an omission of the screen: a
 * plain WireGuard profile is the **absence** of the negotiation block, and the
 * way to reach it is to remove one.
 */
export const PROTECTION_MODES: ProtectionMode[] = ['static_psk', 'ml_kem']

export interface ModeMeta {
  /** Chip label. Only a label: what a mode does is not a caption. */
  label: string
}

const MODE_META: Record<ProtectionMode, ModeMeta> = {
  static_psk: { label: 'PSK' },
  ml_kem: { label: 'ML-KEM' },
}

export function modeMeta(mode: ProtectionMode): ModeMeta {
  return MODE_META[mode]
}

/** Rank in the monotonic order. Higher = stronger. */
export function modeLevel(mode: ProtectionMode): number {
  const level = PROTECTION_MODES.indexOf(mode)
  return level < 0 ? 0 : level
}

/**
 * Can this mode still be selected under that floor?
 *
 * The client refuses a mode below its own floor **before** touching the
 * network, exactly as the gateway does. The screen therefore doesn't offer
 * what would be refused a second later.
 */
export function modeAllowed(mode: ProtectionMode, floor: ProtectionMode): boolean {
  return modeLevel(mode) >= modeLevel(floor)
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
