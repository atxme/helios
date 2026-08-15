import { Shield, ShieldAlert, ShieldCheck, ShieldOff, Wifi } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { TunnelState } from './types'

/**
 * What a tunnel state means, in one place.
 *
 * This module owns a **security** fact, not an aesthetic one: whether traffic
 * is allowed to leave, and what the kill-switch is doing about it. It lives
 * outside `theme.ts` for the same reason Orion's `components/state.ts` does —
 * a redesign must be free to repaint the interface without ever repainting the
 * meaning of "up".
 *
 * Before this existed the answer was written three times (dashboard, tunnel
 * controls, firewall view) and the three copies had already drifted: the
 * dashboard called `connecting` "en attente de pair" while the controls called
 * it "trafic bloqué". Both were true, neither was complete.
 *
 * `tone` names an entry of `palette.state`, and every path below resolves at
 * render time through the current color scheme.
 */
export interface StateSemantics {
  /** Palette key — see the `StatePalette` augmentation in `theme.ts`. */
  tone: 'up' | 'connecting' | 'down' | 'failed' | 'captivePortal'
  Icon: LucideIcon
  /** Headline: what the gateway is doing. */
  label: string
  /** The sentence under it: why, and what it implies for traffic. */
  detail: string
  /**
   * Whether the kill-switch is holding traffic. Only `up` releases it — the
   * gateway invariant, and the reason this is a lookup and not a comparison
   * scattered across views.
   */
  killSwitchEngaged: boolean
  /** How the kill-switch reads in that state, in the controls' footer. */
  trafficLabel: string
}

export const TUNNEL_STATE: Record<TunnelState, StateSemantics> = {
  up: {
    tone: 'up',
    Icon: ShieldCheck,
    label: 'Handshake actif',
    detail: 'Au moins un pair WireGuard a handshaké il y a moins de 150 s.',
    killSwitchEngaged: false,
    trafficLabel: 'Trafic autorisé',
  },
  connecting: {
    tone: 'connecting',
    Icon: Shield,
    label: 'En attente de pair',
    detail: 'Interface montée, kill-switch engagé jusqu’au prochain handshake.',
    killSwitchEngaged: true,
    trafficLabel: 'Trafic bloqué',
  },
  down: {
    tone: 'down',
    Icon: ShieldOff,
    label: 'Hors ligne',
    detail: 'Interface arrêtée, kill-switch engagé.',
    killSwitchEngaged: true,
    trafficLabel: 'Trafic bloqué',
  },
  failed: {
    tone: 'failed',
    Icon: ShieldAlert,
    label: 'Échec',
    detail: 'Le trafic reste bloqué en mode fail-closed.',
    killSwitchEngaged: true,
    trafficLabel: 'Trafic bloqué',
  },
  captive_portal: {
    tone: 'captivePortal',
    Icon: Wifi,
    label: 'Portail captif',
    detail: 'Accès limité à la passerelle du portail.',
    killSwitchEngaged: true,
    trafficLabel: 'Accès portail seul',
  },
}

/** The three `sx` color paths of a tone, ready to spread into a component. */
export function toneColors(tone: StateSemantics['tone']) {
  return {
    main: `state.${tone}.main`,
    container: `state.${tone}.container`,
    onContainer: `state.${tone}.onContainer`,
  }
}
