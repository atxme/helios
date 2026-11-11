import type { RotationsOverview } from '../../types'
import {
  EXPIRING_SOON_SECS,
  OVERLAP_PQ,
  effectiveNow,
  formatDate,
  formatDateTime,
  reachLabel,
  valueOf,
} from './rotationRows'

export type GatewayAction = 'renew' | 'abort' | 'rollback' | 'revoke' | 'resume' | 'discard'

export interface GatewayRow {
  state: string
  /** The identity is to renew now: its expiry is near, or a publication waits. */
  due: boolean
  actions: GatewayAction[]
  /** The sentence that says the daemon must restart; `null` when none is due. */
  restart: string | null
  /** The motif heliosd gave for the restart, raw: a technical detail, never the main text. */
  restartMotif: string | null
  /** Why renew is listed but disabled; `null` when it can be started. */
  renewReason: string | null
  /** A second line of fact, such as a rollback in force or what a stop leaves untouched. */
  detail: string | null
}

/** The button labels of the block, one per action. */
export const GATEWAY_LABELS: Record<GatewayAction, string> = {
  renew: "Renouveler l'identité de la gateway",
  abort: 'Annuler',
  rollback: "Revenir à l'ancienne identité",
  revoke: 'Révoquer la gateway',
  resume: 'Reprendre',
  discard: 'Jeter la décision en attente',
}

export const RESTART_SENTENCE = 'Redémarrer heliosd sur la gateway.'

/** What a waiting revocation leaves untouched: the replacement is in, the revocation is not signed. */
export const REVOCATION_TO_SIGN =
  "Le remplaçant est déposé ; la révocation reste à signer. Rien n'a été révoqué."

/**
 * The gateway's identity row: where it stands on the gateway's clock, and what the operator
 * may do from there. A waiting record (`gatewayPending`) takes the state and the first action.
 */
export function gatewayRow(o: RotationsOverview, local: number): GatewayRow {
  const now = effectiveNow(o, local)
  const domain = valueOf(o.domain)
  const waiting = o.gatewayPending
  const restart = domain?.gateway_restart_due ? RESTART_SENTENCE : null
  const restartMotif = domain?.gateway_restart_due ?? null

  if (waiting?.kind === 'revocation') {
    const toSign = waiting.revocation_to_sign
    return {
      state: toSign
        ? 'Révocation à signer'
        : waiting.revocation_applied
          ? 'Révocation appliquée, reprise à faire'
          : 'Révocation à reprendre',
      due: true,
      actions: toSign ? ['revoke', 'discard'] : ['resume', 'discard'],
      restart,
      restartMotif,
      renewReason: null,
      detail: toSign ? REVOCATION_TO_SIGN : null,
    }
  }

  const detail: string[] = []
  let renewReason: string | null = null
  let state: string
  let due = false
  let actions: GatewayAction[] = []

  if (!domain) {
    state = reachLabel(o.domain) ?? 'Identité non lue'
  } else {
    const activation = domain.gateway_activation_at
    const retire = domain.gateway_retire_active_at
    const published = domain.gateway_transition_published || waiting?.published === true
    // Past the activation an abort is refused by the gateway, and once published none is accepted.
    const abortable = activation === null || now < activation

    if (domain.gateway_rollback_expires_at !== null) {
      detail.push(`Retour arrière jusqu'au ${formatDateTime(domain.gateway_rollback_expires_at)}`)
    }

    if (waiting?.kind === 'decision' && waiting.decision_kind === 'abort') {
      // The cancellation is only to be carried on: a new abort of it is never offered.
      state = 'Annulation à reprendre'
      due = true
    } else if (waiting?.kind === 'decision' && !waiting.installed) {
      state = 'Décision à reprendre'
      due = true
    } else if (
      (waiting?.kind === 'decision' && !waiting.published) ||
      (!waiting && domain.gateway_transition_pending && !published)
    ) {
      state = 'Installée, publication à faire'
      due = true
      if (abortable) actions = ['abort']
    } else if (published && activation !== null && now < activation) {
      state = `Bascule le ${formatDate(activation)}`
      actions = ['revoke']
    } else if (activation !== null && retire !== null && now >= activation && now < retire) {
      state = `Recouvrement jusqu'au ${formatDate(retire)}`
      actions = ['rollback', 'revoke']
    } else {
      const expiries = [domain.gateway_tls_not_after, domain.gateway_pq_not_after].filter(
        (at): at is number => at !== null,
      )
      if (expiries.length === 0) {
        state = 'Échéance inconnue'
      } else {
        const nearest = Math.min(...expiries)
        due = nearest - now < EXPIRING_SOON_SECS
        state = due ? 'À faire' : `Échéance le ${formatDate(nearest)}`
      }
      actions = ['renew', 'revoke']
      // Renewing waits for a CA-PQ overlap to end: every approval under it is refused.
      if (o.caPqOverlap === true) renewReason = OVERLAP_PQ
    }
  }

  // A waiting decision is led by its resumption, and a record can always be discarded.
  if (waiting?.kind === 'decision') {
    actions = ['resume', ...actions.filter((action) => action !== 'resume')]
  }
  if (waiting) actions = [...actions, 'discard']

  return {
    state,
    due,
    actions,
    restart,
    restartMotif,
    renewReason,
    detail: detail.length > 0 ? detail.join(' · ') : null,
  }
}
