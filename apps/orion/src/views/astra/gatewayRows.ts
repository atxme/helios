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

export type GatewayAction = 'renew' | 'abort' | 'rollback' | 'revoke' | 'resume' | 'discard' | 'force_discard'

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
  /**
   * Why a revocation « avec remplaçant » cannot start; `null` when it can. heliosd prepares no
   * replacement while a transition is staged or overlapping.
   */
  replacementReason: string | null
  /** Which confirmation a forced discard asks for: a dead end with a replacement, or a refused publication. */
  forceKind: 'replacement' | 'publication' | null
}

/** The button labels of the block, one per action. */
export const GATEWAY_LABELS: Record<GatewayAction, string> = {
  renew: "Renouveler l'identité de la gateway",
  abort: 'Annuler',
  rollback: "Revenir à l'ancienne identité",
  revoke: 'Révoquer la gateway',
  resume: 'Reprendre',
  discard: 'Jeter la décision en attente',
  force_discard: 'Abandonner la décision',
}

/** Why a replacement waits for the end of a transition: heliosd prepares none while one is staged. */
export const REPLACEMENT_IN_TRANSITION =
  "Une transition est en cours : le remplaçant n'est possible qu'après sa fin."

export const RESTART_SENTENCE = 'Redémarrer heliosd sur la gateway.'

/** What a waiting revocation leaves untouched: the replacement is in, the revocation is not signed. */
export const REVOCATION_TO_SIGN =
  "Le remplaçant est déposé ; la révocation reste à signer. Rien n'a été révoqué."

/** What a revoked gateway that awaits a replacement not on this poste says. */
const REPLACEMENT_NOT_HERE = "Le remplaçant nommé par la révocation n'est pas sur ce poste."

/** What a revoked gateway with no replacement to come says: it is a dead end. */
const REVOKED_FOR_GOOD = 'La gateway ne sert plus. Le domaine doit être reconstruit.'

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

  // A revoked gateway takes no renewal, rollback or revocation: only the record's way out.
  // A signed revocation not yet applied is the exception: its answer may have been lost, and
  // « Reprendre » settles it through the probe, so it keeps the 6b state below. A revocation
  // still to sign is not: the gateway's own view decides what the replacement awaits.
  const unappliedSignedRevocation =
    waiting?.kind === 'revocation' && !waiting.revocation_applied && !waiting.revocation_to_sign
  if (domain?.gateway_revoked && !unappliedSignedRevocation) {
    const awaited = domain.gateway_awaited_replacement
    const base = { due: true, restart, restartMotif, renewReason: null, replacementReason: null }
    if (awaited !== null && waiting?.replacement_fingerprint === awaited) {
      return {
        ...base,
        state: 'Révoquée, remplaçant à installer',
        actions: ['resume'],
        detail: null,
        forceKind: null,
      }
    }
    return {
      ...base,
      state: awaited !== null ? 'Révoquée, remplaçant attendu' : 'Révoquée',
      actions: waiting ? ['force_discard'] : [],
      detail: awaited !== null ? REPLACEMENT_NOT_HERE : REVOKED_FOR_GOOD,
      forceKind: 'replacement',
    }
  }

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
      replacementReason: null,
      forceKind: null,
    }
  }

  const detail: string[] = []
  let renewReason: string | null = null
  let state: string
  let due = false
  let actions: GatewayAction[] = []
  let replacementReason: string | null = null
  let forceKind: GatewayRow['forceKind'] = null
  // A renewal installed, never published, and refused by Astra: led by the cancellation, then by the force.
  let refused = false

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
      refused =
        waiting?.kind === 'decision' &&
        waiting.decision_kind === 'renewal' &&
        waiting.installed &&
        waiting.publication_refused
      // Once activated, heliosd refuses the staged transition: a forced discard of the record
      // leaves it on the gateway, and a revocation without replacement is what clears it.
      if (!waiting && !abortable) {
        actions = ['revoke']
        replacementReason = REPLACEMENT_IN_TRANSITION
      }
      if (refused) {
        if (abortable) {
          if (activation !== null) {
            detail.push(`La publication est refusée : annuler la transition avant le ${formatDateTime(activation)}.`)
          }
          actions = ['abort', 'resume']
        } else {
          actions = ['force_discard', 'resume']
          forceKind = 'publication'
        }
      } else if (abortable) {
        actions = ['abort']
      }
    } else if (published && activation !== null && now < activation) {
      state = `Bascule le ${formatDate(activation)}`
      actions = ['revoke']
      replacementReason = REPLACEMENT_IN_TRANSITION
    } else if (activation !== null && retire !== null && now >= activation && now < retire) {
      state = `Recouvrement jusqu'au ${formatDate(retire)}`
      actions = ['rollback', 'revoke']
      replacementReason = REPLACEMENT_IN_TRANSITION
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
  // A refused publication sets its own actions: its discard is the forced one.
  if (!refused) {
    if (waiting?.kind === 'decision') {
      actions = ['resume', ...actions.filter((action) => action !== 'resume')]
    }
    if (waiting) actions = [...actions, 'discard']
  }

  return {
    state,
    due,
    actions,
    restart,
    restartMotif,
    renewReason,
    detail: detail.length > 0 ? detail.join(' · ') : null,
    replacementReason,
    forceKind,
  }
}
