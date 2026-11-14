import type {
  CampaignScope,
  OperatorOpened,
  OperatorPendingOperation,
  RotationsOverview,
} from '../../types'
import { gatewayRow } from './gatewayRows'
import {
  effectiveNow,
  formatDateTime,
  prerequisites,
  rotationRows,
  valueOf,
  type RotationAction,
} from './rotationRows'

export type ChainAction = 'start' | 'resume_step' | 'continue' | 'reopen' | 'finish' | 'abandon'

export interface ChainRowInput {
  overview: RotationsOverview
  /** The operator's clock; the gateway's answers its own, when it gave one. */
  now: number
  /** The campaign of the step the chain holds, if Orion holds one (`operatorChainHeld`). */
  held: OperatorOpened | null
  /** The operation_id whose fleet ceremony ended `done` in this session, if any. */
  fleetApprovedThisSession: string | null
}

export interface ChainRow {
  title: 'Tout renouveler'
  state: string
  detail: string | null
  actions: ChainAction[]
  /** Why « Commencer » is off; set for `start` only. */
  disabledReason: string | null
}

/** The four steps, in the order the chain runs them. */
const PLAN_STEPS: CampaignScope[] = [
  'issuer_delegation',
  'trust_authorities',
  'gateway_identity',
  'fleet_leafs',
]

export const STEP_NAMES: Record<string, string> = {
  issuer_delegation: "Délégation de l'émetteur",
  trust_authorities: 'CA TLS cliente',
  gateway_identity: 'Identité de la gateway',
  fleet_leafs: 'Postes',
}

/** The rotation row whose reasons a step reuses, for the steps that have one. */
const ROTATION_OF_STEP: Partial<Record<CampaignScope, RotationAction>> = {
  issuer_delegation: 'renew_delegation',
  trust_authorities: 'replace_ca_tls',
  fleet_leafs: 'renew_fleet',
}

const NO_PLAN =
  "Quatre étapes, une cérémonie chacune : délégation de l'émetteur, CA TLS cliente, identité de la gateway, postes. CA-PQ n'en fait pas partie. Chaque cérémonie demande ses clés."

const FLEET_UNKNOWN =
  "Orion ne peut pas savoir si les postes ont été autorisés : rouvrir l'étape si la cérémonie n'a pas abouti."

const UNREAD_DETAIL =
  "Les opérations d'Astra ne sont pas lues : relire avant de continuer."

const lostDetail = (expiresAt: number) =>
  `Campagne de l'étape perdue par Orion : rouvrir l'étape après ${formatDateTime(expiresAt)}.`

/** The pending operations whose expiry is still ahead on the gateway's clock. */
function livePending(o: RotationsOverview, now: number): OperatorPendingOperation[] {
  const at = effectiveNow(o, now)
  return (valueOf(o.pending) ?? []).filter((operation) => operation.expires_at > at)
}

/**
 * Why a step cannot be started now, or `null`. The reasons are the rotation rows' and the
 * gateway row's own; a live operation of the step's scope is the last to be checked.
 */
export function stepBlocker(o: RotationsOverview, scope: CampaignScope, now: number): string | null {
  if (scope === 'gateway_identity') {
    const row = gatewayRow(o, now)
    if (!row.actions.includes('renew') || row.renewReason !== null) {
      return row.renewReason ?? row.state
    }
  } else {
    const action = ROTATION_OF_STEP[scope]
    if (action) {
      const row = rotationRows(o, now).find((candidate) => candidate.action === action)
      if (row?.disabledReason) return row.disabledReason
      const failing = prerequisites(o, action).find((line) => !line.ok)
      if (failing) return failing.label
    }
  }
  const live = livePending(o, now).some((operation) => operation.scope === scope)
  return live ? `Une opération ${STEP_NAMES[scope]} est déjà ouverte` : null
}

const chainRowOf = (
  state: string,
  actions: ChainAction[],
  detail: string | null = null,
  disabledReason: string | null = null,
): ChainRow => ({ title: 'Tout renouveler', state, detail, actions, disabledReason })

/** The row of « Tout renouveler »: the plan Astra holds, or the offer to start one. */
export function chainRow({
  overview: o,
  now,
  held,
  fleetApprovedThisSession,
}: ChainRowInput): ChainRow {
  const chain = valueOf(o.authority)?.chain ?? null
  if (!chain || chain.steps.length === 0 || chain.current >= chain.steps.length) {
    const blocked = PLAN_STEPS.map((scope) => stepBlocker(o, scope, now)).find(
      (reason) => reason !== null,
    )
    return chainRowOf(NO_PLAN, ['start'], null, blocked ?? null)
  }

  const scope = chain.steps[chain.current]
  const head = `Étape ${chain.current + 1} sur ${chain.steps.length} : ${STEP_NAMES[scope] ?? scope}`
  // Without the operations there is no telling open from closed: finishing a fleet step then
  // could close the plan over a campaign that is still open and unapproved.
  if (o.pending.state !== 'ok') return chainRowOf(`${head} · opérations non lues`, ['abandon'], UNREAD_DETAIL)
  const live =
    chain.operation_id === null
      ? undefined
      : livePending(o, now).find((operation) => operation.operation_id === chain.operation_id)

  if (live) {
    const state = `${head} · opération ouverte jusqu’au ${formatDateTime(live.expires_at)}`
    // The delegation's and the gateway's requests are held by Orion alone, never on the page.
    const needsHeld = scope === 'issuer_delegation' || scope === 'gateway_identity'
    const heldHere = held !== null && held.operation_id === live.operation_id
    if (needsHeld && !heldHere) return chainRowOf(state, ['abandon'], lostDetail(live.expires_at))
    return chainRowOf(state, ['resume_step', 'abandon'])
  }

  const state = `${head} · campagne close`
  if (scope !== 'fleet_leafs') return chainRowOf(state, ['continue', 'reopen', 'abandon'])
  // Only this session's own success proves the fleet approval went through.
  if (chain.operation_id !== null && fleetApprovedThisSession === chain.operation_id) {
    return chainRowOf(state, ['continue', 'abandon'])
  }
  return chainRowOf(state, ['reopen', 'finish', 'abandon'], FLEET_UNKNOWN)
}
