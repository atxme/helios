import { describe, expect, it } from 'vitest'

import type { OperatorOpened, OperatorPendingOperation, RotationsOverview } from '../../types'
import { chainRow, stepBlocker, type ChainRowInput } from './chainRow'
import { DAY, NOW, authorityRead, domainRead, overview } from './rotationFixtures'
import { OVERLAP_PQ, formatDateTime, prerequisites } from './rotationRows'

const STEPS = ['issuer_delegation', 'trust_authorities', 'gateway_identity', 'fleet_leafs'] as const

const plan = (current: number, operation_id: string | null) => ({
  steps: [...STEPS],
  current,
  operation_id,
})

/** The overview with the chain Astra holds, and the rest of the screen as the fixtures give it. */
const chained = (
  chain: ReturnType<typeof plan> | null,
  extra: Partial<RotationsOverview> = {},
): RotationsOverview =>
  overview({ authority: { state: 'ok', value: authorityRead({ chain }) }, ...extra })

const operation = (extra: Partial<OperatorPendingOperation> = {}): OperatorPendingOperation => ({
  operation_id: 'op-1',
  scope: 'trust_authorities',
  reason: 'Rotation',
  requested_by: 'Opérateur',
  target_count: 1,
  required_credentials: 1,
  campaign_fingerprint: 'cc'.repeat(32),
  created_at: NOW - 60,
  expires_at: NOW + DAY,
  ...extra,
})

const pendingWith = (...operations: OperatorPendingOperation[]) => ({
  state: 'ok' as const,
  value: operations,
})

const opened = (extra: Partial<OperatorOpened> = {}): OperatorOpened => ({
  operation_id: 'op-1',
  campaign_id: 'campaign-1',
  campaign_fingerprint: 'cc'.repeat(32),
  scope: 'issuer_delegation',
  target_count: 1,
  required_credentials: 1,
  expires_at: NOW + DAY,
  ...extra,
})

const input = (o: RotationsOverview, extra: Partial<ChainRowInput> = {}): ChainRowInput => ({
  overview: o,
  now: NOW,
  held: null,
  fleetApprovedThisSession: null,
  ...extra,
})

describe('the « Tout renouveler » row', () => {
  it('no_plan_offers_start', () => {
    const row = chainRow(input(overview()))
    expect(row.title).toBe('Tout renouveler')
    expect(row.state).toBe(
      "Quatre étapes, une cérémonie chacune : délégation de l'émetteur, CA TLS cliente, identité de la gateway, postes. CA-PQ n'en fait pas partie. Chaque cérémonie demande ses clés.",
    )
    expect(row.actions).toEqual(['start'])
    expect(row.disabledReason).toBeNull()
    expect(row.detail).toBeNull()
  })

  it('start_is_blocked_by_the_first_blocked_step', () => {
    // The delegation is blocked (the vault is ahead of the gateway), and so is the gateway.
    const o = overview({
      localCaEpoch: 4,
      domain: { state: 'ok', value: domainRead({ gateway_revoked: true }) },
    })
    const row = chainRow(input(o))
    expect(row.actions).toEqual(['start'])
    expect(row.disabledReason).toBe('Le coffre a une époque d’avance')
  })

  it('start_is_blocked_by_a_live_operation_of_a_chain_family', () => {
    const o = overview({ pending: pendingWith(operation({ scope: 'trust_authorities' })) })
    const row = chainRow(input(o))
    expect(row.actions).toEqual(['start'])
    expect(row.disabledReason).toBe('Une opération CA TLS cliente est déjà ouverte')
  })

  it('open_step_offers_resume', () => {
    const o = chained(plan(1, 'op-1'), { pending: pendingWith(operation()) })
    const row = chainRow(input(o))
    expect(row.state).toBe(
      `Étape 2 sur 4 : CA TLS cliente · opération ouverte jusqu’au ${formatDateTime(NOW + DAY)}`,
    )
    expect(row.actions).toEqual(['resume_step', 'abandon'])
    expect(row.detail).toBeNull()
  })

  it('delegation_without_held_request_says_lost', () => {
    const o = chained(plan(0, 'op-1'), {
      pending: pendingWith(operation({ scope: 'issuer_delegation' })),
    })
    const lost = chainRow(input(o))
    expect(lost.actions).toEqual(['abandon'])
    expect(lost.detail).toBe(
      `Campagne de l'étape perdue par Orion : rouvrir l'étape après ${formatDateTime(NOW + DAY)}.`,
    )
    // With the request Orion holds for the same operation, the step resumes.
    const held = chainRow(input(o, { held: opened({ operation_id: 'op-1' }) }))
    expect(held.actions).toEqual(['resume_step', 'abandon'])
  })

  it('gateway_without_held_step_says_lost', () => {
    const o = chained(plan(2, 'op-1'), {
      pending: pendingWith(operation({ scope: 'gateway_identity' })),
    })
    const row = chainRow(input(o))
    expect(row.actions).toEqual(['abandon'])
    expect(row.detail).toBe(
      `Campagne de l'étape perdue par Orion : rouvrir l'étape après ${formatDateTime(NOW + DAY)}.`,
    )
  })

  it('closed_step_offers_continue_and_reopen', () => {
    const row = chainRow(input(chained(plan(1, 'op-1'))))
    expect(row.state).toBe('Étape 2 sur 4 : CA TLS cliente · campagne close')
    expect(row.actions).toEqual(['continue', 'reopen', 'abandon'])
    expect(row.detail).toBeNull()
  })

  it('closed_fleet_step_without_session_success_offers_reopen_and_finish', () => {
    const row = chainRow(input(chained(plan(3, 'op-1'))))
    expect(row.actions).toEqual(['reopen', 'finish', 'abandon'])
    expect(row.detail).toBe(
      "Orion ne peut pas savoir si les postes ont été autorisés : rouvrir l'étape si la cérémonie n'a pas abouti.",
    )
  })

  it('closed_fleet_step_after_session_success_offers_continue', () => {
    const row = chainRow(input(chained(plan(3, 'op-1')), { fleetApprovedThisSession: 'op-1' }))
    expect(row.actions).toEqual(['continue', 'abandon'])
    expect(row.detail).toBeNull()
  })

  it('expiry_reads_the_gateway_clock', () => {
    const short = pendingWith(operation({ expires_at: NOW + 60 }))
    // The operator's clock is an hour ahead of the gateway's: the campaign is still open there.
    const alive = chainRow({
      overview: chained(plan(1, 'op-1'), { pending: short }),
      now: NOW + 3600,
      held: null,
      fleetApprovedThisSession: null,
    })
    expect(alive.actions).toEqual(['resume_step', 'abandon'])
    // The gateway's clock is an hour past the expiry, whatever the operator's clock says.
    const expired = chainRow({
      overview: chained(plan(1, 'op-1'), {
        pending: short,
        domain: { state: 'ok', value: domainRead({ now_unix: NOW + 3600 }) },
      }),
      now: NOW,
      held: null,
      fleetApprovedThisSession: null,
    })
    expect(expired.actions).toEqual(['continue', 'reopen', 'abandon'])
  })

  it('unread_pending_offers_only_abandon', () => {
    const o = chained(plan(3, 'op-1'), { pending: { state: 'unreachable' } })
    const row = chainRow(input(o, { fleetApprovedThisSession: 'op-1' }))
    expect(row.state).toBe('Étape 4 sur 4 : Postes · opérations non lues')
    expect(row.actions).toEqual(['abandon'])
    expect(row.detail).toBe(
      "Les opérations d'Astra ne sont pas lues : relire avant de continuer.",
    )
  })
})

describe('stepBlocker, the gateway branch', () => {
  it('gateway_step_blocked_when_renew_is_not_offered', () => {
    const o = overview({ domain: { state: 'ok', value: domainRead({ gateway_revoked: true }) } })
    expect(stepBlocker(o, 'gateway_identity', NOW)).toBe('Révoquée')
  })

  it('gateway_step_blocked_by_renew_reason', () => {
    const o = overview({ caPqOverlap: true })
    expect(stepBlocker(o, 'gateway_identity', NOW)).toBe(OVERLAP_PQ)
  })

  it('gateway_step_blocked_by_the_prerequisites_its_block_requires', () => {
    const o = overview({ vault: null })
    expect(stepBlocker(o, 'gateway_identity', NOW)).toBe(
      prerequisites(o, 'renew_fleet').find((line) => !line.ok)?.label,
    )
    expect(stepBlocker(o, 'gateway_identity', NOW)).not.toBeNull()
  })
})
