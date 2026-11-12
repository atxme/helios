import { describe, expect, it } from 'vitest'

import type { GatewayPendingView, RotationsOverview } from '../../types'
import { gatewayRow } from './gatewayRows'
import { DAY, NOW, domainRead, overview } from './rotationFixtures'
import { OVERLAP_PQ, formatDate, formatDateTime } from './rotationRows'

const pending = (extra: Partial<GatewayPendingView> = {}): GatewayPendingView => ({
  kind: 'decision',
  installed: false,
  published: false,
  revocation_applied: false,
  decision_kind: 'renewal',
  revocation_to_sign: false,
  publication_refused: false,
  replacement_fingerprint: null,
  ...extra,
})

const withGateway = (
  domain: Partial<ReturnType<typeof domainRead>> = {},
  extra: Partial<RotationsOverview> = {},
) => overview({ domain: { state: 'ok', value: domainRead(domain) }, ...extra })

describe('gatewayRow', () => {
  it('nothing_in_flight_reads_the_due_date_far_from_expiry', () => {
    const row = gatewayRow(withGateway(), NOW)
    expect(row.state).toBe(`Échéance le ${formatDate(NOW + 200 * DAY)}`)
    expect(row.due).toBe(false)
    expect(row.actions).toEqual(['renew', 'revoke'])
    expect(row.restart).toBeNull()
    expect(row.detail).toBeNull()
  })

  it('nothing_in_flight_is_due_within_thirty_days_of_expiry', () => {
    const soon = NOW + 10 * DAY
    const row = gatewayRow(
      withGateway({ gateway_pq_not_after: soon, gateway_tls_not_after: NOW + 200 * DAY }),
      NOW,
    )
    expect(row.state).toBe('À faire')
    expect(row.due).toBe(true)
    expect(row.actions).toEqual(['renew', 'revoke'])
  })

  it('installed_unpublished_reads_publication_due', () => {
    const row = gatewayRow(
      withGateway(
        { gateway_transition_pending: true, gateway_activation_at: NOW + 7 * DAY },
        { gatewayPending: pending({ installed: true, published: false }) },
      ),
      NOW,
    )
    expect(row.state).toBe('Installée, publication à faire')
    expect(row.due).toBe(true)
    expect(row.actions[0]).toBe('resume')
    expect(row.actions).toContain('abort')
  })

  it('no_abort_button_once_published_or_activated', () => {
    const published = gatewayRow(
      withGateway(
        { gateway_transition_pending: true, gateway_transition_published: true, gateway_activation_at: NOW + 7 * DAY },
        { gatewayPending: pending({ installed: true, published: true }) },
      ),
      NOW,
    )
    expect(published.actions).not.toContain('abort')

    const activated = gatewayRow(
      withGateway(
        { gateway_transition_pending: true, gateway_activation_at: NOW - DAY, gateway_retire_active_at: NOW + 7 * DAY },
        { gatewayPending: pending({ installed: true, published: false }) },
      ),
      NOW,
    )
    expect(activated.actions).not.toContain('abort')
  })

  it('published_before_activation_reads_the_switch_and_offers_revoke_only', () => {
    const row = gatewayRow(
      withGateway({
        gateway_transition_pending: true,
        gateway_transition_published: true,
        gateway_activation_at: NOW + 7 * DAY,
      }),
      NOW,
    )
    expect(row.state).toBe(`Bascule le ${formatDate(NOW + 7 * DAY)}`)
    expect(row.actions).toEqual(['revoke'])
  })

  it('a_staged_or_overlapping_transition_forbids_the_replacement_with_its_reason', () => {
    const sentence = "Une transition est en cours : le remplaçant n'est possible qu'après sa fin."
    const switching = gatewayRow(
      withGateway({
        gateway_transition_pending: true,
        gateway_transition_published: true,
        gateway_activation_at: NOW + 7 * DAY,
      }),
      NOW,
    )
    const overlapping = gatewayRow(
      withGateway({
        gateway_transition_pending: true,
        gateway_transition_published: true,
        gateway_activation_at: NOW - DAY,
        gateway_retire_active_at: NOW + 6 * DAY,
      }),
      NOW,
    )
    expect(switching.replacementReason).toBe(sentence)
    expect(overlapping.replacementReason).toBe(sentence)
    expect(gatewayRow(withGateway({}), NOW).replacementReason).toBeNull()
  })

  it('overlap_reads_the_retirement_date_and_offers_rollback', () => {
    const row = gatewayRow(
      withGateway({
        gateway_transition_pending: true,
        gateway_transition_published: true,
        gateway_activation_at: NOW - DAY,
        gateway_retire_active_at: NOW + 6 * DAY,
      }),
      NOW,
    )
    expect(row.state).toBe(`Recouvrement jusqu'au ${formatDate(NOW + 6 * DAY)}`)
    expect(row.actions).toEqual(['rollback', 'revoke'])
  })

  it('rollback_in_force_reads_its_expiry_as_the_detail', () => {
    const expires = NOW + 5 * 3600
    const row = gatewayRow(withGateway({ gateway_rollback_expires_at: expires }), NOW)
    expect(row.detail).toBe(`Retour arrière jusqu'au ${formatDateTime(expires)}`)
  })

  it('renew_disabled_during_a_ca_pq_overlap', () => {
    const row = gatewayRow(withGateway({}, { caPqOverlap: true }), NOW)
    // Listed, so the button is there, but its reason says why it cannot be started.
    expect(row.actions).toContain('renew')
    expect(row.renewReason).toBe(OVERLAP_PQ)
    expect(row.actions).toContain('revoke')
    expect(gatewayRow(withGateway(), NOW).renewReason).toBeNull()
  })

  it('abort_record_reads_the_cancellation_to_resume_and_never_offers_abort', () => {
    const row = gatewayRow(
      withGateway(
        { gateway_transition_pending: true, gateway_activation_at: NOW + 7 * DAY },
        { gatewayPending: pending({ decision_kind: 'abort', installed: true, published: false }) },
      ),
      NOW,
    )
    expect(row.state).toBe('Annulation à reprendre')
    expect(row.actions).toEqual(['resume', 'discard'])
  })

  it('restart_due_shows_the_reason_and_the_sentence', () => {
    const row = gatewayRow(
      withGateway({ gateway_restart_due: 'a service rollback is in force' }),
      NOW,
    )
    // The sentence is the main text; heliosd's English motif is kept apart, as a detail.
    expect(row.restart).toBe('Redémarrer heliosd sur la gateway.')
    expect(row.restartMotif).toBe('a service rollback is in force')
    expect(gatewayRow(withGateway(), NOW).restart).toBeNull()
  })

  it('discard_is_offered_whenever_a_record_waits', () => {
    const row = gatewayRow(withGateway({}, { gatewayPending: pending() }), NOW)
    expect(row.actions).toEqual(['resume', 'discard'])
  })

  it('revocation_to_sign_puts_revoke_first_without_resume', () => {
    const row = gatewayRow(
      withGateway(
        {},
        { gatewayPending: pending({ kind: 'revocation', decision_kind: null, installed: true, revocation_to_sign: true }) },
      ),
      NOW,
    )
    expect(row.actions).toEqual(['revoke', 'discard'])
    expect(row.actions).not.toContain('resume')
    expect(row.detail).toBe(
      "Le remplaçant est déposé ; la révocation reste à signer. Rien n'a été révoqué.",
    )
  })

  it('an_unread_domain_leaves_no_gateway_action_but_a_waiting_record', () => {
    const unread = overview({ domain: { state: 'refused', value: 404 } })
    expect(gatewayRow(unread, NOW).actions).toEqual([])
    expect(gatewayRow(unread, NOW).state).toBe('Gateway ancienne ou refus (404)')
    const waiting = overview({
      domain: { state: 'refused', value: 404 },
      gatewayPending: pending(),
    })
    expect(gatewayRow(waiting, NOW).actions).toEqual(['resume', 'discard'])
  })
  const FP = 'cc'.repeat(32)
  const OTHER_FP = 'dd'.repeat(32)
  const revocation = (extra: Partial<GatewayPendingView> = {}) =>
    pending({ kind: 'revocation', decision_kind: null, installed: true, revocation_applied: true, ...extra })

  it('revoked_awaiting_this_replacement_offers_resume_only', () => {
    const row = gatewayRow(
      withGateway(
        { gateway_revoked: true, gateway_awaited_replacement: FP },
        { gatewayPending: revocation({ replacement_fingerprint: FP }) },
      ),
      NOW,
    )
    expect(row.state).toBe('Révoquée, remplaçant à installer')
    expect(row.detail).toBeNull()
    expect(row.actions).toEqual(['resume'])
    expect(row.forceKind).toBeNull()
  })

  it('revoked_awaiting_another_replacement_offers_force_discard', () => {
    const row = gatewayRow(
      withGateway(
        { gateway_revoked: true, gateway_awaited_replacement: OTHER_FP },
        { gatewayPending: revocation({ replacement_fingerprint: FP }) },
      ),
      NOW,
    )
    expect(row.state).toBe('Révoquée, remplaçant attendu')
    expect(row.detail).toBe("Le remplaçant nommé par la révocation n'est pas sur ce poste.")
    expect(row.actions).toEqual(['force_discard'])
    expect(row.forceKind).toBe('replacement')
  })

  it('revoked_without_replacement_and_no_record_offers_nothing', () => {
    const row = gatewayRow(withGateway({ gateway_revoked: true }), NOW)
    expect(row.state).toBe('Révoquée')
    expect(row.detail).toBe('La gateway ne sert plus. Le domaine doit être reconstruit.')
    expect(row.actions).toEqual([])
    expect(row.forceKind).toBe('replacement')
    // An awaited replacement with no record to lean on: still nothing to force.
    const awaiting = gatewayRow(withGateway({ gateway_revoked: true, gateway_awaited_replacement: FP }), NOW)
    expect(awaiting.state).toBe('Révoquée, remplaçant attendu')
    expect(awaiting.actions).toEqual([])
  })

  it('revoked_without_replacement_with_a_record_offers_force_discard', () => {
    const row = gatewayRow(withGateway({ gateway_revoked: true }, { gatewayPending: pending() }), NOW)
    expect(row.state).toBe('Révoquée')
    expect(row.actions).toEqual(['force_discard'])
    expect(row.forceKind).toBe('replacement')
  })

  it('publication_refused_switches_from_abort_to_force_at_activation', () => {
    const activation = NOW + 7 * DAY
    const refused = withGateway(
      { gateway_transition_pending: true, gateway_activation_at: activation },
      { gatewayPending: pending({ installed: true, published: false, publication_refused: true }) },
    )
    const before = gatewayRow(refused, NOW)
    expect(before.state).toBe('Installée, publication à faire')
    expect(before.detail).toBe(
      `La publication est refusée : annuler la transition avant le ${formatDateTime(activation)}.`,
    )
    expect(before.actions).toEqual(['abort', 'resume'])
    expect(before.forceKind).toBeNull()

    const atActivation = withGateway(
      { gateway_transition_pending: true, gateway_activation_at: activation, now_unix: activation },
      { gatewayPending: pending({ installed: true, published: false, publication_refused: true }) },
    )
    const after = gatewayRow(atActivation, NOW)
    expect(after.state).toBe('Installée, publication à faire')
    expect(after.detail).toBeNull()
    expect(after.actions).toEqual(['force_discard', 'resume'])
    expect(after.forceKind).toBe('publication')
  })

  it('a_revoked_gateway_never_offers_renew_rollback_or_revoke', () => {
    const forbidden = ['renew', 'abort', 'rollback', 'revoke', 'discard']
    const cases = [
      withGateway({ gateway_revoked: true, gateway_rollback_expires_at: NOW + DAY }, { caPqOverlap: true }),
      withGateway({ gateway_revoked: true, gateway_awaited_replacement: FP }, { gatewayPending: pending() }),
      withGateway(
        { gateway_revoked: true, gateway_transition_pending: true, gateway_activation_at: NOW + DAY },
        { gatewayPending: pending({ installed: true, publication_refused: true }) },
      ),
    ]
    for (const o of cases) {
      const row = gatewayRow(o, NOW)
      for (const action of forbidden) expect(row.actions).not.toContain(action)
    }
  })
  it('revoked_with_an_unapplied_revocation_record_keeps_its_6b_state_and_actions', () => {
    const unappliedToResume = gatewayRow(
      withGateway(
        { gateway_revoked: true },
        { gatewayPending: revocation({ revocation_applied: false, revocation_to_sign: false }) },
      ),
      NOW,
    )
    expect(unappliedToResume.state).toBe('Révocation à reprendre')
    expect(unappliedToResume.actions).toEqual(['resume', 'discard'])
    expect(unappliedToResume.detail).toBeNull()
    expect(unappliedToResume.forceKind).toBeNull()

    const toSign = gatewayRow(
      withGateway(
        { gateway_revoked: true },
        { gatewayPending: revocation({ revocation_applied: false, revocation_to_sign: true }) },
      ),
      NOW,
    )
    expect(toSign.state).toBe('Révocation à signer')
    expect(toSign.actions).toEqual(['revoke', 'discard'])
    expect(toSign.detail).toBe("Le remplaçant est déposé ; la révocation reste à signer. Rien n'a été révoqué.")
    expect(toSign.forceKind).toBeNull()
  })
  it('forced_discard_leaves_an_installed_transition_before_activation_with_abort', () => {
    // No record any more, the transition is still staged on the gateway, before its activation.
    const row = gatewayRow(
      withGateway({ gateway_transition_pending: true, gateway_activation_at: NOW + 7 * DAY }),
      NOW,
    )
    expect(row.state).toBe('Installée, publication à faire')
    expect(row.actions).toEqual(['abort'])
    expect(row.replacementReason).toBeNull()
  })

  it('forced_discard_unblocks_a_revoke_without_replacement_after_activation', () => {
    // No record any more, the transition is staged and its activation reached: the revocation clears it.
    const row = gatewayRow(
      withGateway({ gateway_transition_pending: true, gateway_activation_at: NOW - DAY }),
      NOW,
    )
    expect(row.state).toBe('Installée, publication à faire')
    expect(row.actions).toEqual(['revoke'])
    expect(row.replacementReason).toBe(
      "Une transition est en cours : le remplaçant n'est possible qu'après sa fin.",
    )
  })
})
