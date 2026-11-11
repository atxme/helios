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
})
