// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorChainStart: vi.fn(),
  operatorChainNext: vi.fn(),
  operatorChainReopen: vi.fn(),
  operatorChainAbandon: vi.fn(),
  operatorChainHeld: vi.fn(),
  operatorGatewayCheckRenewal: vi.fn(),
  operatorCeremonyStatus: vi.fn(),
  beginIssuerCeremony: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  beginGatewayCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { CampaignScope, OperatorOpened, OperatorPendingOperation, OperatorStatus, RotationsOverview } from '../../types'
import { RenewAllBlock } from './RenewAllBlock'
import { NOW, authorityRead, overview } from './rotationFixtures'

const OP = 'c'.repeat(32)
const NEXT = 'd'.repeat(32)
const STEPS: CampaignScope[] = ['issuer_delegation', 'trust_authorities', 'gateway_identity', 'fleet_leafs']

const chain = (current: number, operation_id: string | null = null) => ({
  steps: STEPS,
  current,
  operation_id,
})

const withChain = (
  plan: ReturnType<typeof chain> | null,
  extra: Partial<RotationsOverview> = {},
): RotationsOverview =>
  overview({
    authority: { state: 'ok', value: authorityRead({ chain: plan }) },
    ...extra,
  })

const opened = (scope: CampaignScope, extra: Partial<OperatorOpened> = {}): OperatorOpened => ({
  operation_id: NEXT,
  campaign_id: 'e'.repeat(32),
  campaign_fingerprint: 'a'.repeat(64),
  scope,
  target_count: 2,
  required_credentials: 1,
  expires_at: NOW + 300,
  ...extra,
})

const pendingOp = (scope: CampaignScope, operation_id = OP): OperatorPendingOperation => ({
  operation_id,
  scope,
  reason: 'motif',
  requested_by: 'christophe',
  target_count: 2,
  required_credentials: 1,
  campaign_fingerprint: 'a'.repeat(64),
  created_at: NOW,
  expires_at: NOW + 300,
})

const ceremony = (extra: Partial<OperatorStatus> = {}): OperatorStatus => ({
  session_id: 's',
  revision: 1,
  operation: 'approve_campaign',
  remote: 'local',
  gesture: 'idle',
  allowed: [],
  ...extra,
})

const row = () => within(screen.getByRole('region', { name: 'Tout renouveler' }))
const button = (name: string) => row().getByRole('button', { name })

const show = (o: RotationsOverview, extra: Partial<React.ComponentProps<typeof RenewAllBlock>> = {}) => {
  const onCeremony = vi.fn()
  const refresh = vi.fn().mockResolvedValue(o)
  render(
    <RenewAllBlock
      overview={o}
      onCeremony={onCeremony}
      refresh={refresh}
      operatorLabel="Clé 1"
      {...extra}
    />,
  )
  return { onCeremony, refresh }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorCeremonyStatus.mockResolvedValue(null)
  api.operatorChainHeld.mockResolvedValue(null)
})
afterEach(cleanup)

describe('the row without a plan', () => {
  it('start_opens_the_chain_then_the_issuer_ceremony', async () => {
    const o = withChain(null)
    const { onCeremony, refresh } = show(o)
    api.operatorChainStart.mockResolvedValue(opened('issuer_delegation', { delegation_request: 'REQ' }))
    api.beginIssuerCeremony.mockResolvedValue(ceremony({ operation: 'authorize_issuer' }))

    fireEvent.click(button('Commencer'))
    await waitFor(() => expect(api.beginIssuerCeremony).toHaveBeenCalled())

    expect(refresh).toHaveBeenCalled()
    expect(api.operatorChainStart).toHaveBeenCalledWith('Tout renouveler', 'Clé 1')
    expect(api.operatorChainStart.mock.invocationCallOrder[0]).toBeLessThan(
      api.beginIssuerCeremony.mock.invocationCallOrder[0],
    )
    expect(api.beginIssuerCeremony).toHaveBeenCalledWith({
      gesture: 'authorize_issuer',
      operation_id: NEXT,
      request: 'REQ',
    })
    expect(onCeremony).toHaveBeenCalledWith(ceremony({ operation: 'authorize_issuer' }))
  })

  it('a_blocked_start_is_disabled_with_its_reason', () => {
    show(withChain(null, { tunnel: false }))
    expect((button('Commencer') as HTMLButtonElement).disabled).toBe(true)
    expect(api.operatorChainStart).not.toHaveBeenCalled()
  })
})

describe('the steps of a plan', () => {
  it('continue_checks_before_asking_astra', async () => {
    // The fleet's prerequisites are red: the step after the gateway's is not started.
    const { refresh } = show(withChain(chain(2), { tunnel: false }))
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(row().getByText('Tunnel connecté')).toBeTruthy())
    expect(api.operatorChainNext).not.toHaveBeenCalled()
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
    expect(refresh).toHaveBeenCalled()
  })

  it('continue_to_gateway_checks_renewal_before_next', async () => {
    api.operatorGatewayCheckRenewal.mockRejectedValue(new Error('Renouvellement refusé : clé absente.'))
    show(withChain(chain(1)))
    fireEvent.click(button('Continuer'))
    fireEvent.click(button("Renouveler l'identité de la gateway"))
    await waitFor(() => expect(row().getByText('Renouvellement refusé : clé absente.')).toBeTruthy())
    expect(api.operatorChainNext).not.toHaveBeenCalled()
    expect(api.beginGatewayCeremony).not.toHaveBeenCalled()
  })

  it('continue_to_gateway_renews_in_chain', async () => {
    api.operatorGatewayCheckRenewal.mockResolvedValue(undefined)
    api.operatorChainNext.mockResolvedValue({ outcome: 'opened', ...opened('gateway_identity') })
    api.beginGatewayCeremony.mockResolvedValue(undefined)
    // The mount reads no ceremony, the gesture's own guard reads none either, then the one begun.
    api.operatorCeremonyStatus
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null)
      .mockResolvedValue(ceremony({ operation: 'approve_campaign' }))
    const { onCeremony } = show(withChain(chain(1)))

    fireEvent.click(button('Continuer'))
    fireEvent.click(button("Renouveler l'identité de la gateway"))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(api.beginGatewayCeremony).toHaveBeenCalledWith(
      expect.objectContaining({
        gesture: 'renew',
        in_chain: true,
        rotate_tls: false,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 365,
      }),
    )
    expect(api.operatorChainNext.mock.invocationCallOrder[0]).toBeLessThan(
      api.beginGatewayCeremony.mock.invocationCallOrder[0],
    )
  })

  it('continue_passes_the_expected_step', async () => {
    api.operatorChainNext.mockResolvedValue({ outcome: 'opened', ...opened('fleet_leafs') })
    api.beginOperatorCeremony.mockResolvedValue(ceremony())
    show(withChain(chain(2)))
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(api.beginOperatorCeremony).toHaveBeenCalled())
    expect(api.operatorChainNext).toHaveBeenCalledWith(2)
    expect(api.beginOperatorCeremony).toHaveBeenCalledWith({ kind: 'approve_campaign', operation_id: NEXT })
  })

  it('a_moved_plan_sentence_is_shown_as_is', async () => {
    api.operatorChainNext.mockRejectedValue(new Error("Le plan n'est plus sur cette étape."))
    show(withChain(chain(2)))
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(row().getByText("Le plan n'est plus sur cette étape.")).toBeTruthy())
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('reopen_still_open_sentence_is_shown_as_is_and_reads_later', async () => {
    const sentence = "La campagne de l'étape est encore ouverte jusqu'à 14 nov. : l'approuver."
    api.operatorChainReopen.mockRejectedValue(new Error(sentence))
    const { refresh } = show(withChain(chain(3)))
    fireEvent.click(button('Rouvrir l\'étape'))
    await waitFor(() => expect(row().getByText(sentence)).toBeTruthy())
    const before = refresh.mock.calls.length
    fireEvent.click(button('Relire plus tard'))
    await waitFor(() => expect(refresh.mock.calls.length).toBeGreaterThan(before))
  })

  it('finished_reads_fleet_authorized', async () => {
    api.operatorChainNext.mockResolvedValue({ outcome: 'finished' })
    show(withChain(chain(3, OP), { caTlsCloseAt: NOW + 86_400 }), { fleetApprovedThisSession: OP })
    await waitFor(() => expect(button('Continuer')).toBeTruthy())
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(row().getByText(/Parc autorisé ; chaque poste se renouvelle/)).toBeTruthy())
    expect(row().getByText(/Terminer la rotation CA TLS/)).toBeTruthy()
    expect(api.operatorChainNext).toHaveBeenCalledWith(3)
  })

  it('fleet_done_this_session_offers_continue', () => {
    // The approval comes from the screen, not from a read of the ceremony: no status is read here.
    show(withChain(chain(3, OP)), { fleetApprovedThisSession: OP })
    expect(button('Continuer')).toBeTruthy()
    expect(row().queryByRole('button', { name: "Rouvrir l'étape" })).toBeNull()
  })

  it('an_approval_of_another_campaign_does_not_count', () => {
    show(withChain(chain(3, OP)), { fleetApprovedThisSession: 'f'.repeat(32) })
    expect(row().queryByRole('button', { name: 'Continuer' })).toBeNull()
    expect(button("Rouvrir l'étape")).toBeTruthy()
  })

  it('resume_delegation_leads_the_held_request', async () => {
    api.operatorChainHeld.mockResolvedValue(opened('issuer_delegation', { operation_id: OP, delegation_request: 'REQ' }))
    api.beginIssuerCeremony.mockResolvedValue(ceremony({ operation: 'authorize_issuer' }))
    show(withChain(chain(0, OP), { pending: { state: 'ok', value: [pendingOp('issuer_delegation')] } }))
    await waitFor(() => expect(button("Reprendre l'étape")).toBeTruthy())
    fireEvent.click(button("Reprendre l'étape"))
    await waitFor(() => expect(api.beginIssuerCeremony).toHaveBeenCalled())
    expect(api.operatorChainNext).not.toHaveBeenCalled()
    expect(api.beginIssuerCeremony).toHaveBeenCalledWith({
      gesture: 'authorize_issuer',
      operation_id: OP,
      request: 'REQ',
    })
  })

  it('abandon_says_what_was_approved_keeps_its_effect', async () => {
    api.operatorChainAbandon.mockResolvedValue(undefined)
    show(withChain(chain(1)))
    fireEvent.click(button('Abandonner le plan'))
    expect(row().getByText('Ce qui est déjà approuvé garde son effet.')).toBeTruthy()
    expect(api.operatorChainAbandon).not.toHaveBeenCalled()
    fireEvent.click(button("Confirmer l'abandon du plan"))
    await waitFor(() => expect(api.operatorChainAbandon).toHaveBeenCalledTimes(1))
  })

  it('the_ca_tls_step_hands_its_chain_step_to_the_ceremony_on_continue', async () => {
    type Context = Parameters<NonNullable<React.ComponentProps<typeof RenewAllBlock>['renderStep']>>[0]
    const renderStep = vi.fn((_context: Context) => null)
    const { onCeremony } = show(withChain(chain(0)), { renderStep })
    fireEvent.click(button('Continuer'))
    expect(renderStep).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'replace_ca_tls', existingOperation: null }),
    )
    // The step's own ceremony hands the screen over with the step its approval takes.
    const context = renderStep.mock.calls[renderStep.mock.calls.length - 1][0]
    context.onCeremony(ceremony({ operation: 'rotate_client_tls_ca' }), null)
    expect(onCeremony).toHaveBeenCalledWith(expect.anything(), null, { reopen: false, expected_step: 0 })
    expect(api.operatorChainNext).not.toHaveBeenCalled()
    expect(api.operatorChainReopen).not.toHaveBeenCalled()
  })

  it('the_ca_tls_reopening_hands_a_reopen_step_at_the_current_plan_step', () => {
    type Context = Parameters<NonNullable<React.ComponentProps<typeof RenewAllBlock>['renderStep']>>[0]
    const renderStep = vi.fn((_context: Context) => null)
    const { onCeremony } = show(withChain(chain(1)), { renderStep })
    fireEvent.click(button("Rouvrir l'étape"))
    const context = renderStep.mock.calls[renderStep.mock.calls.length - 1][0]
    context.onCeremony(ceremony({ operation: 'rotate_client_tls_ca' }), null)
    expect(onCeremony).toHaveBeenCalledWith(expect.anything(), null, { reopen: true, expected_step: 1 })
    expect(api.operatorChainReopen).not.toHaveBeenCalled()
  })
})
