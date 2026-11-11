// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  beginGatewayCeremony: vi.fn(),
  operatorCeremonyStatus: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { GatewayPendingView, OperatorStatus, RotationsOverview } from '../../types'
import { GatewayIdentityBlock } from './GatewayIdentityBlock'
import { DAY, NOW, domainRead, overview } from './rotationFixtures'

const block = () => within(screen.getByRole('region', { name: 'Identité de la gateway' }))
const confirmation = () => within(screen.getByRole('region', { name: 'Confirmation' }))
const ceremony: OperatorStatus = { session_id: 's', revision: 1, operation: 'gateway_identity', remote: 'local', gesture: 'verifying', allowed: [] } as unknown as OperatorStatus

const pending = (extra: Partial<GatewayPendingView> = {}): GatewayPendingView => ({
  kind: 'decision',
  installed: false,
  published: false,
  revocation_applied: false,
  decision_kind: 'renewal',
  revocation_to_sign: false,
  ...extra,
})

const withDomain = (
  domain: Partial<ReturnType<typeof domainRead>> = {},
  extra: Partial<RotationsOverview> = {},
) => overview({ domain: { state: 'ok', value: domainRead(domain) }, ...extra })

const renderBlock = (o: RotationsOverview) => {
  const onCeremony = vi.fn()
  const refresh = vi.fn().mockResolvedValue(null)
  render(<GatewayIdentityBlock overview={o} now={NOW} onCeremony={onCeremony} refresh={refresh} />)
  return { onCeremony, refresh }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.beginGatewayCeremony.mockResolvedValue(undefined)
  api.operatorCeremonyStatus.mockResolvedValue(ceremony)
})

afterEach(() => {
  cleanup()
})

describe('GatewayIdentityBlock', () => {
  it('renew_runs_prerequisites_options_and_terms_then_hands_over_the_ceremony', async () => {
    const { onCeremony } = renderBlock(withDomain())
    fireEvent.click(block().getByRole('button', { name: "Renouveler l'identité de la gateway" }))
    expect(screen.getByRole('region', { name: 'Prérequis de la gateway' })).toBeTruthy()
    expect(screen.getByText('Termes : préparation 7 jours, recouvrement 7 jours, validité 365 jours.')).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Remplacer aussi la feuille TLS' }))
    fireEvent.click(screen.getByRole('button', { name: 'Continuer' }))
    await waitFor(() =>
      expect(api.beginGatewayCeremony).toHaveBeenCalledWith({
        gesture: 'renew',
        rotate_tls: true,
        key_recovery: false,
        prepare_days: 7,
        overlap_days: 7,
        validity_days: 365,
      }),
    )
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(ceremony))
  })

  it('key_loss_needs_its_own_confirmation_before_renewing', () => {
    renderBlock(withDomain())
    fireEvent.click(block().getByRole('button', { name: "Renouveler l'identité de la gateway" }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'La clé de la gateway est perdue' }))
    expect(screen.getByText('Aucune preuve de continuité. Réservé à une clé disparue.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Continuer' }).hasAttribute('disabled')).toBe(true)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Je confirme la perte de la clé' }))
    expect(screen.getByRole('button', { name: 'Continuer' }).hasAttribute('disabled')).toBe(false)
  })

  it('renew_is_disabled_during_a_ca_pq_overlap', () => {
    renderBlock(withDomain({}, { caPqOverlap: true }))
    const renew = block().getByRole('button', { name: "Renouveler l'identité de la gateway" })
    expect(renew.hasAttribute('disabled')).toBe(true)
    expect(block().getByText('Recouvrement CA-PQ en cours')).toBeTruthy()
  })

  it('nothing_is_started_while_prerequisites_are_red', () => {
    renderBlock(withDomain({}, { tunnel: false }))
    fireEvent.click(block().getByRole('button', { name: "Renouveler l'identité de la gateway" }))
    expect(screen.getByText('Tunnel connecté')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Continuer' })).toBeNull()
  })

  it('abort_confirms_that_the_epoch_is_consumed_then_aborts', async () => {
    renderBlock(
      withDomain(
        { gateway_transition_pending: true, gateway_activation_at: NOW + 7 * DAY },
        { gatewayPending: pending({ installed: true, published: false }) },
      ),
    )
    fireEvent.click(block().getByRole('button', { name: 'Annuler' }))
    expect(screen.getByText("L'époque reste consommée.")).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Confirmer l’annulation' }))
    await waitFor(() => expect(api.beginGatewayCeremony).toHaveBeenCalledWith({ gesture: 'abort' }))
  })

  it('rollback_checks_hours_and_reason_before_any_call', async () => {
    renderBlock(
      withDomain({
        gateway_transition_published: true,
        gateway_activation_at: NOW - DAY,
        gateway_retire_active_at: NOW + 6 * DAY,
      }),
    )
    fireEvent.click(block().getByRole('button', { name: "Revenir à l'ancienne identité" }))
    expect((screen.getByLabelText('Durée (heures)') as HTMLInputElement).value).toBe('24')
    fireEvent.click(screen.getByRole('button', { name: 'Lancer le retour arrière' }))
    expect(screen.getByText('Motif : de 1 à 200 caractères')).toBeTruthy()
    expect(api.beginGatewayCeremony).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Motif'), { target: { value: '  essai  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Lancer le retour arrière' }))
    await waitFor(() =>
      expect(api.beginGatewayCeremony).toHaveBeenCalledWith({ gesture: 'rollback', hours: 24, reason: 'essai' }),
    )
  })

  it('revoke_with_replacement_announces_two_series_of_touches_before_the_keys', async () => {
    renderBlock(withDomain())
    fireEvent.click(block().getByRole('button', { name: 'Révoquer la gateway' }))
    fireEvent.click(block().getByRole('button', { name: 'Compromis' }))
    expect(screen.getByRole('button', { name: 'Avec remplaçant' }).getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByText('Deux séries de touches : le remplaçant, puis la révocation.')).toBeTruthy()
    fireEvent.click(confirmation().getByRole('button', { name: 'Révoquer la gateway' }))
    await waitFor(() =>
      expect(api.beginGatewayCeremony).toHaveBeenCalledWith({
        gesture: 'revoke',
        reason: 'compromised',
        with_replacement: true,
      }),
    )
  })

  it('revoke_without_replacement_needs_its_second_confirmation', async () => {
    renderBlock(withDomain())
    fireEvent.click(block().getByRole('button', { name: 'Révoquer la gateway' }))
    fireEvent.click(block().getByRole('button', { name: 'Volé ou perdu' }))
    fireEvent.click(block().getByRole('button', { name: 'Sans remplaçant' }))
    expect(screen.getByText('Une série de touches : la révocation.')).toBeTruthy()
    expect(
      screen.getByText('La gateway ne servira plus. Le domaine devra être reconstruit.'),
    ).toBeTruthy()
    const revoke = () => confirmation().getByRole('button', { name: 'Révoquer la gateway' })
    expect(revoke().hasAttribute('disabled')).toBe(true)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Je confirme la révocation sans remplaçant' }))
    fireEvent.click(revoke())
    await waitFor(() =>
      expect(api.beginGatewayCeremony).toHaveBeenCalledWith({
        gesture: 'revoke',
        reason: 'stolen_or_lost',
        with_replacement: false,
      }),
    )
  })

  it('a_deposited_replacement_puts_revoke_first_without_resume_and_one_series', async () => {
    renderBlock(
      withDomain({}, {
        gatewayPending: pending({ kind: 'revocation', decision_kind: null, installed: true, revocation_to_sign: true }),
      }),
    )
    const names = block().getAllByRole('button').map((button) => button.textContent)
    expect(names[0]).toBe('Révoquer la gateway')
    expect(names).not.toContain('Reprendre')
    expect(screen.getByText("Le remplaçant est déposé ; la révocation reste à signer. Rien n'a été révoqué.")).toBeTruthy()
    fireEvent.click(block().getByRole('button', { name: 'Révoquer la gateway' }))
    fireEvent.click(block().getByRole('button', { name: 'Remplacé' }))
    expect(screen.queryByRole('button', { name: 'Sans remplaçant' })).toBeNull()
    expect(screen.getByText('Une série de touches : la révocation.')).toBeTruthy()
    fireEvent.click(confirmation().getByRole('button', { name: 'Révoquer la gateway' }))
    await waitFor(() =>
      expect(api.beginGatewayCeremony).toHaveBeenCalledWith({
        gesture: 'revoke',
        reason: 'replaced',
        with_replacement: true,
      }),
    )
  })

  it('discard_asks_the_confirmation_then_drops_the_record_without_a_ceremony', async () => {
    const { refresh, onCeremony } = renderBlock(withDomain({}, { gatewayPending: pending() }))
    fireEvent.click(block().getByRole('button', { name: 'Jeter la décision en attente' }))
    expect(screen.getByText("La décision signée sera perdue. L'époque reste consommée.")).toBeTruthy()
    fireEvent.click(confirmation().getByRole('button', { name: 'Jeter la décision en attente' }))
    await waitFor(() => expect(api.beginGatewayCeremony).toHaveBeenCalledWith({ gesture: 'discard' }))
    await waitFor(() => expect(refresh).toHaveBeenCalled())
    expect(api.operatorCeremonyStatus).not.toHaveBeenCalled()
    expect(onCeremony).not.toHaveBeenCalled()
  })

  it('discard_shows_the_sentence_the_rust_side_refuses_with', async () => {
    api.beginGatewayCeremony.mockRejectedValue('Une cérémonie est ouverte : la terminer d’abord.')
    renderBlock(withDomain({}, { gatewayPending: pending() }))
    fireEvent.click(block().getByRole('button', { name: 'Jeter la décision en attente' }))
    fireEvent.click(confirmation().getByRole('button', { name: 'Jeter la décision en attente' }))
    expect(await screen.findByText('Une cérémonie est ouverte : la terminer d’abord.')).toBeTruthy()
  })

  it('resume_leads_a_waiting_decision_and_hands_over_the_ceremony', async () => {
    const { onCeremony } = renderBlock(withDomain({}, { gatewayPending: pending() }))
    expect(block().getAllByRole('button')[0].textContent).toBe('Reprendre')
    // The row's button, then the one the flow offers under its prerequisites.
    const resume = block().getAllByRole('button', { name: 'Reprendre' })
    fireEvent.click(resume[0])
    fireEvent.click(block().getAllByRole('button', { name: 'Reprendre' })[1])
    await waitFor(() => expect(api.beginGatewayCeremony).toHaveBeenCalledWith({ gesture: 'resume' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(ceremony))
  })

  it('restart_shows_the_sentence_and_the_raw_motif_as_a_quiet_detail', () => {
    renderBlock(withDomain({ gateway_restart_due: 'a service rollback is in force' }))
    expect(screen.getByText('Redémarrer heliosd sur la gateway.')).toBeTruthy()
    expect(screen.getByText('Détail technique : a service rollback is in force')).toBeTruthy()
  })

  it('a_flow_closes_when_a_refresh_takes_its_action_away', () => {
    const rollbackable = withDomain({
      gateway_transition_published: true,
      gateway_activation_at: NOW - DAY,
      gateway_retire_active_at: NOW + 6 * DAY,
    })
    const onCeremony = vi.fn()
    const refresh = vi.fn()
    const { rerender } = render(
      <GatewayIdentityBlock overview={rollbackable} now={NOW} onCeremony={onCeremony} refresh={refresh} />,
    )
    fireEvent.click(block().getByRole('button', { name: "Revenir à l'ancienne identité" }))
    expect(screen.getByRole('button', { name: 'Lancer le retour arrière' })).toBeTruthy()
    rerender(
      <GatewayIdentityBlock overview={withDomain()} now={NOW} onCeremony={onCeremony} refresh={refresh} />,
    )
    expect(screen.queryByRole('button', { name: 'Lancer le retour arrière' })).toBeNull()
  })

  it('an_error_shows_its_message_without_an_error_prefix', async () => {
    api.beginGatewayCeremony.mockRejectedValue(new Error('la gateway ne répond pas'))
    renderBlock(withDomain({}, { gatewayPending: pending() }))
    fireEvent.click(block().getByRole('button', { name: 'Jeter la décision en attente' }))
    fireEvent.click(confirmation().getByRole('button', { name: 'Jeter la décision en attente' }))
    expect(await screen.findByText('la gateway ne répond pas')).toBeTruthy()
    expect(screen.queryByText(/Error:/)).toBeNull()
  })
})
