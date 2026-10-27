// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  startAstraCaTlsRotation: vi.fn(),
  continueAstraCaTlsRotation: vi.fn(),
  cancelAstraCaTlsRotation: vi.fn(),
  astraCaTlsRotationStatus: vi.fn(),
  operatorCeremonyStatus: vi.fn(),
  advanceOperatorCeremony: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  operatorPendingOperations: vi.fn(),
  dismissOperatorCeremony: vi.fn(),
  operatorOverview: vi.fn(),
}))
vi.mock('../api', () => api)

import { AstraView } from './AstraView'

const fillForm = () => {
  fireEvent.change(screen.getByLabelText('Coffre d’autorité'), {
    target: { value: 'C:\\astra\\authority-vault.json' },
  })
  fireEvent.change(screen.getByLabelText('Identifiant de l’opération'), {
    target: { value: 'a'.repeat(32) },
  })
  fireEvent.change(screen.getByLabelText('Fichier de sortie'), {
    target: { value: 'C:\\astra\\ca-tls-transition.json' },
  })
}

const openTab = (name: string) => fireEvent.click(screen.getByRole('tab', { name }))

const manifest = {
  reason: 'rotation planifiée',
  requested_by: 'christophe',
  fingerprint: 'b'.repeat(64),
  current_ca_tls_epoch: 1,
  next_ca_tls_epoch: 2,
  activation_at: 1_789_198_911,
  not_after: 1_791_790_911,
  outgoing_anchor_fingerprint: 'c'.repeat(64),
  affected_ca: 'client_tls' as const,
  target_count: 12,
}

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorCeremonyStatus.mockResolvedValue(null)
  api.operatorPendingOperations.mockResolvedValue([])
  api.operatorOverview.mockResolvedValue({
    vault_path: 'C:\\astra\\vault.json',
    exists: false,
    vault_fingerprint: null,
    slots: [],
    max_slots: 8,
    domain: null,
  })
  api.dismissOperatorCeremony.mockResolvedValue(undefined)
  api.astraCaTlsRotationStatus.mockResolvedValue({
    phase: 'idle',
    message: '',
    can_continue: false,
    can_cancel: false,
  })
  api.startAstraCaTlsRotation.mockResolvedValue({
    phase: 'awaiting_first_key',
    message: 'première clé attendue',
    can_continue: true,
    can_cancel: true,
    manifest,
  })
  api.continueAstraCaTlsRotation
    .mockResolvedValueOnce({
      phase: 'awaiting_second_key',
      message: 'seconde clé attendue',
      can_continue: true,
      can_cancel: true,
      manifest,
      first_key_label: 'YubiKey portable',
    })
    .mockResolvedValueOnce({
      phase: 'deposited',
      message: 'déposée',
      can_continue: false,
      can_cancel: false,
      manifest,
      first_key_label: 'YubiKey portable',
      second_key_label: 'YubiKey home',
      output_path: 'C:\\astra\\ca-tls-transition.json',
    })
  api.cancelAstraCaTlsRotation.mockResolvedValue({
    phase: 'cancelled',
    message: 'annulée',
    can_continue: false,
    can_cancel: false,
  })
})

afterEach(cleanup)

describe('AstraView', () => {
  it('the_astra_tab_lists_six_sections_in_order', () => {
    render(<AstraView />)
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Enrôlement',
      'Coffre et clés',
      'Domaine',
      'Approbations',
      'Rotations',
      'Gateways',
    ])
    openTab('Enrôlement')
    expect(screen.getByText(/arrivera dans une prochaine version/)).toBeTruthy()
    openTab('Gateways')
    expect(screen.getByText(/arrivera dans une prochaine version/)).toBeTruthy()
  })

  it('the_rotation_flow_still_renders_under_rotations', () => {
    render(<AstraView />)
    openTab('Rotations')
    expect(screen.getByRole('button', { name: 'Démarrer la rotation' })).toBeTruthy()
  })

  it('verify_key_opens_the_ceremony_over_the_tabs', async () => {
    api.operatorOverview.mockResolvedValue({
      vault_path: 'v.json',
      exists: true,
      vault_fingerprint: 'ab12',
      slots: [],
      max_slots: 8,
      domain: null,
    })
    api.beginOperatorCeremony.mockResolvedValue({
      session_id: 'd'.repeat(32),
      revision: 1,
      operation: 'verify_key',
      operation_id: null,
      remote: 'not_required',
      gesture: { awaiting_key: { index: 1, of: 1, purpose: 'verify_key' } },
      allowed: ['continue', 'cancel'],
    })
    render(<AstraView />)
    fireEvent.click(await screen.findByRole('button', { name: 'Vérifier une clé' }))
    await waitFor(() => expect(screen.queryByRole('tab')).toBeNull())
    expect(screen.getByText('Une opération attend l’opérateur.')).toBeTruthy()
  })

  it('starts from an existing operation and sends the four typed fields', async () => {
    render(<AstraView />)
    openTab('Rotations')

    expect(screen.getByRole('button', { name: 'Démarrer la rotation' }).hasAttribute('disabled')).toBe(true)
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))

    await waitFor(() =>
      expect(api.startAstraCaTlsRotation).toHaveBeenCalledWith({
        vault_path: 'C:\\astra\\authority-vault.json',
        heliosd_url: 'http://100.64.0.1:8080',
        operation_id: 'a'.repeat(32),
        output_path: 'C:\\astra\\ca-tls-transition.json',
      }),
    )
    expect(await screen.findByText(/première clé attendue/)).toBeTruthy()
    expect(screen.getByText(/Campagne vérifiée/)).toBeTruthy()
    expect(screen.getByText('rotation planifiée')).toBeTruthy()
    expect(screen.getByText('1 → 2')).toBeTruthy()
  })

  it('separates both key gestures and describes the deposited transition precisely', async () => {
    render(<AstraView />)
    openTab('Rotations')
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))

    fireEvent.click(
      await screen.findByRole('button', { name: 'Première clé branchée — continuer' }),
    )
    await waitFor(() => expect(screen.getByText(/Clé reconnue : YubiKey portable/)).toBeTruthy())

    fireEvent.click(
      screen.getByRole('button', { name: 'Seconde clé branchée — continuer' }),
    )
    await waitFor(() => expect(screen.getByText(/Clé reconnue : YubiKey home/)).toBeTruthy())
    expect(screen.getByText(/Transition CA-TLS déposée/)).toBeTruthy()
    expect(screen.getByText(/La promotion reste à faire/)).toBeTruthy()
    expect(api.continueAstraCaTlsRotation).toHaveBeenCalledTimes(2)
  })

  it('can cancel an open ceremony and reports backend failures', async () => {
    const { unmount } = render(<AstraView />)
    openTab('Rotations')
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Annuler' }))

    await waitFor(() => expect(api.cancelAstraCaTlsRotation).toHaveBeenCalledOnce())
    expect(await screen.findByText(/Aucune transition n’a été produite/)).toBeTruthy()

    unmount()
    api.startAstraCaTlsRotation.mockRejectedValue('coffre illisible')
    render(<AstraView />)
    openTab('Rotations')
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))
    expect(await screen.findByText('coffre illisible')).toBeTruthy()
  })

  it('polls past processing so a campaign can reach its next key', async () => {
    api.operatorCeremonyStatus
      .mockResolvedValueOnce({
        session_id: 'd'.repeat(32),
        revision: 2,
        operation: 'approve_campaign',
        operation_id: 'e'.repeat(32),
        remote: 'awaiting_operator',
        gesture: { processing_key: { index: 1, of: 2 } },
        allowed: [],
      })
      .mockResolvedValue({
        session_id: 'd'.repeat(32),
        revision: 3,
        operation: 'approve_campaign',
        operation_id: 'e'.repeat(32),
        remote: 'awaiting_operator',
        gesture: {
          awaiting_key: { index: 2, of: 2, purpose: 'approve_campaign' },
        },
        allowed: ['continue', 'cancel'],
      })

    render(<AstraView />)

    expect(await screen.findByText('Clé 1 sur 2 en cours de lecture…')).toBeTruthy()
    expect(
      await screen.findByText('Brancher la clé autorisée (2 sur 2), pour approuver la campagne affichée.'),
    ).toBeTruthy()
  })

  it('shows but never launches a campaign the helper cannot execute', async () => {
    api.operatorPendingOperations.mockResolvedValue([
      {
        operation_id: 'f'.repeat(32),
        scope: 'trust_authorities',
        reason: 'rotation des ancres',
        requested_by: 'operator',
        target_count: 2,
        required_credentials: 2,
        campaign_fingerprint: 'a'.repeat(64),
        created_at: 1_800_000_000,
        expires_at: 1_800_000_300,
      },
    ])

    render(<AstraView />)
    openTab('Approbations')

    expect(await screen.findByText('rotation des ancres')).toBeTruthy()
    const open = screen.getByRole('button', { name: 'Ouvrir la cérémonie' })
    expect(open.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(/n’est pas encore disponible dans Orion/)).toBeTruthy()
    fireEvent.click(open)
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('names a WebAuthn foreground refusal instead of blaming the key', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'd'.repeat(32),
      revision: 3,
      operation: 'recover_identity',
      operation_id: 'e'.repeat(32),
      remote: 'awaiting_operator',
      gesture: 'failed',
      allowed: [],
      refusal: { refusal: 'foreground_unavailable' },
    })

    render(<AstraView />)

    expect(await screen.findByText(/boîte WebAuthn au premier plan/)).toBeTruthy()
    expect(screen.queryByText(/Aucune clé n’a répondu/)).toBeNull()
  })

  it('hands a completed recovery back to Orion without a second certificate press', async () => {
    const operationId = 'e'.repeat(32)
    const onRecoveryReady = vi.fn().mockResolvedValue(undefined)
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'd'.repeat(32),
      revision: 5,
      operation: 'recover_identity',
      operation_id: operationId,
      remote: 'granted',
      gesture: 'done',
      allowed: [],
    })

    render(<AstraView onRecoveryReady={onRecoveryReady} />)

    await waitFor(() => expect(onRecoveryReady).toHaveBeenCalledWith(operationId))
    expect(onRecoveryReady).toHaveBeenCalledTimes(1)
  })

  it('keeps a failed automatic finalization retryable', async () => {
    const operationId = 'e'.repeat(32)
    const onRecoveryReady = vi
      .fn()
      .mockRejectedValueOnce('commit temporairement indisponible')
      .mockResolvedValueOnce(undefined)
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'd'.repeat(32),
      revision: 5,
      operation: 'recover_identity',
      operation_id: operationId,
      remote: 'granted',
      gesture: 'done',
      allowed: [],
    })

    render(<AstraView onRecoveryReady={onRecoveryReady} />)

    expect(await screen.findByText(/commit temporairement indisponible/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Réessayer la finalisation' }))
    await waitFor(() => expect(onRecoveryReady).toHaveBeenCalledTimes(2))
  })
})
