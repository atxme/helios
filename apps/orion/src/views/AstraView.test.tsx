// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  startAstraCaTlsRotation: vi.fn(),
  continueAstraCaTlsRotation: vi.fn(),
  cancelAstraCaTlsRotation: vi.fn(),
  astraCaTlsRotationStatus: vi.fn(),
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
  it('starts from an existing operation and sends the four typed fields', async () => {
    render(<AstraView />)

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
    expect(await screen.findByText(/Branchez la première clé autorisée/)).toBeTruthy()
    expect(screen.getByText(/Campagne vérifiée/)).toBeTruthy()
    expect(screen.getByText('rotation planifiée')).toBeTruthy()
    expect(screen.getByText('1 → 2')).toBeTruthy()
  })

  it('separates both key gestures and describes the deposited transition precisely', async () => {
    render(<AstraView />)
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
    expect(screen.getByText(/Transition CA-TLS préparée et déposée/)).toBeTruthy()
    expect(screen.getByText(/La promotion CA-TLS reste requise/)).toBeTruthy()
    expect(api.continueAstraCaTlsRotation).toHaveBeenCalledTimes(2)
  })

  it('can cancel an open ceremony and reports backend failures', async () => {
    const { unmount } = render(<AstraView />)
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Annuler' }))

    await waitFor(() => expect(api.cancelAstraCaTlsRotation).toHaveBeenCalledOnce())
    expect(await screen.findByText(/Aucune transition n’a été produite/)).toBeTruthy()

    unmount()
    api.startAstraCaTlsRotation.mockRejectedValue('coffre illisible')
    render(<AstraView />)
    fillForm()
    fireEvent.click(screen.getByRole('button', { name: 'Démarrer la rotation' }))
    expect(await screen.findByText('coffre illisible')).toBeTruthy()
  })
})
