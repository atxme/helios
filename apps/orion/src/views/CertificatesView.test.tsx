// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ProfileCertificates } from '../types'

const api = vi.hoisted(() => ({
  certificateOverview: vi.fn(),
  runCertificateAction: vi.fn(),
}))
vi.mock('../api', () => api)

import { CertificatesView } from './CertificatesView'

const entry = (overrides: Partial<ProfileCertificates> = {}): ProfileCertificates => ({
  name: 'portable',
  identity: 'orion-portable',
  negotiates: true,
  inventory: {
    gateway_pq: {
      subject: 'CN=gateway.example',
      issuer: 'CN=CA-PQ',
      fingerprint: 'a'.repeat(64),
      not_before: 0,
      not_after: 100_000,
      renewal_at: 80_000,
      phase: 'valid',
    },
    gateway_ca_tls: null,
    client_tls: null,
    client_pq: null,
    faults: [],
    identity_sealed: true,
  },
  actions: [
    {
      action: 'renew_now',
      label: 'Renouveler maintenant',
      blocked_by: { kind: 'renewal_path_not_wired' },
      message: 'Le chemin de renouvellement du §7 n’est pas encore branché.',
    },
  ],
  last_error: null,
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
  api.runCertificateAction.mockResolvedValue(undefined)
})

afterEach(cleanup)

describe('CertificatesView', () => {
  /** One call for the whole device: reading a profile unseals its identity. */
  it('reads every profile in a single call', async () => {
    api.certificateOverview.mockResolvedValue([entry(), entry({ name: 'bureau' })])
    render(<CertificatesView />)

    await waitFor(() => expect(screen.getByText('portable')).toBeTruthy())
    expect(screen.getByText('bureau')).toBeTruthy()
    expect(api.certificateOverview).toHaveBeenCalledOnce()
  })

  /**
   * A profile that pins nothing is named, not hidden: a user looking for it
   * has to learn why it is not listed, rather than conclude the screen is
   * broken.
   */
  it('names the profiles that negotiate nothing instead of dropping them', async () => {
    api.certificateOverview.mockResolvedValue([
      entry(),
      entry({ name: 'classique', negotiates: false, identity: '', actions: [] }),
    ])
    render(<CertificatesView />)

    await waitFor(() => expect(screen.getByText(/sans négociation : classique/)).toBeTruthy())
  })

  /** Nothing at all to show is said, rather than left blank. */
  it('says so when no profile of this device negotiates a key', async () => {
    api.certificateOverview.mockResolvedValue([])
    render(<CertificatesView />)

    await waitFor(() =>
      expect(screen.getByText(/Aucun profil de ce poste ne négocie de clé/)).toBeTruthy(),
    )
  })

  /**
   * A refusal comes back with the refreshed overview, not from the rejection:
   * printing both would show it twice, and the two could disagree after a
   * concurrent change.
   */
  it('re-reads after an action and shows the reason the shell recorded', async () => {
    api.certificateOverview
      .mockResolvedValueOnce([
        entry({
          actions: [
            {
              action: 'renew_now',
              label: 'Renouveler maintenant',
              blocked_by: null,
              message: null,
            },
          ],
        }),
      ])
      .mockResolvedValue([entry({ last_error: 'Le chemin n’est pas branché.' })])
    api.runCertificateAction.mockRejectedValue('refusé')
    render(<CertificatesView />)

    const button = await screen.findByRole('button', { name: 'Renouveler maintenant' })
    fireEvent.click(button)

    await waitFor(() => expect(screen.getByText(/Le chemin n’est pas branché/)).toBeTruthy())
    expect(api.runCertificateAction).toHaveBeenCalledWith('portable', 'renew_now')
    expect(api.certificateOverview).toHaveBeenCalledTimes(2)
  })
})
