// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ProfileCertificates } from '../types'

const api = vi.hoisted(() => ({
  certificateOverview: vi.fn(),
  runCertificateAction: vi.fn(),
  certificateApprovalManifest: vi.fn(),
  certificateApprovalNeedsPin: vi.fn(),
  approveCertificateRenewal: vi.fn(),
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
    previous_identity: null,
  },
  actions: [
    {
      action: 'renew_now',
      label: 'Renouveler maintenant',
      blocked_by: null,
      message: null,
    },
  ],
  last_error: null,
  ...overrides,
})

/** The one action with a driver, unblocked. */
const renewNow = () => ({
  action: 'renew_now' as const,
  label: 'Renouveler maintenant',
  blocked_by: null,
  message: null,
})

/** The device-wide action, unblocked. */
const renewEvery = () => ({
  action: 'renew_every_profile' as const,
  label: 'Renouveler tous les profils Helios de cet appareil',
  blocked_by: null,
  message: null,
})

/** A renewal parked where every renewal legitimately parks. */
const awaiting = () => ({
  step: 'awaiting_operator' as const,
  operation_id: 'f'.repeat(32),
  companion_command: 'astra-signer approve --operation-id ' + 'f'.repeat(32),
})

/** One press's result, keyed by profile as the command returns it. */
const outcome = (step: unknown, name = 'portable') => ({
  progress: { [name]: step },
  refused: {},
})

/** A certificate whose validity is long past, whatever «now» happens to be. */
const expiredFacts = () => ({
  subject: 'CN=workstation',
  issuer: 'CN=CA-TLS',
  fingerprint: 'b'.repeat(64),
  not_before: 0,
  not_after: 100_000,
  renewal_at: 80_000,
  phase: 'expired' as const,
})

beforeEach(() => {
  vi.clearAllMocks()
  api.runCertificateAction.mockResolvedValue(
    outcome({
      step: 'awaiting_operator',
      operation_id: 'f'.repeat(32),
      companion_command: 'astra-signer approve --heliosd-url http://100.64.0.1:8080',
    }),
  )
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
   * The screen is opened because something stopped connecting. The profile
   * that explains it has to be the first one, not the one that happens to sit
   * first in the configuration file.
   */
  it('puts the profiles in trouble before the healthy ones', async () => {
    const healthy = entry({ name: 'sain' })
    const broken = entry({
      name: 'casse',
      inventory: { ...entry().inventory, gateway_pq: null, client_pq: expiredFacts() },
    })
    api.certificateOverview.mockResolvedValue([healthy, broken])
    render(<CertificatesView />)

    await waitFor(() => expect(screen.getByText('casse')).toBeTruthy())
    const names = screen.getAllByRole('heading', { level: 3 }).map((node) => node.textContent)
    expect(names).toEqual(['casse', 'sain'])
  })

  /**
   * An unanswered read is not an empty device: reporting the two the same way
   * told a user with six profiles that they had none.
   */
  it('distinguishes a failed read from a device that negotiates nothing', async () => {
    api.certificateOverview.mockRejectedValue('DPAPI indisponible')
    render(<CertificatesView />)

    await waitFor(() => expect(screen.getByText(/n’ont pas pu être lus/)).toBeTruthy())
    expect(screen.queryByText(/Aucun profil de ce poste ne négocie de clé/)).toBeNull()
  })

  /** The reload says what it does: «Relire» read as an undo. */
  it('offers the reload as an explicit refresh', async () => {
    api.certificateOverview.mockResolvedValue([entry()])
    render(<CertificatesView />)

    const button = await screen.findByRole('button', { name: 'Actualiser' })
    fireEvent.click(button)
    await waitFor(() => expect(api.certificateOverview).toHaveBeenCalledTimes(2))
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

  /**
   * `awaiting_operator` is where every renewal legitimately waits. What ends
   * the wait is a security key, and Orion now asks for it itself — there is no
   * second binary to launch.
   */
  it('offers the ceremony in place of a command to run', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    await waitFor(() => expect(screen.getByText('f'.repeat(32))).toBeTruthy())
    expect(await screen.findByRole('button', { name: 'Lire la demande' })).toBeTruthy()
    expect(screen.queryByText(/astra-signer/)).toBeNull()
  })

  /**
   * The manifest is shown, and only then is the key asked for: what is signed
   * has to be what the user saw.
   */
  it('shows the request before asking for a touch', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.certificateApprovalManifest.mockResolvedValue({
      operation_id: 'f'.repeat(32),
      client_wg_public_key: 'AAAA',
      active_generation: 4,
      requested_generation: 5,
      request_fingerprint: 'a'.repeat(64),
      expires_at: 1_700_000_300,
      eligible_credentials: 2,
    })
    api.certificateApprovalNeedsPin.mockResolvedValue(false)
    api.approveCertificateRenewal.mockResolvedValue({ step: 'issuing', operation_id: 'f'.repeat(32) })
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Lire la demande' }))

    await waitFor(() => expect(api.approveCertificateRenewal).toHaveBeenCalledWith('portable', undefined))
    expect(api.certificateApprovalManifest).toHaveBeenCalledWith('portable')
  })

  /**
   * When the ceremony cannot run — no platform dialog, a key that needs an
   * elevated process — the companion is the answer, and that is the one place
   * its command line belongs.
   */
  it('falls back to the companion command only after a failed ceremony', async () => {
    const command =
      'astra-signer approve --heliosd-url http://100.64.0.1:8080 --operation-id ' + 'f'.repeat(32)
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(
      outcome({ ...awaiting(), companion_command: command }),
    )
    api.certificateApprovalManifest.mockRejectedValue('aucune clé de sécurité n’a répondu')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    expect(screen.queryByText(command)).toBeNull()

    fireEvent.click(await screen.findByRole('button', { name: 'Lire la demande' }))
    await waitFor(() => expect(screen.getByText(command)).toBeTruthy())
    expect(screen.getByRole('button', { name: 'Copier approbation' })).toBeTruthy()
  })

  /** A committed renewal names the generation, and nothing to run. */
  it('reports a committed renewal by its generation', async () => {
    api.certificateOverview.mockResolvedValue([
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
    api.runCertificateAction.mockResolvedValue(outcome({ step: 'committed', generation: 5 }))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    await waitFor(() => expect(screen.getByText('génération suivante')).toBeTruthy())
    expect(screen.getByText('5')).toBeTruthy()
    expect(screen.queryByText(/astra-signer/)).toBeNull()
  })

  /**
   * A refused press drops the step it followed. Leaving it on screen beside
   * the new error would show one renewal as progressing and refused at once.
   */
  /**
   * The device-wide action advances every profile, and each waits on its own.
   *
   * Attributing the whole run to the profile the press started from was the
   * defect: five other renewals would have been opened with nothing on screen
   * saying so, and the approval each of them waits for would never have been
   * offered.
   */
  it('gives every profile its own place to wait after a fleet renewal', async () => {
    api.certificateOverview.mockResolvedValue([
      entry({ actions: [renewNow(), renewEvery()] }),
      entry({ name: 'bureau', actions: [renewNow(), renewEvery()] }),
    ])
    api.runCertificateAction.mockResolvedValue({
      progress: {
        portable: awaiting(),
        bureau: { ...awaiting(), operation_id: 'e'.repeat(32) },
      },
      refused: {},
    })
    render(<CertificatesView />)

    fireEvent.click(
      (
        await screen.findAllByRole('button', {
          name: 'Renouveler tous les profils Helios de cet appareil',
        })
      )[0],
    )

    await waitFor(() => expect(screen.getByText('f'.repeat(32))).toBeTruthy())
    expect(screen.getByText('e'.repeat(32))).toBeTruthy()
    expect(screen.getAllByRole('button', { name: 'Lire la demande' })).toHaveLength(2)
  })

  it('drops the previous step when a later press is refused', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValueOnce(outcome(awaiting()))
    render(<CertificatesView />)

    const button = await screen.findByRole('button', { name: 'Renouveler maintenant' })
    fireEvent.click(button)
    await waitFor(() => expect(screen.getByText('f'.repeat(32))).toBeTruthy())

    api.runCertificateAction.mockRejectedValue('la gateway a refusé')
    fireEvent.click(screen.getByRole('button', { name: 'Renouveler maintenant' }))
    await waitFor(() => expect(screen.queryByText('f'.repeat(32))).toBeNull())
  })
})
