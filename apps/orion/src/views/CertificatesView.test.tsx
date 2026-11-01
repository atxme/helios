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
    operator_credentials: null,
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

/** The verified request, as the shell hands it over before any touch. */
const manifest = (overrides: Record<string, unknown> = {}) => ({
  operation_id: 'f'.repeat(32),
  client_wg_public_key: 'Zm9vYmFy'.repeat(4),
  active_generation: 4,
  requested_generation: 5,
  request_fingerprint: 'c'.repeat(64),
  expires_at: 1_800_000_000,
  eligible_credentials: 2,
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
  api.certificateApprovalManifest.mockResolvedValue(manifest())
  api.certificateApprovalNeedsPin.mockResolvedValue(false)
  api.approveCertificateRenewal.mockResolvedValue({ step: 'committed', generation: 5 })
  api.runCertificateAction.mockResolvedValue(
    outcome({ step: 'awaiting_operator', operation_id: 'f'.repeat(32) }),
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

  /** The request is read as the step appears: no button stands between them. */
  it('the_request_is_read_when_an_operator_is_awaited', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    await waitFor(() =>
      expect(api.certificateApprovalManifest).toHaveBeenCalledWith('portable'),
    )
    expect(await screen.findByText('4 → 5')).toBeTruthy()
    expect(api.certificateApprovalNeedsPin).toHaveBeenCalledWith('portable')
    expect(screen.queryByRole('button', { name: 'Lire la demande d’approbation' })).toBeNull()
    expect(api.certificateApprovalManifest).toHaveBeenCalledOnce()
  })

  /** Reading shows its own state, and a failed read can be redone. */
  it('says the request is being read, then offers to read it again after a failure', async () => {
    let fail: (cause: string) => void = () => {}
    api.certificateApprovalManifest.mockReturnValueOnce(
      new Promise((_resolve, reject) => {
        fail = reject
      }),
    )
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    expect(await screen.findByText('Lecture de la demande…')).toBeTruthy()
    fail('la gateway ne répond pas')
    expect(await screen.findByText(/la gateway ne répond pas/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Relire la demande' }))
    expect(await screen.findByText('4 → 5')).toBeTruthy()
    expect(api.certificateApprovalManifest).toHaveBeenCalledTimes(2)
  })

  /** The companion is gone: nothing is launched and nothing names it. */
  it('no_companion_is_launched', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    const { container } = render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    await screen.findByText('4 → 5')

    // The api module is mocked whole and has no launcher left to call.
    expect('launchCertificateCompanion' in api).toBe(false)
    expect(container.textContent?.toLowerCase()).not.toContain('compagnon')
    expect(screen.queryByRole('button', { name: /compagnon/i })).toBeNull()
  })

  /**
   * An ordinary renewal belongs to the peer that opened it: the fallback says
   * so and names no command.
   */
  it('the_other_workstation_note_names_no_command', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    const { container } = render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'La clé est sur un autre poste ?' }))

    expect(
      screen.getByText(
        'Cette approbation se fait sur ce poste : la gateway n’accepte la réponse que du poste qui a demandé le renouvellement. Branchez ici la clé d’un opérateur.',
      ),
    ).toBeTruthy()
    expect(container.textContent).not.toContain('astra-signer')
  })

  it('the_recovery_note_gives_the_identifier_and_the_operator_path', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(
      outcome({ step: 'recovery_awaiting_operator', operation_id: 'd'.repeat(32) }),
    )
    const { container } = render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'La clé est sur un autre poste ?' }))

    expect(screen.getByText('d'.repeat(32))).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Copier opération' })).toBeTruthy()
    expect(
      screen.getByText(
        'Sur le poste de l’opérateur : Astra › Approbations › « Approuver une récupération », avec cet identifiant. Puis relancez « Récupérer le certificat expiré » ici.',
      ),
    ).toBeTruthy()
    expect(container.textContent).not.toContain('astra-signer')
    expect(api.certificateApprovalManifest).not.toHaveBeenCalled()
  })

  /** Epoch and recovery are local facts; no registry fetch is implied. */
  it('shows the credential epoch and the reason recovery is unavailable', async () => {
    api.certificateOverview.mockResolvedValue([
      entry({
        inventory: {
          ...entry().inventory,
          operator_credentials: { registry_epoch: 7, detail: 'epoch_only', credentials: [] },
        },
        actions: [
          {
            action: 'recover_expired',
            label: 'Récupérer le certificat expiré',
            blocked_by: { kind: 'nothing_expired' },
            message: 'Aucun certificat client n’est expiré.',
          },
        ],
      }),
    ])
    render(<CertificatesView />)

    expect(await screen.findByText('registre époque 7')).toBeTruthy()
    expect(screen.getByText('indisponible')).toBeTruthy()
    expect(screen.getByText('Aucun certificat client n’est expiré.')).toBeTruthy()
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

  it('shows the recovery committed while the Astra view was open', async () => {
    api.certificateOverview.mockResolvedValue([entry()])
    const activationAt = 1_789_198_911

    render(
      <CertificatesView
        completedRecovery={{
          portable: { step: 'recovered', generation: 5, activation_at: activationAt },
        }}
      />,
    )

    expect(await screen.findByText('génération suivante')).toBeTruthy()
    expect(screen.getByText('5')).toBeTruthy()
    expect(screen.getByText(/Identité récupérée et commitée/)).toBeTruthy()
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
    await waitFor(() => expect(api.certificateApprovalManifest).toHaveBeenCalledTimes(2))
  })

  /**
   * What is signed is what was shown: the fields come from the verified
   * request, and nothing can be signed before they are on screen.
   */
  it('shows the verified request before offering the key', async () => {
    let release: (value: unknown) => void = () => {}
    api.certificateApprovalManifest.mockReturnValueOnce(
      new Promise((resolve) => {
        release = resolve
      }),
    )
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    await screen.findByText('Lecture de la demande…')
    expect(screen.queryByRole('button', { name: 'Approuver avec la clé' })).toBeNull()

    release(manifest())
    expect(await screen.findByText('4 → 5')).toBeTruthy()
    expect(screen.getByText('c'.repeat(64))).toBeTruthy()
    expect(screen.getByText('2 clés du domaine peuvent répondre')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Approuver avec la clé' })).toBeTruthy()
  })

  /** One touch, on this machine, and the step the renewal reached comes back. */
  it('runs the ceremony on this machine and reports where the renewal landed', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approuver avec la clé' }))

    await waitFor(() =>
      expect(api.approveCertificateRenewal).toHaveBeenCalledWith('portable', undefined),
    )
    expect(await screen.findByText('génération suivante')).toBeTruthy()
    // The verified request is consumed: a second touch is not offered.
    expect(screen.queryByRole('button', { name: 'Approuver avec la clé' })).toBeNull()
  })

  /** Asked, never assumed: the platform dialog collects it on Windows. */
  it('asks for a PIN only when the key does not collect one itself', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.certificateApprovalNeedsPin.mockResolvedValue(true)
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    const field = await screen.findByLabelText('PIN de la clé')
    // An empty PIN would spend the ceremony on a refusal the key answers with.
    expect(
      screen.getByRole('button', { name: 'Approuver avec la clé' }).hasAttribute('disabled'),
    ).toBe(true)
    fireEvent.change(field, { target: { value: '1234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Approuver avec la clé' }))

    await waitFor(() =>
      expect(api.approveCertificateRenewal).toHaveBeenCalledWith('portable', '1234'),
    )
  })

  /** A key that cannot be probed must not hide the request it would approve. */
  it('keeps the request shown when the PIN probe fails', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.certificateApprovalNeedsPin.mockRejectedValue('no key')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    expect(await screen.findByText('4 → 5')).toBeTruthy()
    expect(await screen.findByText(/no key/)).toBeTruthy()
  })

  /** A touch nobody's key can answer is a touch not worth asking for. */
  it('offers no touch when no credential of the domain may answer', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.certificateApprovalManifest.mockResolvedValue(manifest({ eligible_credentials: 0 }))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))

    expect(
      await screen.findByText(/Aucune clé du domaine n’est autorisée à répondre/),
    ).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Approuver avec la clé' })).toBeNull()
    // And the other door stays open: the key may be elsewhere.
    expect(screen.getByRole('button', { name: 'La clé est sur un autre poste ?' })).toBeTruthy()
  })

  /**
   * The request is consumed only at the deposit, so a key that was absent is
   * retried with one click and without reading again. « Relire la demande » sits
   * next to it for a retry the engine refuses.
   */
  it('a_failed_approval_can_be_retried_without_reading_again', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.approveCertificateRenewal.mockRejectedValueOnce('aucune clé détectée')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approuver avec la clé' }))

    expect(await screen.findByText(/aucune clé détectée/)).toBeTruthy()
    // The manifest stays, the button is live again, and re-reading is offered.
    expect(screen.getByText('4 → 5')).toBeTruthy()
    const retry = screen.getByRole('button', { name: 'Approuver avec la clé' })
    expect(retry.hasAttribute('disabled')).toBe(false)
    expect(screen.getByRole('button', { name: 'Relire la demande' })).toBeTruthy()

    fireEvent.click(retry)
    expect(await screen.findByText('génération suivante')).toBeTruthy()
    expect(api.approveCertificateRenewal).toHaveBeenCalledTimes(2)
    expect(api.certificateApprovalManifest).toHaveBeenCalledOnce()
  })

  /** A retry refused for a consumed request is answered by reading again. */
  it('a_failed_approval_can_be_read_again', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.approveCertificateRenewal.mockRejectedValueOnce('lire d’abord la demande d’approbation')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approuver avec la clé' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Relire la demande' }))

    await waitFor(() => expect(api.certificateApprovalManifest).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.queryByText(/lire d’abord/)).toBeNull())
    expect(screen.getByRole('button', { name: 'Approuver avec la clé' })).toBeTruthy()
  })

  it('a_new_operation_id_triggers_a_new_read_and_a_same_id_rerender_does_not', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValueOnce(outcome(awaiting()))
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    await screen.findByText('4 → 5')
    // Same operation again: the step is re-rendered, not re-read.
    api.runCertificateAction.mockResolvedValueOnce(outcome(awaiting()))
    fireEvent.click(screen.getByRole('button', { name: 'Renouveler maintenant' }))
    await waitFor(() => expect(api.runCertificateAction).toHaveBeenCalledTimes(2))
    await screen.findByText('4 → 5')
    expect(api.certificateApprovalManifest).toHaveBeenCalledOnce()

    api.certificateApprovalManifest.mockResolvedValueOnce(manifest({ requested_generation: 9 }))
    api.runCertificateAction.mockResolvedValueOnce(
      outcome({ ...awaiting(), operation_id: 'e'.repeat(32) }),
    )
    fireEvent.click(screen.getByRole('button', { name: 'Renouveler maintenant' }))
    expect(await screen.findByText('4 → 9')).toBeTruthy()
    expect(api.certificateApprovalManifest).toHaveBeenCalledTimes(2)
  })

  it('a_failed_reread_leaves_nothing_approvable', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.approveCertificateRenewal.mockRejectedValueOnce('aucune clé détectée')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Approuver avec la clé' }))
    const again = await screen.findByRole('button', { name: 'Relire la demande' })
    api.certificateApprovalManifest.mockRejectedValueOnce('la gateway ne répond pas')
    fireEvent.click(again)

    expect(await screen.findByText(/la gateway ne répond pas/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Approuver avec la clé' })).toBeNull()
    expect(screen.queryByText('4 → 5')).toBeNull()
  })

  it('clears_the_pin_after_a_failed_approval', async () => {
    api.certificateOverview.mockResolvedValue([entry({ actions: [renewNow()] })])
    api.runCertificateAction.mockResolvedValue(outcome(awaiting()))
    api.certificateApprovalNeedsPin.mockResolvedValue(true)
    api.approveCertificateRenewal.mockRejectedValueOnce('PIN erroné')
    render(<CertificatesView />)

    fireEvent.click(await screen.findByRole('button', { name: 'Renouveler maintenant' }))
    fireEvent.change(await screen.findByLabelText('PIN de la clé'), { target: { value: '1234' } })
    fireEvent.click(screen.getByRole('button', { name: 'Approuver avec la clé' }))

    expect(await screen.findByText(/PIN erroné/)).toBeTruthy()
    expect((screen.getByLabelText('PIN de la clé') as HTMLInputElement).value).toBe('')
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
