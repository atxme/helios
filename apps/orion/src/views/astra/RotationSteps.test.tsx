// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  advanceOperatorCeremony: vi.fn(),
  approveRotationCeremony: vi.fn(),
  beginRotationCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import type {
  CaRotationManifest,
  KeyPurpose,
  OperatorPendingOperation,
  OperatorStatus,
  Refusal,
  RotationJournalView,
} from '../../types'
import { RotationCeremony, RotationSteps, isRotationStatus } from './RotationSteps'
import { NOW, overview } from './rotationFixtures'

const EXISTING = 'c'.repeat(32)

const awaiting = (index: number, purpose: KeyPurpose = 'validate_key') => ({
  awaiting_key: { index, of: 2, purpose },
})

const status = (extra: Partial<OperatorStatus> = {}): OperatorStatus => ({
  session_id: 's',
  revision: 3,
  operation: 'rotate_anchor',
  remote: 'local',
  gesture: awaiting(1),
  allowed: ['continue', 'cancel'],
  ...extra,
})

const first = { slot: '1', label: 'YubiKey bureau' }
const second = { slot: '2', label: 'YubiKey coffre' }

/** Both keys validated: the approval screen is what the ceremony waits on. */
const approval = (extra: Partial<OperatorStatus> = {}) =>
  status({ gesture: 'idle', allowed: ['cancel'], keys: [first, second], ...extra })

const manifest = (extra: Partial<CaRotationManifest> = {}): CaRotationManifest => ({
  operation: 'ca_rotation',
  trust_domain_id: 'td',
  affected_ca: 'ca_pq',
  current_epoch: 3,
  next_epoch: 4,
  activation_at: NOW + 7 * 86_400,
  not_after: NOW + 37 * 86_400,
  outgoing_anchor_fingerprint: 'aa'.repeat(32),
  ...extra,
})

const journal = (extra: Partial<RotationJournalView> = {}): RotationJournalView => ({
  kind: 'ca_pq',
  stage: 'installed',
  activationAt: NOW + 7 * 86_400,
  notAfter: NOW + 37 * 86_400,
  nextFingerprint: 'bb'.repeat(32),
  offline: false,
  ...extra,
})

const shown = (
  current: OperatorStatus,
  extra: Partial<React.ComponentProps<typeof RotationCeremony>> = {},
) => {
  const onStatus = vi.fn()
  const onDismiss = vi.fn()
  const view = render(
    <RotationCeremony
      status={current}
      onStatus={onStatus}
      onDismiss={onDismiss}
      journal={null}
      existingOperation={null}
      now={NOW}
      {...extra}
    />,
  )
  return { onStatus, onDismiss, ...view }
}

const row = (name: string) => within(screen.getByRole('listitem', { name }))
const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement

beforeEach(() => {
  vi.clearAllMocks()
})
afterEach(cleanup)

describe('the key step', () => {
  it('keys validate one after the other with their state', async () => {
    const { onStatus, rerender, ...rest } = shown(status())
    expect(row('Clé 1').getByText('À valider')).toBeTruthy()
    expect(row('Clé 2').getByText('En attente')).toBeTruthy()
    const next = status({ revision: 4, gesture: awaiting(2), keys: [first] })
    api.advanceOperatorCeremony.mockResolvedValue(next)
    fireEvent.click(button('Valider'))
    await waitFor(() => expect(onStatus).toHaveBeenCalledWith(next))
    expect(api.advanceOperatorCeremony).toHaveBeenCalledWith('continue', 3)

    rerender(
      <RotationCeremony
        status={next}
        onStatus={onStatus}
        onDismiss={rest.onDismiss}
        journal={null}
        existingOperation={null}
        now={NOW}
      />,
    )
    expect(row('Clé 1').getByText('✓ Validée')).toBeTruthy()
    expect(row('Clé 1').getByText('YubiKey bureau')).toBeTruthy()
    expect(row('Clé 2').getByText('À valider')).toBeTruthy()
  })

  it('a repeated key offers retry and keeps key 1', () => {
    shown(
      status({
        revision: 5,
        gesture: awaiting(2),
        keys: [first],
        key_retry: { refusal: 'key_repeated' },
      }),
    )
    expect(row('Clé 1').getByText('✓ Validée')).toBeTruthy()
    expect(row('Clé 2').getByText('Même clé que la clé 1')).toBeTruthy()
    expect(row('Clé 2').getByRole('button', { name: 'Réessayer' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Valider' })).toBeNull()
  })

  it('names why a key was turned down', () => {
    const reasons: [Refusal, string][] = [
      [{ refusal: 'key_not_enrolled' }, 'Clé absente du coffre'],
      [{ refusal: 'key_not_validated' }, 'Autre clé attendue'],
      [{ refusal: 'key_declined' }, 'Clé sans réponse'],
    ]
    for (const [retry, label] of reasons) {
      const { unmount } = shown(status({ key_retry: retry }))
      expect(row('Clé 1').getByText(label)).toBeTruthy()
      expect(row('Clé 1').getByRole('button', { name: 'Réessayer' })).toBeTruthy()
      unmount()
    }
  })

  it('continue stays disabled until both are valid', () => {
    const { unmount } = shown(status({ gesture: awaiting(2), keys: [first] }))
    expect(button('Continuer').disabled).toBe(true)
    unmount()
    shown(approval())
    expect(button('Continuer').disabled).toBe(false)
  })

  it('offers no cancel while a key dialog is open', () => {
    shown(status({ gesture: { processing_key: { index: 1, of: 2 } }, allowed: [] }))
    expect(screen.queryByRole('button', { name: 'Annuler' })).toBeNull()
  })

  it('cancels from the touch screen through the offered action', async () => {
    const { onStatus } = shown(status())
    api.advanceOperatorCeremony.mockResolvedValue(status({ gesture: 'cancelled' }))
    fireEvent.click(button('Annuler'))
    await waitFor(() => expect(onStatus).toHaveBeenCalled())
    expect(api.advanceOperatorCeremony).toHaveBeenCalledWith('cancel', 3)
  })
})

describe('the approval', () => {
  const toApproval = () => {
    fireEvent.click(button('Continuer'))
  }

  it('the campaign opens at Approuver and not before', async () => {
    const { onStatus } = shown(approval())
    toApproval()
    expect(api.approveRotationCeremony).not.toHaveBeenCalled()
    expect(screen.getByText('Garder la clé 2 branchée')).toBeTruthy()
    const next = status({ gesture: 'verifying', keys: [first, second] })
    api.approveRotationCeremony.mockResolvedValue(next)
    fireEvent.click(button('Approuver'))
    await waitFor(() => expect(onStatus).toHaveBeenCalledWith(next))
    expect(api.approveRotationCeremony).toHaveBeenCalledWith(
      {
        existing_operation: null,
        reason: 'Remplacement de la CA-PQ',
        requested_by: 'YubiKey bureau',
        prepare_days: 7,
        overlap_days: 30,
        validity_days: 1825,
      },
      3,
    )
  })

  it('names the action and keeps both keys in view', () => {
    shown(approval({ operation: 'rotate_client_tls_ca' }))
    toApproval()
    expect(screen.getByText('Remplacer la CA TLS')).toBeTruthy()
    expect(screen.getByDisplayValue('Remplacement de la CA TLS')).toBeTruthy()
    expect(screen.getByText('YubiKey coffre')).toBeTruthy()
  })

  it('durations are folded and refuse less than one day', () => {
    shown(approval())
    toApproval()
    expect(screen.queryByLabelText('Préparation (jours)')).toBeNull()
    fireEvent.click(button('Modifier'))
    fireEvent.change(screen.getByLabelText('Préparation (jours)'), { target: { value: '0' } })
    fireEvent.click(button('Approuver'))
    expect(api.approveRotationCeremony).not.toHaveBeenCalled()
    expect(screen.getByText('Préparation : 1 jour au moins')).toBeTruthy()
  })

  it('sends the durations that were edited', async () => {
    shown(approval())
    toApproval()
    fireEvent.click(button('Modifier'))
    fireEvent.change(screen.getByLabelText('Préparation (jours)'), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('Recouvrement (jours)'), { target: { value: '10' } })
    api.approveRotationCeremony.mockResolvedValue(status())
    fireEvent.click(button('Approuver'))
    await waitFor(() => expect(api.approveRotationCeremony).toHaveBeenCalled())
    expect(api.approveRotationCeremony.mock.calls[0][0]).toMatchObject({
      prepare_days: 2,
      overlap_days: 10,
    })
  })

  it('reason over 1024 chars is refused before the call', () => {
    shown(approval())
    toApproval()
    fireEvent.change(screen.getByLabelText('Motif'), { target: { value: 'x'.repeat(1025) } })
    fireEvent.click(button('Approuver'))
    expect(api.approveRotationCeremony).not.toHaveBeenCalled()
    expect(screen.getByText('Motif : 1024 caractères au plus')).toBeTruthy()
  })

  it('terms refused for being too long keep both keys and ask for no touch', async () => {
    const { rerender, onStatus, onDismiss } = shown(approval())
    toApproval()
    fireEvent.click(button('Modifier'))
    fireEvent.change(screen.getByLabelText('Préparation (jours)'), { target: { value: '99999' } })
    api.approveRotationCeremony.mockResolvedValue(approval())
    fireEvent.click(button('Approuver'))
    await waitFor(() => expect(api.approveRotationCeremony).toHaveBeenCalled())

    // The ceremony published the screen again with the reason; the keys are still held.
    rerender(
      <RotationCeremony
        status={approval({ revision: 4, key_retry: { refusal: 'terms_refused' } })}
        onStatus={onStatus}
        onDismiss={onDismiss}
        journal={null}
        existingOperation={null}
        now={NOW}
      />,
    )
    expect(screen.getByText('Durées hors limites')).toBeTruthy()
    expect(screen.getByText('YubiKey bureau')).toBeTruthy()
    expect(screen.getByText('YubiKey coffre')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Valider' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Réessayer' })).toBeNull()
    expect((button('Approuver') as HTMLButtonElement).disabled).toBe(false)
    expect(api.advanceOperatorCeremony).not.toHaveBeenCalled()
  })

  it('an already open operation is offered instead of an error', async () => {
    shown(approval(), { existingOperation: EXISTING, existingExpiresAt: NOW + 20 })
    toApproval()
    expect(screen.getByText('Opération ouverte')).toBeTruthy()
    expect(screen.getByText(/^Ouverte jusqu’au /)).toBeTruthy()
    // Its reason is the campaign's own: none is asked here.
    expect(screen.queryByLabelText('Motif')).toBeNull()
    api.approveRotationCeremony.mockResolvedValue(status())
    fireEvent.click(button('Approuver'))
    await waitFor(() => expect(api.approveRotationCeremony).toHaveBeenCalled())
    expect(api.approveRotationCeremony.mock.calls[0][0].existing_operation).toBe(EXISTING)
  })

  it('shows the screen once the keys are validated and not the touch rows', () => {
    shown(approval())
    toApproval()
    expect(screen.queryByText('À valider')).toBeNull()
  })

  it('cancels from the approval screen', async () => {
    shown(approval())
    toApproval()
    api.advanceOperatorCeremony.mockResolvedValue(status({ gesture: 'cancelled' }))
    fireEvent.click(button('Annuler'))
    await waitFor(() => expect(api.advanceOperatorCeremony).toHaveBeenCalledWith('cancel', 3))
  })
})

describe('the approval touches and the signature', () => {
  const touching = (extra: Partial<OperatorStatus> = {}) =>
    status({
      gesture: awaiting(1, 'approve_campaign'),
      remote: 'awaiting_operator',
      operation_id: EXISTING,
      keys: [first, second],
      manifest: manifest(),
      ...extra,
    })

  it('lists what the touch signs and every key still to touch', () => {
    shown(touching())
    expect(row('Clé 1').getByText('Brancher et toucher la clé')).toBeTruthy()
    expect(row('Clé 2').getByText('Brancher et toucher la clé')).toBeTruthy()
    expect(screen.getByText('autorité visée')).toBeTruthy()
    expect(screen.getByText('époque')).toBeTruthy()
  })

  it('names the key that approved and the one to plug in next', () => {
    shown(touching({ gesture: awaiting(2, 'approve_campaign'), approved: [{ slot: '1', label: 'YubiKey coffre' }] }))
    expect(row('Clé 2').getByText('Approuvée')).toBeTruthy()
    expect(row('Clé 1').getByText('Brancher et toucher la clé')).toBeTruthy()
  })

  it('a key turned down at approval is named', () => {
    shown(
      touching({
        gesture: awaiting(2, 'approve_campaign'),
        approved: [{ slot: '1', label: 'YubiKey bureau' }],
        key_retry: { refusal: 'key_repeated' },
      }),
    )
    expect(row('Clé 1').getByText('Approuvée')).toBeTruthy()
    expect(screen.getByText('Clé déjà approuvée')).toBeTruthy()
  })

  it('says the signature is under way and asks for no touch', () => {
    shown(touching({ gesture: 'signing', allowed: [] }))
    expect(screen.getByText('Signature en cours')).toBeTruthy()
    expect(screen.queryByText('Brancher et toucher la clé')).toBeNull()
    expect(screen.queryByRole('button', { name: /Approuver/ })).toBeNull()
  })

  it('shows the incoming anchor right after signing', () => {
    shown(
      status({
        gesture: 'signing',
        remote: 'prepared',
        manifest: manifest({ next_anchor_fingerprint: 'cd'.repeat(32) }),
      }),
    )
    expect(screen.getByText('Empreinte entrante')).toBeTruthy()
    expect(screen.getAllByText('cdcd cdcd'.concat(' cdcd'.repeat(14))).length).toBeGreaterThan(0)
  })
})

describe('the follow-up', () => {
  const finished = (extra: Partial<OperatorStatus> = {}) =>
    status({
      gesture: 'done',
      remote: 'deposited',
      allowed: [],
      manifest: manifest({ next_anchor_fingerprint: 'cd'.repeat(32) }),
      ...extra,
    })

  it('the follow-up shows the install deadline until installed', () => {
    shown(
      status({ gesture: 'signing', remote: 'prepared', allowed: [], manifest: manifest() }),
      { journal: journal({ stage: 'signed' }) },
    )
    expect(row('Signée').getByText('Fait')).toBeTruthy()
    expect(row('Déposée').getByText('À faire')).toBeTruthy()
    expect(screen.getByText(/^À installer avant le /)).toBeTruthy()
    expect(screen.getByText(/^Fin de rotation le /)).toBeTruthy()
  })

  it('a finished rotation drops the deadline and shows every step done', () => {
    shown(finished(), { journal: null })
    for (const name of ['Signée', 'Déposée', 'Installée sur la gateway', 'Copie du coffre']) {
      expect(row(name).getByText('Fait')).toBeTruthy()
    }
    expect(screen.queryByText(/^À installer avant le /)).toBeNull()
    expect(screen.getByText(/^Fin de rotation le /)).toBeTruthy()
  })

  it('a copy held back is pending and not finished', () => {
    shown(finished(), { journal: journal({ stage: 'installed' }) })
    expect(row('Installée sur la gateway').getByText('Fait')).toBeTruthy()
    expect(row('Copie du coffre').getByText('En attente')).toBeTruthy()
    expect(screen.queryByText('Rotation terminée')).toBeNull()
  })

  it('does not call the copy sent before the journal has been read again', () => {
    shown(finished(), { journal: undefined })
    expect(row('Copie du coffre').queryByText('Fait')).toBeNull()
  })

  it('reads the dates of a resumption from the journal', () => {
    shown(
      status({ gesture: 'idle', remote: 'deposited', allowed: [], keys: undefined }),
      { journal: journal({ stage: 'applied' }) },
    )
    expect(row('Signée').getByText('Fait')).toBeTruthy()
    expect(screen.getByText(/^À installer avant le /)).toBeTruthy()
    expect(screen.getByText('Empreinte entrante')).toBeTruthy()
  })

  it('each terminal refusal has its label', () => {
    const cases: [Refusal, RegExp][] = [
      [{ refusal: 'rotation_expired' }, /^Rotation expirée\. Recommencer/],
      [{ refusal: 'domain_conflict' }, /^Domaine en désaccord/],
      [{ refusal: 'authority_refused', status: 429 }, /^Trop d’opérations en attente$/],
      [{ refusal: 'authority_refused', status: 403 }, /^Opération déjà ouverte, ou poste non administrateur$/],
      [{ refusal: 'rotation_in_flight' }, /^Rotation en cours/],
    ]
    for (const [refusal, label] of cases) {
      const { unmount } = shown(status({ gesture: 'failed', allowed: [], refusal }))
      expect(screen.getByText(label)).toBeTruthy()
      unmount()
    }
  })

  it('Délai dépassé shows the cut date', () => {
    shown(
      status({
        gesture: 'failed',
        remote: 'prepared',
        allowed: [],
        refusal: { refusal: 'install_deadline_passed' },
        manifest: manifest(),
      }),
      { journal: journal({ stage: 'applied' }) },
    )
    const text = screen.getByText(/^Délai dépassé/).textContent ?? ''
    expect(text).toMatch(/Coupure le /)
    expect(text).toMatch(/Intervention manuelle requise/)
  })

  // Read from the journal and this clock alone, it may resume harmlessly: only the
  // resumption's own answer is a dead end.
  it('an install past activation with no refusal is to check, not blocking', () => {
    shown(finished({ gesture: 'idle', remote: 'deposited' }), {
      journal: journal({ stage: 'applied', activationAt: NOW - 60 * 86_400, notAfter: NOW - 30 * 86_400 }),
    })
    expect(screen.getByText('Délai d’installation passé : à vérifier à la connexion')).toBeTruthy()
    expect(screen.queryByText(/Intervention manuelle requise/)).toBeNull()
  })

  it('a gateway that cannot be reached says nothing of admission.txt', () => {
    shown(
      status({
        gesture: 'failed',
        remote: 'prepared',
        allowed: [],
        refusal: { refusal: 'gateway_unavailable' },
      }),
      { journal: journal({ stage: 'signed' }) },
    )
    expect(screen.getByText(/^Gateway injoignable/)).toBeTruthy()
    expect(document.body.textContent).not.toMatch(/admission\.txt/)
  })

  it('after a cancel past the opening the campaign is said to stay open', () => {
    shown(
      status({
        gesture: 'cancelled',
        remote: 'awaiting_operator',
        allowed: [],
        refusal: { refusal: 'cancelled' },
        manifest: manifest(),
      }),
    )
    expect(document.body.textContent).toMatch(/Campagne encore ouverte/)
    expect(document.body.textContent).not.toMatch(/Rien n’a quitté/)
    // Nothing was signed: no rotation is in flight, whatever the manifest's dates say.
    expect(screen.queryByRole('listitem', { name: 'Signée' })).toBeNull()
    expect(document.body.textContent).not.toMatch(/À installer avant/)
  })

  it('a replacement stopped during the touches is not a rotation in flight', () => {
    shown(
      status({
        gesture: 'failed',
        remote: 'awaiting_operator',
        allowed: [],
        refusal: { refusal: 'window_expired' },
        manifest: manifest(),
      }),
    )
    expect(screen.getByText('Campagne expirée')).toBeTruthy()
    expect(screen.queryByRole('listitem', { name: 'Installée sur la gateway' })).toBeNull()
  })

  it('finishing, cancelled or refused, never reads as a missed install deadline', () => {
    const finish = manifest({ affected_ca: 'ca_tls', activation_at: NOW - 40 * 86_400, campaign: undefined })
    for (const [gesture, refusal] of [
      ['cancelled', { refusal: 'cancelled' }],
      ['failed', { refusal: 'rotation_in_flight' }],
      ['failed', { refusal: 'domain_changed' }],
    ] as const) {
      const { unmount } = shown(
        status({
          operation: 'rotate_client_tls_ca',
          gesture,
          remote: 'local',
          allowed: [],
          refusal: refusal as Refusal,
          manifest: finish,
        }),
      )
      expect(document.body.textContent).not.toMatch(/Délai dépassé/)
      expect(screen.queryByRole('listitem', { name: 'Signée' })).toBeNull()
      unmount()
    }
  })

  it('a finished « Terminer » says so', () => {
    shown(
      status({
        operation: 'rotate_client_tls_ca',
        gesture: 'done',
        remote: 'local',
        allowed: [],
        manifest: manifest({ affected_ca: 'ca_tls', campaign: undefined }),
      }),
    )
    expect(screen.getByText('Rotation terminée')).toBeTruthy()
  })

  it('an expiry before any campaign exists is not worded as one', () => {
    shown(status({ gesture: 'failed', remote: 'local', allowed: [], refusal: { refusal: 'window_expired' } }))
    expect(screen.getByText(/^Délai écoulé/)).toBeTruthy()
    expect(screen.queryByText('Campagne expirée')).toBeNull()
  })

  it('a resumption that found nothing says so and names no kind', () => {
    shown(status({ gesture: 'done', remote: 'local', allowed: [], keys: undefined }), { journal: null })
    expect(screen.getByText('Rien à reprendre')).toBeTruthy()
    expect(screen.queryByText('Rotation terminée')).toBeNull()
    expect(screen.queryByText(/CA-PQ|CA TLS/)).toBeNull()
  })

  it('shows the end of the wait at the key step and at the terms', () => {
    const idle = Date.UTC(2027, 0, 15, 10, 0, 0) / 1000
    const { unmount } = shown(status({ idle_until: idle }))
    expect(screen.getByText(/^Délai jusqu’à \d{2}:\d{2}:\d{2}$/)).toBeTruthy()
    unmount()
    shown(approval({ idle_until: idle }))
    fireEvent.click(button('Continuer'))
    expect(screen.getByText(/^Délai jusqu’à \d{2}:\d{2}:\d{2}$/)).toBeTruthy()
  })

  it('shows no end when the status carries none', () => {
    shown(status())
    expect(screen.queryByText(/Délai jusqu’à/)).toBeNull()
  })

  it('offers the way back once it has ended', () => {
    const { onDismiss } = shown(finished())
    fireEvent.click(button('Retour aux opérations'))
    expect(onDismiss).toHaveBeenCalled()
  })
})

describe('the wording', () => {
  it('has no second person text and no sentences made of the helper', () => {
    shown(approval())
    fireEvent.click(button('Continuer'))
    expect(document.body.textContent ?? '').not.toMatch(/\b(tu|te|ton|ta|tes|toi)\b/i)
  })

  it('tells a rotation status from the others', () => {
    expect(isRotationStatus(status())).toBe(true)
    expect(isRotationStatus(status({ operation: 'rotate_client_tls_ca' }))).toBe(true)
    expect(isRotationStatus(status({ operation: 'approve_campaign' }))).toBe(false)
  })
})

describe('starting a rotation', () => {
  const pending = (): OperatorPendingOperation => ({
    operation_id: EXISTING,
    scope: 'trust_authorities',
    reason: 'ancres 2027',
    requested_by: 'christophe',
    target_count: 2,
    required_credentials: 2,
    campaign_fingerprint: 'a'.repeat(64),
    created_at: NOW,
    expires_at: NOW + 300,
  })

  const context = (extra: Partial<React.ComponentProps<typeof RotationSteps>> = {}) => {
    const onCeremony = vi.fn()
    const refresh = vi.fn().mockResolvedValue(overview())
    render(
      <RotationSteps
        action="replace_ca_pq"
        overview={overview()}
        existingOperation={null}
        operatorLabel="Clé 1"
        onCeremony={onCeremony}
        refresh={refresh}
        {...extra}
      />,
    )
    return { onCeremony, refresh }
  }

  it('reads pending before the key step and hands the ceremony over', async () => {
    api.beginRotationCeremony.mockResolvedValue(status())
    const { onCeremony, refresh } = context()
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(refresh).toHaveBeenCalled()
    expect(api.beginRotationCeremony).toHaveBeenCalledWith({ gesture: 'replace_ca_pq' })
    expect(onCeremony).toHaveBeenCalledWith(status(), null)
  })

  it('an operation open elsewhere is offered and carried to the approval', async () => {
    api.beginRotationCeremony.mockResolvedValue(status())
    const { onCeremony } = context({
      existingOperation: pending(),
      refresh: vi
        .fn()
        .mockResolvedValue(overview({ pending: { state: 'ok', value: [pending()] } })),
    })
    expect(screen.getByText(/ancres 2027/)).toBeTruthy()
    fireEvent.click(button('Reprendre l’opération ouverte'))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(onCeremony).toHaveBeenCalledWith(status(), EXISTING)
  })

  it('an operation that opened since the last poll is found by the read', async () => {
    api.beginRotationCeremony.mockResolvedValue(status())
    const { onCeremony } = context({
      refresh: vi
        .fn()
        .mockResolvedValue(overview({ pending: { state: 'ok', value: [pending()] } })),
    })
    fireEvent.click(button('Continuer'))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status(), EXISTING))
  })

  it('does not start when pending cannot be read', async () => {
    const { onCeremony } = context({
      refresh: vi.fn().mockResolvedValue(overview({ pending: { state: 'unreachable' } })),
    })
    fireEvent.click(button('Continuer'))
    expect(await screen.findByText('Opérations non lues')).toBeTruthy()
    expect(api.beginRotationCeremony).not.toHaveBeenCalled()
    expect(onCeremony).not.toHaveBeenCalled()
  })

  it('finish and resume open their gesture with no pending read', async () => {
    api.beginRotationCeremony.mockResolvedValue(status())
    const finish = context({ action: 'finish_ca_tls' })
    fireEvent.click(button('Terminer'))
    await waitFor(() => expect(finish.onCeremony).toHaveBeenCalled())
    expect(api.beginRotationCeremony).toHaveBeenCalledWith({ gesture: 'finish_ca_tls' })
    expect(finish.refresh).not.toHaveBeenCalled()
    cleanup()
    const resume = context({ action: 'resume' })
    fireEvent.click(button('Reprendre'))
    await waitFor(() => expect(resume.onCeremony).toHaveBeenCalled())
    expect(api.beginRotationCeremony).toHaveBeenLastCalledWith({ gesture: 'resume' })
  })

  it('shows the refusal of a ceremony that did not open', async () => {
    api.beginRotationCeremony.mockRejectedValue('une cérémonie opérateur est déjà ouverte')
    context()
    fireEvent.click(button('Continuer'))
    expect(await screen.findByText(/déjà ouverte/)).toBeTruthy()
  })
})
