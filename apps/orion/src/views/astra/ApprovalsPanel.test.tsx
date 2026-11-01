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
  beginIssuerCeremony: vi.fn(),
  operatorPendingOperations: vi.fn(),
  dismissOperatorCeremony: vi.fn(),
  operatorOverview: vi.fn(),
  operatorArtifacts: vi.fn(),
  operatorInvitations: vi.fn(),
  getState: vi.fn(),
  getConfig: vi.fn(),
}))
vi.mock('../../api', () => api)

import { AstraView } from '../AstraView'

const openApprovals = () => fireEvent.click(screen.getByRole('tab', { name: /Approbations/ }))

const overview = (authority: string | null) => ({
  vault_path: 'v.json',
  exists: true,
  location_available: true,
  bootstrapped: true,
  credentials_complete: true,
  vault_fingerprint: 'ab12',
  slots: [],
  max_slots: 8,
  domain: {
    trust_domain_id: 'td',
    rp_id: 'gw',
    ca_pq_fingerprint: 'ff',
    ca_epoch: 1,
    ca_tls_epoch: 1,
    ca_tls_present: true,
    server_name: 'gw',
    gateway_wg_public_key: 'KEY',
    astra_service_public_key: null,
    astra_service_key_epoch: null,
    astra_authority_url: authority,
  },
})

const campaign = (scope: string, id = 'c'.repeat(32)) => ({
  operation_id: id,
  scope,
  reason: 'déléguer Astra',
  requested_by: 'operator',
  target_count: 1,
  required_credentials: 1,
  campaign_fingerprint: 'a'.repeat(64),
  created_at: 1_800_000_000,
  expires_at: 1_800_000_300,
})

const status = (operation: string, gesture: unknown, extra: object = {}) => ({
  session_id: 's'.repeat(32),
  revision: 1,
  operation,
  operation_id: 'a'.repeat(32),
  remote: 'awaiting_operator',
  gesture,
  allowed: [],
  ...extra,
})

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorCeremonyStatus.mockResolvedValue(null)
  api.operatorPendingOperations.mockResolvedValue([])
  api.operatorArtifacts.mockResolvedValue([])
  api.operatorInvitations.mockResolvedValue([])
  api.getState.mockResolvedValue('down')
  api.getConfig.mockResolvedValue({ profiles: [], selected: null })
  api.operatorOverview.mockResolvedValue(overview(null))
  api.dismissOperatorCeremony.mockResolvedValue(undefined)
  api.astraCaTlsRotationStatus.mockResolvedValue({
    phase: 'idle',
    message: '',
    can_continue: false,
    can_cancel: false,
  })
})
afterEach(cleanup)

const recoveryButton = () => {
  const buttons = screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })
  return buttons[buttons.length - 1]
}

describe('the recovery block', () => {
  it('a_recovery_id_is_normalised_or_refused', async () => {
    api.beginOperatorCeremony.mockResolvedValue(status('recover_identity', 'verifying'))
    render(<AstraView />)
    openApprovals()
    const field = await screen.findByLabelText('Identifiant d’opération')
    for (const bad of ['a'.repeat(31), 'a'.repeat(33), 'g'.repeat(32), '']) {
      fireEvent.change(field, { target: { value: bad } })
      expect(recoveryButton().hasAttribute('disabled')).toBe(true)
    }
    fireEvent.change(field, { target: { value: `  ${'ABCDEF0123456789'.repeat(2)}  ` } })
    expect(recoveryButton().hasAttribute('disabled')).toBe(false)
    fireEvent.click(recoveryButton())
    await waitFor(() =>
      expect(api.beginOperatorCeremony).toHaveBeenCalledWith({
        kind: 'recover_identity',
        operation_id: 'abcdef0123456789'.repeat(2),
      }),
    )
  })

  it('a_remote_recovery_is_not_finished_here', async () => {
    api.beginOperatorCeremony.mockResolvedValue(status('recover_identity', 'done'))
    const onRecoveryReady = vi.fn().mockResolvedValue(undefined)
    render(<AstraView onRecoveryReady={onRecoveryReady} />)
    openApprovals()
    fireEvent.change(await screen.findByLabelText('Identifiant d’opération'), {
      target: { value: 'a'.repeat(32) },
    })
    fireEvent.click(recoveryButton())
    expect(
      await screen.findByText('Récupération approuvée. Le poste concerné reprend de son côté.'),
    ).toBeTruthy()
    expect(onRecoveryReady).not.toHaveBeenCalled()
  })
})

describe('a recovery that belongs to another machine', () => {
  const sentence = 'Récupération approuvée. Le poste concerné reprend de son côté.'
  const recovery = (gesture: unknown) => status('recover_identity', gesture, { remote: 'granted' })

  it('is_never_finished_here_when_the_view_remounts_while_open_then_done', async () => {
    const onRecoveryReady = vi.fn().mockResolvedValue(undefined)
    api.operatorCeremonyStatus.mockResolvedValue(
      recovery({ awaiting_key: { index: 1, of: 1, purpose: 'open_vault' } }),
    )
    const first = render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={null} />)
    await screen.findByText(/Brancher la clé autorisée/)
    first.unmount()

    api.operatorCeremonyStatus.mockResolvedValue(recovery('done'))
    render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={null} />)
    expect(await screen.findByText(sentence)).toBeTruthy()
    expect(onRecoveryReady).not.toHaveBeenCalled()
  })

  it('is_never_finished_here_when_it_is_done_before_the_view_remounts', async () => {
    const onRecoveryReady = vi.fn().mockResolvedValue(undefined)
    api.operatorCeremonyStatus.mockResolvedValue(recovery('done'))
    const first = render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={null} />)
    await screen.findByText(sentence)
    first.unmount()

    render(
      <AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={'b'.repeat(32)} />,
    )
    expect(await screen.findByText(sentence)).toBeTruthy()
    expect(onRecoveryReady).not.toHaveBeenCalled()
  })

  it('a_recovery_opened_here_still_finishes_locally_and_has_no_remote_sentence', async () => {
    const onRecoveryReady = vi.fn().mockResolvedValue(undefined)
    api.operatorCeremonyStatus.mockResolvedValue(recovery('done'))
    render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={'a'.repeat(32)} />)
    await waitFor(() => expect(onRecoveryReady).toHaveBeenCalledWith('a'.repeat(32)))
    expect(screen.queryByText(sentence)).toBeNull()
  })
})

describe('the delegation', () => {
  it('an_issuer_campaign_asks_for_the_request_file', async () => {
    api.operatorPendingOperations.mockResolvedValue([campaign('issuer_delegation')])
    api.beginIssuerCeremony.mockResolvedValue(status('authorize_issuer', 'verifying'))
    render(<AstraView />)
    openApprovals()
    await screen.findByText('déléguer Astra')
    const [open] = screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })
    expect(open.hasAttribute('disabled')).toBe(false)
    fireEvent.click(open)
    expect(api.beginIssuerCeremony).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Choisir la demande de délégation…' })).toBeTruthy()
    const file = new File(['{"request":1}'], 'delegation.json', { type: 'application/json' })
    fireEvent.change(screen.getByLabelText('Demande de délégation'), { target: { files: [file] } })
    await waitFor(() =>
      expect(api.beginIssuerCeremony).toHaveBeenCalledWith({
        gesture: 'authorize_issuer',
        operation_id: 'c'.repeat(32),
        request: '{"request":1}',
      }),
    )
  })

  it('a_request_file_that_is_too_large_opens_nothing', async () => {
    api.operatorPendingOperations.mockResolvedValue([campaign('issuer_delegation')])
    render(<AstraView />)
    openApprovals()
    await screen.findByText('déléguer Astra')
    const [open] = screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })
    fireEvent.click(open)
    const file = new File(['x'.repeat(256 * 1024 + 1)], 'big.json')
    fireEvent.change(screen.getByLabelText('Demande de délégation'), { target: { files: [file] } })
    expect(
      await screen.findByText('Ce fichier est illisible ou trop grand (256 Kio au plus).'),
    ).toBeTruthy()
    expect(api.beginIssuerCeremony).not.toHaveBeenCalled()
  })

  it('a_full_chain_campaign_can_be_opened', async () => {
    api.operatorPendingOperations.mockResolvedValue([campaign('full_certificate_chain')])
    api.beginOperatorCeremony.mockResolvedValue(status('approve_campaign', 'verifying'))
    render(<AstraView />)
    openApprovals()
    await screen.findByText('déléguer Astra')
    const [open] = screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })
    expect(open.hasAttribute('disabled')).toBe(false)
    fireEvent.click(open)
    await waitFor(() =>
      expect(api.beginOperatorCeremony).toHaveBeenCalledWith({
        kind: 'approve_campaign',
        operation_id: 'c'.repeat(32),
      }),
    )
  })

  it('the_offline_delegation_is_offered_only_without_an_origin', async () => {
    api.beginIssuerCeremony.mockResolvedValue(status('authorize_issuer', 'verifying'))
    const { unmount } = render(<AstraView />)
    openApprovals()
    expect(await screen.findByText(/Rien ne rattache ce fichier à Astra/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Signer une délégation sans campagne…' }))
    const file = new File(['REQ'], 'r.json')
    fireEvent.change(screen.getByLabelText('Demande de délégation sans campagne'), {
      target: { files: [file] },
    })
    await waitFor(() =>
      expect(api.beginIssuerCeremony).toHaveBeenCalledWith({
        gesture: 'authorize_issuer_offline',
        request: 'REQ',
      }),
    )
    unmount()

    api.operatorOverview.mockResolvedValue(overview('https://astra.example'))
    render(<AstraView />)
    openApprovals()
    expect(await screen.findByText(/Ce domaine a une origine Astra/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Signer une délégation sans campagne/ })).toBeNull()
    expect(screen.queryByText(/Rien ne rattache ce fichier/)).toBeNull()
  })

  it('the_offline_delegation_ends_on_its_file_and_the_install_command', async () => {
    api.operatorCeremonyStatus.mockResolvedValue(status('authorize_issuer', 'done'))
    api.operatorArtifacts.mockResolvedValue([
      { file_name: 'issuer-authorization.json', encoding: 'text', contents: '{}' },
    ])
    render(<AstraView />)
    expect(
      await screen.findByRole('button', { name: 'Enregistrer issuer-authorization.json' }),
    ).toBeTruthy()
    expect(
      screen.getByText(
        'À installer sur l’hôte d’Astra : astra issuer install --authorization <fichier>.',
      ),
    ).toBeTruthy()
  })
})
