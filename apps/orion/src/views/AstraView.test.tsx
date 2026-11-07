// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorCeremonyStatus: vi.fn(),
  advanceOperatorCeremony: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  operatorPendingOperations: vi.fn(),
  operatorRotationsOverview: vi.fn(),
  dismissOperatorCeremony: vi.fn(),
  operatorOverview: vi.fn(),
  operatorVaultLocation: vi.fn(),
  operatorDomainDefaults: vi.fn(),
  operatorInvitations: vi.fn(),
  operatorArtifacts: vi.fn(),
  beginVaultCeremony: vi.fn(),
  getState: vi.fn(),
  getConfig: vi.fn(),
  beginEnrollmentCeremony: vi.fn(),
}))
vi.mock('../api', () => api)

import { AstraView } from './AstraView'

const openTab = (name: string | RegExp) => fireEvent.click(screen.getByRole('tab', { name }))

const rotations = (extra: object = {}) => ({
  tunnel: true,
  pending: { state: 'ok', value: [] },
  authority: { state: 'unreachable' },
  domain: { state: 'unreachable' },
  vault: null,
  vaultError: null,
  localVaultFingerprint: null,
  localCaEpoch: null,
  localCaTlsEpoch: null,
  localCaTlsNotAfter: null,
  journal: null,
  resumable: false,
  caPqOverlap: false,
  caTlsCloseDue: false,
  caTlsCloseAt: null,
  ...extra,
})

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorCeremonyStatus.mockResolvedValue(null)
  api.operatorPendingOperations.mockResolvedValue([])
  api.operatorRotationsOverview.mockResolvedValue(rotations())
  api.operatorInvitations.mockResolvedValue([])
  api.operatorArtifacts.mockResolvedValue([])
  api.getState.mockResolvedValue('down')
  api.getConfig.mockResolvedValue({ profiles: [], selected: null })
  api.operatorOverview.mockResolvedValue({
    vault_path: 'C:\\astra\\vault.json',
    exists: false,
    location_available: true,
    bootstrapped: false,
    credentials_complete: false,
    vault_fingerprint: null,
    slots: [],
    max_slots: 8,
    domain: null,
  })
  api.operatorVaultLocation.mockResolvedValue({
    path: 'C:\\astra',
    is_default: true,
    picker_available: false,
    error: null,
  })
  api.operatorDomainDefaults.mockResolvedValue({ rp_id: null })
  api.dismissOperatorCeremony.mockResolvedValue(undefined)
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
    openTab('Gateways')
    expect(screen.getByText(/arrivera dans une prochaine version/)).toBeTruthy()
  })

  it('the_section_menu_fits_the_base_window_in_two_rows', () => {
    render(<AstraView />)
    const menu = screen.getByRole('tablist', { name: 'Sections Astra' })
    // A fixed three-column grid: the six sections take two rows whatever the
    // labels, and the menu never scrolls nor widens the view.
    expect(menu.style.gridTemplateColumns || getComputedStyle(menu).gridTemplateColumns).toBe(
      'repeat(3, minmax(0, 1fr))',
    )
    expect(screen.queryByRole('button', { name: /scroll/i })).toBeNull()
    openTab('Domaine')
    expect(screen.getByRole('tab', { name: 'Domaine' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: 'Enrôlement' }).getAttribute('aria-selected')).toBe('false')
  })

  it('the_enrolment_tab_is_the_default_and_offers_both_gestures', async () => {
    render(<AstraView />)
    expect(screen.getByRole('tab', { name: 'Enrôlement' }).getAttribute('aria-selected')).toBe('true')
    expect(await screen.findByText(/Aucun coffre opérateur/)).toBeTruthy()
    expect(screen.getByRole('button', { name: /Inviter un poste/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Accepter une demande/ })).toBeTruthy()
  })

  it('the_rotations_tab_lists_the_rotations_and_not_the_old_form', async () => {
    render(<AstraView />)
    openTab('Rotations')
    expect(await screen.findByRole('region', { name: 'Renouveler les postes' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Démarrer la rotation' })).toBeNull()
  })

  it('verify_key_opens_the_ceremony_over_the_tabs', async () => {
    api.operatorOverview.mockResolvedValue({
      vault_path: 'v.json',
      exists: true,
      location_available: true,
      bootstrapped: true,
      credentials_complete: true,
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
    openTab('Coffre et clés')
    fireEvent.click(await screen.findByRole('button', { name: 'Vérifier une clé' }))
    await waitFor(() => expect(screen.queryByRole('tab')).toBeNull())
    expect(screen.getByText('Une opération attend l’opérateur.')).toBeTruthy()
  })

  it('a_finished_finalization_offers_the_ca_tls_pem_for_saving', async () => {
    api.operatorOverview.mockResolvedValue({
      vault_path: 'v.json',
      exists: true,
      location_available: true,
      bootstrapped: true,
      credentials_complete: false,
      vault_fingerprint: 'ab12',
      slots: [],
      max_slots: 8,
      domain: {
        trust_domain_id: 'td',
        rp_id: 'gw',
        ca_pq_fingerprint: 'ff',
        ca_epoch: 1,
        ca_tls_epoch: null,
        ca_tls_present: false,
        server_name: 'gw',
        gateway_wg_public_key: 'KEY',
        astra_service_public_key: null,
        astra_service_key_epoch: null,
        astra_authority_url: null,
      },
    })
    api.beginVaultCeremony.mockResolvedValue({
      session_id: 'e'.repeat(32),
      revision: 3,
      operation: 'finalize_domain',
      operation_id: null,
      remote: 'not_required',
      gesture: 'done',
      allowed: [],
    })
    api.operatorArtifacts.mockResolvedValue([
      { file_name: 'ca-tls.pem', encoding: 'text', contents: '-----BEGIN CERTIFICATE-----' },
    ])
    render(<AstraView />)
    openTab('Domaine')
    fireEvent.click(await screen.findByRole('button', { name: 'Finaliser le domaine' }))
    expect(await screen.findByRole('button', { name: 'Enregistrer ca-tls.pem' })).toBeTruthy()
  })

  it('the_bootstrap_offers_its_artifacts', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'e'.repeat(32),
      revision: 3,
      operation: 'issue_gateway_bootstrap',
      operation_id: null,
      remote: 'not_required',
      gesture: 'done',
      allowed: [],
    })
    api.operatorArtifacts.mockResolvedValue([
      {
        file_name: 'gateway-bootstrap-certificate.json',
        encoding: 'text',
        contents: '{}',
        fingerprint: 'c'.repeat(64),
      },
      { file_name: 'ca-tls.pem', encoding: 'text', contents: '-----BEGIN CERTIFICATE-----' },
    ])
    render(<AstraView />)
    expect(
      await screen.findByRole('button', { name: 'Enregistrer gateway-bootstrap-certificate.json' }),
    ).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enregistrer ca-tls.pem' })).toBeTruthy()
    expect(screen.getByText(`empreinte : ${'c'.repeat(64)}`)).toBeTruthy()
    expect(screen.getAllByText(/^empreinte : /)).toHaveLength(1)
    expect(screen.getByText(/Portez la feuille sur la gateway/)).toBeTruthy()
    expect(screen.getByText(/seule la feuille\s+d’amorçage de la gateway est aussi écrite/)).toBeTruthy()
    expect(screen.queryByText(/reprend ce qui manque/)).toBeNull()
  })

  it('a_bootstrap_that_failed_after_its_leaf_still_offers_it', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'e'.repeat(32),
      revision: 4,
      operation: 'issue_gateway_bootstrap',
      operation_id: null,
      remote: 'not_required',
      gesture: 'failed',
      allowed: [],
      refusal: { refusal: 'internal' },
    })
    api.operatorArtifacts.mockResolvedValue([
      {
        file_name: 'gateway-bootstrap-certificate.json',
        encoding: 'text',
        contents: '{}',
        fingerprint: 'c'.repeat(64),
      },
    ])
    render(<AstraView />)
    expect(
      await screen.findByRole('button', { name: 'Enregistrer gateway-bootstrap-certificate.json' }),
    ).toBeTruthy()
    expect(screen.getByText(`empreinte : ${'c'.repeat(64)}`)).toBeTruthy()
    expect(
      screen.getByText(
        'La feuille est émise et enregistrée à côté du coffre ; « Finaliser le domaine » reprend ce qui manque.',
      ),
    ).toBeTruthy()
    expect(screen.queryByText(/Portez la feuille sur la gateway/)).toBeNull()
  })

  it('a_bootstrap_that_failed_before_its_leaf_says_nothing_of_it', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'e'.repeat(32),
      revision: 4,
      operation: 'issue_gateway_bootstrap',
      operation_id: null,
      remote: 'not_required',
      gesture: 'failed',
      allowed: [],
      refusal: { refusal: 'key_repeated' },
    })
    render(<AstraView />)
    await waitFor(() => expect(api.operatorArtifacts).toHaveBeenCalled())
    expect(screen.queryByText(/reprend ce qui manque/)).toBeNull()
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

  it('badges_the_approvals_tab_with_the_pending_count', async () => {
    const operation = {
      operation_id: 'f'.repeat(32),
      scope: 'trust_authorities',
      reason: 'rotation des ancres',
      requested_by: 'operator',
      target_count: 2,
      required_credentials: 2,
      campaign_fingerprint: 'a'.repeat(64),
      created_at: 1_800_000_000,
      expires_at: 1_800_000_300,
    }
    api.operatorPendingOperations.mockResolvedValue([
      operation,
      { ...operation, operation_id: 'e'.repeat(32) },
    ])
    render(<AstraView />)
    const tab = await screen.findByRole('tab', { name: /Approbations/ })
    await waitFor(() => expect(tab.textContent).toBe('Approbations2'))
    expect(screen.getByRole('tab', { name: /Enrôlement/ }).textContent).toBe('Enrôlement')
  })

  it('shows but never launches a campaign the helper cannot execute', async () => {
    api.operatorPendingOperations.mockResolvedValue([
      {
        operation_id: 'f'.repeat(32),
        scope: 'emergency_revocation',
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
    openTab(/Approbations/)

    expect(await screen.findByText('rotation des ancres')).toBeTruthy()
    const [open] = screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })
    expect(open.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(/n’est pas encore disponible dans Orion/)).toBeTruthy()
    fireEvent.click(open)
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('leads_a_CA_rotation_campaign_to_the_rotations_tab', async () => {
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
    openTab(/Approbations/)
    await screen.findByText('rotation des ancres')
    const open = screen.getByRole('button', { name: 'Ouvrir dans Rotations' })
    await waitFor(() => expect(open.hasAttribute('disabled')).toBe(false))
    fireEvent.click(open)
    expect(await screen.findByRole('region', { name: 'Renouveler les postes' })).toBeTruthy()
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('suspends_every_launch_during_a_CA_PQ_overlap_or_when_the_authority_is_unread', async () => {
    const delegation = {
      operation_id: 'f'.repeat(32),
      scope: 'issuer_delegation',
      reason: 'déléguer Astra',
      requested_by: 'operator',
      target_count: 1,
      required_credentials: 1,
      campaign_fingerprint: 'a'.repeat(64),
      created_at: 1_800_000_000,
      expires_at: 1_800_000_300,
    }
    api.operatorPendingOperations.mockResolvedValue([delegation])
    for (const [overlap, reason] of [
      [true, 'Recouvrement CA-PQ en cours'],
      [null, 'Autorité non lue'],
    ] as const) {
      api.operatorRotationsOverview.mockResolvedValue(rotations({ caPqOverlap: overlap }))
      const view = render(<AstraView />)
      openTab(/Approbations/)
      await screen.findByText('déléguer Astra')
      await screen.findByText(reason)
      for (const button of screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })) {
        expect(button.hasAttribute('disabled')).toBe(true)
      }
      fireEvent.click(screen.getAllByRole('button', { name: 'Ouvrir la cérémonie' })[0])
      expect(screen.queryByLabelText('Demande de délégation')).toBeNull()
      view.unmount()
    }
  })

  it('ends a domain creation on its fingerprints and next steps', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'd'.repeat(32),
      revision: 9,
      operation: 'create_domain',
      operation_id: null,
      remote: 'awaiting_operator',
      gesture: 'done',
      allowed: [],
    })
    api.operatorOverview.mockResolvedValue({
      vault_path: 'C:\\astra\\authority-vault.json',
      exists: true,
      location_available: true,
      bootstrapped: true,
      credentials_complete: false,
      vault_fingerprint: 'abcdef0123456789',
      slots: [],
      max_slots: 8,
      domain: {
        trust_domain_id: 'td',
        rp_id: 'gw',
        ca_pq_fingerprint: '9999 8888',
        ca_epoch: 1,
        ca_tls_epoch: null,
        ca_tls_present: false,
        server_name: null,
        gateway_wg_public_key: null,
        astra_service_public_key: null,
        astra_service_key_epoch: null,
        astra_authority_url: null,
      },
    })

    render(<AstraView />)

    expect(await screen.findByText('Domaine créé')).toBeTruthy()
    expect(screen.getByText('abcd ef01 2345 6789')).toBeTruthy()
    expect(screen.getByText('9999 8888')).toBeTruthy()
    expect(screen.getByText(/Sauvegardez le coffre/)).toBeTruthy()
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

    render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={operationId} />)

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

    render(<AstraView onRecoveryReady={onRecoveryReady} localRecoveryId={operationId} />)

    expect(await screen.findByText(/commit temporairement indisponible/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Réessayer la finalisation' }))
    await waitFor(() => expect(onRecoveryReady).toHaveBeenCalledTimes(2))
  })
})
