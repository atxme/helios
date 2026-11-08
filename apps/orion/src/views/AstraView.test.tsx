// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorCeremonyStatus: vi.fn(),
  advanceOperatorCeremony: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  beginRotationCeremony: vi.fn(),
  approveRotationCeremony: vi.fn(),
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
  operatorSendVaultCopy: vi.fn(),
}))
vi.mock('../api', () => api)

import { AstraView } from './AstraView'
import { DAY, overview as fullOverview } from './astra/rotationFixtures'

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
  localCredentialRegistryEpoch: null,
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

  it('shows_why_a_key_was_turned_down_on_any_ceremony', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      session_id: '5'.repeat(32),
      revision: 3,
      operation: 'approve_campaign',
      operation_id: 'e'.repeat(32),
      remote: 'awaiting_operator',
      gesture: { awaiting_key: { index: 2, of: 2, purpose: 'approve_campaign' } },
      allowed: ['continue', 'cancel'],
      key_retry: { refusal: 'key_not_enrolled' },
    })
    render(<AstraView />)
    expect(await screen.findByText('Clé absente du coffre')).toBeTruthy()
  })

  describe('the rotation ceremonies', () => {
    const keyStep = (session: string) => ({
      session_id: session,
      revision: 2,
      operation: 'rotate_anchor' as const,
      remote: 'local' as const,
      gesture: { awaiting_key: { index: 1, of: 2, purpose: 'validate_key' as const } },
      allowed: ['continue', 'cancel'] as const,
    })
    const journal = (extra: object = {}) => ({
      kind: 'ca_pq' as const,
      stage: 'applied' as const,
      activationAt: Math.floor(Date.now() / 1000) + 3 * DAY,
      notAfter: Math.floor(Date.now() / 1000) + 33 * DAY,
      nextFingerprint: 'bb'.repeat(32),
      offline: false,
      ...extra,
    })

    it('hands_the_rotation_over_even_when_the_row_turns_impossible_before_the_answer', async () => {
      let release: (value: unknown) => void = () => {}
      api.operatorRotationsOverview.mockResolvedValue(fullOverview())
      api.beginRotationCeremony.mockImplementation(
        () => new Promise((resolve) => (release = resolve)),
      )
      render(<AstraView />)
      openTab(/Rotations/)
      const row = await screen.findByRole('region', { name: 'Remplacer la CA-PQ' })
      fireEvent.click(within(row).getByRole('button'))
      fireEvent.click(await screen.findByRole('button', { name: 'Continuer' }))
      await waitFor(() => expect(api.beginRotationCeremony).toHaveBeenCalled())

      // The panel is still mounted: a forced read flips the row and unmounts the step.
      api.operatorRotationsOverview.mockResolvedValue(fullOverview({ resumable: true }))
      fireEvent.click(screen.getByRole('button', { name: 'Vérifier' }))
      await waitFor(() => expect(screen.queryByRole('button', { name: 'Continuer' })).toBeNull())

      release(keyStep('1'.repeat(32)))
      expect(await screen.findByText('À valider')).toBeTruthy()
      expect(screen.getByRole('listitem', { name: 'Clé 1' })).toBeTruthy()
    })

    it('reads_the_overview_again_when_the_ceremony_ends_and_shows_the_copy_as_pending', async () => {
      const session = '2'.repeat(32)
      const signing = { ...keyStep(session), remote: 'prepared' as const, gesture: 'signing' as const, allowed: [] }
      api.operatorCeremonyStatus.mockResolvedValueOnce(signing)
      api.operatorRotationsOverview.mockResolvedValue(fullOverview({ journal: null }))
      render(<AstraView />)
      await screen.findByRole('listitem', { name: 'Signée' })
      const reads = api.operatorRotationsOverview.mock.calls.length
      api.operatorRotationsOverview.mockResolvedValue(
        fullOverview({ caPqOverlap: true, journal: journal({ stage: 'installed' }) }),
      )
      api.operatorCeremonyStatus.mockResolvedValue({
        ...signing,
        revision: 9,
        remote: 'deposited' as const,
        gesture: 'done' as const,
      })
      const copy = await screen.findByRole('listitem', { name: 'Copie du coffre' })
      await waitFor(() => expect(within(copy).getByText('En attente')).toBeTruthy())
      expect(api.operatorRotationsOverview.mock.calls.length).toBeGreaterThan(reads)
    })

    it('does_not_let_the_stop_of_an_automatic_resumption_take_the_tab', async () => {
      api.operatorCeremonyStatus.mockResolvedValue({
        automatic: true,
        session_id: '3'.repeat(32),
        revision: 6,
        operation: 'rotate_anchor',
        remote: 'prepared',
        gesture: 'failed',
        allowed: [],
        refusal: { refusal: 'install_deadline_passed' },
      })
      api.operatorRotationsOverview.mockResolvedValue(
        fullOverview({ resumable: true, journal: journal() }),
      )
      render(<AstraView />)
      expect(await screen.findByRole('tablist')).toBeTruthy()
      expect(screen.queryByRole('button', { name: 'Retour aux opérations' })).toBeNull()
      openTab(/Rotations/)
      const row = await screen.findByRole('region', { name: 'Reprendre une rotation' })
      expect(within(row).getByText(/Intervention manuelle requise/)).toBeTruthy()
    })

    it('keeps_an_operators_own_finished_screen_after_leaving_and_coming_back', async () => {
      // No memory of this view: the origin is the session's own, so a reload changes nothing.
      api.operatorCeremonyStatus.mockResolvedValue({
        ...keyStep('4'.repeat(32)),
        automatic: false,
        revision: 8,
        remote: 'prepared',
        gesture: 'failed',
        allowed: [],
        refusal: { refusal: 'gateway_unavailable' },
      })
      api.operatorRotationsOverview.mockResolvedValue(fullOverview({ resumable: true, journal: journal() }))
      render(<AstraView />)
      expect(await screen.findByRole('button', { name: 'Retour aux opérations' })).toBeTruthy()
    })

    it('lets_go_of_an_automatic_resumption_that_ends_while_the_tab_shows_it', async () => {
      const running = {
        ...keyStep('6'.repeat(32)),
        automatic: true,
        remote: 'deposited' as const,
        gesture: 'idle' as const,
        allowed: [],
      }
      api.operatorCeremonyStatus.mockResolvedValueOnce(running)
      api.operatorRotationsOverview.mockResolvedValue(fullOverview({ resumable: true, journal: journal() }))
      render(<AstraView />)
      await screen.findByRole('listitem', { name: 'Signée' })
      api.operatorCeremonyStatus.mockResolvedValue({
        ...running,
        revision: 9,
        gesture: 'failed',
        refusal: { refusal: 'gateway_unavailable' },
      })
      expect(await screen.findByRole('tablist')).toBeTruthy()
      expect(screen.queryByRole('button', { name: 'Retour aux opérations' })).toBeNull()
    })

    it('finds_the_open_campaign_again_when_the_tab_comes_back_to_the_approval', async () => {
      const operation = {
        operation_id: 'f'.repeat(32),
        scope: 'trust_authorities',
        reason: 'ancres 2027',
        requested_by: 'operator',
        target_count: 2,
        required_credentials: 2,
        campaign_fingerprint: 'a'.repeat(64),
        created_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 200,
      }
      api.operatorPendingOperations.mockResolvedValue([operation])
      api.operatorCeremonyStatus.mockResolvedValue({
        ...keyStep('7'.repeat(32)),
        gesture: 'idle',
        allowed: ['cancel'],
        keys: [
          { slot: '1', label: 'A' },
          { slot: '2', label: 'B' },
        ],
      })
      api.approveRotationCeremony.mockResolvedValue(keyStep('7'.repeat(32)))
      render(<AstraView />)
      fireEvent.click(await screen.findByRole('button', { name: 'Continuer' }))
      expect(await screen.findByText('Opération ouverte')).toBeTruthy()
      expect(screen.queryByLabelText('Motif')).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Approuver' }))
      await waitFor(() => expect(api.approveRotationCeremony).toHaveBeenCalled())
      expect(api.approveRotationCeremony.mock.calls[0][0].existing_operation).toBe('f'.repeat(32))
    })

    it('raises_a_line_with_the_deadline_of_a_journal_in_flight_with_no_session', async () => {
      api.operatorRotationsOverview.mockResolvedValue(
        fullOverview({ resumable: true, journal: journal() }),
      )
      render(<AstraView />)
      expect(await screen.findByText(/^Rotation CA-PQ · à installer avant le /)).toBeTruthy()
      expect(screen.getByRole('tab', { name: /Rotations/ }).textContent).toMatch(/1$/)
    })

    it('a_deadline_passed_on_local_data_alone_is_to_check_and_not_a_dead_end', async () => {
      const past = { activationAt: Math.floor(Date.now() / 1000) - DAY }
      api.operatorRotationsOverview.mockResolvedValue(
        fullOverview({ resumable: true, journal: journal(past) }),
      )
      render(<AstraView />)
      const line = await screen.findByText(
        'Rotation CA-PQ · Délai d’installation passé : à vérifier à la connexion',
      )
      expect(line.closest('.MuiAlert-colorWarning')).toBeTruthy()
      expect(screen.queryByText(/Intervention manuelle requise/)).toBeNull()
    })

    it('a_resumption_that_met_the_deadline_makes_the_line_blocking', async () => {
      const past = { activationAt: Math.floor(Date.now() / 1000) - DAY }
      api.operatorCeremonyStatus.mockResolvedValue({
        automatic: true,
        session_id: '2'.repeat(32),
        revision: 6,
        operation: 'rotate_anchor',
        remote: 'prepared',
        gesture: 'failed',
        allowed: [],
        refusal: { refusal: 'install_deadline_passed' },
      })
      api.operatorRotationsOverview.mockResolvedValue(
        fullOverview({ resumable: true, journal: journal(past) }),
      )
      render(<AstraView />)
      const line = await screen.findByText(/^Délai dépassé le .*Intervention manuelle requise/)
      expect(line.closest('.MuiAlert-colorError')).toBeTruthy()
    })

    it('says_nothing_when_no_rotation_is_in_flight', async () => {
      render(<AstraView />)
      await waitFor(() => expect(api.operatorRotationsOverview).toHaveBeenCalled())
      expect(screen.queryByText(/à installer avant le/)).toBeNull()
    })
  })
})

// Spec §5.9: a key added, removed or marked reaches Astra with the copy, from Orion.
describe('after a key change', () => {
  const marked = {
    session_id: '7'.repeat(32),
    revision: 6,
    operation: 'mark_key',
    operation_id: null,
    remote: 'local',
    gesture: 'done',
    allowed: [],
  }

  it('a_key_marked_lost_is_sent_to_astra_with_the_copy', async () => {
    api.operatorCeremonyStatus.mockResolvedValue(marked)
    api.operatorSendVaultCopy.mockResolvedValue({
      state: 'copied',
      fingerprint: 'ef'.repeat(32),
      credential_registry_epoch: 6,
      document_waits: false,
    })
    render(<AstraView />)
    expect(
      await screen.findByText('Copie du coffre et document de credentials envoyés à Astra'),
    ).toBeTruthy()
    expect(api.operatorSendVaultCopy).toHaveBeenCalledTimes(1)
  })

  it('a_document_held_by_a_rotation_is_said', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      ...marked,
      session_id: '8'.repeat(32),
      operation: 'remove_key',
    })
    api.operatorSendVaultCopy.mockResolvedValue({
      state: 'copied',
      fingerprint: 'ef'.repeat(32),
      credential_registry_epoch: 5,
      document_waits: true,
    })
    render(<AstraView />)
    expect(await screen.findByText(/document de credentials en attente/)).toBeTruthy()
  })

  it('a_copy_held_back_is_said', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      ...marked,
      session_id: '9'.repeat(32),
      operation: 'add_key',
    })
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'held_back' })
    render(<AstraView />)
    expect(await screen.findByText(/Copie retenue par une opération en cours/)).toBeTruthy()
  })

  it('a_send_that_failed_is_said_and_offered_again', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({ ...marked, session_id: 'a'.repeat(32) })
    api.operatorSendVaultCopy
      .mockRejectedValueOnce('la gateway ne répond pas')
      .mockResolvedValue({
        state: 'copied',
        fingerprint: 'ef'.repeat(32),
        credential_registry_epoch: 6,
        document_waits: false,
      })
    render(<AstraView />)
    expect(await screen.findByText(/Copie non envoyée à Astra : la gateway ne répond pas/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Réessayer l’envoi' }))
    expect(
      await screen.findByText('Copie du coffre et document de credentials envoyés à Astra'),
    ).toBeTruthy()
  })

  it('a_failed_or_other_gesture_sends_nothing', async () => {
    api.operatorCeremonyStatus.mockResolvedValue({
      ...marked,
      session_id: 'b'.repeat(32),
      gesture: 'failed',
      refusal: { refusal: 'key_declined' },
    })
    render(<AstraView />)
    await screen.findByText(/Aucune clé n’a répondu/)
    cleanup()
    api.operatorCeremonyStatus.mockResolvedValue({
      ...marked,
      session_id: 'c'.repeat(32),
      operation: 'finalize_domain',
    })
    render(<AstraView />)
    await waitFor(() => expect(api.operatorCeremonyStatus).toHaveBeenCalled())
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(api.operatorSendVaultCopy).not.toHaveBeenCalled()
  })
})
