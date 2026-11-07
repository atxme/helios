// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  onTrayView: vi.fn(),
  resizeForView: vi.fn(),
  vaultPosture: vi.fn(),
  useClient: vi.fn(),
  operatorCeremonyStatus: vi.fn(),
  astraCaTlsRotationStatus: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  operatorRotationsOverview: vi.fn(),
  resumeCertificateRecovery: vi.fn(),
  dismissOperatorCeremony: vi.fn(),
  operatorPendingOperations: vi.fn(),
}))

vi.mock('./api', () => ({
  onTrayView: mocks.onTrayView,
  resizeForView: mocks.resizeForView,
  vaultPosture: mocks.vaultPosture,
  operatorCeremonyStatus: mocks.operatorCeremonyStatus,
  astraCaTlsRotationStatus: mocks.astraCaTlsRotationStatus,
  beginOperatorCeremony: mocks.beginOperatorCeremony,
  operatorRotationsOverview: mocks.operatorRotationsOverview,
  resumeCertificateRecovery: mocks.resumeCertificateRecovery,
  dismissOperatorCeremony: mocks.dismissOperatorCeremony,
  operatorPendingOperations: mocks.operatorPendingOperations,
}))
vi.mock('./hooks/useClient', () => ({ useClient: mocks.useClient }))
vi.mock('./views/ConnectView', () => ({
  ConnectView: ({ onConnect, onDisconnect }: { onConnect: () => void; onDisconnect: () => void }) => (
    <div>
      connect-view
      <button onClick={onConnect}>test-connect</button>
      <button onClick={onDisconnect}>test-disconnect</button>
    </div>
  ),
}))
vi.mock('./views/ProfilesView', () => ({
  ProfilesView: () => <div>profiles-view</div>,
}))
vi.mock('./views/SpeedTestView', () => ({
  SpeedTestView: () => <div>speedtest-view</div>,
}))
vi.mock('./views/AstraView', () => ({
  AstraView: ({
    onRecoveryReady,
    localRecoveryId,
  }: {
    onRecoveryReady?: (operationId: string) => Promise<void>
    localRecoveryId?: string | null
  }) => (
    <div>
      astra-view
      <span>local-recovery-{localRecoveryId ?? 'none'}</span>
      <button onClick={() => void onRecoveryReady?.('e'.repeat(32))}>test-finish-recovery</button>
    </div>
  ),
}))
vi.mock('./views/CertificatesView', () => ({
  CertificatesView: ({
    onApprove,
    completedRecovery,
  }: {
    onApprove?: (operationId: string) => Promise<void>
    completedRecovery?: Record<string, { step: string; generation?: number }>
  }) => (
    <div>
      certificates-view
      <button onClick={() => void onApprove?.('e'.repeat(32))?.catch(() => undefined)}>
        test-start-recovery
      </button>
      {completedRecovery?.portable && (
        <span>recovered-generation-{completedRecovery.portable.generation}</span>
      )}
    </div>
  ),
}))
vi.mock('./components/EventLog', () => ({
  EventLog: () => <div>logs-view</div>,
}))
vi.mock('./components/PosturePanel', () => ({
  PosturePanel: ({ anchor, onClose }: { anchor: HTMLElement | null; onClose: () => void }) =>
    anchor ? <button onClick={onClose}>close-posture</button> : null,
}))

import App from './App'

function client(overrides: Record<string, unknown> = {}) {
  return {
    state: 'down',
    adapterUp: false,
    selectedProfile: null,
    psk: null,
    backend: 'dry-run',
    pathImportedProfile: null,
    error: null,
    logs: [],
    config: { profiles: [], selected: null },
    telemetry: null,
    history: [],
    upSince: null,
    connect: vi.fn(),
    disconnect: vi.fn(),
    importProfile: vi.fn(),
    saveProfile: vi.fn(),
    removeProfile: vi.fn(),
    select: vi.fn(),
    clearPathImportedProfile: vi.fn(),
    clearError: vi.fn(),
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.resizeForView.mockResolvedValue(undefined)
  mocks.onTrayView.mockResolvedValue(vi.fn())
  // Nothing waits on the operator by default: Astra remains accessible and
  // simply carries no attention badge.
  mocks.operatorCeremonyStatus.mockResolvedValue(null)
  mocks.astraCaTlsRotationStatus.mockResolvedValue({ phase: 'idle' })
  mocks.operatorPendingOperations.mockResolvedValue([])
  mocks.beginOperatorCeremony.mockResolvedValue({})
  mocks.operatorRotationsOverview.mockResolvedValue({ caPqOverlap: false })
  mocks.resumeCertificateRecovery.mockResolvedValue({
    progress: {
      portable: { step: 'recovered', generation: 5, activation_at: 1_789_198_911 },
    },
    refused: {},
  })
  mocks.dismissOperatorCeremony.mockResolvedValue(undefined)
  // The shell reads the vault posture when the panel opens. A rejection is
  // the honest default here: the panel must survive it, and every test that
  // needs a real posture says so explicitly.
  mocks.vaultPosture.mockRejectedValue(new Error('pas de coffre en test'))
})

afterEach(cleanup)

describe('App interactions', () => {
  it('switches views, expands the rail and delegates connection actions', async () => {
    const state = client({ logs: [{ level: 'info', message: 'ready', ts: '12:00:00' }] })
    mocks.useClient.mockReturnValue(state)
    render(<App />)

    expect(screen.getByText('connect-view')).toBeTruthy()
    await waitFor(() => expect(mocks.resizeForView).toHaveBeenCalledWith('connect'))

    fireEvent.click(screen.getByRole('button', { name: 'test-connect' }))
    fireEvent.click(screen.getByRole('button', { name: 'test-disconnect' }))
    expect(state.connect).toHaveBeenCalledWith(undefined)
    expect(state.disconnect).toHaveBeenCalledOnce()

    const nav = screen.getByRole('navigation', { name: 'Navigation principale' })
    fireEvent.mouseEnter(nav.firstElementChild as Element)
    fireEvent.mouseLeave(nav.firstElementChild as Element)
    fireEvent.focus(nav.firstElementChild as Element)
    fireEvent.blur(nav.firstElementChild as Element, { relatedTarget: document.body })

    fireEvent.click(screen.getByRole('button', { name: 'Profils' }))
    expect(screen.getByText('profiles-view')).toBeTruthy()
    await waitFor(() => expect(mocks.resizeForView).toHaveBeenCalledWith('profiles'))

    fireEvent.click(screen.getByRole('button', { name: 'Journal' }))
    expect(screen.getByText('logs-view')).toBeTruthy()
    await waitFor(() => expect(mocks.resizeForView).toHaveBeenCalledWith('logs'))

    fireEvent.click(screen.getByRole('button', { name: 'Speedtest' }))
    expect(screen.getByText('speedtest-view')).toBeTruthy()
    await waitFor(() => expect(mocks.resizeForView).toHaveBeenCalledWith('speedtest'))

    // Astra is also the entry point for authority operations initiated here,
    // so an empty pending queue must not lock the whole destination.
    const astra = screen.getByRole('button', { name: 'Astra' })
    expect(astra).toHaveProperty('disabled', false)
    fireEvent.click(astra)
    expect(screen.getByText('astra-view')).toBeTruthy()
  })

  it('opens the Astra tab exactly when a ceremony waits on the operator', async () => {
    mocks.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'a'.repeat(32),
      revision: 1,
      operation: 'recover_identity',
      remote: 'awaiting_operator',
      gesture: { awaiting_key: { index: 1, of: 1, purpose: 'open_vault' } },
      allowed: ['continue', 'cancel'],
    })
    render(<App />)

    const astra = await screen.findByRole('button', { name: 'Astra' })
    await waitFor(() => expect(astra).toHaveProperty('disabled', false))
    fireEvent.click(astra)
    expect(screen.getByText('astra-view')).toBeTruthy()
    await waitFor(() => expect(mocks.resizeForView).toHaveBeenCalledWith('astra'))
  })

  it('keeps Astra available after a ceremony has finished', async () => {
    mocks.operatorCeremonyStatus.mockResolvedValue({
      session_id: 'a'.repeat(32),
      revision: 4,
      operation: 'approve_campaign',
      remote: 'deposited',
      gesture: 'done',
      allowed: [],
    })
    render(<App />)

    const astra = await screen.findByRole('button', { name: 'Astra' })
    await waitFor(() => expect(astra).toHaveProperty('disabled', false))
  })

  it('returns a completed Astra recovery to the certificate that opened it', async () => {
    render(<App />)

    fireEvent.click(screen.getByRole('button', { name: 'Certificats' }))
    fireEvent.click(await screen.findByRole('button', { name: 'test-start-recovery' }))
    await waitFor(() =>
      expect(mocks.beginOperatorCeremony).toHaveBeenCalledWith({
        kind: 'recover_identity',
        operation_id: 'e'.repeat(32),
      }),
    )
    expect(screen.getByText('astra-view')).toBeTruthy()
    expect(screen.getByText(`local-recovery-${'e'.repeat(32)}`)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'test-finish-recovery' }))

    await waitFor(() =>
      expect(mocks.resumeCertificateRecovery).toHaveBeenCalledWith('e'.repeat(32)),
    )
    expect(await screen.findByText('recovered-generation-5')).toBeTruthy()
  })

  it.each([[true], [null]])(
    'does not open a recovery while the CA-PQ overlap is %s',
    async (overlap) => {
      mocks.operatorRotationsOverview.mockResolvedValue({ caPqOverlap: overlap })
      render(<App />)
      fireEvent.click(screen.getByRole('button', { name: 'Certificats' }))
      fireEvent.click(await screen.findByRole('button', { name: 'test-start-recovery' }))
      await waitFor(() => expect(mocks.operatorRotationsOverview).toHaveBeenCalled())
      await new Promise((resolve) => setTimeout(resolve, 20))
      expect(mocks.beginOperatorCeremony).not.toHaveBeenCalled()
      expect(screen.queryByText('astra-view')).toBeNull()
    },
  )

  it('does not open a recovery when the overview cannot be read', async () => {
    mocks.operatorRotationsOverview.mockRejectedValue('illisible')
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Certificats' }))
    fireEvent.click(await screen.findByRole('button', { name: 'test-start-recovery' }))
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(mocks.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('opens and closes posture details and delegates error dismissal', () => {
    const clearError = vi.fn()
    mocks.useClient.mockReturnValue(client({ error: 'backend unavailable', clearError }))
    render(<App />)

    expect(screen.getByText('backend unavailable')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Masquer l’erreur' }))
    expect(clearError).toHaveBeenCalledOnce()

    fireEvent.click(screen.getByRole('button', { name: /Ouvrir le détail de la posture/ }))
    fireEvent.click(screen.getByRole('button', { name: 'close-posture' }))
    expect(screen.queryByRole('button', { name: 'close-posture' })).toBeNull()
  })

  it('opens the profile view when an associated file was imported', async () => {
    mocks.useClient.mockReturnValue(client({ pathImportedProfile: { name: 'associated' } }))
    render(<App />)

    await waitFor(() => expect(screen.getByText('profiles-view')).toBeTruthy())
    expect(mocks.resizeForView).toHaveBeenCalledWith('profiles')
  })
})
