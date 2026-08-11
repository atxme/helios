// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  onTrayView: vi.fn(),
  resizeForView: vi.fn(),
  vaultPosture: vi.fn(),
  useClient: vi.fn(),
}))

vi.mock('./api', () => ({
  onTrayView: mocks.onTrayView,
  resizeForView: mocks.resizeForView,
  vaultPosture: mocks.vaultPosture,
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
