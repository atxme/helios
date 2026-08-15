// @vitest-environment jsdom

import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ClientConfig, ClientEvent, ClientProfile, ImportOutcome } from '../types'

const api = vi.hoisted(() => ({
  adapterIsUp: vi.fn(),
  backendKind: vi.fn(),
  connect: vi.fn(),
  deleteProfile: vi.fn(),
  disconnect: vi.fn(),
  getConfig: vi.fn(),
  getState: vi.fn(),
  importProfile: vi.fn(),
  importProfilePath: vi.fn(),
  onConfigChanged: vi.fn(),
  onEvent: vi.fn(),
  onProfilePath: vi.fn(),
  saveProfile: vi.fn(),
  selectProfile: vi.fn(),
}))

vi.mock('../api', () => api)

import { useClient } from './useClient'

const portable: ClientProfile = {
  name: 'portable',
  endpoint: '203.0.113.10:51820',
  peer_public_key: 'gateway-public',
  public_key: 'client-public',
  has_private_key: true,
  has_static_psk: false,
  address: '100.64.1.2/32',
  allowed_ips: '0.0.0.0/0',
  persistent_keepalive: 25,
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
  key_negotiation: null,
}

const config: ClientConfig = { profiles: [portable], selected: 'portable' }
const imported = (overrides: Partial<ImportOutcome> = {}): ImportOutcome => ({
  profile: { ...portable, name: 'imported' },
  identity_sealed: false,
  identity_error: null,
  private_key_missing: null,
  incomplete: null,
  notices: [],
  ...overrides,
})

let emit: (event: ClientEvent) => void
let profilePath: () => void
let configChanged: () => void
let unlistenEvent: ReturnType<typeof vi.fn>
let unlistenProfilePath: ReturnType<typeof vi.fn>
let unlistenConfig: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()
  unlistenEvent = vi.fn()
  unlistenProfilePath = vi.fn()
  unlistenConfig = vi.fn()
  api.getConfig.mockResolvedValue(config)
  api.getState.mockResolvedValue('down')
  api.backendKind.mockResolvedValue('dry-run')
  api.adapterIsUp.mockResolvedValue(false)
  api.importProfilePath.mockResolvedValue(null)
  api.onEvent.mockImplementation(async (listener) => {
    emit = listener
    return unlistenEvent
  })
  api.onProfilePath.mockImplementation(async (listener) => {
    profilePath = listener
    return unlistenProfilePath
  })
  api.onConfigChanged.mockImplementation(async (listener) => {
    configChanged = listener
    return unlistenConfig
  })
})

afterEach(cleanup)

describe('useClient', () => {
  it('loads state, consumes events and releases both subscriptions', async () => {
    const { result, unmount } = renderHook(() => useClient())

    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))
    expect(result.current.backend).toBe('dry-run')
    expect(api.importProfilePath).toHaveBeenCalledWith()

    act(() => emit({ type: 'state_changed', state: 'up' }))
    await waitFor(() => expect(result.current.state).toBe('up'))
    expect(result.current.upSince).not.toBeNull()

    act(() => {
      emit({ type: 'protection', psk: 'ml_kem' })
      emit({ type: 'log', level: 'info', message: 'connected' })
      for (let index = 0; index < 65; index += 1) {
        emit({
          type: 'telemetry',
          iface: 'orion0',
          rx_bps: index,
          tx_bps: index * 2,
          rx_pps: index,
          tx_pps: index,
        })
      }
      emit({ type: 'error', message: 'link lost' })
    })
    expect(result.current.psk).toBe('ml_kem')
    expect(result.current.telemetry).toEqual({ rx_bps: 64, tx_bps: 128 })
    expect(result.current.history).toHaveLength(60)
    expect(result.current.logs.map((line) => line.message)).toEqual(['link lost', 'connected'])

    act(() => emit({ type: 'state_changed', state: 'failed' }))
    expect(result.current.upSince).toBeNull()
    expect(result.current.telemetry).toBeNull()
    expect(result.current.history).toEqual([])
    expect(result.current.psk).toBeNull()

    unmount()
    await waitFor(() => {
      expect(unlistenEvent).toHaveBeenCalledOnce()
      expect(unlistenProfilePath).toHaveBeenCalledOnce()
      expect(unlistenConfig).toHaveBeenCalledOnce()
    })
  })

  // The notification area connects a profile, which selects it. The window may
  // be open behind that menu: without this reread it would keep displaying the
  // profile the selection has just left.
  it('rereads the configuration when the tray changes the selection', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    const other: ClientProfile = { ...portable, name: 'bureau' }
    api.getConfig.mockResolvedValue({ profiles: [portable, other], selected: 'bureau' })
    act(() => configChanged())

    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('bureau'))
  })

  it('reports every associated-profile import outcome', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(api.importProfilePath).toHaveBeenCalledOnce())

    api.importProfilePath.mockResolvedValueOnce(imported({ identity_sealed: true }))
    act(() => profilePath())
    await waitFor(() => expect(result.current.pathImportedProfile?.name).toBe('imported'))
    expect(result.current.logs[0]?.message).toContain('scellée')

    act(() => result.current.clearPathImportedProfile())
    api.importProfilePath.mockResolvedValueOnce(imported({ identity_error: 'DPAPI unavailable' }))
    act(() => profilePath())
    await waitFor(() => expect(result.current.error).toContain('DPAPI unavailable'))

    api.importProfilePath.mockResolvedValueOnce(imported({ private_key_missing: 'key expected' }))
    act(() => profilePath())
    await waitFor(() => expect(result.current.error).toBe('key expected'))

    api.importProfilePath.mockRejectedValueOnce(new Error('unreadable'))
    act(() => profilePath())
    await waitFor(() => expect(result.current.error).toContain('unreadable'))
    expect(result.current.logs[0]?.level).toBe('error')
  })

  it('updates configuration through successful actions', async () => {
    const saved = { profiles: [{ ...portable, name: 'saved' }], selected: 'saved' }
    api.connect.mockResolvedValue(undefined)
    api.disconnect.mockResolvedValue(undefined)
    api.importProfile.mockResolvedValue(imported())
    api.saveProfile.mockResolvedValue(saved)
    api.deleteProfile.mockResolvedValue({ profiles: [], selected: null })
    api.selectProfile.mockResolvedValue(config)
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    await act(() => result.current.connect('portable'))
    expect(api.connect).toHaveBeenCalledWith('portable')
    await act(() => result.current.disconnect())
    expect(result.current.adapterUp).toBe(false)
    await expect(
      act(() => result.current.importProfile('{"format":"orion-profile"}', 'profile.json')),
    ).resolves.toEqual(imported())
    await act(() => result.current.saveProfile(saved.profiles[0]))
    expect(result.current.selectedProfile?.name).toBe('saved')
    await act(() => result.current.select('portable'))
    expect(result.current.selectedProfile?.name).toBe('portable')
    await act(() => result.current.removeProfile('portable'))
    expect(result.current.selectedProfile).toBeNull()
  })

  it('surfaces action and initial-load failures', async () => {
    api.getConfig.mockRejectedValueOnce(new Error('config failed'))
    api.connect.mockRejectedValueOnce(new Error('connect failed'))
    api.disconnect.mockRejectedValueOnce(new Error('disconnect failed'))
    const { result } = renderHook(() => useClient())

    await waitFor(() => expect(result.current.error).toContain('config failed'))
    await act(() => result.current.connect())
    expect(result.current.error).toContain('connect failed')
    await act(() => result.current.disconnect())
    expect(result.current.error).toContain('disconnect failed')

    for (const [operation, invoke] of [
      ['import', () => result.current.importProfile('{}', 'bad.json')],
      ['save', () => result.current.saveProfile(portable)],
      ['delete', () => result.current.removeProfile('portable')],
      ['select', () => result.current.select('portable')],
    ] as const) {
      const failure = new Error(`${operation} failed`)
      if (operation === 'import') api.importProfile.mockRejectedValueOnce(failure)
      if (operation === 'save') api.saveProfile.mockRejectedValueOnce(failure)
      if (operation === 'delete') api.deleteProfile.mockRejectedValueOnce(failure)
      if (operation === 'select') api.selectProfile.mockRejectedValueOnce(failure)
      await act(async () => {
        await expect(invoke()).rejects.toThrow(`${operation} failed`)
      })
      await waitFor(() => expect(result.current.error).toContain(`${operation} failed`))
    }

    act(() => result.current.clearError())
    expect(result.current.error).toBeNull()
  })
})
