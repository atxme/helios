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
  makeNomad: vi.fn(),
  changePassphrase: vi.fn(),
  makeService: vi.fn(),
}))

vi.mock('../api', () => api)

import { useClient } from './useClient'

const portable: ClientProfile = {
  name: 'portable',
  endpoint: '203.0.113.10:51820',
  peer_public_key: 'gateway-public',
  mode: 'service',
  profile_type: 'classic',
  public_key: 'client-public',
  has_private_key: true,
  has_static_psk: false,
  address: '100.64.1.2/32',
  address_v6: null,
  allowed_ips: '0.0.0.0/0, ::/0',
  ipv6_uncaptured_full_tunnel: false,
  persistent_keepalive: 25,
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
  dns: null,
  key_negotiation: null,
}

const config: ClientConfig = { profiles: [portable], selected: 'portable', locked: [] }
const imported = (overrides: Partial<ImportOutcome> = {}): ImportOutcome => ({
  profile: { ...portable, name: 'imported' },
  identity_sealed: false,
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
  it('follows a renewal from its start to its end, and forgets it with the tunnel', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))
    expect(result.current.renewing).toBe(false)

    act(() => emit({ type: 'renewal', in_flight: true }))
    expect(result.current.renewing).toBe(true)
    act(() => emit({ type: 'renewal', in_flight: false }))
    expect(result.current.renewing).toBe(false)

    act(() => {
      emit({ type: 'renewal', in_flight: true })
      emit({ type: 'state_changed', state: 'down' })
    })
    expect(result.current.renewing).toBe(false)
  })

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

  // The adapter stays mounted on failure with the routes it had, so a capture
  // gap outlives `failed`; only unmounting, or a new connection that reads
  // the adapter back again, ends it.
  it('keeps the capture verdict for as long as the adapter it describes', async () => {
    api.connect.mockResolvedValue(undefined)
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))
    expect(result.current.capture).toBeNull()

    act(() =>
      emit({
        type: 'capture',
        capture: { status: 'incomplete', missing: ['::/0'], missing_addresses: [] },
      }),
    )
    expect(result.current.capture).toEqual({
      status: 'incomplete',
      missing: ['::/0'],
      missing_addresses: [],
    })

    act(() => emit({ type: 'state_changed', state: 'failed' }))
    expect(result.current.capture).toEqual({
      status: 'incomplete',
      missing: ['::/0'],
      missing_addresses: [],
    })

    act(() => emit({ type: 'state_changed', state: 'down' }))
    expect(result.current.capture).toBeNull()

    act(() => emit({ type: 'capture', capture: { status: 'complete' } }))
    await act(() => result.current.connect('portable'))
    expect(result.current.capture).toBeNull()
  })

  // A late proposal must not overwrite the resolvers actually applied: it only
  // says the gateway's answer was not read. A new connection starts clean.
  it('keeps the DNS verdict when a proposal is unread, and clears both at down', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))
    expect(result.current.dns).toEqual({ check: null, proposalUnread: false })

    const applied = {
      status: 'applied' as const,
      servers: ['86.54.11.100', '86.54.11.200'],
      origin: 'default' as const,
    }
    act(() => emit({ type: 'dns', dns: applied }))
    act(() => emit({ type: 'dns', dns: { status: 'proposal_unread', reason: 'refusée' } }))
    expect(result.current.dns).toEqual({ check: applied, proposalUnread: true })

    act(() => emit({ type: 'state_changed', state: 'failed' }))
    expect(result.current.dns).toEqual({ check: applied, proposalUnread: true })

    act(() => emit({ type: 'state_changed', state: 'down' }))
    expect(result.current.dns).toEqual({ check: null, proposalUnread: false })
  })

  // The notification area connects a profile, which selects it. The window may
  // be open behind that menu: without this reread it would keep displaying the
  // profile the selection has just left.
  it('rereads the configuration when the tray changes the selection', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    const other: ClientProfile = { ...portable, name: 'bureau' }
    api.getConfig.mockResolvedValue({ profiles: [portable, other], selected: 'bureau', locked: [] })
    act(() => configChanged())

    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('bureau'))
  })

  // A lock turns the nomad profiles back to locked, and the engine says so
  // with an event: the window must read the configuration again.
  it('rereads the configuration when the engine reports a config change', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    const lockedCoffre = { name: 'coffre', client_public_key: 'c', peer_public_key: 'g' }
    api.getConfig.mockResolvedValue({ profiles: [], selected: 'coffre', locked: [lockedCoffre] })
    act(() => emit({ type: 'config_changed' }))

    await waitFor(() => expect(result.current.config.locked).toHaveLength(1))
    expect(result.current.config.profiles).toHaveLength(0)
  })

  // The engine opens a locked profile inside a connect and answers with
  // nothing: the list must be read back, or it keeps showing the row locked.
  it('rereads the configuration after a connect', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))
    const lockedCoffre = { name: 'coffre', client_public_key: 'c', peer_public_key: 'g' }
    api.getConfig.mockResolvedValue({ profiles: [portable], selected: 'portable', locked: [lockedCoffre] })
    api.connect.mockResolvedValueOnce(undefined)

    await act(async () => {
      await result.current.connect('coffre')
    })

    await waitFor(() => expect(result.current.config.locked).toHaveLength(1))
  })

  // A locked selected profile is not among the profiles: the header must name
  // it, not fall back to the first profile and connect another tunnel.
  it('keeps a locked selected profile as the connect target', async () => {
    const lockedCoffre = { name: 'coffre', client_public_key: 'c', peer_public_key: 'g' }
    api.getConfig.mockResolvedValue({ profiles: [portable], selected: 'coffre', locked: [lockedCoffre] })
    const { result } = renderHook(() => useClient())

    await waitFor(() => expect(result.current.selectedLocked?.name).toBe('coffre'))
    expect(result.current.selectedProfile).toBeNull()
    expect(result.current.selectedName).toBe('coffre')
  })

  it('reports every associated-profile import outcome', async () => {
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(api.importProfilePath).toHaveBeenCalledOnce())

    api.importProfilePath.mockResolvedValueOnce(imported({ identity_sealed: true }))
    act(() => profilePath())
    await waitFor(() => expect(result.current.pathImportedProfile?.name).toBe('imported'))
    expect(result.current.logs[0]?.message).toContain('scellée')

    act(() => result.current.clearPathImportedProfile())
    api.importProfilePath.mockResolvedValueOnce(imported({ private_key_missing: 'key expected' }))
    act(() => profilePath())
    await waitFor(() => expect(result.current.error).toBe('key expected'))

    api.importProfilePath.mockRejectedValueOnce(new Error('unreadable'))
    act(() => profilePath())
    await waitFor(() => expect(result.current.error).toContain('unreadable'))
    expect(result.current.logs[0]?.level).toBe('error')
  })

  it('updates configuration through successful actions', async () => {
    const saved = { profiles: [{ ...portable, name: 'saved' }], selected: 'saved', locked: [] }
    api.connect.mockResolvedValue(undefined)
    api.disconnect.mockResolvedValue(undefined)
    api.importProfile.mockResolvedValue(imported())
    api.saveProfile.mockResolvedValue(saved)
    api.deleteProfile.mockResolvedValue({ profiles: [], selected: null, locked: [] })
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

  /// The dialog the user closed is an answer, not a failure: nothing is shown
  /// as an error and the configuration is left as it was.
  it('reports a cancelled passphrase dialog as neutral, and a refusal as an error', async () => {
    api.getConfig.mockResolvedValue(config)
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    api.makeNomad.mockRejectedValueOnce('Saisie annulée.')
    let outcome: string | undefined
    await act(async () => {
      outcome = await result.current.makeNomad('portable')
    })
    expect(outcome).toBe('cancelled')
    expect(result.current.error).toBeNull()

    api.changePassphrase.mockRejectedValueOnce('profil « portable » introuvable')
    await act(async () => {
      await expect(result.current.changePassphrase('portable')).rejects.toBe(
        'profil « portable » introuvable',
      )
    })
    expect(result.current.error).toBe('profil « portable » introuvable')
  })

  /// Closing the unlock dialog from «Se connecter» is a choice, not a refusal:
  /// it resolves as cancelled and leaves the global error line empty. The
  /// header connect and the locked-row connect both reach this path.
  it('reports a closed unlock dialog on connect as cancelled, not as an error', async () => {
    api.getConfig.mockResolvedValue(config)
    const { result } = renderHook(() => useClient())
    await waitFor(() => expect(result.current.selectedProfile?.name).toBe('portable'))

    api.connect.mockRejectedValueOnce('Saisie annulée.')
    let outcome: string | undefined
    await act(async () => {
      outcome = await result.current.connect('coffre')
    })
    expect(outcome).toBe('cancelled')
    expect(result.current.error).toBeNull()

    api.connect.mockRejectedValueOnce('profil « coffre » introuvable')
    await act(async () => {
      outcome = await result.current.connect('coffre')
    })
    expect(outcome).toBe('done')
    expect(result.current.error).toBe('profil « coffre » introuvable')
  })
})
