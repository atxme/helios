import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }))
vi.mock('@tauri-apps/api/event', () => ({ listen: mocks.listen }))

import {
  adapterIsUp,
  backendKind,
  connect,
  deleteProfile,
  disconnect,
  getConfig,
  getState,
  importProfile,
  importProfilePath,
  keyNegotiationFingerprint,
  keyNegotiationIdentitySealed,
  keyNegotiationSupport,
  onEvent,
  onProfilePath,
  resizeForView,
  saveProfile,
  selectProfile,
  validateProfile,
  vaultPosture,
  exportLogs,
} from './api'

describe('Orion Tauri bridge', () => {
  beforeEach(() => vi.clearAllMocks())

  it('only uses explicitly authorized commands', async () => {
    mocks.invoke.mockResolvedValue(undefined)
    const profile = { name: 'portable' }

    await getState()
    await backendKind()
    await adapterIsUp()
    await getConfig()
    await importProfile('{"format":"orion-profile"}', 'portable.json')
    await importProfilePath('C:\\Profils\\portable.orionprofile')
    await importProfilePath()
    await keyNegotiationIdentitySealed(profile as never)
    await validateProfile(profile as never)
    await vaultPosture()
    await keyNegotiationSupport()
    await keyNegotiationFingerprint(profile as never)
    await saveProfile(profile as never)
    await deleteProfile('portable')
    await selectProfile('portable')
    await connect('portable')
    await connect()
    await disconnect()
    await resizeForView('profiles')
    await exportLogs('orion-log', 'contents')

    expect(mocks.invoke.mock.calls).toEqual([
      ['get_state'],
      ['backend_kind'],
      ['adapter_is_up'],
      ['get_config'],
      [
        'import_profile',
        { contents: '{"format":"orion-profile"}', fileName: 'portable.json' },
      ],
      [
        'import_profile_path',
        { path: 'C:\\Profils\\portable.orionprofile' },
      ],
      ['import_profile_path', { path: null }],
      ['key_negotiation_identity_sealed', { keyNegotiation: profile }],
      ['validate_profile', { draft: profile }],
      ['vault_posture'],
      ['key_negotiation_support'],
      ['key_negotiation_fingerprint', { keyNegotiation: profile }],
      ['save_profile', { draft: profile }],
      ['delete_profile', { name: 'portable' }],
      ['select_profile', { name: 'portable' }],
      ['connect', { name: 'portable' }],
      ['connect', { name: null }],
      ['disconnect'],
      ['resize_for_view', { view: 'profiles' }],
      ['export_logs', { stem: 'orion-log', contents: 'contents' }],
    ])
  })

  it('only relays the backend event payload', async () => {
    const unlisten = vi.fn()
    mocks.listen.mockImplementation(async (_name, handler) => {
      handler({ payload: { type: 'state_changed', state: 'up' } })
      return unlisten
    })
    const callback = vi.fn()

    await expect(onEvent(callback)).resolves.toBe(unlisten)
    expect(mocks.listen).toHaveBeenCalledWith('helios://event', expect.any(Function))
    expect(callback).toHaveBeenCalledWith({ type: 'state_changed', state: 'up' })
  })

  it('reports profile paths without exposing a JavaScript read', async () => {
    const unlisten = vi.fn()
    const callback = vi.fn()
    mocks.listen.mockImplementation(async (_name, handler) => {
      handler({ payload: null })
      return unlisten
    })

    await expect(onProfilePath(callback)).resolves.toBe(unlisten)
    expect(mocks.listen).toHaveBeenCalledWith('helios://profile-path', callback)
    expect(callback).toHaveBeenCalledOnce()
  })
})
