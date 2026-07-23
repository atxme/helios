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
  onEvent,
  onProfilePath,
  profilePublicKey,
  saveProfile,
  selectProfile,
} from './api'

describe('pont Tauri Orion', () => {
  beforeEach(() => vi.clearAllMocks())

  it('utilise uniquement les commandes explicitement autorisées', async () => {
    mocks.invoke.mockResolvedValue(undefined)
    const profile = { name: 'portable' }

    await getState()
    await backendKind()
    await adapterIsUp()
    await getConfig()
    await importProfile('{"format":"orion-profile"}', 'portable.json')
    await importProfilePath('C:\\Profils\\portable.orionprofile')
    await profilePublicKey(profile as never)
    await saveProfile(profile as never)
    await deleteProfile('portable')
    await selectProfile('portable')
    await connect('portable')
    await connect()
    await disconnect()

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
      ['profile_public_key', { profile }],
      ['save_profile', { profile }],
      ['delete_profile', { name: 'portable' }],
      ['select_profile', { name: 'portable' }],
      ['connect', { name: 'portable' }],
      ['connect', { name: null }],
      ['disconnect'],
    ])
  })

  it('ne relaie que la charge utile de l’événement backend', async () => {
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

  it('signale les chemins de profil sans exposer de lecture JavaScript', async () => {
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
