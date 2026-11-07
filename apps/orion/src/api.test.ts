import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }))
vi.mock('@tauri-apps/api/event', () => ({ listen: mocks.listen }))

import {
  aboutOrion,
  adapterIsUp,
  allowUnencryptedVolume,
  astraCaTlsRotationStatus,
  cancelAstraCaTlsRotation,
  backendKind,
  certificateActions,
  certificateInventory,
  certificateOverview,
  connect,
  continueAstraCaTlsRotation,
  deleteProfile,
  disconnect,
  renewPsk,
  getConfig,
  getState,
  importProfile,
  importProfilePath,
  keyNegotiationSupport,
  lastCertificateError,
  onConfigChanged,
  onEvent,
  onProfilePath,
  onTrayView,
  operatorRotationsOverview,
  operatorSendVaultCopy,
  resizeForView,
  runCertificateAction,
  runSpeedTest,
  saveProfile,
  selectProfile,
  startAstraCaTlsRotation,
  validateProfile,
  vaultPosture,
  exportLogs,
} from './api'

describe('Orion Tauri bridge', () => {
  beforeEach(() => vi.clearAllMocks())

  it('reads the rotations screen and sends the vault copy without naming anything', async () => {
    mocks.invoke.mockResolvedValue(undefined)

    await operatorRotationsOverview()
    await operatorSendVaultCopy()

    expect(mocks.invoke.mock.calls).toEqual([
      ['operator_rotations_overview'],
      ['operator_send_vault_copy'],
    ])
  })

  it('only uses explicitly authorized commands', async () => {
    mocks.invoke.mockResolvedValue(undefined)
    const profile = { name: 'portable' }

    await getState()
    await backendKind()
    await adapterIsUp()
    await getConfig()
    await aboutOrion()
    await importProfile('{"format":"orion-profile"}', 'portable.json')
    await importProfilePath('C:\\Profils\\portable.orion')
    await importProfilePath()
    await validateProfile(profile as never)
    await vaultPosture()
    await allowUnencryptedVolume()
    await keyNegotiationSupport()
    await certificateInventory(profile as never)
    await certificateActions(profile as never)
    await certificateOverview()
    await runCertificateAction('portable', 'renew_now')
    await lastCertificateError('portable')
    await runSpeedTest('udp')
    await saveProfile(profile as never)
    await deleteProfile('portable')
    await selectProfile('portable')
    await connect('portable')
    await connect()
    await disconnect()
    await renewPsk()
    const astraInput = {
      vault_path: 'C:\\astra\\authority-vault.json',
      heliosd_url: 'http://100.64.0.1:8080',
      operation_id: 'a'.repeat(32),
      output_path: 'C:\\astra\\ca-tls-transition.json',
    }
    await startAstraCaTlsRotation(astraInput)
    await continueAstraCaTlsRotation()
    await cancelAstraCaTlsRotation()
    await astraCaTlsRotationStatus()
    await resizeForView('profiles')
    await exportLogs('orion-log', 'contents')

    expect(mocks.invoke.mock.calls).toEqual([
      ['get_state'],
      ['backend_kind'],
      ['adapter_is_up'],
      ['get_config'],
      ['about_orion'],
      [
        'import_profile',
        { contents: '{"format":"orion-profile"}', fileName: 'portable.json' },
      ],
      [
        'import_profile_path',
        { path: 'C:\\Profils\\portable.orion' },
      ],
      ['import_profile_path', { path: null }],
      ['validate_profile', { draft: profile }],
      ['vault_posture'],
      ['allow_unencrypted_volume'],
      ['key_negotiation_support'],
      ['certificate_inventory', { keyNegotiation: profile }],
      ['certificate_actions', { keyNegotiation: profile }],
      ['certificate_overview'],
      ['run_certificate_action', { name: 'portable', action: 'renew_now' }],
      ['last_certificate_error', { name: 'portable' }],
      ['run_speed_test', { mode: 'udp' }],
      ['save_profile', { draft: profile }],
      ['delete_profile', { name: 'portable' }],
      ['select_profile', { name: 'portable' }],
      ['connect', { name: 'portable' }],
      ['connect', { name: null }],
      ['disconnect'],
      ['renew_psk'],
      ['start_astra_ca_tls_rotation', { input: astraInput }],
      ['continue_astra_ca_tls_rotation'],
      ['cancel_astra_ca_tls_rotation'],
      ['astra_ca_tls_rotation_status'],
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

  it('only accepts known tray destinations', async () => {
    const unlisten = vi.fn()
    const callback = vi.fn()
    mocks.listen.mockImplementation(async (_name, handler) => {
      handler({ payload: 'profiles' })
      handler({ payload: 'import' })
      handler({ payload: 'about' })
      handler({ payload: 'unexpected' })
      return unlisten
    })

    await expect(onTrayView(callback)).resolves.toBe(unlisten)
    expect(mocks.listen).toHaveBeenCalledWith('helios://tray-view', expect.any(Function))
    expect(callback.mock.calls).toEqual([['profiles'], ['import'], ['about']])
  })

  it('relays the configuration changes the tray causes', async () => {
    const unlisten = vi.fn()
    const callback = vi.fn()
    mocks.listen.mockImplementation(async (_name, handler) => {
      handler({ payload: null })
      return unlisten
    })

    await expect(onConfigChanged(callback)).resolves.toBe(unlisten)
    expect(mocks.listen).toHaveBeenCalledWith('helios://config-changed', callback)
    expect(callback).toHaveBeenCalledOnce()
  })
})
