// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorOverview: vi.fn(),
  operatorInvitations: vi.fn(),
  revokeInvitation: vi.fn(),
  beginEnrollmentCeremony: vi.fn(),
  getConfig: vi.fn(),
  getState: vi.fn(),
  operatorArtifacts: vi.fn(),
}))
vi.mock('../../api', () => api)

import { ArtifactDownloads, artifactBytes } from './ArtifactDownloads'
import { EnrollmentOperatorPanel } from './EnrollmentOperatorPanel'

const overview = {
  vault_path: 'C:\\astra\\vault.json',
  exists: true,
  vault_fingerprint: 'aaaa',
  slots: [],
  max_slots: 8,
  domain: null,
}

const profile = (endpoint: string) => ({
  name: 'home-gw',
  endpoint,
  profile_type: 'classic',
})

const invitation = (id: string, over: Record<string, unknown> = {}) => ({
  invitation_id: id.repeat(32).slice(0, 32),
  state: 'consommée',
  not_after_unix: 1_800_000_000,
  requested_name: 'portable-bureau',
  peer_admitted: false,
  resumable: false,
  ...over,
})

const status = { session_id: 's', revision: 1, operation: 'invite_enrollment', gesture: 'verifying' }

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorOverview.mockResolvedValue(overview)
  api.operatorInvitations.mockResolvedValue([])
  api.getState.mockResolvedValue('up')
  api.getConfig.mockResolvedValue({
    profiles: [profile('198.51.100.7:51820')],
    selected: 'home-gw',
  })
  api.beginEnrollmentCeremony.mockResolvedValue(status)
  api.revokeInvitation.mockResolvedValue(undefined)
})
afterEach(cleanup)

describe('EnrollmentOperatorPanel', () => {
  it('invite_form_limits_the_duration_to_24_hours', async () => {
    const onCeremony = vi.fn()
    render(<EnrollmentOperatorPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: /Inviter un poste/ }))
    fireEvent.change(screen.getByLabelText('Nom du poste'), { target: { value: 'portable' } })
    const hours = screen.getByLabelText('Durée (heures)')
    const send = screen.getByRole('button', { name: 'Signer l’invitation' }) as HTMLButtonElement

    fireEvent.change(hours, { target: { value: '25' } })
    expect(send.disabled).toBe(true)
    expect(screen.getByText('De 1 à 24 heures.')).toBeTruthy()
    fireEvent.change(hours, { target: { value: '0' } })
    expect(send.disabled).toBe(true)

    fireEvent.change(hours, { target: { value: '24' } })
    expect(send.disabled).toBe(false)
    fireEvent.click(send)
    await waitFor(() => expect(api.beginEnrollmentCeremony).toHaveBeenCalledTimes(1))
    expect(api.beginEnrollmentCeremony).toHaveBeenCalledWith({
      gesture: 'invite',
      valid_for_hours: 24,
      allow_readmission: false,
      name: 'portable',
    })
    expect(onCeremony).toHaveBeenCalledWith(status)
  })

  it('invite_asks_for_the_gateway_leaf_only_without_a_connected_gateway', async () => {
    api.getState.mockResolvedValue('down')
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Inviter un poste/ }))
    expect(screen.getByLabelText('Feuille PQ de la gateway')).toBeTruthy()
    cleanup()

    api.getState.mockResolvedValue('up')
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Inviter un poste/ }))
    await waitFor(() => expect(api.getConfig).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByLabelText('Feuille PQ de la gateway')).toBeNull())
  })

  it('accept_prefills_the_endpoint_of_the_connected_profile', async () => {
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Accepter une demande/ }))
    const endpoint = (await screen.findByLabelText('Adresse publique de la gateway')) as HTMLInputElement
    await waitFor(() => expect(endpoint.value).toBe('198.51.100.7:51820'))
  })

  it('accept_sends_the_request_text_read_in_the_webview', async () => {
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Accepter une demande/ }))
    const endpoint = (await screen.findByLabelText('Adresse publique de la gateway')) as HTMLInputElement
    await waitFor(() => expect(endpoint.value).not.toBe(''))
    const file = new File(['REQUEST-TEXT'], 'portable.helios-request', { type: 'text/plain' })
    fireEvent.change(screen.getByLabelText('Fichier de demande'), { target: { files: [file] } })
    const send = screen.getByRole('button', { name: 'Vérifier et accepter' }) as HTMLButtonElement
    await waitFor(() => expect(send.disabled).toBe(false))
    fireEvent.click(send)
    await waitFor(() => expect(api.beginEnrollmentCeremony).toHaveBeenCalledTimes(1))
    expect(api.beginEnrollmentCeremony).toHaveBeenCalledWith({
      gesture: 'accept',
      request: 'REQUEST-TEXT',
      validity_days: 365,
      endpoint: '198.51.100.7:51820',
    })
  })

  it('resume_is_offered_only_when_resumable', async () => {
    api.operatorInvitations.mockResolvedValue([
      invitation('a', { resumable: true, requested_name: 'pc-salon' }),
      invitation('b', { resumable: false, requested_name: 'tablette' }),
      invitation('c', { state: 'émise', requested_name: null, peer_admitted: null }),
    ])
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText('pc-salon')).toBeTruthy()
    expect(screen.getAllByRole('button', { name: 'Reprendre' })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: 'Révoquer' })).toHaveLength(1)
  })

  it('resume_opens_the_resume_gesture_with_the_connected_endpoint', async () => {
    api.operatorInvitations.mockResolvedValue([invitation('a', { resumable: true })])
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reprendre' }))
    const endpoint = (await screen.findByLabelText('Adresse publique de la gateway')) as HTMLInputElement
    await waitFor(() => expect(endpoint.value).toBe('198.51.100.7:51820'))
    fireEvent.click(screen.getByRole('button', { name: 'Reprendre l’enrôlement' }))
    await waitFor(() => expect(api.beginEnrollmentCeremony).toHaveBeenCalledTimes(1))
    expect(api.beginEnrollmentCeremony).toHaveBeenCalledWith({
      gesture: 'resume',
      invitation_id: 'a'.repeat(32),
      endpoint: '198.51.100.7:51820',
    })
  })

  it('revoking_asks_for_a_confirmation_first', async () => {
    api.operatorInvitations.mockResolvedValue([
      invitation('c', { state: 'émise', requested_name: null, peer_admitted: null }),
    ])
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Révoquer' }))
    expect(api.revokeInvitation).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByRole('button', { name: 'Révoquer l’invitation' }))
    await waitFor(() => expect(api.revokeInvitation).toHaveBeenCalledWith('c'.repeat(32)))
    await waitFor(() => expect(api.operatorInvitations).toHaveBeenCalledTimes(2))
  })

  it('a_rejected_call_shows_an_alert', async () => {
    api.beginEnrollmentCeremony.mockRejectedValue('une cérémonie opérateur est déjà ouverte')
    render(<EnrollmentOperatorPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Inviter un poste/ }))
    fireEvent.change(screen.getByLabelText('Nom du poste'), { target: { value: 'portable' } })
    fireEvent.click(screen.getByRole('button', { name: 'Signer l’invitation' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText(/déjà ouverte/)).toBeTruthy()
  })
})

describe('ArtifactDownloads', () => {
  it('artifacts_are_offered_for_download', async () => {
    api.operatorArtifacts.mockResolvedValue([
      { file_name: 'laptop.helios-invite', contents: 'INVITE', encoding: 'text' },
      { file_name: 'a-client-cert.der', contents: 'AAEC/w==', encoding: 'base64' },
    ])
    const saved: Blob[] = []
    const create = vi.fn((blob: Blob) => {
      saved.push(blob)
      return 'blob:x'
    })
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    render(<ArtifactDownloads gesture="done" />)
    fireEvent.click(await screen.findByRole('button', { name: /laptop\.helios-invite/ }))
    fireEvent.click(screen.getByRole('button', { name: /a-client-cert\.der/ }))
    expect(click).toHaveBeenCalledTimes(2)

    const read = (blob: Blob) =>
      new Promise<number[]>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(Array.from(new Uint8Array(reader.result as ArrayBuffer)))
        reader.readAsArrayBuffer(blob)
      })
    expect(await read(saved[0])).toEqual(Array.from(new TextEncoder().encode('INVITE')))
    // The DER is saved as its raw bytes, not as the base64 text.
    expect(await read(saved[1])).toEqual([0, 1, 2, 255])
    click.mockRestore()
  })

  it('a_base64_artifact_decodes_to_its_raw_bytes', () => {
    expect(
      Array.from(artifactBytes({ file_name: 'x.der', contents: 'AAEC/w==', encoding: 'base64' })),
    ).toEqual([0, 1, 2, 255])
    expect(
      Array.from(artifactBytes({ file_name: 'x.txt', contents: 'é', encoding: 'text' })),
    ).toEqual([0xc3, 0xa9])
  })

  it('nothing_is_fetched_before_the_ceremony_ends', () => {
    render(<ArtifactDownloads gesture="signing" />)
    expect(api.operatorArtifacts).not.toHaveBeenCalled()
  })
})
