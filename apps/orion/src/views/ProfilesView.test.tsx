// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ClientProfile, ImportOutcome, ProfileIssues } from '../types'

const api = vi.hoisted(() => ({
  keyNegotiationFingerprint: vi.fn(),
  keyNegotiationIdentitySealed: vi.fn(),
  keyNegotiationSupport: vi.fn(),
  validateProfile: vi.fn(),
}))
const documents = vi.hoisted(() => ({ readProfileDocument: vi.fn() }))

vi.mock('../api', () => api)
vi.mock('../profileDocument', () => ({ readProfileDocument: documents.readProfileDocument }))

import { ProfilesView } from './ProfilesView'

const profile = (overrides: Partial<ClientProfile> = {}): ClientProfile => ({
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
  key_negotiation: null,
  ...overrides,
})

const noIssues: ProfileIssues = {
  name: null,
  endpoint: null,
  private_key: null,
  peer_public_key: null,
  preshared_key: null,
  address: null,
  allowed_ips: null,
  persistent_keepalive: null,
  heliosd_url: null,
  key_negotiation: null,
}

function callbacks() {
  return {
    onPathImportHandled: vi.fn(),
    onImport: vi.fn(),
    onSave: vi.fn().mockResolvedValue(undefined),
    onDelete: vi.fn().mockResolvedValue(undefined),
    onSelect: vi.fn().mockResolvedValue(undefined),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.keyNegotiationFingerprint.mockResolvedValue('sha256:fingerprint')
  api.keyNegotiationIdentitySealed.mockResolvedValue(false)
  api.keyNegotiationSupport.mockResolvedValue({ identity_store: false })
  api.validateProfile.mockResolvedValue(noIssues)
  documents.readProfileDocument.mockResolvedValue('{"format":"orion-profile"}')
})

afterEach(cleanup)

describe('ProfilesView interactions', () => {
  it('edits, undoes, saves and exposes advanced security choices', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile({ has_static_psk: true })], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )

    await waitFor(() =>
      expect((screen.getByLabelText('Votre clé publique') as HTMLInputElement).value).toBe(
        'client-public',
      ),
    )
    fireEvent.change(screen.getByLabelText('Nom'), { target: { value: 'workstation' } })
    fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: 'vpn.example:51820' } })
    expect(screen.getByText('Modifications non enregistrées')).toBeTruthy()

    fireEvent.keyDown(window, { key: 'z', ctrlKey: true })
    expect((screen.getByLabelText('Endpoint') as HTMLInputElement).value).toBe(
      '203.0.113.10:51820',
    )

    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))
    fireEvent.change(screen.getByLabelText('Trafic capté'), { target: { value: '100.64.0.0/10' } })
    expect(screen.getByText(/ce qui en sort part/)).toBeTruthy()
    expect(screen.getByText(/Une valeur ici la/)).toBeTruthy()
    expect(screen.queryByDisplayValue('static-secret')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retirer le PSK statique' }))
    fireEvent.click(screen.getByRole('button', { name: 'Générer une nouvelle clé' }))

    fireEvent.click(screen.getByRole('button', { name: 'Ajouter' }))
    expect(screen.getByText(/CA TLS absente/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Identité protégée'), { target: { value: 'workstation' } })
    expect(screen.getByText(/Aucune identité protégée nommée/)).toBeTruthy()
    expect(screen.getByText(/Aucun stockage protégé d’identité/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Afficher les données encodées' }))
    fireEvent.change(screen.getByLabelText('CA TLS de la gateway (DER base64)'), {
      target: { value: 'ca-data' },
    })
    fireEvent.change(screen.getByLabelText('Certificat PQ épinglé (base64)'), {
      target: { value: 'pq-data' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Fermer' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

    fireEvent.click(screen.getByRole('button', { name: /Retirer la négociation/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())
    expect(screen.getByText(/« workstation » enregistré/)).toBeTruthy()
  })

  /**
   * The property the whole redaction exists for, asserted on the DOM.
   *
   * The screen used to hold the WireGuard private key in a `TextField` with a
   * reveal button. Nothing here may put a secret in a node's value again, and
   * the check is on the rendered document rather than on a component we
   * remembered not to use.
   */
  it('never renders a secret and never sends one back', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile({ has_static_psk: true })], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))

    // No masked field at all: a `type="password"` input is how a secret used
    // to get here, and there is no longer any secret for one to hold.
    expect(document.querySelectorAll('input[type="password"]').length).toBe(0)
    // Nor a way to reveal one.
    expect(screen.queryByLabelText('Afficher la valeur')).toBeNull()

    // The two secrets are *stated*, never shown.
    expect(screen.getByText('scellée dans le coffre')).toBeTruthy()
    expect(screen.getByText('scellé dans le coffre')).toBeTruthy()

    // And what leaves the screen carries neither, in either direction.
    fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: 'vpn.example:51820' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())

    const sent = handlers.onSave.mock.calls[0][0]
    expect(sent).not.toHaveProperty('private_key')
    expect(sent).not.toHaveProperty('preshared_key')
    expect(sent).not.toHaveProperty('public_key')
    expect(sent.endpoint).toBe('vpn.example:51820')

    const validated = api.validateProfile.mock.calls[api.validateProfile.mock.calls.length - 1]?.[0]
    expect(validated).not.toHaveProperty('private_key')
    expect(validated).not.toHaveProperty('preshared_key')
  })

  /**
   * The intents are the only way the screen touches a secret, and they are
   * requests, not values.
   */
  it('asks Rust to draw a key and to drop a PSK, without carrying either', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile({ has_static_psk: true })], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))

    fireEvent.click(screen.getByRole('button', { name: 'Générer une nouvelle clé' }))
    expect(screen.getByText(/réadmise par l’opérateur/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Retirer le PSK statique' }))

    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())

    const sent = handlers.onSave.mock.calls[0][0]
    expect(sent.generatePrivateKey).toBe(true)
    expect(sent.clearPresharedKey).toBe(true)
    // Still no value anywhere near it.
    expect(JSON.stringify(sent)).not.toContain('client-public')
  })

  it('selects, creates and deletes profiles through explicit actions', async () => {
    const handlers = callbacks()
    const backup = profile({ name: 'backup', endpoint: 'backup.example:51820' })
    render(
      <ProfilesView
        config={{ profiles: [profile(), backup], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'backup' }))
    expect(handlers.onSelect).toHaveBeenCalledWith('backup')
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('backup')

    fireEvent.click(screen.getByRole('button', { name: 'Nouveau' }))
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('nouveau')
    fireEvent.click(screen.getByRole('button', { name: 'Annuler' }))
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('portable')

    fireEvent.click(screen.getByRole('button', { name: 'Supprimer le profil portable' }))
    const dialog = screen.getByRole('dialog', { name: 'Supprimer « portable » ?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Supprimer' }))
    await waitFor(() => expect(handlers.onDelete).toHaveBeenCalledWith('portable'))
  })

  it('imports normal, incomplete, oversized and unreadable documents', async () => {
    const handlers = callbacks()
    const outcome = (overrides: Partial<ImportOutcome> = {}): ImportOutcome => ({
      profile: profile({ name: 'imported' }),
      identity_sealed: true,
      identity_error: null,
      private_key_missing: null,
      ...overrides,
    })
    handlers.onImport.mockResolvedValueOnce(outcome())
    const { container } = render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    const input = container.querySelector('input[type="file"]') as HTMLInputElement

    fireEvent.change(input, { target: { files: [new File(['profile'], 'imported.orionprofile')] } })
    await waitFor(() => expect(screen.getByText(/Identité scellée/)).toBeTruthy())
    expect(handlers.onImport).toHaveBeenCalledWith('{"format":"orion-profile"}', 'imported.orionprofile')

    handlers.onImport.mockResolvedValueOnce(outcome({ private_key_missing: 'private key expected' }))
    fireEvent.change(input, { target: { files: [new File(['profile'], 'invitation.json')] } })
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('private key expected'))

    fireEvent.change(input, {
      target: { files: [new File([new Uint8Array(64 * 1024 + 1)], 'huge.json')] },
    })
    expect(screen.getByRole('alert').textContent).toContain('maximum 64 Kio')

    documents.readProfileDocument.mockRejectedValueOnce(new Error('invalid encoding'))
    fireEvent.change(input, { target: { files: [new File(['bad'], 'bad.json')] } })
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('invalid encoding'))
  })

  it('loads an associated profile and explains a failed identity seal', async () => {
    const handlers = callbacks()
    const associated = profile({ name: 'portable', has_private_key: false })
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={associated}
        {...handlers}
      />,
    )

    await waitFor(() => expect(handlers.onPathImportHandled).toHaveBeenCalledOnce())
    expect(screen.getByText(/remplacera le profil existant/)).toBeTruthy()
  })
})
