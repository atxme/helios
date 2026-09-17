// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  CertificateInventory,
  ClientProfile,
  ImportOutcome,
  ProfileIssues,
} from '../types'

const api = vi.hoisted(() => ({
  certificateActions: vi.fn(),
  certificateInventory: vi.fn(),
  lastCertificateError: vi.fn(),
  runCertificateAction: vi.fn(),
  keyNegotiationSupport: vi.fn(),
  validateProfile: vi.fn(),
  generatePrivateKey: vi.fn(),
  adoptPrivateKey: vi.fn(),
  discardStagedKey: vi.fn(),
  adoptPresharedKey: vi.fn(),
  discardStagedPsk: vi.fn(),
  vaultPosture: vi.fn(),
  allowUnencryptedVolume: vi.fn(),
}))
const documents = vi.hoisted(() => ({ readProfileDocument: vi.fn() }))

vi.mock('../api', () => api)
vi.mock('../profileDocument', () => ({ readProfileDocument: documents.readProfileDocument }))

import { ProfilesView } from './ProfilesView'

const profile = (overrides: Partial<ClientProfile> = {}): ClientProfile => {
  const profile_type =
    overrides.profile_type ??
    (overrides.key_negotiation ? 'helios_key_negotiation' : 'classic')
  return {
    name: 'portable',
    endpoint: '203.0.113.10:51820',
    peer_public_key: 'gateway-public',
    profile_type,
    public_key: 'client-public',
    has_private_key: true,
    has_static_psk: false,
    address: '100.64.1.2/32',
    allowed_ips: '0.0.0.0/0',
    persistent_keepalive: 25,
    heliosd_url: 'http://100.64.0.1:8080',
    ssh_target: null,
    key_negotiation: null,
    ...overrides,
  }
}

/**
 * What the shell reports for a profile whose identity is not on this machine.
 *
 * The default in these tests, because it is the default of a fresh machine:
 * the material is pinned, the protected store holds nothing yet.
 */
const emptyInventory: CertificateInventory = {
  gateway_pq: null,
  gateway_ca_tls: null,
  client_tls: null,
  client_pq: null,
  faults: [],
  identity_sealed: false,
  previous_identity: null,
  operator_credentials: null,
}

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
  ssh_target: null,
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
  api.certificateInventory.mockResolvedValue(emptyInventory)
  api.certificateActions.mockResolvedValue([])
  api.lastCertificateError.mockResolvedValue(null)
  api.runCertificateAction.mockResolvedValue(undefined)
  api.keyNegotiationSupport.mockResolvedValue({ identity_store: false })
  api.validateProfile.mockResolvedValue(noIssues)
  api.generatePrivateKey.mockResolvedValue('clé-publique-générée')
  api.adoptPrivateKey.mockResolvedValue('clé-publique-importée')
  api.discardStagedKey.mockResolvedValue(undefined)
  api.adoptPresharedKey.mockResolvedValue(undefined)
  api.discardStagedPsk.mockResolvedValue(undefined)
  api.vaultPosture.mockResolvedValue({
    hardwareBacked: true,
    softwareKeystore: false,
    volume: 'Volume chiffré.',
    volumeProtected: true,
    unencryptedVolumeWaived: false,
    memoryLocked: true,
    memory: '',
    dumpsExcluded: true,
    dumps: '',
    rotationRequired: [],
    legacyPresent: false,
  })
  api.allowUnencryptedVolume.mockResolvedValue(undefined)
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
    // A preset owns the list it wrote: typing one is what «Personnalisé» is
    // for, and the field does not exist until it is chosen.
    fireEvent.click(screen.getByRole('button', { name: 'Personnalisé' }))
    fireEvent.change(screen.getByLabelText('Trafic via le tunnel'), {
      target: { value: '100.64.0.0/10' },
    })
    // The speedtest targets Helios through the established tunnel; there is
    // no user-configurable API URL on a profile anymore.
    expect(screen.queryByLabelText('URL Helios')).toBeNull()
    // Split tunnelling is a decision, not a defect: narrowing the range warns
    // about nothing.
    expect(screen.queryByText(/en clair/)).toBeNull()
    expect(screen.queryByDisplayValue('static-secret')).toBeNull()
    // The static PSK is this profile's whole protection, so it sits on the
    // «Protection du tunnel» ladder and not under «Avancé». Taking it away
    // drops the profile to the rung below.
    expect(
      screen.getByRole('button', { name: 'PSK statique' }).getAttribute('aria-pressed'),
    ).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: 'Retirer le PSK statique' }))
    expect(screen.getByRole('button', { name: 'Aucune' }).getAttribute('aria-pressed')).toBe(
      'true',
    )
    fireEvent.click(screen.getByRole('button', { name: 'Générer une nouvelle clé' }))

    fireEvent.click(screen.getByRole('button', { name: 'Négociation Helios' }))
    expect(screen.getByText(/CA TLS absente/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Identité protégée'), { target: { value: 'workstation' } })
    // Certificates live in their own destination now; what stays here is the
    // machine-level fact, which is about this build rather than this profile.
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

    // Back down the ladder: nothing has been negotiated, so the floor is
    // still `classic` and the rung is reachable.
    fireEvent.click(screen.getByRole('button', { name: 'Aucune' }))
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

    // Nothing masked is mounted while nobody is entering a key: the paste
    // field is the only one, and it appears on demand.
    expect(document.querySelectorAll('input[type="password"]').length).toBe(0)
    // And no way to reveal a stored value, in either direction.
    expect(screen.queryByLabelText('Afficher la valeur')).toBeNull()

    // The secrets are *stated*, never shown — and the public half, which is
    // meant to leave the machine, is the one value on screen.
    expect(screen.getByText('clé scellée dans le coffre')).toBeTruthy()
    expect(screen.getByText('scellé dans le coffre')).toBeTruthy()
    expect((screen.getByLabelText('Votre clé publique') as HTMLInputElement).value).toBe(
      'client-public',
    )

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
   * The enrolment workflow, which is what the identity block exists for.
   *
   * Generating must yield a **public** key on the spot — copiable, and handed
   * to the operator — because admission is out of band and everything else
   * waits on it. Producing the key only at save time showed a dash where that
   * value belonged and left nothing to copy.
   */
  it('shows and stages a generated public key without ever holding the private one', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile({ has_static_psk: true })], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: 'Générer une nouvelle clé' }))
    await waitFor(() =>
      expect((screen.getByLabelText('Votre clé publique') as HTMLInputElement).value).toBe(
        'clé-publique-générée',
      ),
    )
    expect(screen.getByText('nouvelle clé — à enregistrer')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))
    fireEvent.click(screen.getByRole('button', { name: 'Retirer le PSK statique' }))
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())

    const sent = handlers.onSave.mock.calls[0][0]
    expect(sent.useStagedKey).toBe(true)
    expect(sent.clearPresharedKey).toBe(true)
    // The pair itself stayed in Rust: only the intent travelled.
    expect(sent).not.toHaveProperty('private_key')
  })

  /**
   * Importing an existing key: the one inbound path, and it must not linger.
   *
   * The field is cleared as soon as Rust answers, and Rust answers with the
   * public half — so the value the user gives the operator is the one that
   * will actually be saved.
   */
  it('imports a pasted private key and clears the field at once', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: 'Importer une clé privée' }))
    const field = screen.getByLabelText('Clé privée WireGuard (base64)') as HTMLInputElement
    expect(field.type).toBe('password')

    fireEvent.change(field, { target: { value: 'cGFzdGVkLXByaXZhdGUta2V5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Valider' }))

    await waitFor(() =>
      expect(api.adoptPrivateKey).toHaveBeenCalledWith('cGFzdGVkLXByaXZhdGUta2V5'),
    )
    // The field is gone, and the public half is on screen.
    await waitFor(() =>
      expect(screen.queryByLabelText('Clé privée WireGuard (base64)')).toBeNull(),
    )
    expect((screen.getByLabelText('Votre clé publique') as HTMLInputElement).value).toBe(
      'clé-publique-importée',
    )
    expect(document.body.innerHTML).not.toContain('cGFzdGVkLXByaXZhdGUta2V5')
  })

  /**
   * The screen used to be able to take a static PSK away and nothing else,
   * on the grounds that a PSK is an out-of-band value. That left an operator
   * rotating one — or pointing a profile at a gateway pinned to `static_psk` —
   * with no move but to reissue the whole profile.
   *
   * Entering one is also what selects the mode it is valid under: `orion-core`
   * treats mode and PSK as a single decision, so a screen that set them apart
   * could only build profiles it would then have to mark invalid.
   */
  it('takes a static PSK under the mode that owns it, never among the WireGuard settings', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{
          profiles: [
            profile({
              key_negotiation: {
                mode: 'ml_kem',
                minimum_mode: 'classic',
                endpoint: '203.0.113.10:51821',
                server_name: '203.0.113.10',
                gateway_ca_der: 'ca',
                gateway_pq_certificate: 'pq',
                identity: 'orion-portable',
              },
            }),
          ],
          selected: 'portable',
        }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    // Under ML-KEM there is no PSK row at all — not a greyed one, not one
    // with a sentence explaining why it is unusable. Nor is it hiding under
    // «Avancé»: a negotiation block owns the PSK, the WireGuard block does
    // not.
    expect(screen.queryByRole('button', { name: 'Définir un PSK statique' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))
    expect(screen.queryByRole('button', { name: 'Définir un PSK statique' })).toBeNull()

    // Choosing the mode is what brings the field with it.
    const modes = within(screen.getByLabelText('Mode'))
    fireEvent.click(modes.getByRole('button', { name: 'PSK' }))
    fireEvent.click(screen.getByRole('button', { name: 'Définir un PSK statique' }))
    const field = screen.getByLabelText('PSK WireGuard (base64)') as HTMLInputElement
    expect(field.type).toBe('password')
    fireEvent.change(field, { target: { value: 'cHNrLXNlY3JldA==' } })
    fireEvent.click(screen.getByRole('button', { name: 'Valider' }))

    await waitFor(() => expect(api.adoptPresharedKey).toHaveBeenCalledWith('cHNrLXNlY3JldA=='))
    // The field is gone and the secret never stayed in the document.
    await waitFor(() => expect(screen.queryByLabelText('PSK WireGuard (base64)')).toBeNull())
    expect(document.body.innerHTML).not.toContain('cHNrLXNlY3JldA==')
    expect(screen.getByText('nouveau PSK — à enregistrer')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())
    const sent = handlers.onSave.mock.calls[0][0]
    expect(sent.useStagedPsk).toBe(true)
    expect(sent.clearPresharedKey).toBe(false)
    expect(sent.key_negotiation.mode).toBe('static_psk')
  })

  /**
   * `classic` is the absence of the block, never a mode inside it.
   *
   * The gateway refuses a negotiated `classic` by name
   * (`ClassicNotNegotiable`), so offering it here would only build profiles
   * that fail before the first handshake.
   */
  it('offers only the two negotiable modes and keeps an existing profile Helios', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{
          profiles: [
            profile({
              profile_type: 'helios_key_negotiation',
              key_negotiation: {
                mode: 'ml_kem',
                minimum_mode: 'classic',
                endpoint: '203.0.113.10:51821',
                server_name: '203.0.113.10',
                gateway_ca_der: 'ca',
                gateway_pq_certificate: 'pq',
                identity: 'orion-portable',
              },
            }),
          ],
          selected: 'portable',
        }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    const modes = within(screen.getByLabelText('Mode'))
    expect(modes.getAllByRole('button').map((button) => button.textContent)).toEqual([
      'PSK',
      'ML-KEM',
    ])
    // The floor still shows all three: it is a ratchet, and seeing what one
    // has climbed past is the point.
    expect(within(screen.getByLabelText('Plancher')).getAllByRole('button')).toHaveLength(3)

    expect(screen.queryByRole('button', { name: 'Retirer' })).toBeNull()
  })

  /** Certificates have their own destination: none of it leaks back here. */
  it('shows no certificate surface on the profiles screen', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    expect(screen.queryByRole('heading', { name: 'Certificats' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Renouveler maintenant' })).toBeNull()
    expect(api.certificateInventory).not.toHaveBeenCalled()
  })

  /** The other direction: asking for ML-KEM is what removes the PSK. */
  it('removes the static PSK only when the requested mode stops allowing one', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{
          profiles: [
            profile({
              has_static_psk: true,
              key_negotiation: {
                mode: 'static_psk',
                minimum_mode: 'classic',
                endpoint: '203.0.113.10:51821',
                server_name: '203.0.113.10',
                gateway_ca_der: 'ca',
                gateway_pq_certificate: 'pq',
                identity: 'orion-portable',
              },
            }),
          ],
          selected: 'portable',
        }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    // Shown with its mode, without opening «Avancé»: the PSK belongs to the
    // negotiation block now.
    expect(screen.getByText('scellé dans le coffre')).toBeTruthy()

    // Scoped to the mode group: the floor row offers the same labels.
    const modes = within(screen.getByLabelText('Mode'))
    fireEvent.click(modes.getByRole('button', { name: 'ML-KEM' }))
    // The row goes away with the mode that owned it, rather than lingering as
    // an "aucun" with a sentence about the floor.
    await waitFor(() => expect(screen.queryByText('scellé dans le coffre')).toBeNull())
    expect(screen.queryByRole('button', { name: 'Définir un PSK statique' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())
    const sent = handlers.onSave.mock.calls[0][0]
    expect(sent.clearPresharedKey).toBe(true)
    expect(sent.key_negotiation.mode).toBe('ml_kem')
  })

  /** A rejected key must not stay in the field either. */
  it('clears the paste field when Rust refuses the key', async () => {
    api.adoptPrivateKey.mockRejectedValueOnce('clé privée invalide')
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: 'Importer une clé privée' }))
    fireEvent.change(screen.getByLabelText('Clé privée WireGuard (base64)'), {
      target: { value: 'pas-une-cle' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Valider' }))

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('invalide'))
    expect(document.body.innerHTML).not.toContain('pas-une-cle')
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

    expect(screen.getByRole('list', { name: 'Choisir le profil chargé' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'portable' }).getAttribute('aria-current')).toBe(
      'true',
    )

    fireEvent.click(screen.getByRole('button', { name: 'backup' }))
    await waitFor(() => expect(handlers.onSelect).toHaveBeenCalledWith('backup'))
    await waitFor(() =>
      expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('backup'),
    )
    expect(screen.getByRole('button', { name: 'backup' }).getAttribute('aria-current')).toBe('true')

    fireEvent.click(screen.getByRole('button', { name: 'Nouveau' }))
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('nouveau')
    fireEvent.click(screen.getByRole('button', { name: 'Annuler' }))
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('portable')

    fireEvent.click(screen.getByRole('button', { name: 'Supprimer le profil portable' }))
    const dialog = screen.getByRole('dialog', { name: 'Supprimer « portable » ?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Supprimer' }))
    await waitFor(() => expect(handlers.onDelete).toHaveBeenCalledWith('portable'))
  })

  it('keeps the loaded profile when selecting another profile is refused', async () => {
    const handlers = callbacks()
    handlers.onSelect.mockRejectedValueOnce(new Error('configuration non écrite'))
    render(
      <ProfilesView
        config={{
          profiles: [profile(), profile({ name: 'backup', endpoint: 'backup.example:51820' })],
          selected: 'portable',
        }}
        pathImport={null}
        {...handlers}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'backup' }))
    await waitFor(() => expect(handlers.onSelect).toHaveBeenCalledWith('backup'))
    expect((screen.getByLabelText('Nom') as HTMLInputElement).value).toBe('portable')
    expect(screen.getByRole('button', { name: 'portable' }).getAttribute('aria-current')).toBe(
      'true',
    )
  })

  /**
   * A wg-quick file carries `DNS`, `MTU`, `Table`. The profile imports, and
   * what will not be honoured is said — dropping it silently would hand back a
   * tunnel that differs from the one the file describes.
   */
  it('reports what an imported WireGuard file said and Orion does not apply', async () => {
    const handlers = callbacks()
    handlers.onImport.mockResolvedValue({
      profile: profile({ name: 'fournisseur' }),
      identity_sealed: false,
      identity_error: null,
      private_key_missing: null,
      incomplete: null,
      notices: ['DNS = 100.64.0.1 : Orion n’applique pas de serveur DNS.'],
    })
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    Object.defineProperty(input, 'files', {
      value: [new File(['[Interface]'], 'fournisseur.conf')],
    })
    fireEvent.change(input)

    await waitFor(() => expect(screen.getByText(/n’applique pas de serveur DNS/)).toBeTruthy())
    // Appended, not substituted: the profile still loaded.
    expect(screen.getByText(/« fournisseur » chargé/)).toBeTruthy()
  })

  it('imports normal, incomplete, oversized and unreadable documents', async () => {
    const handlers = callbacks()
    const outcome = (overrides: Partial<ImportOutcome> = {}): ImportOutcome => ({
      profile: profile({ name: 'imported' }),
      identity_sealed: true,
      identity_error: null,
      private_key_missing: null,
      incomplete: null,
      notices: [],
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

    fireEvent.change(input, { target: { files: [new File(['profile'], 'imported.orion')] } })
    await waitFor(() => expect(screen.getByText(/Identité scellée/)).toBeTruthy())
    expect(handlers.onImport).toHaveBeenCalledWith('{"format":"orion-profile"}', 'imported.orion')

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

  // The tray's «Importer un profil…» has no picker of its own: it asks this
  // screen for the one it already owns. A counter drives it because two
  // requests in a row must open it twice.
  it('opens the file picker when the notification area asks for an import', async () => {
    const handlers = callbacks()
    const { container, rerender } = render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        importRequest={0}
        {...handlers}
      />,
    )
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    const click = vi.spyOn(input, 'click')

    // Mounted value: reaching the screen by the navigation rail opens nothing.
    expect(click).not.toHaveBeenCalled()

    for (const request of [1, 2]) {
      rerender(
        <ProfilesView
          config={{ profiles: [profile()], selected: 'portable' }}
          pathImport={null}
          importRequest={request}
          {...handlers}
        />,
      )
    }
    await waitFor(() => expect(click).toHaveBeenCalledTimes(2))
  })

  it('allows import without BitLocker only after stating the incomplete protection', async () => {
    api.vaultPosture.mockResolvedValueOnce({
      hardwareBacked: true,
      softwareKeystore: false,
      volume: 'Volume non chiffré.',
      volumeProtected: false,
      unencryptedVolumeWaived: false,
      memoryLocked: true,
      memory: '',
      dumpsExcluded: true,
      dumps: '',
      rotationRequired: [],
      legacyPresent: false,
    })
    const handlers = callbacks()
    const { container } = render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    const click = vi.spyOn(input, 'click')

    fireEvent.click(screen.getByRole('button', { name: 'Importer' }))

    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByText(/n’est pas chiffré par BitLocker/)).toBeTruthy()
    expect(screen.getByText(/vous acceptez ce niveau de protection/)).toBeTruthy()
    expect(screen.queryByText(/exigence levée/)).toBeNull()
    expect(click).not.toHaveBeenCalled()

    fireEvent.click(
      screen.getByRole('button', { name: 'Continuer avec une protection incomplète' }),
    )

    await waitFor(() => expect(api.allowUnencryptedVolume).toHaveBeenCalledOnce())
    await waitFor(() => expect(click).toHaveBeenCalledOnce())
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('retries the pending save as soon as the bare-volume choice is persisted', async () => {
    api.vaultPosture.mockResolvedValueOnce({
      hardwareBacked: true,
      softwareKeystore: false,
      volume: 'Volume non chiffré.',
      volumeProtected: false,
      unencryptedVolumeWaived: false,
      memoryLocked: true,
      memory: '',
      dumpsExcluded: true,
      dumps: '',
      rotationRequired: [],
      legacyPresent: false,
    })
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    fireEvent.change(screen.getByLabelText('Endpoint'), {
      target: { value: 'vpn.example:51820' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))

    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(handlers.onSave).not.toHaveBeenCalled()
    fireEvent.click(
      screen.getByRole('button', { name: 'Continuer avec une protection incomplète' }),
    )

    await waitFor(() => expect(api.allowUnencryptedVolume).toHaveBeenCalledOnce())
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())
    expect(handlers.onSave.mock.calls[0][0].endpoint).toBe('vpn.example:51820')
  })

  /**
   * The split-tunnel rows, on the property that made them worth adding: one
   * click each way, and no field contradicting the row that is lit.
   */
  it('switches the captured traffic between presets and only types under «Personnalisé»', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))

    const pressed = (name: string) =>
      screen.getByRole('button', { name }).getAttribute('aria-pressed')
    const field = () => screen.getByRole('textbox', { name: 'Trafic via le tunnel' })

    // Under a preset the list is stated, never offered for editing, and one
    // caption explains the chosen segment — not all four at once.
    expect(pressed('Tout')).toBe('true')
    expect((field() as HTMLInputElement).value).toBe('0.0.0.0/0')
    expect(field().hasAttribute('readonly')).toBe(true)
    expect(screen.getByText('Internet et réseaux privés')).toBeTruthy()
    expect(screen.queryByText('Uniquement la passerelle')).toBeNull()

    // The gateway prefix comes from the profile's internal Helios URL, not
    // from a constant: this profile answers at 100.64.0.1.
    fireEvent.click(screen.getByRole('button', { name: 'Helios seul' }))
    expect(pressed('Helios seul')).toBe('true')
    expect((field() as HTMLInputElement).value).toBe('100.64.0.1/32')
    expect(screen.getByText('Uniquement la passerelle')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Réseaux privés' }))
    expect((field() as HTMLInputElement).value).toBe(
      '100.64.0.1/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
    )

    // And back, in one click.
    fireEvent.click(screen.getByRole('button', { name: 'Tout' }))
    expect(pressed('Tout')).toBe('true')

    // «Personnalisé» opens the field on the list the preset left behind, with
    // the caret already in it.
    fireEvent.click(screen.getByRole('button', { name: 'Personnalisé' }))
    expect(pressed('Personnalisé')).toBe('true')
    expect((field() as HTMLInputElement).value).toBe('0.0.0.0/0')
    expect(field().hasAttribute('readonly')).toBe(false)
    await waitFor(() => expect(document.activeElement).toBe(field()))

    // And it stays editable even on a list a preset would recognise: closing
    // the field under the caret is what the sticky choice exists to prevent.
    fireEvent.change(field(), { target: { value: '100.64.0.1/32' } })
    expect(pressed('Personnalisé')).toBe('true')
    expect(field().hasAttribute('readonly')).toBe(false)

    fireEvent.change(field(), { target: { value: '192.168.42.0/24' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    await waitFor(() => expect(handlers.onSave).toHaveBeenCalledOnce())
    expect(handlers.onSave.mock.calls[0][0].allowed_ips).toBe('192.168.42.0/24')
  })

  /**
   * An imported profile whose list matches no preset opens on the field, with
   * no click needed: it was hand-written by whoever produced the document.
   */
  it('opens on the field when the stored list matches no preset', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{
          profiles: [profile({ allowed_ips: '10.9.0.0/16, 192.168.1.0/24' })],
          selected: 'portable',
        }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))

    expect(
      screen.getByRole('button', { name: 'Personnalisé' }).getAttribute('aria-pressed'),
    ).toBe('true')
    const field = screen.getByRole('textbox', { name: 'Trafic via le tunnel' })
    expect((field as HTMLInputElement).value).toBe('10.9.0.0/16, 192.168.1.0/24')
    expect(field.hasAttribute('readonly')).toBe(false)
  })

  /**
   * The protection ladder, on the two things it replaced: a PSK filed under
   * «Avancé» and a type nobody could choose.
   */
  it('puts the static PSK on the protection ladder and opens its entry field', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    const pressed = (name: string) =>
      screen.getByRole('button', { name }).getAttribute('aria-pressed')

    // A classic profile with no key: the weakest rung, and the ladder says so
    // without anyone opening a fold.
    expect(pressed('Aucune')).toBe('true')
    expect(screen.getByText(/premier handshake n’est protégé par rien/)).toBeTruthy()

    // Choosing the rung opens what it is waiting for, rather than a link to it.
    fireEvent.click(screen.getByRole('button', { name: 'PSK statique' }))
    expect(pressed('PSK statique')).toBe('true')
    const field = screen.getByLabelText('PSK WireGuard (base64)') as HTMLInputElement
    expect(field.type).toBe('password')
    fireEvent.change(field, { target: { value: 'cHNrLXN0YXRpcXVl' } })
    fireEvent.click(screen.getByRole('button', { name: 'Valider' }))
    await waitFor(() => expect(api.adoptPresharedKey).toHaveBeenCalledWith('cHNrLXN0YXRpcXVl'))
    expect(document.body.innerHTML).not.toContain('cHNrLXN0YXRpcXVl')

    // The rung is not a WireGuard setting: «Avancé» keeps the three that are.
    fireEvent.click(screen.getByRole('button', { name: 'Avancé' }))
    expect(screen.queryByRole('button', { name: 'Définir un PSK statique' })).toBeNull()

    // A stored profile does not change type. The refusal is said on the
    // segment now, instead of being an alert raised after the save.
    const negotiation = screen.getByRole('button', { name: 'Négociation Helios' })
    expect(negotiation.hasAttribute('disabled')).toBe(true)
    expect(negotiation.getAttribute('title')).toMatch(/Renommez-le/)

    fireEvent.change(screen.getByLabelText('Nom'), { target: { value: 'atelier' } })
    expect(
      screen.getByRole('button', { name: 'Négociation Helios' }).hasAttribute('disabled'),
    ).toBe(false)
  })

  /**
   * The anti-downgrade ratchet of ADR-001, said where the gesture is made:
   * a profile that has negotiated something does not go back to a bare tunnel.
   */
  it('refuses to leave the negotiation rung once a floor has been climbed', async () => {
    const handlers = callbacks()
    render(
      <ProfilesView
        config={{
          profiles: [
            profile({
              name: 'atelier',
              key_negotiation: {
                mode: 'ml_kem',
                minimum_mode: 'ml_kem',
                endpoint: '203.0.113.10:51821',
                server_name: '203.0.113.10',
                gateway_ca_der: 'ca',
                gateway_pq_certificate: 'pq',
                identity: 'orion-atelier',
              },
            }),
          ],
          selected: 'atelier',
        }}
        pathImport={null}
        {...handlers}
      />,
    )
    await waitFor(() => expect(api.validateProfile).toHaveBeenCalled())

    expect(
      screen.getByRole('button', { name: 'Négociation Helios' }).getAttribute('aria-pressed'),
    ).toBe('true')
    for (const rung of ['Aucune', 'PSK statique']) {
      const segment = screen.getByRole('button', { name: rung })
      expect(segment.hasAttribute('disabled')).toBe(true)
      fireEvent.click(segment)
    }
    // Neither click went through: the block is still there, mode included.
    expect(within(screen.getByLabelText('Mode')).getAllByRole('button')).toHaveLength(2)
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
