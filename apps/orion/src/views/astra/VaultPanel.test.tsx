// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorOverview: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  beginVaultCeremony: vi.fn(),
  renameOperatorKey: vi.fn(),
  operatorDomainDefaults: vi.fn(),
  operatorVaultLocation: vi.fn(),
  chooseVaultLocation: vi.fn(),
  resetVaultLocation: vi.fn(),
  operatorRotationsOverview: vi.fn(),
  operatorSendVaultCopy: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { SlotView, VaultOverview } from '../../types'
import { overview as rotationsOverview } from './rotationFixtures'
import { VaultPanel } from './VaultPanel'

const overview: VaultOverview = {
  vault_path: 'C:\\astra\\vault.json',
  exists: true,
  location_available: true,
  bootstrapped: true,
  credentials_complete: true,
  vault_fingerprint: 'aaaa bbbb cccc',
  slots: [
    { slot_id: '01', label: 'YubiKey bureau', role: 'principale', state: 'active' },
    { slot_id: '02', label: 'YubiKey coffre', role: 'recuperation', state: 'active' },
  ],
  max_slots: 8,
  domain: null,
}

const readyDomain = {
  trust_domain_id: 'td',
  rp_id: 'gw.tail.ts.net',
  ca_pq_fingerprint: 'ff',
  ca_epoch: 1,
  ca_tls_epoch: 1,
  ca_tls_present: true,
  server_name: 'gw.tail.ts.net',
  gateway_wg_public_key: 'KEY',
}

const slot = (n: number): SlotView => ({
  slot_id: `0${n}`,
  label: `Clé ${n}`,
  role: n === 1 ? 'principale' : 'recuperation',
  state: 'active',
})

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorOverview.mockResolvedValue(overview)
  api.operatorVaultLocation.mockResolvedValue({
    path: 'C:\\astra',
    is_default: true,
    picker_available: true,
    error: null,
  })
  api.operatorDomainDefaults.mockResolvedValue({ rp_id: 'gw.tail.ts.net' })
})
afterEach(cleanup)

describe('VaultPanel', () => {
  it('the_vault_panel_shows_slots_and_fingerprint', async () => {
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText('YubiKey bureau')).toBeTruthy()
    expect(screen.getByText('YubiKey coffre')).toBeTruthy()
    expect(screen.getByText('Principale')).toBeTruthy()
    expect(screen.getByText('Récupération')).toBeTruthy()
    expect(screen.getByText('aaaa bbbb cccc')).toBeTruthy()
    expect(screen.getByText(/2 sur 8/)).toBeTruthy()
  })

  it('verify_key_starts_the_ceremony', async () => {
    const status = { session_id: 's', revision: 1, operation: 'verify_key' }
    api.beginOperatorCeremony.mockResolvedValue(status)
    const onCeremony = vi.fn()
    render(<VaultPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Vérifier une clé' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    expect(api.beginOperatorCeremony).toHaveBeenCalledWith({ kind: 'verify_key' })
  })

  it('shows_the_error_when_the_overview_fails', async () => {
    api.operatorOverview.mockRejectedValue('coffre illisible')
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText(/coffre illisible/)).toBeTruthy()
  })

  it('an_unreadable_setting_keeps_the_ways_out_beside_its_error', async () => {
    const unreadable = 'le réglage de l’emplacement du coffre est illisible'
    api.operatorOverview.mockRejectedValueOnce(unreadable).mockResolvedValue(overview)
    api.operatorVaultLocation.mockResolvedValue({
      path: null,
      is_default: false,
      picker_available: true,
      error: unreadable,
    })
    api.resetVaultLocation.mockResolvedValue({
      path: 'C:\\astra',
      is_default: true,
      picker_available: true,
      error: null,
    })
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText(unreadable)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Changer…' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Emplacement par défaut' }))
    await waitFor(() => expect(api.resetVaultLocation).toHaveBeenCalled())
    expect(await screen.findByText('YubiKey bureau')).toBeTruthy()
    expect(screen.queryByText(unreadable)).toBeNull()
  })

  it('a_failed_read_still_offers_the_location_buttons', async () => {
    api.operatorOverview.mockRejectedValue('coffre illisible')
    api.operatorVaultLocation.mockResolvedValue({
      path: 'D:\\x',
      is_default: false,
      picker_available: true,
      error: null,
    })
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText(/Lecture du coffre impossible : coffre illisible/)).toBeTruthy()
    expect(await screen.findByRole('button', { name: 'Changer…' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Emplacement par défaut' })).toBeTruthy()
  })

  it('an_absent_vault_offers_the_domain_creation_with_a_suggested_name', async () => {
    api.operatorOverview.mockResolvedValue({ ...overview, exists: false, slots: [] })
    const status = { session_id: 's', revision: 1, operation: 'create_domain' }
    api.beginVaultCeremony.mockResolvedValue(status)
    const onCeremony = vi.fn()
    render(<VaultPanel onCeremony={onCeremony} />)
    const rp = (await screen.findByLabelText('Nom du domaine (RP ID)')) as HTMLInputElement
    await waitFor(() => expect(rp.value).toBe('gw.tail.ts.net'))
    expect(screen.getByText(/Ce nom ne se change plus\. Prenez le nom Tailscale/)).toBeTruthy()
    expect((screen.getByLabelText('Clé principale') as HTMLInputElement).value).toBe('Clé principale')
    expect((screen.getByLabelText('Clé de récupération') as HTMLInputElement).value).toBe(
      'Clé de récupération',
    )
    expect(screen.queryByText(/astra-signer init/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Créer le domaine' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    expect(api.beginVaultCeremony).toHaveBeenCalledWith({
      gesture: 'create_domain',
      rp_id: 'gw.tail.ts.net',
      authority_url: 'https://gw.tail.ts.net',
      first_label: 'Clé principale',
      second_label: 'Clé de récupération',
    })
  })

  it('the_origin_follows_the_rp_id_until_edited', async () => {
    api.operatorOverview.mockResolvedValue({ ...overview, exists: false, slots: [] })
    api.operatorDomainDefaults.mockResolvedValue({ rp_id: null })
    render(<VaultPanel onCeremony={vi.fn()} />)
    const rp = (await screen.findByLabelText('Nom du domaine (RP ID)')) as HTMLInputElement
    const origin = screen.getByLabelText('Origine') as HTMLInputElement
    fireEvent.change(rp, { target: { value: 'a.example' } })
    expect(origin.value).toBe('https://a.example')
    fireEvent.change(origin, { target: { value: 'https://autre.example:8443' } })
    fireEvent.change(rp, { target: { value: 'b.example' } })
    expect(origin.value).toBe('https://autre.example:8443')
  })

  it('an_unavailable_location_offers_no_creation', async () => {
    api.operatorOverview.mockResolvedValue({
      ...overview,
      exists: false,
      location_available: false,
      slots: [],
    })
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText('Emplacement introuvable')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Créer le domaine' })).toBeNull()
    expect(screen.queryByLabelText('Nom du domaine (RP ID)')).toBeNull()
  })

  it('the_location_can_be_changed_and_reset_and_errors_are_shown', async () => {
    api.chooseVaultLocation.mockResolvedValueOnce(null)
    api.operatorVaultLocation.mockResolvedValue({
      path: 'D:\\x',
      is_default: false,
      picker_available: true,
      error: null,
    })
    api.resetVaultLocation.mockRejectedValue('une cérémonie opérateur est ouverte')
    render(<VaultPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Changer…' }))
    await waitFor(() => expect(api.chooseVaultLocation).toHaveBeenCalled())
    expect(api.operatorOverview).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Emplacement par défaut' }))
    expect(await screen.findByText(/une cérémonie opérateur est ouverte/)).toBeTruthy()
  })

  it('a_single_key_vault_shows_the_unbootstrapped_banner', async () => {
    api.operatorOverview.mockResolvedValue({
      ...overview,
      bootstrapped: false,
      slots: [slot(1)],
    })
    const status = { session_id: 's', revision: 1, operation: 'add_key' }
    api.beginVaultCeremony.mockResolvedValue(status)
    const onCeremony = vi.fn()
    render(<VaultPanel onCeremony={onCeremony} />)
    expect(await screen.findByText('Une seule clé : la perdre, c’est perdre le domaine.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Ajouter la clé de récupération' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    expect(api.beginVaultCeremony).toHaveBeenCalledWith({
      gesture: 'add_key',
      label: 'Clé de récupération',
      role: 'recuperation',
    })
  })

  it('removal_is_disabled_at_two_keys_and_confirmed_above', async () => {
    render(<VaultPanel onCeremony={vi.fn()} />)
    await screen.findByText('YubiKey bureau')
    for (const button of screen.getAllByRole('button', { name: /^Retirer/ })) {
      expect((button as HTMLButtonElement).disabled).toBe(true)
    }
    expect(screen.getByText('Le coffre doit garder au moins deux clés.')).toBeTruthy()
    cleanup()

    api.operatorOverview.mockResolvedValue({ ...overview, slots: [slot(1), slot(2), slot(3)] })
    const status = { session_id: 's', revision: 1, operation: 'remove_key' }
    api.beginVaultCeremony.mockResolvedValue(status)
    const onCeremony = vi.fn()
    render(<VaultPanel onCeremony={onCeremony} />)
    await screen.findByText('Clé 3')
    fireEvent.click(screen.getByRole('button', { name: 'Retirer Clé 3' }))
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(
        'Retirer « Clé 3 » ? Le retrait est définitif. Une sauvegarde antérieure du coffre reste ouvrable par cette clé.',
      ),
    ).toBeTruthy()
    expect(
      within(dialog).getByText('Pour ouvrir le coffre, présentez une autre clé que « Clé 3 ».'),
    ).toBeTruthy()
    expect(api.beginVaultCeremony).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Retirer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    expect(api.beginVaultCeremony).toHaveBeenCalledWith({ gesture: 'remove_key', slot_id: '03' })
  })

  it('marking_waits_for_the_gateway', async () => {
    render(<VaultPanel onCeremony={vi.fn()} />)
    await screen.findByText('YubiKey bureau')
    expect(screen.getByText('La gateway n’est pas encore dans le relais.')).toBeTruthy()
    for (const button of screen.getAllByRole('button', { name: /^Marquer perdue/ })) {
      expect((button as HTMLButtonElement).disabled).toBe(true)
    }
    cleanup()

    api.operatorOverview.mockResolvedValue({
      ...overview,
      domain: readyDomain,
      slots: [
        slot(1),
        { ...slot(2), state: 'lost' },
        { ...slot(3), state: 'revoked' },
      ],
    })
    const status = { session_id: 's', revision: 1, operation: 'mark_key' }
    api.beginVaultCeremony.mockResolvedValue(status)
    render(<VaultPanel onCeremony={vi.fn()} />)
    await screen.findByText('Clé 3')
    expect(screen.getByText('perdue')).toBeTruthy()
    expect(screen.getByText('révoquée')).toBeTruthy()
    expect(screen.queryByText('La gateway n’est pas encore dans le relais.')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Marquer perdue Clé 3' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Réactiver Clé 3' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Marquer perdue Clé 1' }))
    await waitFor(() =>
      expect(api.beginVaultCeremony).toHaveBeenCalledWith({
        gesture: 'mark_key',
        slot_id: '01',
        lost: true,
      }),
    )
    fireEvent.click(screen.getByRole('button', { name: 'Réactiver Clé 2' }))
    await waitFor(() =>
      expect(api.beginVaultCeremony).toHaveBeenCalledWith({
        gesture: 'mark_key',
        slot_id: '02',
        lost: false,
      }),
    )
  })

  it('renaming_saves_on_enter_and_refreshes', async () => {
    api.renameOperatorKey.mockResolvedValue(undefined)
    render(<VaultPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Renommer YubiKey bureau' }))
    const input = screen.getByLabelText('Nouveau libellé')
    fireEvent.change(input, { target: { value: 'Bureau 2' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(api.renameOperatorKey).toHaveBeenCalledWith('01', 'Bureau 2'))
    await waitFor(() => expect(api.operatorOverview).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.queryByLabelText('Nouveau libellé')).toBeNull())
  })

  it('renaming_is_cancelled_on_escape', async () => {
    render(<VaultPanel onCeremony={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Renommer YubiKey bureau' }))
    fireEvent.keyDown(screen.getByLabelText('Nouveau libellé'), { key: 'Escape' })
    expect(screen.queryByLabelText('Nouveau libellé')).toBeNull()
    expect(api.renameOperatorKey).not.toHaveBeenCalled()
  })

  it('adding_is_disabled_when_full', async () => {
    api.operatorOverview.mockResolvedValue({
      ...overview,
      max_slots: 2,
    })
    render(<VaultPanel onCeremony={vi.fn()} />)
    await screen.findByText('YubiKey bureau')
    expect((screen.getByRole('button', { name: 'Ajouter une clé' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText('Le coffre porte déjà huit clés.')).toBeTruthy()
  })

  it('adding_starts_the_ceremony_with_label_and_role', async () => {
    const status = { session_id: 's', revision: 1, operation: 'add_key' }
    api.beginVaultCeremony.mockResolvedValue(status)
    const onCeremony = vi.fn()
    render(<VaultPanel onCeremony={onCeremony} />)
    fireEvent.change(await screen.findByLabelText('Libellé de la nouvelle clé'), {
      target: { value: 'Clé voyage' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Ajouter une clé' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    expect(api.beginVaultCeremony).toHaveBeenCalledWith({
      gesture: 'add_key',
      label: 'Clé voyage',
      role: 'recuperation',
    })
  })

  // Spec §5.9: a key change reaches Astra with the copy. A marking leaves the vault bytes
  // as they were, so the copy reads old only by the document's epoch.
  it('a_document_ahead_of_astra_offers_the_send_here', async () => {
    api.operatorRotationsOverview
      .mockResolvedValueOnce(rotationsOverview({ localCredentialRegistryEpoch: 6 }))
      .mockResolvedValue(rotationsOverview({ localCredentialRegistryEpoch: 6 }))
    api.operatorSendVaultCopy.mockResolvedValue({
      state: 'copied',
      fingerprint: 'ef'.repeat(32),
      credential_registry_epoch: 6,
      document_waits: false,
    })
    render(<VaultPanel onCeremony={vi.fn()} />)
    const line = (await screen.findByText('Copie du coffre')).closest('li') as HTMLElement
    expect(within(line).getByText('Document ancien')).toBeTruthy()
    fireEvent.click(within(line).getByRole('button', { name: 'Envoyer' }))
    await waitFor(() => expect(api.operatorSendVaultCopy).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(api.operatorRotationsOverview).toHaveBeenCalledTimes(2))
  })

  it('a_send_held_back_is_said_and_not_dropped', async () => {
    api.operatorRotationsOverview.mockResolvedValue(
      rotationsOverview({ localCredentialRegistryEpoch: 6 }),
    )
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'held_back' })
    render(<VaultPanel onCeremony={vi.fn()} />)
    const line = (await screen.findByText('Copie du coffre')).closest('li') as HTMLElement
    fireEvent.click(within(line).getByRole('button', { name: 'Envoyer' }))
    expect(await screen.findByText(/Copie retenue par une opération en cours/)).toBeTruthy()
  })

  it('a_copy_in_step_shows_no_send', async () => {
    api.operatorRotationsOverview.mockResolvedValue(rotationsOverview())
    render(<VaultPanel onCeremony={vi.fn()} />)
    const line = (await screen.findByText('Copie du coffre')).closest('li') as HTMLElement
    expect(within(line).queryByRole('button', { name: 'Envoyer' })).toBeNull()
  })
})
