// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorOverview: vi.fn(),
  writeDomainRelay: vi.fn(),
  adoptConnectedGateway: vi.fn(),
  beginVaultCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import { DomainPanel } from './DomainPanel'

const base = {
  vault_path: 'v.json',
  exists: true,
  location_available: true,
  vault_fingerprint: null,
  slots: [],
  max_slots: 8,
}

const onCeremony = vi.fn()
const domain = {
  trust_domain_id: 'td-1',
  rp_id: 'helios.example',
  ca_pq_fingerprint: 'abcd',
  ca_epoch: 3,
  ca_tls_epoch: 2,
  ca_tls_present: true,
  server_name: 'gw.example' as string | null,
  gateway_wg_public_key: 'wgkey=' as string | null,
  astra_service_public_key: null as string | null,
  astra_service_key_epoch: null as number | null,
  astra_authority_url: null as string | null,
}
const withDomain = (over: Partial<typeof domain>, credentials_complete = true) => ({
  ...base,
  location_available: true,
  bootstrapped: true,
  credentials_complete,
  domain: { ...domain, ...over },
})
const status = { session_id: 's', revision: 1, operation: 'finalize_domain' }

beforeEach(() => {
  vi.clearAllMocks()
  api.writeDomainRelay.mockResolvedValue(undefined)
  api.adoptConnectedGateway.mockResolvedValue(undefined)
  api.beginVaultCeremony.mockResolvedValue(status)
})
afterEach(cleanup)

describe('DomainPanel', () => {
  it('the_domain_panel_shows_the_ca_pq_fingerprint_grouped', async () => {
    api.operatorOverview.mockResolvedValue({
      ...base,
      domain: {
        trust_domain_id: 'td-1',
        rp_id: 'helios.example',
        ca_pq_fingerprint: 'abcd 1234 ef56',
        ca_epoch: 3,
        ca_tls_epoch: 2,
        ca_tls_present: true,
        server_name: 'gw.example',
        gateway_wg_public_key: 'wgkey=',
        astra_service_public_key: null,
        astra_service_key_epoch: null,
        astra_authority_url: null,
      },
    })
    render(<DomainPanel onCeremony={onCeremony} />)
    expect(await screen.findByText('abcd 1234 ef56')).toBeTruthy()
    expect(screen.getByText('helios.example')).toBeTruthy()
    expect(screen.getByText('gw.example')).toBeTruthy()
  })

  it('says_when_no_relay_is_recorded', async () => {
    api.operatorOverview.mockResolvedValue({ ...base, domain: null })
    render(<DomainPanel onCeremony={onCeremony} />)
    expect(await screen.findByText(/Aucun relais n’est enregistré/)).toBeTruthy()
  })

  it('says_when_the_location_is_missing_or_holds_no_vault', async () => {
    api.operatorOverview.mockResolvedValue({
      ...base,
      exists: false,
      location_available: false,
      domain: null,
    })
    render(<DomainPanel onCeremony={onCeremony} />)
    expect(await screen.findByText(/Emplacement introuvable/)).toBeTruthy()
    expect(screen.queryByText(/Aucun relais/)).toBeNull()
    cleanup()

    api.operatorOverview.mockResolvedValue({ ...base, exists: false, domain: null })
    render(<DomainPanel onCeremony={onCeremony} />)
    expect(await screen.findByText(/Aucun coffre à cet emplacement/)).toBeTruthy()
    expect(screen.queryByText(/Aucun relais/)).toBeNull()
  })

  it('refuses_an_epoch_of_zero_inline', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({}))
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    fireEvent.change(screen.getByLabelText('Époque de la clé de service'), {
      target: { value: '0' },
    })
    expect(screen.getByText('Un entier supérieur à zéro.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enregistrer' }).hasAttribute('disabled')).toBe(true)
  })

  it('shows_the_error_when_the_overview_fails', async () => {
    api.operatorOverview.mockRejectedValue('lecture impossible')
    render(<DomainPanel onCeremony={onCeremony} />)
    expect(await screen.findByText(/lecture impossible/)).toBeTruthy()
  })

  it('only_changed_values_are_sent_and_overwrites_are_confirmed', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({ server_name: null, gateway_wg_public_key: null }))
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    fireEvent.change(screen.getByLabelText('Nom de service'), { target: { value: 'gw.new' } })
    fireEvent.change(screen.getByLabelText('Époque de la clé de service'), { target: { value: '4' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    // Not yet recorded: the confirmation lists what will be written.
    expect(await screen.findByText('Époque de la clé de service : 4')).toBeTruthy()
    expect(api.writeDomainRelay).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirmer' }))
    await waitFor(() =>
      expect(api.writeDomainRelay).toHaveBeenCalledWith({
        server_name: 'gw.new',
        astra_service_key_epoch: 4,
      }),
    )
  })

  it('an_overwrite_shows_the_old_and_new_values_and_waits_for_confirmation', async () => {
    api.operatorOverview.mockResolvedValue(
      withDomain({
        astra_service_public_key: 'oldkey=',
        astra_authority_url: 'https://old.example',
      }),
    )
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    fireEvent.change(screen.getByLabelText('Clé de service Astra'), { target: { value: 'newkey=' } })
    fireEvent.change(screen.getByLabelText('Origine d’Astra'), { target: { value: 'https://new.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    expect(await screen.findByText('Clé de service Astra : oldkey= → newkey=')).toBeTruthy()
    expect(screen.getByText('Origine d’Astra : https://old.example → https://new.example')).toBeTruthy()
    expect(api.writeDomainRelay).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirmer' }))
    await waitFor(() =>
      expect(api.writeDomainRelay).toHaveBeenCalledWith({
        astra_service_public_key: 'newkey=',
        astra_authority_url: 'https://new.example',
      }),
    )
  })

  it('refuses_an_epoch_beyond_the_safe_integers', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({}))
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    fireEvent.change(screen.getByLabelText('Époque de la clé de service'), {
      target: { value: '99999999999999999999' },
    })
    expect(screen.getByText('Un entier supérieur à zéro.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enregistrer' }).hasAttribute('disabled')).toBe(true)
  })

  it('a_recorded_gateway_identity_is_read_only_in_the_form', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({}))
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    expect(screen.queryByLabelText('Nom de service')).toBeNull()
    expect(screen.queryByLabelText('Clé WireGuard de la gateway')).toBeNull()
    expect(screen.getByLabelText('Origine d’Astra')).toBeTruthy()
  })

  it('shows_a_refused_write_under_the_form', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({}))
    api.writeDomainRelay.mockRejectedValue('une cérémonie opérateur est ouverte')
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Modifier' }))
    fireEvent.change(screen.getByLabelText('Origine d’Astra'), { target: { value: 'https://astra.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Confirmer' }))
    expect(await screen.findByText(/cérémonie opérateur est ouverte/)).toBeTruthy()
  })

  it('the_connected_gateway_is_offered_until_the_relay_names_one', async () => {
    api.operatorOverview.mockResolvedValue(withDomain({ server_name: null, gateway_wg_public_key: null }))
    const { unmount } = render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reprendre la gateway connectée' }))
    await waitFor(() => expect(api.adoptConnectedGateway).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(api.operatorOverview).toHaveBeenCalledTimes(2))
    unmount()

    api.adoptConnectedGateway.mockRejectedValue('aucune gateway connectée')
    render(<DomainPanel onCeremony={onCeremony} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reprendre la gateway connectée' }))
    expect(await screen.findByText(/aucune gateway connectée/)).toBeTruthy()
    cleanup()

    api.operatorOverview.mockResolvedValue(withDomain({}))
    render(<DomainPanel onCeremony={onCeremony} />)
    await screen.findByRole('button', { name: 'Modifier' })
    expect(screen.queryByRole('button', { name: 'Reprendre la gateway connectée' })).toBeNull()
  })

  it('finalizing_waits_for_the_gateway_and_hides_when_complete', async () => {
    api.operatorOverview.mockResolvedValue(
      withDomain({ server_name: null, gateway_wg_public_key: null, ca_tls_present: false }, false),
    )
    const { unmount } = render(<DomainPanel onCeremony={onCeremony} />)
    const waiting = await screen.findByRole('button', { name: 'Finaliser le domaine' })
    expect(waiting.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText('La gateway n’est pas encore dans le relais.')).toBeTruthy()
    unmount()

    api.operatorOverview.mockResolvedValue(withDomain({ ca_tls_present: false }, false))
    const second = render(<DomainPanel onCeremony={onCeremony} />)
    const ready = await screen.findByRole('button', { name: 'Finaliser le domaine' })
    expect(ready.hasAttribute('disabled')).toBe(false)
    fireEvent.click(ready)
    await waitFor(() => expect(api.beginVaultCeremony).toHaveBeenCalledWith({ gesture: 'finalize_domain' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    second.unmount()

    api.operatorOverview.mockResolvedValue(withDomain({}, true))
    render(<DomainPanel onCeremony={onCeremony} />)
    await screen.findByRole('button', { name: 'Modifier' })
    expect(screen.queryByRole('button', { name: 'Finaliser le domaine' })).toBeNull()
  })

  describe('the gateway bootstrap', () => {
    const slot = (slot_id: string, state: 'active' | 'lost' | 'revoked' | null) => ({
      slot_id,
      label: `Clé ${slot_id}`,
      role: 'principale' as const,
      state,
    })
    const open = async (slots: ReturnType<typeof slot>[]) => {
      api.operatorOverview.mockResolvedValue({ ...withDomain({}), slots })
      render(<DomainPanel onCeremony={onCeremony} />)
      return screen.findByRole('button', { name: 'Amorcer la gateway…' })
    }
    const pick = (file: File) =>
      fireEvent.change(screen.getByLabelText('Demande d’amorçage de la gateway'), {
        target: { files: [file] },
      })
    const NEEDS = 'Il faut deux clés actives pour amorcer la gateway.'

    it('the_bootstrap_button_needs_two_usable_keys', async () => {
      const one = await open([slot('01', 'active')])
      expect(one.hasAttribute('disabled')).toBe(true)
      expect(screen.getByText(NEEDS)).toBeTruthy()
      cleanup()
      const revoked = await open([slot('01', 'active'), slot('02', 'revoked')])
      expect(revoked.hasAttribute('disabled')).toBe(true)
      expect(screen.getByText(NEEDS)).toBeTruthy()
      cleanup()
      const two = await open([slot('01', 'active'), slot('02', null)])
      expect(two.hasAttribute('disabled')).toBe(false)
      expect(screen.queryByText(NEEDS)).toBeNull()
    })

    it('the_bootstrap_sends_the_file_text_only', async () => {
      await open([slot('01', 'active'), slot('02', 'active')])
      pick(new File(['{"request":1}'], 'gateway.json', { type: 'application/json' }))
      await waitFor(() =>
        expect(api.beginVaultCeremony).toHaveBeenCalledWith({
          gesture: 'bootstrap_gateway',
          request: '{"request":1}',
        }),
      )
      expect(api.beginVaultCeremony).toHaveBeenCalledTimes(1)
      await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status))
    })

    it('a_wrong_file_is_refused_inline', async () => {
      await open([slot('01', 'active'), slot('02', 'active')])
      pick(new File(['x'.repeat(256 * 1024 + 1)], 'big.json'))
      expect(
        await screen.findByText('Ce fichier est illisible ou trop grand (256 Kio au plus).'),
      ).toBeTruthy()
      expect(api.beginVaultCeremony).not.toHaveBeenCalled()
      expect(onCeremony).not.toHaveBeenCalled()
    })
  })
})
