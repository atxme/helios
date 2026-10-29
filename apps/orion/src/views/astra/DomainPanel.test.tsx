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
    expect(await screen.findByText(/Époque de la clé de service/, { selector: 'li' })).toBeTruthy()
    expect(api.writeDomainRelay).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirmer' }))
    await waitFor(() =>
      expect(api.writeDomainRelay).toHaveBeenCalledWith({
        server_name: 'gw.new',
        astra_service_key_epoch: 4,
      }),
    )
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
})
