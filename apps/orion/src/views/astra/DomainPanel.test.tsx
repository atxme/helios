// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ operatorOverview: vi.fn() }))
vi.mock('../../api', () => api)

import { DomainPanel } from './DomainPanel'

const base = {
  vault_path: 'v.json',
  exists: true,
  vault_fingerprint: null,
  slots: [],
  max_slots: 8,
}

beforeEach(() => vi.clearAllMocks())
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
    render(<DomainPanel />)
    expect(await screen.findByText('abcd 1234 ef56')).toBeTruthy()
    expect(screen.getByText('helios.example')).toBeTruthy()
    expect(screen.getByText('gw.example')).toBeTruthy()
  })

  it('says_when_no_relay_is_recorded', async () => {
    api.operatorOverview.mockResolvedValue({ ...base, domain: null })
    render(<DomainPanel />)
    expect(await screen.findByText(/Aucun relais n’est enregistré/)).toBeTruthy()
  })

  it('shows_the_error_when_the_overview_fails', async () => {
    api.operatorOverview.mockRejectedValue('lecture impossible')
    render(<DomainPanel />)
    expect(await screen.findByText(/lecture impossible/)).toBeTruthy()
  })
})
