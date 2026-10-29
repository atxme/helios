// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorOverview: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { VaultOverview } from '../../types'
import { DomainCreated } from './DomainCreated'

const created: VaultOverview = {
  vault_path: 'C:\\astra\\authority-vault.json',
  exists: true,
  location_available: true,
  bootstrapped: true,
  credentials_complete: false,
  vault_fingerprint: '0123456789abcdef0123',
  slots: [],
  max_slots: 8,
  domain: {
    trust_domain_id: 'td',
    rp_id: 'gw.tail.ts.net',
    ca_pq_fingerprint: 'abcd 1234 ef56',
    ca_epoch: 1,
    ca_tls_epoch: null,
    ca_tls_present: false,
    server_name: null,
    gateway_wg_public_key: null,
    astra_service_public_key: null,
    astra_service_key_epoch: null,
    astra_authority_url: 'https://gw.tail.ts.net',
  },
}

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorOverview.mockResolvedValue(created)
})
afterEach(cleanup)

describe('DomainCreated', () => {
  it('shows_both_fingerprints_grouped_the_backup_and_the_next_steps', async () => {
    render(<DomainCreated />)
    expect(await screen.findByText('0123 4567 89ab cdef 0123')).toBeTruthy()
    expect(screen.getByText('abcd 1234 ef56')).toBeTruthy()
    expect(screen.getByText(/Sauvegardez le coffre/)).toBeTruthy()
    const steps = screen.getAllByRole('listitem').map((step) => step.textContent)
    expect(steps).toHaveLength(3)
    expect(steps[0]).toContain('./scripts/deploy.sh')
    expect(steps[1]).toContain('astra-signer issue-gateway-bootstrap')
    expect(steps[1]).toContain('--vault')
    expect(steps[2]).toContain('« Finaliser le domaine »')
    expect(steps[2]).toContain('./scripts/deploy.sh --astra')
  })

  it('says_when_the_vault_cannot_be_read', async () => {
    api.operatorOverview.mockRejectedValue('coffre illisible')
    render(<DomainCreated />)
    expect(await screen.findByText(/coffre illisible/)).toBeTruthy()
  })
})
