// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorOverview: vi.fn(),
  beginOperatorCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import { VaultPanel } from './VaultPanel'

const overview = {
  vault_path: 'C:\\astra\\vault.json',
  exists: true,
  vault_fingerprint: 'aaaa bbbb cccc',
  slots: [
    { slot_id: '01', label: 'YubiKey bureau', role: 'principale' as const },
    { slot_id: '02', label: 'YubiKey coffre', role: 'recuperation' as const },
  ],
  max_slots: 8,
  domain: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  api.operatorOverview.mockResolvedValue(overview)
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

  it('a_missing_vault_says_how_to_create_one', async () => {
    api.operatorOverview.mockResolvedValue({ ...overview, exists: false, slots: [] })
    render(<VaultPanel onCeremony={vi.fn()} />)
    expect(
      await screen.findByText(
        "Aucun coffre opérateur à cet emplacement. La création d'un domaine arrivera dans Orion ; d'ici là, `astra-signer init`.",
      ),
    ).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Vérifier une clé' })).toBeNull()
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
})
