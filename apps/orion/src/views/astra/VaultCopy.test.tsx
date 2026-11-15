// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorRotationsOverview: vi.fn(),
  operatorSendVaultCopy: vi.fn(),
  onEvent: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { RotationsOverview } from '../../types'
import { authorityRead, overview } from './rotationFixtures'
import { VaultCopyLine, resetForTests } from './VaultCopy'

const REFUSAL =
  'Astra tient un coffre plus récent que celui de ce poste, ou qui a divergé. Récupérez le coffre à jour sur le poste qui le tient.'
const WARNING =
  'La copie d’Astra sera remplacée par ce coffre. À ne faire que si vous savez que la copie d’Astra est fausse.'
const REPLACE = 'Remplacer quand même'

// The local vault is revision 4 of one fingerprint; Astra holds revision 5 of another.
const newerOnAstra = (extra: Partial<RotationsOverview> = {}): RotationsOverview =>
  overview({
    localVaultFingerprint: '11'.repeat(32),
    localVaultRevision: 4,
    authority: {
      state: 'ok',
      value: authorityRead({ vault_copy_fingerprint: '22'.repeat(32), vault_copy_revision: 5 }),
    },
    ...extra,
  })

const copied = {
  state: 'copied' as const,
  fingerprint: '11'.repeat(32),
  credential_registry_epoch: 5,
  document_waits: false,
}

beforeEach(() => {
  vi.clearAllMocks()
  resetForTests()
  api.onEvent.mockResolvedValue(() => {})
  api.operatorRotationsOverview.mockResolvedValue(newerOnAstra())
})
afterEach(cleanup)

/** Sends from the « Envoyer » of the line: the first send, which Astra refuses as stale. */
async function sendAndWait() {
  render(<VaultCopyLine />)
  fireEvent.click(await screen.findByRole('button', { name: 'Envoyer' }))
  await waitFor(() => expect(api.operatorSendVaultCopy).toHaveBeenCalledTimes(1))
}

describe('a stale vault copy', () => {
  it('is_refused_with_the_sentence_and_offered_a_forced_replacement', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'stale' })
    await sendAndWait()
    expect(await screen.findByText(REFUSAL)).toBeTruthy()
    expect(screen.getByText(WARNING)).toBeTruthy()
    expect(screen.getByRole('button', { name: REPLACE })).toBeTruthy()
  })

  it('a_forced_replacement_is_sent_once_with_replace_newer', async () => {
    api.operatorSendVaultCopy.mockResolvedValueOnce({ state: 'stale' }).mockResolvedValueOnce(copied)
    await sendAndWait()
    fireEvent.click(await screen.findByRole('button', { name: REPLACE }))
    await waitFor(() => expect(screen.queryByText(REFUSAL)).toBeNull())
    const forced = api.operatorSendVaultCopy.mock.calls.filter((call) => call[0] === true)
    expect(forced).toHaveLength(1)
    expect(api.operatorSendVaultCopy).toHaveBeenLastCalledWith(true)
  })

  it('is_kept_when_the_view_is_left_and_mounted_again', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'stale' })
    await sendAndWait()
    expect(await screen.findByText(REFUSAL)).toBeTruthy()
    cleanup()
    render(<VaultCopyLine />)
    expect(await screen.findByText(REFUSAL)).toBeTruthy()
    expect(screen.getByRole('button', { name: REPLACE })).toBeTruthy()
  })

  it('is_not_offered_while_a_rotation_is_resumable', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'stale' })
    api.operatorRotationsOverview.mockResolvedValue(newerOnAstra({ resumable: true }))
    await sendAndWait()
    expect(await screen.findByText(REFUSAL)).toBeTruthy()
    expect(screen.queryByRole('button', { name: REPLACE })).toBeNull()
  })

  it('is_never_offered_after_a_held_back_or_copied_send', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'held_back' })
    await sendAndWait()
    expect(await screen.findByText(/copie retenue/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: REPLACE })).toBeNull()
    cleanup()

    api.operatorSendVaultCopy.mockReset()
    api.operatorSendVaultCopy.mockResolvedValue(copied)
    await sendAndWait()
    await waitFor(() => expect(screen.queryByRole('button', { name: REPLACE })).toBeNull())
    expect(screen.queryByText(REFUSAL)).toBeNull()
  })
})
