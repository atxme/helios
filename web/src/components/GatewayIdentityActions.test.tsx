// @vitest-environment jsdom

import { ThemeProvider } from '@mui/material/styles'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { heliosTheme } from '../theme'
import type { CertificateDomain } from '../types'
import { GatewayIdentityActions } from './GatewayIdentityActions'

/**
 * The four gestures of §12.2 this gateway actually owns.
 *
 * What is tested here is not the layout but the three refusals that would
 * otherwise be discovered against a live domain: a second preparation while a
 * transition is staged, an abort offered when nothing is staged, and a daemon
 * refusal reaching the operator with its reason rather than as a status code.
 */

const DOMAIN: CertificateDomain = {
  trust_domain_id: 'ab'.repeat(16),
  server_name: 'gateway.example',
  now_unix: 50_000,
  ca_epoch: 1,
  ca_pq_fingerprint: 'cd'.repeat(32),
  ca_transition_pending: false,
  ca_activation_at: null,
  client_tls_ca_epoch: 2,
  client_tls_ca_transition_pending: false,
  gateway_identity_epoch: 3,
  gateway_tls_fingerprint: 'ef'.repeat(32),
  gateway_pq_fingerprint: '12'.repeat(32),
  gateway_transition_pending: false,
  gateway_activation_at: null,
  astra_authority_url: 'https://astra.example',
  astra_service_key_epoch: 5,
  astra_policy_fingerprint: '34'.repeat(32),
  webauthn_rp_id: 'astra.example',
  credential_registry_epoch: 1,
  credential_bindings: 2,
  issuer: null,
  peers: [],
}

function mount(domain: CertificateDomain = DOMAIN) {
  return render(
    <ThemeProvider theme={heliosTheme}>
      <GatewayIdentityActions domain={domain} />
    </ThemeProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('GatewayIdentityActions', () => {
  it('hands back the epoch, the identifier and the fingerprint to compare', async () => {
    const answer = {
      gateway_identity_epoch: 4,
      request_id: '7'.repeat(32),
      request_fingerprint: 'aa'.repeat(32),
      expires_at: 136_400,
      candidate_tls_fingerprint: null,
      reused: false,
      key_recovery: false,
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response(JSON.stringify(answer), { status: 200 }))),
    )
    mount()

    fireEvent.click(screen.getByText('Préparer la demande'))

    expect(await screen.findByText('aa'.repeat(32))).toBeTruthy()
    expect(screen.getByText('4')).toBeTruthy()
    expect(screen.getByText('inchangée')).toBeTruthy()
  })

  /**
   * One epoch carries one decision. Offering a second preparation would let an
   * operator seal a key for a number a staged transition already holds.
   */
  it('refuses a second preparation while a transition is staged', () => {
    mount({ ...DOMAIN, gateway_transition_pending: true })

    expect(screen.getByText('Préparer la demande').closest('button')?.disabled).toBe(true)
    expect(screen.getByText(/Une transition est déjà en attente/)).toBeTruthy()
  })

  /** Nothing staged, nothing to cancel. */
  it('offers the abort only against a staged transition', () => {
    const { unmount } = mount()
    expect(screen.getByText('Annuler la transition préparée').closest('button')?.disabled).toBe(
      true,
    )
    unmount()

    mount({ ...DOMAIN, gateway_transition_pending: true })
    const textarea = screen.getByPlaceholderText(/Coller ici la transition/)
    fireEvent.change(textarea, { target: { value: '{"a":1}' } })
    expect(screen.getByText('Annuler la transition préparée').closest('button')?.disabled).toBe(
      false,
    )
  })

  /**
   * The refusal reason is the whole point of this surface: an operator sent to
   * the daemon logs mid-renewal is sent there at the worst moment.
   */
  it('shows the reason the daemon refused, not its status code', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              message: 'this gateway identity is revoked at epoch 2',
            }),
            { status: 409 },
          ),
        ),
      ),
    )
    mount()

    fireEvent.click(screen.getByText('Préparer la demande'))

    await waitFor(() =>
      expect(screen.getByText('this gateway identity is revoked at epoch 2')).toBeTruthy(),
    )
  })

  /** A paste that is not a document must not reach the daemon at all. */
  it('refuses a paste that is not a signed document without calling the daemon', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    mount()

    const textarea = screen.getByPlaceholderText(/Coller ici la transition/)
    fireEvent.change(textarea, { target: { value: 'pas du json' } })
    fireEvent.click(screen.getByText('Installer la transition'))

    expect(await screen.findByText(/Ce n’est pas un document JSON/)).toBeTruthy()
    expect(fetcher).not.toHaveBeenCalled()
  })

  /** The campaign actions are named, with their command, and never faked. */
  it('names the campaign actions it cannot open itself', () => {
    mount()
    expect(screen.getByText(/astra campaign open --scope fleet-leafs/)).toBeTruthy()
  })
})
