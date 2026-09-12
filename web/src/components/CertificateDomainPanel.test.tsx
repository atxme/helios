// @vitest-environment jsdom

import { ThemeProvider } from '@mui/material/styles'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { heliosTheme } from '../theme'
import type { CertificateDomain, PeerCertificateView } from '../types'
import { CertificateDomainPanel } from './CertificateDomainPanel'

/**
 * The lifecycle panel, against the three answers the route actually gives:
 * a domain, no domain at all, and a refusal.
 *
 * The middle one is the case worth a test of its own. `404` here means the
 * gateway was never initialised — the lifecycle routes are closed and nothing
 * can renew — and treating it as an error would put "le démon ne répond pas"
 * on screen for a gateway that answered correctly.
 */

const PEER: PeerCertificateView = {
  name: 'poste-windows',
  wg_public_key: 'kZ8vQ2nR4tLmXpW7yB3cF6hJ1dS5gA0eU9iO2rT4vNc=',
  generation: 3,
  not_before: 1_000,
  not_after: 101_000,
  phase: 'valid',
  revoked: false,
  pending: null,
  next_generation: null,
  activation_at: null,
  distribution_chunks_pending: 0,
}

const DOMAIN: CertificateDomain = {
  trust_domain_id: 'ab'.repeat(16),
  server_name: 'gateway.example',
  now_unix: 50_000,
  ca_epoch: 1,
  ca_pq_fingerprint: 'cd'.repeat(32),
  ca_transition_pending: false,
  ca_activation_at: null,
  ca_retire_active_at: null,
  next_ca_fingerprint: null,
  client_tls_ca_epoch: 2,
  client_tls_ca_transition_pending: false,
  gateway_identity_epoch: 3,
  gateway_tls_fingerprint: 'ef'.repeat(32),
  gateway_pq_fingerprint: '12'.repeat(32),
  gateway_transition_pending: false,
  gateway_activation_at: null,
  gateway_retire_active_at: null,
  gateway_transition_published: false,
  gateway_rollback_expires_at: null,
  gateway_restart_due: null,
  astra_authority_url: 'https://astra.example',
  astra_service_key_epoch: 5,
  astra_policy_fingerprint: '34'.repeat(32),
  webauthn_rp_id: 'astra.example',
  credential_registry_epoch: 1,
  credential_bindings: 2,
  issuer: {
    issuer_epoch: 4,
    lifecycle: 'active',
    not_before: 0,
    not_after: 200_000,
    usable: true,
  },
  peers: [PEER],
}

function answer(body: unknown, status = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status }))),
  )
}

function mount() {
  return render(
    <ThemeProvider theme={heliosTheme}>
      <CertificateDomainPanel />
    </ThemeProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('CertificateDomainPanel', () => {
  it('dit qu’un redémarrage est dû quand la feuille servie n’est plus la bonne', async () => {
    answer({
      ...DOMAIN,
      gateway_restart_due:
        'gateway identity epoch 4 is due and this process is serving the outgoing leaf; restart to present it',
    })
    mount()

    expect(await screen.findByText('La feuille en service n’est plus la bonne')).toBeTruthy()
    expect(screen.getByText(/gateway identity epoch 4 is due/)).toBeTruthy()
    // Le geste est nommé : l’identité servie ne se recharge pas à chaud.
    expect(screen.getByText('systemctl restart heliosd')).toBeTruthy()
  })

  it('ne dit rien tant que la feuille servie est la bonne', async () => {
    answer(DOMAIN)
    mount()

    expect(await screen.findByText('gateway.example')).toBeTruthy()
    expect(screen.queryByText('La feuille en service n’est plus la bonne')).toBeNull()
  })

  it('names the client, its generation and where its leaf stands', async () => {
    answer(DOMAIN)
    mount()

    expect(await screen.findByText('poste-windows')).toBeTruthy()
    expect(screen.getByText('valide')).toBeTruthy()
    expect(screen.getByText('3')).toBeTruthy()
    expect(screen.getByText('gateway.example')).toBeTruthy()
  })

  /**
   * The renewal ladder is the gateway's verdict, not a recomputation.
   *
   * A console that placed the rung itself would use the operator's own clock,
   * and a workstation minutes off would draw every leaf at the wrong rung.
   */
  it('shows the rung the gateway sent, not one it computes', async () => {
    answer({ ...DOMAIN, peers: [{ ...PEER, phase: 'critical' }] })
    mount()

    expect(await screen.findByText('expiration imminente')).toBeTruthy()
    expect(screen.queryByText('valide')).toBeNull()
  })

  /**
   * Nominal is silent: a peer with nothing in flight shows no empty rows for
   * the candidate, the successor and the queue it does not have.
   */
  it('shows a staging in progress only while there is one', async () => {
    answer(DOMAIN)
    const { unmount } = mount()
    expect(await screen.findByText('poste-windows')).toBeTruthy()
    expect(screen.queryByText('En cours')).toBeNull()
    expect(screen.queryByText('À distribuer')).toBeNull()
    unmount()

    answer({
      ...DOMAIN,
      peers: [
        {
          ...PEER,
          pending: { generation: 4, state: 'pending_commit', stage_expires_at: 90_000 },
          distribution_chunks_pending: 2,
        },
      ],
    })
    mount()

    expect(await screen.findByText('En cours')).toBeTruthy()
    expect(screen.getByText('génération 4 · attend le commit')).toBeTruthy()
    expect(screen.getByText('2 fragments')).toBeTruthy()
  })

  /**
   * An `active` delegation past its `not_after` signs nothing, and no client
   * renewal will complete. The lifecycle field alone would read as healthy.
   */
  it('says out loud when the delegated issuer can no longer sign', async () => {
    answer({
      ...DOMAIN,
      issuer: { issuer_epoch: 4, lifecycle: 'active', not_before: 0, not_after: 10, usable: false },
    })
    mount()

    expect(await screen.findByText('L’émetteur délégué ne peut plus signer')).toBeTruthy()
  })

  it('reports a gateway with no trust domain as a state, not as a failure', async () => {
    answer({}, 404)
    mount()

    expect(
      await screen.findByText('Aucun domaine de confiance sur cette gateway'),
    ).toBeTruthy()
    expect(screen.queryByText('Registre de certificats illisible')).toBeNull()
  })

  it('reports a refusal as a refusal', async () => {
    answer({}, 500)
    mount()

    await waitFor(() =>
      expect(screen.getByText('Registre de certificats illisible')).toBeTruthy(),
    )
  })

  /**
   * A domain at rest leaves nothing behind. The card of dashes it would
   * otherwise draw is the thing that teaches an operator to stop reading the
   * screen.
   */
  it('draws no transition card while nothing is in flight', async () => {
    answer(DOMAIN)
    mount()

    await screen.findByText('poste-windows')
    expect(screen.queryByText('Transitions en cours')).toBeNull()
  })

  /**
   * The two instants an operator plans around, and the door of §6.3: before
   * distribution a transition can still be aborted, after it only the bounded
   * rollback remains. Both used to vanish on a reload.
   */
  it('states when a staged gateway transition switches, retires, and can still be aborted', async () => {
    answer({
      ...DOMAIN,
      gateway_transition_pending: true,
      gateway_activation_at: 60_000,
      gateway_retire_active_at: 150_000,
      gateway_transition_published: false,
    })
    mount()

    await screen.findByText('Transitions en cours')
    expect(screen.getByText('époque 3 → 4')).toBeTruthy()
    expect(screen.getByText(/non distribuée/)).toBeTruthy()
    // Both instants are drawn against the gateway's clock, not the browser's.
    expect(screen.getAllByText(/dans 1 j/).length).toBeGreaterThan(0)
  })

  /** Past distribution the options change, and the screen says which ones. */
  it('says the abort is gone once the transition has been distributed', async () => {
    answer({
      ...DOMAIN,
      gateway_transition_pending: true,
      gateway_activation_at: 40_000,
      gateway_retire_active_at: 150_000,
      gateway_transition_published: true,
    })
    mount()

    await screen.findByText('Transitions en cours')
    expect(screen.getByText(/l’avortement n’est plus accepté/)).toBeTruthy()
  })

  /**
   * §9.1 makes the comparison with the companion the check, not the signature
   * alone — so the incoming anchor has to be on the screen to be compared.
   */
  it('shows the incoming anchor and its window during a CA-PQ rotation', async () => {
    answer({
      ...DOMAIN,
      ca_transition_pending: true,
      ca_activation_at: 60_000,
      ca_retire_active_at: 150_000,
      next_ca_fingerprint: 'ab'.repeat(32),
    })
    mount()

    await screen.findByText('Transitions en cours')
    expect(screen.getByText('époque 1 → 2')).toBeTruthy()
    expect(screen.getByText('ab'.repeat(32))).toBeTruthy()
  })

  /** A selection in force is a restart pending, so it is never silent. */
  it('shows a service rollback in force', async () => {
    answer({ ...DOMAIN, gateway_rollback_expires_at: 90_000 })
    mount()

    await screen.findByText('Transitions en cours')
    expect(screen.getByText(/ancienne feuille servie/)).toBeTruthy()
  })

  /**
   * The worst rung first. An operator opens this screen to find what needs
   * doing, and alphabetical order buries it under whatever is fine.
   */
  it('puts the client that needs attention at the top', async () => {
    answer({
      ...DOMAIN,
      peers: [
        { ...PEER, name: 'a-tranquille', phase: 'valid' },
        { ...PEER, name: 'b-urgent', wg_public_key: 'other=', phase: 'expired' },
      ],
    })
    mount()

    await screen.findByText('b-urgent')
    const names = screen.getAllByText(/tranquille|urgent/).map(node => node.textContent)
    expect(names).toEqual(['b-urgent', 'a-tranquille'])
  })
})
