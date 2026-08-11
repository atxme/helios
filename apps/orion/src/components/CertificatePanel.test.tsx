// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { CertificatePanel } from './CertificatePanel'
import type { CertificateFacts, CertificateInventory, CertificatePhase } from '../types'

afterEach(cleanup)

const facts = (phase: CertificatePhase, overrides: Partial<CertificateFacts> = {}) =>
  ({
    subject: 'CN=gateway.example',
    issuer: 'CN=CA-PQ',
    fingerprint: 'a'.repeat(64),
    not_before: 0,
    not_after: 100_000,
    renewal_at: 80_000,
    phase,
    ...overrides,
  }) satisfies CertificateFacts

const inventory = (overrides: Partial<CertificateInventory> = {}): CertificateInventory => ({
  gateway_pq: null,
  gateway_ca_tls: null,
  client_tls: null,
  client_pq: null,
  faults: [],
  identity_sealed: false,
  ...overrides,
})

describe('CertificatePanel', () => {
  /**
   * The question the panel exists for: *is something expired?* An answer of
   * "absent" for every row is the answer a screen gave before it existed.
   */
  it('states the phase and the expiry of each certificate it is given', () => {
    render(
      <CertificatePanel
        inventory={inventory({
          gateway_pq: facts('valid'),
          client_pq: facts('expired', { subject: 'CN=workstation' }),
        })}
        identityName="orion-poste"
      />,
    )
    expect(screen.getByText('valide')).toBeTruthy()
    expect(screen.getByText('expiré')).toBeTruthy()
    // Two rows have no certificate, and that is an absence, not a failure.
    expect(screen.getAllByText('absent')).toHaveLength(2)
  })

  /**
   * The renewal ladder is the protocol's. Each rung has a distinct label,
   * because "bientôt" for both 80 % and 95 % is what makes a user ignore the
   * first one and be surprised by the second.
   */
  it('names each rung of the renewal ladder distinctly', () => {
    const rungs: Array<[CertificatePhase, string]> = [
      ['not_yet_valid', 'pas encore valide'],
      ['valid', 'valide'],
      ['renewal_due', 'renouvellement ouvert'],
      ['warning', 'renouvellement en retard'],
      ['critical', 'expiration imminente'],
      ['expired', 'expiré'],
    ]
    for (const [phase, label] of rungs) {
      cleanup()
      render(
        <CertificatePanel
          inventory={inventory({ gateway_pq: facts(phase) })}
          identityName=""
        />,
      )
      expect(screen.getByText(label)).toBeTruthy()
    }
  })

  /**
   * A profile that pins nothing readable and names an unsealed identity is
   * exactly the case the message exists for. Rendering nothing there would
   * leave the user with the failure and no cause.
   */
  it('names the missing protected identity even when nothing else is readable', () => {
    render(<CertificatePanel inventory={inventory()} identityName="orion-poste" />)
    expect(screen.getByText(/Aucune identité protégée nommée/)).toBeTruthy()
  })

  /** A slot that exists and could not be read is a fault, and it is named. */
  it('reports a fault rather than showing a dash', () => {
    render(
      <CertificatePanel
        inventory={inventory({ faults: ['certificat PQ de la gateway : base64 illisible'] })}
        identityName=""
      />,
    )
    expect(screen.getByText(/base64 illisible/)).toBeTruthy()
  })

  /**
   * Nothing to say, nothing shown. A profile with no negotiation block pins
   * no certificate, and four «absent» rows would be noise on every classic
   * profile in the list.
   */
  it('renders nothing when there is nothing to report', () => {
    const { container } = render(<CertificatePanel inventory={inventory()} identityName="" />)
    expect(container.firstChild).toBeNull()
  })

  /** And nothing at all before the shell has answered. */
  it('renders nothing while the inventory is still unknown', () => {
    const { container } = render(<CertificatePanel inventory={null} identityName="orion" />)
    expect(container.firstChild).toBeNull()
  })
})
