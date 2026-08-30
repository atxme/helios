// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { CertificatePanel } from './CertificatePanel'
import type {
  CertificateActionState,
  CertificateFacts,
  CertificateInventory,
  CertificatePhase,
} from '../types'

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
  previous_identity: null,
  operator_credentials: null,
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
   * The remaining life is the value that decides whether the user acts today.
   * A date alone makes them subtract, and subtracting wrong is the whole
   * failure this panel exists to prevent.
   */
  it('states how long is left, not only the instant', () => {
    const now = Date.now() / 1000
    render(
      <CertificatePanel
        inventory={inventory({
          gateway_pq: facts('valid', { not_after: now + 12 * 86_400 }),
          client_pq: facts('expired', { not_after: now - 3 * 86_400 }),
        })}
        identityName="orion-poste"
      />,
    )
    expect(screen.getByText('dans 12 jours')).toBeTruthy()
    expect(screen.getByText('depuis 3 jours')).toBeTruthy()
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
   * §12.2 names four actions. They are shown disabled with their reason, never
   * hidden: an action that disappears when unavailable teaches the user it
   * does not exist, and the day it becomes available nobody looks for it.
   */
  it('offers the four actions of the specification, disabled with their reason', () => {
    const actions: CertificateActionState[] = [
      {
        action: 'renew_now',
        label: 'Renouveler maintenant',
        blocked_by: { kind: 'trust_material_missing' },
        message: 'Ce profil ne porte pas le matériel de confiance…',
      },
      {
        action: 'renew_every_profile',
        label: 'Renouveler tous les profils Helios de cet appareil',
        blocked_by: { kind: 'trust_material_missing' },
        message: 'Ce profil ne porte pas le matériel de confiance…',
      },
      {
        action: 'recover_expired',
        label: 'Récupérer le certificat expiré',
        blocked_by: { kind: 'nothing_expired' },
        message: 'Aucun certificat de ce profil n’est expiré…',
      },
      {
        action: 'rollback_to_previous',
        label: 'Revenir temporairement à l’ancienne identité',
        blocked_by: { kind: 'no_previous_identity' },
        message: 'Ce poste ne détient aucune identité précédente…',
      },
    ]
    render(
      <CertificatePanel
        inventory={inventory({ gateway_pq: facts('valid') })}
        identityName="orion-poste"
        actions={actions}
        onRun={() => {}}
      />,
    )
    for (const action of actions) {
      const button = screen.getByRole('button', { name: action.label })
      expect(button).toBeTruthy()
      expect((button as HTMLButtonElement).disabled).toBe(true)
    }
  })

  /** An action that may run is pressable, and presses. */
  it('runs an action that the state machine allows', () => {
    const run: string[] = []
    render(
      <CertificatePanel
        inventory={inventory({ client_pq: facts('renewal_due') })}
        identityName="orion-poste"
        actions={[
          {
            action: 'renew_now',
            label: 'Renouveler maintenant',
            blocked_by: null,
            message: null,
          },
        ]}
        onRun={(action) => run.push(action)}
      />,
    )
    const button = screen.getByRole('button', { name: 'Renouveler maintenant' })
    expect((button as HTMLButtonElement).disabled).toBe(false)
    button.click()
    expect(run).toEqual(['renew_now'])
  })

  it('shows how long a selected previous identity may stay in service', () => {
    render(
      <CertificatePanel
        inventory={inventory({
          identity_sealed: true,
          previous_identity: {
            available_from: 1_000,
            available_until: Date.now() / 1000 + 3_600,
            phase: 'available',
            selected: true,
          },
        })}
        identityName="orion-poste"
        actions={[
          {
            action: 'rollback_to_previous',
            label: 'Revenir temporairement à l’ancienne identité',
            blocked_by: null,
            message: null,
          },
        ]}
        onRun={() => {}}
      />,
    )

    expect(screen.getByText('ancienne identité servie')).toBeTruthy()
    expect(screen.getByText(/jusqu’au/)).toBeTruthy()
    expect(
      (screen.getByRole('button', {
        name: 'Revenir temporairement à l’ancienne identité',
      }) as HTMLButtonElement).disabled,
    ).toBe(false)
  })

  /** The two other things §12.2 asks the surface to show. */
  it('states the chosen renewal date and the last error', () => {
    render(
      <CertificatePanel
        inventory={inventory({ client_pq: facts('valid', { renewal_at: 80_000 }) })}
        identityName="orion-poste"
        lastError="Ce profil ne porte pas le matériel de confiance."
      />,
    )
    expect(screen.getByText('renouvellement')).toBeTruthy()
    expect(screen.getByText(/matériel de confiance/)).toBeTruthy()
  })

  /**
   * A fresh certificate is not broken when Astra answers 403: its policy is
   * saying that the 80% renewal window has not opened. The UI must make that
   * distinction without receiving Astra's protected reason over WireGuard.
   */
  it('presents a 403 before the renewal window as information', () => {
    render(
      <CertificatePanel
        inventory={inventory({ client_pq: facts('valid') })}
        identityName="orion-poste"
        lastError="la gateway a refusé le renouvellement (403)."
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/Renouvellement non nécessaire pour le moment/)
    expect(alert.className).toContain('MuiAlert-colorInfo')
  })

  /** A 403 during an active renewal window still needs operator attention. */
  it('keeps a 403 during the renewal window as an error', () => {
    render(
      <CertificatePanel
        inventory={inventory({ client_pq: facts('renewal_due') })}
        identityName="orion-poste"
        lastError="la gateway a refusé le renouvellement (403)."
      />,
    )
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toMatch(/la gateway a refusé/)
    expect(alert.className).toContain('MuiAlert-colorError')
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
