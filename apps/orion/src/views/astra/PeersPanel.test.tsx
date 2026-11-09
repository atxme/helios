// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorPeersOverview: vi.fn(),
  operatorRotationsOverview: vi.fn(),
  beginRevocationCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { OperatorStatus, PeerCertificateRead, PeersOverview, RotationsOverview } from '../../types'
import { OperatorCeremonyPanel } from '../OperatorCeremony'
import { PeersPanel } from './PeersPanel'
import { NOW, overview as rotationsOverview } from './rotationFixtures'

const KEY_A = 'A'.repeat(43) + '='
const KEY_B = 'B'.repeat(43) + '='
const OWN = 'O'.repeat(43) + '='

const peer = (extra: Partial<PeerCertificateRead> & { name: string; wg_public_key: string }): PeerCertificateRead => ({
  not_before: NOW - 1_000,
  not_after: NOW + 90 * 86_400,
  revoked: false,
  renewing: false,
  ...extra,
})

const peers = (extra: Partial<PeersOverview> = {}): PeersOverview => ({
  certificates: {
    state: 'ok',
    value: [
      peer({ name: 'PORTABLE', wg_public_key: KEY_A }),
      peer({ name: 'PC_BUREAU', wg_public_key: KEY_B, revoked: true }),
    ],
  },
  admitted: { state: 'ok', value: [{ name: 'PORTABLE', wg_public_key: KEY_A }] },
  astra_revoked: { state: 'ok', value: [KEY_B] },
  pending_revocations: { state: 'ok', value: [] },
  own_key: null,
  now_unix: NOW,
  local_pending: null,
  ...extra,
})

const status = (extra: Partial<OperatorStatus> = {}): OperatorStatus => ({
  session_id: 's',
  revision: 1,
  operation: 'revoke_certificate',
  remote: 'local',
  gesture: 'idle',
  allowed: ['cancel'],
  ...extra,
})

const region = (name: string) => screen.getByRole('region', { name })
const prerequisites = () => within(region('Prérequis'))
const motif = () => within(screen.getByRole('group', { name: 'Motif' }))

/** Shows the screen with the given reads and waits for the first read to end. */
const show = async (
  peersRead: PeersOverview = peers(),
  rotations: RotationsOverview = rotationsOverview(),
) => {
  api.operatorPeersOverview.mockResolvedValue(peersRead)
  api.operatorRotationsOverview.mockResolvedValue(rotations)
  const onCeremony = vi.fn()
  render(<PeersPanel onCeremony={onCeremony} />)
  await waitFor(() => expect(screen.queryByLabelText('Lecture en cours')).toBeNull())
  return { onCeremony }
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useRealTimers()
})
afterEach(cleanup)

describe('the list', () => {
  it('shows_each_workstation_with_its_state_and_its_expiry', async () => {
    await show()
    expect(within(region('PORTABLE')).getByText('Actif')).toBeTruthy()
    expect(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' })).toBeTruthy()
    expect(within(region('PC_BUREAU')).getByText('Révoqué')).toBeTruthy()
    expect(within(region('PC_BUREAU')).queryByRole('button')).toBeNull()
  })

  it('an_unreadable_admission_is_said_above_the_list_and_its_rows_are_unknown', async () => {
    await show(peers({ admitted: { state: 'unreachable' } }))
    expect(screen.getByText(/Admission : Gateway injoignable/)).toBeTruthy()
    expect(within(region('PORTABLE')).getByText('État inconnu')).toBeTruthy()
    expect(within(region('PORTABLE')).queryByRole('button')).toBeNull()
  })

  it('the_refresh_button_reads_both_overviews_again', async () => {
    await show()
    const reads = api.operatorPeersOverview.mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: 'Actualiser' }))
    await waitFor(() => expect(api.operatorPeersOverview.mock.calls.length).toBeGreaterThan(reads))
    expect(api.operatorRotationsOverview.mock.calls.length).toBeGreaterThan(1)
  })

  it('the_own_workstation_has_no_action_and_names_the_gateway_command', async () => {
    await show(
      peers({
        own_key: OWN,
        certificates: { state: 'ok', value: [peer({ name: 'PC_FIXE', wg_public_key: OWN })] },
        admitted: { state: 'ok', value: [{ name: 'PC_FIXE', wg_public_key: OWN }] },
      }),
    )
    const row = within(region('PC_FIXE'))
    expect(row.getByText('Ce poste')).toBeTruthy()
    expect(row.queryByRole('button')).toBeNull()
    expect(row.getByText('Se coupe sur la gateway : helios peer revoke PC_FIXE.')).toBeTruthy()
  })
})

describe('the revocation path', () => {
  it('revoke_goes_through_prerequisites_motif_confirmation_and_the_ceremony', async () => {
    api.beginRevocationCeremony.mockResolvedValue(status())
    const { onCeremony } = await show()
    fireEvent.click(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' }))

    expect(prerequisites().getByText('Tunnel connecté')).toBeTruthy()
    fireEvent.click(motif().getByRole('button', { name: 'Compromis' }))
    expect(
      within(region('Confirmation')).getByText(
        "Révoquer PORTABLE ? Le poste sera coupé tout de suite. C'est définitif.",
      ),
    ).toBeTruthy()

    fireEvent.click(within(region('Confirmation')).getByRole('button', { name: 'Révoquer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(status()))
    expect(api.beginRevocationCeremony).toHaveBeenCalledWith({
      gesture: 'revoke',
      peer: KEY_A,
      name: 'PORTABLE',
      reason: 'compromised',
    })
  })

  it('resume_on_a_cut_workstation_asks_the_motif_then_redeposits', async () => {
    api.beginRevocationCeremony.mockResolvedValue(status())
    const { onCeremony } = await show(
      peers({
        certificates: { state: 'ok', value: [peer({ name: 'PC_BUREAU', wg_public_key: KEY_B })] },
        admitted: { state: 'ok', value: [] },
        astra_revoked: { state: 'ok', value: [] },
      }),
    )
    fireEvent.click(within(region('PC_BUREAU')).getByRole('button', { name: 'Reprendre' }))
    fireEvent.click(motif().getByRole('button', { name: 'Remplacé' }))
    fireEvent.click(within(region('Confirmation')).getByRole('button', { name: 'Reprendre' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(api.beginRevocationCeremony).toHaveBeenCalledWith({
      gesture: 'resume',
      peer: KEY_B,
      reason: 'replaced',
    })
  })

  it('a_red_cut_prerequisite_offers_no_motif', async () => {
    await show(undefined, rotationsOverview({ tunnel: false }))
    fireEvent.click(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' }))
    expect(prerequisites().getByText('Connecter')).toBeTruthy()
    expect(screen.queryByRole('group', { name: 'Motif' })).toBeNull()
  })

  it('a_red_signing_prerequisite_does_not_stop_the_cut', async () => {
    await show(
      undefined,
      rotationsOverview({ vault: null, vaultError: 'illisible' }),
    )
    fireEvent.click(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' }))
    expect(screen.getByRole('group', { name: 'Motif' })).toBeTruthy()
    expect(screen.getByText(/la coupure se fait quand même/)).toBeTruthy()
  })

  it('a_not_before_refusal_is_shown_with_its_date_in_the_ceremony', async () => {
    api.beginRevocationCeremony.mockResolvedValue(
      status({
        refusal: { refusal: 'revocation_not_before', until: 1_800_000_000 },
        peer_cut: true,
        gesture: 'failed',
      }),
    )
    const { onCeremony } = await show()
    fireEvent.click(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' }))
    fireEvent.click(motif().getByRole('button', { name: 'Compromis' }))
    fireEvent.click(within(region('Confirmation')).getByRole('button', { name: 'Révoquer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledTimes(1))

    const shown = onCeremony.mock.calls[0][0] as OperatorStatus
    await act(async () => {
      render(<OperatorCeremonyPanel status={shown} onStatus={vi.fn()} />)
    })
    expect(screen.getByText(/Révocation possible après le .*2027/)).toBeTruthy()
    expect(screen.getByText(/Le poste est coupé ; la révocation reste à signer\./)).toBeTruthy()
  })

  it('a_refused_start_is_said_in_the_panel', async () => {
    api.beginRevocationCeremony.mockRejectedValue('Une cérémonie est déjà ouverte.')
    const { onCeremony } = await show()
    fireEvent.click(within(region('PORTABLE')).getByRole('button', { name: 'Révoquer' }))
    fireEvent.click(motif().getByRole('button', { name: 'Compromis' }))
    fireEvent.click(within(region('Confirmation')).getByRole('button', { name: 'Révoquer' }))
    expect(await screen.findByText('Une cérémonie est déjà ouverte.')).toBeTruthy()
    expect(onCeremony).not.toHaveBeenCalled()
  })
})
