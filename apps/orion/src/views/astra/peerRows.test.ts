import { describe, expect, it } from 'vitest'

import type { PeerCertificateRead, PeersOverview } from '../../types'
import { peerRows } from './peerRows'

const NOW = 1_800_000_000
const KEY_A = 'A'.repeat(43) + '='
const KEY_B = 'B'.repeat(43) + '='
const KEY_C = 'C'.repeat(43) + '='
const OWN = 'O'.repeat(43) + '='

const peer = (extra: Partial<PeerCertificateRead> & { name: string; wg_public_key: string }): PeerCertificateRead => ({
  not_before: NOW - 1_000,
  not_after: NOW + 90 * 86_400,
  revoked: false,
  renewing: false,
  ...extra,
})

const overview = (extra: Partial<PeersOverview> = {}): PeersOverview => ({
  certificates: { state: 'ok', value: [] },
  admitted: { state: 'ok', value: [] },
  astra_revoked: { state: 'ok', value: [] },
  pending_revocations: { state: 'ok', value: [] },
  own_key: null,
  now_unix: NOW,
  local_pending: null,
  ...extra,
})

const one = (rows: ReturnType<typeof peerRows>, key: string) => {
  const row = rows.find((candidate) => candidate.key === key)
  if (!row) throw new Error(`no row for ${key}`)
  return row
}

describe('the state of each workstation', () => {
  it('an_admitted_peer_not_revoked_at_astra_is_active_and_can_be_revoked', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PORTABLE', wg_public_key: KEY_A })] },
        admitted: { state: 'ok', value: [{ name: 'PORTABLE', wg_public_key: KEY_A }] },
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ name: 'PORTABLE', state: 'Actif', action: 'revoke' })
  })

  it('a_renewing_admitted_peer_says_so', () => {
    const rows = peerRows(
      overview({
        certificates: {
          state: 'ok',
          value: [peer({ name: 'PORTABLE', wg_public_key: KEY_A, renewing: true })],
        },
        admitted: { state: 'ok', value: [{ name: 'PORTABLE', wg_public_key: KEY_A }] },
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ state: 'Renouvellement en cours', action: 'revoke' })
  })

  it('a_peer_no_longer_admitted_and_not_revoked_at_astra_is_cut_and_resumable', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PC_BUREAU', wg_public_key: KEY_B })] },
        admitted: { state: 'ok', value: [] },
      }),
    )
    expect(one(rows, KEY_B)).toMatchObject({
      state: 'Coupé, révocation à signer',
      action: 'resume',
    })
  })

  it('a_revoked_peer_no_longer_admitted_is_revoked_and_greyed_without_action', () => {
    const rows = peerRows(
      overview({
        certificates: {
          state: 'ok',
          value: [peer({ name: 'PC_BUREAU', wg_public_key: KEY_B, revoked: true })],
        },
        admitted: { state: 'ok', value: [] },
        astra_revoked: { state: 'ok', value: [KEY_B] },
      }),
    )
    expect(one(rows, KEY_B)).toMatchObject({ state: 'Révoqué', action: null })
  })

  it('a_revoked_peer_still_admitted_says_the_gateway_is_not_informed_yet', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PC_BUREAU', wg_public_key: KEY_B })] },
        admitted: { state: 'ok', value: [{ name: 'PC_BUREAU', wg_public_key: KEY_B }] },
        astra_revoked: { state: 'ok', value: [KEY_B] },
      }),
    )
    expect(one(rows, KEY_B)).toMatchObject({
      state: 'Révoqué, gateway pas encore informée',
      action: null,
    })
  })

  it('rows_match_the_admission_by_wireguard_key_never_by_name', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PC_FIXE', wg_public_key: KEY_A })] },
        admitted: { state: 'ok', value: [{ name: 'PC_FIXE', wg_public_key: KEY_C }] },
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ state: 'Coupé, révocation à signer' })
  })
})

describe('the rows of the screen', () => {
  it('duplicate_names_show_the_added_date', () => {
    const notBefore = NOW - 40 * 86_400
    const rows = peerRows(
      overview({
        certificates: {
          state: 'ok',
          value: [
            peer({ name: 'PORTABLE', wg_public_key: KEY_A, not_before: notBefore, revoked: true }),
            peer({ name: 'PORTABLE', wg_public_key: KEY_B, not_before: NOW - 2_000 }),
            peer({ name: 'PC_FIXE', wg_public_key: KEY_C }),
          ],
        },
        admitted: {
          state: 'ok',
          value: [{ name: 'PORTABLE', wg_public_key: KEY_B }, { name: 'PC_FIXE', wg_public_key: KEY_C }],
        },
        astra_revoked: { state: 'ok', value: [KEY_A] },
      }),
    )
    expect(one(rows, KEY_A).addedAt).toBe(notBefore)
    expect(one(rows, KEY_B).addedAt).toBe(NOW - 2_000)
    expect(one(rows, KEY_C).addedAt).toBeUndefined()
  })

  it('own_workstation_has_no_revoke_button', () => {
    const rows = peerRows(
      overview({
        own_key: OWN,
        certificates: { state: 'ok', value: [peer({ name: 'PC_FIXE', wg_public_key: OWN })] },
        admitted: { state: 'ok', value: [{ name: 'PC_FIXE', wg_public_key: OWN }] },
      }),
    )
    expect(one(rows, OWN)).toMatchObject({
      own: true,
      state: 'Actif',
      action: null,
      reason: 'Se coupe sur la gateway : helios peer revoke PC_FIXE.',
    })
  })

  it('a_key_pending_at_astra_without_a_local_record_has_no_action', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PC_BUREAU', wg_public_key: KEY_B })] },
        admitted: { state: 'ok', value: [] },
        pending_revocations: { state: 'ok', value: [KEY_B] },
      }),
    )
    expect(one(rows, KEY_B)).toMatchObject({
      action: null,
      reason: 'Révocation déjà ouverte chez Astra.',
    })
  })

  it('a_local_decision_on_a_key_gives_resume_whatever_its_state', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PORTABLE', wg_public_key: KEY_A })] },
        admitted: { state: 'ok', value: [{ name: 'PORTABLE', wg_public_key: KEY_A }] },
        local_pending: KEY_A,
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ state: 'Actif', action: 'resume' })
  })

  it('no_certificate_read_means_no_row', () => {
    expect(peerRows(overview({ certificates: { state: 'unreachable' } }))).toEqual([])
  })

  it('an_unreadable_admission_leaves_every_row_unknown_without_action', () => {
    const rows = peerRows(
      overview({
        certificates: { state: 'ok', value: [peer({ name: 'PORTABLE', wg_public_key: KEY_A })] },
        admitted: { state: 'unreachable' },
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ state: 'État inconnu', action: null })
  })

  it('an_unreadable_astra_leaves_a_cut_peer_unknown_and_an_admitted_one_active', () => {
    const rows = peerRows(
      overview({
        certificates: {
          state: 'ok',
          value: [peer({ name: 'PORTABLE', wg_public_key: KEY_A }), peer({ name: 'PC_BUREAU', wg_public_key: KEY_B })],
        },
        admitted: { state: 'ok', value: [{ name: 'PORTABLE', wg_public_key: KEY_A }] },
        astra_revoked: { state: 'astra_unavailable' },
      }),
    )
    expect(one(rows, KEY_A)).toMatchObject({ state: 'Actif', action: 'revoke' })
    expect(one(rows, KEY_B)).toMatchObject({ state: 'État inconnu', action: null })
  })
})
