import { describe, expect, it } from 'vitest'

import type { RotationsOverview } from '../../types'
import {
  DAY,
  NOW,
  authorityRead,
  domainRead,
  overview,
  vaultOverview,
} from './rotationFixtures'
import {
  allGreen,
  effectiveNow,
  liveOperation,
  plainFingerprint,
  prerequisites,
  rotationRows,
  stopSentence,
} from './rotationRows'

const row = (o: RotationsOverview, action: string) =>
  rotationRows(o, NOW).find((candidate) => candidate.action === action)

describe('the order of the rows', () => {
  it('lists the rows in the order of the spec', () => {
    expect(rotationRows(overview(), NOW).map((r) => r.title)).toEqual([
      'Renouveler les postes',
      'Remplacer la CA-PQ',
      'Remplacer la CA TLS',
      'Renouveler la délégation',
    ])
  })

  it('a_due_row_comes_first', () => {
    const o = overview({
      domain: { state: 'ok', value: domainRead({ peers: [{ not_after: NOW + 3 * DAY }] }) },
    })
    const rows = rotationRows(o, NOW)
    expect(rows[0].action).toBe('renew_fleet')
    expect(rows[0].due).toBe(true)
    expect(rows[0].state).toMatch(/Expire bientôt/)
    expect(rows.slice(1).every((r) => !r.due)).toBe(true)
  })

  it('a_finish_row_precedes_a_resume_row', () => {
    const o = overview({ caTlsCloseAt: NOW - 10, resumable: true })
    expect(rotationRows(o, NOW).map((r) => r.action).slice(0, 3)).toEqual([
      'finish_ca_tls',
      'resume',
      'renew_fleet',
    ])
  })
})

describe('one CA rotation at a time', () => {
  it('a_CA_PQ_overlap_disables_both_replacements_and_the_fleet', () => {
    const o = overview({ caPqOverlap: true })
    expect(row(o, 'replace_ca_pq')?.disabledReason).toBe('Recouvrement CA-PQ en cours')
    expect(row(o, 'replace_ca_tls')?.disabledReason).toBe('Recouvrement CA-PQ en cours')
    expect(row(o, 'renew_fleet')?.disabledReason).toBe('Recouvrement CA-PQ en cours')
  })

  it('a_CA_TLS_overlap_disables_both_replacements_but_not_the_fleet', () => {
    const o = overview({
      domain: { state: 'ok', value: domainRead({ client_tls_ca_transition_pending: true }) },
      caTlsCloseAt: NOW + 10 * DAY,
    })
    expect(row(o, 'replace_ca_pq')?.disabledReason).toBe('Recouvrement CA TLS en cours')
    expect(row(o, 'replace_ca_tls')?.disabledReason).toBe('Recouvrement CA TLS en cours')
    expect(row(o, 'replace_ca_tls')?.state).toMatch(/Recouvrement jusqu’au/)
    expect(row(o, 'renew_fleet')?.disabledReason).toBeNull()
    expect(row(o, 'renew_delegation')?.disabledReason).toBeNull()
  })

  it('an_unread_authority_disables_what_an_overlap_would_refuse', () => {
    const o = overview({ caPqOverlap: null, authority: { state: 'unreachable' } })
    expect(row(o, 'renew_fleet')?.disabledReason).toBe('Autorité non lue')
    expect(row(o, 'renew_delegation')?.disabledReason).toBe('Autorité non lue')
    expect(row(o, 'replace_ca_tls')?.disabledReason).toBe('Autorité non lue')
  })

  it('a_rotation_to_resume_blocks_a_new_one', () => {
    const o = overview({ resumable: true })
    expect(row(o, 'replace_ca_pq')?.disabledReason).toBe('Rotation à reprendre')
  })
})

describe('finish and resume', () => {
  it('finish_appears_at_not_after_only', () => {
    const before = overview({ caTlsCloseAt: NOW + 5 })
    expect(row(before, 'finish_ca_tls')).toBeUndefined()
    const at = overview({ caTlsCloseAt: NOW })
    expect(row(at, 'finish_ca_tls')?.due).toBe(true)
    expect(row(at, 'finish_ca_tls')?.state).toMatch(/^À faire/)
    expect(row(overview(), 'finish_ca_tls')).toBeUndefined()
  })

  it('finish_follows_the_gateway_clock_over_the_local_one', () => {
    const o = overview({
      caTlsCloseAt: NOW + 100,
      domain: { state: 'ok', value: domainRead({ now_unix: NOW + 200 }) },
    })
    expect(row(o, 'finish_ca_tls')).toBeDefined()
    const unread = overview({ caTlsCloseAt: NOW + 100, domain: { state: 'unreachable' } })
    expect(effectiveNow(unread, NOW)).toBe(NOW)
    expect(row(unread, 'finish_ca_tls')).toBeUndefined()
  })

  it('resume_appears_with_a_journal', () => {
    const journal = {
      kind: 'ca_pq' as const,
      stage: 'applied' as const,
      activationAt: NOW + 3 * DAY,
      notAfter: NOW + 30 * DAY,
      nextFingerprint: 'aa',
    }
    const found = row(overview({ resumable: true, journal }), 'resume')
    expect(found?.state).toMatch(/CA-PQ/)
    expect(found?.state).toMatch(/Appliquée/)
    expect(found?.state).toMatch(/installation avant/)
    expect(found?.disabledReason).toBeNull()
  })

  it('resume_appears_without_a_journal_when_something_is_resumable', () => {
    const found = row(overview({ resumable: true, journal: null }), 'resume')
    expect(found?.state).toBe('À reprendre')
    expect(row(overview({ resumable: false }), 'resume')).toBeUndefined()
  })

  it('the_deadline_shows_as_passed_without_a_live_session', () => {
    const journal = {
      kind: 'ca_tls' as const,
      stage: 'signed' as const,
      activationAt: NOW - DAY,
      notAfter: NOW + 30 * DAY,
      nextFingerprint: 'aa',
    }
    expect(row(overview({ resumable: true, journal }), 'resume')?.state).toMatch(/délai dépassé/)
  })
})

describe('the fleet row', () => {
  it('counts_the_postes_and_dates_the_nearest_expiry_on_the_gateway_clock', () => {
    const o = overview({
      domain: {
        state: 'ok',
        value: domainRead({ now_unix: NOW + 100 * DAY, peers: [{ not_after: NOW + 120 * DAY }] }),
      },
    })
    const found = row(o, 'renew_fleet')
    // 20 days left on the gateway's clock, 120 on a clock that is wrong.
    expect(found?.due).toBe(true)
    expect(found?.state).toMatch(/1 poste /)
  })

  it('an_unreachable_and_a_refusing_gateway_read_differently', () => {
    const down = row(overview({ domain: { state: 'unreachable' } }), 'renew_fleet')
    const refused = row(overview({ domain: { state: 'refused', value: 404 } }), 'renew_fleet')
    expect(down?.state).toBe('Gateway injoignable')
    expect(refused?.state).toMatch(/ancienne ou refus \(404\)/)
  })
})

describe('delegation follows the epochs', () => {
  const issuer = (extra: object) => ({
    recorded_epoch: 4,
    serving_epoch: 4,
    ca_epoch: 3,
    ca_tls_epoch: 2,
    not_after: NOW + 300 * DAY,
    ...extra,
  })
  const withIssuer = (extra: object, rest: Partial<RotationsOverview> = {}) =>
    overview({
      authority: { state: 'ok', value: authorityRead({ issuer: issuer(extra) }) },
      ...rest,
    })

  it('is_due_when_the_epochs_differ_and_the_vault_is_level_with_the_gateway', () => {
    const found = row(withIssuer({ ca_epoch: 2 }), 'renew_delegation')
    expect(found?.due).toBe(true)
    expect(found?.disabledReason).toBeNull()
    expect(found?.state).toMatch(/^À faire/)
  })

  it('is_not_due_when_they_match', () => {
    expect(row(withIssuer({}), 'renew_delegation')?.due).toBe(false)
  })

  it('is_disabled_when_the_vault_is_ahead', () => {
    const found = row(withIssuer({ ca_epoch: 2 }, { localCaEpoch: 4 }), 'renew_delegation')
    expect(found?.due).toBe(false)
    expect(found?.disabledReason).toBe('Le coffre a une époque d’avance')
  })

  it('is_disabled_when_the_TLS_epoch_of_the_vault_is_ahead', () => {
    const found = row(withIssuer({}, { localCaTlsEpoch: 3 }), 'renew_delegation')
    expect(found?.disabledReason).toBe('Le coffre a une époque d’avance')
  })

  it('is_due_when_it_expires_soon', () => {
    const found = row(withIssuer({ not_after: NOW + 5 * DAY }), 'renew_delegation')
    expect(found?.due).toBe(true)
  })

  it('shows_a_served_epoch_that_is_not_the_recorded_one', () => {
    const found = row(withIssuer({ serving_epoch: 3 }), 'renew_delegation')
    expect(found?.state).toMatch(/servie 3, inscrite 4/)
    const none = row(withIssuer({ serving_epoch: null }), 'renew_delegation')
    expect(none?.state).toMatch(/servie absente/)
  })
})

describe('the CA TLS row', () => {
  it('shows_the_expiry_outside_an_overlap_and_not_inside_one', () => {
    expect(row(overview(), 'replace_ca_tls')?.state).toMatch(/^Expire le .* · 2 clés$/)
    const inside = row(
      overview({ caTlsCloseAt: NOW + 20 * DAY }),
      'replace_ca_tls',
    )
    expect(inside?.state).not.toMatch(/^Expire/)
  })
})

describe('concordance', () => {
  it('concordance_accepts_the_current_or_next_anchor', () => {
    expect(allGreen(prerequisites(overview(), 'renew_fleet'))).toBe(true)
    const next = 'cd'.repeat(32)
    const during = overview({
      domain: { state: 'ok', value: domainRead({ next_ca_fingerprint: next }) },
      vault: vaultOverview({
        domain: { ...vaultOverview().domain!, ca_pq_fingerprint: next.match(/.{4}/g)!.join(' ') },
      }),
    })
    const line = prerequisites(during, 'renew_fleet').find((p) => p.label === 'Domaine concordant')
    expect(line?.ok).toBe(true)
  })

  it('rejects_another_domain', () => {
    const other = overview({
      vault: vaultOverview({
        domain: { ...vaultOverview().domain!, ca_pq_fingerprint: '1234 5678' },
      }),
    })
    const line = prerequisites(other, 'renew_fleet').find((p) => p.label === 'Domaine concordant')
    expect(line?.ok).toBe(false)
  })

  it('compares_a_grouped_fingerprint_with_a_plain_one', () => {
    expect(plainFingerprint('AB12 cd34')).toBe('ab12cd34')
  })
})

describe('prerequisites', () => {
  const find = (o: RotationsOverview, label: string, action: 'replace_ca_tls' | 'renew_fleet' = 'replace_ca_tls') =>
    prerequisites(o, action).find((p) => p.label === label)

  it('lists_the_lines_of_a_CA_rotation_in_order', () => {
    expect(prerequisites(overview(), 'replace_ca_pq').map((p) => p.label)).toEqual([
      'Tunnel connecté',
      'Administrateur du tunnel',
      'Service Astra',
      'Coffre présent',
      'Deux clés enregistrées',
      'Copie du coffre',
      'Domaine concordant',
    ])
  })

  it('the_other_actions_need_neither_two_keys_nor_the_copy', () => {
    const labels = prerequisites(overview(), 'renew_fleet').map((p) => p.label)
    expect(labels).not.toContain('Deux clés enregistrées')
    expect(labels).not.toContain('Copie du coffre')
  })

  it('a_403_and_a_503_are_two_lines', () => {
    const notAdmin = overview({ pending: { state: 'not_admin' } })
    expect(find(notAdmin, 'Administrateur du tunnel')?.ok).toBe(false)
    const noAstra = overview({ pending: { state: 'astra_unavailable' } })
    expect(find(noAstra, 'Service Astra')?.ok).toBe(false)
    expect(find(noAstra, 'Administrateur du tunnel')?.ok).toBe(true)
  })

  it('an_unreachable_gateway_is_not_green', () => {
    const down = overview({ pending: { state: 'unreachable' } })
    expect(find(down, 'Service Astra')?.ok).toBe(false)
    expect(find(down, 'Administrateur du tunnel')?.detail).toBe('Gateway injoignable')
  })

  it('the_copy_is_absent_or_old_with_a_send_and_no_key', () => {
    const absent = overview({
      authority: { state: 'ok', value: authorityRead({ vault_copy_fingerprint: null }) },
    })
    expect(find(absent, 'Copie du coffre')).toMatchObject({
      ok: false,
      detail: 'Absente',
      fix: 'Envoyer',
      fixAction: 'send_vault_copy',
    })
    const old = overview({
      authority: { state: 'ok', value: authorityRead({ vault_copy_fingerprint: '99'.repeat(32) }) },
    })
    expect(find(old, 'Copie du coffre')).toMatchObject({ detail: 'Ancienne', fixAction: 'send_vault_copy' })
    expect(find(overview(), 'Copie du coffre')?.ok).toBe(true)
  })

  it('two_keys_need_a_complete_document', () => {
    const one = overview({ vault: vaultOverview({ slots: vaultOverview().slots.slice(0, 1) }) })
    expect(find(one, 'Deux clés enregistrées')?.ok).toBe(false)
    const incomplete = overview({ vault: vaultOverview({ credentials_complete: false }) })
    expect(find(incomplete, 'Deux clés enregistrées')?.ok).toBe(false)
  })

  it('names_why_the_vault_is_missing', () => {
    const bad = overview({ vault: null, vaultError: 'illisible' })
    expect(find(bad, 'Coffre présent')).toMatchObject({ ok: false, detail: 'Illisible' })
    const where = overview({ vault: null, vaultError: 'emplacement' })
    expect(find(where, 'Coffre présent')?.detail).toBe('Emplacement illisible')
  })
})

describe('live operations', () => {
  it('finds_the_operation_of_the_scope_an_action_opens', () => {
    const operation = {
      operation_id: 'c'.repeat(32),
      scope: 'fleet_leafs' as const,
      reason: 'x',
      requested_by: 'y',
      target_count: 1,
      required_credentials: 1,
      campaign_fingerprint: 'a'.repeat(64),
      created_at: NOW,
      expires_at: NOW + 300,
    }
    const o = overview({ pending: { state: 'ok', value: [operation] } })
    expect(liveOperation(o, 'renew_fleet')?.operation_id).toBe('c'.repeat(32))
    expect(liveOperation(o, 'renew_delegation')).toBeNull()
    expect(liveOperation(overview({ pending: { state: 'not_admin' } }), 'renew_fleet')).toBeNull()
  })
})

describe('the stops', () => {
  const journal = {
    kind: 'ca_pq' as const,
    stage: 'applied' as const,
    activationAt: 1_800_000_000,
    notAfter: 1_802_000_000,
    nextFingerprint: 'aa',
  }

  it('an_install_deadline_shows_its_date', () => {
    expect(stopSentence('install_deadline_passed', journal)).toMatch(/^Délai dépassé le .*2027/)
    expect(stopSentence('install_deadline_passed', journal)).toMatch(/Intervention manuelle requise/)
  })

  it('a_CA_PQ_conflict_points_to_the_signer', () => {
    expect(stopSentence('domain_conflict', journal)).toMatch(/astra-signer rotate-ca-pq/)
    expect(stopSentence('domain_conflict', { ...journal, kind: 'ca_tls' })).not.toMatch(/astra-signer/)
  })
})

describe('the wording', () => {
  it('the_screen_has_no_second_person_text', () => {
    const texts: string[] = []
    const o = overview({
      resumable: true,
      caTlsCloseAt: NOW - 1,
      journal: {
        kind: 'ca_tls',
        stage: 'signed',
        activationAt: NOW + 1,
        notAfter: NOW + 2,
        nextFingerprint: 'aa',
      },
    })
    for (const variant of [o, overview({ caPqOverlap: true }), overview({ vault: null, vaultError: 'illisible', tunnel: false })]) {
      for (const r of rotationRows(variant, NOW)) texts.push(r.title, r.state, r.disabledReason ?? '', r.button)
      for (const action of ['replace_ca_pq', 'renew_fleet'] as const) {
        for (const p of prerequisites(variant, action)) texts.push(p.label, p.fix ?? '', p.detail ?? '')
      }
    }
    texts.push(stopSentence('domain_conflict', null), stopSentence('install_deadline_passed', null))
    for (const text of texts) expect(text).not.toMatch(/\b(tu|te|ton|ta|tes|toi)\b/i)
  })
})
