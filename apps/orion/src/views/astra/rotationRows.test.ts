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
  journalLine,
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

  // Spec §5.4: nothing opens while the gateway holds a transition of the same kind, even
  // one Astra has already promoted (the gateway's own lag) or never heard of.
  it('a_CA_PQ_transition_the_gateway_holds_disables_the_replacements', () => {
    for (const gateway of [
      domainRead({ ca_transition_pending: true }),
      domainRead({ next_ca_fingerprint: '12'.repeat(32) }),
    ]) {
      const o = overview({ caPqOverlap: false, domain: { state: 'ok', value: gateway } })
      expect(row(o, 'replace_ca_pq')?.disabledReason).toBe('Recouvrement CA-PQ en cours')
      expect(row(o, 'replace_ca_tls')?.disabledReason).toBe('Recouvrement CA-PQ en cours')
    }
    expect(row(overview(), 'replace_ca_pq')?.disabledReason).toBeNull()
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
      offline: false,
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
      offline: false,
    }
    // Local data and the workstation clock: a Signed journal Astra never heard of, or an
    // Applied one already on the gateway, resume harmlessly. Not a dead end yet.
    const state = row(overview({ resumable: true, journal }), 'resume')?.state ?? ''
    expect(state).toMatch(/Délai d’installation passé : à vérifier à la connexion/)
    expect(state).not.toMatch(/Intervention manuelle/)
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

  it('the_copy_reads_old_when_only_the_credential_epoch_is_ahead', () => {
    // Same vault bytes: a key marked lost changes the document and not the vault.
    const marked = overview({ localCredentialRegistryEpoch: 6 })
    expect(find(marked, 'Copie du coffre')).toMatchObject({
      ok: false,
      detail: 'Document ancien',
      fix: 'Envoyer',
      fixAction: 'send_vault_copy',
    })
    const noneServed = overview({
      localCredentialRegistryEpoch: 1,
      authority: { state: 'ok', value: authorityRead({ credential_registry_epoch: null }) },
    })
    expect(find(noneServed, 'Copie du coffre')?.detail).toBe('Document ancien')
    // Astra ahead or level: nothing to send.
    expect(find(overview({ localCredentialRegistryEpoch: 4 }), 'Copie du coffre')?.ok).toBe(true)
    expect(find(overview({ localCredentialRegistryEpoch: null }), 'Copie du coffre')?.ok).toBe(true)
  })

  it('the_document_is_not_offered_where_the_send_leaves_it_out', () => {
    // During a CA-PQ overlap Astra adopts its own document at the promotion, and a
    // rotation to resume replaces the one beside the vault: « Envoyer » would not carry it.
    const overlap = overview({
      localCredentialRegistryEpoch: 6,
      caPqOverlap: true,
      authority: { state: 'ok', value: authorityRead({ next_ca_fingerprint: '12'.repeat(32) }) },
    })
    expect(find(overlap, 'Copie du coffre')?.ok).toBe(true)
    const resumable = overview({ localCredentialRegistryEpoch: 6, resumable: true })
    expect(find(resumable, 'Copie du coffre')?.ok).toBe(true)
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

describe('the delegation copy', () => {
  it('the_delegation_needs_the_vault_copy_and_one_key', () => {
    const labels = prerequisites(overview(), 'renew_delegation').map((p) => p.label)
    expect(labels).toContain('Copie du coffre')
    expect(labels).not.toContain('Deux clés enregistrées')
  })
})

describe('a live delegation', () => {
  it('is_shown_open_with_its_expiry_and_not_resumable_then_offered_once_closed', () => {
    const live = {
      operation_id: 'c'.repeat(32),
      scope: 'issuer_delegation' as const,
      reason: 'x',
      requested_by: 'y',
      target_count: 1,
      required_credentials: 1,
      campaign_fingerprint: 'a'.repeat(64),
      created_at: NOW - 100,
      expires_at: NOW + 200,
    }
    const open = row(overview({ pending: { state: 'ok', value: [live] } }), 'renew_delegation')
    expect(open?.disabledReason).toMatch(/^Opération ouverte jusqu’au /)
    const closed = row(
      overview({ pending: { state: 'ok', value: [{ ...live, expires_at: NOW - 1 }] } }),
      'renew_delegation',
    )
    expect(closed?.disabledReason).toBeNull()
  })
})

describe('live operations', () => {
  it('ignores_an_operation_past_its_expiry_on_the_gateway_clock', () => {
    const stale = {
      operation_id: 'c'.repeat(32),
      scope: 'fleet_leafs' as const,
      reason: 'x',
      requested_by: 'y',
      target_count: 1,
      required_credentials: 1,
      campaign_fingerprint: 'a'.repeat(64),
      created_at: NOW - 500,
      expires_at: NOW - 1,
    }
    const o = overview({ pending: { state: 'ok', value: [stale] } })
    expect(liveOperation(o, 'renew_fleet', NOW)).toBeNull()
    // The local clock is behind, the gateway's is not: the gateway's decides.
    expect(liveOperation(o, 'renew_fleet', NOW - 1_000)).toBeNull()
    const late = overview({
      pending: { state: 'ok', value: [{ ...stale, expires_at: NOW + 50 }] },
      domain: { state: 'unreachable' },
    })
    expect(liveOperation(late, 'renew_fleet', NOW)?.operation_id).toBe('c'.repeat(32))
  })

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
    expect(liveOperation(o, 'renew_fleet', NOW)?.operation_id).toBe('c'.repeat(32))
    expect(liveOperation(o, 'renew_delegation', NOW)).toBeNull()
    expect(liveOperation(overview({ pending: { state: 'not_admin' } }), 'renew_fleet', NOW)).toBeNull()
  })
})

describe('the stops', () => {
  const journal = {
    kind: 'ca_pq' as const,
    stage: 'applied' as const,
    activationAt: 1_800_000_000,
    notAfter: 1_802_000_000,
    nextFingerprint: 'aa',
    offline: true,
  }

  it('an_install_deadline_shows_its_date', () => {
    expect(stopSentence('install_deadline_passed', journal)).toMatch(/^Délai dépassé le .*2027/)
    expect(stopSentence('install_deadline_passed', journal)).toMatch(/Intervention manuelle requise/)
  })

  it('an_install_deadline_gives_the_cut_date_apart_from_the_activation', () => {
    const sentence = stopSentence('install_deadline_passed', journal)
    expect(sentence).toMatch(/Coupure le .*2027/)
    expect(sentence).toMatch(/Intervention manuelle requise\.$/)
    expect(stopSentence('install_deadline_passed', null)).toBe(
      'Délai dépassé. Intervention manuelle requise.',
    )
  })

  it('the_label_of_a_gateway_naming_no_anchor_gives_both_causes', () => {
    const label = stopSentence('gateway_names_no_anchor', { ...journal, kind: 'ca_tls' })
    expect(label).toMatch(/CA TLS/)
    expect(label).toMatch(/mise à jour/)
    expect(label).not.toBe(stopSentence('domain_conflict', journal))
  })

  it('an_offline_CA_PQ_conflict_points_to_the_signer', () => {
    expect(stopSentence('domain_conflict', journal)).toMatch(/astra-signer rotate-ca-pq/)
    expect(stopSentence('domain_conflict', { ...journal, kind: 'ca_tls' })).not.toMatch(/astra-signer/)
  })

  it('a_conflict_on_a_rotation_Orion_carries_does_not_send_to_the_signer', () => {
    const sentence = stopSentence('domain_conflict', { ...journal, offline: false })
    expect(sentence).not.toMatch(/astra-signer/)
    expect(sentence).toMatch(/Intervention manuelle requise/)
  })

  it('the_outdated_gateway_names_the_kind_of_the_journal', () => {
    expect(stopSentence('gateway_names_no_anchor', journal)).toMatch(/CA-PQ/)
    expect(stopSentence('gateway_names_no_anchor', journal)).not.toMatch(/CA TLS/)
    expect(stopSentence('gateway_names_no_anchor', { ...journal, kind: 'ca_tls' })).toMatch(/CA TLS/)
    expect(stopSentence('gateway_names_no_anchor', null)).toMatch(/sans CA TLS/)
  })
})

describe('the incoming anchor on its row', () => {
  it('stays_visible_during_a_CA_PQ_overlap_from_the_authority', () => {
    const o = overview({
      caPqOverlap: true,
      authority: { state: 'ok', value: authorityRead({ next_ca_fingerprint: 'cd'.repeat(32) }) },
    })
    expect(row(o, 'replace_ca_pq')?.detail).toBe(
      `Ancre entrante ${'cdcd '.repeat(15)}cdcd`,
    )
  })

  it('falls_back_on_the_gateway_and_is_absent_outside_an_overlap', () => {
    const o = overview({
      caPqOverlap: true,
      authority: { state: 'unreachable' },
      domain: { state: 'ok', value: domainRead({ next_ca_fingerprint: 'ef'.repeat(32) }) },
    })
    expect(row(o, 'replace_ca_pq')?.detail).toMatch(/^Ancre entrante efef /)
    expect(row(overview(), 'replace_ca_pq')?.detail).toBeNull()
  })
})

describe('the journal line', () => {
  const journal = {
    kind: 'ca_pq' as const,
    stage: 'applied' as const,
    activationAt: NOW + 3 * DAY,
    notAfter: NOW + 33 * DAY,
    nextFingerprint: 'aa',
    offline: false,
  }

  it('gives_the_deadline_of_a_rotation_still_to_install', () => {
    const line = journalLine(journal, NOW)
    expect(line.blocking).toBe(false)
    expect(line.text).toMatch(/^Rotation CA-PQ · à installer avant le /)
  })

  it('past_the_activation_it_is_to_check_at_the_connection_and_not_a_dead_end', () => {
    const line = journalLine({ ...journal, activationAt: NOW - DAY }, NOW)
    expect(line.blocking).toBe(false)
    expect(line.text).toBe('Rotation CA-PQ · Délai d’installation passé : à vérifier à la connexion')
  })

  it('a_resumption_that_found_the_deadline_passed_is_blocking_with_the_cut_date', () => {
    const line = journalLine({ ...journal, activationAt: NOW - DAY }, NOW, true)
    expect(line.blocking).toBe(true)
    expect(line.text).toMatch(/^Délai dépassé le /)
    expect(line.text).toMatch(/Coupure le /)
    expect(line.text).toMatch(/Intervention manuelle requise/)
  })

  it('an_installed_rotation_only_awaits_its_copy', () => {
    const line = journalLine({ ...journal, kind: 'ca_tls', stage: 'installed' }, NOW - 400 * DAY)
    expect(line.blocking).toBe(false)
    expect(line.text).toBe('Rotation CA TLS · copie du coffre en attente')
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
        offline: false,
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
