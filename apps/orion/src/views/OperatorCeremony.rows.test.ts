import { describe, expect, it } from 'vitest'
import { rowsOf } from './OperatorCeremony'
import type {
  AcceptanceManifest,
  CaRotationManifest,
  InvitationManifest,
  IssuerManifest,
} from '../types'

const acceptance: AcceptanceManifest = {
  operation: 'enrollment_acceptance',
  invitation_id: '0'.repeat(32),
  request_fingerprint: 'a'.repeat(64),
  requested_name: 'portable',
  client_wg_public_key: 'k'.repeat(44),
  leaves_not_after_unix: 1_800_000_000,
  endpoint: '198.51.100.7:51820',
}

describe('rowsOf for the enrolment manifests', () => {
  it('shows_the_signed_routes_when_present', () => {
    const rows = rowsOf({
      ...acceptance,
      allowed_ips: '10.0.0.0/24',
      ssh_target: 'root@10.0.0.1',
    })
    expect(rows).toContainEqual(['routes autorisées', '10.0.0.0/24'])
    expect(rows).toContainEqual(['cible SSH', 'root@10.0.0.1'])
  })

  it('omits_the_routes_that_the_document_does_not_carry', () => {
    const labels = rowsOf(acceptance).map(([label]) => label)
    expect(labels).not.toContain('routes autorisées')
    expect(labels).not.toContain('cible SSH')
  })

  it('shows_the_ca_pq_fingerprint_in_groups_of_four', () => {
    const invitation: InvitationManifest = {
      operation: 'invitation',
      server_name: 'gateway.example',
      gateway_wg_public_key: 'k'.repeat(44),
      not_after_unix: 1_800_000_000,
      allow_readmission: false,
      ca_pq_fingerprint: '0123456789abcdef0123',
    }
    expect(rowsOf(invitation)).toContainEqual(['CA-PQ', '0123 4567 89ab cdef 0123'])
  })
})

describe('rowsOf for the issuer delegation', () => {
  const issuer: IssuerManifest = {
    operation: 'issuer_authorization',
    trust_domain_id: 'td',
    issuer_epoch: 3,
    not_before: 1_800_000_000,
    not_after: 1_802_592_000,
    allowed_usages: ['issue_client_leaf', 'issue_gateway_leaf'],
    policy_fingerprint: 'p'.repeat(64),
    request_fingerprint: 'r'.repeat(64),
    maximum_leaf_lifetime_secs: 90 * 86_400,
    pq_public_key_fingerprint: 'q'.repeat(64),
    tls_public_key_info_fingerprint: 't'.repeat(64),
  }

  it('the_delegation_manifest_lists_what_is_signed', () => {
    const rows = rowsOf(issuer)
    expect(rows.map(([label]) => label)).toEqual([
      'domaine',
      'époque de l’émetteur',
      'valide du / jusqu’au',
      'leaf au plus (jours)',
      'usages',
      'clé PQ (empreinte)',
      'clé TLS (empreinte)',
      'demande (empreinte)',
      'politique',
    ])
    expect(rows).toContainEqual(['leaf au plus (jours)', '90'])
    expect(rows).toContainEqual(['usages', 'issue_client_leaf, issue_gateway_leaf'])
    expect(rows).toContainEqual(['clé PQ (empreinte)', 'q'.repeat(64)])
    expect(rows).toContainEqual(['clé TLS (empreinte)', 't'.repeat(64)])
  })

  it('the_campaign_rows_follow_only_when_there_is_a_campaign', () => {
    const rows = rowsOf({
      ...issuer,
      campaign: {
        campaign: {
          format_version: 1,
          campaign_id: 'c'.repeat(32),
          trust_domain_id: 'td',
          gateway_wg_public_key: 'k',
          server_name: 'gw',
          created_at: 1,
          expires_at: 2,
          scope: 'issuer_delegation',
          targets: [],
          reason: 'déléguer',
          requested_by: 'operator',
          policy_fingerprint: 'p'.repeat(64),
          required_credentials: 1,
        },
        fingerprint: 'f'.repeat(64),
      },
    })
    expect(rows.slice(-4)).toEqual([
      ['campagne', 'c'.repeat(32)],
      ['motif', 'déléguer'],
      ['demandée par', 'operator'],
      ['empreinte de campagne', 'f'.repeat(64)],
    ])
  })
})

describe('rowsOf for a CA rotation', () => {
  const rotation: CaRotationManifest = {
    operation: 'ca_rotation',
    trust_domain_id: 'td',
    affected_ca: 'ca_tls',
    current_epoch: 1,
    next_epoch: 2,
    activation_at: 1_800_000_000,
    not_after: 1_802_000_000,
    outgoing_anchor_fingerprint: 'o'.repeat(64),
    target_count: 1,
  }

  it('the_incoming_anchor_is_named_as_still_to_come_at_the_touch', () => {
    const rows = rowsOf(rotation)
    expect(rows).toContainEqual(['autorité visée', 'CA-TLS cliente'])
    expect(rows).toContainEqual(['époque', '1 → 2'])
    expect(rows).toContainEqual(['ancre sortante', 'o'.repeat(64)])
    expect(rows).toContainEqual(['ancre entrante', 'créée à la signature'])
    expect(rows.map(([label]) => label)).not.toContain('campagne')
  })

  it('the_incoming_anchor_is_shown_once_it_exists', () => {
    const rows = rowsOf({ ...rotation, next_anchor_fingerprint: 'n'.repeat(64) })
    expect(rows).toContainEqual(['ancre entrante', 'n'.repeat(64)])
  })

  it('the_campaign_rows_follow_without_listing_its_targets', () => {
    const rows = rowsOf({
      ...rotation,
      campaign: {
        campaign: {
          format_version: 1,
          campaign_id: 'c'.repeat(32),
          trust_domain_id: 'td',
          gateway_wg_public_key: 'k',
          server_name: 'gw',
          created_at: 1,
          expires_at: 2,
          scope: 'trust_authorities',
          targets: [],
          reason: 'renouveler',
          requested_by: 'operator',
          policy_fingerprint: 'p'.repeat(64),
          required_credentials: 2,
        },
        fingerprint: 'f'.repeat(64),
      },
    })
    expect(rows.slice(-5)).toEqual([
      ['campagne', 'c'.repeat(32)],
      ['portée', 'les ancres du domaine'],
      ['motif', 'renouveler'],
      ['demandée par', 'operator'],
      ['empreinte de campagne', 'f'.repeat(64)],
    ])
  })
})
