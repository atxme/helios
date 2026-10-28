import { describe, expect, it } from 'vitest'
import { rowsOf } from './OperatorCeremony'
import type { AcceptanceManifest, InvitationManifest } from '../types'

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
