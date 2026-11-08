// Test fixtures for the rotations screen.
import type {
  GatewayDomainRead,
  OperatorAuthorityStatus,
  RotationsOverview,
  VaultOverview,
} from '../../types'

export const DAY = 86_400
export const NOW = 1_800_000_000
export const ANCHOR = 'ab'.repeat(32)
export const GROUPED = ANCHOR.match(/.{4}/g)!.join(' ')

export const domainRead = (extra: Partial<GatewayDomainRead> = {}): GatewayDomainRead => ({
  now_unix: NOW,
  ca_fingerprint: ANCHOR,
  ca_epoch: 3,
  ca_tls_epoch: 2,
  ca_transition_pending: false,
  ca_retire_active_at: null,
  next_ca_fingerprint: null,
  client_tls_ca_transition_pending: false,
  peers: [{ not_after: NOW + 90 * DAY }, { not_after: NOW + 120 * DAY }],
  ...extra,
})

export const authorityRead = (
  extra: Partial<OperatorAuthorityStatus> = {},
): OperatorAuthorityStatus => ({
  ca_epoch: 3,
  ca_fingerprint: ANCHOR,
  next_ca_fingerprint: null,
  ca_tls_epoch: 2,
  ca_tls_fingerprint: 'cd'.repeat(32),
  next_ca_tls_fingerprint: null,
  issuer: { recorded_epoch: 4, serving_epoch: 4, ca_epoch: 3, ca_tls_epoch: 2, not_after: NOW + 300 * DAY },
  vault_copy_fingerprint: 'ef'.repeat(32),
  credential_registry_epoch: 5,
  ...extra,
})

export const vaultOverview = (extra: Partial<VaultOverview> = {}): VaultOverview => ({
  vault_path: '',
  exists: true,
  location_available: true,
  bootstrapped: true,
  credentials_complete: true,
  vault_fingerprint: 'ef'.repeat(32),
  slots: [
    { slot_id: 'a', label: 'Clé 1', role: 'principale', state: 'active' },
    { slot_id: 'b', label: 'Clé 2', role: 'recuperation', state: 'active' },
  ],
  max_slots: 8,
  domain: {
    trust_domain_id: 'td',
    rp_id: 'gw',
    ca_pq_fingerprint: GROUPED,
    ca_epoch: 3,
    ca_tls_epoch: 2,
    ca_tls_present: true,
    server_name: 'gw',
    gateway_wg_public_key: null,
    astra_service_public_key: null,
    astra_service_key_epoch: null,
    astra_authority_url: null,
  },
  ...extra,
})

export const overview = (extra: Partial<RotationsOverview> = {}): RotationsOverview => ({
  tunnel: true,
  pending: { state: 'ok', value: [] },
  authority: { state: 'ok', value: authorityRead() },
  domain: { state: 'ok', value: domainRead() },
  vault: vaultOverview(),
  vaultError: null,
  localVaultFingerprint: 'ef'.repeat(32),
  localCaEpoch: 3,
  localCaTlsEpoch: 2,
  localCaTlsNotAfter: NOW + 1500 * DAY,
  localCredentialRegistryEpoch: 5,
  journal: null,
  resumable: false,
  caPqOverlap: false,
  caTlsCloseDue: false,
  caTlsCloseAt: null,
  ...extra,
})

