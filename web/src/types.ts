export type TunnelState = 'down' | 'connecting' | 'up' | 'failed' | 'captive_portal'

/**
 * Protection a client may negotiate before the WireGuard handshake
 * (ADR-001, amendment of 24 July 2026). The order is monotonic:
 * `classic < static_psk < ml_kem`.
 */
export type ProtectionMode = 'classic' | 'static_psk' | 'ml_kem'

/**
 * WireGuard peer admitted by the gateway. The PSK is never exposed.
 *
 * The last four fields are the **runtime**: what the data plane last reported.
 * They are absent — not zeroed — when the interface is down or the peer has
 * never been seen, because "never observed" and "transferred nothing" are
 * different facts and the console shows them differently.
 */
export interface PeerSummary {
  name: string
  public_key: string
  address: string
  /**
   * IPv6 VIP, `…/128`, when the gateway has a tunnel prefix and this peer an
   * address in it (ADRESSAGE-IPV6.md §5.1); `null` otherwise. Configuration,
   * not observation: whether it is actually routed depends on `Status.ipv6`.
   */
  address_v6: string | null
  post_quantum: boolean
  admin: boolean
  /**
   * Floor this peer can no longer fall back below. It rises on its own after
   * each committed negotiation and never comes back down over the network —
   * only a local edit of `network.toml` lowers it.
   */
  minimum_key_negotiation_mode: ProtectionMode
  last_handshake_age_seconds: number | null
  endpoint: string | null
  rx_bytes: number | null
  tx_bytes: number | null
}

/**
 * Why a configured IPv6 tunnel prefix was not installed
 * (`aether::net::Ipv6Unavailable`, ADRESSAGE-IPV6.md §6.2).
 */
export type Ipv6Unavailable =
  | { reason: 'tunnel_mtu_too_small'; tunnel_mtu: number; minimum: number }
  | { reason: 'disabled_by_kernel'; setting: string }
  | { reason: 'no_kernel_support'; path: string }
  | { reason: 'address_refused'; address: string; detail: string }

/**
 * What the last bring-up did with the IPv6 tunnel prefix
 * (`aether::net::Ipv6TunnelStatus`). `unavailable` is the visible degraded
 * state: the gateway runs IPv4-only.
 */
export type Ipv6TunnelStatus = 'not_configured' | 'installed' | { unavailable: Ipv6Unavailable }

/** Exact contract of GET /api/status. */
export interface Status {
  state: TunnelState
  version: string
  wan_ifaces: string[]
  lan_ifaces: string[]
  /** Static outbound peers (site-to-site), distinct from admitted clients. */
  wg_peers: string[]
  allow_ssh_from: string[]
  peers: PeerSummary[]
  wg_iface: string
  wg_listen_port: number | null
  /** Public UDP port of the key negotiation, `null` if the service is off. */
  key_negotiation_port: number | null
  dry_run: boolean
  split_tunnel_cidrs: string[]
  mss_clamp: number | null
  captive_portal_gateway: string | null
  /**
   * Age past which a handshake no longer proves a peer is there.
   *
   * Read from the daemon rather than hardcoded here: it is the same threshold
   * the orchestrator uses to decide whether the kill-switch lifts, and a
   * console applying its own would eventually show a client as connected after
   * the firewall had already cut it.
   */
  handshake_stale_after_seconds: number
  /** Observed on the data plane at the last bring-up, not read from the configuration. */
  ipv6: Ipv6TunnelStatus
}

/**
 * Request accepted by `POST /api/peers`.
 *
 * No address: the gateway derives the CGNAT VIP from the public key itself
 * (`helios-provisioning`'s IPAM), so an operator never picks one — and cannot
 * pick one already taken.
 */
export interface PeerAdmission {
  name: string
  public_key: string
  admin?: boolean
  key_negotiation_certificate_sha256?: string | null
  key_negotiation_pq_certificate_sha256?: string | null
  minimum_key_negotiation_mode?: ProtectionMode
}

/** An epoch of the publisher keyring. The key is never exposed, only its fingerprint. */
export interface PublisherKey {
  key_epoch: number
  fingerprint: string
}

/**
 * Contract of GET /api/trust — the trust anchor compiled into the binary (ADR-002).
 * Everything here is a compile-time constant: nothing is reconfigured at runtime.
 */
export interface Trust {
  required_algs: string[]
  publisher_keys: PublisherKey[]
  development_keys: boolean
  reseal_domain: string
  reseal_format_version: number
}

/**
 * Sealing posture of the gateway, without the secret behind it.
 *
 * `preserved_vaults: false` is the single most consequential thing this
 * console reports: the sealed WireGuard identity and the negotiation identity
 * no longer open, so the whole fleet has to be re-enrolled.
 */
export interface TpmSummary {
  kind: 'disabled' | 'bypassed' | 'unsealed' | 'provisioned' | 'resealed' | 'window_resealed'
  preserved_vaults: boolean
}

/**
 * Health of the machine carrying the gateway.
 *
 * Every field is independent and optional: a kernel that publishes no thermal
 * zone — every virtual machine, and WSL2 — must cost the other readings
 * nothing.
 */
export interface Health {
  uptime_seconds: number | null
  load: [number, number, number] | null
  cpu_count: number | null
  memory_total_bytes: number | null
  memory_available_bytes: number | null
  temperature_celsius: number | null
  tpm: TpmSummary | null
}

export type HeliosEvent =
  | { type: 'state_changed'; state: TunnelState }
  | { type: 'log'; level: string; message: string }
  | { type: 'telemetry'; iface: string; rx_bps: number; tx_bps: number; rx_pps: number; tx_pps: number }
  | { type: 'captive_portal_detected'; gateway: string }
  | { type: 'mtu_discovered'; mtu: number; mss: number }
  | { type: 'split_tunnel_changed'; cidrs: string[] }

export interface TelemetrySample {
  rx_bps: number
  tx_bps: number
  rx_pps: number
  tx_pps: number
}

/** Events displayed in the terminal — excluding telemetry (streamed separately). */
export type DisplayEvent = Exclude<HeliosEvent, { type: 'telemetry' }>

export interface FirewallRules {
  rules: string
  default_verdict: string
  dry_run: boolean
}

export interface CommandResponse {
  ok: boolean
  error?: string
}

export interface FinalizedRelease {
  release_sequence: number
  version: string
  sha256: string
}

export interface UpdateStatus {
  highest_confirmed_sequence: number
  active_version: string | null
  staged: FinalizedRelease[]
  activation_pending: number | null
  channel: string
  target: string
}

/**
 * Where a certificate sits on the renewal ladder of spec §4.3.
 *
 * The rungs are the protocol's own — 80 / 90 / 95 % of the lifetime — computed
 * by the gateway from `aether::certificates::window`. The console never
 * recomputes them: a screen with its own arithmetic eventually disagrees with
 * the planner that actually schedules the renewal.
 */
export type CertificatePhase =
  | 'not_yet_valid'
  | 'valid'
  | 'renewal_due'
  | 'warning'
  | 'critical'
  | 'expired'

/** How far a candidate generation has got between staging and commit. */
export type PendingStageState = 'pending_grant' | 'pending_commit'

export type IssuerLifecycle = 'active' | 'expiring' | 'revoked'

export interface PendingStageView {
  generation: number
  state: PendingStageState
  stage_expires_at: number
}

/** The bounded delegation ordinary renewals are issued under (spec §3.4). */
export interface IssuerView {
  issuer_epoch: number
  lifecycle: IssuerLifecycle
  not_before: number
  not_after: number
  /**
   * Whether it may sign right now, which the lifecycle alone does not say: an
   * `active` delegation past its `not_after` signs nothing.
   */
  usable: boolean
}

export interface PeerCertificateView {
  name: string
  wg_public_key: string
  generation: number
  not_before: number
  not_after: number
  phase: CertificatePhase
  revoked: boolean
  pending: PendingStageView | null
  next_generation: number | null
  activation_at: number | null
  /** Fragments of a signed transaction this peer has not collected yet. */
  distribution_chunks_pending: number
}

/**
 * Contract of GET /api/certificates — the trust domain as an operator reads it.
 *
 * `now_unix` is the **gateway's** clock, and the whole view is drawn against
 * it. A workstation minutes off would otherwise place every leaf on the wrong
 * rung of the ladder, and the operator would trust the screen.
 */
export interface CertificateDomain {
  trust_domain_id: string
  server_name: string
  now_unix: number
  ca_epoch: number
  ca_pq_fingerprint: string
  ca_transition_pending: boolean
  ca_activation_at: number | null
  ca_retire_active_at: number | null
  next_ca_fingerprint: string | null
  client_tls_ca_epoch: number
  client_tls_ca_transition_pending: boolean
  gateway_identity_epoch: number
  gateway_tls_fingerprint: string
  gateway_pq_fingerprint: string
  gateway_transition_pending: boolean
  gateway_activation_at: number | null
  gateway_retire_active_at: number | null
  gateway_transition_published: boolean
  gateway_rollback_expires_at: number | null
  gateway_restart_due: string | null
  astra_authority_url: string
  astra_service_key_epoch: number
  astra_policy_fingerprint: string
  webauthn_rp_id: string
  credential_registry_epoch: number
  credential_bindings: number
  issuer: IssuerView | null
  peers: PeerCertificateView[]
}

/** What the console asks of a gateway renewal (spec §12.2, §11.1 steps 1-2). */
export interface GatewayRenewalRequest {
  rotate_tls: boolean
  new_key: boolean
  key_recovery: boolean
}

/** The exported request, as the operator reads it before carrying it away. */
export interface GatewayRenewalView {
  gateway_identity_epoch: number
  request_id: string
  request_fingerprint: string
  expires_at: number
  candidate_tls_fingerprint: string | null
  reused: boolean
  key_recovery: boolean
}

/** A staged or cancelled decision, as the console displays it back. */
export interface GatewayDecisionView {
  gateway_identity_epoch: number
  fingerprint: string
  already_present: boolean
  activation_at: number | null
  not_after: number | null
}

/** A service rollback, as the console displays it back (§4.4). */
export interface GatewayRollbackView {
  gateway_identity_epoch: number
  selected_certificate_fingerprint: string
  expires_at: number
  already_present: boolean
}

/** A staged anchor rotation, as the console displays it back (§9.1). */
export interface AnchorDecisionView {
  ca_epoch: number
  next_ca_epoch: number
  next_ca_fingerprint: string
  activation_at: number
  not_after: number
  already_present: boolean
}
