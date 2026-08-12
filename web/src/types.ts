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
