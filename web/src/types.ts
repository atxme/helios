export type TunnelState = 'down' | 'connecting' | 'up' | 'failed' | 'captive_portal'

/**
 * Protection a client may negotiate before the WireGuard handshake
 * (ADR-001, amendment of 24 July 2026). The order is monotonic:
 * `classic < static_psk < ml_kem`.
 */
export type ProtectionMode = 'classic' | 'static_psk' | 'ml_kem'

/** WireGuard peer admitted by the gateway. The PSK is never exposed. */
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
}

/** Exact contract of GET /api/status. */
export interface Status {
  state: TunnelState
  version: string
  wan_iface: string
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
