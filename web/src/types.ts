export type TunnelState = 'down' | 'connecting' | 'up' | 'failed' | 'captive_portal'

/** Pair WireGuard admis par la gateway. Le PSK n'est jamais exposé. */
export interface PeerSummary {
  name: string
  public_key: string
  address: string
  post_quantum: boolean
}

/** Contrat exact de GET /api/status. */
export interface Status {
  state: TunnelState
  version: string
  wan_iface: string
  lan_ifaces: string[]
  /** Pairs statiques sortants (site-à-site), distincts des clients admis. */
  wg_peers: string[]
  allow_ssh_from: string[]
  peers: PeerSummary[]
  wg_iface: string
  wg_listen_port: number | null
  dry_run: boolean
  split_tunnel_cidrs: string[]
  mss_clamp: number | null
  captive_portal_gateway: string | null
}

/** Une époque du trousseau éditeur. La clé n'est jamais exposée, seulement son empreinte. */
export interface PublisherKey {
  key_epoch: number
  fingerprint: string
}

/**
 * Contrat de GET /api/trust — l'ancre de confiance compilée dans le binaire (ADR-002).
 * Tout y est constante de compilation : rien ici ne se reconfigure à chaud.
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

/** Événements affichés dans le terminal — hors télémétrie (streamée séparément). */
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
