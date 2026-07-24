// Mirror types of Rust structures (orion-core) serialized via Tauri.
// Aligned with web/src/types.ts for the state/telemetry part shared with heliosd.

// WireGuard model (ADR-001). `rekeying` disappeared: WireGuard rekeys
// transparently, there's no observable state. `up` is *inferred* from a
// recent handshake (< 150 s), not received as an event.
export type TunnelState =
  | 'down'
  | 'connecting'
  | 'up'
  | 'failed'
  | 'captive_portal'

// A WireGuard peer: identity = Curve25519 public key, reached via a UDP
// endpoint. No CA, no EAP, no cryptographic proposal — WireGuard has only
// one suite.
export interface ClientProfile {
  name: string
  /** Gateway's UDP endpoint: `IP:port` or `FQDN:port`. */
  endpoint: string
  /** Client's Curve25519 private key (base64). Secret. */
  private_key: string
  /** Gateway's Curve25519 public key (base64). */
  peer_public_key: string
  /**
   * **Static** PSK shared out of band (base64). Secret.
   *
   * The PQC PSK from ML-KEM never lands here: it isn't persisted and gets
   * renegotiated on every connection. `null` is therefore the normal case
   * for a Helios profile — see `PskKind`.
   */
  preshared_key: string | null
  /** CGNAT VIP assigned by the gateway at enrollment (e.g. `100.64.1.2/32`). */
  address: string | null
  /** Traffic routed into the tunnel. Defaults to `0.0.0.0/0`. */
  allowed_ips: string
  /** Keepalive in seconds. Defaults to 25. */
  persistent_keepalive: number
  heliosd_url: string | null
}

export interface ClientConfig {
  profiles: ClientProfile[]
  selected: string | null
}

/**
 * Faulty fields of a profile, reported by `orion-core::inspect_profile`.
 *
 * `null` = nothing to report. An empty field is never reported: while
 * typing, "not filled in yet" is not "impossible".
 */
export interface ProfileIssues {
  name: string | null
  endpoint: string | null
  private_key: string | null
  peer_public_key: string | null
  preshared_key: string | null
  address: string | null
  allowed_ips: string | null
  persistent_keepalive: string | null
  heliosd_url: string | null
}

/**
 * What occupies the `PresharedKey` slot of the current tunnel — mirror of
 * `orion_core::events::PskKind`.
 *
 * A PSK is not a PQC PSK: both live in the same WireGuard slot, but one was
 * copied by hand and never rotates, the other comes from an ML-KEM-768
 * exchange replayed on every connection. The profile can't distinguish them,
 * since the latter is never persisted — only the client core knows which
 * one it set.
 */
export type PskKind = 'none' | 'static' | 'ml_kem'

// Events pushed by the Rust backend (emit "helios://event").
export type ClientEvent =
  | { type: 'state_changed'; state: TunnelState }
  | { type: 'protection'; psk: PskKind }
  | { type: 'log'; level: string; message: string }
  | { type: 'telemetry'; iface: string; rx_bps: number; tx_bps: number; rx_pps: number; tx_pps: number }
  | { type: 'error'; message: string }

export interface LogLine {
  level: string
  message: string
  ts: string
}

export interface TelemetrySample {
  rx_bps: number
  tx_bps: number
}
