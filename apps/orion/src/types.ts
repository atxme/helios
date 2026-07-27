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

/**
 * Protection negotiated **before** the WireGuard handshake, on the gateway's
 * public key-negotiation port (ADR-001, amendment of 24 July 2026).
 *
 * The order is monotonic — `classic < static_psk < ml_kem` — and it is the
 * whole point: a profile carries a floor it can rise above but never fall
 * below.
 */
export type ProtectionMode = 'classic' | 'static_psk' | 'ml_kem'

/**
 * Public settings of the key negotiation, as the operator distributes them.
 *
 * **No client secret lives here.** The certificate and its private key stay
 * in the machine's protected store; `identity` is only the name of the entry
 * to look up there.
 */
export interface KeyNegotiationSettings {
  mode: ProtectionMode
  /** Floor below which this profile refuses to negotiate. */
  minimum_mode: ProtectionMode
  /** Gateway's UDP endpoint for the negotiation — normally port 51821. */
  endpoint: string
  /** DNS name authenticated by the gateway certificate. */
  server_name: string
  /** Gateway CA certificate, DER encoded in base64. */
  gateway_ca_der: string
  /** Pinned ML-DSA-65 gateway certificate: base64-encoded JSON. */
  gateway_pq_certificate: string
  /** Opaque lookup name in the protected identity store. */
  identity: string
}

/**
 * What this machine can actually do with the negotiation port.
 *
 * The negotiation itself is not a build option: every Orion carries it. Only
 * the protected identity store is conditional — it is the machine's, and
 * DPAPI exists only on Windows.
 */
export interface KeyNegotiationSupport {
  /** A protected identity store is wired into the client core. */
  identity_store: boolean
}

/**
 * Result of importing a document — mirror of the shell's `ImportOutcome`.
 *
 * The identity's fate is reported next to the profile rather than replacing
 * it: a profile stays importable on a machine that cannot seal, and hiding it
 * behind that failure would leave the user with nothing to look at.
 */
export interface ImportOutcome {
  profile: ClientProfile
  /** The document carried an identity **and** it was sealed. */
  identity_sealed: boolean
  /** Why sealing failed, when the document carried one and it did not. */
  identity_error: string | null
  /**
   * Why the draft has no private key.
   *
   * An invitation carries none, by design: the operator never held it. When
   * no local profile holds the admitted half either, the draft is still
   * shown — with this explanation — rather than refused.
   */
  private_key_missing: string | null
}

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
  /**
   * Authenticated negotiation played before WireGuard is mounted.
   *
   * `null` = legacy path: a classic tunnel first, then a PQ PSK over the
   * internal API. That path leaves the **first** handshake unprotected.
   */
  key_negotiation: KeyNegotiationSettings | null
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
  /**
   * Fault of the key-negotiation block as a whole.
   *
   * One message rather than one per sub-field: what makes the block wrong is
   * almost always a relation — a mode under the floor, a PSK contradicting
   * the mode, a certificate pinned to another gateway.
   */
  key_negotiation: string | null
}

/**
 * What occupies the `PresharedKey` slot of the current tunnel — mirror of
 * `orion_core::events::PskKind`.
 *
 * A PSK is not a PQC PSK: both live in the same WireGuard slot, but one was
 * copied by hand and never rotates, the other comes from an ML-KEM-1024
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
