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
  /** Pinned ML-DSA-87 gateway certificate: base64-encoded JSON. */
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
 * Where a certificate stands on the renewal ladder of the spec's §4.3.
 *
 * Computed in Rust from the lifecycle's own `ValidityPeriod` — 80 %, 90 %,
 * 95 % of the lifetime. The screen renders it; it does not derive it.
 */
export type CertificatePhase =
  | 'not_yet_valid'
  | 'valid'
  | 'renewal_due'
  | 'warning'
  | 'critical'
  | 'expired'

/** One certificate, as the shell reports it. */
export interface CertificateFacts {
  subject: string
  issuer: string
  /** SHA-256, lowercase hex — the value read out to compare. */
  fingerprint: string
  not_before: number
  not_after: number
  /** Instant the renewal window opens: 80 % of the lifetime. */
  renewal_at: number
  phase: CertificatePhase
}

/**
 * The four certificates a connection depends on.
 *
 * Two are pinned by the profile, two live in the protected identity store.
 * An absent slot is an absence — no negotiation block, no protected store —
 * while a slot that exists and could not be read appears in `faults`, named.
 */
/** The four actions spec §12.2 requires the Profiles surface to offer. */
export type CertificateAction =
  | 'renew_now'
  | 'renew_every_profile'
  | 'recover_expired'
  | 'rollback_to_previous'

/**
 * Why an action cannot run.
 *
 * Each variant is a **different** thing for the user to do — import an
 * enrolment file, run on a machine with a protected store, wait for a format
 * migration — which is why they are not one flag.
 */
export type CertificateActionBlockKind =
  | 'no_negotiation'
  | 'no_identity_store'
  | 'identity_missing'
  | 'nothing_expired'
  | 'no_previous_identity'
  | 'trust_material_missing'
  | 'companion_transport_missing'
  | 'operator_credential_required'

/** One action and whether it may run, as the shell decides. */
export interface CertificateActionState {
  action: CertificateAction
  /** Fixed in Rust: §12.2 forbids an ambiguous « Renouveler ». */
  label: string
  blocked_by: { kind: CertificateActionBlockKind } | null
  /** The sentence to show, as-is. `null` when the action may run. */
  message: string | null
}

/**
 * Where a renewal stands after one press (spec §8.1.2).
 *
 * `awaiting_operator` is a step and not a failure: it is where every renewal
 * legitimately waits, sometimes for hours, while a human finds their key.
 * `companion_command` is the exact line that approves this operation — a value
 * the operator runs, which is why it is carried rather than described.
 */
export type RenewalProgress =
  | { step: 'awaiting_operator'; operation_id: string; companion_command: string }
  | { step: 'issuing'; operation_id: string }
  | { step: 'committed'; generation: number }

/** Everything the Certificates screen shows for one profile. */
export interface ProfileCertificates {
  name: string
  /** Protected identity the profile names. Empty when it negotiates nothing. */
  identity: string
  /** The profile carries a key-negotiation block. */
  negotiates: boolean
  inventory: CertificateInventory
  actions: CertificateActionState[]
  last_error: string | null
}

export interface CertificateInventory {
  gateway_pq: CertificateFacts | null
  gateway_ca_tls: CertificateFacts | null
  client_tls: CertificateFacts | null
  client_pq: CertificateFacts | null
  faults: string[]
  identity_sealed: boolean
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
  /**
   * What else the document leaves to fill in.
   *
   * A document is allowed to be partial: the operator sends what they know.
   * The import shows it and names the gap rather than refusing the file — the
   * refusal belongs at Connect, not at the file picker.
   */
  incomplete: string | null
  /**
   * What the document said that Orion read and does **not** apply.
   *
   * A wg-quick file routinely carries `DNS`, `MTU` or `Table`. Refusing the
   * file over them made Orion unable to open an ordinary WireGuard
   * configuration; dropping them without a word would hand back a tunnel that
   * differs from the one the file describes.
   */
  notices: string[]
}

/**
 * What the About box states.
 *
 * Four facts, each of which a support exchange has had to ask for: which
 * version is installed, whether it drives a real adapter or the dry-run
 * backend, what a profile file looks like, and where the log is.
 */
export interface About {
  version: string
  /** `wireguard` or `dry-run` — what the shipped client actually mounts. */
  backend: string
  /** Extension of a profile document, without the dot. */
  profile_extension: string
  /** Absolute path of this run's log, when one could be opened. */
  log_path: string | null
}

// A WireGuard peer: identity = Curve25519 public key, reached via a UDP
// endpoint. No CA, no EAP, no cryptographic proposal — WireGuard has only
// one suite.
//
// **No secret in this type, by construction** (ADR-006 §5). The shell's
// `ProfileView` is the mirror of it, and it carries neither the private key nor
// the static PSK: both stay in Rust, sealed in the vault. Anything that reached
// this interface would have been serialised into a Tauri message, parsed into a
// JavaScript `String` nothing can wipe, and held in a DOM node for as long as
// the screen lives.
//
// What the screen actually needs is the **public** half — the one value meant
// to leave the machine — plus a boolean saying whether each secret is present.
export interface ClientProfile {
  name: string
  /** Gateway's UDP endpoint: `IP:port` or `FQDN:port`. */
  endpoint: string
  /** Gateway's Curve25519 public key (base64). */
  peer_public_key: string
  /**
   * Public half of the profile's WireGuard key.
   *
   * `null` while the profile has no key yet. This is what the user hands to
   * the operator to be admitted (ADR-004 §6).
   */
  public_key: string | null
  /** A private key is stored. The screen shows the state, never the value. */
  has_private_key: boolean
  /**
   * A **static** PSK is stored.
   *
   * The PQC PSK from ML-KEM never lands here: it isn't persisted and gets
   * renegotiated on every connection. `false` is therefore the normal case
   * for a Helios profile — see `PskKind`.
   */
  has_static_psk: boolean
  /** CGNAT VIP assigned by the gateway at enrollment (e.g. `100.64.1.2/32`). */
  address: string | null
  /** Traffic routed into the tunnel. Defaults to `0.0.0.0/0`. */
  allowed_ips: string
  /** Keepalive in seconds. Defaults to 25. */
  persistent_keepalive: number
  heliosd_url: string | null
  /**
   * SSH destination inside the tunnel, `user@host`.
   *
   * `null` = this profile offers no terminal. Reachable only once the tunnel
   * is up, and only if the gateway sets `allow_ssh_over_tunnel`.
   */
  ssh_target: string | null
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
 * What the screen sends back on save — mirror of the shell's `ProfileDraft`.
 *
 * Everything the user can edit, and **no secret**. The secret-touching fields
 * are intents rather than values: the interface asks Rust to adopt the key or
 * the PSK it is already holding, it never carries either back.
 *
 * A secret only ever travels *towards* Rust, once, at an explicit gesture —
 * `adoptPrivateKey`, `adoptPresharedKey` — and no path returns one (ADR-006
 * §5). An enrolment document remains the usual way both arrive (ADR-004 §6).
 */
export interface ProfileDraft {
  name: string
  endpoint: string
  peer_public_key: string
  address: string | null
  allowed_ips: string
  persistent_keepalive: number
  heliosd_url: string | null
  /** SSH destination inside the tunnel, `user@host`. `null` = no terminal. */
  ssh_target: string | null
  key_negotiation: KeyNegotiationSettings | null
  /**
   * Adopt the key staged by `generatePrivateKey` or `adoptPrivateKey`.
   *
   * The pair already exists in Rust and its public half is on screen; this
   * only says "keep it". Without it, a save leaves the stored key untouched.
   */
  useStagedKey?: boolean
  /** Drop the stored static PSK. */
  clearPresharedKey?: boolean
  /**
   * Adopt the PSK staged by `adoptPresharedKey`.
   *
   * Same shape as {@link useStagedKey}: the value waits in Rust, this only
   * says "keep it".
   */
  useStagedPsk?: boolean
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
  ssh_target: string | null
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

export type SpeedTestMode = 'tcp' | 'udp' | 'full'

export type SpeedTestPhase =
  | 'preparing'
  | 'latency'
  | 'tcp_download'
  | 'tcp_upload'
  | 'udp_download'
  | 'udp_upload'
  | 'complete'

/** Progress of the direct TCP/UDP measurement. */
export interface SpeedTestProgress {
  phase: SpeedTestPhase
  fraction: number
  current_mbps: number
  bytes: number
  elapsed_ms: number
  message: string
}

/** One raw WireGuard data-path measurement. */
export interface SpeedTestResult {
  latency_ms: number
  jitter_ms: number
  latency_p95_ms: number
  mode: SpeedTestMode
  tcp_download_mbps: number | null
  tcp_upload_mbps: number | null
  udp_download_mbps: number | null
  udp_upload_mbps: number | null
  udp_loss_pct: number | null
  udp_jitter_ms: number | null
  tcp_streams: number
  test_duration_secs: number
  /** Compatibility projections used by older log consumers. */
  download_mbps: number
  upload_mbps: number
  download_variation_pct: number
  upload_variation_pct: number
  duration_ms: number
  download_bytes: number
  upload_bytes: number
  parallel_streams: number
  measurement_rounds: number
}

/**
 * What the vault can honestly claim about itself (ADR-006 §3).
 *
 * Every field is **measured**, never assumed. A guarantee that could not be
 * established is reported as absent rather than defaulted to the reassuring
 * answer — a panel that promised what nothing backs is the failure the ADR
 * names, not a cosmetic one.
 */
export interface VaultPosture {
  /** Installation root bound to a TPM key whose properties were verified. */
  hardwareBacked: boolean
  /**
   * `danger_allow_software_keystore` is on. A **downgrade**, not a recovery:
   * resistance to inter-machine copying and to a domain administrator holding
   * DPAPI backup keys is withdrawn with it.
   */
  softwareKeystore: boolean
  /** Volume-encryption posture of the disk holding the profiles. */
  volume: string
  volumeProtected: boolean
  /** `danger_allow_unencrypted_volume` est posé : un refus devenu un choix. */
  unencryptedVolumeWaived: boolean
  /** Secret pages held out of swap and of the hibernation file. */
  memoryLocked: boolean
  memory: string
  /** Secret pages excluded from Windows Error Reporting dumps. */
  dumpsExcluded: boolean
  dumps: string
  /**
   * Profiles whose key once lived in plaintext. Presumed compromised — sealing
   * the file does not recall the copies already in backups — and unconnectable
   * until a new key is admitted.
   */
  rotationRequired: string[]
  /** A plaintext `profiles.toml` is still present and not yet migrated. */
  legacyPresent: boolean
}
