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
 * The order is monotonic — `static_psk < ml_kem` — and it is the whole
 * point: a profile carries a floor it can rise above but never fall below.
 * A plain WireGuard profile has no negotiation block, hence no mode at all.
 */
export type ProtectionMode = 'static_psk' | 'ml_kem'

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
  | 'previous_identity_expired'
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
 *
 * The two recovery steps are the §7.5 path, where the active leaf has already
 * expired. They are separate variants and not a flag on the others, because
 * nothing about them can be done here: no manifest to read, no ceremony to
 * run, no companion to launch. Every step the shell can send is named — one it
 * does not know is one the surface renders as nothing at all, which is
 * indistinguishable from a press that did nothing.
 */
export type RenewalProgress =
  | { step: 'awaiting_operator'; operation_id: string; companion_command: string }
  | { step: 'issuing'; operation_id: string }
  | { step: 'committed'; generation: number }
  | { step: 'recovery_awaiting_operator'; operation_id: string; operator_command: string }
  | { step: 'recovered'; generation: number; activation_at: number }
  | { step: 'rolled_back'; generation: number; available_until: number }

/**
 * What one press produced, per profile.
 *
 * A map and not a single step, because one of the four actions is
 * device-wide: returning the progress of the profile the press started from
 * would attribute every other renewal to it, and hide the approval each of
 * them is waiting for. `refused` is only ever filled by that action — a
 * single-profile press rejects instead.
 */
export interface ActionOutcome {
  progress: Record<string, RenewalProgress>
  refused: Record<string, string>
}

/**
 * What the operator is shown **before** being asked to touch their key.
 *
 * Every field comes from a request verified against what the profile pins, not
 * from the answer's own claims: showing a generation or a peer that nothing
 * vouches for is how a ceremony gets spent on a lie.
 */
export interface ApprovalManifest {
  operation_id: string
  client_wg_public_key: string
  active_generation: number
  requested_generation: number
  /** SHA-256 of the rotation request this approval is bound to. */
  request_fingerprint: string
  expires_at: number
  /** How many of the domain's credentials may answer this request. */
  eligible_credentials: number
}

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
  previous_identity: {
    available_from: number
    available_until: number
    phase: 'not_yet_available' | 'available' | 'expired'
    selected: boolean
  } | null
  /** Public projection of the locally verified operator registry. */
  operator_credentials: {
    registry_epoch: number
    detail: 'epoch_only' | 'verified'
    credentials: Array<{
      fingerprint: string
      state: 'active' | 'lost' | 'revoked'
      credential_epoch: number
      created_at: number
    }>
  } | null
}

/**
 * Result of importing a document — mirror of the shell's `ImportOutcome`.
 */
export interface ImportOutcome {
  profile: ClientProfile
  /**
   * A signed v5 document completed the pending enrollment it answers, and the
   * identity it yields is sealed.
   */
  identity_sealed: boolean
  /**
   * Why the draft has no private key: a classic invitation no local key
   * completes, or a signed document no pending enrollment of this machine
   * answers. The draft is still shown — with this explanation.
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
export type ProfileKind = 'classic' | 'helios_key_negotiation'

export interface ClientProfile {
  name: string
  /**
   * Which of the two profile shapes this is (spec §19).
   *
   * Resolved by the core, never absent: a profile stored before the
   * discriminant existed still has a kind, and the screen shows what the
   * connection path acts on rather than what the file happens to record.
   */
  profile_type: ProfileKind
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
  /**
   * IPv6 VIP assigned by a gateway that has an IPv6 tunnel prefix, one `/128`
   * host (`fd3c:91a2:7e04::2/128`). `null` = IPv4-only tunnel, which is every
   * profile of a gateway without IPv6.
   */
  address_v6: string | null
  /** Traffic routed into the tunnel. Defaults to `0.0.0.0/0, ::/0`. */
  allowed_ips: string
  /**
   * The stored list captures all of IPv4 and lets IPv6 out — the full
   * tunnel as it was before `::/0` joined the default.
   *
   * Decided by `orion-core` (`ClientProfile::ipv6_uncaptured_full_tunnel`)
   * for the **stored** list. The profile editor judges the list being typed
   * with `splitTunnel.leavesIpv6Uncaptured`, which mirrors the same rule.
   */
  ipv6_uncaptured_full_tunnel: boolean
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
  /**
   * Why the vault could not be opened at start-up, when it could not. An empty
   * list says nothing about its cause: after a failed migration, this is the
   * message that says the legacy vault was kept, and why.
   */
  vault_error?: string | null
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
  address_v6: string | null
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
  /** Also judged against `address`: an IPv6 address accompanies an IPv4 one. */
  address_v6: string | null
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

/**
 * What the mounted adapter really captures — mirror of
 * `orion_core::events::CaptureCheck`.
 *
 * The profile states what was asked; the driver may apply less without
 * failing (on Windows, a family the adapter does not carry is dropped). Only
 * the core's read-back knows, and only the real backend sends it: no verdict
 * means nothing was verified, never that everything was.
 */
export type CaptureCheck =
  | { status: 'complete' }
  | {
      status: 'incomplete'
      /** `AllowedIPs` the adapter does not capture. */
      missing: string[]
      /**
       * Profile addresses the driver did not put on the adapter — on Windows,
       * the IPv6 address of an adapter without IPv6. At least one of the two
       * lists is non-empty.
       */
      missing_addresses: string[]
    }
  | { status: 'unverified'; reason: string }

// Events pushed by the Rust backend (emit "helios://event").
export type ClientEvent =
  | { type: 'state_changed'; state: TunnelState }
  | { type: 'protection'; psk: PskKind }
  | { type: 'capture'; capture: CaptureCheck }
  | { type: 'renewal'; in_flight: boolean }
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

/** Paths and existing Astra campaign chosen by the operator for a CA-TLS rotation. */
export interface AstraRotationInput {
  vault_path: string
  heliosd_url: string
  operation_id: string
  output_path: string
}

/** One observable boundary of the two-key CA-TLS ceremony. */
export type AstraRotationPhase =
  | 'idle'
  | 'starting'
  | 'awaiting_first_key'
  | 'processing_first_key'
  | 'awaiting_second_key'
  | 'processing_second_key'
  | 'finalizing'
  | 'prepared'
  | 'deposited'
  | 'awaiting_promotion_key'
  | 'promoting'
  | 'promoted'
  | 'failed'
  | 'cancelled'

/** Verified campaign fields displayed before either credential is exercised. */
export interface AstraCaTlsRotationManifest {
  reason: string
  requested_by: string
  fingerprint: string
  current_ca_tls_epoch: number
  next_ca_tls_epoch: number
  activation_at: number
  not_after: number
  outgoing_anchor_fingerprint: string
  affected_ca: 'client_tls'
  target_count: number
}

/**
 * State returned by the Rust-owned signer session.
 *
 * Labels identify the credentials that actually answered; the WebView never
 * discovers security keys or handles their PINs itself.
 */
export interface AstraRotationStatus {
  phase: AstraRotationPhase
  message: string
  can_continue: boolean
  can_cancel: boolean
  manifest?: AstraCaTlsRotationManifest | null
  first_key_label?: string | null
  second_key_label?: string | null
  output_path?: string | null
  next_ca_tls_epoch?: number | null
  activation_at?: number | null
  not_after?: number | null
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

/* ─────────────────────────── Cérémonies opérateur ───────────────────────────
 *
 * Protocole 2. Deux machines d'état et non une : une récupération est tenue par
 * deux parties à la fois — Orion détient les clés privées clientes et signe le
 * commit, le processus opérateur détient le coffre et signe le grant. « Attente
 * de la clé » et « mis en scène chez la gateway » sont deux coordonnées, pas
 * deux points d'une ligne.
 *
 * Les manifestes sont typés par opération. Une liste libre `label/valeur`
 * laisserait omettre une génération ou reformuler une opération dangereuse sans
 * que rien ici puisse s'en apercevoir, et §12.2 demande que ce qui est signé
 * soit ce qui a été montré. Les mots affichés sont choisis **ici**, jamais
 * transportés depuis le processus opérateur ou le réseau.
 */

export type OperationKind =
  | 'recover_identity'
  | 'approve_campaign'
  | 'authorize_issuer'
  | 'rotate_client_tls_ca'
  | 'rotate_anchor'
  | 'revoke_certificate'
  | 'verify_key'
  | 'invite_enrollment'
  | 'accept_enrollment'

/** Ce que le WebView a le droit de nommer : un genre, au plus un identifiant. */
export interface OperationLocator {
  kind: OperationKind
  operation_id?: string
}

export type OperatorAction = 'continue' | 'cancel'

/** Où en est la cérémonie **chez l'autorité**. */
export type RemoteState =
  | 'local'
  | 'awaiting_operator'
  | 'prepared'
  | 'deposited'
  | 'staged'
  | 'pending_grant'
  | 'granted'
  | 'committed'
  | { activation_deferred: { activation_at: number } }
  | 'refused'

export type KeyPurpose = 'open_vault' | 'approve_campaign' | 'second_approval' | 'promotion'

/** Où en est la cérémonie **sur ce poste**. */
export type GestureState =
  | 'verifying'
  | 'idle'
  | { awaiting_key: { index: number; of: number; purpose: KeyPurpose } }
  | { processing_key: { index: number; of: number } }
  | 'signing'
  | 'done'
  | 'cancelled'
  | 'failed'

export type Refusal =
  | { refusal: 'vault_unavailable' }
  | { refusal: 'key_declined' }
  | { refusal: 'foreground_unavailable' }
  | { refusal: 'key_not_enrolled' }
  | { refusal: 'key_repeated' }
  | { refusal: 'window_expired' }
  | { refusal: 'authority_refused'; status: number }
  | { refusal: 'gateway_unavailable' }
  | { refusal: 'handoff_mismatch' }
  | { refusal: 'manifest_mismatch' }
  | { refusal: 'protocol_violation' }
  | { refusal: 'cancelled' }
  | { refusal: 'internal' }

export interface RecoveryManifest {
  operation: 'recovery'
  trust_domain_id: string
  peer_name: string
  client_wg_public_key: string
  expired_generation: number
  next_generation: number
  expired_since_secs: number
  request_fingerprint: string
  ca_epoch: number
  ca_tls_epoch: number
  activation_at: number
  not_after: number
}

export type AffectedCa = 'ca_pq' | 'ca_tls'

export type CampaignScope =
  | 'orion_profile'
  | 'orion_device'
  | 'fleet_leafs'
  | 'full_certificate_chain'
  | 'trust_authorities'
  | 'emergency_revocation'
  | 'gateway_identity'
  | 'issuer_delegation'
  | 'gateway_bootstrap'

export interface CampaignManifest {
  operation: 'campaign'
  campaign: {
    format_version: number
    campaign_id: string
    trust_domain_id: string
    gateway_wg_public_key: string
    server_name: string
    created_at: number
    expires_at: number
    scope: CampaignScope
    targets: Array<{
      certificate_kind:
        | 'gateway_tls'
        | 'gateway_pq'
        | 'client_tls'
        | 'client_pq'
        | 'ca_pq'
        | 'ca_tls'
        | 'astra_issuer'
        | 'astra_service_key'
      identity_key: string
      epoch: number
      generation: number
      active_tls_certificate_fingerprint: string
      active_pq_certificate_fingerprint: string
    }>
    reason: string
    requested_by: string
    policy_fingerprint: string
    required_credentials: number
  }
  fingerprint: string
}

export interface IssuerManifest {
  operation: 'issuer_authorization'
  trust_domain_id: string
  issuer_epoch: number
  not_before: number
  not_after: number
  allowed_usages: string[]
  policy_fingerprint: string
  request_fingerprint: string
}

export interface CaRotationManifest {
  operation: 'ca_rotation'
  trust_domain_id: string
  affected_ca: AffectedCa
  current_epoch: number
  next_epoch: number
  activation_at: number
  not_after: number
  outgoing_anchor_fingerprint: string
  next_anchor_fingerprint: string
  target_count: number
}

export interface RevocationManifest {
  operation: 'revocation'
  trust_domain_id: string
  target: string
  scope: string
  reason: string
  revocation_epoch: number
  effective_at: number
}

export interface KeyCheckManifest {
  operation: 'key_check'
  vault_fingerprint: string
}

export interface InvitationManifest {
  operation: 'invitation'
  server_name: string
  gateway_wg_public_key: string
  not_after_unix: number
  allow_readmission: boolean
  ca_pq_fingerprint: string
}

export interface AcceptanceManifest {
  operation: 'enrollment_acceptance'
  invitation_id: string
  request_fingerprint: string
  requested_name: string
  client_wg_public_key: string
  leaves_not_after_unix: number
  endpoint: string
}

export type AstraManifest =
  | RecoveryManifest
  | CampaignManifest
  | IssuerManifest
  | CaRotationManifest
  | RevocationManifest
  | KeyCheckManifest
  | InvitationManifest
  | AcceptanceManifest

export interface KeySlotLabel {
  slot: string
  label: string
}

export interface OperatorStatus {
  session_id: string
  /** Strictement croissante. Une commande nomme celle à laquelle elle répond. */
  revision: number
  operation: OperationKind
  operation_id?: string
  remote: RemoteState
  gesture: GestureState
  /** Dérivé côté Rust, et vérifié à l'arrivée : un bouton inventé ici ne sert à rien. */
  allowed: OperatorAction[]
  manifest?: AstraManifest
  keys?: KeySlotLabel[]
  refusal?: Refusal
}

/**
 * Une opération qui attend l'opérateur, telle qu'une liste peut la nommer.
 *
 * Aucun jeton de capacité : ils sont émis pour l'appelant qui va agir, sur
 * l'opération qu'il a nommée. Une liste qui les porterait donnerait à tout
 * lecteur un droit sur toutes les opérations qu'elle contient.
 *
 * Les récupérations en sont **absentes**, et cette absence est leur contrôle
 * d'accès : une récupération est servie sans tunnel — le tunnel est ce qui a
 * expiré — et sa seule revendication est l'identifiant que le client détient.
 * Orion a déjà celui des siennes, puisque c'est lui qui les ouvre.
 */
export interface OperatorPendingOperation {
  operation_id: string
  scope: CampaignScope
  reason: string
  requested_by: string
  target_count: number
  required_credentials: number
  campaign_fingerprint: string
  created_at: number
  expires_at: number
}

/** What the screen shows of an enrollment invitation before it is confirmed. */
export interface InvitationPreview {
  server_name: string
  /** `CA-PQ` fingerprint, hexadecimal in groups of four. */
  ca_fingerprint: string
  expires_at_unix: number
  /** The invitation text, sent back when the request is created. */
  invitation_token: string
}

/** An enrollment request this machine sent and still waits an answer for. */
export interface PendingEnrollment {
  invitation_id: string
  request_id: string
  requested_name: string
  server_name: string
  created_at_unix: number
  invitation_expires_at_unix: number
}

/* Le coffre opérateur lu sans clé : aucun matériel chiffré n'y figure. */
export interface SlotView {
  slot_id: string
  label: string
  role: 'principale' | 'recuperation'
}

export interface DomainView {
  trust_domain_id: string
  rp_id: string
  ca_pq_fingerprint: string
  ca_epoch: number | null
  ca_tls_epoch: number | null
  ca_tls_present: boolean
  server_name: string | null
  gateway_wg_public_key: string | null
}

export interface VaultOverview {
  vault_path: string
  exists: boolean
  vault_fingerprint: string | null
  slots: SlotView[]
  max_slots: number
  domain: DomainView | null
}
