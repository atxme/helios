//! Client VPN profile: editable in the UI, persisted locally in TOML.
//!
//! **WireGuard** model (ADR-001): a peer is identified by its Curve25519
//! public key and reached via a UDP endpoint. There's no CA, no EAP, no
//! cryptographic proposal to choose — WireGuard only has one suite.
//!
//! Post-quantum protection goes through the `PresharedKey` slot, but it is
//! **not** stored in this file: the PQC PSK is negotiated with ML-KEM-1024 on
//! each connection and is never persisted. What the profile can carry is a
//! *static* PSK entered by hand, which disables this negotiation.
//!
//! The `private_key` / `preshared_key` fields are **secrets**: `Debug` is
//! masked so they don't leak into logs.

use std::fmt;
use std::path::PathBuf;

use aether::key_negotiation::ProtectionMode;
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Default `AllowedIPs`: all traffic goes through the tunnel, in both families.
///
/// It's this capture, combined with the adapter lifecycle invariant (see
/// [`crate::backend`]), that makes WireGuard **drop** packets instead of
/// letting them leak in clear when the session is dead.
///
/// `::/0` is there even though the gateway routes no IPv6 for its peers: what
/// the adapter captures and cannot deliver, WireGuard drops, which is exactly
/// the kill-switch §3 bis of ADR-001 relies on. With `0.0.0.0/0` alone, a
/// dual-stack machine sent all of its IPv6 out of the physical interface, in
/// clear, while the tunnel was up. Spelled in the canonical form of
/// [`crate::profile_import::normalize_cidr_list`], so a fresh profile never
/// reads as modified.
pub const DEFAULT_ALLOWED_IPS: &str = "0.0.0.0/0, ::/0";

/// Enforced keepalive: without traffic, WireGuard doesn't handshake and our
/// state inference would wrongly conclude the tunnel is down (ADR-001 §3).
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// Public settings for the pre-WireGuard key-negotiation service.
///
/// The client certificate and its private key stay in a protected identity
/// store selected by the Orion shell. Only an opaque identity name and the
/// public gateway CA are persisted in the VPN profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyNegotiationSettings {
    pub mode: ProtectionMode,
    /// Persistent local security floor. Helios enforces its own copy, so a
    /// network attacker cannot lower both sides through negotiation.
    #[serde(default)]
    pub minimum_mode: ProtectionMode,
    /// Public UDP endpoint, normally the WireGuard host on port 51821.
    pub endpoint: String,
    /// DNS name authenticated by the gateway certificate.
    pub server_name: String,
    /// DER gateway CA certificate encoded as base64.
    pub gateway_ca_der: String,
    /// Base64-encoded JSON ML-DSA-65 gateway certificate.
    pub gateway_pq_certificate: String,
    /// Opaque lookup name in the shell's protected identity store.
    pub identity: String,
    /// What this client needs to renew its own identity (spec §19).
    ///
    /// Optional, and that is the migration in progress: a document written
    /// before §19 carries none, and such a profile connects exactly as before
    /// while being unable to rotate. `certificate_actions` names that gap
    /// rather than offering a button that would fail at the last step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustMaterial>,
}

/// The trust material a §7 renewal needs, and that a profile used not to hold.
///
/// # Why each field is here
///
/// A renewal has the client sign a rotation request, hand it to Astra's
/// delegated issuer, relay the resulting staging to the gateway and commit the
/// grant it gets back. Each step needs something the profile did not carry:
///
/// - the **request** is bound to a trust domain and to the generation it
///   follows, so `trust_domain_id` and `client_generation`;
/// - reaching the authority needs `astra_authority_url`, and believing what
///   comes back needs the pinned `astra_service_public_key` with its epoch;
/// - verifying the **grant** needs the anchor `ca_pq_public_key` at
///   `ca_epoch`, and the client `CA-TLS` at `ca_tls_epoch` — the new TLS leaf
///   chains to that one, not to the gateway CA the profile already pinned.
///
/// The two fingerprints of the current generation are deliberately **not**
/// here: they are derived from the certificates in the protected store, and a
/// second copy in a file an operator edits is a second thing that can be
/// wrong.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustMaterial {
    /// 32 lowercase hex characters — 16 bytes.
    pub trust_domain_id: String,
    pub ca_epoch: u64,
    /// `CA-PQ`, base64 ML-DSA-87. The anchor, **not** the pinned gateway leaf.
    pub ca_pq_public_key: String,
    pub ca_tls_epoch: u64,
    /// Client TLS anchor, base64 DER.
    pub client_tls_ca_der: String,
    /// Generation this client's current identity is at.
    pub client_generation: u64,
    /// Epoch of the gateway leaf the domain serves, and the highest decision
    /// this profile is told about. Both are `1` on a fresh domain (§13.1).
    ///
    /// They are seeded from here and from nowhere else: an identity transition
    /// only moves a store from the decision it already holds to the next one,
    /// so a store seeded at `0` against a registry at `1` stays behind for
    /// good, and the gateway answers `503` to every trust update it sends.
    ///
    /// `default` for the shape alone — a block emitted before these fields
    /// existed decodes, and [`Self::validate`] then refuses it by name rather
    /// than sealing a profile that cannot ever update its trust.
    #[serde(default)]
    pub active_gateway_identity_epoch: u64,
    #[serde(default)]
    pub gateway_decision_epoch: u64,
    pub astra_authority_url: String,
    /// RP ID of the operator WebAuthn ceremony. It is stable across a TLS
    /// certificate rotation of Astra and is never inferred from a relay URL.
    #[serde(default)]
    pub webauthn_rp_id: String,
    /// Out-of-band policy pin, lowercase SHA-256 hexadecimal.
    #[serde(default)]
    pub astra_policy_fingerprint: String,
    /// Highest CA-PQ-signed credential registry decision this profile saw.
    #[serde(default)]
    pub credential_registry_epoch: u64,
    /// The operator credentials of the domain, as `CA-PQ` signed them.
    ///
    /// Verified under [`Self::ca_pq_public_key`] before anything is done with
    /// them, so the document that carried them proves nothing by itself.
    ///
    /// Absent on a profile emitted before this field existed. That profile
    /// still mounts a tunnel and still renews; what it cannot do is recover an
    /// expired identity, because naming the credential that will approve it is
    /// the first thing §7.5 does.
    #[serde(default)]
    pub astra_credential_bindings: Vec<aether::certificates::approval::AstraCredentialBinding>,
    pub astra_service_key_epoch: u64,
    /// Astra's service key, base64 ML-DSA-87.
    pub astra_service_public_key: String,
}

impl TrustMaterial {
    /// Decodes and checks every field, or names the one that is wrong.
    ///
    /// Called at import and by [`validate_key_negotiation`], so a document
    /// whose trust block is unusable is refused when it arrives rather than at
    /// the first renewal — 80 % into a leaf's life, which is the worst moment
    /// to discover a typo an operator made months earlier.
    ///
    /// The messages are user-facing: they are displayed as-is in Orion.
    pub fn validate(&self) -> Result<()> {
        aether::certificates::encoding::TrustDomainId::parse_hex(self.trust_domain_id.trim())
            .map_err(|_| {
                anyhow::anyhow!(
                    "identifiant de domaine de confiance invalide : 32 caractères hexadécimaux \
                     attendus"
                )
            })?;
        aether::certificates::encoding::MlDsa87PublicKey::parse(self.ca_pq_public_key.trim())
            .map_err(|_| anyhow::anyhow!("clé publique CA-PQ illisible"))?;
        aether::certificates::encoding::MlDsa87PublicKey::parse(
            self.astra_service_public_key.trim(),
        )
        .map_err(|_| anyhow::anyhow!("clé de service Astra illisible"))?;

        let der = base64::engine::general_purpose::STANDARD
            .decode(self.client_tls_ca_der.trim())
            .map_err(|_| anyhow::anyhow!("CA TLS cliente : base64 illisible"))?;
        let certificate = aether::certificates::encoding::DerCertificate::new(der)
            .map_err(|error| anyhow::anyhow!("CA TLS cliente : {error}"))?;
        // A real authority, checked by the same validator the lifecycle uses.
        // A byte string that merely decodes would fail at the first chain
        // verification, on the machine that can least afford it.
        aether::certificates::x509::assert_certificate_authority(&certificate)
            .map_err(|error| anyhow::anyhow!("CA TLS cliente : {error}"))?;

        let authority = url::Url::parse(self.astra_authority_url.trim())
            .map_err(|_| anyhow::anyhow!("l'URL de l'autorité Astra est illisible"))?;
        if authority.scheme() != "https" || authority.host_str().is_none() {
            anyhow::bail!("l'URL de l'autorité Astra doit être une origine https://");
        }
        aether::certificates::encoding::validate_server_name(self.webauthn_rp_id.trim())
            .map_err(|_| anyhow::anyhow!("RP ID WebAuthn Astra invalide"))?;
        let host = authority.host_str().expect("checked above");
        let rp_id = self.webauthn_rp_id.trim();
        if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
            anyhow::bail!("le RP ID WebAuthn Astra ne gouverne pas l'origine de l'autorité");
        }
        let policy = aether::certificates::encoding::Fingerprint::parse_hex(
            self.astra_policy_fingerprint.trim(),
        )
        .map_err(|_| anyhow::anyhow!("empreinte de politique Astra illisible"))?;
        aether::certificates::AstraPolicyPin::new(policy)
            .map_err(|_| anyhow::anyhow!("empreinte de politique Astra absente"))?;
        if self.ca_epoch == 0
            || self.ca_tls_epoch == 0
            || self.client_generation == 0
            || self.astra_service_key_epoch == 0
            || self.credential_registry_epoch == 0
        {
            anyhow::bail!("les compteurs d'autorité commencent à 1");
        }
        // Named apart from the counters above because the remedy is different.
        // A block printed before these two fields existed carries them as
        // zero, and the profile made from it is refused a trust update for
        // good — a 503 on every poll, which no renewal repairs. What fixes it
        // is reprinting the block, so the message says exactly that.
        if self.active_gateway_identity_epoch == 0 || self.gateway_decision_epoch == 0 {
            anyhow::bail!(
                "bloc de confiance trop ancien : il ne porte pas les époques d'identité de la \
                 gateway. Le réimprimer avec `heliosd show-trust-enrolment --public-key <clé>`"
            );
        }
        Ok(())
    }

    /// The trust domain identifier, decoded.
    pub fn trust_domain(&self) -> Result<aether::certificates::encoding::TrustDomainId> {
        aether::certificates::encoding::TrustDomainId::parse_hex(self.trust_domain_id.trim())
            .map_err(|_| anyhow::anyhow!("identifiant de domaine de confiance invalide"))
    }

    /// `CA-PQ`, decoded.
    pub fn ca_pq(&self) -> Result<aether::certificates::encoding::MlDsa87PublicKey> {
        aether::certificates::encoding::MlDsa87PublicKey::parse(self.ca_pq_public_key.trim())
            .map_err(|_| anyhow::anyhow!("clé publique CA-PQ illisible"))
    }

    /// The client TLS anchor, decoded.
    pub fn client_tls_ca(&self) -> Result<aether::certificates::encoding::DerCertificate> {
        let der = base64::engine::general_purpose::STANDARD
            .decode(self.client_tls_ca_der.trim())
            .map_err(|_| anyhow::anyhow!("CA TLS cliente : base64 illisible"))?;
        aether::certificates::encoding::DerCertificate::new(der)
            .map_err(|error| anyhow::anyhow!("CA TLS cliente : {error}"))
    }

    pub fn astra_policy_pin(&self) -> Result<aether::certificates::AstraPolicyPin> {
        let fingerprint = aether::certificates::encoding::Fingerprint::parse_hex(
            self.astra_policy_fingerprint.trim(),
        )
        .map_err(|_| anyhow::anyhow!("empreinte de politique Astra illisible"))?;
        aether::certificates::AstraPolicyPin::new(fingerprint)
            .map_err(|error| anyhow::anyhow!("empreinte de politique Astra : {error}"))
    }
}

impl KeyNegotiationSettings {
    /// Decodes the pinned gateway PQ certificate.
    pub fn gateway_pq_certificate(&self) -> Result<aether::key_negotiation::PqCertificate> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.gateway_pq_certificate.trim())
            .context("décodage du certificat PQ de la gateway")?;
        serde_json::from_slice(&raw).context("lecture du certificat PQ de la gateway")
    }

    /// SHA-256 fingerprint of the pinned gateway PQ certificate.
    ///
    /// It is the value `heliosd init-key-negotiation` prints on the gateway:
    /// showing it in Orion lets the user read out loud what their client
    /// pinned instead of trusting that the imported file is the right one.
    /// `None` as long as the certificate is unreadable — the fault is then
    /// reported by [`validate_key_negotiation`], not disguised as a hash.
    pub fn gateway_pq_fingerprint(&self) -> Option<String> {
        self.gateway_pq_certificate().ok()?.fingerprint().ok()
    }
}

/// Validates a key-negotiation block against the profile carrying it.
///
/// Shared by [`ClientProfile::validate`], profile import and
/// [`crate::inspect_profile`]: three rule sets for the same block would
/// eventually diverge, and a screen would accept what the connection refuses.
///
/// The messages are user-facing — they are displayed as-is in Orion.
pub fn validate_key_negotiation(
    settings: &KeyNegotiationSettings,
    peer_public_key: &str,
    has_preshared_key: bool,
) -> Result<()> {
    if settings.endpoint.trim().is_empty()
        || settings.server_name.trim().is_empty()
        || settings.gateway_ca_der.trim().is_empty()
        || settings.gateway_pq_certificate.trim().is_empty()
        || settings.identity.trim().is_empty()
    {
        anyhow::bail!(
            "négociation de clé incomplète : endpoint, nom de serveur, CA, certificat PQ et identité protégée sont tous requis"
        );
    }
    if !settings.mode.satisfies(settings.minimum_mode) {
        anyhow::bail!(
            "le mode {} est sous le plancher {} : la négociation ne redescend jamais",
            mode_label(settings.mode),
            mode_label(settings.minimum_mode)
        );
    }
    let authority = base64::engine::general_purpose::STANDARD
        .decode(settings.gateway_ca_der.trim())
        .context("la CA de la gateway n'est pas encodée en base64")?;
    if authority.is_empty() {
        anyhow::bail!("la CA de la gateway est vide");
    }

    let certificate = settings.gateway_pq_certificate()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("l'horloge système précède l'époque Unix")?
        .as_secs();
    verify_pinned_gateway_certificate(
        &certificate,
        &settings.server_name,
        peer_public_key,
        settings.trust.as_ref(),
        now,
    )?;

    match (settings.mode, has_preshared_key) {
        (ProtectionMode::StaticPsk, false) => {
            anyhow::bail!("le mode PSK statique exige un PSK dans le profil")
        }
        (ProtectionMode::Classic | ProtectionMode::MlKem, true) => {
            anyhow::bail!("un PSK de profil n'est valable qu'avec le mode PSK statique")
        }
        _ => Ok(()),
    }
}

/// Verifies the pinned gateway leaf under the authority that actually issued it.
///
/// Two shapes exist, and a profile is only ever right about one of them. A
/// gateway with no trust domain serves a self-signed leaf: the pinned bytes
/// *are* the trust, and there is no anchor to check them against. Once
/// `heliosd init-trust-domain` installs the CA-PQ bootstrap leaf (ADR-008
/// §13.1) the same gateway serves a leaf signed by `CA-PQ`, and the anchor
/// that verifies it is the one the trust block carries.
///
/// The choice is made on `issuer == subject`, not on the presence of a trust
/// block, so the two cases can never swap silently: a CA-issued leaf in a
/// profile that carries no anchor is refused by name rather than accepted on
/// its own signature — which is what `verify_self_signed` would do if the
/// leaf ever carried the issuer's key.
pub fn verify_pinned_gateway_certificate(
    certificate: &aether::key_negotiation::PqCertificate,
    server_name: &str,
    peer_public_key: &str,
    trust: Option<&TrustMaterial>,
    now_unix: u64,
) -> Result<()> {
    let role = aether::key_negotiation::PqCertificateRole::Gateway;
    let subject = Some(server_name.trim());
    if certificate.issuer == certificate.subject {
        return certificate
            .verify_self_signed(role, subject, peer_public_key, now_unix)
            .context("le certificat PQ épinglé ne correspond pas à cette gateway");
    }
    let trust = trust.ok_or_else(|| {
        anyhow::anyhow!(
            "le certificat PQ épinglé est émis par l'autorité « {} », que ce profil ne porte \
             pas : réimporter un profil produit après l'amorçage du domaine de confiance",
            certificate.issuer.trim()
        )
    })?;
    let anchor =
        aether::certificates::encoding::MlDsa87PublicKey::parse(trust.ca_pq_public_key.trim())
            .map_err(|_| anyhow::anyhow!("clé publique CA-PQ illisible"))?;
    certificate
        .verify(anchor.as_bytes(), role, subject, peer_public_key, now_unix)
        .context("le certificat PQ épinglé n'est pas émis par le CA-PQ de ce domaine")
}

/// Name of a mode as the user reads it on screen.
fn mode_label(mode: ProtectionMode) -> &'static str {
    match mode {
        ProtectionMode::Classic => "classique",
        ProtectionMode::StaticPsk => "PSK statique",
        ProtectionMode::MlKem => "ML-KEM-1024",
    }
}

/// What kind of profile this is (spec §19, §22).
///
/// # Why an explicit discriminant, when the block already says it
///
/// It used to be inferred: a `key_negotiation` block meant a Helios profile,
/// its absence meant classic. Inference reads a **presence** as an
/// **intention**, and the two come apart in the direction that matters — a
/// profile whose negotiation block was dropped by an edit, a conversion or a
/// partial import arrives looking exactly like a deliberate classic profile.
/// Orion would then mount a tunnel with no pre-WireGuard authentication and
/// report nothing, because from its side nothing was wrong. A silent downgrade
/// of the protection level is the one outcome this client may not produce.
///
/// So the profile says which it is, and the two shapes are **exclusive**: a
/// `helios_key_negotiation` profile without a block, or a `classic` profile
/// carrying one, is refused rather than cleaned up. Guessing which half of a
/// contradiction to keep is choosing a protection level in the operator's
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// A plain WireGuard peer. No negotiation block, and none expected.
    Classic,
    /// A Helios profile: the negotiation block is mandatory.
    HeliosKeyNegotiation,
}

impl ProfileKind {
    /// Name of the kind as it is written in a document and read on screen.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::HeliosKeyNegotiation => "helios_key_negotiation",
        }
    }
}

/// A complete VPN profile, as edited by the user in the UI.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// Unique friendly name (selection key in the list).
    pub name: String,
    /// Gateway's UDP endpoint: `IP:port` or `FQDN:port`. **Not** an HTTP URL.
    ///
    /// `default` like almost every field below: a document is allowed to carry
    /// only part of a profile. An operator hands out what they know — often an
    /// invitation with no private key, sometimes a block without an endpoint
    /// yet — and refusing to *parse* it would leave the user with a rejection
    /// instead of a form they can finish. [`Self::validate`] is what decides
    /// whether a profile may mount a tunnel; parsing only decides whether the
    /// document is intelligible. Only `name` stays required, because it is the
    /// key the profile is stored under.
    #[serde(default)]
    pub endpoint: String,
    /// Client's Curve25519 private key (base64). **Secret.**
    #[serde(default)]
    pub private_key: String,
    /// Gateway's Curve25519 public key (base64) — the peer's identity.
    #[serde(default)]
    pub peer_public_key: String,
    /// **Static** PSK shared out of band (base64). **Secret.**
    ///
    /// If set, it is sovereign: the core no longer negotiates anything and
    /// sets this secret as is. The PQC PSK from the ML-KEM exchange never
    /// lands here — it isn't persisted, it's renegotiated on each connection.
    /// `None` is therefore the *normal* case for a Helios profile, not a gap.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Virtual address assigned by the gateway (CGNAT, e.g. `100.64.1.2/32`).
    /// Derived on the gateway side by `helios-provisioning`, received on enrollment.
    #[serde(default)]
    pub address: Option<String>,
    /// IPv6 VIP assigned by the gateway, one host written `…/128`
    /// (`ADRESSAGE-IPV6.md` §2.3), when the gateway has an IPv6 tunnel prefix.
    ///
    /// Optional on every path, and absent means exactly what it meant before
    /// the field existed: an IPv4-only adapter. Never written when absent, so a
    /// profile without it serializes as it always did (§8). It accompanies
    /// [`Self::address`], never replaces it: the control plane stays IPv4
    /// (§2.6), so a tunnel without its IPv4 address is not a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_v6: Option<String>,
    /// Traffic routed into the tunnel. Defaults to [`DEFAULT_ALLOWED_IPS`].
    ///
    /// One or more CIDR prefixes, comma-separated — the `wg-quick` spelling of
    /// `AllowedIPs`, which is WireGuard's cryptographic routing table. A split
    /// tunnel usually needs several: the VPN network *and* the remote LAN have
    /// no common supernet short of `0.0.0.0/0`, so a single prefix forced a
    /// choice between them.
    ///
    /// Stored normalized (`a/n, b/m`) by
    /// [`crate::profile_import::normalize_cidr_list`]: the screen, the sealed
    /// profile and the peer built from it have to agree character for
    /// character, or a reloaded profile reads as modified.
    ///
    /// A stored value is never widened behind the user's back, including the
    /// `0.0.0.0/0` every profile carried before [`DEFAULT_ALLOWED_IPS`]
    /// captured IPv6 too: [`ClientProfile::ipv6_uncaptured_full_tunnel`]
    /// names that case so the screen can warn, and the user decides.
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    /// Keepalive in seconds. Defaults to [`DEFAULT_KEEPALIVE_SECS`].
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
    /// Internal heliosd API URL, reachable **only once the tunnel is
    /// mounted** (e.g. `http://100.64.0.1:8080`). `None` = no enriched telemetry.
    #[serde(default)]
    pub heliosd_url: Option<String>,
    /// SSH destination inside the tunnel, as `user@host` or `host`.
    ///
    /// Reachable only once the tunnel is up, and only if the gateway sets
    /// `allow_ssh_over_tunnel`. `None` = the client offers no terminal.
    ///
    /// # Why a whole field for what looks like a shortcut
    ///
    /// This value is handed to a **process launcher**. It is the one string in
    /// a profile that becomes part of a command line, so it is the one string
    /// an attacker would want to control — a profile document arrives from
    /// outside, and `orion-core` is what decides whether its contents are
    /// allowed to mean anything. Hence a named field with its own grammar
    /// ([`crate::profile_import::validate_ssh_target`]) rather than a value
    /// parsed out of `heliosd_url` at launch time, where no validation would
    /// have a natural home.
    #[serde(default)]
    pub ssh_target: Option<String>,
    /// Which of the two profile shapes this is (spec §19, §22).
    ///
    /// `None` only for a profile that predates the discriminant — a sealed
    /// manifest below v5, or a document written before §19. Every path that
    /// **produces** a profile stamps it, so the absent case is a migration
    /// state and not a third kind. Read it through [`ClientProfile::kind`],
    /// never directly: that is where the legacy inference lives, once, with
    /// its reason.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub profile_type: Option<ProfileKind>,
    /// Authenticated public negotiation performed before WireGuard is mounted.
    #[serde(default)]
    pub key_negotiation: Option<KeyNegotiationSettings>,
    /// The `preshared_key` above holds a **negotiated** secret, not a static
    /// one.
    ///
    /// Never persisted, and that is the whole point: a profile read back from
    /// disk carrying a PSK necessarily carries a static one. The flag is set
    /// only by the core, on the ephemeral copy it hands to the backend once
    /// ML-KEM has produced a key.
    ///
    /// Without it, that copy contradicted its own settings — a PSK plus a
    /// non-static mode — and [`ClientProfile::validate`], called by every
    /// `up()`, refused the very tunnel the negotiation had just succeeded in
    /// preparing. The negotiation could never commit.
    #[serde(skip)]
    pub preshared_key_is_negotiated: bool,
}

fn default_allowed_ips() -> String {
    DEFAULT_ALLOWED_IPS.to_string()
}

fn default_keepalive() -> u16 {
    DEFAULT_KEEPALIVE_SECS
}

/// Masked `Debug`: never let the private key or PSK leak into logs.
impl fmt::Debug for ClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientProfile")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("private_key", &"***")
            .field("peer_public_key", &self.peer_public_key)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "***"))
            .field("address", &self.address)
            .field("address_v6", &self.address_v6)
            .field("allowed_ips", &self.allowed_ips)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("heliosd_url", &self.heliosd_url)
            .field("ssh_target", &self.ssh_target)
            .field("profile_type", &self.profile_type)
            .field("key_negotiation", &self.key_negotiation)
            .finish()
    }
}

impl ClientProfile {
    /// Is the profile usable to mount a tunnel?
    ///
    /// An incomplete profile must not be presented as connectable: we fail
    /// **before** touching the network rather than mounting an adapter that
    /// will never handshake.
    /// The kind this profile is, declared or — for a legacy profile — inferred.
    ///
    /// The inference is the historical rule, kept in exactly one place instead
    /// of at every call site: a profile sealed before manifest v5 carries no
    /// discriminant, and the presence of the block is the only thing left to
    /// go on. It is resolved once, and [`crate::vault::store::ProfileStore`]
    /// writes the answer back at the next save — so the guess is made about a
    /// file, never about a decision.
    pub fn kind(&self) -> ProfileKind {
        self.profile_type.unwrap_or({
            if self.key_negotiation.is_some() {
                ProfileKind::HeliosKeyNegotiation
            } else {
                ProfileKind::Classic
            }
        })
    }

    /// Does this profile negotiate before WireGuard?
    ///
    /// The single question the connection path asks. It reads the
    /// discriminant, not the presence of the block: a Helios profile that lost
    /// its block must fail loudly at [`Self::validate`], never quietly mount a
    /// classic tunnel.
    pub fn negotiates(&self) -> bool {
        self.kind() == ProfileKind::HeliosKeyNegotiation
    }

    /// Checks the two shapes of spec §19 against each other.
    ///
    /// Separate from [`Self::validate`] because it answers a different
    /// question, at a different moment. `validate` asks whether a profile can
    /// mount a tunnel, and a half-filled draft legitimately cannot. This asks
    /// whether the profile **contradicts itself**, which a draft never has the
    /// right to do — so it can be applied when a profile is stored, long
    /// before it is complete.
    pub fn check_kind(&self) -> Result<()> {
        // The contradiction is refused rather than resolved. Either half could
        // be the true one, and the wrong guess mounts a tunnel with no
        // pre-WireGuard authentication while the screen still says «Helios».
        match (self.profile_type, self.key_negotiation.is_some()) {
            (Some(ProfileKind::HeliosKeyNegotiation), false) => anyhow::bail!(
                "ce profil se déclare « helios_key_negotiation » mais ne porte pas de bloc de \
                 négociation : il monterait un tunnel sans authentification avant WireGuard. \
                 Réimporter le document d'enrôlement."
            ),
            (Some(ProfileKind::Classic), true) => anyhow::bail!(
                "ce profil se déclare « classic » mais porte un bloc de négociation : l'un des \
                 deux est faux, et deviner lequel reviendrait à choisir un niveau de protection \
                 à la place de l'opérateur"
            ),
            _ => {}
        }
        Ok(())
    }

    /// Refuses changing the security variant of an existing stable profile.
    ///
    /// A classic and a Helios profile may target the same endpoint, but they
    /// must have distinct stable identifiers (spec §14, §19). Reusing the
    /// existing profile would erase the fact that it has carried Helios trust
    /// material; after that, losing the negotiation block would once again
    /// look exactly like an intentional classic profile.
    pub fn check_replacement_of(&self, known: &Self) -> Result<()> {
        self.check_kind()?;
        known.check_kind()?;
        if self.kind() != known.kind() {
            anyhow::bail!(
                "le type du profil « {} » est immuable : il est enregistré comme « {} » mais \
                 le remplacement propose « {} ». Créer un nouveau profil sous un autre nom \
                 pour obtenir un identifiant distinct.",
                known.name,
                known.kind().as_str(),
                self.kind().as_str(),
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.check_kind()?;
        if self.endpoint.trim().is_empty() {
            anyhow::bail!("l'endpoint de la gateway (IP/FQDN:port) est requis");
        }
        if self.private_key.trim().is_empty() {
            anyhow::bail!("la clé privée du client est requise (enrôlement non effectué ?)");
        }
        if self.peer_public_key.trim().is_empty() {
            anyhow::bail!("la clé publique de la gateway est requise");
        }
        if let Some(settings) = &self.key_negotiation {
            // Only a **static** PSK contradicts a negotiating mode. The one
            // ML-KEM just produced is the expected outcome of that very mode,
            // and judging it by the same rule refused every commit.
            validate_key_negotiation(settings, &self.peer_public_key, self.has_static_psk())?;
        }
        Ok(())
    }

    /// Validates a profile **about to be installed on the data plane**.
    ///
    /// # The gap this closes
    ///
    /// [`Self::validate`] runs on the profile as the user edits and stores it,
    /// where an ML-KEM profile legitimately holds **no** PSK: the PSK does not
    /// exist yet, it is what the negotiation produces. That leniency is right
    /// there and wrong here — applied unchanged at mount time it accepts a
    /// profile whose mode announces ML-KEM while the `PresharedKey` slot is
    /// empty. WireGuard would then come up on the static key pair alone, a
    /// perfectly functional tunnel with none of the post-quantum protection
    /// the screen claims and the floor promised. Nothing downstream would say
    /// so: the handshake succeeds, the state goes `Up`, and the only trace is
    /// a `PskKind` nobody cross-checks.
    ///
    /// So the data plane asks a stricter question: *is the secret that mode
    /// requires actually here*. In ML-KEM mode the answer must be a PSK
    /// carrying [`Self::preshared_key_is_negotiated`] — a static one is not
    /// interchangeable, it is the operator's out-of-band value and would mean
    /// the negotiation never happened.
    ///
    /// The client's WireGuard private key is required either way and is not
    /// what this arbitrates: WireGuard's handshake needs it in every mode. The
    /// negotiated PSK is mixed **in addition** to it, and this is what refuses
    /// to mount when that addition is missing.
    pub fn validate_for_data_plane(&self) -> Result<()> {
        self.validate()?;
        let Some(settings) = &self.key_negotiation else {
            return Ok(());
        };
        if settings.mode != ProtectionMode::MlKem {
            return Ok(());
        }
        if !self.has_preshared_key() {
            anyhow::bail!(
                "mode ML-KEM sans PSK négocié : monter le tunnel maintenant l'établirait sur la \
                 seule paire de clés statique, sans la protection post-quantique annoncée. \
                 La négociation doit aboutir avant la pose."
            );
        }
        if !self.preshared_key_is_negotiated {
            anyhow::bail!(
                "mode ML-KEM avec un PSK statique : un PSK partagé hors bande n'est pas le \
                 secret que la négociation produit, et ne peut pas en tenir lieu"
            );
        }
        Ok(())
    }

    /// Does the profile carry a PSK **shared out of band**?
    ///
    /// The distinction [`Self::has_preshared_key`] cannot make: same slot,
    /// opposite meanings. A static PSK excludes the negotiation; a negotiated
    /// one is its result.
    pub fn has_static_psk(&self) -> bool {
        self.has_preshared_key() && !self.preshared_key_is_negotiated
    }

    /// Does this profile route all IPv4 into the tunnel and let IPv6 out?
    ///
    /// The shape of every full tunnel stored before [`DEFAULT_ALLOWED_IPS`]
    /// captured `::/0`: on a dual-stack machine its IPv6 leaves in clear
    /// while the tunnel is up. Such a profile is **reported, never rewritten**
    /// — widening a stored routing table is a decision for the user, taken in
    /// the editor, not a migration run on load. The rule lives in
    /// [`crate::profile_import::tunnel_capture`], once, so the screen and
    /// `helios-ctl` cannot disagree about which profiles it names.
    pub fn ipv6_uncaptured_full_tunnel(&self) -> bool {
        crate::profile_import::tunnel_capture(&self.allowed_ips)
            == crate::profile_import::TunnelCapture::Ipv4Only
    }

    /// Public key corresponding to the profile's private key.
    ///
    /// It's the only half of the pair meant to leave the machine: the user
    /// communicates it to the operator to be admitted on the gateway
    /// (ADR-004 §6). `None` if the profile has no private key yet, or if it
    /// is unreadable.
    pub fn public_key(&self) -> Option<String> {
        aether::wg::public_from_private(&self.private_key).ok()
    }

    /// Is the `PresharedKey` slot set in this profile?
    ///
    /// **Says nothing about the secret's origin**, and can't say anything: a
    /// PQC PSK derived from ML-KEM is never persisted, it only exists in the
    /// ephemeral profile the core passes to the backend when setting it. A
    /// `true` read from the *saved* profile therefore always denotes a static
    /// PSK. To distinguish the two in the UI, it's
    /// [`crate::events::PskKind`] that is authoritative, not this predicate.
    pub fn has_preshared_key(&self) -> bool {
        self.preshared_key
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty())
    }
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            name: "nouveau".to_string(),
            endpoint: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            address: None,
            address_v6: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: DEFAULT_KEEPALIVE_SECS,
            heliosd_url: None,
            // Left undeclared while the user is still filling the form: a new
            // profile that started as classic and receives a negotiation block
            // must not have to fight its own discriminant. It is stamped when
            // the profile is persisted, which is the moment it becomes a fact
            // rather than a draft.
            profile_type: None,
            ssh_target: None,
            key_negotiation: None,
            preshared_key_is_negotiated: false,
        }
    }
}

/// Persisted client configuration: set of profiles + current selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    #[serde(default)]
    pub profiles: Vec<ClientProfile>,
    /// Name of the currently selected profile.
    #[serde(default)]
    pub selected: Option<String>,
}

impl ClientConfig {
    /// Path to the config file. Overridden by `ORION_CONFIG` (tests/dev),
    /// otherwise the OS's standard config directory (`directories`).
    pub fn path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("ORION_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dirs = directories::ProjectDirs::from("net", "helios", "orion")
            .context("impossible de déterminer le répertoire de config de l'OS")?;
        Ok(dirs.config_dir().join("profiles.toml"))
    }

    /// Loads the config from disk. Returns an empty config if the file
    /// doesn't exist yet (first launch).
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                toml::from_str(&raw).with_context(|| format!("config invalide: {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", path.display())),
        }
    }

    /// Writes `profiles.toml` — **test-only, and deliberately so**.
    ///
    /// # Why this is not a production path any more
    ///
    /// This wrote the private key and the static PSK in the clear, and that is
    /// exactly the file ADR-006 §3 retires: `profiles.toml` is now an *import*
    /// format the migration consumes and deletes, never something Orion
    /// produces. [`crate::vault::ProfileStore::save_profile`] is the writer.
    ///
    /// It is `cfg(test)` rather than deleted because the migration tests need
    /// to *create* a legacy file to migrate. Keeping it callable from the
    /// shipped binary is what let a floor raise silently recreate that file
    /// after every negotiated connection — the compiler now refuses that,
    /// which is a stronger guarantee than a comment asking nobody to call it.
    #[cfg(test)]
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            aether::private_file::create_private_dir(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(self).context("sérialisation TOML")?;
        // 0600 from creation on Unix — see `aether::private_file`, including
        // why Windows gets nothing here and what actually protects it (ADR-006).
        aether::private_file::write_private_atomic(&path, raw.as_bytes())
            .with_context(|| format!("écriture privée de {}", path.display()))?;
        Ok(())
    }

    /// Returns the profile with this name, if any.
    pub fn find(&self, name: &str) -> Option<&ClientProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Inserts or replaces a profile (key = `name`).
    ///
    /// The key-negotiation floor only ever goes **up**, exactly as the gateway
    /// refuses to lower a peer's floor when a redacted view is reposted
    /// (ADR-001, amendment of 24 July 2026). A screen that forgot the block,
    /// or a draft opened before a raise and saved after it, must not silently
    /// reopen a weaker negotiation. The profile variant is an even stronger
    /// boundary: changing it under the same stable profile is refused. A
    /// classic peer and a Helios peer use two distinct profile identifiers.
    pub fn upsert(&mut self, mut profile: ClientProfile) -> Result<()> {
        profile.check_kind()?;
        match self.profiles.iter_mut().find(|p| p.name == profile.name) {
            Some(slot) => {
                profile.check_replacement_of(slot)?;
                Self::keep_strongest_floor(&mut profile, slot);
                *slot = profile;
            }
            None => self.profiles.push(profile),
        }
        Ok(())
    }

    /// Carries the known floor over to the profile about to replace it.
    ///
    /// The caller has already proved both profiles are Helios. Dropping the
    /// block is refused before this function; only the monotone floor remains
    /// to reconcile here.
    fn keep_strongest_floor(incoming: &mut ClientProfile, known: &ClientProfile) {
        let Some(previous) = known.key_negotiation.as_ref() else {
            return;
        };
        let Some(next) = incoming.key_negotiation.as_mut() else {
            return;
        };
        if !next.minimum_mode.satisfies(previous.minimum_mode) {
            next.minimum_mode = previous.minimum_mode;
        }
        if !next.mode.satisfies(next.minimum_mode) {
            next.mode = next.minimum_mode;
        }
    }

    /// Removes the profile with this name. Deselects it if it was the current profile.
    pub fn remove(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.selected.as_deref() == Some(name) {
            self.selected = self.profiles.first().map(|p| p.name.clone());
        }
    }
}

#[cfg(test)]
mod tests;
