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

/// Default `AllowedIPs`: all traffic goes through the tunnel.
///
/// It's this `0.0.0.0/0`, combined with the adapter lifecycle invariant
/// (see [`crate::backend`]), that makes WireGuard **drop** packets instead of
/// letting them leak in clear when the session is dead.
pub const DEFAULT_ALLOWED_IPS: &str = "0.0.0.0/0";

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
    pub astra_authority_url: String,
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

        if self.astra_authority_url.trim().is_empty() {
            anyhow::bail!("l'URL de l'autorité Astra est vide");
        }
        // Astra authenticates itself by its pinned ML-DSA-87 service key, not
        // by its transport (spec §9.6). `https` is still required: without it
        // an observer reads which client renews, and when.
        if !self.astra_authority_url.trim().starts_with("https://") {
            anyhow::bail!("l'URL de l'autorité Astra doit être en https://");
        }
        if self.ca_epoch == 0 || self.ca_tls_epoch == 0 || self.astra_service_key_epoch == 0 {
            anyhow::bail!("les compteurs d'autorité commencent à 1");
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
    certificate
        .verify_self_signed(
            aether::key_negotiation::PqCertificateRole::Gateway,
            Some(&settings.server_name),
            peer_public_key,
            now,
        )
        .context("le certificat PQ épinglé ne correspond pas à cette gateway")?;

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

/// Name of a mode as the user reads it on screen.
fn mode_label(mode: ProtectionMode) -> &'static str {
    match mode {
        ProtectionMode::Classic => "classique",
        ProtectionMode::StaticPsk => "PSK statique",
        ProtectionMode::MlKem => "ML-KEM-1024",
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
            .field("allowed_ips", &self.allowed_ips)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("heliosd_url", &self.heliosd_url)
            .field("ssh_target", &self.ssh_target)
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
    pub fn validate(&self) -> Result<()> {
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
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: DEFAULT_KEEPALIVE_SECS,
            heliosd_url: None,
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
    /// reopen a weaker negotiation. Lowering the floor stays possible, but
    /// only by editing `profiles.toml` by hand — a deliberate local act, never
    /// a side effect of saving a form.
    pub fn upsert(&mut self, mut profile: ClientProfile) {
        match self.profiles.iter_mut().find(|p| p.name == profile.name) {
            Some(slot) => {
                Self::keep_strongest_floor(&mut profile, slot);
                *slot = profile;
            }
            None => self.profiles.push(profile),
        }
    }

    /// Carries the known floor over to the profile about to replace it.
    ///
    /// Dropping the block entirely is a downgrade too: a profile that
    /// negotiated in ML-KEM and comes back without any block would fall back
    /// to the legacy path, whose first handshake is unprotected. The known
    /// block is therefore preserved rather than erased.
    fn keep_strongest_floor(incoming: &mut ClientProfile, known: &ClientProfile) {
        let Some(previous) = known.key_negotiation.as_ref() else {
            return;
        };
        let Some(next) = incoming.key_negotiation.as_mut() else {
            if previous.minimum_mode != ProtectionMode::Classic {
                incoming.key_negotiation = Some(previous.clone());
            }
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
mod tests {
    use super::*;

    #[test]
    fn upsert_and_remove() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "a".into(),
            ..ClientProfile::default()
        });
        cfg.upsert(ClientProfile {
            name: "b".into(),
            ..ClientProfile::default()
        });
        cfg.selected = Some("b".into());
        assert_eq!(cfg.profiles.len(), 2);

        // upsert on an existing name replaces, doesn't add.
        cfg.upsert(ClientProfile {
            name: "a".into(),
            endpoint: "203.0.113.1:51820".into(),
            ..ClientProfile::default()
        });
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.find("a").unwrap().endpoint, "203.0.113.1:51820");

        cfg.remove("b");
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.selected.as_deref(), Some("a")); // auto re-selection
    }

    fn negotiating(mode: ProtectionMode, minimum_mode: ProtectionMode) -> ClientProfile {
        ClientProfile {
            name: "poste".into(),
            key_negotiation: Some(KeyNegotiationSettings {
                mode,
                minimum_mode,
                endpoint: "vpn.example.net:51821".into(),
                server_name: "vpn.example.net".into(),
                gateway_ca_der: "MIIB".into(),
                gateway_pq_certificate: "e30=".into(),
                identity: "orion-poste".into(),
                trust: None,
            }),
            ..ClientProfile::default()
        }
    }

    /// Saving a profile must never reopen a weaker negotiation.
    ///
    /// The scenario is ordinary: a screen left open before the floor was
    /// raised, saved afterwards. Without the ratchet, the stale draft would
    /// carry the whole client back down to `classic` — exactly the downgrade
    /// the gateway refuses over the network.
    #[test]
    fn saving_a_profile_never_lowers_the_key_negotiation_floor() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem));
        cfg.upsert(negotiating(
            ProtectionMode::Classic,
            ProtectionMode::Classic,
        ));

        let saved = cfg.find("poste").unwrap().key_negotiation.as_ref().unwrap();
        assert_eq!(saved.minimum_mode, ProtectionMode::MlKem);
        // A mode left below the restored floor is raised with it: the two
        // must never contradict each other on disk.
        assert_eq!(saved.mode, ProtectionMode::MlKem);
    }

    /// Dropping the block is a downgrade too: the legacy path leaves the
    /// first handshake unprotected.
    #[test]
    fn saving_a_profile_without_its_block_keeps_the_known_one() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem));
        cfg.upsert(ClientProfile {
            name: "poste".into(),
            ..ClientProfile::default()
        });

        let saved = cfg.find("poste").unwrap().key_negotiation.as_ref().unwrap();
        assert_eq!(saved.minimum_mode, ProtectionMode::MlKem);
    }

    /// Adding negotiation to a profile that had none must survive the save
    /// **and** the round-trip through `profiles.toml`.
    ///
    /// This is the upgrade path a user actually walks: a profile enrolled long
    /// ago, re-enrolled with a negotiation block. If the block were dropped by
    /// the ratchet, by serialization, or by a default, the Profiles screen
    /// would keep saying "this profile does not negotiate" with no way to tell
    /// whether the import or the display was at fault.
    ///
    /// Serialized in place rather than through `save`/`load`: those go through
    /// `ORION_CONFIG`, a process-wide variable that parallel tests would fight
    /// over. The property under test is the encoding, not the file path.
    #[test]
    fn a_negotiation_block_survives_save_and_reload() {
        let mut cfg = ClientConfig::default();
        // The profile as it exists before enrollment: no block at all.
        cfg.upsert(ClientProfile {
            name: "poste".into(),
            endpoint: "vpn.example.net:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            ..ClientProfile::default()
        });
        assert!(cfg.find("poste").unwrap().key_negotiation.is_none());

        // Re-enrolled: same name, now carrying negotiation.
        cfg.upsert(negotiating(ProtectionMode::MlKem, ProtectionMode::MlKem));

        let encoded = toml::to_string_pretty(&cfg).unwrap();
        let reloaded: ClientConfig = toml::from_str(&encoded).unwrap();
        let settings = reloaded
            .find("poste")
            .expect("profile kept")
            .key_negotiation
            .as_ref()
            .expect("the negotiation block must survive the round-trip");
        assert_eq!(settings.mode, ProtectionMode::MlKem);
        assert_eq!(settings.identity, "orion-poste");
    }

    /// A floor still at `classic` carries no promise: nothing to preserve.
    #[test]
    fn a_classic_floor_does_not_pin_the_block() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(negotiating(
            ProtectionMode::Classic,
            ProtectionMode::Classic,
        ));
        cfg.upsert(ClientProfile {
            name: "poste".into(),
            ..ClientProfile::default()
        });

        assert!(cfg.find("poste").unwrap().key_negotiation.is_none());
    }

    #[test]
    fn disk_roundtrip() {
        let dir = std::env::temp_dir().join(format!("orion-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        std::env::set_var("ORION_CONFIG", &path);

        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "site-a".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            preshared_key: Some("cHNr".into()),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        });
        cfg.selected = Some("site-a".into());
        cfg.save().unwrap();

        let loaded = ClientConfig::load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        let p = loaded.find("site-a").unwrap();
        assert_eq!(p.endpoint, "203.0.113.10:51820");
        assert_eq!(p.address.as_deref(), Some("100.64.1.2/32"));
        // WireGuard defaults must survive the round-trip.
        assert_eq!(p.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(p.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
        assert!(p.has_preshared_key());
        assert_eq!(loaded.selected.as_deref(), Some("site-a"));

        // The file carries a private key and a PSK: it must never be readable
        // by anyone else. Asserted on the SECOND write too, because that is the
        // one that used to hand the mode back to the umask (ADR-006).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &std::path::Path| {
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777
            };
            assert_eq!(mode(&path), 0o600, "mode after the first save");
            cfg.save().unwrap();
            assert_eq!(mode(&path), 0o600, "mode after a rewrite");
        }

        std::env::remove_var("ORION_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_masked_in_debug() {
        let p = ClientProfile {
            private_key: "TRES_SECRET".into(),
            preshared_key: Some("PSK_SECRET".into()),
            ..ClientProfile::default()
        };
        let dump = format!("{p:?}");
        assert!(
            !dump.contains("TRES_SECRET"),
            "the private key leaks into logs"
        );
        assert!(!dump.contains("PSK_SECRET"), "the PSK leaks into logs");
    }
}
