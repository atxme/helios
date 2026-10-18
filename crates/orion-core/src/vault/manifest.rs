//! Atomic security manifest of an Orion profile (ADR-006 §2).
//!
//! # Why the manifest holds more than the two secrets
//!
//! Encrypting only the private key and the PSK would leave endpoint, pinned CA,
//! `allowed_ips`, negotiated mode and anti-downgrade floor in a file anyone can
//! edit. An attacker could then keep the secrets sealed and still redirect the
//! tunnel, swap the trust anchor or lower the floor — the secret would be safe
//! and the connection would not. Everything that decides *where* and *how* the
//! tunnel is established therefore lives inside the same AEAD.
//!
//! # Why a hand-rolled encoding
//!
//! ADR-006 §5 forbids handing a secret-bearing type to a TOML or JSON
//! serializer. Those build intermediate `String`s nobody can wipe, keep buffers
//! alive inside the library, and would spread copies of the private key through
//! allocations this crate does not own. The manifest is therefore written
//! straight into a bounded [`Zeroizing`] buffer.
//!
//! The encoding is deliberately dull: a version byte, then length-prefixed
//! fields in a fixed order. No field names, no self-description, nothing to
//! parse ambiguously. Adding a field means a new version, which an older binary
//! refuses instead of misreading — the same doctrine as the container's `ver`
//! byte and the negotiation protocol's version.

use zeroize::Zeroizing;

use super::{codec, codec::Cursor, VaultError};
use crate::config::{ClientProfile, KeyNegotiationSettings, ProfileKind};
use aether::key_negotiation::ProtectionMode;

/// Version written today for a profile carrying an IPv6 address. Any
/// version not listed below is refused, never guessed.
///
/// It appends `address_v6`, and it is written **only** when the profile has
/// one: a profile without it is still sealed as
/// [`MANIFEST_VERSION_WITHOUT_ADDRESS_V6`], byte for byte as before. The
/// absent value writes nothing, so an IPv4-only profile stays readable by an
/// Orion that predates the field, and only a profile that would lose an
/// address when read by such an Orion is refused by it (`ADRESSAGE-IPV6.md`
/// §8 — the same line the `orion-profile` document draws).
const MANIFEST_VERSION: u8 = 8;

/// Version written for a profile without an IPv6 address: everything of
/// today except the trailing `address_v6`.
const MANIFEST_VERSION_WITHOUT_ADDRESS_V6: u8 = 7;

/// Previous version, still readable: it lacks the trailing `ssh_target`.
///
/// # Why both, rather than a clean bump
///
/// The manifest is what a **sealed** profile is stored as. Refusing v1 would
/// not have meant "migrate later", it would have meant every profile already
/// on a user's machine becoming unreadable at the next start — with its
/// WireGuard private key inside it, and the enrolment document long since
/// destroyed as the import instructions require. There would be nothing to
/// restore from.
///
/// So v1 decodes with `ssh_target: None` and is rewritten as v2 on the next
/// save. The decoder stays strict about everything else: an unknown version
/// is still refused, and trailing bytes still are.
const MANIFEST_VERSION_WITHOUT_SSH: u8 = 1;

/// Previous version, still readable: it lacks the trailing trust material of
/// spec §19. A profile sealed by an older Orion keeps decoding byte for byte,
/// and re-sealing writes the current version.
const MANIFEST_VERSION_WITHOUT_TRUST: u8 = 2;

/// Previous version. It carries the first §19 trust block but predates the
/// policy pin, WebAuthn RP ID and credential-registry anti-rollback counter.
/// It remains readable so the UI can name the required profile re-issuance.
const MANIFEST_VERSION_WITHOUT_ASTRA_POLICY: u8 = 3;

/// Previous version: everything of today except the §19 profile discriminant.
///
/// Read as **undeclared**, not as classic. The difference is the whole point
/// of the field: a profile sealed before it exists has no opinion recorded,
/// and [`ClientProfile::kind`] infers one from the block exactly as this
/// client always did — once, on the way in. Re-sealing writes the answer down,
/// and from then on the guess is never made again.
const MANIFEST_VERSION_WITHOUT_PROFILE_KIND: u8 = 4;

/// Previous version: everything of today except the domain's operator
/// credential bindings.
///
/// Read as an empty list, which is what such a profile actually knows. It
/// still mounts a tunnel and still renews; what it cannot do is recover an
/// expired identity, because §7.5 begins by naming the credential that will
/// approve it. Re-sealing after a re-issued enrolment writes the list down.
const MANIFEST_VERSION_WITHOUT_CREDENTIAL_BINDINGS: u8 = 5;

/// Previous version: everything of today except the two gateway identity
/// epochs of the §19 block.
///
/// Read as zero, which is what such a profile actually knows — and which the
/// trust block's own validation refuses, so the profile is re-issued rather
/// than resealed into a store that can never be updated. It still mounts a
/// tunnel; what it cannot do is collect a trust update, because a store seeded
/// at epoch 0 is permanently behind a registry that starts at 1.
const MANIFEST_VERSION_WITHOUT_GATEWAY_EPOCHS: u8 = 6;

/// The credential bindings, as the one text field the manifest stores them in.
///
/// JSON rather than a hand-rolled framing: a binding is a signed document with
/// a dozen fields, and a second encoder for it would be a second place for the
/// bytes under a `CA-PQ` signature to drift. What the manifest needs of it is
/// only that it round-trips, and the signature is re-checked on the way out of
/// the seed anyway.
///
/// An unencodable list yields an empty one rather than failing the seal: this
/// value is a convenience the enrolment can restate, and refusing to save a
/// profile over it would trade a recoverable identity for an unopenable vault.
fn credential_bindings_json(trust: &crate::config::TrustMaterial) -> String {
    serde_json::to_string(&trust.astra_credential_bindings).unwrap_or_else(|_| "[]".into())
}

/// The inverse, refusing what it cannot read exactly.
fn decode_credential_bindings(
    text: &str,
) -> Result<Vec<aether::certificates::approval::AstraCredentialBinding>, VaultError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).map_err(|error| {
        VaultError::ManifestEncoding(format!("invalid Astra credential bindings: {error}"))
    })
}

/// Bound on a decoded manifest, checked before any allocation.
///
/// A profile holds two base64 keys, a few addresses and two certificates —
/// dozens of kilobytes at the very most.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Monotonic counter of a profile's security-relevant state.
///
/// Raised on a key rotation, a PSK change, a trust-anchor change or a floor
/// change. Orion and Helios refuse a generation lower than one already observed
/// **during the run**.
///
/// # Limite connue
///
/// This bounds replay in-process only. Detecting a restore of every file at
/// once needs a counter a restore cannot rewind, and that arbitration is the
/// one still blocked by ADR-002's second amendment. Until then, **no resistance
/// to a full offline rollback is claimed** — and the limit can never justify a
/// downgrade: in doubt, the connection fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SecurityGeneration(pub u64);

impl SecurityGeneration {
    /// Next generation. Saturating rather than wrapping: a counter that wraps
    /// to zero would accept every past manifest again.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Everything a profile needs to establish its tunnel, sealed as one object.
///
/// Never derives `Clone`, `Debug` or `Serialize`: the rule is on the type
/// first, because a copy already made cannot be zeroized (ADR-006 §5).
pub struct ProfileManifest {
    pub generation: SecurityGeneration,
    /// Display name. Inside the manifest so renaming cannot be done from
    /// outside, which would let a lure profile take a trusted one's place.
    pub name: String,
    pub endpoint: String,
    /// **Secret.**
    pub private_key: aether::SecretString,
    pub peer_public_key: String,
    /// **Secret**, when a static PSK is in use.
    pub preshared_key: Option<aether::SecretString>,
    pub address: Option<String>,
    /// Present only in a manifest of `MANIFEST_VERSION`.
    pub address_v6: Option<String>,
    pub allowed_ips: String,
    pub persistent_keepalive: u16,
    pub heliosd_url: Option<String>,
    pub ssh_target: Option<String>,
    /// The §19 discriminant, absent in a manifest sealed before v5.
    pub profile_type: Option<ProfileKind>,
    pub key_negotiation: Option<KeyNegotiationSettings>,
}

impl ProfileManifest {
    /// Declared kind, or the one-time historical inference for a pre-v5 blob.
    pub fn kind(&self) -> ProfileKind {
        self.profile_type
            .unwrap_or(if self.key_negotiation.is_some() {
                ProfileKind::HeliosKeyNegotiation
            } else {
                ProfileKind::Classic
            })
    }

    /// Builds a manifest from the profile shape the UI edits.
    pub fn from_profile(profile: &ClientProfile, generation: SecurityGeneration) -> Self {
        Self {
            generation,
            name: profile.name.clone(),
            endpoint: profile.endpoint.clone(),
            private_key: profile.private_key.duplicate(),
            peer_public_key: profile.peer_public_key.clone(),
            preshared_key: profile
                .preshared_key
                .as_ref()
                .map(aether::SecretString::duplicate),
            address: profile.address.clone(),
            address_v6: profile.address_v6.clone(),
            allowed_ips: profile.allowed_ips.clone(),
            persistent_keepalive: profile.persistent_keepalive,
            heliosd_url: profile.heliosd_url.clone(),
            ssh_target: profile.ssh_target.clone(),
            // Resolved on the way in, so a manifest never stores the
            // undeclared state a legacy one is read back as. Sealing is what
            // turns the inference into a recorded fact.
            profile_type: Some(profile.kind()),
            key_negotiation: profile.key_negotiation.clone(),
        }
    }

    /// Rebuilds the profile the rest of the client works with.
    pub fn to_profile(&self) -> ClientProfile {
        ClientProfile {
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            private_key: self.private_key.duplicate(),
            peer_public_key: self.peer_public_key.clone(),
            preshared_key: self
                .preshared_key
                .as_ref()
                .map(aether::SecretString::duplicate),
            address: self.address.clone(),
            address_v6: self.address_v6.clone(),
            allowed_ips: self.allowed_ips.clone(),
            persistent_keepalive: self.persistent_keepalive,
            heliosd_url: self.heliosd_url.clone(),
            ssh_target: self.ssh_target.clone(),
            profile_type: self.profile_type,
            key_negotiation: self.key_negotiation.clone(),
            preshared_key_is_negotiated: false,
        }
    }

    /// Digest of everything whose change is a **security event**.
    ///
    /// ADR-006 §2 names four triggers for raising the generation: a key
    /// rotation, a PSK change, a trust-anchor change and a floor change. The
    /// key rotation is tracked separately — the registry already holds the
    /// client public key — so this digest covers the other three, and nothing
    /// else. Endpoint, display name and `allowed_ips` deliberately stay out:
    /// they belong to the sealed manifest, they are not what the generation
    /// counter is for, and raising it on an ordinary edit would make a real
    /// rollback indistinguishable from a renamed profile.
    ///
    /// The PSK is covered by its **value**, not merely its presence: swapping
    /// one static PSK for another is exactly the change the ADR lists.
    /// Hashing it is what lets the registry witness that change without ever
    /// holding the secret — the registry carries no PSK, and must not start.
    pub fn security_digest(&self) -> [u8; 32] {
        // Length-prefixed like every other canonical encoding here: without it
        // an empty CA followed by a certificate would hash like the reverse.
        let mut input = Zeroizing::new(Vec::with_capacity(512));
        let mut field = |value: &[u8]| {
            input.extend_from_slice(&(value.len() as u32).to_be_bytes());
            input.extend_from_slice(value);
        };
        match &self.preshared_key {
            None => field(b""),
            Some(psk) => field(psk.expose().as_bytes()),
        }
        match &self.key_negotiation {
            None => {
                field(b"");
                field(b"");
                field(b"");
            }
            Some(settings) => {
                field(settings.gateway_ca_der.as_bytes());
                field(settings.gateway_pq_certificate.as_bytes());
                field(&[mode_id(settings.minimum_mode)]);
                match &settings.trust {
                    None => field(b""),
                    Some(trust) => {
                        field(b"orion-trust-material-v2");
                        field(trust.trust_domain_id.as_bytes());
                        field(&trust.ca_epoch.to_be_bytes());
                        field(trust.ca_pq_public_key.as_bytes());
                        field(&trust.ca_tls_epoch.to_be_bytes());
                        field(trust.client_tls_ca_der.as_bytes());
                        field(&trust.client_generation.to_be_bytes());
                        field(trust.astra_authority_url.as_bytes());
                        field(trust.webauthn_rp_id.as_bytes());
                        field(trust.astra_policy_fingerprint.as_bytes());
                        field(&trust.credential_registry_epoch.to_be_bytes());
                        // Les liaisons de credentials sont délibérément
                        // absentes : ADR-006 §2 fait monter la génération sur
                        // un changement d'**ancre**, et une liaison n'en est
                        // pas une — elle est signée par celle-ci. L'y mettre
                        // ferait monter le compteur à chaque enrôlement de clé
                        // opérateur, et un vrai retour en arrière deviendrait
                        // indiscernable d'une routine.
                        field(&trust.astra_service_key_epoch.to_be_bytes());
                        field(trust.astra_service_public_key.as_bytes());
                    }
                }
            }
        }
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// Encodes into a bounded, zeroizing buffer.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        out.push(if self.address_v6.is_some() {
            MANIFEST_VERSION
        } else {
            MANIFEST_VERSION_WITHOUT_ADDRESS_V6
        });
        out.extend_from_slice(&self.generation.0.to_be_bytes());
        codec::put(&mut out, self.name.as_bytes())?;
        codec::put(&mut out, self.endpoint.as_bytes())?;
        codec::put(&mut out, self.private_key.expose().as_bytes())?;
        codec::put(&mut out, self.peer_public_key.as_bytes())?;
        codec::put_option(
            &mut out,
            self.preshared_key.as_ref().map(|v| v.expose().as_bytes()),
        )?;
        codec::put_option(&mut out, self.address.as_deref().map(str::as_bytes))?;
        codec::put(&mut out, self.allowed_ips.as_bytes())?;
        out.extend_from_slice(&self.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut out, self.heliosd_url.as_deref().map(str::as_bytes))?;
        codec::put_option(&mut out, self.ssh_target.as_deref().map(str::as_bytes))?;
        out.push(profile_kind_id(self.profile_type));
        match &self.key_negotiation {
            None => out.push(0),
            Some(settings) => {
                out.push(1);
                out.push(mode_id(settings.mode));
                out.push(mode_id(settings.minimum_mode));
                codec::put(&mut out, settings.endpoint.as_bytes())?;
                codec::put(&mut out, settings.server_name.as_bytes())?;
                codec::put(&mut out, settings.gateway_ca_der.as_bytes())?;
                codec::put(&mut out, settings.gateway_pq_certificate.as_bytes())?;
                codec::put(&mut out, settings.identity.as_bytes())?;
                match &settings.trust {
                    None => out.push(0),
                    Some(trust) => {
                        out.push(1);
                        codec::put(&mut out, trust.trust_domain_id.as_bytes())?;
                        out.extend_from_slice(&trust.ca_epoch.to_be_bytes());
                        codec::put(&mut out, trust.ca_pq_public_key.as_bytes())?;
                        out.extend_from_slice(&trust.ca_tls_epoch.to_be_bytes());
                        codec::put(&mut out, trust.client_tls_ca_der.as_bytes())?;
                        out.extend_from_slice(&trust.client_generation.to_be_bytes());
                        codec::put(&mut out, trust.astra_authority_url.as_bytes())?;
                        codec::put(&mut out, trust.webauthn_rp_id.as_bytes())?;
                        codec::put(&mut out, trust.astra_policy_fingerprint.as_bytes())?;
                        out.extend_from_slice(&trust.credential_registry_epoch.to_be_bytes());
                        codec::put(&mut out, credential_bindings_json(trust).as_bytes())?;
                        out.extend_from_slice(&trust.astra_service_key_epoch.to_be_bytes());
                        codec::put(&mut out, trust.astra_service_public_key.as_bytes())?;
                        out.extend_from_slice(&trust.active_gateway_identity_epoch.to_be_bytes());
                        out.extend_from_slice(&trust.gateway_decision_epoch.to_be_bytes());
                    }
                }
            }
        }
        // Last, and only in the version that carries it: see
        // [`MANIFEST_VERSION`].
        if let Some(address_v6) = &self.address_v6 {
            codec::put(&mut out, address_v6.as_bytes())?;
        }
        if out.len() > MAX_MANIFEST_BYTES {
            return Err(VaultError::ManifestTooLarge(out.len()));
        }
        Ok(out)
    }

    /// Decodes a manifest, refusing anything it cannot read exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(VaultError::ManifestTooLarge(bytes.len()));
        }
        let mut cursor = Cursor::new(bytes);
        let version = cursor.byte()?;
        if version != MANIFEST_VERSION
            && version != MANIFEST_VERSION_WITHOUT_ADDRESS_V6
            && version != MANIFEST_VERSION_WITHOUT_GATEWAY_EPOCHS
            && version != MANIFEST_VERSION_WITHOUT_CREDENTIAL_BINDINGS
            && version != MANIFEST_VERSION_WITHOUT_PROFILE_KIND
            && version != MANIFEST_VERSION_WITHOUT_ASTRA_POLICY
            && version != MANIFEST_VERSION_WITHOUT_TRUST
            && version != MANIFEST_VERSION_WITHOUT_SSH
        {
            return Err(VaultError::UnsupportedManifest(version));
        }
        let generation = SecurityGeneration(u64::from_be_bytes(cursor.array::<8>()?));
        let name = cursor.text()?;
        let endpoint = cursor.text()?;
        let private_key = aether::SecretString::new(cursor.text()?);
        let peer_public_key = cursor.text()?;
        let preshared_key = cursor.option_text()?.map(aether::SecretString::new);
        let address = cursor.option_text()?;
        let allowed_ips = cursor.text()?;
        let persistent_keepalive = u16::from_be_bytes(cursor.array::<2>()?);
        let heliosd_url = cursor.option_text()?;
        // The one field whose presence depends on the version. Read where it
        // was written, so v1 keeps decoding byte for byte as it always did.
        let ssh_target = if version != MANIFEST_VERSION_WITHOUT_SSH {
            cursor.option_text()?
        } else {
            None
        };
        // Read where it was written, so a v4 manifest keeps decoding byte for
        // byte as it always did. Written since v5, so the test is the version
        // that introduced it and not the current one: a comparison against
        // `MANIFEST_VERSION` stops being true for every sealed profile the
        // moment the version is bumped, and each of them would then be read
        // one byte out of step.
        let profile_type = if version > MANIFEST_VERSION_WITHOUT_PROFILE_KIND {
            profile_kind_from_id(cursor.byte()?)?
        } else {
            None
        };
        let key_negotiation = match cursor.byte()? {
            0 => None,
            1 => Some(KeyNegotiationSettings {
                mode: mode_from_id(cursor.byte()?)?,
                minimum_mode: mode_from_id(cursor.byte()?)?,
                endpoint: cursor.text()?,
                server_name: cursor.text()?,
                gateway_ca_der: cursor.text()?,
                gateway_pq_certificate: cursor.text()?,
                identity: cursor.text()?,
                // Read where it was written, so a v2 manifest keeps decoding
                // byte for byte as it always did.
                trust: if version > MANIFEST_VERSION_WITHOUT_TRUST {
                    match cursor.byte()? {
                        0 => None,
                        1 => Some(crate::config::TrustMaterial {
                            trust_domain_id: cursor.text()?,
                            ca_epoch: u64::from_be_bytes(cursor.array::<8>()?),
                            ca_pq_public_key: cursor.text()?,
                            ca_tls_epoch: u64::from_be_bytes(cursor.array::<8>()?),
                            client_tls_ca_der: cursor.text()?,
                            client_generation: u64::from_be_bytes(cursor.array::<8>()?),
                            astra_authority_url: cursor.text()?,
                            webauthn_rp_id: if version != MANIFEST_VERSION_WITHOUT_ASTRA_POLICY {
                                cursor.text()?
                            } else {
                                String::new()
                            },
                            astra_policy_fingerprint: if version
                                != MANIFEST_VERSION_WITHOUT_ASTRA_POLICY
                            {
                                cursor.text()?
                            } else {
                                String::new()
                            },
                            credential_registry_epoch: if version
                                != MANIFEST_VERSION_WITHOUT_ASTRA_POLICY
                            {
                                u64::from_be_bytes(cursor.array::<8>()?)
                            } else {
                                0
                            },
                            astra_credential_bindings: if version
                                > MANIFEST_VERSION_WITHOUT_CREDENTIAL_BINDINGS
                            {
                                decode_credential_bindings(&cursor.text()?)?
                            } else {
                                Vec::new()
                            },
                            astra_service_key_epoch: u64::from_be_bytes(cursor.array::<8>()?),
                            astra_service_public_key: cursor.text()?,
                            active_gateway_identity_epoch: if version
                                > MANIFEST_VERSION_WITHOUT_GATEWAY_EPOCHS
                            {
                                u64::from_be_bytes(cursor.array::<8>()?)
                            } else {
                                0
                            },
                            gateway_decision_epoch: if version
                                > MANIFEST_VERSION_WITHOUT_GATEWAY_EPOCHS
                            {
                                u64::from_be_bytes(cursor.array::<8>()?)
                            } else {
                                0
                            },
                        }),
                        other => {
                            return Err(VaultError::ManifestEncoding(format!(
                                "invalid trust-material presence byte {other}"
                            )))
                        }
                    }
                } else {
                    None
                },
            }),
            other => {
                return Err(VaultError::ManifestEncoding(format!(
                    "invalid key-negotiation presence byte {other}"
                )))
            }
        };
        // Written last, by the one version that carries it. Never empty there:
        // that version is only chosen when the value exists.
        let address_v6 = if version > MANIFEST_VERSION_WITHOUT_ADDRESS_V6 {
            let text = cursor.text()?;
            if text.is_empty() {
                return Err(VaultError::ManifestEncoding(
                    "empty address_v6 in a manifest that exists to carry one".into(),
                ));
            }
            Some(text)
        } else {
            None
        };
        // Trailing bytes mean the encoder and decoder disagree. Ignoring them
        // is how a format silently forks.
        cursor.expect_end()?;
        Ok(Self {
            generation,
            name,
            endpoint,
            private_key,
            peer_public_key,
            preshared_key,
            address,
            address_v6,
            allowed_ips,
            persistent_keepalive,
            heliosd_url,
            ssh_target,
            profile_type,
            key_negotiation,
        })
    }
}

/// Explicit identifiers rather than `as u8` on the enum: reordering the enum
/// would otherwise silently reinterpret every stored profile's mode — and the
/// mode is what decides the protection level.
fn mode_id(mode: ProtectionMode) -> u8 {
    match mode {
        ProtectionMode::Classic => 0,
        ProtectionMode::StaticPsk => 1,
        ProtectionMode::MlKem => 2,
    }
}

/// Explicit identifiers, for the same reason as [`mode_id`]: this byte decides
/// whether a profile negotiates before WireGuard, and reordering an enum must
/// never be able to change that for a profile already on disk.
///
/// `0` is the **undeclared** state, which only a v4-or-older manifest produces
/// and which nothing writes: [`ProfileManifest::from_profile`] resolves the
/// kind before sealing.
fn profile_kind_id(kind: Option<ProfileKind>) -> u8 {
    match kind {
        None => 0,
        Some(ProfileKind::Classic) => 1,
        Some(ProfileKind::HeliosKeyNegotiation) => 2,
    }
}

fn profile_kind_from_id(id: u8) -> Result<Option<ProfileKind>, VaultError> {
    match id {
        0 => Ok(None),
        1 => Ok(Some(ProfileKind::Classic)),
        2 => Ok(Some(ProfileKind::HeliosKeyNegotiation)),
        other => Err(VaultError::ManifestEncoding(format!(
            "unknown profile kind {other}"
        ))),
    }
}

fn mode_from_id(id: u8) -> Result<ProtectionMode, VaultError> {
    match id {
        0 => Ok(ProtectionMode::Classic),
        1 => Ok(ProtectionMode::StaticPsk),
        2 => Ok(ProtectionMode::MlKem),
        other => Err(VaultError::ManifestEncoding(format!(
            "unknown protection mode {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn negotiation() -> KeyNegotiationSettings {
        KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::StaticPsk,
            endpoint: "203.0.113.10:51821".into(),
            server_name: "vpn.example.net".into(),
            gateway_ca_der: "MIIB".into(),
            gateway_pq_certificate: "e30=".into(),
            identity: "orion-poste".into(),
            trust: None,
        }
    }

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "poste".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            preshared_key: Some("cHNr".into()),
            address: Some("100.64.1.2/32".into()),
            address_v6: None,
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: 25,
            heliosd_url: Some("http://100.64.0.1:8080".into()),
            ssh_target: Some("christophe@100.64.0.1".into()),
            profile_type: Some(ProfileKind::HeliosKeyNegotiation),
            key_negotiation: Some(negotiation()),
            preshared_key_is_negotiated: false,
        }
    }

    #[test]
    fn a_full_manifest_round_trips() {
        let manifest = ProfileManifest::from_profile(&profile(), SecurityGeneration(7));
        let encoded = manifest.encode().expect("encode");
        let decoded = ProfileManifest::decode(&encoded).expect("decode");

        assert_eq!(decoded.generation, SecurityGeneration(7));
        let rebuilt = decoded.to_profile();
        let original = profile();
        assert_eq!(rebuilt.name, original.name);
        assert_eq!(rebuilt.endpoint, original.endpoint);
        assert_eq!(rebuilt.private_key, original.private_key);
        assert_eq!(rebuilt.peer_public_key, original.peer_public_key);
        assert_eq!(rebuilt.preshared_key, original.preshared_key);
        assert_eq!(rebuilt.address, original.address);
        assert_eq!(rebuilt.allowed_ips, original.allowed_ips);
        assert_eq!(rebuilt.persistent_keepalive, original.persistent_keepalive);
        assert_eq!(rebuilt.heliosd_url, original.heliosd_url);
        assert_eq!(rebuilt.ssh_target, original.ssh_target);
        let block = rebuilt.key_negotiation.expect("negotiation block");
        assert_eq!(block.mode, ProtectionMode::MlKem);
        assert_eq!(block.minimum_mode, ProtectionMode::StaticPsk);
        assert_eq!(block.identity, "orion-poste");
    }

    /// A profile sealed before `ssh_target` existed must still open.
    ///
    /// Built byte for byte in the v1 layout rather than derived from the v2
    /// encoder: a test that reuses the encoder proves the encoder agrees with
    /// itself, which is exactly what a compatibility test must not do. These
    /// are the bytes an installed Orion actually has on disk.
    #[test]
    fn a_manifest_sealed_before_ssh_target_still_decodes() {
        let source = profile();
        let mut v1: Vec<u8> = Vec::new();
        v1.push(MANIFEST_VERSION_WITHOUT_SSH);
        v1.extend_from_slice(&9u64.to_be_bytes());
        codec::put(&mut v1, source.name.as_bytes()).unwrap();
        codec::put(&mut v1, source.endpoint.as_bytes()).unwrap();
        codec::put(&mut v1, source.private_key.expose().as_bytes()).unwrap();
        codec::put(&mut v1, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(
            &mut v1,
            source
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose)
                .map(str::as_bytes),
        )
        .unwrap();
        codec::put_option(&mut v1, source.address.as_deref().map(str::as_bytes)).unwrap();
        codec::put(&mut v1, source.allowed_ips.as_bytes()).unwrap();
        v1.extend_from_slice(&source.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut v1, source.heliosd_url.as_deref().map(str::as_bytes)).unwrap();
        // No ssh_target here — that is the whole point of the version.
        v1.push(0); // no key-negotiation block

        let decoded = ProfileManifest::decode(&v1).expect("a v1 manifest must still open");
        assert_eq!(decoded.generation, SecurityGeneration(9));
        assert_eq!(decoded.ssh_target, None, "absent, not invented");
        let rebuilt = decoded.to_profile();
        assert_eq!(rebuilt.private_key, source.private_key);
        assert_eq!(rebuilt.heliosd_url, source.heliosd_url);

        // And re-sealing writes the current version, so the migration happens
        // on the next save without anyone being asked to do anything.
        let resealed = ProfileManifest::from_profile(&rebuilt, SecurityGeneration(9))
            .encode()
            .expect("encode");
        assert_eq!(
            resealed[0], MANIFEST_VERSION_WITHOUT_ADDRESS_V6,
            "current layout without IPv6"
        );
    }

    /// The trust material of spec §19 survives a seal and an open.
    #[test]
    fn the_trust_material_round_trips() {
        let mut source = profile();
        let block = source.key_negotiation.as_mut().expect("negotiation block");
        block.trust = Some(crate::config::TrustMaterial {
            trust_domain_id: "0102030405060708090a0b0c0d0e0f10".into(),
            ca_epoch: 3,
            ca_pq_public_key: "Y2EtcHE=".into(),
            ca_tls_epoch: 2,
            client_tls_ca_der: "Y2EtdGxz".into(),
            client_generation: 4,
            astra_authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: "11".repeat(32),
            credential_registry_epoch: 6,
            astra_credential_bindings: Vec::new(),
            astra_service_key_epoch: 5,
            astra_service_public_key: "c2VydmljZQ==".into(),
            active_gateway_identity_epoch: 7,
            gateway_decision_epoch: 8,
        });

        let original_digest =
            ProfileManifest::from_profile(&source, SecurityGeneration(1)).security_digest();
        let mut changed_policy = source.duplicate();
        changed_policy
            .key_negotiation
            .as_mut()
            .and_then(|block| block.trust.as_mut())
            .expect("trust material")
            .astra_policy_fingerprint = "22".repeat(32);
        assert_ne!(
            original_digest,
            ProfileManifest::from_profile(&changed_policy, SecurityGeneration(1)).security_digest(),
            "a restored policy pin must be observed as a security change"
        );

        let encoded = ProfileManifest::from_profile(&source, SecurityGeneration(1))
            .encode()
            .expect("encode");
        let decoded = ProfileManifest::decode(&encoded).expect("decode");
        let trust = decoded
            .to_profile()
            .key_negotiation
            .and_then(|block| block.trust)
            .expect("the trust material survives");
        assert_eq!(trust.trust_domain_id, "0102030405060708090a0b0c0d0e0f10");
        assert_eq!(trust.ca_epoch, 3);
        assert_eq!(trust.ca_tls_epoch, 2);
        assert_eq!(trust.client_generation, 4);
        assert_eq!(trust.astra_service_key_epoch, 5);
        assert_eq!(trust.active_gateway_identity_epoch, 7);
        assert_eq!(trust.gateway_decision_epoch, 8);
        assert_eq!(trust.astra_authority_url, "https://astra.example");
    }

    /// A profile sealed before the trust material existed must still open.
    ///
    /// Built byte for byte in the v2 layout, like the v1 test above and for
    /// the same reason: reusing the encoder would only prove it agrees with
    /// itself.
    #[test]
    fn a_manifest_sealed_before_the_trust_material_still_decodes() {
        let source = profile();
        let block = source.key_negotiation.as_ref().expect("negotiation block");
        let mut v2: Vec<u8> = Vec::new();
        v2.push(MANIFEST_VERSION_WITHOUT_TRUST);
        v2.extend_from_slice(&11u64.to_be_bytes());
        codec::put(&mut v2, source.name.as_bytes()).unwrap();
        codec::put(&mut v2, source.endpoint.as_bytes()).unwrap();
        codec::put(&mut v2, source.private_key.expose().as_bytes()).unwrap();
        codec::put(&mut v2, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(
            &mut v2,
            source
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose)
                .map(str::as_bytes),
        )
        .unwrap();
        codec::put_option(&mut v2, source.address.as_deref().map(str::as_bytes)).unwrap();
        codec::put(&mut v2, source.allowed_ips.as_bytes()).unwrap();
        v2.extend_from_slice(&source.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut v2, source.heliosd_url.as_deref().map(str::as_bytes)).unwrap();
        codec::put_option(&mut v2, source.ssh_target.as_deref().map(str::as_bytes)).unwrap();
        v2.push(1);
        v2.push(mode_id(block.mode));
        v2.push(mode_id(block.minimum_mode));
        codec::put(&mut v2, block.endpoint.as_bytes()).unwrap();
        codec::put(&mut v2, block.server_name.as_bytes()).unwrap();
        codec::put(&mut v2, block.gateway_ca_der.as_bytes()).unwrap();
        codec::put(&mut v2, block.gateway_pq_certificate.as_bytes()).unwrap();
        codec::put(&mut v2, block.identity.as_bytes()).unwrap();
        // No trust block here — that is the whole point of the version.

        let decoded = ProfileManifest::decode(&v2).expect("a v2 manifest must still open");
        assert_eq!(decoded.generation, SecurityGeneration(11));
        let rebuilt = decoded.to_profile();
        let opened = rebuilt.key_negotiation.clone().expect("negotiation block");
        assert_eq!(opened.identity, "orion-poste");
        assert_eq!(opened.trust, None, "absent, not invented");
        assert_eq!(rebuilt.ssh_target, source.ssh_target);

        // And re-sealing writes the current version: the migration happens on
        // the next save without anyone being asked to do anything.
        let resealed = ProfileManifest::from_profile(&rebuilt, SecurityGeneration(11))
            .encode()
            .expect("encode");
        assert_eq!(
            resealed[0], MANIFEST_VERSION_WITHOUT_ADDRESS_V6,
            "current layout without IPv6"
        );
    }

    /// Version 3 carried trust anchors but not the out-of-band Astra policy.
    /// It remains decryptable so Orion can ask for a re-issued profile; the
    /// three missing fields stay conspicuously invalid rather than being
    /// invented from a signed delegation or a URL.
    #[test]
    fn a_v3_manifest_opens_but_cannot_invent_the_astra_policy() {
        let source = profile();
        let block = source.key_negotiation.as_ref().expect("negotiation block");
        let mut v3 = Vec::new();
        v3.push(MANIFEST_VERSION_WITHOUT_ASTRA_POLICY);
        v3.extend_from_slice(&12u64.to_be_bytes());
        codec::put(&mut v3, source.name.as_bytes()).unwrap();
        codec::put(&mut v3, source.endpoint.as_bytes()).unwrap();
        codec::put(&mut v3, source.private_key.expose().as_bytes()).unwrap();
        codec::put(&mut v3, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(
            &mut v3,
            source
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose)
                .map(str::as_bytes),
        )
        .unwrap();
        codec::put_option(&mut v3, source.address.as_deref().map(str::as_bytes)).unwrap();
        codec::put(&mut v3, source.allowed_ips.as_bytes()).unwrap();
        v3.extend_from_slice(&source.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut v3, source.heliosd_url.as_deref().map(str::as_bytes)).unwrap();
        codec::put_option(&mut v3, source.ssh_target.as_deref().map(str::as_bytes)).unwrap();
        v3.push(1);
        v3.push(mode_id(block.mode));
        v3.push(mode_id(block.minimum_mode));
        codec::put(&mut v3, block.endpoint.as_bytes()).unwrap();
        codec::put(&mut v3, block.server_name.as_bytes()).unwrap();
        codec::put(&mut v3, block.gateway_ca_der.as_bytes()).unwrap();
        codec::put(&mut v3, block.gateway_pq_certificate.as_bytes()).unwrap();
        codec::put(&mut v3, block.identity.as_bytes()).unwrap();
        v3.push(1);
        codec::put(&mut v3, b"0102030405060708090a0b0c0d0e0f10").unwrap();
        v3.extend_from_slice(&3u64.to_be_bytes());
        codec::put(&mut v3, b"Y2EtcHE=").unwrap();
        v3.extend_from_slice(&2u64.to_be_bytes());
        codec::put(&mut v3, b"Y2EtdGxz").unwrap();
        v3.extend_from_slice(&4u64.to_be_bytes());
        codec::put(&mut v3, b"https://astra.example").unwrap();
        v3.extend_from_slice(&5u64.to_be_bytes());
        codec::put(&mut v3, b"c2VydmljZQ==").unwrap();

        let decoded = ProfileManifest::decode(&v3).expect("v3 remains decryptable");
        let trust = decoded
            .to_profile()
            .key_negotiation
            .and_then(|settings| settings.trust)
            .expect("old trust block");
        assert!(trust.webauthn_rp_id.is_empty());
        assert!(trust.astra_policy_fingerprint.is_empty());
        assert_eq!(trust.credential_registry_epoch, 0);
        assert!(
            trust.validate().is_err(),
            "an old profile must be re-issued, not silently upgraded"
        );
    }

    /// A v4 manifest carries no discriminant, and is read as **undeclared**.
    ///
    /// Not as classic: the difference is the point of the field. An undeclared
    /// profile still resolves through the historical inference, so it connects
    /// exactly as it did — and re-sealing writes the answer down, which is
    /// what stops the guess from being made a second time.
    #[test]
    fn a_v4_manifest_is_undeclared_and_resolves_by_the_old_inference() {
        let source = profile();
        let block = source.key_negotiation.as_ref().expect("negotiation block");
        let mut v4 = Vec::new();
        v4.push(MANIFEST_VERSION_WITHOUT_PROFILE_KIND);
        v4.extend_from_slice(&12u64.to_be_bytes());
        codec::put(&mut v4, source.name.as_bytes()).unwrap();
        codec::put(&mut v4, source.endpoint.as_bytes()).unwrap();
        codec::put(&mut v4, source.private_key.expose().as_bytes()).unwrap();
        codec::put(&mut v4, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(
            &mut v4,
            source
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose)
                .map(str::as_bytes),
        )
        .unwrap();
        codec::put_option(&mut v4, source.address.as_deref().map(str::as_bytes)).unwrap();
        codec::put(&mut v4, source.allowed_ips.as_bytes()).unwrap();
        v4.extend_from_slice(&source.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut v4, source.heliosd_url.as_deref().map(str::as_bytes)).unwrap();
        codec::put_option(&mut v4, source.ssh_target.as_deref().map(str::as_bytes)).unwrap();
        v4.push(1);
        v4.push(mode_id(block.mode));
        v4.push(mode_id(block.minimum_mode));
        codec::put(&mut v4, block.endpoint.as_bytes()).unwrap();
        codec::put(&mut v4, block.server_name.as_bytes()).unwrap();
        codec::put(&mut v4, block.gateway_ca_der.as_bytes()).unwrap();
        codec::put(&mut v4, block.gateway_pq_certificate.as_bytes()).unwrap();
        codec::put(&mut v4, block.identity.as_bytes()).unwrap();
        v4.push(0);

        let decoded = ProfileManifest::decode(&v4).expect("v4 remains decryptable");
        assert_eq!(decoded.profile_type, None, "a v4 manifest declares nothing");
        let restored = decoded.to_profile();
        assert_eq!(restored.kind(), ProfileKind::HeliosKeyNegotiation);
        assert!(restored.negotiates());

        // Re-sealing records the answer, so the inference happens once.
        let resealed = ProfileManifest::from_profile(&restored, SecurityGeneration(13));
        assert_eq!(
            resealed.profile_type,
            Some(ProfileKind::HeliosKeyNegotiation)
        );
    }

    /// The byte is what decides whether a profile negotiates, so its
    /// identifiers are pinned rather than derived from the enum order.
    #[test]
    fn profile_kind_identifiers_are_stable() {
        assert_eq!(profile_kind_id(None), 0);
        assert_eq!(profile_kind_id(Some(ProfileKind::Classic)), 1);
        assert_eq!(profile_kind_id(Some(ProfileKind::HeliosKeyNegotiation)), 2);
        assert!(profile_kind_from_id(3).is_err());
    }

    /// An unknown version is still refused — compatibility is a list, not a
    /// tolerance.
    #[test]
    fn an_unknown_manifest_version_is_still_refused() {
        let encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode");
        let mut future = encoded.to_vec();
        future[0] = MANIFEST_VERSION + 1;
        assert!(matches!(
            ProfileManifest::decode(&future),
            Err(VaultError::UnsupportedManifest(_))
        ));
    }

    /// A profile without an IPv6 address is sealed exactly as before the
    /// field existed: same version byte, same bytes. Built by hand in the v7
    /// layout, for the reason given on the v1 test — the encoder agreeing
    /// with itself proves nothing about the bytes an older Orion reads.
    #[test]
    fn a_profile_without_ipv6_is_sealed_in_the_previous_layout() {
        let source = profile();
        let settings = negotiation();
        let mut v7: Vec<u8> = Vec::new();
        v7.push(MANIFEST_VERSION_WITHOUT_ADDRESS_V6);
        v7.extend_from_slice(&3u64.to_be_bytes());
        codec::put(&mut v7, source.name.as_bytes()).unwrap();
        codec::put(&mut v7, source.endpoint.as_bytes()).unwrap();
        codec::put(&mut v7, source.private_key.expose().as_bytes()).unwrap();
        codec::put(&mut v7, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(
            &mut v7,
            source
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose)
                .map(str::as_bytes),
        )
        .unwrap();
        codec::put_option(&mut v7, source.address.as_deref().map(str::as_bytes)).unwrap();
        codec::put(&mut v7, source.allowed_ips.as_bytes()).unwrap();
        v7.extend_from_slice(&source.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut v7, source.heliosd_url.as_deref().map(str::as_bytes)).unwrap();
        codec::put_option(&mut v7, source.ssh_target.as_deref().map(str::as_bytes)).unwrap();
        v7.push(2); // helios_key_negotiation
        v7.push(1); // key-negotiation block present
        v7.push(mode_id(settings.mode));
        v7.push(mode_id(settings.minimum_mode));
        codec::put(&mut v7, settings.endpoint.as_bytes()).unwrap();
        codec::put(&mut v7, settings.server_name.as_bytes()).unwrap();
        codec::put(&mut v7, settings.gateway_ca_der.as_bytes()).unwrap();
        codec::put(&mut v7, settings.gateway_pq_certificate.as_bytes()).unwrap();
        codec::put(&mut v7, settings.identity.as_bytes()).unwrap();
        v7.push(0); // no trust material

        let encoded = ProfileManifest::from_profile(&source, SecurityGeneration(3))
            .encode()
            .expect("encode");
        assert_eq!(encoded.as_slice(), v7.as_slice());
        let decoded = ProfileManifest::decode(&v7).expect("a v7 manifest still opens");
        assert_eq!(decoded.address_v6, None, "absent, not invented");
        assert_eq!(decoded.to_profile().address, source.address);
    }

    /// An IPv6 address moves the profile to the version that carries it, so
    /// an Orion that cannot apply it refuses the profile instead of mounting
    /// an IPv4-only adapter in silence.
    #[test]
    fn an_ipv6_address_is_sealed_in_its_own_version_and_round_trips() {
        let mut dual = profile();
        dual.address_v6 = Some("fd3c:91a2:7e04::2/128".into());
        let encoded = ProfileManifest::from_profile(&dual, SecurityGeneration(4))
            .encode()
            .expect("encode");
        assert_eq!(encoded[0], MANIFEST_VERSION);

        let decoded = ProfileManifest::decode(&encoded).expect("decode");
        let rebuilt = decoded.to_profile();
        assert_eq!(rebuilt.address.as_deref(), Some("100.64.1.2/32"));
        assert_eq!(rebuilt.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));

        // The field is the trailing one of its version: cut it, and the
        // manifest is refused rather than read as an IPv4-only profile.
        let without_trailer = &encoded[..encoded.len() - 1];
        assert!(ProfileManifest::decode(without_trailer).is_err());
    }

    /// The version that exists to carry the address never carries an empty
    /// one: an encoder that wrote it so is a bug, not a profile.
    #[test]
    fn an_empty_ipv6_address_in_its_own_version_is_refused() {
        let encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode");
        let mut forged = encoded.to_vec();
        forged[0] = MANIFEST_VERSION;
        codec::put(&mut forged, b"").unwrap();
        assert!(matches!(
            ProfileManifest::decode(&forged),
            Err(VaultError::ManifestEncoding(_))
        ));
    }

    #[test]
    fn a_minimal_manifest_round_trips() {
        let mut bare = profile();
        bare.preshared_key = None;
        bare.address = None;
        bare.heliosd_url = None;
        bare.ssh_target = None;
        bare.key_negotiation = None;
        let encoded = ProfileManifest::from_profile(&bare, SecurityGeneration::default())
            .encode()
            .expect("encode");
        let decoded = ProfileManifest::decode(&encoded)
            .expect("decode")
            .to_profile();
        assert!(decoded.preshared_key.is_none());
        assert!(decoded.address.is_none());
        assert!(decoded.heliosd_url.is_none());
        assert!(decoded.key_negotiation.is_none());
    }

    /// The property that justifies putting these fields inside the AEAD: an
    /// attacker who cannot read the manifest must not be able to redirect the
    /// tunnel, swap the trust anchor or lower the floor either.
    #[test]
    fn the_manifest_carries_every_field_that_decides_the_tunnel() {
        let encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode");
        for expected in [
            "203.0.113.10:51820", // endpoint
            "cHVibGlj",           // gateway public key
            "0.0.0.0/0",          // captured range
            "MIIB",               // pinned CA
            "e30=",               // pinned PQ certificate
            "vpn.example.net",    // authenticated server name
            "poste",              // display name
        ] {
            assert!(
                encoded
                    .windows(expected.len())
                    .any(|w| w == expected.as_bytes()),
                "{expected} is not inside the manifest and could be altered from outside"
            );
        }
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode")
            .to_vec();
        encoded[0] = 42;
        assert!(matches!(
            ProfileManifest::decode(&encoded),
            Err(VaultError::UnsupportedManifest(42))
        ));
    }

    /// Silently ignoring trailing bytes is how an encoder and a decoder fork
    /// without anyone noticing.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode")
            .to_vec();
        encoded.push(0);
        assert!(ProfileManifest::decode(&encoded).is_err());
    }

    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode");
        for cut in 0..encoded.len() {
            assert!(
                ProfileManifest::decode(&encoded[..cut]).is_err(),
                "a truncated manifest decoded at {cut}"
            );
        }
    }

    /// A lying length must produce an error, never an allocation sized by the
    /// attacker nor a panic.
    #[test]
    fn a_lying_field_length_is_refused() {
        let mut encoded = ProfileManifest::from_profile(&profile(), SecurityGeneration(1))
            .encode()
            .expect("encode")
            .to_vec();
        // First field length lives right after version + generation.
        encoded[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ProfileManifest::decode(&encoded).is_err());
    }

    /// Protection modes are stored as explicit identifiers, so reordering the
    /// enum cannot silently reinterpret a stored profile's protection level.
    #[test]
    fn protection_modes_have_stable_identifiers() {
        assert_eq!(mode_id(ProtectionMode::Classic), 0);
        assert_eq!(mode_id(ProtectionMode::StaticPsk), 1);
        assert_eq!(mode_id(ProtectionMode::MlKem), 2);
        assert!(mode_from_id(3).is_err());
    }

    #[test]
    fn a_generation_never_wraps_to_zero() {
        assert_eq!(
            SecurityGeneration(u64::MAX).next(),
            SecurityGeneration(u64::MAX)
        );
        assert_eq!(SecurityGeneration(4).next(), SecurityGeneration(5));
    }
}
