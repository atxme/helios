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
use crate::config::{ClientProfile, KeyNegotiationSettings};
use aether::key_negotiation::ProtectionMode;

/// Version written today. Any version not listed below is refused, never
/// guessed.
const MANIFEST_VERSION: u8 = 4;

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
    pub private_key: Zeroizing<String>,
    pub peer_public_key: String,
    /// **Secret**, when a static PSK is in use.
    pub preshared_key: Option<Zeroizing<String>>,
    pub address: Option<String>,
    pub allowed_ips: String,
    pub persistent_keepalive: u16,
    pub heliosd_url: Option<String>,
    pub ssh_target: Option<String>,
    pub key_negotiation: Option<KeyNegotiationSettings>,
}

impl ProfileManifest {
    /// Builds a manifest from the profile shape the UI edits.
    pub fn from_profile(profile: &ClientProfile, generation: SecurityGeneration) -> Self {
        Self {
            generation,
            name: profile.name.clone(),
            endpoint: profile.endpoint.clone(),
            private_key: Zeroizing::new(profile.private_key.clone()),
            peer_public_key: profile.peer_public_key.clone(),
            preshared_key: profile.preshared_key.clone().map(Zeroizing::new),
            address: profile.address.clone(),
            allowed_ips: profile.allowed_ips.clone(),
            persistent_keepalive: profile.persistent_keepalive,
            heliosd_url: profile.heliosd_url.clone(),
            ssh_target: profile.ssh_target.clone(),
            key_negotiation: profile.key_negotiation.clone(),
        }
    }

    /// Rebuilds the profile the rest of the client works with.
    pub fn to_profile(&self) -> ClientProfile {
        ClientProfile {
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            private_key: self.private_key.as_str().to_string(),
            peer_public_key: self.peer_public_key.clone(),
            preshared_key: self
                .preshared_key
                .as_ref()
                .map(|psk| psk.as_str().to_string()),
            address: self.address.clone(),
            allowed_ips: self.allowed_ips.clone(),
            persistent_keepalive: self.persistent_keepalive,
            heliosd_url: self.heliosd_url.clone(),
            ssh_target: self.ssh_target.clone(),
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
            Some(psk) => field(psk.as_bytes()),
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
        out.push(MANIFEST_VERSION);
        out.extend_from_slice(&self.generation.0.to_be_bytes());
        codec::put(&mut out, self.name.as_bytes())?;
        codec::put(&mut out, self.endpoint.as_bytes())?;
        codec::put(&mut out, self.private_key.as_bytes())?;
        codec::put(&mut out, self.peer_public_key.as_bytes())?;
        codec::put_option(&mut out, self.preshared_key.as_ref().map(|v| v.as_bytes()))?;
        codec::put_option(&mut out, self.address.as_deref().map(str::as_bytes))?;
        codec::put(&mut out, self.allowed_ips.as_bytes())?;
        out.extend_from_slice(&self.persistent_keepalive.to_be_bytes());
        codec::put_option(&mut out, self.heliosd_url.as_deref().map(str::as_bytes))?;
        codec::put_option(&mut out, self.ssh_target.as_deref().map(str::as_bytes))?;
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
                        out.extend_from_slice(&trust.astra_service_key_epoch.to_be_bytes());
                        codec::put(&mut out, trust.astra_service_public_key.as_bytes())?;
                    }
                }
            }
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
            && version != MANIFEST_VERSION_WITHOUT_ASTRA_POLICY
            && version != MANIFEST_VERSION_WITHOUT_TRUST
            && version != MANIFEST_VERSION_WITHOUT_SSH
        {
            return Err(VaultError::UnsupportedManifest(version));
        }
        let generation = SecurityGeneration(u64::from_be_bytes(cursor.array::<8>()?));
        let name = cursor.text()?;
        let endpoint = cursor.text()?;
        let private_key = Zeroizing::new(cursor.text()?);
        let peer_public_key = cursor.text()?;
        let preshared_key = cursor.option_text()?.map(Zeroizing::new);
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
                trust: if version == MANIFEST_VERSION
                    || version == MANIFEST_VERSION_WITHOUT_ASTRA_POLICY
                {
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
                            webauthn_rp_id: if version == MANIFEST_VERSION {
                                cursor.text()?
                            } else {
                                String::new()
                            },
                            astra_policy_fingerprint: if version == MANIFEST_VERSION {
                                cursor.text()?
                            } else {
                                String::new()
                            },
                            credential_registry_epoch: if version == MANIFEST_VERSION {
                                u64::from_be_bytes(cursor.array::<8>()?)
                            } else {
                                0
                            },
                            astra_service_key_epoch: u64::from_be_bytes(cursor.array::<8>()?),
                            astra_service_public_key: cursor.text()?,
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
            allowed_ips,
            persistent_keepalive,
            heliosd_url,
            ssh_target,
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
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: 25,
            heliosd_url: Some("http://100.64.0.1:8080".into()),
            ssh_target: Some("christophe@100.64.0.1".into()),
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
        codec::put(&mut v1, source.private_key.as_bytes()).unwrap();
        codec::put(&mut v1, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(&mut v1, source.preshared_key.as_deref().map(str::as_bytes)).unwrap();
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
        assert_eq!(resealed[0], MANIFEST_VERSION);
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
            astra_service_key_epoch: 5,
            astra_service_public_key: "c2VydmljZQ==".into(),
        });

        let original_digest =
            ProfileManifest::from_profile(&source, SecurityGeneration(1)).security_digest();
        let mut changed_policy = source.clone();
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
        codec::put(&mut v2, source.private_key.as_bytes()).unwrap();
        codec::put(&mut v2, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(&mut v2, source.preshared_key.as_deref().map(str::as_bytes)).unwrap();
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
        assert_eq!(resealed[0], MANIFEST_VERSION);
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
        codec::put(&mut v3, source.private_key.as_bytes()).unwrap();
        codec::put(&mut v3, source.peer_public_key.as_bytes()).unwrap();
        codec::put_option(&mut v3, source.preshared_key.as_deref().map(str::as_bytes)).unwrap();
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
