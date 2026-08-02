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

/// Manifest encoding version. Any other value is refused, never guessed.
const MANIFEST_VERSION: u8 = 1;

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
        if version != MANIFEST_VERSION {
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
        let block = rebuilt.key_negotiation.expect("negotiation block");
        assert_eq!(block.mode, ProtectionMode::MlKem);
        assert_eq!(block.minimum_mode, ProtectionMode::StaticPsk);
        assert_eq!(block.identity, "orion-poste");
    }

    #[test]
    fn a_minimal_manifest_round_trips() {
        let mut bare = profile();
        bare.preshared_key = None;
        bare.address = None;
        bare.heliosd_url = None;
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
