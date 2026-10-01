//! Hybrid signatures of the publisher's trust artifacts.
//!
//! The policy is deliberately non-configurable: Ed25519 **and** ML-DSA-65
//! must both verify the same canonical message. Unknown additional
//! algorithms are ignored to allow future extension, but removing one of
//! the two required signatures is always a rejection.

use std::collections::HashSet;

use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use fips204::{
    ml_dsa_65::{self, PublicKey},
    traits::{SerDes, Verifier},
};
use serde::{Deserialize, Serialize};

/// Size of a raw Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Size of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Size of a serialized ML-DSA-65 public key (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
/// Size of a serialized ML-DSA-65 private key (publisher tool only).
#[cfg(feature = "publisher-signing")]
pub const ML_DSA_65_PRIVATE_KEY_LEN: usize = ml_dsa_65::SK_LEN;
/// Size of an ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// Algorithms understood by this verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgId {
    Ed25519,
    MlDsa65,
}

impl AlgId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ed25519" => Some(Self::Ed25519),
            "ml-dsa-65" => Some(Self::MlDsa65),
            _ => None,
        }
    }
}

impl std::fmt::Display for AlgId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Anti-downgrade policy compiled into every verifier.
pub const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];

/// Publisher public keys for one epoch.
#[derive(Clone, Copy)]
pub struct PublisherPublicKeys {
    pub key_epoch: u32,
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    pub ml_dsa_65: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

impl PublisherPublicKeys {
    /// Displayable fingerprint of the trust anchor, for visual comparison
    /// with what the publisher publishes out-of-band.
    ///
    /// Both keys are hashed **together**: the fingerprint identifies the
    /// epoch as a whole, not one of its halves. An operator comparing it
    /// therefore cannot validate a keyring where only the Ed25519 part is
    /// correct. Truncated to 128 bits — this is a comparison memory aid, not
    /// a security check: the real anchor is compiled into the binary.
    pub fn fingerprint(&self) -> String {
        let mut material = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_65_PUBLIC_KEY_LEN);
        material.extend_from_slice(&self.ed25519);
        material.extend_from_slice(&self.ml_dsa_65);
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &material);
        hex::encode(&digest.as_ref()[..16])
    }
}

// Generated from the public file designated at build time. In release, the
// build script refuses the development keyring shipped with the tests.
include!(concat!(env!("OUT_DIR"), "/publisher_keyring.rs"));

/// A signature encoded in base64 in the JSON envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    pub alg: String,
    pub sig: String,
}

/// Envelope common to every signed artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<P> {
    pub payload: P,
    pub key_epoch: u32,
    pub signatures: Vec<ArtifactSignature>,
}

/// Canonical serialization and domain specific to an artifact.
pub trait ArtifactPayload {
    /// Full domain, distinct for each artifact type.
    const DOMAIN: &'static [u8];
    /// Format version encoded as 32-bit big-endian in the message.
    const FORMAT_VERSION: u32;

    /// Appends the canonical payload to `output`, without going through JSON.
    fn encode_canonical(&self, output: &mut Vec<u8>);
}

/// Verification backend for a signature algorithm.
pub trait SignatureSuite {
    const ALGORITHM: AlgId;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub struct Ed25519Suite;

impl SignatureSuite for Ed25519Suite {
    const ALGORITHM: AlgId = AlgId::Ed25519;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if !ed25519_inputs_are_strict(public_key, signature) {
            return false;
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    }
}

/// AWS-LC 1.17.1 notably accepts a forgery with the key and `R` at the
/// identity point. These pre-checks explicitly preserve the guarantees of
/// `ed25519-dalek::verify_strict()` before delegating the equation to
/// AWS-LC.
fn ed25519_inputs_are_strict(public_key: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; ED25519_SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let Some(public_point) = CompressedEdwardsY(public_key).decompress() else {
        return false;
    };
    let Ok(encoded_r) = <[u8; 32]>::try_from(&signature[..32]) else {
        return false;
    };
    let Some(signature_r) = CompressedEdwardsY(encoded_r).decompress() else {
        return false;
    };
    if public_point.is_small_order() || signature_r.is_small_order() {
        return false;
    }
    let Ok(encoded_s) = <[u8; 32]>::try_from(&signature[32..]) else {
        return false;
    };
    bool::from(Scalar::from_canonical_bytes(encoded_s).is_some())
}

pub struct MlDsa65Suite;

impl SignatureSuite for MlDsa65Suite {
    const ALGORITHM: AlgId = AlgId::MlDsa65;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public_key) = <[u8; ML_DSA_65_PUBLIC_KEY_LEN]>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = <[u8; ML_DSA_65_SIGNATURE_LEN]>::try_from(signature) else {
            return false;
        };
        let Ok(public_key) = PublicKey::try_from_bytes(public_key) else {
            return false;
        };
        public_key.verify(message, &signature, &[])
    }
}

/// Fail-closed errors of the hybrid envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("unknown publisher key epoch: {0}")]
    UnknownKeyEpoch(u32),
    #[error("required signature missing: {0}")]
    MissingRequiredAlgorithm(AlgId),
    #[error("duplicate signature algorithm: {0}")]
    DuplicateAlgorithm(AlgId),
    #[error("signature {0} malformed")]
    InvalidEncoding(AlgId),
    #[error("signature {0} invalid")]
    InvalidSignature(AlgId),
    #[cfg(feature = "publisher-signing")]
    #[error("invalid publisher private key: {0}")]
    InvalidPrivateKey(&'static str),
    #[cfg(feature = "publisher-signing")]
    #[error("publisher signing operation failed: {0}")]
    Signing(&'static str),
}

impl<P: ArtifactPayload> SignedEnvelope<P> {
    /// Verifies the authenticated epoch then every required signature.
    pub fn verify(&self, keyring: &[PublisherPublicKeys]) -> Result<(), SignatureError> {
        let keys = keyring
            .iter()
            .find(|keys| keys.key_epoch == self.key_epoch)
            .ok_or(SignatureError::UnknownKeyEpoch(self.key_epoch))?;
        let message = signing_bytes(&self.payload, self.key_epoch);
        let mut seen = HashSet::new();

        for entry in &self.signatures {
            let Some(algorithm) = AlgId::parse(&entry.alg) else {
                // Forward extension: the compiled policy will decide when it becomes required.
                continue;
            };
            if !seen.insert(algorithm) {
                return Err(SignatureError::DuplicateAlgorithm(algorithm));
            }
            let signature = STANDARD
                .decode(&entry.sig)
                .map_err(|_| SignatureError::InvalidEncoding(algorithm))?;
            let valid = match algorithm {
                AlgId::Ed25519 => Ed25519Suite::verify(&keys.ed25519, &message, &signature),
                AlgId::MlDsa65 => MlDsa65Suite::verify(&keys.ml_dsa_65, &message, &signature),
            };
            if !valid {
                return Err(SignatureError::InvalidSignature(algorithm));
            }
        }

        for required in REQUIRED_ALGS {
            if !seen.contains(required) {
                return Err(SignatureError::MissingRequiredAlgorithm(*required));
            }
        }
        Ok(())
    }
}

/// Signed bytes: domain || format version || epoch || canonical payload.
pub fn signing_bytes<P: ArtifactPayload>(payload: &P, key_epoch: u32) -> Vec<u8> {
    let mut message = Vec::with_capacity(P::DOMAIN.len() + 8 + 64);
    message.extend_from_slice(P::DOMAIN);
    message.extend_from_slice(&P::FORMAT_VERSION.to_be_bytes());
    message.extend_from_slice(&key_epoch.to_be_bytes());
    payload.encode_canonical(&mut message);
    message
}

/// Payload of the TPM v2 reseal ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResealPayload {
    pub version: u64,
    #[serde(
        default,
        serialize_with = "serialize_optional_digest",
        deserialize_with = "deserialize_optional_digest"
    )]
    pub expected_pcr_digest: Option<[u8; 32]>,
}

impl ArtifactPayload for ResealPayload {
    const DOMAIN: &'static [u8] = b"helios-tpm-reseal-v2";
    const FORMAT_VERSION: u32 = 2;

    fn encode_canonical(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.version.to_be_bytes());
        match self.expected_pcr_digest {
            Some(digest) => {
                output.push(1);
                output.extend_from_slice(&digest);
            }
            None => output.push(0),
        }
    }
}

pub type SignedResealTicket = SignedEnvelope<ResealPayload>;

/// Authorizes restoration of one existing TPM root after planned firmware
/// maintenance. This domain never authorizes creation of a replacement root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareRecoveryPayload {
    pub version: u64,
    #[serde(
        serialize_with = "serialize_digest",
        deserialize_with = "deserialize_digest"
    )]
    pub sealed_blob_anchor: [u8; 32],
    #[serde(
        serialize_with = "serialize_digest",
        deserialize_with = "deserialize_digest"
    )]
    pub secret_commitment: [u8; 32],
    pub device_id: String,
    pub target_version: String,
}

impl FirmwareRecoveryPayload {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version == 0 {
            return Err("firmware recovery version must be positive");
        }
        if self.device_id.len() != 40 || !self.device_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid firmware device identifier");
        }
        if self.target_version.is_empty()
            || self.target_version.starts_with('-')
            || self.target_version.len() > 128
            || !self
                .target_version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
        {
            return Err("invalid firmware target version");
        }
        Ok(())
    }
}

impl ArtifactPayload for FirmwareRecoveryPayload {
    const DOMAIN: &'static [u8] = b"helios-firmware-recovery-v1";
    const FORMAT_VERSION: u32 = 1;

    fn encode_canonical(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&self.sealed_blob_anchor);
        output.extend_from_slice(&self.secret_commitment);
        encode_string(output, &self.device_id);
        encode_string(output, &self.target_version);
    }
}

pub type SignedFirmwareRecovery = SignedEnvelope<FirmwareRecoveryPayload>;

/// Signed metadata of a distributable `heliosd` binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryReleasePayload {
    pub product: String,
    pub channel: String,
    pub release_sequence: u64,
    pub version: String,
    pub git_commit: String,
    pub target: String,
    pub features: Vec<String>,
    pub binary_size: u64,
    #[serde(
        serialize_with = "serialize_digest",
        deserialize_with = "deserialize_digest"
    )]
    pub sha256: [u8; 32],
    pub minimum_installer_version: u32,
}

impl ArtifactPayload for BinaryReleasePayload {
    const DOMAIN: &'static [u8] = b"helios-binary-release-v1";
    const FORMAT_VERSION: u32 = 1;

    fn encode_canonical(&self, output: &mut Vec<u8>) {
        encode_string(output, &self.product);
        encode_string(output, &self.channel);
        output.extend_from_slice(&self.release_sequence.to_be_bytes());
        encode_string(output, &self.version);
        encode_string(output, &self.git_commit);
        encode_string(output, &self.target);
        output.extend_from_slice(&(self.features.len() as u32).to_be_bytes());
        for feature in &self.features {
            encode_string(output, feature);
        }
        output.extend_from_slice(&self.binary_size.to_be_bytes());
        output.extend_from_slice(&self.sha256);
        output.extend_from_slice(&self.minimum_installer_version.to_be_bytes());
    }
}

pub type SignedBinaryRelease = SignedEnvelope<BinaryReleasePayload>;

/// A bundle file, designated by its relative path and its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    /// Path **relative** to the bundle root, `/`-separated.
    pub path: String,
    pub size: u64,
    #[serde(
        serialize_with = "serialize_digest",
        deserialize_with = "deserialize_digest"
    )]
    pub sha256: [u8; 32],
    /// Executable file: installed as 0755, otherwise as 0644.
    pub executable: bool,
}

/// Signed metadata of a complete installation bundle.
///
/// # Why a second artifact type rather than the binary manifest
///
/// [`BinaryReleasePayload`] authenticates **one** executable: that is what
/// the application update mechanism (ADR-003) needs, and nothing more. An
/// installation bundle also carries the installer program, the operations
/// tool and the systemd units. Shipping them under the authority of a
/// signature that does not cover them would amount to displaying a false
/// guarantee: the systemd unit decides the daemon's command line, it is just
/// as sensitive as the binary it launches.
///
/// The domain is distinct (`helios-bundle-v1`), so a bundle's signature
/// cannot be replayed as a binary release signature, nor the reverse
/// (ADR-002 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePayload {
    pub product: String,
    pub channel: String,
    pub release_sequence: u64,
    pub version: String,
    pub git_commit: String,
    pub target: String,
    pub minimum_installer_version: u32,
    /// Exhaustive content, sorted by path. A file present in the archive but
    /// absent here must make installation fail.
    pub files: Vec<BundleEntry>,
}

/// Rejection of bundle content, before even looking at the signatures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("bundle with no declared file")]
    Empty,
    #[error("invalid bundle path: {0}")]
    Path(String),
    #[error("file list not sorted or duplicated at \"{0}\"")]
    Order(String),
}

impl BundlePayload {
    /// Validates the shape of the file list.
    ///
    /// Call **before** extracting anything. An absolute or ascending path
    /// (`..`) would write outside the intended destination; an unsorted list
    /// would make the canonical encoding ambiguous, and a duplicate would
    /// allow declaring two digests for the same file.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.files.is_empty() {
            return Err(BundleError::Empty);
        }
        let mut previous: Option<&str> = None;
        for entry in &self.files {
            validate_bundle_path(&entry.path)?;
            if let Some(previous) = previous {
                if entry.path.as_str() <= previous {
                    return Err(BundleError::Order(entry.path.clone()));
                }
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }

    /// Entry matching a relative path, if declared.
    pub fn entry(&self, path: &str) -> Option<&BundleEntry> {
        self.files.iter().find(|entry| entry.path == path)
    }
}

fn validate_bundle_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(BundleError::Path(path.to_string()));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(BundleError::Path(path.to_string()));
    }
    Ok(())
}

impl ArtifactPayload for BundlePayload {
    const DOMAIN: &'static [u8] = b"helios-bundle-v1";
    const FORMAT_VERSION: u32 = 1;

    fn encode_canonical(&self, output: &mut Vec<u8>) {
        encode_string(output, &self.product);
        encode_string(output, &self.channel);
        output.extend_from_slice(&self.release_sequence.to_be_bytes());
        encode_string(output, &self.version);
        encode_string(output, &self.git_commit);
        encode_string(output, &self.target);
        output.extend_from_slice(&self.minimum_installer_version.to_be_bytes());
        output.extend_from_slice(&(self.files.len() as u32).to_be_bytes());
        for entry in &self.files {
            encode_string(output, &entry.path);
            output.extend_from_slice(&entry.size.to_be_bytes());
            output.extend_from_slice(&entry.sha256);
            output.push(u8::from(entry.executable));
        }
    }
}

pub type SignedBundle = SignedEnvelope<BundlePayload>;

fn encode_string(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn serialize_digest<S>(digest: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(digest))
}

fn deserialize_digest<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    hex::decode(encoded)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| serde::de::Error::custom("invalid SHA-256 hex"))
}

fn serialize_optional_digest<S>(digest: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    digest.as_ref().map(hex::encode).serialize(serializer)
}

fn deserialize_optional_digest<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = Option::<String>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            hex::decode(value)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| serde::de::Error::custom("invalid PCR digest hex"))
        })
        .transpose()
}

#[cfg(feature = "publisher-signing")]
mod signing {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use fips204::{
        ml_dsa_65::{self, PrivateKey},
        traits::{KeyGen, SerDes, Signer},
    };

    use super::*;

    /// Private key pair loaded only by the publisher tool.
    pub struct PublisherSigner {
        key_epoch: u32,
        ed25519: Ed25519KeyPair,
        ml_dsa_65: PrivateKey,
    }

    impl PublisherSigner {
        /// Loads two serialized private keys consistent with an epoch.
        pub fn from_private_keys(
            key_epoch: u32,
            ed25519_pkcs8: &[u8],
            ml_dsa_65: &[u8],
        ) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::from_pkcs8(ed25519_pkcs8)
                .map_err(|_| SignatureError::InvalidPrivateKey("Ed25519 PKCS#8"))?;
            let ml_dsa_65 = <[u8; ml_dsa_65::SK_LEN]>::try_from(ml_dsa_65)
                .map_err(|_| SignatureError::InvalidPrivateKey("ML-DSA-65 length"))?;
            let ml_dsa_65 =
                PrivateKey::try_from_bytes(ml_dsa_65).map_err(SignatureError::InvalidPrivateKey)?;
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        /// Rebuilds both keys from their raw 32-byte seeds.
        /// Prefer PKCS#8 and [`Self::from_private_keys`] for real storage.
        pub fn from_seed_material(
            key_epoch: u32,
            ed25519_seed: &[u8; 32],
            ml_dsa_65_seed: &[u8; 32],
        ) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::from_seed_unchecked(ed25519_seed)
                .map_err(|_| SignatureError::InvalidPrivateKey("Ed25519 seed"))?;
            let (_, ml_dsa_65) = ml_dsa_65::KG::keygen_from_seed(ml_dsa_65_seed);
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        /// Generates off-gateway both key pairs for a new epoch.
        pub fn generate(key_epoch: u32) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::generate()
                .map_err(|_| SignatureError::Signing("Ed25519 generation"))?;
            let (_, ml_dsa_65) = ml_dsa_65::try_keygen().map_err(SignatureError::Signing)?;
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        pub const fn key_epoch(&self) -> u32 {
            self.key_epoch
        }

        /// Extracts the public keys destined for the compiled keyring.
        pub fn public_keys(&self) -> PublisherPublicKeys {
            let ed25519 = self
                .ed25519
                .public_key()
                .as_ref()
                .try_into()
                .expect("AWS-LC guarantees 32 bytes for Ed25519");
            let ml_dsa_65 = self.ml_dsa_65.get_public_key().into_bytes();
            PublisherPublicKeys {
                key_epoch: self.key_epoch,
                ed25519,
                ml_dsa_65,
            }
        }

        /// Serializes the secrets for offline storage.
        pub fn private_key_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), SignatureError> {
            let ed25519 = self
                .ed25519
                .to_pkcs8()
                .map_err(|_| SignatureError::Signing("Ed25519 PKCS#8 serialization"))?;
            let ml_dsa_65 = self.ml_dsa_65.clone().into_bytes();
            Ok((ed25519.as_ref().to_vec(), ml_dsa_65.to_vec()))
        }

        /// Produces the hybrid envelope; both signatures cover the same bytes.
        pub fn sign<P: ArtifactPayload>(
            &self,
            payload: P,
        ) -> Result<SignedEnvelope<P>, SignatureError> {
            let message = signing_bytes(&payload, self.key_epoch);
            let ed25519 = self
                .ed25519
                .try_sign(&message)
                .map_err(|_| SignatureError::Signing("Ed25519"))?;
            let ml_dsa_65 = self
                .ml_dsa_65
                .try_sign(&message, &[])
                .map_err(SignatureError::Signing)?;
            Ok(SignedEnvelope {
                payload,
                key_epoch: self.key_epoch,
                signatures: vec![
                    ArtifactSignature {
                        alg: AlgId::Ed25519.as_str().to_string(),
                        sig: STANDARD.encode(ed25519.as_ref()),
                    },
                    ArtifactSignature {
                        alg: AlgId::MlDsa65.as_str().to_string(),
                        sig: STANDARD.encode(ml_dsa_65),
                    },
                ],
            })
        }
    }
}

#[cfg(feature = "publisher-signing")]
pub use signing::PublisherSigner;

#[cfg(test)]
mod tests;
