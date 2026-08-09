//! Bounded wire types and the canonical byte encoding every signature covers.
//!
//! The certificate lifecycle signs **binary transcripts**, never the JSON that
//! transports them. Two rules make that safe and are enforced here rather than
//! at each call site:
//!
//! - every variable-length field is length-prefixed with a `u32`, so no two
//!   field boundaries can be shifted to produce the same concatenation;
//! - every fixed-length field is decoded to its bytes before it is signed. A
//!   fingerprint is 32 bytes in the transcript and lowercase hexadecimal in
//!   JSON; a WireGuard key is 32 bytes in the transcript and base64 in JSON.
//!
//! The types below refuse malformed values at **deserialization**, which is
//! what lets the verifiers read like the specification: by the time an object
//! exists, its keys are the right length and its fingerprints are canonical.
//! A `String` field validated three screens later would eventually be
//! validated only twice.
//!
//! This is a deliberate divergence from [`crate::key_negotiation`], whose four
//! oldest messages sign canonical *text* with a length prefix. Those have
//! deployed signatures to preserve; these domains are new, so they follow the
//! specification to the letter. Two encodings under two distinct domain
//! separators cannot be confused for one another.

use std::fmt;

use aws_lc_rs::{constant_time, digest};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fips204::{
    ml_dsa_87::{self, PublicKey},
    traits::{SerDes, Verifier},
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use super::CertificateError;

/// Length of every fingerprint in this module: SHA-256.
pub const FINGERPRINT_LEN: usize = 32;
/// Length of a trust-domain identifier and of every opaque operation nonce.
pub const ID_LEN: usize = 16;
/// Length of a WireGuard Curve25519 public key.
pub const WIREGUARD_KEY_LEN: usize = crate::wg::KEY_LEN;

/// Upper bound for one DER certificate carried by a signed object.
///
/// A classical X.509 leaf is a couple of kilobytes; sixteen leaves room for an
/// intermediate with large extensions while keeping a bounded parse cost on a
/// public endpoint.
pub const MAX_DER_CERTIFICATE_BYTES: usize = 16 * 1024;

/// Domain separator of the `CA-PQ` fingerprint (spec §2.3).
///
/// A CA fingerprint is **not** the SHA-256 of a bare public key: the prefix
/// keeps it from ever colliding with a leaf fingerprint or with a hash
/// computed elsewhere over the same bytes.
const CA_FINGERPRINT_DOMAIN: &[u8] = b"helios-key-negotiation-ca-fingerprint-v5";

/// SHA-256 fingerprint, hexadecimal in JSON and 32 raw bytes when signed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_LEN]) -> Self {
        Self(bytes)
    }

    /// SHA-256 of `input`.
    pub fn of(input: &[u8]) -> Self {
        let digest = digest::digest(&digest::SHA256, input);
        let mut bytes = [0u8; FINGERPRINT_LEN];
        bytes.copy_from_slice(digest.as_ref());
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Parses the lowercase hexadecimal form, and only that form.
    ///
    /// Uppercase is refused rather than normalized: a fingerprint is compared
    /// against signed bytes, and accepting two spellings of the same value
    /// means two chances to compare the wrong one.
    pub fn parse_hex(value: &str) -> Result<Self, CertificateError> {
        if value.len() != FINGERPRINT_LEN * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CertificateError::InvalidFingerprint);
        }
        let mut bytes = [0u8; FINGERPRINT_LEN];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| CertificateError::InvalidFingerprint)?;
        Ok(Self(bytes))
    }

    /// Constant-time equality.
    ///
    /// Fingerprints are public, but a comparison that returns early leaks how
    /// many leading bytes a forgery got right — and the transition parsers
    /// compare them *before* verifying any signature (spec §6.2).
    pub fn matches(&self, other: &Self) -> bool {
        constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", hex::encode(self.0))
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse_hex(&raw).map_err(D::Error::custom)
    }
}

/// Sixteen opaque bytes: a trust domain, a stage, a request, a campaign.
///
/// Never all-zero. A zero identifier is the value an uninitialized structure
/// serializes to, and it must not be able to name a real object.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id16([u8; ID_LEN]);

impl Id16 {
    pub fn new(bytes: [u8; ID_LEN]) -> Result<Self, CertificateError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(CertificateError::ZeroIdentifier);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn parse_hex(value: &str) -> Result<Self, CertificateError> {
        if value.len() != ID_LEN * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CertificateError::InvalidIdentifier);
        }
        let mut bytes = [0u8; ID_LEN];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| CertificateError::InvalidIdentifier)?;
        Self::new(bytes)
    }
}

impl fmt::Display for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id16({})", hex::encode(self.0))
    }
}

impl Serialize for Id16 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Id16 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse_hex(&raw).map_err(D::Error::custom)
    }
}

/// Identifier of a trust domain, created once with the first `CA-PQ`.
pub type TrustDomainId = Id16;

/// WireGuard Curve25519 public key: base64 in JSON, 32 bytes when signed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireGuardKey([u8; WIREGUARD_KEY_LEN]);

impl WireGuardKey {
    pub const fn from_bytes(bytes: [u8; WIREGUARD_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the base64 form used everywhere else in the workspace.
    pub fn parse(value: &str) -> Result<Self, CertificateError> {
        let decoded = STANDARD
            .decode(value.trim())
            .map_err(|_| CertificateError::InvalidWireGuardKey)?;
        let bytes: [u8; WIREGUARD_KEY_LEN] = decoded
            .try_into()
            .map_err(|_| CertificateError::InvalidWireGuardKey)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; WIREGUARD_KEY_LEN] {
        &self.0
    }

    pub fn to_base64(self) -> String {
        STANDARD.encode(self.0)
    }
}

impl fmt::Display for WireGuardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for WireGuardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireGuardKey({})", STANDARD.encode(self.0))
    }
}

impl Serialize for WireGuardKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WireGuardKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// ML-DSA-87 public key, checked for length **and** decodability.
///
/// [`fips204`] refuses a byte string that is not a valid key; doing it here
/// means a verifier never carries a public key it could not use.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa87PublicKey(Vec<u8>);

impl MlDsa87PublicKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CertificateError> {
        let fixed = <[u8; ml_dsa_87::PK_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| CertificateError::InvalidPublicKey)?;
        PublicKey::try_from_bytes(fixed).map_err(|_| CertificateError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn parse(value: &str) -> Result<Self, CertificateError> {
        let decoded = STANDARD
            .decode(value.trim())
            .map_err(|_| CertificateError::InvalidPublicKey)?;
        Self::new(decoded)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }

    /// Fingerprint of an authority key, under the domain of spec §2.3.
    pub fn authority_fingerprint(&self) -> Fingerprint {
        let mut input = Vec::with_capacity(CA_FINGERPRINT_DOMAIN.len() + self.0.len());
        input.extend_from_slice(CA_FINGERPRINT_DOMAIN);
        input.extend_from_slice(&self.0);
        Fingerprint::of(&input)
    }

    fn verifier(&self) -> Result<PublicKey, CertificateError> {
        let fixed = <[u8; ml_dsa_87::PK_LEN]>::try_from(self.0.as_slice())
            .map_err(|_| CertificateError::InvalidPublicKey)?;
        PublicKey::try_from_bytes(fixed).map_err(|_| CertificateError::InvalidPublicKey)
    }
}

impl fmt::Debug for MlDsa87PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsa87PublicKey({})", self.authority_fingerprint())
    }
}

impl Serialize for MlDsa87PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for MlDsa87PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// ML-DSA-87 signature, checked for length at deserialization.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa87Signature(Vec<u8>);

impl MlDsa87Signature {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CertificateError> {
        if bytes.len() != ml_dsa_87::SIG_LEN {
            return Err(CertificateError::InvalidSignatureEncoding);
        }
        Ok(Self(bytes))
    }

    pub fn parse(value: &str) -> Result<Self, CertificateError> {
        let decoded = STANDARD
            .decode(value.trim())
            .map_err(|_| CertificateError::InvalidSignatureEncoding)?;
        Self::new(decoded)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }
}

impl fmt::Debug for MlDsa87Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa87Signature(..)")
    }
}

impl Serialize for MlDsa87Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for MlDsa87Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// A DER-encoded X.509 certificate, bounded and never empty.
#[derive(Clone, PartialEq, Eq)]
pub struct DerCertificate(Vec<u8>);

impl DerCertificate {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CertificateError> {
        if bytes.is_empty() || bytes.len() > MAX_DER_CERTIFICATE_BYTES {
            return Err(CertificateError::InvalidDerCertificate);
        }
        Ok(Self(bytes))
    }

    pub fn parse(value: &str) -> Result<Self, CertificateError> {
        let decoded = STANDARD
            .decode(value.trim())
            .map_err(|_| CertificateError::InvalidDerCertificate)?;
        Self::new(decoded)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }

    /// SHA-256 of the complete DER (spec §2.3).
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.0)
    }
}

impl fmt::Debug for DerCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerCertificate({})", self.fingerprint())
    }
}

impl Serialize for DerCertificate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for DerCertificate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// A DNS name in the canonical form of the v5 negotiation.
///
/// Bounded, non-empty, and free of the characters that would let one name be
/// read as two. It is signed length-prefixed, so no separator is needed for
/// safety — the check exists so an operator typo is a refusal rather than a
/// certificate nobody can match.
pub fn validate_server_name(value: &str) -> Result<(), CertificateError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.trim()
        || value
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        return Err(CertificateError::InvalidServerName);
    }
    Ok(())
}

/// Accumulator for a canonical signed transcript.
///
/// Every object in this module builds its signed bytes here, so the encoding
/// rules live in one place instead of being restated — and mistyped — once per
/// message.
pub(crate) struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// Starts a transcript with its domain separator.
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut buffer = Vec::with_capacity(512);
        buffer.extend_from_slice(domain);
        Self(buffer)
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Raw fixed-length bytes: identifiers, keys and fingerprints only.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn id(&mut self, value: &Id16) -> &mut Self {
        self.raw(value.as_bytes())
    }

    pub(crate) fn key(&mut self, value: &WireGuardKey) -> &mut Self {
        self.raw(value.as_bytes())
    }

    pub(crate) fn fingerprint(&mut self, value: &Fingerprint) -> &mut Self {
        self.raw(value.as_bytes())
    }

    /// An optional fingerprint: a presence byte, then the 32 bytes if present.
    ///
    /// The presence byte is what keeps `Some(all-zero)` and `None` from
    /// producing the same transcript.
    pub(crate) fn optional_fingerprint(&mut self, value: Option<&Fingerprint>) -> &mut Self {
        match value {
            Some(fingerprint) => {
                self.u8(1);
                self.fingerprint(fingerprint)
            }
            None => self.u8(0),
        }
    }

    /// Variable-length field, prefixed by its `u32` length.
    pub(crate) fn length_prefixed(&mut self, bytes: &[u8]) -> &mut Self {
        // A field longer than 4 GiB cannot exist here: every variable-length
        // type in this module is bounded well below that at deserialization.
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn text(&mut self, value: &str) -> &mut Self {
        self.length_prefixed(value.as_bytes())
    }

    pub(crate) fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Verifies an ML-DSA-87 signature over a canonical transcript.
pub fn verify_ml_dsa_87(
    public_key: &MlDsa87PublicKey,
    message: &[u8],
    signature: &MlDsa87Signature,
) -> Result<(), CertificateError> {
    let verifier = public_key.verifier()?;
    let signature = <[u8; ml_dsa_87::SIG_LEN]>::try_from(signature.as_bytes())
        .map_err(|_| CertificateError::InvalidSignatureEncoding)?;
    if !verifier.verify(message, &signature, &[]) {
        return Err(CertificateError::InvalidSignature);
    }
    Ok(())
}

/// Signs a canonical transcript with an ML-DSA-87 private key.
///
/// Behind the same feature as the negotiation signing API: a gateway that only
/// verifies never links a signing implementation.
#[cfg(feature = "key-negotiation-signing")]
pub fn sign_ml_dsa_87(
    private_key: &[u8],
    message: &[u8],
) -> Result<MlDsa87Signature, CertificateError> {
    use fips204::{ml_dsa_87::PrivateKey, traits::Signer as _};

    let private_key = <[u8; ml_dsa_87::SK_LEN]>::try_from(private_key)
        .map_err(|_| CertificateError::InvalidPrivateKey)?;
    let private_key =
        PrivateKey::try_from_bytes(private_key).map_err(|_| CertificateError::InvalidPrivateKey)?;
    let signature = private_key
        .try_sign(message, &[])
        .map_err(|_| CertificateError::Signing)?;
    MlDsa87Signature::new(signature.to_vec())
}

/// Generates an ML-DSA-87 authority or leaf key pair.
///
/// Returns `(private, public)`. The private half is the caller's to seal — no
/// path in this module writes one to disk.
#[cfg(feature = "key-negotiation-signing")]
pub fn generate_ml_dsa_87_keypair(
) -> Result<(zeroize::Zeroizing<Vec<u8>>, MlDsa87PublicKey), CertificateError> {
    let (public_key, private_key) =
        ml_dsa_87::try_keygen().map_err(|_| CertificateError::Signing)?;
    let public_key = MlDsa87PublicKey::new(public_key.into_bytes().to_vec())?;
    Ok((
        zeroize::Zeroizing::new(private_key.into_bytes().to_vec()),
        public_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_round_trips_through_its_lowercase_hexadecimal_form() {
        let fingerprint = Fingerprint::of(b"helios");
        let hex = fingerprint.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Fingerprint::parse_hex(&hex).expect("parse"), fingerprint);
        assert!(fingerprint.matches(&Fingerprint::parse_hex(&hex).unwrap()));
    }

    /// Uppercase is a second spelling of the same value, and a second spelling
    /// is a second chance to compare the wrong one.
    #[test]
    fn an_uppercase_fingerprint_is_refused_rather_than_normalized() {
        let hex = Fingerprint::of(b"helios").to_hex().to_uppercase();
        assert!(matches!(
            Fingerprint::parse_hex(&hex),
            Err(CertificateError::InvalidFingerprint)
        ));
    }

    #[test]
    fn a_zero_identifier_can_never_name_an_object() {
        assert!(matches!(
            Id16::new([0; ID_LEN]),
            Err(CertificateError::ZeroIdentifier)
        ));
        assert!(matches!(
            Id16::parse_hex(&"0".repeat(32)),
            Err(CertificateError::ZeroIdentifier)
        ));
        assert!(Id16::new([1; ID_LEN]).is_ok());
    }

    #[test]
    fn a_wireguard_key_round_trips_through_base64() {
        let key = WireGuardKey::from_bytes([7; WIREGUARD_KEY_LEN]);
        assert_eq!(WireGuardKey::parse(&key.to_base64()).expect("parse"), key);
        assert!(matches!(
            WireGuardKey::parse("too-short"),
            Err(CertificateError::InvalidWireGuardKey)
        ));
    }

    /// The presence byte is the whole point: without it, an absent optional
    /// and a present all-zero one would sign identically.
    #[test]
    fn an_absent_optional_fingerprint_does_not_encode_like_a_zero_one() {
        let mut absent = CanonicalBytes::new(b"domain");
        absent.optional_fingerprint(None);
        let mut zero = CanonicalBytes::new(b"domain");
        zero.optional_fingerprint(Some(&Fingerprint::from_bytes([0; FINGERPRINT_LEN])));
        assert_ne!(absent.finish(), zero.finish());
    }

    /// Two adjacent variable-length fields must not be re-splittable.
    #[test]
    fn length_prefixes_make_field_boundaries_unambiguous() {
        let mut left = CanonicalBytes::new(b"domain");
        left.text("ab").text("c");
        let mut right = CanonicalBytes::new(b"domain");
        right.text("a").text("bc");
        assert_ne!(left.finish(), right.finish());
    }

    #[test]
    fn a_server_name_outside_the_canonical_form_is_refused() {
        assert!(validate_server_name("gateway.example").is_ok());
        for invalid in ["", " gateway.example", "gateway example", "gateway/example"] {
            assert!(
                validate_server_name(invalid).is_err(),
                "accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn a_der_certificate_is_bounded_and_never_empty() {
        assert!(matches!(
            DerCertificate::new(Vec::new()),
            Err(CertificateError::InvalidDerCertificate)
        ));
        assert!(matches!(
            DerCertificate::new(vec![0; MAX_DER_CERTIFICATE_BYTES + 1]),
            Err(CertificateError::InvalidDerCertificate)
        ));
        let certificate = DerCertificate::new(vec![1, 2, 3]).expect("certificate");
        assert_eq!(certificate.fingerprint(), Fingerprint::of(&[1, 2, 3]));
    }

    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_signature_verifies_only_over_the_bytes_it_covers() {
        let (private_key, public_key) = generate_ml_dsa_87_keypair().expect("keygen");
        let signature = sign_ml_dsa_87(&private_key, b"transcript").expect("sign");
        assert!(verify_ml_dsa_87(&public_key, b"transcript", &signature).is_ok());
        assert!(matches!(
            verify_ml_dsa_87(&public_key, b"transcripT", &signature),
            Err(CertificateError::InvalidSignature)
        ));
    }

    /// An authority fingerprint is domain-separated, so it can never equal a
    /// hash computed elsewhere over the same public key.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn an_authority_fingerprint_is_not_the_bare_hash_of_its_key() {
        let (_, public_key) = generate_ml_dsa_87_keypair().expect("keygen");
        assert_ne!(
            public_key.authority_fingerprint(),
            Fingerprint::of(public_key.as_bytes())
        );
    }
}
