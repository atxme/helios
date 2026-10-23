//! Enrollment without a travelling private key (spec §15).
//!
//! Three public objects carry the whole ceremony, and none of them holds a
//! secret:
//!
//! - an [`EnrollmentInvitation`], signed by `CA-PQ`, single-use, aimed at one
//!   gateway and alive for 24 hours at most;
//! - an [`EnrollmentRequest`], self-signed by the client's new ML-DSA-87 key,
//!   carrying a TLS CSR and a WireGuard proof of possession, bound to that
//!   invitation;
//! - the signed `.orion` document the operator returns, bound to the request.
//!
//! WireGuard has no signature, so the proof of the WireGuard key is an HMAC
//! keyed by an X25519 agreement with a key the invitation dedicates to that
//! purpose. The gateway's own WireGuard identity is never reused in a second
//! protocol.
//!
//! The transcripts follow §15.3 to the byte, through the same
//! [`CanonicalBytes`] the certificate lifecycle signs with.

use aws_lc_rs::{constant_time, hmac};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

use super::ProtectionMode;
use crate::certificates::encoding::{
    verify_ml_dsa_87, CanonicalBytes, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature, WireGuardKey,
};

/// Version of the invitation and request formats.
pub const ENROLLMENT_FORMAT_VERSION: u16 = 1;
/// Protocol the enrolled client will speak.
pub const ENROLLMENT_PROTOCOL_VERSION: u16 = super::KEY_NEGOTIATION_VERSION;
/// Longest window an invitation may span, in seconds.
pub const MAX_INVITATION_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// Longest `requested_name`, in UTF-8 bytes.
pub const MAX_REQUESTED_NAME_BYTES: usize = 255;
/// Largest TLS CSR a request may carry, in DER bytes.
pub const MAX_ENROLLMENT_CSR_BYTES: usize = 16 * 1024;
/// How far a clock may run behind the operator's when an invitation opens.
///
/// The operator stamps `not_before` with its own clock and the client checks
/// it with another, minutes later, on another machine. A client a little
/// behind would otherwise refuse an invitation issued a second ago, and stamp a
/// request the operator then refuses. Only the opening edge is relaxed: the
/// closing one is the single-use guarantee and stays exact.
pub const ENROLLMENT_CLOCK_SKEW_SECS: u64 = 300;

/// `format` of a `.helios-invite` file.
pub const INVITATION_FILE_FORMAT: &str = "helios-enrollment-invitation";
/// `format` of a `.helios-request` file.
pub const REQUEST_FILE_FORMAT: &str = "helios-enrollment-request";

const INVITATION_DOMAIN: &[u8] = b"helios-key-negotiation-enrollment-invitation-v5";
const REQUEST_DOMAIN: &[u8] = b"helios-key-negotiation-enrollment-request-v5";
const WIREGUARD_POP_DOMAIN: &[u8] = b"helios-key-negotiation-wireguard-pop-v5";

/// Why an enrollment object is refused.
///
/// The messages are English: they are translated where they reach a person.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("malformed enrollment object: {0}")]
    Format(&'static str),
    #[error("outside the invitation window")]
    Window,
    #[error("the enrollment signature does not verify")]
    Signature,
    #[error("the request is not bound to this invitation: {0}")]
    Binding(&'static str),
    #[error("the WireGuard proof of possession does not verify")]
    Proof,
    #[error("the TLS certificate request does not verify")]
    Csr,
    #[error("the X25519 agreement produced an all-zero secret")]
    ZeroSharedSecret,
    #[error("randomness unavailable")]
    Random,
    #[error("enrollment signing failed")]
    Signing,
}

/// The operator's single-use authorization for one enrollment (§15.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentInvitation {
    pub format_version: u16,
    pub protocol_version: u16,
    pub invitation_id: Id16,
    pub gateway_wg_public_key: WireGuardKey,
    pub gateway_certificate_fingerprint: Fingerprint,
    pub server_name: String,
    pub operator_ca_public_key: MlDsa87PublicKey,
    /// Dedicated X25519 key of the WireGuard proof. Its private half stays in
    /// the operator's registry and dies with the invitation.
    pub wireguard_proof_public_key: WireGuardKey,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub minimum_mode: ProtectionMode,
    pub allow_readmission: bool,
    pub operator_signature: MlDsa87Signature,
}

impl EnrollmentInvitation {
    /// The bytes `CA-PQ` signs, in the order of §15.3.
    pub fn signed_bytes(&self) -> Vec<u8> {
        self.transcript().finish()
    }

    fn transcript(&self) -> CanonicalBytes {
        let mut bytes = CanonicalBytes::new(INVITATION_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.invitation_id)
            .key(&self.gateway_wg_public_key)
            .fingerprint(&self.gateway_certificate_fingerprint)
            .text(&self.server_name)
            .length_prefixed(self.operator_ca_public_key.as_bytes())
            .key(&self.wireguard_proof_public_key)
            .u64(self.not_before_unix)
            .u64(self.not_after_unix)
            .u8(self.minimum_mode.security_level())
            .u8(u8::from(self.allow_readmission));
        bytes
    }

    /// SHA-256 of the signed bytes followed by the length-prefixed signature.
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of(self.signed_bytes(), &self.operator_signature)
    }

    /// Shape checks that need no key.
    pub fn validate(&self) -> Result<(), EnrollmentError> {
        validate_versions(self.format_version, self.protocol_version)?;
        crate::certificates::encoding::validate_server_name(&self.server_name)
            .map_err(|_| EnrollmentError::Format("server_name"))?;
        if self.minimum_mode != ProtectionMode::MlKem {
            return Err(EnrollmentError::Format("minimum_mode must be ml_kem"));
        }
        let lifetime = self
            .not_after_unix
            .checked_sub(self.not_before_unix)
            .ok_or(EnrollmentError::Window)?;
        if lifetime == 0 || lifetime > MAX_INVITATION_LIFETIME_SECS {
            return Err(EnrollmentError::Window);
        }
        Ok(())
    }

    /// Whether `now_unix` falls inside the window, opening edge relaxed by
    /// [`ENROLLMENT_CLOCK_SKEW_SECS`].
    pub fn is_open_at(&self, now_unix: u64) -> bool {
        now_unix.saturating_add(ENROLLMENT_CLOCK_SKEW_SECS) >= self.not_before_unix
            && now_unix <= self.not_after_unix
    }

    /// Verifies the invitation under the `CA-PQ` key the client pinned.
    ///
    /// The key embedded in the invitation must **be** the pinned one: a CA
    /// that only the invitation names is never an anchor.
    pub fn verify(
        &self,
        pinned_ca: &MlDsa87PublicKey,
        now_unix: u64,
    ) -> Result<(), EnrollmentError> {
        self.validate()?;
        if &self.operator_ca_public_key != pinned_ca {
            return Err(EnrollmentError::Signature);
        }
        verify_ml_dsa_87(
            pinned_ca,
            &self.transcript().finish_signed(),
            &self.operator_signature,
        )
        .map_err(|_| EnrollmentError::Signature)?;
        if !self.is_open_at(now_unix) {
            return Err(EnrollmentError::Window);
        }
        Ok(())
    }

    /// Signs the invitation with the `CA-PQ` private key.
    #[cfg(feature = "key-negotiation-signing")]
    pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, EnrollmentError> {
        self.validate()?;
        self.operator_signature = crate::certificates::encoding::sign_ml_dsa_87(
            ca_pq_private_key,
            &self.transcript().finish_signed(),
        )
        .map_err(|_| EnrollmentError::Signing)?;
        Ok(self)
    }
}

/// The client's request, self-signed by its new ML-DSA-87 key (§15.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub invitation_id: Id16,
    pub invitation_fingerprint: Fingerprint,
    pub request_id: Id16,
    pub timestamp_unix: u64,
    pub requested_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub tls_csr: DerCertificate,
    pub client_ml_dsa_87_public_key: MlDsa87PublicKey,
    #[serde(with = "hex32")]
    pub wireguard_proof: [u8; 32],
    pub client_signature: MlDsa87Signature,
}

impl EnrollmentRequest {
    /// The bytes the client's ML-DSA-87 key signs, in the order of §15.3.
    pub fn signed_bytes(&self) -> Vec<u8> {
        self.transcript().finish()
    }

    fn transcript(&self) -> CanonicalBytes {
        let mut bytes = CanonicalBytes::new(REQUEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.invitation_id)
            .fingerprint(&self.invitation_fingerprint)
            .id(&self.request_id)
            .u64(self.timestamp_unix)
            .text(&self.requested_name)
            .key(&self.client_wg_public_key)
            .length_prefixed(self.tls_csr.as_bytes())
            .length_prefixed(self.client_ml_dsa_87_public_key.as_bytes())
            .raw(&self.wireguard_proof);
        bytes
    }

    /// SHA-256 of the signed bytes followed by the length-prefixed signature.
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint_of(self.signed_bytes(), &self.client_signature)
    }

    /// Shape checks that need neither the invitation nor a key.
    pub fn validate(&self) -> Result<(), EnrollmentError> {
        validate_versions(self.format_version, self.protocol_version)?;
        validate_requested_name(&self.requested_name)?;
        if self.tls_csr.as_bytes().len() > MAX_ENROLLMENT_CSR_BYTES {
            return Err(EnrollmentError::Format("tls_csr"));
        }
        Ok(())
    }

    /// Verifies the request against the invitation it names.
    ///
    /// Binding, window, self-signature and CSR. The WireGuard proof needs the
    /// operator's ephemeral private key and is checked by
    /// [`verify_wireguard_proof`].
    pub fn verify(&self, invitation: &EnrollmentInvitation) -> Result<(), EnrollmentError> {
        self.validate()?;
        if self.invitation_id != invitation.invitation_id {
            return Err(EnrollmentError::Binding("invitation_id"));
        }
        if self.invitation_fingerprint != invitation.fingerprint() {
            return Err(EnrollmentError::Binding("invitation_fingerprint"));
        }
        if !invitation.is_open_at(self.timestamp_unix) {
            return Err(EnrollmentError::Window);
        }
        verify_ml_dsa_87(
            &self.client_ml_dsa_87_public_key,
            &self.transcript().finish_signed(),
            &self.client_signature,
        )
        .map_err(|_| EnrollmentError::Signature)?;
        // The CSR's self-signature is what proves possession of the TLS key.
        // Its usages are not the client's to choose: the issuer sets them.
        crate::certificates::x509::certification_request_public_key_info(&self.tls_csr)
            .map_err(|_| EnrollmentError::Csr)?;
        Ok(())
    }

    /// Signs the request with the client's new ML-DSA-87 private key.
    #[cfg(feature = "key-negotiation-signing")]
    pub fn sign(mut self, client_ml_dsa_private_key: &[u8]) -> Result<Self, EnrollmentError> {
        self.validate()?;
        self.client_signature = crate::certificates::encoding::sign_ml_dsa_87(
            client_ml_dsa_private_key,
            &self.transcript().finish_signed(),
        )
        .map_err(|_| EnrollmentError::Signing)?;
        Ok(self)
    }
}

/// The client side of the WireGuard proof of possession (§15.2).
///
/// The invitation's signature must have been verified first: the agreement is
/// made with a key only the invitation vouches for. `request.wireguard_proof`
/// is not an input — the proof is what fills it.
pub fn wireguard_proof(
    client_wg_private_key: &[u8; 32],
    invitation: &EnrollmentInvitation,
    request: &EnrollmentRequest,
) -> Result<[u8; 32], EnrollmentError> {
    let secret = x25519_dalek::StaticSecret::from(*client_wg_private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    if public.as_bytes() != request.client_wg_public_key.as_bytes() {
        return Err(EnrollmentError::Binding("client_wg_public_key"));
    }
    let peer = x25519_dalek::PublicKey::from(*invitation.wireguard_proof_public_key.as_bytes());
    let shared = secret.diffie_hellman(&peer);
    proof_tag(&shared, invitation, request)
}

/// The operator side: recompute the proof with the invitation's ephemeral
/// private key and compare in constant time.
pub fn verify_wireguard_proof(
    proof_private_key: &[u8; 32],
    invitation: &EnrollmentInvitation,
    request: &EnrollmentRequest,
) -> Result<(), EnrollmentError> {
    let secret = x25519_dalek::StaticSecret::from(*proof_private_key);
    let peer = x25519_dalek::PublicKey::from(*request.client_wg_public_key.as_bytes());
    let shared = secret.diffie_hellman(&peer);
    let expected = proof_tag(&shared, invitation, request).map_err(|error| match error {
        // A low-order client key is a proof that cannot verify.
        EnrollmentError::ZeroSharedSecret => EnrollmentError::Proof,
        other => other,
    })?;
    constant_time::verify_slices_are_equal(&expected, &request.wireguard_proof)
        .map_err(|_| EnrollmentError::Proof)
}

fn proof_tag(
    shared: &x25519_dalek::SharedSecret,
    invitation: &EnrollmentInvitation,
    request: &EnrollmentRequest,
) -> Result<[u8; 32], EnrollmentError> {
    if !shared.was_contributory() {
        return Err(EnrollmentError::ZeroSharedSecret);
    }
    let z = Zeroizing::new(shared.to_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, z.as_slice());
    let mut data = CanonicalBytes::new(WIREGUARD_POP_DOMAIN);
    data.fingerprint(&invitation.fingerprint())
        .id(&request.request_id)
        .key(&request.client_wg_public_key)
        .fingerprint(&Fingerprint::of(request.tls_csr.as_bytes()))
        .fingerprint(&Fingerprint::of(
            request.client_ml_dsa_87_public_key.as_bytes(),
        ))
        .text(&request.requested_name);
    let tag = hmac::sign(&key, &data.finish());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationFile {
    format: String,
    invitation: EnrollmentInvitation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFile {
    format: String,
    request: EnrollmentRequest,
}

/// Reads a `.helios-invite`: envelope, shape. Not the signature — the CA is
/// not pinned yet when a person first opens the file.
pub fn decode_invitation_file(text: &str) -> Result<EnrollmentInvitation, EnrollmentError> {
    let file: InvitationFile = serde_json::from_str(strip_bom(text))
        .map_err(|_| EnrollmentError::Format("not an enrollment invitation"))?;
    if file.format != INVITATION_FILE_FORMAT {
        return Err(EnrollmentError::Format("not an enrollment invitation"));
    }
    file.invitation.validate()?;
    Ok(file.invitation)
}

/// Reads a `.helios-request`: envelope and shape.
pub fn decode_request_file(text: &str) -> Result<EnrollmentRequest, EnrollmentError> {
    let file: RequestFile = serde_json::from_str(strip_bom(text))
        .map_err(|_| EnrollmentError::Format("not an enrollment request"))?;
    if file.format != REQUEST_FILE_FORMAT {
        return Err(EnrollmentError::Format("not an enrollment request"));
    }
    file.request.validate()?;
    Ok(file.request)
}

/// Writes a `.helios-invite`.
pub fn encode_invitation_file(invitation: &EnrollmentInvitation) -> String {
    encode(&InvitationFile {
        format: INVITATION_FILE_FORMAT.into(),
        invitation: invitation.clone(),
    })
}

/// Writes a `.helios-request`.
pub fn encode_request_file(request: &EnrollmentRequest) -> String {
    encode(&RequestFile {
        format: REQUEST_FILE_FORMAT.into(),
        request: request.clone(),
    })
}

fn encode<T: Serialize>(value: &T) -> String {
    // Every field is a string, an integer or a boolean: serialization of these
    // types cannot fail.
    serde_json::to_string(value).unwrap_or_default()
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn validate_versions(format_version: u16, protocol_version: u16) -> Result<(), EnrollmentError> {
    if format_version != ENROLLMENT_FORMAT_VERSION {
        return Err(EnrollmentError::Format("format_version"));
    }
    if protocol_version != ENROLLMENT_PROTOCOL_VERSION {
        return Err(EnrollmentError::Format("protocol_version"));
    }
    Ok(())
}

/// UTF-8 NFC, 1 to 255 bytes, no control character.
fn validate_requested_name(name: &str) -> Result<(), EnrollmentError> {
    if name.is_empty() || name.len() > MAX_REQUESTED_NAME_BYTES {
        return Err(EnrollmentError::Format("requested_name length"));
    }
    if name.chars().any(char::is_control) || name != name.trim() {
        return Err(EnrollmentError::Format("requested_name characters"));
    }
    if !name.nfc().eq(name.chars()) {
        return Err(EnrollmentError::Format("requested_name is not NFC"));
    }
    Ok(())
}

fn fingerprint_of(mut signed: Vec<u8>, signature: &MlDsa87Signature) -> Fingerprint {
    let signature = signature.as_bytes();
    // A signature is 4 627 bytes: the length always fits.
    let length = u32::try_from(signature.len()).unwrap_or(u32::MAX);
    signed.extend_from_slice(&length.to_be_bytes());
    signed.extend_from_slice(signature);
    Fingerprint::of(&signed)
}

mod hex32 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.len() != 64 || raw.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(D::Error::custom("expected 64 lowercase hex digits"));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(&raw, &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests;
