//! Canonical signed bytes, ML-DSA-87 signing and verification, and the
//! `authenticate_*` entry points.

use super::*;

pub(super) fn pq_certificate_signing_bytes(
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let public_key = STANDARD
        .decode(&certificate.ml_dsa_87_public_key)
        .map_err(|_| KeyNegotiationError::InvalidPqCertificate)?;
    if public_key.len() != ml_dsa_87::PK_LEN {
        return Err(KeyNegotiationError::InvalidPqCertificate);
    }
    let mut output = Vec::with_capacity(256 + public_key.len());
    output.extend_from_slice(PQ_CERTIFICATE_DOMAIN);
    output.extend_from_slice(&certificate.version.to_be_bytes());
    output.extend_from_slice(&certificate.serial);
    output.push(certificate.role.domain_byte());
    append_bytes(&mut output, certificate.subject.as_bytes())?;
    append_bytes(&mut output, certificate.issuer.as_bytes())?;
    append_bytes(&mut output, certificate.wireguard_public_key.as_bytes())?;
    append_bytes(&mut output, &public_key)?;
    output.extend_from_slice(&certificate.not_before_unix.to_be_bytes());
    output.extend_from_slice(&certificate.not_after_unix.to_be_bytes());
    Ok(output)
}

pub(super) fn pq_request_signing_bytes(
    request: &KeyNegotiationRequest,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(2048);
    output.extend_from_slice(PQ_REQUEST_DOMAIN);
    output.extend_from_slice(&request.protocol_version.to_be_bytes());
    output.extend_from_slice(&request.server_challenge);
    output.extend_from_slice(&request.transaction_id);
    output.push(request.mode.security_level());
    append_bytes(&mut output, request.client_wg_public_key.as_bytes())?;
    append_bytes(&mut output, request.gateway_wg_public_key.as_bytes())?;
    append_bytes(&mut output, request.server_name.as_bytes())?;
    append_bytes(
        &mut output,
        request.gateway_certificate_fingerprint.as_bytes(),
    )?;
    output.extend_from_slice(&request.client_nonce);
    output.extend_from_slice(&request.timestamp_unix.to_be_bytes());
    append_optional_bytes(&mut output, request.kem_public_key.as_deref())?;
    append_optional_bytes(
        &mut output,
        request.static_psk_commitment.as_deref().map(str::as_bytes),
    )?;
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

pub(super) fn pq_response_signing_bytes(
    response: &KeyNegotiationResponse,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let mut output = Vec::with_capacity(2048);
    output.extend_from_slice(PQ_RESPONSE_DOMAIN);
    output.extend_from_slice(&response.protocol_version.to_be_bytes());
    output.extend_from_slice(&response.transaction_id);
    output.extend_from_slice(&response.server_challenge);
    output.push(response.selected_mode.security_level());
    append_bytes(&mut output, response.gateway_wg_public_key.as_bytes())?;
    append_bytes(&mut output, response.client_wg_public_key.as_bytes())?;
    output.extend_from_slice(&response.gateway_nonce);
    append_optional_bytes(&mut output, response.kem_ciphertext.as_deref())?;
    output.extend_from_slice(&response.confirmation_timeout_secs.to_be_bytes());
    output.extend_from_slice(&response.psk_lifetime_secs.to_be_bytes());
    append_bytes(&mut output, certificate.fingerprint()?.as_bytes())?;
    Ok(output)
}

/// Spec §8.4, and the one message in this module that follows §8 to the
/// letter: keys and fingerprints are **decoded** to their 32 bytes, with no
/// length prefix and no base64 or hexadecimal text in the signed transcript.
///
/// The four older messages still sign the canonical text with a `u32` length.
/// That divergence is uniform, already served, and correcting it would
/// invalidate every deployed pair at once. This message has no deployed
/// signature to preserve — its domain is new — so it is written to the
/// contract rather than to the neighbours. Two encodings under two distinct
/// domains cannot be confused for one another; a standing divergence from the
/// spec is the thing worth avoiding.
pub(super) fn pq_release_signing_bytes(
    release: &PskRelease,
    certificate: &PqCertificate,
) -> Result<Vec<u8>, KeyNegotiationError> {
    let client_wg_public_key = decode_exact::<{ crate::wg::KEY_LEN }>(
        &release.client_wg_public_key,
        KeyNegotiationError::InvalidWireGuardKey,
    )?;
    let gateway_wg_public_key = decode_exact::<{ crate::wg::KEY_LEN }>(
        &release.gateway_wg_public_key,
        KeyNegotiationError::InvalidWireGuardKey,
    )?;
    let fingerprint = decode_hex_sha256(&certificate.fingerprint()?)?;

    let mut output = Vec::with_capacity(PQ_IN_TUNNEL_RELEASE_DOMAIN.len() + 2 + 16 + 32 * 3);
    output.extend_from_slice(PQ_IN_TUNNEL_RELEASE_DOMAIN);
    output.extend_from_slice(&release.protocol_version.to_be_bytes());
    output.extend_from_slice(&release.installed_transaction_id);
    output.extend_from_slice(&client_wg_public_key);
    output.extend_from_slice(&gateway_wg_public_key);
    output.extend_from_slice(&fingerprint);
    Ok(output)
}

fn decode_hex_sha256(value: &str) -> Result<[u8; 32], KeyNegotiationError> {
    validate_hex_sha256(value)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| KeyNegotiationError::InvalidCertificateFingerprint)?;
    Ok(bytes)
}

pub(super) fn pq_transaction_signing_bytes(
    domain: &[u8],
    protocol_version: u16,
    server_challenge: &[u8; SERVER_CHALLENGE_LEN],
    transaction_id: &[u8; KEY_NEGOTIATION_NONCE_LEN],
) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(domain.len() + 2 + SERVER_CHALLENGE_LEN + KEY_NEGOTIATION_NONCE_LEN);
    output.extend_from_slice(domain);
    output.extend_from_slice(&protocol_version.to_be_bytes());
    output.extend_from_slice(server_challenge);
    output.extend_from_slice(transaction_id);
    output
}

/// The external ML-DSA-87 context of one signed type (spec §8).
///
/// Every domain below also opens the transcript it covers, and
/// [`crate::ml_dsa`] refuses the pair if it does not: the prefix and the
/// context are two controls, and neither stands in for the other.
pub(super) fn signing_context(
    domain: &[u8],
) -> Result<crate::ml_dsa::Context<'_>, KeyNegotiationError> {
    crate::ml_dsa::Context::new(domain).map_err(|_| KeyNegotiationError::InvalidPqProtocolSignature)
}

pub(super) fn verify_protocol_signature(
    public_key: &str,
    domain: &[u8],
    message: &[u8],
    signature: &str,
) -> Result<(), KeyNegotiationError> {
    let public_key = decode_exact::<{ ml_dsa_87::PK_LEN }>(
        public_key,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    let signature = decode_exact::<{ ml_dsa_87::SIG_LEN }>(
        signature,
        KeyNegotiationError::InvalidPqProtocolSignature,
    )?;
    crate::ml_dsa::verify(&public_key, signing_context(domain)?, message, &signature)
        .map_err(|_| KeyNegotiationError::InvalidPqProtocolSignature)
}

#[cfg(feature = "key-negotiation-signing")]
pub(super) fn sign_ml_dsa_87(
    private_key: &[u8],
    domain: &[u8],
    message: &[u8],
) -> Result<String, KeyNegotiationError> {
    use crate::ml_dsa::MlDsaError;

    let signature =
        crate::ml_dsa::sign(private_key, signing_context(domain)?, message).map_err(|error| {
            match error {
                MlDsaError::InvalidPrivateKey => KeyNegotiationError::InvalidPqPrivateKey,
                _ => KeyNegotiationError::PqSigning,
            }
        })?;
    Ok(STANDARD.encode(signature))
}

/// Generates an ML-DSA-87 identity. The private half is zeroized on drop.
#[cfg(feature = "key-negotiation-signing")]
pub fn generate_ml_dsa_87_keypair() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), KeyNegotiationError> {
    crate::ml_dsa::generate_keypair().map_err(|_| KeyNegotiationError::PqSigning)
}

/// Signs a new PQ certificate with an ML-DSA-87 issuer key.
#[cfg(feature = "key-negotiation-signing")]
pub fn issue_pq_certificate(
    mut certificate: PqCertificate,
    issuer_private_key: &[u8],
) -> Result<PqCertificate, KeyNegotiationError> {
    certificate.ml_dsa_87_signature.clear();
    certificate.ml_dsa_87_signature = sign_ml_dsa_87(
        issuer_private_key,
        PQ_CERTIFICATE_DOMAIN,
        &pq_certificate_signing_bytes(&certificate)?,
    )?;
    Ok(certificate)
}

/// Signs an Orion request, including its challenge and gateway binding.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_request(
    request: KeyNegotiationRequest,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationRequest, KeyNegotiationError> {
    request.validate()?;
    let signature = sign_ml_dsa_87(
        subject_private_key,
        PQ_REQUEST_DOMAIN,
        &pq_request_signing_bytes(&request, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationRequest {
        request,
        certificate,
        ml_dsa_87_signature: signature,
    })
}

/// Signs the Helios response containing the ML-KEM ciphertext.
#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_response(
    response: KeyNegotiationResponse,
    certificate: PqCertificate,
    subject_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationResponse, KeyNegotiationError> {
    let signature = sign_ml_dsa_87(
        subject_private_key,
        PQ_RESPONSE_DOMAIN,
        &pq_response_signing_bytes(&response, &certificate)?,
    )?;
    Ok(AuthenticatedKeyNegotiationResponse {
        response,
        certificate,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_confirmation(
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    client_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationConfirmation, KeyNegotiationError> {
    let confirmation = KeyNegotiationConfirmation {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge,
        transaction_id,
    };
    let signature = sign_ml_dsa_87(
        client_private_key,
        PQ_CONFIRMATION_DOMAIN,
        &pq_transaction_signing_bytes(
            PQ_CONFIRMATION_DOMAIN,
            confirmation.protocol_version,
            &confirmation.server_challenge,
            &confirmation.transaction_id,
        ),
    )?;
    Ok(AuthenticatedKeyNegotiationConfirmation {
        confirmation,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_commit(
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    gateway_private_key: &[u8],
) -> Result<AuthenticatedKeyNegotiationCommit, KeyNegotiationError> {
    let protocol_version = KEY_NEGOTIATION_VERSION;
    let signature = sign_ml_dsa_87(
        gateway_private_key,
        PQ_COMMIT_DOMAIN,
        &pq_transaction_signing_bytes(
            PQ_COMMIT_DOMAIN,
            protocol_version,
            &server_challenge,
            &transaction_id,
        ),
    )?;
    Ok(AuthenticatedKeyNegotiationCommit {
        protocol_version,
        server_challenge,
        transaction_id,
        ml_dsa_87_signature: signature,
    })
}

#[cfg(feature = "key-negotiation-signing")]
pub fn authenticate_release(
    release: PskRelease,
    certificate: PqCertificate,
    client_private_key: &[u8],
) -> Result<AuthenticatedPskRelease, KeyNegotiationError> {
    let signature = sign_ml_dsa_87(
        client_private_key,
        PQ_IN_TUNNEL_RELEASE_DOMAIN,
        &pq_release_signing_bytes(&release, &certificate)?,
    )?;
    Ok(AuthenticatedPskRelease {
        release,
        certificate,
        ml_dsa_87_signature: signature,
    })
}
