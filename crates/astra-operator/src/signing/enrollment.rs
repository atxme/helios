//! Enrolling a client without its private keys ever leaving it (spec §15.2).
//!
//! Three gestures, each opening the vault once:
//!
//! 1. [`sign_invitation`] — `CA-PQ` signs a single-use invitation aimed at one
//!    gateway, and the registry records it with its proof key **before** it is
//!    handed back;
//! 2. [`accept_request`] — the request is verified and its invitation consumed
//!    durably, and only then are the two client leaves issued;
//! 3. [`sign_document`] — `CA-PQ` signs the returned `.orion`, and only around
//!    the leaves step 2 actually issued.
//!
//! None of them is a campaign: like the gateway bootstrap, enrollment happens
//! before Astra holds any state for the client, so the credential policy is
//! applied here directly — one key, two for a readmission (ADR-008 §4).

use super::*;

use aether::certificates::encoding::Id16;
use aether::key_negotiation::{
    EnrollmentDocument, EnrollmentInvitation, EnrollmentRequest, PqCertificate, PqCertificateRole,
    ProtectionMode, ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use rcgen::ExtendedKeyUsagePurpose;
use zeroize::Zeroizing;

use crate::enrollment::{InvitationRegistry, InvitationState, IssuedLeafFingerprints};
use crate::gestures::require_distinct_credentials;

/// Credentials an invitation needs: one, or two distinct ones when it may
/// readmit a key that was already enrolled.
pub fn enrollment_credentials(allow_readmission: bool) -> usize {
    if allow_readmission {
        2
    } else {
        1
    }
}

/// What the operator decides about one invitation.
#[derive(Clone, Copy)]
pub struct InvitationDraft<'a> {
    /// The leaf the gateway serves. Verified under `CA-PQ` here, and pinned by
    /// fingerprint in the invitation.
    pub gateway_certificate: &'a PqCertificate,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: &'a str,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub allow_readmission: bool,
}

/// The two leaves an accepted request receives.
#[derive(Debug, Clone)]
pub struct IssuedLeaves {
    pub tls_certificate: DerCertificate,
    pub pq_certificate: PqCertificate,
}

/// A PQ leaf as a profile carries it: base64 of its JSON.
pub fn encode_pq_certificate(certificate: &PqCertificate) -> Result<String> {
    let json = serde_json::to_vec(certificate)
        .map_err(|_| GestureError::Anchors("encodage de la feuille PQ".into()))?;
    Ok(encode(&json))
}

fn decode_pq_certificate(value: &str) -> Option<PqCertificate> {
    let json = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    serde_json::from_slice(&json).ok()
}

fn anchor(vault: &AuthorityVault) -> Result<MlDsa87PublicKey> {
    Ok(MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?)
}

fn registry_error(error: anyhow::Error) -> GestureError {
    GestureError::Anchors(format!("{error:#}"))
}

/// Signs an invitation under `CA-PQ` and records it (§15.2).
///
/// The invitation is returned only once the registry holds it, with the
/// private half of its proof key: an invitation that left without its record
/// could never be accepted, and one recorded twice could be accepted twice.
pub fn sign_invitation(
    vault: &AuthorityVault,
    openings: &[&crate::authenticator::Opened],
    draft: &InvitationDraft<'_>,
    registry: &InvitationRegistry,
    now_unix: u64,
) -> Result<EnrollmentInvitation> {
    require_distinct_credentials(enrollment_credentials(draft.allow_readmission), openings)?;
    let opening = openings
        .first()
        .ok_or_else(|| GestureError::Anchors("aucun credential présenté".into()))?;
    let ca_pq_public_key = anchor(vault)?;
    draft
        .gateway_certificate
        .verify(
            ca_pq_public_key.as_bytes(),
            PqCertificateRole::Gateway,
            Some(draft.server_name),
            &draft.gateway_wg_public_key.to_base64(),
            now_unix,
        )
        .map_err(|error| {
            GestureError::Anchors(format!(
                "la feuille PQ gateway ne vérifie pas sous CA-PQ pour cette gateway : {error}"
            ))
        })?;
    let gateway_certificate_fingerprint =
        aether::certificates::gateway::pq_certificate_fingerprint(draft.gateway_certificate)?;

    let proof = aether::wg::generate_keypair()
        .map_err(|error| GestureError::Anchors(format!("clé de preuve : {error}")))?;
    let proof_private = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(proof.private_key.expose())
            .map_err(|_| GestureError::Anchors("clé de preuve illisible".into()))?,
    );
    let mut proof_private_key = Zeroizing::new([0u8; 32]);
    if proof_private.len() != proof_private_key.len() {
        return Err(GestureError::Anchors("clé de preuve illisible".into()));
    }
    proof_private_key.copy_from_slice(&proof_private);
    let invitation_id = Id16::new(
        aether::random::public_bytes()
            .map_err(|_| GestureError::Anchors("aléa indisponible".into()))?,
    )?;

    let invitation = with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        EnrollmentInvitation {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id,
            gateway_wg_public_key: draft.gateway_wg_public_key,
            gateway_certificate_fingerprint,
            server_name: draft.server_name.to_string(),
            operator_ca_public_key: ca_pq_public_key.clone(),
            wireguard_proof_public_key: WireGuardKey::parse(&proof.public_key)?,
            not_before_unix: draft.not_before_unix,
            not_after_unix: draft.not_after_unix,
            minimum_mode: ProtectionMode::MlKem,
            allow_readmission: draft.allow_readmission,
            operator_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)
        .map_err(|error| GestureError::Anchors(format!("invitation : {error}")))
    })?;
    invitation
        .verify(&ca_pq_public_key, now_unix)
        .map_err(|error| GestureError::Anchors(format!("invitation : {error}")))?;
    registry.purge_lapsed(now_unix).map_err(registry_error)?;
    registry
        .issue(&invitation, proof_private_key)
        .map_err(registry_error)?;
    Ok(invitation)
}

/// Accepts a request: consume, then issue (§15.2).
///
/// The invitation must be one this vault's `CA-PQ` signed. It is then
/// consumed — verified, marked, synchronized — **before** the vault is opened.
/// Any failure from there on leaves it consumed: a new invitation is the only
/// way forward, never a second accept.
pub fn accept_request(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    registry: &InvitationRegistry,
    ca_tls_certificate: &DerCertificate,
    request: &EnrollmentRequest,
    leaf_validity: (u64, u64),
    now_unix: u64,
) -> Result<IssuedLeaves> {
    if leaf_validity.1 <= leaf_validity.0 {
        return Err(GestureError::Anchors(
            "période de validité des feuilles clientes vide".into(),
        ));
    }
    let ca_pq_public_key = anchor(vault)?;
    let record = registry
        .load(&request.invitation_id)
        .map_err(registry_error)?;
    if record.invitation.operator_ca_public_key != ca_pq_public_key {
        return Err(GestureError::Anchors(
            "cette invitation n'a pas été signée par le CA-PQ de ce coffre".into(),
        ));
    }
    let consumed = registry
        .consume(&request.invitation_id, request, now_unix)
        .map_err(registry_error)?;

    let serial = aether::random::public_bytes()
        .map_err(|_| GestureError::Anchors("aléa indisponible".into()))?;
    let leaves = with_anchors(vault, opening, |secrets| {
        let name = request.requested_name.clone();
        let tls_certificate = issue_tls_leaf(
            secrets,
            ca_tls_certificate,
            &request.tls_csr,
            leaf_validity,
            |params| {
                // What the leaf says is the issuer's decision, not the CSR's:
                // a client leaf, under the name the request asked for.
                params.is_ca = IsCa::NoCa;
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
                params.subject_alt_names = Vec::new();
                let mut subject = DistinguishedName::new();
                subject.push(DnType::CommonName, name);
                params.distinguished_name = subject;
            },
        )?;
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let pq_certificate = aether::key_negotiation::issue_pq_certificate(
            PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial,
                subject: request.requested_name.clone(),
                issuer: "helios-ca-pq".to_string(),
                role: PqCertificateRole::Client,
                wireguard_public_key: request.client_wg_public_key.to_base64(),
                ml_dsa_87_public_key: encode(request.client_ml_dsa_87_public_key.as_bytes()),
                not_before_unix: leaf_validity.0,
                not_after_unix: leaf_validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;
        Ok(IssuedLeaves {
            tls_certificate,
            pq_certificate,
        })
    })?;

    // Checked against the request before anyone carries them: a leaf that
    // does not certify the keys Orion holds is a leaf no handshake will use.
    aether::certificates::x509::assert_csr_matches(&request.tls_csr, &leaves.tls_certificate)?;
    aether::certificates::x509::assert_client_leaf(
        &leaves.tls_certificate,
        leaf_validity.0,
        leaf_validity.0,
    )?;
    leaves
        .pq_certificate
        .verify(
            ca_pq_public_key.as_bytes(),
            PqCertificateRole::Client,
            Some(&request.requested_name),
            &request.client_wg_public_key.to_base64(),
            leaf_validity.0,
        )
        .map_err(|error| GestureError::Anchors(format!("feuille PQ cliente : {error}")))?;

    registry
        .record_issued(
            &consumed.invitation.invitation_id,
            IssuedLeafFingerprints {
                tls_certificate: leaves.tls_certificate.fingerprint(),
                pq_certificate: aether::certificates::gateway::pq_certificate_fingerprint(
                    &leaves.pq_certificate,
                )?,
            },
        )
        .map_err(registry_error)?;
    Ok(leaves)
}

/// Signs the returned `.orion` document under `CA-PQ` (§15.3).
///
/// Refused unless the document is bound to a consumed invitation of this
/// registry, to the very request that consumed it, to the leaves that request
/// received, to this `CA-PQ`, and to the gateway the invitation named.
pub fn sign_document(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    registry: &InvitationRegistry,
    draft: EnrollmentDocument,
) -> Result<EnrollmentDocument> {
    let ca_pq_public_key = anchor(vault)?;
    let record = registry
        .load(&draft.invitation_id)
        .map_err(registry_error)?;
    let InvitationState::Consumed {
        request_id,
        request_fingerprint,
        issued: Some(issued),
        ..
    } = record.state
    else {
        return Err(GestureError::Anchors(format!(
            "l'invitation {} n'a émis aucune feuille : il n'y a pas de document à signer",
            draft.invitation_id
        )));
    };
    if draft.request_id != request_id || draft.request_fingerprint != request_fingerprint {
        return Err(GestureError::Anchors(
            "le document ne nomme pas la demande qui a consommé cette invitation".into(),
        ));
    }
    let pq_certificate = decode_pq_certificate(&draft.client_pq_certificate)
        .ok_or_else(|| GestureError::Anchors("feuille PQ cliente illisible".into()))?;
    if draft.client_tls_certificate.fingerprint() != issued.tls_certificate
        || aether::certificates::gateway::pq_certificate_fingerprint(&pq_certificate)?
            != issued.pq_certificate
    {
        return Err(GestureError::Anchors(
            "le document porte des feuilles que cette invitation n'a pas reçues".into(),
        ));
    }
    if draft.operator_ca_fingerprint != ca_pq_public_key.authority_fingerprint() {
        return Err(GestureError::Anchors(
            "le document nomme un autre CA-PQ que celui de ce coffre".into(),
        ));
    }
    let profile = serde_json::Value::Object(draft.profile.clone());
    let trusted = profile
        .pointer("/key_negotiation/trust/ca_pq_public_key")
        .and_then(serde_json::Value::as_str)
        .map(MlDsa87PublicKey::parse)
        .transpose()?;
    if trusted.as_ref() != Some(&ca_pq_public_key) {
        return Err(GestureError::Anchors(
            "le bloc de confiance du profil ne nomme pas le CA-PQ de ce coffre".into(),
        ));
    }
    let invitation = &record.invitation;
    let peer = profile
        .pointer("/peer_public_key")
        .and_then(serde_json::Value::as_str)
        .map(WireGuardKey::parse)
        .transpose()?;
    if peer != Some(invitation.gateway_wg_public_key) {
        return Err(GestureError::Anchors(
            "le profil vise une autre clé WireGuard gateway que l'invitation".into(),
        ));
    }
    if profile
        .pointer("/key_negotiation/server_name")
        .and_then(serde_json::Value::as_str)
        != Some(invitation.server_name.as_str())
    {
        return Err(GestureError::Anchors(
            "le profil vise un autre nom de serveur que l'invitation".into(),
        ));
    }
    let pinned = profile
        .pointer("/key_negotiation/gateway_pq_certificate")
        .and_then(serde_json::Value::as_str)
        .and_then(decode_pq_certificate);
    let pinned = pinned
        .as_ref()
        .map(aether::certificates::gateway::pq_certificate_fingerprint)
        .transpose()?;
    if pinned != Some(invitation.gateway_certificate_fingerprint) {
        return Err(GestureError::Anchors(
            "le profil épingle une autre feuille PQ gateway que l'invitation".into(),
        ));
    }

    let signed = with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        draft
            .sign(&ca_pq_private_key)
            .map_err(|error| GestureError::Anchors(format!("document : {error}")))
    })?;
    signed
        .verify(&ca_pq_public_key)
        .map_err(|error| GestureError::Anchors(format!("document : {error}")))?;
    Ok(signed)
}
