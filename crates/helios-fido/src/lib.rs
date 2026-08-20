//! The one ceremony that opens no vault — spec §14.1, ADR-008 §4.
//!
//! # Why this is a crate of its own
//!
//! `astra-signer` is the only program in this repository that ever holds
//! `CA-PQ` in the clear, and ADR-008 §4 keeps it away from every other one.
//! An **ordinary client renewal**, however, opens no vault at all: the
//! approval receives no salt, so no `hmac-secret` output exists for it and no
//! key-slot can be unwrapped. §14.1 says exactly that.
//!
//! That makes the gesture separable from the program, and separating it is
//! what lets Orion run it without linking the code that can open a vault.
//! The boundary is a type rather than a convention: [`approve_renewal`] takes
//! no vault, and [`Authenticator::approve`] is handed no salt. An edit that
//! wanted to open one here would have to change both signatures — and neither
//! the vault format nor `CA-PQ` is reachable from this crate at all.
//!
//! # What Orion is allowed to do with a security key
//!
//! This, and nothing else. Registering a credential, deriving a slot secret
//! and everything that touches `hmac-secret` stay in
//! [`authenticator::Authenticator`]'s other methods, which are called only by
//! the companion. Orion holds no vault to open and no anchor to unwrap.
//!
//! # Limite connue : le matériel ne s'exerce pas en WSL2
//!
//! Voir [`authenticator`]. Aucun passthrough USB, et le module `webauthn` ne
//! s'y compile même pas ; la séquence au-dessus du matériel, elle, est
//! éprouvée par les essais d'`astra-signer`.

pub mod authenticator;

use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraCredentialBinding, AstraRenewalApproval,
    CredentialRegistry,
};
use aether::certificates::encoding::Fingerprint;
use aether::certificates::encoding::{
    MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::webauthn::{verify_assertion, AssertionExpectation};
use aether::certificates::{CertificateError, CERTIFICATE_FORMAT_VERSION};

use crate::authenticator::Authenticator;

/// Why an approval could not be produced.
///
/// Three causes and not one, because they send the operator to three different
/// places: the key refused or was absent, an object did not verify, or the
/// domain material does not describe this operation.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error(transparent)]
    Authenticator(#[from] authenticator::AuthenticatorError),
    #[error("objet de cycle de vie refusé : {0}")]
    Certificate(#[from] CertificateError),
    #[error("{0}")]
    Anchors(String),
}

pub type Result<T> = std::result::Result<T, ApprovalError>;

/// The `clientDataJSON` a WebAuthn assertion is taken over.
///
/// Composed here rather than by the caller: the challenge is the SHA-256 of a
/// canonical request, and a caller free to choose these bytes could obtain an
/// assertion over a challenge nobody derived. The verifier re-derives from the
/// bytes returned inside the assertion, so what is written here is checked by
/// the other end rather than trusted.
fn client_data(challenge: &Fingerprint, origin: &str) -> Vec<u8> {
    use base64::Engine as _;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// The domain, as the approval needs to know it.
///
/// Five public values. They come from the profile on Orion and from the
/// hand-off beside the vault on the operator's workstation; either way they
/// are what the approval is checked **against**, never what it learns from
/// the request it is approving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainIdentity {
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
}

impl DomainIdentity {
    /// The pinned issuance policy of §2.4, computed rather than learned.
    ///
    /// Computed on both ends from the same three values, so a delegation is
    /// checked against a policy neither end was told — being told one is
    /// exactly how a pin stops being a pin.
    pub fn policy(
        &self,
    ) -> std::result::Result<aether::certificates::approval::AstraIssuancePolicy, CertificateError>
    {
        Ok(
            aether::certificates::approval::AstraIssuancePolicy::standard(
                self.trust_domain_id,
                self.gateway_wg_public_key,
                self.server_name.clone(),
            ),
        )
    }
}

/// Approves one exact client renewal at a security key (spec §2.4, §14.1).
///
/// **No vault, and no salt.** The parameters are the request, the bindings the
/// domain already published, and a token — nothing here can open a key-slot,
/// which is the property §14.1 asks for in as many words: «un renouvellement
/// ordinaire n'obtient aucune sortie PRF et n'ouvre aucun key-slot».
///
/// The challenge is the SHA-256 of the canonical request, so the assertion is
/// unmovable to another peer, generation or deadline. It is re-derived and the
/// assertion re-verified here, under the credential's own public key, before
/// anything is returned: a companion that handed back an assertion it had not
/// checked would be asking Astra to discover the failure.
///
/// `active_generation` is the generation the operator states, when they know
/// it. The companion holds no certificate state, so `None` means the request's
/// own value is used and that one check is not performed here — Helios and
/// Orion each re-run it against their persisted generation, which is where it
/// actually decides anything.
#[allow(clippy::too_many_arguments)]
pub fn approve_renewal(
    key: &dyn Authenticator,
    request: &AstraCredentialApprovalRequest,
    service_key: &MlDsa87PublicKey,
    service_key_epoch: u64,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    bindings: &CredentialRegistry,
    webauthn_rp_id: &str,
    active_generation: Option<u64>,
    pin: &str,
    now_unix: u64,
) -> Result<AstraRenewalApproval> {
    // The service signature first: an operator must not be shown fields that
    // nothing vouches for, and a token must not be asked to touch for them.
    request.verify(
        service_key,
        service_key_epoch,
        &identity.trust_domain_id,
        &identity.gateway_wg_public_key,
        &request.client_wg_public_key,
        webauthn_rp_id,
        active_generation.unwrap_or(request.active_generation),
        now_unix,
    )?;
    bindings.verify(
        ca_pq_public_key,
        &identity.trust_domain_id,
        &identity.gateway_wg_public_key,
        identity.ca_epoch,
        request.credential_registry_epoch,
    )?;

    // Only active credentials, and only those the request enumerated: the
    // allow-list handed to the token is the intersection, so a token holding a
    // credential the request did not name is a token that answers nothing.
    let offered: Vec<&AstraCredentialBinding> = bindings
        .approvable()
        .into_iter()
        .filter(|binding| {
            request
                .allowed_credential_ids
                .contains(&binding.credential_id)
        })
        .collect();
    if offered.is_empty() {
        return Err(ApprovalError::Anchors(
            "aucun credential actif de ce domaine n'est autorisé par cette demande".into(),
        ));
    }

    let challenge = request.challenge();
    let client_data_json = client_data(&challenge, &request.webauthn_origin);
    let credential_ids: Vec<Vec<u8>> = offered
        .iter()
        .map(|binding| binding.credential_id.clone())
        .collect();
    let approval = key.approve(
        &request.webauthn_rp_id,
        &credential_ids,
        &client_data_json,
        pin,
    )?;
    let binding = offered
        .into_iter()
        .find(|binding| binding.credential_id == approval.credential_id)
        .ok_or_else(|| {
            ApprovalError::Anchors("la clé a répondu pour un credential non proposé".into())
        })?;

    // Checked here, with the same function the consumers run. Astra signs a
    // fact rather than a claim.
    verify_assertion(
        &approval.assertion,
        &binding.credential_public_key,
        &AssertionExpectation {
            relying_party_id: &request.webauthn_rp_id,
            origin: &request.webauthn_origin,
            challenge: &challenge,
        },
    )?;

    // At most five minutes, and never past the request's own deadline
    // (spec §2.4). Astra re-checks both under its clock.
    let expires_at = request.expires_at.min(
        now_unix
            .checked_add(aether::certificates::approval::MAX_APPROVAL_LIFETIME_SECS)
            .ok_or(CertificateError::ArithmeticOverflow)?,
    );
    Ok(AstraRenewalApproval {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: request.operation_id,
        request_fingerprint: request.request_fingerprint,
        approval_request_fingerprint: request.fingerprint(),
        credential_fingerprint: binding.fingerprint(),
        credential_binding: binding.clone(),
        assertion_fingerprint: approval.assertion.fingerprint(),
        webauthn_assertion: approval.assertion,
        approved_at: now_unix,
        expires_at,
        astra_service_key_epoch: service_key_epoch,
        // Filled by Astra: the companion does not hold the service key, and
        // must not — see the module header.
        astra_signature: MlDsa87Signature::placeholder(),
    })
}
