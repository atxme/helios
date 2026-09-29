//! The delegated issuer: the only key Astra may use without a human present.
//!
//! It holds two subordinate keys — an ML-DSA-87 one and a TLS intermediate —
//! and an [`AstraIssuerAuthorization`] signed by `CA-PQ` that says exactly what
//! they may do: renew the leaves of an already-admitted, non-revoked peer of
//! **one** gateway, to generation `active + 1`, for at most a stated lifetime,
//! inside a stated window.
//!
//! # What a host compromise buys
//!
//! This key is sealed in Astra's state on the gateway, so an attacker with
//! `root` can use it until the delegation expires. That is accepted and
//! bounded (ADR-008, *Conséquences*): they can renew tomorrow's leaf of a peer
//! that is already admitted. They cannot enrol, readmit, recover an expired
//! identity, rotate the gateway, rotate a CA, or skip a generation — every
//! consumer checks the scope before the signature, and the master key is not
//! here to be stolen.
//!
//! # Limite connue
//!
//! Astra issues the leaves; it never signs a `GatewayIdentityTransition`, a
//! `CaTransition` or a recovery authorization. Those need `CA-PQ`, which lives
//! in the encrypted vault and is opened by the operator companion against a
//! hardware credential. This crate therefore refuses those operations in the
//! type — [`IssuerError::MasterAuthorityRequired`] — rather than offering a
//! degraded path.

use aether::certificates::{
    approval::{DelegatedApproval, PolicyMigration},
    authority::{AstraIssuerAuthorization, RotationReason},
    client::{
        ClientCertificateGeneration, ClientCertificateRotationGrant,
        ClientCertificateRotationRequest, ClientCertificateStageAuthorization,
        GatewayCertificateStageReceipt, IssuerKind,
    },
    encoding::{DerCertificate, Fingerprint, Id16, MlDsa87Signature},
    gateway::pq_certificate_fingerprint,
    window::TransitionWindow,
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{CertificateParams, CertificateSigningRequestParams, KeyPair};
use zeroize::Zeroizing;

/// Unix seconds as the X.509 encoder wants them.
fn to_offset_date_time(seconds: u64) -> Result<time::OffsetDateTime, IssuerError> {
    let seconds = i64::try_from(seconds).map_err(|_| CertificateError::ArithmeticOverflow)?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| IssuerError::Certificate(CertificateError::InvalidValidityPeriod))
}

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("certificate object refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("X.509 issuance failed: {0}")]
    X509(#[from] rcgen::Error),
    #[error(
        "this operation requires the master authority `CA-PQ`, which the delegated issuer does \
         not hold: run it through the operator companion"
    )]
    MasterAuthorityRequired,
    #[error("the gateway receipt does not answer this staging authorization")]
    ReceiptMismatch,
    #[error(
        "the {0} private key on disk does not belong to the delegation the registry holds: Astra \
         would announce an issuer it cannot issue with"
    )]
    IssuerKeyMismatch(&'static str),
}

/// What Astra asks the companion to delegate to, for one issuer epoch.
///
/// Defined in `aether`, next to the [`AstraIssuerAuthorization`] it asks for:
/// the operator companion reads it on another machine, and it may not depend
/// on this crate to name a document. Same reason the operation views that
/// `signing` re-exports live there.
pub use aether::certificates::authority::IssuerDelegationRequest;

/// The issuer's private material, as Astra holds it.
///
/// The private halves are `Zeroizing`: they are read once at startup and never
/// serialized back out. No route in [`crate::service`] can reach them.
pub struct DelegatedIssuer {
    pub authorization: AstraIssuerAuthorization,
    pq_private_key: Zeroizing<Vec<u8>>,
    tls_intermediate_key_der: Zeroizing<Vec<u8>>,
}

impl DelegatedIssuer {
    pub fn new(
        authorization: AstraIssuerAuthorization,
        pq_private_key: Zeroizing<Vec<u8>>,
        tls_intermediate_key_der: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            authorization,
            pq_private_key,
            tls_intermediate_key_der,
        }
    }

    /// Builds the issuer only if both private keys match the delegation.
    ///
    /// The three parts arrive from two different places — the authorization is
    /// public and travels in the registry, the keys are sealed locally — so
    /// nothing else guarantees they belong together. Checking that the files
    /// merely *exist* lets Astra start up announcing a delegation it cannot
    /// use, and the mismatch then surfaces at the first renewal: at 80 % of a
    /// leaf's life, on a client with no fallback, as an unexplained refusal.
    ///
    /// Both checks are possession proofs against the **public** halves the
    /// delegation names: an ML-DSA-87 signature verified under
    /// `pq_issuer_public_key`, and the TLS key's `SubjectPublicKeyInfo`
    /// compared with the intermediate's.
    pub fn load(
        authorization: AstraIssuerAuthorization,
        pq_private_key: Zeroizing<Vec<u8>>,
        tls_intermediate_key_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, IssuerError> {
        let derived = aether::certificates::encoding::derive_ml_dsa_87_public_key(&pq_private_key)
            .map_err(|_| IssuerError::IssuerKeyMismatch("ML-DSA-87"))?;
        if derived != authorization.pq_issuer_public_key {
            return Err(IssuerError::IssuerKeyMismatch("ML-DSA-87"));
        }

        let tls_key = KeyPair::try_from(tls_intermediate_key_der.as_slice())
            .map_err(|_| IssuerError::IssuerKeyMismatch("TLS"))?;
        let certified = aether::certificates::x509::subject_public_key_info(
            &authorization.tls_intermediate_certificate,
        )?;
        if tls_key.public_key_der() != certified {
            return Err(IssuerError::IssuerKeyMismatch("TLS"));
        }

        Ok(Self::new(
            authorization,
            pq_private_key,
            tls_intermediate_key_der,
        ))
    }

    /// Issues the two leaves of a candidate generation.
    ///
    /// The TLS leaf comes from the client's own CSR, so the private key stays
    /// in Orion's protected store; the PQ leaf certifies the public key the
    /// request proved possession of. Both chain to the **delegation**, not to
    /// `CA-PQ` — which is what every consumer then checks.
    pub fn issue_generation(
        &self,
        request: &ClientCertificateRotationRequest,
        subject_name: &str,
        window: &TransitionWindow,
        validity: (u64, u64),
        serial: [u8; 16],
        reason: RotationReason,
    ) -> Result<(DerCertificate, PqCertificate), IssuerError> {
        let lifetime = validity
            .1
            .checked_sub(validity.0)
            .ok_or(CertificateError::InvalidValidityPeriod)?;
        // Scope first: an issuer that signed and *then* checked would have
        // already produced the object it was not allowed to produce.
        self.authorization.authorize_renewal(
            request.active_generation,
            request.requested_generation,
            lifetime,
            reason,
        )?;
        let _ = window;

        let mut csr =
            CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().into())?;
        // A PKCS#10 request carries no validity — and must not: the period is
        // the **issuer's** decision, bounded by the delegation's ceiling. Left
        // alone, the leaf would silently inherit the library's default window
        // and stop matching the generation it belongs to.
        csr.params.not_before = to_offset_date_time(validity.0)?;
        csr.params.not_after = to_offset_date_time(validity.1)?;
        let issuer_key = KeyPair::try_from(self.tls_intermediate_key_der.as_slice())?;
        let issuer_params = CertificateParams::from_ca_cert_der(
            &self
                .authorization
                .tls_intermediate_certificate
                .as_bytes()
                .into(),
        )?;
        let issuer = issuer_params.self_signed(&issuer_key)?;
        let tls_leaf = csr.signed_by(&issuer, &issuer_key)?;

        let pq_leaf = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial,
                subject: subject_name.to_string(),
                issuer: "astra-delegated-issuer".to_string(),
                role: PqCertificateRole::Client,
                wireguard_public_key: request.client_wg_public_key.to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(request.new_ml_dsa_87_public_key.as_bytes()),
                not_before_unix: validity.0,
                not_after_unix: validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &self.pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;

        Ok((DerCertificate::new(tls_leaf.der().to_vec())?, pq_leaf))
    }

    /// Builds the staging authorization the gateway will act on (spec §7.2).
    ///
    /// It carries the issued leaves but is **not** the grant: the client
    /// receives nothing installable until the gateway has persisted the
    /// candidate and signed a receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_stage(
        &self,
        request: &ClientCertificateRotationRequest,
        active: &ClientCertificateGeneration,
        stage_id: Id16,
        tls_ca_fingerprint: Fingerprint,
        tls_leaf: DerCertificate,
        pq_leaf: PqCertificate,
        window: TransitionWindow,
        issued_at: u64,
        stage_expires_at: u64,
        approval: DelegatedApproval,
    ) -> Result<ClientCertificateStageAuthorization, IssuerError> {
        // The reason is read off the evidence rather than supplied beside it:
        // the two cannot then name different things (see `DelegatedApproval`).
        let reason = approval.reason();
        if !reason.is_delegable() {
            return Err(IssuerError::MasterAuthorityRequired);
        }
        let renewal_authorization_fingerprint = approval.fingerprint()?;
        let (renewal_approval, campaign_approval) = match approval {
            DelegatedApproval::Automatic(request_fingerprint) => {
                if !request_fingerprint.matches(&request.fingerprint()) {
                    return Err(IssuerError::Certificate(
                        CertificateError::ApprovalMismatch("automatic renewal request fingerprint"),
                    ));
                }
                (None, None)
            }
            DelegatedApproval::Renewal(evidence) => (Some(*evidence), None),
            DelegatedApproval::Campaign(evidence) => (None, Some(evidence)),
        };
        let authorization = ClientCertificateStageAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.authorization.trust_domain_id,
            ca_epoch: self.authorization.ca_epoch,
            ca_tls_epoch: self.authorization.ca_tls_epoch,
            issuer_kind: IssuerKind::Astra,
            issuer_epoch: self.authorization.issuer_epoch,
            issuer_authorization_fingerprint: self.authorization.fingerprint(),
            issuer_authorization: Some(self.authorization.clone()),
            stage_id,
            request_fingerprint: request.fingerprint(),
            renewal_authorization_fingerprint,
            renewal_approval,
            campaign_approval,
            gateway_wg_public_key: self.authorization.gateway_wg_public_key,
            server_name: self.authorization.server_name.clone(),
            client_wg_public_key: request.client_wg_public_key,
            active_generation: active.generation,
            next_generation: request.requested_generation,
            active_tls_certificate_fingerprint: active.tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: tls_ca_fingerprint,
            next_tls_certificate: tls_leaf,
            next_pq_certificate: pq_leaf,
            issued_at,
            stage_expires_at,
            window,
            reason,
            signature: MlDsa87Signature::placeholder(),
        };
        Ok(authorization.sign(&self.pq_private_key)?)
    }

    /// Releases the grant — and **only** against a receipt that answers this
    /// exact authorization (spec §7.3).
    ///
    /// Every field is compared, not just the identifier. A receipt naming the
    /// right `stage_id` while describing another generation would otherwise be
    /// a valid signature over the wrong fact.
    pub fn release_grant(
        &self,
        authorization: &ClientCertificateStageAuthorization,
        receipt: &GatewayCertificateStageReceipt,
        gateway_pq_public_key: &aether::certificates::encoding::MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
    ) -> Result<ClientCertificateRotationGrant, IssuerError> {
        receipt
            .verify(
                gateway_pq_public_key,
                gateway_certificate_fingerprint,
                authorization,
            )
            .map_err(|_| IssuerError::ReceiptMismatch)?;

        let grant = ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            ca_epoch: authorization.ca_epoch,
            ca_tls_epoch: authorization.ca_tls_epoch,
            issuer_kind: authorization.issuer_kind,
            issuer_epoch: authorization.issuer_epoch,
            issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
            issuer_authorization: authorization.issuer_authorization.clone(),
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            renewal_approval: authorization.renewal_approval.clone(),
            campaign_approval: authorization.campaign_approval.clone(),
            stage_receipt_fingerprint: receipt.fingerprint(),
            stage_receipt: receipt.clone(),
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            server_name: authorization.server_name.clone(),
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: authorization.active_generation,
            next_generation: authorization.next_generation,
            active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            next_tls_certificate: authorization.next_tls_certificate.clone(),
            next_pq_certificate: authorization.next_pq_certificate.clone(),
            stage_expires_at: authorization.stage_expires_at,
            window: authorization.window,
            reason: authorization.reason,
            signature: MlDsa87Signature::placeholder(),
        };
        Ok(grant.sign(&self.pq_private_key)?)
    }

    /// The candidate generation this issuance describes.
    pub fn candidate(
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<ClientCertificateGeneration, CertificateError> {
        Ok(ClientCertificateGeneration {
            generation: authorization.next_generation,
            ca_tls_epoch: authorization.ca_tls_epoch,
            tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            tls_certificate_fingerprint: authorization.next_tls_certificate.fingerprint(),
            pq_certificate_fingerprint: pq_certificate_fingerprint(
                &authorization.next_pq_certificate,
            )?,
            not_before: authorization.next_pq_certificate.not_before_unix,
            not_after: authorization.next_pq_certificate.not_after_unix,
        })
    }
}

#[cfg(test)]
mod tests;

/// Where one delegation's ML-DSA-87 private half is sealed in the state volume.
///
/// Named here rather than in the two callers, because «where the key is» is
/// one fact: a request written by one path and adopted by another must look
/// in the same place, and two spellings of the same format string is exactly
/// how they stop doing so.
pub fn pq_key_path(state_dir: &std::path::Path, issuer_epoch: u64) -> std::path::PathBuf {
    state_dir.join(format!("issuer-pq-key-{issuer_epoch}.bin"))
}

/// Where one delegation's TLS private half is sealed in the state volume.
pub fn tls_key_path(state_dir: &std::path::Path, issuer_epoch: u64) -> std::path::PathBuf {
    state_dir.join(format!("issuer-tls-key-{issuer_epoch}.der"))
}

/// Everything that must be true before a signed delegation is recorded.
///
/// Three checks from three different places, and the delegation is only
/// installed when all three agree: the anchor and epochs this registry pins,
/// the issuance policy confirmed out of band at bootstrap, and the private
/// halves already sealed in the state volume. A file that satisfies all three
/// is one this authority can actually issue under; skipping the last would
/// announce an issuer whose first use fails at 80 % of a client's leaf — and
/// would make the next start-up refuse to load a registry it just wrote.
///
/// Recording the delegation already held is a no-op, so an operator result
/// whose response was lost may be redeposited byte for byte (§8.2).
#[derive(Debug, thiserror::Error)]
pub enum AdoptionError {
    #[error("delegation refused under this domain's anchor: {0}")]
    Authorization(#[from] CertificateError),
    #[error("the delegation does not match the pinned Astra issuance policy: {0}")]
    Policy(#[source] CertificateError),
    #[error(
        "no private material for issuer epoch {issuer_epoch} in this state volume: the \
         delegation answers a request another state directory made"
    )]
    NoPrivateMaterial { issuer_epoch: u64 },
    #[error("reading the delegated issuer's private material: {0}")]
    PrivateMaterial(#[source] std::io::Error),
    #[error("the delegation does not match the private material on disk: {0}")]
    Possession(#[source] IssuerError),
    #[error("recording the delegation: {0}")]
    Registry(#[from] crate::registry::RegistryError),
}

/// Verifies a signed delegation and records it (spec §9.5).
///
/// Shared by the local `astra issuer install` and by the operator result the
/// service accepts on the §8.2 transport, because the checks are the same
/// checks: which path the document arrived by decides nothing about whether
/// this authority may issue under it.
pub fn adopt(
    registry: &mut crate::registry::AstraRegistry,
    authorization: AstraIssuerAuthorization,
    pq_key_path: &std::path::Path,
    tls_key_path: &std::path::Path,
    now_unix: u64,
) -> Result<u64, AdoptionError> {
    // `None` unless this delegation is the one that carries the domain off the
    // superseded per-request policy; then it is the pin to persist with it.
    let adopted_policy = {
        let state = registry.state();
        authorization.verify(
            &state.ca_public_key,
            &state.trust_domain_id,
            state.ca_epoch,
            state.ca_tls_epoch,
            &state.gateway_wg_public_key,
            &state.server_name,
            now_unix,
        )?;
        // §2.4 ordering is preserved: `CA-PQ` has spoken above, and only then
        // is the policy the document names read.
        match state
            .astra_policy_fingerprint
            .assert_authorizes(&authorization)
        {
            Ok(()) => None,
            Err(refusal) => match state
                .astra_policy_fingerprint
                .adopt_automatic_renewal_policy(
                    state.trust_domain_id,
                    state.gateway_wg_public_key,
                    &state.server_name,
                    &authorization,
                ) {
                Ok(PolicyMigration::Adopted(pin)) => Some(pin),
                // The pin already names the current policy, yet the delegation
                // did not match it: the document carries some third policy.
                // The first refusal is the accurate one.
                Ok(PolicyMigration::AlreadyCurrent) => return Err(AdoptionError::Policy(refusal)),
                Err(_) => return Err(AdoptionError::Policy(refusal)),
            },
        }
    };

    let issuer_epoch = authorization.issuer_epoch;
    if !pq_key_path.exists() || !tls_key_path.exists() {
        return Err(AdoptionError::NoPrivateMaterial { issuer_epoch });
    }
    let pq_private_key =
        Zeroizing::new(std::fs::read(pq_key_path).map_err(AdoptionError::PrivateMaterial)?);
    let tls_private_key =
        Zeroizing::new(std::fs::read(tls_key_path).map_err(AdoptionError::PrivateMaterial)?);
    DelegatedIssuer::load(authorization.clone(), pq_private_key, tls_private_key)
        .map_err(AdoptionError::Possession)?;

    registry.install_issuer_adopting_policy(
        aether::certificates::state::AstraIssuerState {
            issuer_epoch,
            authorization,
            state: aether::certificates::state::IssuerLifecycle::Active,
        },
        adopted_policy,
        now_unix,
    )?;
    Ok(issuer_epoch)
}
