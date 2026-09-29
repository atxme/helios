//! The gateway's identity: its bootstrap leaf, its transitions, their abort
//! and the bounded service rollback.

use super::*;

/// Operator-controlled contents of a gateway identity transition (spec §6.1).
pub struct GatewayTransitionDecision {
    pub gateway_identity_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub active_tls_fingerprint: Fingerprint,
    pub active_pq_fingerprint: Fingerprint,
    /// The key the gateway sealed and proved possession of, in its §5 request.
    pub next_pq_public_key: MlDsa87PublicKey,
    /// The gateway's candidate TLS leaf, when the renewal moves that half too.
    pub next_tls_certificate: Option<DerCertificate>,
    pub window: TransitionWindow,
    pub leaf_validity: (u64, u64),
    pub reason: RotationReason,
    pub serial: [u8; 16],
}

/// Public inputs of the one-time, continuity-free issuance (§13.1).
pub struct GatewayBootstrapDecision<'a> {
    pub request: &'a GatewayBootstrapRequest,
    pub leaf_validity: (u64, u64),
    pub serial: [u8; 16],
}

/// Issues epoch 1 directly under `CA-PQ`, before Astra has any online state.
pub fn issue_gateway_bootstrap_certificate(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &GatewayBootstrapDecision<'_>,
) -> Result<aether::key_negotiation::PqCertificate> {
    decision.request.verify()?;
    if decision.leaf_validity.1 <= decision.leaf_validity.0 {
        return Err(GestureError::Anchors(
            "période de validité de la feuille gateway vide".into(),
        ));
    }
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let leaf = aether::key_negotiation::issue_pq_certificate(
            aether::key_negotiation::PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: decision.serial,
                subject: decision.request.server_name.clone(),
                issuer: "helios-ca-pq".to_string(),
                role: aether::key_negotiation::PqCertificateRole::Gateway,
                wireguard_public_key: decision.request.gateway_wg_public_key.to_base64(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                    .encode(decision.request.ml_dsa_87_public_key.as_bytes()),
                not_before_unix: decision.leaf_validity.0,
                not_after_unix: decision.leaf_validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;
        leaf.verify(
            ca_pq_public_key.as_bytes(),
            aether::key_negotiation::PqCertificateRole::Gateway,
            Some(&decision.request.server_name),
            &decision.request.gateway_wg_public_key.to_base64(),
            decision.leaf_validity.0,
        )
        .map_err(|error| GestureError::Anchors(error.to_string()))?;
        Ok(leaf)
    })
}

/// Issues the next gateway leaf and signs its transition (spec §11.1 step 4).
///
/// Both halves in one gesture, for the reason [`authorize_issuer`] gives: the
/// transition's signature binds the exact leaf, so a transition signed around
/// a leaf issued in a separate step would bind whatever leaf was on disk.
///
/// Under `CA-PQ` and never under the delegated issuer. The delegation renews
/// admitted clients; the identity every client pins is not its to move.
pub fn sign_gateway_transition(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &GatewayTransitionDecision,
) -> Result<GatewayIdentityTransition> {
    // The leaf must outlive the decision it is installed by: a leaf expiring
    // inside its own overlap would retire the identity before the fleet has
    // finished adopting it.
    if decision.leaf_validity.0 > decision.window.not_before
        || decision.leaf_validity.1 < decision.window.not_after
    {
        return Err(GestureError::Anchors(
            "la validité de la feuille ne couvre pas la fenêtre de transition".into(),
        ));
    }
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let next_leaf = aether::key_negotiation::issue_pq_certificate(
            aether::key_negotiation::PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: decision.serial,
                subject: decision.server_name.clone(),
                issuer: "helios-ca-pq".to_string(),
                role: aether::key_negotiation::PqCertificateRole::Gateway,
                wireguard_public_key: decision.gateway_wg_public_key.to_base64(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                    .encode(decision.next_pq_public_key.as_bytes()),
                not_before_unix: decision.leaf_validity.0,
                not_after_unix: decision.leaf_validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;

        let transition = GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            gateway_identity_epoch: decision.gateway_identity_epoch,
            gateway_wg_public_key: decision.gateway_wg_public_key,
            server_name: decision.server_name.clone(),
            active_gateway_tls_certificate_fingerprint: decision.active_tls_fingerprint,
            next_gateway_tls_certificate: decision.next_tls_certificate.clone(),
            active_gateway_certificate_fingerprint: decision.active_pq_fingerprint,
            next_gateway_certificate: Some(next_leaf),
            window: decision.window,
            reason: decision.reason,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        // Verified under the anchor before it is returned, against the same
        // state the campaign froze: a transition that cannot be installed is
        // one an operator would carry back and be refused at, having spent the
        // ceremony.
        transition.verify(
            ca_pq_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
            decision
                .gateway_identity_epoch
                .checked_sub(1)
                .ok_or_else(|| GestureError::Anchors("époque de décision nulle".into()))?,
            &decision.gateway_wg_public_key,
            &decision.server_name,
            &decision.active_tls_fingerprint,
            &decision.active_pq_fingerprint,
        )?;
        Ok(transition)
    })
}

/// Operator-controlled contents of an abort (spec §6.3).
#[derive(Clone, Copy)]
pub struct GatewayAbortDecision<'a> {
    /// The document being cancelled, not merely its fingerprint: the object is
    /// verified against it at the end, which is the same check the gateway
    /// makes, and a fingerprint alone could not make it.
    pub transition: &'a GatewayIdentityTransition,
    pub reason: AbortReason,
    pub campaign_fingerprint: Fingerprint,
    pub aborted_at: u64,
}

/// Signs the cancellation of a staged, unpublished transition (spec §6.3).
///
pub fn sign_gateway_abort(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &GatewayAbortDecision<'_>,
) -> Result<GatewayTransitionAbort> {
    let GatewayAbortDecision {
        transition,
        reason,
        campaign_fingerprint,
        aborted_at,
    } = *decision;
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let abort = GatewayTransitionAbort {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            gateway_wg_public_key: transition.gateway_wg_public_key,
            server_name: transition.server_name.clone(),
            gateway_identity_epoch: transition.gateway_identity_epoch,
            gateway_transition_fingerprint: transition.fingerprint()?,
            aborted_at,
            reason,
            campaign_fingerprint,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        // `published` is false here and that is not an assumption about the
        // gateway: this companion cannot know what Astra has distributed. It
        // is the gateway that refuses a published transition, under its own
        // persisted marker, and this check only rejects an object that could
        // never be applied anywhere.
        abort.verify(ca_pq_public_key, transition, false, aborted_at)?;
        Ok(abort)
    })
}

/// What one service rollback selects (spec §4.4).
pub struct ServiceRollbackDecision<'a> {
    /// The staged transition whose overlap this selection lives inside.
    pub transition: &'a GatewayIdentityTransition,
    pub campaign_fingerprint: Fingerprint,
    /// When the selection lapses. At most the transition's `not_after`.
    pub expires_at: u64,
}

/// Signs the temporary selection of the outgoing gateway leaf (spec §4.4).
///
/// # Why the outgoing leaf is read from the transition
///
/// The transition names `active_gateway_tls_certificate_fingerprint` — the
/// leaf it is replacing — and `CA-PQ` signed that. Taking the selection from
/// an operator's command line instead would let one typo authorize serving a
/// certificate the domain never issued, and the gateway's own check would be
/// the only thing between that and a downgrade.
///
/// # Why no window is opened
///
/// A rollback moves no counter and removes no slot. It cannot outlive the
/// overlap it lives in, so its expiry is bounded here by `not_after` rather
/// than by a window of its own — a second window would be a second decision
/// about the same transition.
pub fn sign_service_rollback(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &ServiceRollbackDecision<'_>,
    now_unix: u64,
) -> Result<CertificateServiceRollbackAuthorization> {
    let ServiceRollbackDecision {
        transition,
        campaign_fingerprint,
        expires_at,
    } = *decision;
    if expires_at > transition.window.not_after || now_unix >= expires_at {
        return Err(GestureError::Anchors(
            "un rollback de service expire au plus tard avec le recouvrement qu'il vise, et pas              dans le passé"
                .into(),
        ));
    }
    let transition_fingerprint = transition.fingerprint()?;
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let authorization = CertificateServiceRollbackAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            gateway_wg_public_key: transition.gateway_wg_public_key,
            server_name: transition.server_name.clone(),
            transition_fingerprint,
            selected_certificate_fingerprint: transition.active_gateway_tls_certificate_fingerprint,
            campaign_fingerprint,
            expires_at,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        // Verified here against the same transition the gateway will verify it
        // against, so a document that could never be applied is not handed to
        // an operator to carry.
        authorization.verify(
            ca_pq_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
            &transition.gateway_wg_public_key,
            &transition.server_name,
            &transition_fingerprint,
            &transition.active_gateway_tls_certificate_fingerprint,
            transition.window.not_after,
            now_unix,
        )?;
        Ok(authorization)
    })
}
