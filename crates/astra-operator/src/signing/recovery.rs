//! Recovering an expired client identity, and granting the recovered leaves.

use super::*;

/// What one recovery ceremony produced (spec §7.5).
///
/// Both halves, because one touch made both: the assertion answers the
/// recovery challenge, and the PRF output of that same session opens the
/// key-slot whose `CA-PQ` signs the authorization. Returning them separately
/// would let a caller present one without the other.
pub struct RecoveryAuthorization {
    pub authorization: ClientCertificateStageAuthorization,
    pub evidence: ExpiredRecoveryApprovalEvidence,
}

/// Approves and authorizes the recovery of an expired identity (spec §7.5).
///
/// # The order, and why it is not negotiable
///
/// The request is verified against the domain **before** the operator is asked
/// to touch anything: a key must never be asked to answer for fields nothing
/// vouches for. Then the assertion is produced and **verified here**, under the
/// credential's own `CA-PQ`-signed row, before its PRF output is used to open
/// the vault — §7.5 requires exactly that, and the reason is that an assertion
/// which does not verify is an assertion whose session should not be trusted
/// to unseal an anchor.
///
/// Only then are the two leaves issued and the staging signed. `CA-PQ` signs
/// it, never the delegated issuer: a bounded online key that could revive an
/// expired identity would be a key that can undo a validity period.
///
/// # Limite connue : deux touchers plutôt qu'un
///
/// §7.5 asks for a **single** `GetAssertion` carrying both the challenge and
/// the PRF salt. [`Authenticator`] deliberately splits the two — `approve`
/// takes no salt at all, which is what makes §14.1 hold by construction — so
/// this gesture asks the same key, in the same session, twice. The security
/// properties are the ones §7.5 names: same credential, same connection, and
/// the assertion verified before the secret is used. What is missing is the
/// convenience of one press. Merging them means a combined call in
/// `aether-fido` and in **both** transports, neither of which can be exercised
/// where this is built.
#[allow(clippy::too_many_arguments)]
pub fn recover_expired_identity(
    vault: &AuthorityVault,
    key: &dyn Authenticator,
    pin: &str,
    identity: &DomainIdentity,
    bindings: &CredentialRegistry,
    ca_tls_certificate: &DerCertificate,
    request: &ExpiredCertificateRecoveryRequest,
    subject_name: &str,
    window: TransitionWindow,
    validity: (u64, u64),
    stage_id: aether::certificates::encoding::Id16,
    serial: [u8; 16],
    webauthn_origin: &str,
    stage_expires_at: u64,
    now_unix: u64,
) -> Result<RecoveryAuthorization> {
    let ca_pq_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
    if request.trust_domain_id != identity.trust_domain_id
        || request.gateway_wg_public_key != identity.gateway_wg_public_key
    {
        return Err(GestureError::Anchors(
            "cette récupération vise un autre domaine ou une autre gateway".into(),
        ));
    }
    // A recovery request carries no policy fingerprint — §7.5 does not put one
    // in the transcript — so there is nothing here to compare a pin against.
    // The policy still governs the operation: it is checked where it *can* be,
    // by the gateway when this authorization arrives.
    bindings.verify(
        &ca_pq_public_key,
        &identity.trust_domain_id,
        &identity.gateway_wg_public_key,
        identity.ca_epoch,
        bindings.credential_registry_epoch,
    )?;
    validate_https_origin(webauthn_origin, &vault.rp_id)?;

    // The credential the request names, and it must be **active**: §7.5 is the
    // one operation that reaches past a validity period, and a lost or revoked
    // key must not be the thing that reaches.
    let binding = bindings
        .approvable()
        .into_iter()
        .find(|binding| binding.credential_id == request.credential_id)
        .ok_or_else(|| {
            GestureError::Anchors(
                "la demande nomme un credential que ce domaine ne tient pas pour actif".into(),
            )
        })?
        .clone();

    let approval_expires_at = request.expires_at;
    let mut approval = ExpiredRecoveryApproval {
        request_fingerprint: request.fingerprint(),
        astra_challenge: request.astra_challenge,
        approved_at: now_unix,
        expires_at: approval_expires_at,
        credential_id: binding.credential_id.clone(),
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: Fingerprint::from_bytes([0; 32]),
        webauthn_assertion: aether::certificates::webauthn::WebAuthnAssertion {
            authenticator_data: Vec::new(),
            client_data_json: Vec::new(),
            signature: Vec::new(),
        },
    };
    let challenge = approval.challenge();
    let answered = key.approve(
        &vault.rp_id,
        std::slice::from_ref(&binding.credential_id),
        &client_data(&challenge, webauthn_origin),
        pin,
    )?;
    if answered.credential_id != binding.credential_id {
        return Err(GestureError::Anchors(
            "la clé a répondu pour un autre credential que celui que la demande nomme".into(),
        ));
    }
    approval.assertion_fingerprint = answered.assertion.fingerprint();
    approval.webauthn_assertion = answered.assertion;

    // Verified before its session is trusted to unseal anything.
    verify_assertion(
        &approval.webauthn_assertion,
        &binding.credential_public_key,
        &AssertionExpectation {
            relying_party_id: &vault.rp_id,
            origin: webauthn_origin,
            challenge: &challenge,
        },
    )?;

    let opening = crate::gestures::open_with_authorized_key(key, vault, pin)?;
    if opening.credential_id != binding.credential_id {
        return Err(GestureError::Anchors(
            "le key-slot ouvert n'appartient pas au credential qui a approuvé".into(),
        ));
    }

    let evidence = ExpiredRecoveryApprovalEvidence {
        approval,
        credential_registry: bindings.clone(),
        webauthn_origin: webauthn_origin.to_string(),
    };
    let operator_approval_fingerprint = evidence.fingerprint()?;

    let authorization = with_anchors(vault, &opening, |secrets| {
        let tls_key_der = decode(&secrets.ca_tls_private_key, "clé privée CA-TLS")?;
        let tls_key = KeyPair::try_from(tls_key_der.as_slice())
            .map_err(|error| GestureError::Anchors(format!("clé privée CA-TLS : {error}")))?;
        let mut csr = CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().into())
            .map_err(|error| {
                GestureError::Anchors(format!("demande PKCS#10 illisible : {error}"))
            })?;
        // The period is the issuer's decision. Left alone the leaf silently
        // takes the library's default window and stops matching the generation
        // it belongs to.
        csr.params.not_before = to_offset_date_time(validity.0)?;
        csr.params.not_after = to_offset_date_time(validity.1)?;
        let issuer = Issuer::from_ca_cert_der(&ca_tls_certificate.as_bytes().into(), &tls_key)
            .map_err(|error| GestureError::Anchors(format!("CA-TLS illisible : {error}")))?;
        let signed = csr.signed_by(&issuer).map_err(|error| {
            GestureError::Anchors(format!("signature de la feuille TLS : {error}"))
        })?;
        let tls_leaf = DerCertificate::new(signed.der().to_vec())?;

        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let pq_leaf = aether::key_negotiation::issue_pq_certificate(
            aether::key_negotiation::PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial,
                subject: subject_name.to_string(),
                issuer: "helios-ca-pq".to_string(),
                role: aether::key_negotiation::PqCertificateRole::Client,
                wireguard_public_key: request.client_wg_public_key.to_base64(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                    .encode(request.new_ml_dsa_87_public_key.as_bytes()),
                not_before_unix: validity.0,
                not_after_unix: validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;

        let authorization = ClientCertificateStageAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            ca_tls_epoch: identity.ca_tls_epoch,
            // `CA-PQ` itself. The delegated issuer is not allowed near this.
            issuer_kind: IssuerKind::Master,
            issuer_epoch: identity.ca_epoch,
            issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
            issuer_authorization: None,
            stage_id,
            request_fingerprint: request.fingerprint(),
            renewal_authorization_fingerprint: operator_approval_fingerprint,
            // Neither delegated family. A recovery is authorized by the anchor
            // and by the assertion beside it, and carrying one of the other two
            // would leave «which one was checked» to the reader.
            renewal_approval: None,
            campaign_approval: None,
            gateway_wg_public_key: identity.gateway_wg_public_key,
            server_name: request.server_name.clone(),
            client_wg_public_key: request.client_wg_public_key,
            // The expired generation is the active one, as far as every
            // registry is concerned: nothing replaced it, it merely aged out.
            active_generation: request.expired_generation,
            next_generation: request.requested_generation,
            active_tls_certificate_fingerprint: request.expired_tls_certificate.fingerprint(),
            active_pq_certificate_fingerprint:
                aether::certificates::gateway::pq_certificate_fingerprint(
                    &request.expired_pq_certificate,
                )?,
            next_tls_ca_certificate_fingerprint: ca_tls_certificate.fingerprint(),
            next_tls_certificate: tls_leaf,
            next_pq_certificate: pq_leaf,
            issued_at: now_unix,
            stage_expires_at,
            window,
            reason: RotationReason::ExpiredRecovery,
            signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        Ok(authorization)
    })?;

    Ok(RecoveryAuthorization {
        authorization,
        evidence,
    })
}

/// Signs the grant once the gateway's receipt exists (spec §7.3, §7.5).
///
/// A recovery staging is `IssuerKind::Master`, so its grant is `CA-PQ`'s too:
/// the delegated issuer may not vouch for an operation it was never allowed to
/// authorize. The receipt is verified against **this exact authorization**
/// first — every field, not only the identifier — because a receipt naming the
/// right stage while describing another generation would otherwise be a valid
/// signature over the wrong fact.
#[allow(clippy::too_many_arguments)]
pub fn grant_recovered_identity(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    authorization: &ClientCertificateStageAuthorization,
    receipt: &GatewayCertificateStageReceipt,
    gateway_pq_public_key: &MlDsa87PublicKey,
    gateway_certificate_fingerprint: &Fingerprint,
) -> Result<ClientCertificateRotationGrant> {
    receipt.verify(
        gateway_pq_public_key,
        gateway_certificate_fingerprint,
        authorization,
    )?;
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let grant = ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            ca_epoch: authorization.ca_epoch,
            ca_tls_epoch: authorization.ca_tls_epoch,
            issuer_kind: authorization.issuer_kind,
            issuer_epoch: authorization.issuer_epoch,
            issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
            issuer_authorization: authorization.issuer_authorization.clone(),
            request_fingerprint: authorization.request_fingerprint,
            renewal_authorization_fingerprint: authorization.renewal_authorization_fingerprint,
            renewal_approval: None,
            campaign_approval: None,
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
        }
        .sign(&ca_pq_private_key)?;
        Ok(grant)
    })
}
