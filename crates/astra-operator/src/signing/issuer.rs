//! Delegating a bounded issuer to Astra.

use super::*;

/// Issues the delegated issuer's TLS intermediate and signs its authorization.
///
/// Both halves in one gesture, and that is not a convenience: the delegation's
/// signature binds the exact intermediate, so an authorization signed around
/// an intermediate issued in a separate step would be an authorization for
/// whatever intermediate was on disk at the time.
///
/// The result is verified under the anchor before it is returned, and the
/// pinned policy is compared before anything is signed — the §2.4 ordering,
/// applied to the producer as well as to the consumer.
pub fn authorize_issuer(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_tls_certificate: &DerCertificate,
    request: &IssuerDelegationRequest,
    bounds: &DelegationBounds,
    now_unix: u64,
) -> Result<AstraIssuerAuthorization> {
    // The certificate supplied beside the vault is a pinned anchor, not an
    // arbitrary issuer template.  Prove both its structure and that the
    // private key held by this vault really recreates this exact certificate
    // before issuing anything below it.
    aether::certificates::x509::assert_certificate_authority(ca_tls_certificate)?;
    let requested_domain = TrustDomainId::parse_hex(request.trust_domain_id.trim())?;
    if requested_domain != identity.trust_domain_id {
        return Err(GestureError::Anchors(format!(
            "la demande vise le domaine {requested_domain}, ce coffre porte {}",
            identity.trust_domain_id
        )));
    }
    if bounds.not_after <= bounds.not_before {
        return Err(GestureError::Anchors(
            "la fenêtre de délégation se termine avant de commencer".into(),
        ));
    }
    if bounds.maximum_leaf_lifetime_secs == 0 {
        return Err(GestureError::Anchors(
            "une délégation sans durée de leaf n'émet rien".into(),
        ));
    }
    let policy = identity.policy()?;
    if bounds.maximum_leaf_lifetime_secs > policy.maximum_leaf_lifetime_secs {
        return Err(GestureError::Anchors(format!(
            "la politique épinglée plafonne une leaf à {} secondes",
            policy.maximum_leaf_lifetime_secs
        )));
    }
    let policy_fingerprint = policy.fingerprint()?;
    let pq_issuer_public_key = MlDsa87PublicKey::parse(request.pq_issuer_public_key.trim())?;
    let csr_der = decode(&request.tls_intermediate_csr, "CSR de l'émetteur")?;

    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let ca_tls_key_der = decode(&secrets.ca_tls_private_key, "clé privée CA-TLS")?;
        let ca_tls_key = KeyPair::try_from(ca_tls_key_der.as_slice())
            .map_err(|error| GestureError::Anchors(format!("clé privée CA-TLS : {error}")))?;

        let mut csr = CertificateSigningRequestParams::from_der(&csr_der.into())
            .map_err(|error| GestureError::Anchors(format!("CSR de l'émetteur : {error}")))?;
        // A PKCS#10 request carries no validity and no basic constraints, and
        // must not: both are the issuer's decision. Left alone, the
        // intermediate would inherit the library's default window and stop
        // covering the delegation it is named by.
        csr.params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        csr.params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        csr.params.not_before = to_offset_date_time(bounds.not_before)?;
        csr.params.not_after = to_offset_date_time(
            bounds
                .not_after
                .checked_add(ISSUER_CERTIFICATE_MARGIN_SECS)
                .ok_or(CertificateError::ArithmeticOverflow)?,
        )?;

        let ca = Issuer::from_ca_cert_der(&ca_tls_certificate.as_bytes().into(), &ca_tls_key)
            .map_err(|error| GestureError::Anchors(format!("certificat CA-TLS : {error}")))?;
        let intermediate = csr
            .signed_by(&ca)
            .map_err(|error| GestureError::Anchors(format!("émission intermédiaire : {error}")))?;
        let intermediate = DerCertificate::new(intermediate.der().to_vec())?;
        aether::certificates::x509::assert_issued_by(&intermediate, ca_tls_certificate)?;
        let intermediate_facts = aether::certificates::x509::inspect(&intermediate)?;
        if !intermediate_facts.is_certificate_authority || !intermediate_facts.can_sign_certificates
        {
            return Err(GestureError::Anchors(
                "l'intermédiaire émis ne peut pas signer de certificats".into(),
            ));
        }
        aether::certificates::x509::assert_covers(
            ca_tls_certificate,
            bounds.not_before,
            bounds.not_after,
        )?;

        let authorization = AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            ca_tls_epoch: identity.ca_tls_epoch,
            gateway_wg_public_key: identity.gateway_wg_public_key,
            server_name: identity.server_name.clone(),
            issuer_epoch: request.issuer_epoch,
            pq_issuer_public_key,
            tls_intermediate_certificate: intermediate,
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: bounds.maximum_leaf_lifetime_secs,
            policy_fingerprint,
            not_before: bounds.not_before,
            not_after: bounds.not_after,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;

        // Verified here, under the anchor that just signed it, at the clock a
        // consumer will read it with. A delegation that would be refused on
        // arrival is better found on the operator's machine, while the vault
        // is still open.
        let verified_at = now_unix.max(bounds.not_before);
        authorization.verify(
            &MlDsa87PublicKey::parse(secrets.ca_pq_public_key.trim())?,
            &identity.trust_domain_id,
            identity.ca_epoch,
            identity.ca_tls_epoch,
            &identity.gateway_wg_public_key,
            &identity.server_name,
            verified_at,
        )?;
        Ok(authorization)
    })
}
