//! `CA-TLS`: issuing it under `CA-PQ`, rotating it, and advancing a
//! scheduled rotation.

use super::*;

/// Self-signs the client `CA-TLS` around the key the vault already holds.
///
/// The private key was drawn when the vault was created and has never left it;
/// this is the first and only time it is used, and it is used to prove
/// possession and certification capability (spec §9.4). The self-signature is
/// classic X.509 and never replaces a `ca_pq_signature` as a Helios
/// authorization — it says «this key can certify», not «this authority may».
pub fn issue_ca_tls(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    not_before: u64,
    not_after: u64,
) -> Result<DerCertificate> {
    if not_after <= not_before || not_after - not_before > MAX_CA_TLS_LIFETIME_SECS {
        return Err(GestureError::Anchors(format!(
            "période de validité hors bornes : au plus {MAX_CA_TLS_LIFETIME_SECS} secondes"
        )));
    }
    with_anchors(vault, opening, |secrets| {
        let key_der = decode(&secrets.ca_tls_private_key, "clé privée CA-TLS")?;
        let key = KeyPair::try_from(key_der.as_slice())
            .map_err(|error| GestureError::Anchors(format!("clé privée CA-TLS : {error}")))?;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(
            DnType::CommonName,
            format!(
                "Helios client CA-TLS {} epoch {}",
                identity.trust_domain_id, identity.ca_tls_epoch
            ),
        );
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| GestureError::Anchors(error.to_string()))?;
        params.distinguished_name = distinguished_name;
        // Unconstrained rather than a path length of zero: this CA signs the
        // delegated issuer's intermediate, which then signs the leaves.
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = to_offset_date_time(not_before)?;
        params.not_after = to_offset_date_time(not_after)?;

        let certificate = params
            .self_signed(&key)
            .map_err(|error| GestureError::Anchors(format!("auto-signature CA-TLS : {error}")))?;
        let der = DerCertificate::new(certificate.der().to_vec())?;
        // Proved rather than intended: a CA that cannot certify would only be
        // found when the first delegation refused to verify.
        aether::certificates::x509::assert_certificate_authority(&der)?;
        Ok(der)
    })
}

/// A `CA-TLS` rotation, and everything its two consumers need (spec §9.4).
pub struct RotatedClientTlsCa {
    pub transition: ClientTlsCaTransition,
    /// The incoming anchor, for the operator to read and for the gateway to
    /// pin. Its private half stayed in the vault.
    pub next_certificate: DerCertificate,
}

/// Rotates the client `CA-TLS`, under `CA-PQ` (spec §9.4).
///
/// # Why one credential and not two
///
/// §9.1 asks for two because it replaces the operator anchor — the key that
/// authorises everything else, including its own successor. `CA-TLS`
/// authenticates a transport, and the object that installs it is authorised by
/// `CA-PQ`, which does not move here. Requiring two would be borrowing the
/// weight of a different ceremony; the campaign scope is what carries it.
///
/// # Why the vault does not swap here
///
/// The successor is sealed **beside** the issuing key, not over it. §9.4 makes
/// the gateway prepare the anchor before anything is issued under it, and §4.1
/// puts an `activation_at` between the decision and that moment: a vault that
/// swapped at the ceremony would certify leaves the fleet does not yet accept,
/// and a crash before the decision reached the authority would leave an
/// operator holding an anchor nobody has heard of.
///
/// The outgoing key keeps issuing for the whole overlap — the gateway checks
/// `ca_tls_epoch` with strict equality and only advances it at `not_after`, so
/// stamping the next generation earlier would have every issuance of the
/// window refused. At `not_after`, [`AuthorityVault::advance_ca_tls`] promotes
/// the successor and destroys the outgoing private half in one sealed write,
/// which is where §9.2 permits that destruction and nowhere before.
pub fn rotate_ca_tls(
    vault: &mut AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    active_certificate: &DerCertificate,
    window: TransitionWindow,
    validity: (u64, u64),
) -> Result<RotatedClientTlsCa> {
    if validity.1 <= validity.0 || validity.1 - validity.0 > MAX_CA_TLS_LIFETIME_SECS {
        return Err(GestureError::Anchors(format!(
            "période de validité hors bornes : au plus {MAX_CA_TLS_LIFETIME_SECS} secondes"
        )));
    }
    window.validate()?;
    // The incoming anchor must outlive the window it opens: an anchor expiring
    // inside its own overlap would retire the chains it authorises while the
    // outgoing one is already scheduled for removal (§4.1).
    if validity.0 > window.not_before || validity.1 <= window.not_after {
        return Err(GestureError::Anchors(
            "la validité de la CA-TLS entrante ne couvre pas la fenêtre de transition".into(),
        ));
    }
    let next_ca_tls_epoch = identity
        .ca_tls_epoch
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;

    let key = KeyPair::generate()
        .map_err(|error| GestureError::Anchors(format!("clé CA-TLS suivante : {error}")))?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(
        DnType::CommonName,
        format!(
            "Helios client CA-TLS {} epoch {next_ca_tls_epoch}",
            identity.trust_domain_id
        ),
    );
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| GestureError::Anchors(error.to_string()))?;
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = to_offset_date_time(validity.0)?;
    params.not_after = to_offset_date_time(validity.1)?;
    let next_certificate = params
        .self_signed(&key)
        .map_err(|error| GestureError::Anchors(format!("auto-signature CA-TLS : {error}")))?;
    let next_certificate = DerCertificate::new(next_certificate.der().to_vec())?;
    // Proved rather than intended, exactly as at issuance.
    aether::certificates::x509::assert_certificate_authority(&next_certificate)?;

    let transition = with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let transition = ClientTlsCaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            current_ca_tls_epoch: identity.ca_tls_epoch,
            next_ca_tls_epoch,
            active_client_tls_ca_fingerprint: active_certificate.fingerprint(),
            next_client_tls_ca_certificate: next_certificate.clone(),
            window,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        transition.verify(
            &ca_pq_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
            identity.ca_tls_epoch,
            &active_certificate.fingerprint(),
        )?;
        Ok(transition)
    })?;
    let successor = RetainedCaTls {
        private_key: encode(&key.serialize_der()),
        certificate_fingerprint: next_certificate.fingerprint().to_hex(),
        counterpart_fingerprint: active_certificate.fingerprint().to_hex(),
        activation_at: window.activation_at,
        not_after: window.not_after,
    };

    // The object is signed and verified before the vault moves. A vault that
    // held a successor no transition names would leave the operator unable to
    // rotate again — the next ceremony would resolve its target from an anchor
    // the domain has never heard of.
    vault.stage_ca_tls_successor(&opening.credential_id, &opening.secret, successor)?;

    Ok(RotatedClientTlsCa {
        transition,
        next_certificate,
    })
}

/// Whether `certificate` certifies the key the vault issues under.
///
/// What an advanced vault says of its window, since it no longer holds one: the
/// private half is all that remains to compare.
pub fn issues_under(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    certificate: &DerCertificate,
) -> Result<bool> {
    with_anchors(vault, opening, |secrets| {
        let key_der = decode(&secrets.ca_tls_private_key, "clé privée CA-TLS")?;
        let key = KeyPair::try_from(key_der.as_slice())
            .map_err(|error| GestureError::Anchors(format!("clé privée CA-TLS : {error}")))?;
        Ok(rcgen::PublicKeyData::subject_public_key_info(&key)
            == aether::certificates::x509::subject_public_key_info(certificate)?)
    })
}

/// Closes an open `CA-TLS` window once its `not_after` has passed (spec §9.2).
///
/// A thin wrapper: the whole decision is [`AuthorityVault::advance_ca_tls`],
/// which does it in one re-seal. This exists so the command reaches it the
/// same way every other gesture reaches the anchors.
pub fn advance_ca_tls(
    vault: &mut AuthorityVault,
    opening: &crate::authenticator::Opened,
    now_unix: u64,
) -> Result<CaTlsAdvance> {
    Ok(vault.advance_ca_tls(&opening.credential_id, &opening.secret, now_unix)?)
}
