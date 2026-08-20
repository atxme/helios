//! The signing gestures: what `CA-PQ` and `CA-TLS` are opened for.
//!
//! Like [`crate::gestures`], these are the sequences without the prompts, so
//! the order of the steps is exercised rather than only performed. What is new
//! here is that they produce **signed objects**, and every one of those
//! signatures is an `MlDsa87Signature` of a key that came out of the sealed
//! body. No security key produces one; see below.
//!
//! # The one rule that shapes this module
//!
//! An ordinary client renewal must not open the vault (spec §14.1, ADR-008
//! §4). That is enforced here by a type rather than by a convention:
//! [`approve_renewal`] takes no [`AuthorityVault`] at all, and the
//! authenticator method it calls — [`Authenticator::approve`] — is handed no
//! salt, so there is no `hmac-secret` output for it to obtain and no key-slot
//! for it to unwrap. A future edit that wanted to open the vault there would
//! have to change both signatures, which is the point.
//!
//! Everything else in this module does the opposite, and says so by taking an
//! [`Opened`]: issuing `CA-TLS`, signing a delegation, signing credential
//! bindings, rotating the anchor. Those hold private keys in memory for the
//! length of one operation and drop them.
//!
//! # What a security key signs here
//!
//! Nothing this protocol keeps. [`approve_renewal`] and [`approve_campaign`]
//! obtain a WebAuthn assertion, and that assertion **authorizes** — it names
//! the exact request or campaign an operator agreed to, and travels beside the
//! ML-DSA-87 objects rather than inside them. A YubiKey 5 holds RSA, P-256 and
//! Ed25519; the certificate lifecycle has no field any of those can fill.
//!
//! # Why bindings are rebuilt rather than edited
//!
//! See [`crate::credentials`]. Every gesture that changes the key-slot table
//! returns a whole new [`CredentialRegistry`] derived from that table, so a
//! binding describing a slot the vault no longer holds is not refused — it is
//! never constructed.
//!
//! # Limite connue : le compagnon ne parle pas encore aux routes du §8.2
//!
//! Chaque geste lit et écrit des **documents locaux**. Récupérer
//! l'`AstraSignerRequest` et déposer le résultat par les routes à jeton de
//! capacité du §8.2 n'est pas câblé, parce qu'Astra les sert en `501` : il n'y
//! a rien à appeler. Ce qui débloque : les routes `signer-requests`,
//! `vaults` et `signer-results` côté Astra, dont les jetons sont déjà décrits
//! et vérifiés par `aether::certificates::capability`.
//!
//! # Limite connue : `AstraRenewalApproval` sort sans la signature de service
//!
//! Le compagnon ne détient pas la clé de service Astra, et ne doit pas la
//! détenir : elle est en ligne, l'ancre ne l'est pas. [`approve_renewal`] rend
//! donc l'objet complet avec un `astra_signature` de remplissage, qu'Astra
//! remplace par la sienne au moment de le persister. Tout le reste de l'objet
//! — l'assertion, le binding, les quatre empreintes — est produit et
//! **vérifié** ici, de sorte qu'Astra ne peut que signer un fait déjà établi.

use aether::certificates::approval::{AstraCredentialBinding, CredentialState};
use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization, CaTransition};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId,
};
use aether::certificates::status::AstraRotationCampaign;
use aether::certificates::webauthn::{
    validate_https_origin, verify_assertion, AssertionExpectation,
};
use aether::certificates::window::TransitionWindow;
use aether::certificates::{CertificateError, CERTIFICATE_FORMAT_VERSION};
use astra::vault::{AuthoritySecrets, AuthorityVault};
use base64::Engine as _;
use helios_fido::authenticator::Authenticator;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, KeyPair, KeyUsagePurpose,
};

use crate::credentials::CredentialRegistry;
use crate::gestures::{GestureError, Result};

/// Longest life this companion will self-sign a `CA-TLS` for.
///
/// Ten years. A client TLS CA is pinned by the gateway and rotated by §9.4
/// rather than by expiry, and a shorter default would make the whole fleet
/// depend on a renewal nobody scheduled.
pub const MAX_CA_TLS_LIFETIME_SECS: u64 = 10 * 365 * 86_400;

/// How far past a delegation's window its TLS intermediate is issued for.
///
/// Spec §4.1 asks a certificate to cover the whole span it is in service for,
/// and asks it strictly: `not_after > until`. An intermediate cut at exactly
/// the delegation's `not_after` therefore fails the check its own
/// [`AstraIssuerAuthorization::verify`] runs, and fails it at the far end
/// rather than here. A day of margin makes the property hold under clock skew
/// instead of by one second, and buys nothing else: the delegation, not the
/// certificate, is what bounds issuance.
pub const ISSUER_CERTIFICATE_MARGIN_SECS: u64 = 86_400;

/// Operator credentials the anchor rotation of §9.1 requires.
///
/// Two, and distinct: §2.4 states it for every operation that touches an
/// anchor. The vault stays 1-of-N — this is an approval policy the honest
/// companion applies, never a cryptographic threshold, and the interfaces must
/// say « confirmation par deux clés » rather than « M-sur-N ».
pub const ANCHOR_ROTATION_CREDENTIALS: usize = 2;

/// What Astra asks the companion to delegate to, for one issuer epoch.
///
/// Defined by `astra`, which is the end that **writes** it, and re-exported
/// here rather than declared twice: the two ends are two programs on two
/// machines, and a field that drifted would surface as a JSON refusal in the
/// middle of a ceremony with a security key already plugged in.
pub use astra::issuer::IssuerDelegationRequest;

/// n   The bounds an operator sets on one delegation.
#[derive(Debug, Clone, Copy)]
pub struct DelegationBounds {
    pub maximum_leaf_lifetime_secs: u64,
    pub not_before: u64,
    pub not_after: u64,
}

/// The domain, as every gesture here needs to know it.
///
/// Defined at the approval boundary and re-exported: Orion needs the same five
/// values to run the ceremony of §14.1, and two definitions of a domain are
/// two things to keep equal.
pub use helios_fido::DomainIdentity;

/// The companion's campaign result, and the assertions inside it.
///
/// Defined in `aether` rather than here, because it is a **wire type**: this
/// program writes it and Astra reads it, on another machine. A shape owned by
/// the companion would make Astra depend on the one binary in the repository
/// that holds `CA-PQ` in the clear — the dependency ADR-008 §4 exists to
/// forbid. What the gesture below produces, `CampaignApproval::verify`
/// re-derives from the campaign and the `CA-PQ`-signed registry.
pub use aether::certificates::status::{CampaignApproval, CredentialAssertion};

fn decode(value: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| GestureError::Anchors(format!("{what} : base64 illisible")))
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn to_offset_date_time(seconds: u64) -> Result<time::OffsetDateTime> {
    let seconds = i64::try_from(seconds)
        .map_err(|_| GestureError::Anchors("horodatage hors bornes".into()))?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| GestureError::Anchors("horodatage hors bornes".into()))
}

/// Opens the anchors for the length of one operation.
///
/// A single helper so every gesture below reaches the private keys the same
/// way — through a slot the authenticator just opened — and none of them holds
/// the secrets any longer than the closure it is given.
fn with_anchors<T>(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    operation: impl FnOnce(&AuthoritySecrets) -> Result<T>,
) -> Result<T> {
    let secrets = vault.open(&opening.credential_id, &opening.secret)?;
    let outcome = operation(&secrets);
    drop(secrets);
    outcome
}

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

        let ca_params = CertificateParams::from_ca_cert_der(&ca_tls_certificate.as_bytes().into())
            .map_err(|error| GestureError::Anchors(format!("certificat CA-TLS : {error}")))?;
        let ca = ca_params
            .self_signed(&ca_tls_key)
            .map_err(|error| GestureError::Anchors(format!("certificat CA-TLS : {error}")))?;
        let intermediate = csr
            .signed_by(&ca, &ca_tls_key)
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

/// Rebuilds the whole credential document from the vault's key-slot table.
///
/// Called by every gesture that changes that table, in the **same** operation
/// (spec §2.4). The table is the input, so a binding for a slot the vault no
/// longer holds cannot be produced: withdrawn credentials keep a row, and it
/// says `revoked`.
///
/// `previous` carries the epochs and the states a decision already recorded.
/// A credential once `revoked` stays `revoked` — [`AstraCredentialBinding::
/// supersedes`] refuses the walk-back at the consumer, and refusing to produce
/// it here means the consumer never has to.
pub fn sign_credential_bindings(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
    now_unix: u64,
) -> Result<CredentialRegistry> {
    if let Some(previous) = previous {
        let current_ca = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
        previous.verify(
            &current_ca,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            previous.credential_registry_epoch,
        )?;
    }
    sign_credential_bindings_from_verified_previous(
        vault, opening, identity, previous, overrides, now_unix,
    )
}

/// Signs a new snapshot after the caller proved the previous one.
///
/// Kept separate for `CA-PQ` rotation: there the previous snapshot verifies
/// under the outgoing anchor, while the result must be signed under the new
/// one after the vault body has moved.
fn sign_credential_bindings_from_verified_previous(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
    now_unix: u64,
) -> Result<CredentialRegistry> {
    let registry_epoch = previous
        .map(|previous| previous.credential_registry_epoch)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let mut bindings = Vec::new();

        // One row per slot present, then one per credential that left. The two
        // loops are the whole invariant: the first cannot describe an absent
        // slot, and the second cannot describe a present one as revoked.
        for slot in &vault.slots {
            let credential_id = slot.credential_id()?;
            let state = state_of(&credential_id, previous, overrides)?;
            bindings.push(sign_binding(
                identity,
                credential_id,
                slot.credential_public_key()?,
                slot.aaguid,
                state,
                previous,
                registry_epoch,
                now_unix,
                &ca_pq_private_key,
            )?);
        }
        for old in previous
            .map(|previous| previous.bindings.as_slice())
            .unwrap_or_default()
        {
            if vault.slot_for_credential(&old.credential_id).is_ok() {
                continue;
            }
            bindings.push(sign_binding(
                identity,
                old.credential_id.clone(),
                old.credential_public_key.clone(),
                old.aaguid,
                CredentialState::Revoked,
                previous,
                registry_epoch,
                now_unix,
                &ca_pq_private_key,
            )?);
        }

        Ok(CredentialRegistry {
            trust_domain_id: identity.trust_domain_id,
            gateway_wg_public_key: identity.gateway_wg_public_key,
            ca_epoch: identity.ca_epoch,
            credential_registry_epoch: registry_epoch,
            bindings,
        })
    })
}

/// The state one credential carries into the new document.
///
/// A revocation is terminal: an override that tried to walk one back is
/// refused rather than applied, because the consumers refuse it too and a
/// document nobody accepts is worse than a command that failed.
fn state_of(
    credential_id: &[u8],
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
) -> Result<CredentialState> {
    let recorded = previous
        .and_then(|previous| previous.binding(credential_id))
        .map(|binding| binding.state);
    let requested = overrides
        .iter()
        .find(|(id, _)| id.as_slice() == credential_id)
        .map(|(_, state)| *state);
    match (recorded, requested) {
        (Some(CredentialState::Revoked), Some(state)) if state != CredentialState::Revoked => {
            Err(GestureError::Anchors(
                "une révocation est définitive : ce credential ne redevient pas actif".into(),
            ))
        }
        (_, Some(state)) => Ok(state),
        (Some(state), None) => Ok(state),
        (None, None) => Ok(CredentialState::Active),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_binding(
    identity: &DomainIdentity,
    credential_id: Vec<u8>,
    credential_public_key: Vec<u8>,
    aaguid: [u8; 16],
    state: CredentialState,
    previous: Option<&CredentialRegistry>,
    registry_epoch: u64,
    now_unix: u64,
    ca_pq_private_key: &[u8],
) -> Result<AstraCredentialBinding> {
    let recorded = previous.and_then(|previous| previous.binding(&credential_id));
    // The per-credential counter moves only when this credential's decision
    // moves. A counter that advanced with the registry would say every token
    // changed each time any one of them did.
    let credential_epoch = match recorded {
        Some(recorded) if recorded.state == state => recorded.credential_epoch,
        Some(recorded) => recorded
            .credential_epoch
            .checked_add(1)
            .ok_or(CertificateError::ArithmeticOverflow)?,
        None => 1,
    };
    let created_at = recorded
        .filter(|recorded| recorded.state == state)
        .map(|recorded| recorded.created_at)
        .unwrap_or(now_unix);

    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id,
        credential_public_key,
        aaguid,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        state,
        credential_epoch,
        credential_registry_epoch: registry_epoch,
        ca_epoch: identity.ca_epoch,
        created_at,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_pq_private_key)?;
    binding.supersedes(recorded)?;
    Ok(binding)
}

/// Approves a manual campaign, at as many distinct credentials as its scope
/// demands (spec §7.6).
///
/// `keys` are plugged one at a time, and the gesture refuses two answers from
/// the same credential: `TrustAuthorities` asking for two touches of one token
/// would be a policy that reads as two people and is one.
///
/// The challenge is the campaign fingerprint, which covers every target **and
/// their order** — so an approval cannot be reused for the same set applied
/// differently, and a target added afterwards is refused by
/// [`AstraRotationCampaign::assert_unchanged`].
#[allow(clippy::too_many_arguments)]
pub fn approve_campaign(
    keys: &[&dyn Authenticator],
    campaign: &AstraRotationCampaign,
    bindings: &CredentialRegistry,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    webauthn_rp_id: &str,
    webauthn_origin: &str,
    pins: &[&str],
    now_unix: u64,
) -> Result<CampaignApproval> {
    campaign.validate(now_unix)?;
    bindings.verify(
        ca_pq_public_key,
        &identity.trust_domain_id,
        &identity.gateway_wg_public_key,
        identity.ca_epoch,
        bindings.credential_registry_epoch,
    )?;
    if campaign.trust_domain_id != identity.trust_domain_id
        || campaign.gateway_wg_public_key != identity.gateway_wg_public_key
    {
        return Err(GestureError::Anchors(
            "cette campagne vise un autre domaine ou une autre gateway".into(),
        ));
    }
    // The pin decides before any target is read (spec §2.4).
    identity
        .policy()?
        .pin()?
        .assert_matches(&campaign.policy_fingerprint)?;
    validate_https_origin(webauthn_origin, webauthn_rp_id)?;

    let required = usize::from(campaign.required_credentials);
    if keys.len() != required || pins.len() != required {
        return Err(GestureError::Anchors(format!(
            "cette campagne exige {required} credential(s) distinct(s), {} clé(s) fournie(s)",
            keys.len()
        )));
    }

    let fingerprint = campaign.fingerprint();
    let client_data_json = client_data(&fingerprint, webauthn_origin);
    let offered: Vec<&AstraCredentialBinding> = bindings.approvable();
    if offered.len() < required {
        return Err(GestureError::Anchors(format!(
            "{required} credential(s) actifs sont exigés, {} enregistré(s)",
            offered.len()
        )));
    }

    let mut approvals: Vec<CredentialAssertion> = Vec::with_capacity(required);
    for (key, pin) in keys.iter().zip(pins) {
        // The allow-list shrinks with every answer, so the *token* refuses a
        // credential that already approved rather than a comparison after the
        // fact — the same discipline as the enrolment exclusion list.
        let credential_ids: Vec<Vec<u8>> = offered
            .iter()
            .map(|binding| binding.credential_id.clone())
            .filter(|id| {
                !approvals
                    .iter()
                    .any(|approval| approval.credential_id == *id)
            })
            .collect();
        let approval = key.approve(webauthn_rp_id, &credential_ids, &client_data_json, pin)?;
        if approvals
            .iter()
            .any(|previous| previous.credential_id == approval.credential_id)
        {
            return Err(GestureError::Anchors(
                "la même clé a répondu deux fois : deux confirmations exigent deux objets \
                 distincts"
                    .into(),
            ));
        }
        let binding = offered
            .iter()
            .find(|binding| binding.credential_id == approval.credential_id)
            .ok_or_else(|| {
                GestureError::Anchors("la clé a répondu pour un credential non proposé".into())
            })?;
        verify_assertion(
            &approval.assertion,
            &binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: webauthn_rp_id,
                origin: webauthn_origin,
                challenge: &fingerprint,
            },
        )?;
        approvals.push(CredentialAssertion {
            credential_id: approval.credential_id,
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: approval.assertion.fingerprint(),
            assertion: approval.assertion,
        });
    }

    Ok(CampaignApproval {
        campaign_id: campaign.campaign_id,
        campaign_fingerprint: fingerprint,
        required_credentials: campaign.required_credentials,
        approved_at: now_unix,
        approvals,
    })
}

/// What an anchor rotation produced.
pub struct RotatedAnchor {
    pub transition: CaTransition,
    pub next_ca_public_key: MlDsa87PublicKey,
    pub bindings: CredentialRegistry,
}

/// Rotates `CA-PQ`, under two distinct credentials (spec §9.1, §2.4).
///
/// Two signatures, and they answer different questions: the outgoing anchor
/// vouches for its successor, and the successor proves it holds its own key. A
/// caller with only one of them cannot produce a valid object, which is what
/// [`CaTransition::verify`] enforces at the far end.
///
/// The key-slots do not move: every credential that opened the vault before
/// opens it after. Only the body changes, and the clear `ca_pq_public_key`
/// moves in the same write.
///
/// The credential bindings are re-signed here too, under the **new** anchor
/// and the new `ca_epoch`. Leaving them behind would leave the domain holding
/// approvals verifiable only under an anchor it has just replaced.
pub fn rotate_ca_pq(
    vault: &mut AuthorityVault,
    openings: &[&crate::authenticator::Opened],
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    window: TransitionWindow,
    now_unix: u64,
) -> Result<RotatedAnchor> {
    if openings.len() != ANCHOR_ROTATION_CREDENTIALS {
        return Err(GestureError::Anchors(format!(
            "une rotation d'ancre exige {ANCHOR_ROTATION_CREDENTIALS} confirmations, {} \
             fournie(s)",
            openings.len()
        )));
    }
    if openings[0].credential_id == openings[1].credential_id {
        return Err(GestureError::Anchors(
            "les deux confirmations viennent de la même clé : elles doivent venir de deux objets \
             distincts"
                .into(),
        ));
    }
    // Both must genuinely open the vault, before anything is generated: an
    // operator whose second key does not work should find out now and not
    // after the anchor has moved.
    for opening in openings {
        let secrets = vault.open(&opening.credential_id, &opening.secret)?;
        drop(secrets);
    }
    if let Some(previous) = previous {
        let current_ca = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
        previous.verify(
            &current_ca,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            previous.credential_registry_epoch,
        )?;
    }
    window.validate()?;
    let next_ca_epoch = identity
        .ca_epoch
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    let (next_private_key, next_public_key) = generate_ml_dsa_87_keypair()?;
    let current_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
    let transition = with_anchors(vault, openings[0], |secrets| {
        let current_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let transition = CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            current_ca_epoch: identity.ca_epoch,
            next_ca_epoch,
            current_ca_fingerprint: current_public_key.authority_fingerprint(),
            next_ca_public_key: next_public_key.clone(),
            next_ca_fingerprint: next_public_key.authority_fingerprint(),
            window,
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&current_private_key, &next_private_key)?;
        transition.verify(
            &current_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
        )?;

        // The `CA-TLS` key rides through unchanged: §9.1 rotates the operator
        // anchor, and §9.4 is a separate transition with its own overlap. A
        // rotation that quietly replaced both would invalidate every mTLS
        // chain in the fleet on an operation nobody scheduled for it.
        Ok((
            transition,
            AuthoritySecrets {
                ca_pq_private_key: encode(&next_private_key),
                ca_pq_public_key: next_public_key.to_base64(),
                ca_tls_private_key: secrets.ca_tls_private_key.clone(),
            },
        ))
    })?;
    let (transition, next_secrets) = transition;

    vault.replace_anchors(
        &openings[0].credential_id,
        &openings[0].secret,
        &next_secrets,
    )?;

    let rotated_identity = DomainIdentity {
        ca_epoch: next_ca_epoch,
        ..identity.clone()
    };
    let bindings = sign_credential_bindings_from_verified_previous(
        vault,
        openings[0],
        &rotated_identity,
        previous,
        &[],
        now_unix,
    )?;

    Ok(RotatedAnchor {
        transition,
        next_ca_public_key: next_public_key,
        bindings,
    })
}

/// The `clientDataJSON` an authenticator signs over.
///
/// Composed here rather than by a platform, because there is no browser in
/// this path: the challenge is the SHA-256 of a canonical request or campaign,
/// and the origin is the signed Astra origin — never the gateway's HTTP URL,
/// even when the bytes travel through the tunnel relay (spec §2.4).
fn client_data(challenge: &Fingerprint, origin: &str) -> Vec<u8> {
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}
