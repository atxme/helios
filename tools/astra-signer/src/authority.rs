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

use aether::certificates::approval::{
    AstraCredentialBinding, CredentialState, ExpiredRecoveryApproval,
    ExpiredRecoveryApprovalEvidence,
};
use aether::certificates::authority::{
    AllowedUsage, AstraIssuerAuthorization, CaTransition, ClientTlsCaTransition, RotationReason,
};
use aether::certificates::client::{
    ClientCertificateRotationGrant, ClientCertificateStageAuthorization,
    ExpiredCertificateRecoveryRequest, GatewayCertificateStageReceipt, IssuerKind,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87PublicKey, MlDsa87Signature,
    TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::{
    AbortReason, GatewayBootstrapRequest, GatewayIdentityTransition, GatewayTransitionAbort,
};
use aether::certificates::revocation::{
    EmergencyCertificateRevocation, RevocationReason, RevocationScope,
};
use aether::certificates::status::{
    AstraRotationCampaign, CertificateServiceRollbackAuthorization,
};
use aether::certificates::webauthn::{
    validate_https_origin, verify_assertion, AssertionExpectation,
};
use aether::certificates::window::TransitionWindow;
use aether::certificates::{CertificateError, CERTIFICATE_FORMAT_VERSION};
use astra::vault::{AuthoritySecrets, AuthorityVault, CaTlsAdvance, RetainedCaTls};
use base64::Engine as _;
use helios_fido::authenticator::{Approval, Authenticator};
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

/// Operator-controlled contents of an emergency revocation (spec §10.1).
pub struct RevocationDecision {
    pub scope: RevocationScope,
    pub identity_key: WireGuardKey,
    pub server_name: Option<String>,
    pub revocation_epoch: u64,
    pub revoked_tls: Option<(Fingerprint, u64)>,
    pub revoked_pq: Option<(Fingerprint, u64)>,
    pub effective_at: u64,
    pub reason: RevocationReason,
    /// The one transition a revoked identity will still accept (spec §10.1).
    ///
    /// Naming it here is what makes the withdrawal recoverable: without it the
    /// state is terminal on every holder, and the service stays down until the
    /// trust domain is rebuilt.
    pub replacement_transition_fingerprint: Option<Fingerprint>,
}

/// Signs an emergency revocation with the master `CA-PQ` key.
///
/// A delegated online issuer may renew an admitted identity, but it may never
/// withdraw one. Requiring an already-opened vault here keeps that boundary in
/// the function signature.
pub fn sign_revocation(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &RevocationDecision,
    current_revocation_epoch: u64,
) -> Result<EmergencyCertificateRevocation> {
    if decision.revoked_tls.is_none() && decision.revoked_pq.is_none() {
        return Err(GestureError::Anchors(
            "une révocation doit nommer au moins une feuille".into(),
        ));
    }
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let revocation = EmergencyCertificateRevocation {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
            scope: decision.scope,
            identity_key: decision.identity_key,
            server_name: decision.server_name.clone(),
            revocation_epoch: decision.revocation_epoch,
            revoked_tls_fingerprint: decision.revoked_tls.map(|value| value.0),
            revoked_tls_not_after: decision.revoked_tls.map(|value| value.1),
            revoked_pq_fingerprint: decision.revoked_pq.map(|value| value.0),
            revoked_pq_not_after: decision.revoked_pq.map(|value| value.1),
            effective_at: decision.effective_at,
            reason: decision.reason,
            replacement_transition_fingerprint: decision.replacement_transition_fingerprint,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_pq_private_key)?;
        revocation.verify(
            ca_pq_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
            current_revocation_epoch,
        )?;
        Ok(revocation)
    })
}

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
    let mut session = CampaignApprovalSession::new(
        campaign,
        bindings,
        identity,
        ca_pq_public_key,
        webauthn_rp_id,
        webauthn_origin,
        now_unix,
    )?;
    if keys.len() != session.required() || pins.len() != session.required() {
        return Err(GestureError::Anchors(format!(
            "cette campagne exige {} credential(s) distinct(s), {} clé(s) fournie(s)",
            session.required(),
            keys.len()
        )));
    }
    for (key, pin) in keys.iter().zip(pins) {
        let offered = session.offered_credentials();
        let approval = key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            pin,
        )?;
        session.accept(approval, now_unix)?;
    }
    session.finish(now_unix)
}

/// A campaign approval collected one physical key at a time.
///
/// Platform WebAuthn handles select the authenticator that is plugged in when
/// `approve` runs. Keeping a list of handles and using it after the operator
/// swapped keys therefore does not preserve physical-key identity. This
/// session exposes the shrinking allow-list so callers can approve each key
/// while that key is still connected, then move to the next one.
pub struct CampaignApprovalSession {
    campaign_id: aether::certificates::encoding::Id16,
    fingerprint: Fingerprint,
    required_credentials: u8,
    expires_at: u64,
    webauthn_rp_id: String,
    webauthn_origin: String,
    client_data_json: Vec<u8>,
    offered: Vec<AstraCredentialBinding>,
    approvals: Vec<CredentialAssertion>,
}

impl CampaignApprovalSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: &AstraRotationCampaign,
        bindings: &CredentialRegistry,
        identity: &DomainIdentity,
        ca_pq_public_key: &MlDsa87PublicKey,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<Self> {
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

        let fingerprint = campaign.fingerprint();
        let client_data_json = client_data(&fingerprint, webauthn_origin);
        let offered: Vec<AstraCredentialBinding> =
            bindings.approvable().into_iter().cloned().collect();
        let required = usize::from(campaign.required_credentials);
        if offered.len() < required {
            return Err(GestureError::Anchors(format!(
                "{required} credential(s) actifs sont exigés, {} enregistré(s)",
                offered.len()
            )));
        }

        Ok(Self {
            campaign_id: campaign.campaign_id,
            fingerprint,
            required_credentials: campaign.required_credentials,
            expires_at: campaign.expires_at,
            webauthn_rp_id: webauthn_rp_id.to_string(),
            webauthn_origin: webauthn_origin.to_string(),
            client_data_json,
            offered,
            approvals: Vec::with_capacity(required),
        })
    }

    pub fn required(&self) -> usize {
        usize::from(self.required_credentials)
    }

    pub fn webauthn_rp_id(&self) -> &str {
        &self.webauthn_rp_id
    }

    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    pub fn offered_credentials(&self) -> Vec<Vec<u8>> {
        self.offered
            .iter()
            .map(|binding| binding.credential_id.clone())
            .filter(|id| {
                !self
                    .approvals
                    .iter()
                    .any(|approval| approval.credential_id == *id)
            })
            .collect()
    }

    pub fn accept(&mut self, approval: Approval, now_unix: u64) -> Result<()> {
        self.accept_for(approval, None, now_unix)
    }

    /// Accepts an assertion and, when the caller already opened a vault slot,
    /// binds it to that same physical credential.
    pub fn accept_for(
        &mut self,
        approval: Approval,
        expected_credential_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<()> {
        if now_unix >= self.expires_at {
            return Err(GestureError::Anchors(
                "la campagne a expiré pendant la cérémonie ; aucune transition ne sera signée"
                    .into(),
            ));
        }
        if self.approvals.len() >= self.required() {
            return Err(GestureError::Anchors(
                "cette campagne a déjà reçu toutes ses confirmations".into(),
            ));
        }
        if expected_credential_id.is_some_and(|expected| expected != approval.credential_id) {
            return Err(GestureError::Anchors(
                "la clé qui approuve n'est pas celle qui vient d'ouvrir le coffre ; recommencer avec une seule clé branchée"
                    .into(),
            ));
        }
        if self
            .approvals
            .iter()
            .any(|previous| previous.credential_id == approval.credential_id)
        {
            return Err(GestureError::Anchors(
                "la même clé a répondu deux fois : deux confirmations exigent deux objets \
                 distincts"
                    .into(),
            ));
        }
        let binding = self
            .offered
            .iter()
            .find(|binding| binding.credential_id == approval.credential_id)
            .ok_or_else(|| {
                GestureError::Anchors("la clé a répondu pour un credential non proposé".into())
            })?;
        verify_assertion(
            &approval.assertion,
            &binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: &self.webauthn_rp_id,
                origin: &self.webauthn_origin,
                challenge: &self.fingerprint,
            },
        )?;
        self.approvals.push(CredentialAssertion {
            credential_id: approval.credential_id,
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: approval.assertion.fingerprint(),
            assertion: approval.assertion,
        });
        Ok(())
    }

    pub fn finish(self, now_unix: u64) -> Result<CampaignApproval> {
        if now_unix >= self.expires_at {
            return Err(GestureError::Anchors(
                "la campagne a expiré pendant la cérémonie ; aucune transition ne sera signée"
                    .into(),
            ));
        }
        if self.approvals.len() != self.required() {
            return Err(GestureError::Anchors(format!(
                "cette campagne exige {} credential(s) distinct(s), {} confirmation(s) reçue(s)",
                self.required(),
                self.approvals.len()
            )));
        }
        Ok(CampaignApproval {
            campaign_id: self.campaign_id,
            campaign_fingerprint: self.fingerprint,
            required_credentials: self.required_credentials,
            approved_at: now_unix,
            approvals: self.approvals,
        })
    }
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
                retained_ca_tls: secrets.retained_ca_tls.clone(),
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
/// `helios-fido` and in **both** transports, neither of which can be exercised
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
        let issuer_params =
            CertificateParams::from_ca_cert_der(&ca_tls_certificate.as_bytes().into())
                .map_err(|error| GestureError::Anchors(format!("CA-TLS illisible : {error}")))?;
        let issuer = issuer_params
            .self_signed(&tls_key)
            .map_err(|error| GestureError::Anchors(format!("CA-TLS : {error}")))?;
        let signed = csr.signed_by(&issuer, &tls_key).map_err(|error| {
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
