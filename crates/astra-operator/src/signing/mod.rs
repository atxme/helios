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
//! §4). That is enforced by a type rather than by a convention:
//! [`approve_renewal`](aether_fido::approve_renewal) takes no
//! [`AuthorityVault`] at all, and the authenticator method it calls —
//! [`Authenticator::approve`] — is handed no salt, so there is no
//! `hmac-secret` output for it to obtain and no key-slot for it to unwrap. A
//! future edit that wanted to open the vault there would have to change both
//! signatures, which is the point. The function lives in `aether-fido`, a crate
//! that does not depend on the vault and could not even name it.
//!
//! Everything else in this module does the opposite, and says so by taking an
//! [`Opened`](crate::authenticator::Opened): issuing `CA-TLS`, signing a delegation, signing credential
//! bindings, rotating the anchor. Those hold private keys in memory for the
//! length of one operation and drop them.
//!
//! # What a security key signs here
//!
//! Nothing this protocol keeps. [`approve_renewal`](aether_fido::approve_renewal)
//! and [`approve_campaign`]
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
//! détenir : elle est en ligne, l'ancre ne l'est pas. [`approve_renewal`](aether_fido::approve_renewal) rend
//! donc l'objet complet avec un `astra_signature` de remplissage, qu'Astra
//! remplace par la sienne au moment de le persister. Tout le reste de l'objet
//! — l'assertion, le binding, les quatre empreintes — est produit et
//! **vérifié** ici, de sorte qu'Astra ne peut que signer un fait déjà établi.

use crate::vault::{AuthoritySecrets, AuthorityVault, CaTlsAdvance, RetainedCaTls};
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
use aether_fido::authenticator::{Approval, Authenticator};
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
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
/// Defined in `aether` and re-exported here rather than declared twice: the
/// two ends are two programs on two machines, and a field that drifted would
/// surface as a JSON refusal in the middle of a ceremony with a security key
/// already plugged in. Owned by `aether` rather than by `astra`, the end that
/// writes it, so that the companion does not depend on the online
/// coordinator to read one document.
pub use aether::certificates::authority::IssuerDelegationRequest;

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
pub use aether_fido::DomainIdentity;

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

mod anchor;
mod bindings;
mod ca_tls;
mod campaign;
mod gateway;
mod issuer;
mod recovery;
mod revocation;

pub use anchor::{rotate_ca_pq, RotatedAnchor};
pub use bindings::sign_credential_bindings;
pub use ca_tls::{advance_ca_tls, issue_ca_tls, rotate_ca_tls, RotatedClientTlsCa};
pub use campaign::{approve_campaign, CampaignApprovalSession};
pub use gateway::{
    issue_gateway_bootstrap_certificate, sign_gateway_abort, sign_gateway_transition,
    sign_service_rollback, GatewayAbortDecision, GatewayBootstrapDecision,
    GatewayTransitionDecision, ServiceRollbackDecision,
};
pub use issuer::authorize_issuer;
pub use recovery::{grant_recovered_identity, recover_expired_identity, RecoveryAuthorization};
pub use revocation::{sign_revocation, RevocationDecision};

// What the gestures name of each other, through `use super::*`.
use self::bindings::*;

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
