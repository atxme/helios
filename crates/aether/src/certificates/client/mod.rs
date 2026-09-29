//! The client identity: request, staging, receipt, grant, commit and the
//! recovery of an expired leaf — spec §7.
//!
//! # Why a renewal takes five objects instead of one
//!
//! The naive design is: the client asks, the authority issues, the client
//! installs. It has a hole. The authority would have handed out a leaf the
//! gateway has not admitted yet, and a client that then disappears leaves the
//! gateway either refusing an issued identity or holding a generation nobody
//! uses. The five objects close it by ordering the two persistences:
//!
//! 1. [`ClientCertificateRotationRequest`] — the client proves the active key,
//!    the new PQ key and the new TLS key. Three proofs, because continuity
//!    alone would let a stolen active identity pick the successor's keys.
//! 2. [`ClientCertificateStageAuthorization`] — the authority issues both
//!    leaves but does **not** release them; it authorizes the gateway to hold
//!    them as a candidate under a bounded lease.
//! 3. [`GatewayCertificateStageReceipt`] — the gateway persists the candidate,
//!    `fsync`s, and only then signs. This receipt is the proof that admission
//!    happened before issuance was revealed.
//! 4. [`ClientCertificateRotationGrant`] — the authority releases the leaves,
//!    and only against that receipt.
//! 5. [`ClientCertificateStageCommit`] — the client, having persisted the
//!    candidate, commits under both the active and the candidate key. Until
//!    then neither end can present the new generation.
//!
//! Without a commit before the lease expires, both ends purge the candidate
//! and `active + 1` becomes requestable again under a **new** `stage_id`. No
//! object of the dead stage is valid for the new one.
//!
//! # Why TLS and PQ are one indivisible generation
//!
//! A connection recognised under generation `N+1` must present and use the PQ
//! certificate of that same generation. `TLS N / PQ N+1` and `TLS N+1 / PQ N`
//! are refused (spec §3.3). Both pairs are individually valid, and treating
//! the two families as independent sets would let an attacker holding one half
//! of each generation assemble an identity that was never issued.

use serde::{Deserialize, Serialize};

use crate::key_negotiation::{PqCertificate, PqCertificateRole};

use super::{
    approval::{AstraCampaignApprovalEvidence, AstraPolicyPin, AstraRenewalApprovalEvidence},
    authority::{AstraIssuerAuthorization, RotationReason},
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, DerCertificate, Fingerprint, Id16,
        MlDsa87PublicKey, MlDsa87Signature, SignedTranscript, TrustDomainId, WireGuardKey,
    },
    gateway::pq_certificate_fingerprint,
    window::{
        require_next_generation, validate_lease, TransitionWindow, ValidityPeriod,
        MAX_RECOVERY_REQUEST_LIFETIME_SECS, MAX_REQUEST_LIFETIME_SECS, MAX_STAGE_LEASE_SECS,
    },
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};

const ROTATION_REQUEST_DOMAIN: &[u8] = b"helios-client-certificate-rotation-request-v5";
const STAGE_AUTHORIZATION_DOMAIN: &[u8] = b"helios-client-certificate-stage-authorization-v5";
const STAGE_RECEIPT_DOMAIN: &[u8] = b"helios-gateway-certificate-stage-receipt-v5";
const ROTATION_GRANT_DOMAIN: &[u8] = b"helios-client-certificate-rotation-grant-v5";
const STAGE_COMMIT_DOMAIN: &[u8] = b"helios-client-certificate-stage-commit-v5";
const RECOVERY_REQUEST_DOMAIN: &[u8] = b"helios-expired-client-certificate-recovery-request-v5";
const RECOVERY_APPROVAL_DOMAIN: &[u8] = b"helios-astra-expired-recovery-approval-v5";

/// Longest credential identifier accepted from a FIDO2 authenticator.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;

/// Verifies a client PQ leaf under whichever authority may have issued it.
///
/// After an ordinary renewal a client leaf chains to the **delegated Astra
/// issuer**, not to `CA-PQ`. A consumer that only ever tried the anchor would
/// refuse every renewed identity — which is exactly what happened to the
/// in-tunnel trust-update route before this existed.
///
/// The candidates are supplied by the caller, in the order it trusts them, and
/// they come from its own state: the anchor it pins and the delegation it has
/// installed. The certificate never names the key that verifies it.
pub fn verify_client_leaf_under_any(
    certificate: &PqCertificate,
    issuers: &[&MlDsa87PublicKey],
    client_wg_public_key: &WireGuardKey,
    now_unix: u64,
) -> Result<(), CertificateError> {
    if issuers.is_empty() {
        return Err(CertificateError::UnauthorizedIssuer);
    }
    for issuer in issuers {
        if certificate
            .verify(
                issuer.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                now_unix,
            )
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(CertificateError::UnauthorizedIssuer)
}

/// Authenticates a client PQ leaf by **identity**, against the one the verifier
/// itself recorded at admission, instead of by issuer.
///
/// A client's first leaf is issued by the operator CA. A domain registry does
/// not carry that authority — and must not learn it from the request it is
/// checking — so no issuer set can ever authenticate a first-generation leaf.
/// Astra refused every peer that had never renewed, which on a fresh domain is
/// every peer.
///
/// This is not the weaker question. An issuer set admits every certificate
/// that authority ever signed; the recorded leaf admits exactly one. What
/// identity does not replace is time: the validity window is still read
/// against `now_unix` below, because a leaf that was recorded is not a leaf
/// that is eternal.
pub fn verify_client_leaf_against_recorded(
    certificate: &PqCertificate,
    recorded: &PqCertificate,
    client_wg_public_key: &WireGuardKey,
    now_unix: u64,
) -> Result<(), CertificateError> {
    if certificate != recorded {
        return Err(CertificateError::UnauthorizedIssuer);
    }
    // The signature is not re-checked, and cannot be: its issuer is precisely
    // the authority this side does not hold. It was checked once, by the side
    // that admitted this exact certificate and stored it — which is what makes
    // the equality above an authentication rather than a comparison.
    if certificate.role != PqCertificateRole::Client
        || certificate.wireguard_public_key != client_wg_public_key.to_base64()
    {
        return Err(CertificateError::UnauthorizedIssuer);
    }
    if certificate.not_before_unix > now_unix || now_unix > certificate.not_after_unix {
        return Err(CertificateError::OutsideValidityPeriod);
    }
    Ok(())
}

/// One client generation: TLS and PQ bound together (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateGeneration {
    pub generation: u64,
    pub ca_tls_epoch: u64,
    pub tls_ca_certificate_fingerprint: Fingerprint,
    pub tls_certificate_fingerprint: Fingerprint,
    pub pq_certificate_fingerprint: Fingerprint,
    pub not_before: u64,
    pub not_after: u64,
}

impl ClientCertificateGeneration {
    pub fn validity(&self) -> Result<ValidityPeriod, CertificateError> {
        ValidityPeriod::new(self.not_before, self.not_after)
    }

    /// Whether this generation may be presented at `now_unix`.
    ///
    /// A status of `active` published by Astra never widens this: an expired
    /// leaf stays expired (spec §6 of ADR-008).
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        self.not_before <= now_unix && now_unix < self.not_after
    }

    /// Refuses the two mixed pairs of spec §3.3.
    ///
    /// Given the TLS and PQ fingerprints a connection actually presented, both
    /// must belong to *this* generation. Called by the gateway after mTLS and
    /// before any negotiation decision.
    pub fn accepts_pair(&self, tls: &Fingerprint, pq: &Fingerprint) -> bool {
        self.tls_certificate_fingerprint.matches(tls) && self.pq_certificate_fingerprint.matches(pq)
    }
}

/// Which authority signed a staging authorization or a grant (spec §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKind {
    /// `CA-PQ` itself, opened by the operator companion.
    Master,
    /// The bounded online delegation of [`AstraIssuerAuthorization`].
    Astra,
}

impl IssuerKind {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Master => 0,
            Self::Astra => 1,
        }
    }
}

mod commit;
mod grant;
mod recovery;
mod request;
mod stage;

pub use commit::{ClientCertificateStageCommit, StageCommitRequest};
pub use grant::ClientCertificateRotationGrant;
pub use recovery::{expired_recovery_approval_challenge, ExpiredCertificateRecoveryRequest};
pub use request::ClientCertificateRotationRequest;
pub use stage::{ClientCertificateStageAuthorization, GatewayCertificateStageReceipt};

/// Signing side of the client objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing;

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests;
