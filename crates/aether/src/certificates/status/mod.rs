//! Astra's signed state: status, campaigns, companion requests and the
//! bounded service rollback — spec §2.4, §7.6 and §8.2.
//!
//! # A status is freshness, never validity
//!
//! [`AstraCertificateStatus`] takes its shape from OCSP and stops exactly
//! where OCSP does: it says whether Astra considers a certificate revoked,
//! superseded or due for renewal. It never makes a leaf acceptable outside
//! `not_before..not_after`. Orion verifies the signature and the monotonicity,
//! then computes validity itself — a signed `active` on an expired leaf is a
//! statement about the registry, not a permission.
//!
//! Monotonicity is lexicographic on `(astra_service_key_epoch, status_epoch)`.
//! The key epoch is compared first, which is what stops a compromised service
//! key from publishing `status_epoch = u64::MAX` and freezing its own target
//! forever: as soon as the key transition is persisted, every status under the
//! old epoch is older, whatever number it carries.
//!
//! # A campaign is approved as a whole
//!
//! [`AstraRotationCampaign::fingerprint`] covers the SHA-256 of the complete
//! canonical campaign: every target, its key, its epoch, its generation and
//! its exact current fingerprints. Astra refuses a target added, removed or
//! modified afterwards — the difference between "renew these eleven leaves"
//! and "renew whatever this list holds when I get to it".
//!
//! # What a hardware credential does here, and what it never does
//!
//! It **never signs anything this module verifies.** No field in the whole
//! certificate lifecycle holds anything but an `MlDsa87Signature`, and a
//! YubiKey signs no ML-DSA — it has RSA, P-256/P-384 and Ed25519, nothing
//! post-quantum.
//!
//! Its job is authentication and key derivation: presence plus user
//! verification release a CTAP2 `hmac-secret` output, that output unwraps a
//! key-slot of the authority vault, and the anchors inside it produce the
//! ML-DSA-87 signature. The campaign fingerprint is what `astra-signer`
//! **displays** before asking for the touch, and what the resulting `CA-PQ`
//! signature is bound to.
//!
//! `required_credentials` follows from that: two is not a threshold anyone
//! verifies, it is two key-slots the companion must see opened before it will
//! sign — an operational barrier against a mistake and against one stolen key
//! used with an honest companion (ADR-008 §4, which says so in as many
//! words).

use serde::{Deserialize, Serialize};

use super::{
    encoding::{
        verify_ml_dsa_87, CanonicalBytes, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
        SignedTranscript, TrustDomainId, WireGuardKey,
    },
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

const STATUS_DOMAIN: &[u8] = b"helios-astra-certificate-status-v5";
const STATUS_QUERY_DOMAIN: &[u8] = b"helios-astra-certificate-status-query-v5";
const CAMPAIGN_APPROVAL_DOMAIN: &[u8] = b"helios-astra-rotation-campaign-approval-v5";
const SIGNER_REQUEST_DOMAIN: &[u8] = b"helios-astra-signer-request-v5";
const SERVICE_ROLLBACK_DOMAIN: &[u8] = b"helios-certificate-service-rollback-authorization-v5";

/// Largest campaign Astra will resolve, sign or apply (spec §8.2).
pub const MAX_CAMPAIGN_TARGETS: usize = 256;

/// Largest number of transition objects one campaign result may carry.
///
/// [`CampaignScope::TrustAuthorities`] names two anchors, so two is the whole
/// domain of the honest case. The ceiling is four to leave room for a scope
/// that later names more, and low enough that a result cannot be a delivery
/// vehicle for an object set nobody read.
pub const MAX_CAMPAIGN_OBJECTS: usize = 4;

mod campaign;
mod campaign_approval;
mod certificate_status;
mod rollback;
mod signer;

pub use campaign::{AstraRotationCampaign, CampaignFamily, CampaignScope, CampaignTarget};
pub use campaign_approval::{CampaignApproval, CredentialAssertion};
pub use certificate_status::{
    status_query_signing_bytes, AstraCertificateStatus, CertificateKind, CertificateStatus,
};
pub use rollback::CertificateServiceRollbackAuthorization;
pub use signer::{AstraSignerRequest, AstraSignerResult};

/// Signing side of the Astra objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing;

#[cfg(test)]
mod tests;
