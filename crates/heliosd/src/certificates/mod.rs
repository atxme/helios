//! The gateway's certificate lifecycle service: one owner, one serializer.
//!
//! [`helios_provisioning::certificates::CertificateRegistry`] is a plain state
//! machine that takes `&mut self` and the clock as an argument. Something has
//! to own it, hold the lock, read the clock once per operation and hold the
//! sealed gateway key that signs receipts. That is this module, and there is
//! deliberately exactly one instance: a second one would give one slot two
//! writers, the same reason the negotiation state machine is a singleton.
//!
//! # What the gateway signs, and what it never signs
//!
//! It signs **receipts** — statements that a candidate is on its disk — with
//! its own active PQ leaf. It never signs a certificate, never holds `CA-PQ`,
//! and never calls an authority key on demand: every object it distributes was
//! pre-signed by Astra or by the operator companion (spec §8.1).
//!
//! # The gateway is a queue, not an author
//!
//! A transition reaches a client in two hops: the authority leaves a signed
//! transaction on the private veth (`POST
//! /internal/v1/certificates/distribution`), and the client collects its
//! fragments through `trust-update`. Nothing in between verifies a signature,
//! and that is the design: this process holds neither `CA-PQ` nor Astra's
//! service key, so any check it wrote would have to name an authority it does
//! have — exactly the substitution the receiver's own verification exists to
//! refuse. What it checks is the addressing, the fragment set and the
//! deadline; Orion checks the signatures, under anchors it already trusts.
//!
//! A caller that is provably behind with nothing queued for it still receives
//! [`TrustUpdateRefusal::Unavailable`] — a `503` — rather than an empty update,
//! because an empty update tells a client the opposite of the truth and it
//! would stop asking.
//!
//! # Limite connue : la réponse ne porte jamais de statut signé
//!
//! A status is signed by the **Astra service key**, which this process does not
//! hold and must not hold. Answering with an unsigned status, or with one
//! signed by the gateway leaf, would be inventing an authority. A client that
//! needs a signed freshness statement asks the authority for it through the
//! public channel of §8.2; what it gets here is the transaction itself, which
//! is what it actually has to apply.

use std::path::PathBuf;
use std::sync::Arc;

use ::astra_channel::AstraStageHandler;
use aether::certificates::client::GatewayCertificateStageReceipt;
use aether::certificates::{encoding::WireGuardKey, CertificateError};
use anyhow::{Context, Result};
use async_trait::async_trait;
use helios_api::certificates::GatewayActionRefusal;
use helios_api::certificates::{
    StageCommitRequest, TrustUpdateHandler, TrustUpdateRefusal, TrustUpdateResponse,
};
use helios_provisioning::certificates::{CertificateRegistry, RegistryError};
use tokio::sync::Mutex;

/// Signs a staging receipt with the gateway's **served** PQ leaf.
///
/// A trait, and not a copy of the private key, because that key is unsealed
/// exactly once — by the negotiation service — and the receipt has to be
/// signed by the leaf the client already pins. Handing this module a second
/// copy of the secret would be a second place to leak it from, for no gain.
pub trait StageReceiptSigner: Send + Sync {
    fn sign_stage_receipt(
        &self,
        receipt: GatewayCertificateStageReceipt,
    ) -> Result<GatewayCertificateStageReceipt, CertificateError>;

    /// The leaf this daemon actually serves.
    ///
    /// The **served** one, and that is the whole point: a rotation the daemon
    /// has not restarted for leaves a newer certificate on disk that no client
    /// is offered, and an authority verifying a receipt against the file would
    /// be verifying against a key that signed nothing. It comes from the same
    /// holder as the private half, so the two cannot disagree.
    fn served_pq_certificate(&self) -> aether::key_negotiation::PqCertificate;
}

/// Opens the registry once, for both the lifecycle and the negotiation.
///
/// Called before the negotiation starts, because the negotiation needs to read
/// it and the lifecycle service is built afterwards — it signs its receipts
/// through the negotiation handler. Loading it twice would put two writers on
/// one file.
///
/// A missing file is `None`, and that is not an empty domain: without `CA-PQ`
/// there is no anchor to verify anything against, so the lifecycle routes stay
/// closed rather than accepting the first object that arrives, and the
/// negotiation keeps to the pins of `network.toml`.
pub fn open_registry(path: &std::path::Path) -> Result<Option<SharedRegistry>> {
    let Some(registry) = CertificateRegistry::load(path)
        .with_context(|| format!("reading the certificate registry {}", path.display()))?
    else {
        return Ok(None);
    };
    Ok(Some(Arc::new(Mutex::new(registry))))
}

/// A registry behind its one lock, shared by its owner and its readers.
///
/// The **writer** is [`CertificateService`], and there is only ever one. The
/// key negotiation holds the same handle to *read* it: a caller resolved by
/// the fingerprint mTLS proved has to be looked up in the thing that recorded
/// the last rotation, not in a file written once at admission. One lock, one
/// registry — a second `CertificateRegistry` over the same path would be two
/// writers of one slot, which is the arrangement this module exists to avoid.
pub type SharedRegistry = Arc<Mutex<CertificateRegistry>>;

mod admission;
mod astra;
mod gateway_identity;
mod service;
mod trust_update;
mod views;

pub use admission::{queue_admission, spawn_admission_drain, QueuedAdmission};
pub use service::{spawn_maintenance, CertificateService};
pub use views::{domain_view, enrolment_view};

// Only the tests name these two helpers directly.
#[cfg(test)]
use self::{astra::assert_candidate_is_presentable, trust_update::client_leaf_issuers};

/// The two other routes of the private veth API (spec §8.3).
///
/// Staging lives in [`AstraStageHandler`] above; this adds revocation and the
/// read-back of one peer's state. All three go through the **same** mutex as
/// the in-tunnel commit and the maintenance sweep: a revocation has to dominate
/// a staging that is running concurrently, and it can only do that if both take
/// one serializer.
///
/// # Limite connue
///
/// A revocation whose scope is `gateway` is refused. Withdrawing the gateway's
/// own leaf is not a registry mutation but the identity transition of spec §6 —
/// it changes what the negotiation service serves, and that identity is read
/// once at startup and served until the process stops. Applying it here would
/// mark a state nothing acts on, which is worse than refusing. Delivering §6's
/// transition path, with the restart it implies, is what unblocks it.
/// The operator admission anchor, as the negotiation port reads it.
///
/// Absent when the file is missing or unreadable rather than fatal: the
/// authority then verifies a historical leaf under the domain's own
/// authorities alone, which is the behaviour that predates this field. A
/// gateway without it refuses recoveries of never-renewed identities; one that
/// failed the whole private channel over it would refuse everything.
fn admission_pq_ca() -> Option<aether::certificates::encoding::MlDsa87PublicKey> {
    let bytes = std::fs::read(crate::key_negotiation::CLIENT_PQ_CA_PATH).ok()?;
    aether::certificates::encoding::MlDsa87PublicKey::new(bytes).ok()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Whether the caller already holds everything this gateway would send it.
///
/// Every value the request declares is compared, and that exhaustiveness is
/// the property: a comparison that skipped a counter would answer "you are up
/// to date" to a client that is behind on exactly that counter, and the client
/// would stop asking. Since the only other answer this route can give today is
/// a `503`, a false "current" is the one outcome with no recovery — the client
/// has been told there is nothing to fetch.
///
/// Written as a free function over the persisted state so it can be exercised
/// without a runtime, a lock or a signer.
fn caller_is_current(
    state: &helios_provisioning::certificates::RegistryState,
    peer: &helios_provisioning::certificates::PeerCertificates,
    request: &aether::certificates::transport::TrustUpdateRequest,
) -> Result<bool, CertificateError> {
    let issuer_epoch = state
        .issuer
        .as_ref()
        .map_or(0, |issuer| issuer.issuer_epoch);
    Ok(request.ca_epoch == state.gateway.ca_epoch
        && request.ca_tls_epoch == state.client_tls_ca.ca_tls_epoch
        && request.astra_service_key_epoch == state.astra.astra_service_key_epoch
        && request.issuer_epoch == issuer_epoch
        && request.active_gateway_identity_epoch == state.gateway.active_gateway_identity_epoch
        && request.gateway_decision_epoch == state.gateway.gateway_decision_epoch
        && request
            .active_gateway_tls_certificate_fingerprint
            .matches(&state.gateway.active_tls_fingerprint())
        && request
            .active_gateway_certificate_fingerprint
            .matches(&state.gateway.active_pq_fingerprint()?)
        && request.client_identity_generation == peer.state.active.generation
        && request
            .active_client_tls_certificate_fingerprint
            .matches(&peer.state.active.tls_certificate_fingerprint)
        && request
            .active_client_pq_certificate_fingerprint
            .matches(&peer.state.active.pq_certificate_fingerprint))
}

/// Maps a registry refusal to the bounded class the API may report.
///
/// The detail goes to the protected log. A peer learns only the class, exactly
/// as on the public negotiation port: a finer taxonomy on an
/// authenticated-but-hostile caller is an oracle on other peers' generations.
fn classify(error: RegistryError) -> TrustUpdateRefusal {
    match error {
        RegistryError::Io(_) | RegistryError::Corrupt(_) => TrustUpdateRefusal::Internal,
        RegistryError::Certificate(CertificateError::UnsupportedFormatVersion { .. })
        | RegistryError::Certificate(CertificateError::UnsupportedProtocolVersion { .. }) => {
            TrustUpdateRefusal::Protocol
        }
        _ => TrustUpdateRefusal::Rejected,
    }
}

#[cfg(test)]
mod tests;
