//! The client half of the in-tunnel trust update — spec §8.1.1 and §0.6.
//!
//! # What this asks, and what it never asks for
//!
//! One question: «here is every counter and fingerprint I hold, plus the hash
//! of my complete local state — is there anything for me?» The gateway answers
//! with nothing at all, or with one fragment of a signed transaction. There is
//! no way to ask for a *particular* object, and that is deliberate: a client
//! that could name what it wants could also decline to name a revocation.
//!
//! # The compare-and-swap token
//!
//! `base_state_fingerprint` is the hash of the **whole** local store, and it
//! travels inside the signed request (§0.6). Everything that comes back is
//! bound to it. So a transaction is only ever applied to the exact state it
//! was computed against: anything that moved the store in between — a
//! renewal committing, a revocation landing, a scheduled item coming due —
//! invalidates the transaction rather than applying a decision taken about a
//! state that no longer exists. The recomputation happens at
//! [`TrustStore::apply_transaction`], on the live store, not here.
//!
//! # Why a session and not a call
//!
//! A transaction is chunked, and one poll returns one fragment. The manifest
//! comes back with every fragment — so a manifest that changes mid-collection
//! is a conflict, not a resumption — and nothing is applied until the last
//! fragment lands. Holding that across polls is the session's whole job.

use std::time::Duration;

use aether::certificates::encoding::{Fingerprint, Id16};
use aether::certificates::transport::{
    AuthenticatedTrustUpdateRequest, PendingTrustTransaction, TrustUpdateRequest,
    MAX_TRUST_UPDATE_OBJECTS,
};
use aether::certificates::{CertificateError, CERTIFICATE_PROTOCOL_VERSION};
use aether::key_negotiation::PqCertificate;
use zeroize::Zeroizing;

use crate::certificates::{TrustError, TrustStore};

/// How long one poll may take.
///
/// The route is inside WireGuard and answers from a registry read; ten seconds
/// is generous. It exists so a gateway that accepts the connection and then
/// says nothing cannot pin the caller for good.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest number of polls one collection may spend.
///
/// A transaction is bounded at [`MAX_TRUST_UPDATE_OBJECTS`] objects and each
/// poll returns at least one fragment, so a well-behaved gateway finishes well
/// inside this. The bound is here so a gateway that returns the same fragment
/// forever ends the collection instead of spinning.
pub const MAX_POLLS: usize = MAX_TRUST_UPDATE_OBJECTS + 8;

#[derive(Debug, thiserror::Error)]
pub enum TrustUpdateError {
    #[error("trust update transport: {0}")]
    Transport(String),
    #[error("the gateway answered {status}")]
    Status { status: u16 },
    #[error("the gateway's answer could not be read: {0}")]
    Malformed(String),
    #[error(
        "the gateway sent a fragment without the manifest that owns it; a fragment alone \
         authorizes nothing"
    )]
    ManifestMissing,
    #[error(
        "the manifest changed while its fragments were being collected: a transaction is one \
         decision, and two of them cannot be assembled into it"
    )]
    ManifestChanged,
    #[error(
        "this transaction was built for a local state this client has already left; a new \
         request under the current state is the way forward"
    )]
    BaseStateMoved,
    #[error(
        "the gateway never finished this transaction within {MAX_POLLS} polls; nothing has been \
         applied"
    )]
    NeverCompleted,
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store: {0}")]
    Store(#[from] TrustError),
}

/// What one round of polling concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustUpdateOutcome {
    /// The gateway holds nothing this client lacks.
    UpToDate,
    /// A complete transaction was verified and applied, object by object.
    Applied { objects: usize },
}

/// One collection, from the first poll to the applied transaction.
pub struct TrustUpdateSession {
    url: String,
    http: reqwest::Client,
    request: AuthenticatedTrustUpdateRequest,
}

impl TrustUpdateSession {
    /// Builds and signs the request from the store's own state.
    ///
    /// Every field is read from the store, including the opaque token. Nothing
    /// is passed in that the store already knows: a caller that could supply a
    /// counter could ask about a state this client is not in, and the answer
    /// would be a transaction it then refuses at commit — a full fragment
    /// cycle spent on a mistake nobody can see from here.
    pub fn prepare(
        store: &TrustStore,
        heliosd_url: &str,
        certificate: PqCertificate,
        active_pq_private_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, TrustUpdateError> {
        let state = store.state();
        let mut request_id = [0u8; 16];
        aether::random::fill_public(&mut request_id)
            .map_err(|_| CertificateError::RandomnessUnavailable)?;

        let presented = aether::certificates::gateway::pq_certificate_fingerprint(&certificate)?;
        let request = TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new(request_id)?,
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            client_wg_public_key: state.client_wg_public_key,
            ca_epoch: state.gateway.ca_epoch,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
            astra_service_key_epoch: state.astra.astra_service_key_epoch,
            issuer_epoch: state.issuer_epoch,
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
            client_identity_generation: state.certificates.active.generation,
            active_gateway_tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
            active_gateway_certificate_fingerprint: state.gateway.active_pq_fingerprint()?,
            active_client_tls_certificate_fingerprint: state
                .certificates
                .active
                .tls_certificate_fingerprint,
            active_client_pq_certificate_fingerprint: state
                .certificates
                .active
                .pq_certificate_fingerprint,
            client_pq_certificate_fingerprint: presented,
            // The compare-and-swap token of §0.6, over the complete store.
            base_state_fingerprint: store.base_state_fingerprint()?,
        };

        Ok(Self {
            url: format!(
                "{}/api/key-negotiation/trust-update",
                heliosd_url.trim_end_matches('/')
            ),
            http: reqwest::Client::builder()
                .timeout(CALL_TIMEOUT)
                // The route is inside WireGuard. A system proxy would send a
                // signed request away from the gateway the profile names.
                .no_proxy()
                // And this route never redirects: following one would hand the
                // signed request to whatever host a compromised gateway chose.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| TrustUpdateError::Transport(error.to_string()))?,
            request: request.authenticate(certificate, active_pq_private_key)?,
        })
    }

    /// The token this collection is bound to, for logs.
    pub fn base_state_fingerprint(&self) -> Fingerprint {
        self.request.request.base_state_fingerprint
    }

    /// Polls until the transaction is whole, then applies it in one write.
    ///
    /// Nothing is written before the last fragment lands: `store.apply` is
    /// reached once, with the complete ordered object list, and it verifies
    /// each object under the anchors this client already holds — the manifest
    /// authorizes attribution and ordering, never a trust mutation.
    pub async fn run(
        &self,
        store: &mut TrustStore,
        now_unix: u64,
    ) -> Result<TrustUpdateOutcome, TrustUpdateError> {
        let mut pending: Option<PendingTrustTransaction> = None;
        let mut collected: Vec<aether::certificates::transport::TrustUpdateChunk> = Vec::new();
        for _ in 0..MAX_POLLS {
            let answer = self.poll().await?;
            let Some(chunk) = answer.chunk else {
                // No fragment. Either nothing is owed, or the gateway sent a
                // manifest alone — which authorizes nothing and is not a state
                // this collection can advance from.
                return match (answer.manifest, pending) {
                    (None, None) => Ok(TrustUpdateOutcome::UpToDate),
                    _ => Err(TrustUpdateError::ManifestMissing),
                };
            };
            let manifest = answer.manifest.ok_or(TrustUpdateError::ManifestMissing)?;

            let accumulator = match pending {
                None => {
                    // One cheap check before spending a whole fragment cycle:
                    // the token this transaction was built for against the one
                    // this store is in. Everything else — the signature, the
                    // authority, the window, the target — is checked by
                    // `verify_and_apply_transaction`, at the only instant that
                    // matters, and is deliberately not duplicated here.
                    if !manifest
                        .base_state_fingerprint
                        .matches(&store.base_state_fingerprint()?)
                    {
                        return Err(TrustUpdateError::BaseStateMoved);
                    }
                    pending = Some(PendingTrustTransaction::new(manifest));
                    pending.as_mut().expect("just set")
                }
                Some(ref mut accumulator) => {
                    // A manifest comes back with every fragment. A different
                    // one mid-collection is a second decision, and two of them
                    // cannot be assembled into one.
                    if !accumulator
                        .manifest_fingerprint()
                        .matches(&manifest.fingerprint())
                    {
                        return Err(TrustUpdateError::ManifestChanged);
                    }
                    accumulator
                }
            };
            accumulator.accept(&chunk)?;
            collected.push(chunk);
            if accumulator.is_complete() {
                let manifest = accumulator.manifest().clone();
                let objects =
                    store.verify_and_apply_transaction(&manifest, &collected, now_unix)?;
                return Ok(TrustUpdateOutcome::Applied { objects });
            }
        }
        Err(TrustUpdateError::NeverCompleted)
    }

    async fn poll(&self) -> Result<TrustUpdateAnswer, TrustUpdateError> {
        let body = serde_json::to_vec(&self.request)
            .map_err(|error| TrustUpdateError::Malformed(error.to_string()))?;
        let response = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(TrustUpdateError::Status {
                status: status.as_u16(),
            });
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| TrustUpdateError::Malformed(error.to_string()))
    }
}

/// The gateway's answer, exactly as `helios-api` renders it.
///
/// Redeclared here rather than imported: `orion-core` does not depend on the
/// gateway's crate, and a client that could only be built against the server's
/// own types would be a client that cannot be tested without one.
#[derive(Debug, Clone, serde::Deserialize)]
struct TrustUpdateAnswer {
    #[serde(default)]
    manifest: Option<aether::certificates::transport::TrustUpdateTransactionManifest>,
    #[serde(default)]
    chunk: Option<aether::certificates::transport::TrustUpdateChunk>,
}
