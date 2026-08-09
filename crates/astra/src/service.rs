//! The public Astra endpoint — spec §8.2.
//!
//! Everything here is reachable from the Internet, so every rule of the public
//! QUIC port applies again: bodies bounded before deserialization, budgets per
//! IPv4 **or per IPv6 `/64`**, single-use challenges, and refusals that do not
//! distinguish "unknown peer" from "revoked" from "bad signature" before a
//! valid proof has been presented.
//!
//! # No status by fingerprint alone
//!
//! `POST /v1/status/challenge` hands out 32 random bytes without confirming
//! that any target exists, and `POST /v1/status/query` answers only against a
//! fresh signature by the PQ key of the exact identity being asked about.
//! Knowing a fingerprint observed on the wire therefore reveals neither
//! generation, nor window, nor rotation schedule.
//!
//! # Limite connue
//!
//! The operator-credential routes of spec §8.2 — campaigns, signer requests,
//! encrypted vault download and signer results — need a FIDO2 authenticator
//! and the `astra-signer` companion, neither of which exists yet and neither
//! of which can be exercised in WSL2. They are refused explicitly with
//! [`ServiceError::OperatorCredentialUnavailable`] and answer `501`, rather
//! than offering a path that would look like an approval without one. See
//! [`docs/testing/TESTING.md`](../../../../docs/testing/TESTING.md).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aether::certificates::{
    encoding::{Fingerprint, Id16, MlDsa87Signature, WireGuardKey},
    status::status_query_signing_bytes,
};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::issuer::DelegatedIssuer;
use crate::planner;
use crate::registry::{AstraRegistry, ChallengeStore};

/// Largest request body read before deserialization (spec §8.2).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Requests one source may make per window before it is refused.
pub const SOURCE_BUDGET: u32 = 30;
/// Length of the budget window, in seconds.
pub const BUDGET_WINDOW_SECS: u64 = 60;
/// Largest number of challenges held at once.
pub const MAX_LIVE_CHALLENGES: usize = 4096;

/// Refusals the public endpoint may produce.
///
/// Deliberately few, and deliberately uninformative: `Refused` covers unknown
/// peer, revoked peer, wrong generation and bad signature alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("malformed request")]
    Protocol,
    #[error("refused")]
    Refused,
    #[error("too many requests from this source")]
    Throttled,
    #[error(
        "this operation needs an operator hardware credential and the `astra-signer` companion, \
         which this build does not implement"
    )]
    OperatorCredentialUnavailable,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Refused => StatusCode::FORBIDDEN,
            Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::OperatorCredentialUnavailable => StatusCode::NOT_IMPLEMENTED,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // The reason travels in the protected log, never in the answer.
        (
            status,
            Json(ErrorBody {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

/// Budget keyed by IPv4 address or IPv6 `/64` prefix, and by admitted peer.
///
/// Two properties, and both are load-bearing:
///
/// - counting IPv6 by exact address makes a limit decorative: a single
///   ordinary allocation holds 2^64 of them, so the key is the `/64`;
/// - the map itself is **bounded**. An unbounded one turns a rate limit into a
///   memory-exhaustion primitive: every fresh source costs an entry, and an
///   attacker with a `/64` — or a botnet — has as many as they like. Past the
///   ceiling, stale windows are dropped and a source that still has no entry
///   is refused rather than admitted for free.
#[derive(Debug, Default)]
pub struct SourceBudget {
    sources: HashMap<[u8; 16], (u64, u32)>,
    peers: HashMap<[u8; 32], (u64, u32)>,
}

/// Largest number of sources tracked at once.
///
/// Sixty-five thousand entries is a few megabytes; beyond that the map is the
/// attack rather than the defence.
pub const MAX_TRACKED_SOURCES: usize = 65_536;
/// Largest number of admitted peers tracked at once.
pub const MAX_TRACKED_PEERS: usize = 4_096;
/// Requests one admitted identity may make per window (spec §8.2).
pub const PEER_BUDGET: u32 = 12;

/// Charges one request against a bounded per-key window.
fn charge_bounded<K: Copy + Eq + std::hash::Hash>(
    windows: &mut HashMap<K, (u64, u32)>,
    key: K,
    now_unix: u64,
    budget: u32,
    capacity: usize,
) -> bool {
    let window = now_unix / BUDGET_WINDOW_SECS;
    if !windows.contains_key(&key) && windows.len() >= capacity {
        // Drop what is already spent before refusing anything.
        windows.retain(|_, (seen, _)| *seen == window);
        if windows.len() >= capacity {
            return false;
        }
    }
    let entry = windows.entry(key).or_insert((window, 0));
    if entry.0 != window {
        *entry = (window, 0);
    }
    if entry.1 >= budget {
        return false;
    }
    entry.1 += 1;
    true
}

impl SourceBudget {
    /// Charges one request. `false` means the source is over budget.
    pub fn charge(&mut self, source: IpAddr, now_unix: u64) -> bool {
        charge_bounded(
            &mut self.sources,
            Self::key(source),
            now_unix,
            SOURCE_BUDGET,
            MAX_TRACKED_SOURCES,
        )
    }

    /// Charges one request against an admitted identity (spec §8.2).
    ///
    /// A network budget alone bounds an anonymous flood; it does nothing about
    /// one admitted peer spending the authority's signature budget from a
    /// thousand addresses.
    pub fn charge_peer(&mut self, peer: &WireGuardKey, now_unix: u64) -> bool {
        charge_bounded(
            &mut self.peers,
            *peer.as_bytes(),
            now_unix,
            PEER_BUDGET,
            MAX_TRACKED_PEERS,
        )
    }

    fn key(source: IpAddr) -> [u8; 16] {
        let mut key = [0u8; 16];
        match source {
            IpAddr::V4(address) => key[..4].copy_from_slice(&address.octets()),
            // The /64 prefix, not the address: the host half is free to the
            // attacker and counting it would bound nothing.
            IpAddr::V6(address) => key[..8].copy_from_slice(&address.octets()[..8]),
        }
        key
    }
}

/// Everything a request handler may touch.
pub struct AstraService {
    pub registry: Mutex<AstraRegistry>,
    pub issuer: Option<DelegatedIssuer>,
    pub challenges: Mutex<ChallengeStore>,
    pub budgets: Mutex<SourceBudget>,
    /// Signs statuses, challenges and operational answers. Never a leaf.
    pub service_private_key: Zeroizing<Vec<u8>>,
}

impl AstraService {
    async fn charge(&self, source: IpAddr, now_unix: u64) -> Result<(), ServiceError> {
        if self.budgets.lock().await.charge(source, now_unix) {
            Ok(())
        } else {
            Err(ServiceError::Throttled)
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Builds the public router.
pub fn router(service: Arc<AstraService>) -> Router {
    Router::new()
        .route("/v1/status/challenge", post(status_challenge))
        .route("/v1/status/query", post(status_query))
        .route("/v1/campaigns", post(operator_credential_required))
        .route(
            "/v1/client-rotation/recovery",
            post(operator_credential_required),
        )
        .route(
            "/v1/signer-results/:operation",
            post(operator_credential_required),
        )
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(service)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    pub astra_challenge: [u8; 32],
    pub expires_in_secs: u64,
}

/// `POST /v1/status/challenge`.
///
/// Answers the same way whether or not any target exists — it is issued before
/// anything is looked up, precisely so it confirms nothing.
async fn status_challenge(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
) -> Result<Json<ChallengeResponse>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;

    let mut challenge = [0u8; 32];
    aws_lc_random(&mut challenge).map_err(|_| ServiceError::Internal)?;
    if !service.challenges.lock().await.issue(challenge, now) {
        // Full rather than evicting: a flood must not invalidate the
        // challenges of clients that are mid-request.
        return Err(ServiceError::Throttled);
    }
    Ok(Json(ChallengeResponse {
        astra_challenge: challenge,
        expires_in_secs: crate::registry::CHALLENGE_LIFETIME_SECS,
    }))
}

/// Authenticated status query (spec §8.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    pub astra_challenge: [u8; 32],
    pub request_id: Id16,
    pub trust_domain_id: aether::certificates::encoding::TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub certificate_fingerprint: Fingerprint,
    pub certificate: aether::key_negotiation::PqCertificate,
    pub signature: MlDsa87Signature,
}

/// `POST /v1/status/query`.
async fn status_query(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Json(query): Json<StatusQuery>,
) -> Result<Json<aether::certificates::status::AstraCertificateStatus>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;

    // The challenge is consumed **before** any lookup: a query with a stale or
    // replayed challenge must not even reveal how long the lookup took.
    if !service
        .challenges
        .lock()
        .await
        .consume(&query.astra_challenge, now)
    {
        return Err(ServiceError::Refused);
    }

    let mut registry = service.registry.lock().await;
    let state = registry.state();
    if query.trust_domain_id != state.trust_domain_id
        || query.gateway_wg_public_key != state.gateway_wg_public_key
    {
        return Err(ServiceError::Refused);
    }
    let peer = registry
        .peer(&query.client_wg_public_key)
        .ok_or(ServiceError::Refused)?
        .clone();
    // Charged after the challenge and the lookup, before any ML-DSA work: the
    // per-identity budget is what stops one admitted peer from spending the
    // authority's signature budget from a thousand addresses.
    if !service
        .budgets
        .lock()
        .await
        .charge_peer(&query.client_wg_public_key, now)
    {
        return Err(ServiceError::Throttled);
    }

    // The proof is by the PQ key of the identity being asked about, verified
    // through the certificate the query carries — which must itself be the one
    // the registry records. A fingerprint alone proves nothing.
    let presented = aether::certificates::gateway::pq_certificate_fingerprint(&query.certificate)
        .map_err(|_| ServiceError::Refused)?;
    if !presented.matches(&peer.active.pq_certificate_fingerprint)
        || !query.certificate_fingerprint.matches(&presented)
    {
        return Err(ServiceError::Refused);
    }
    let public_key = aether::certificates::encoding::MlDsa87PublicKey::parse(
        &query.certificate.ml_dsa_87_public_key,
    )
    .map_err(|_| ServiceError::Refused)?;
    let transcript = status_query_signing_bytes(
        &query.trust_domain_id,
        &query.astra_challenge,
        &query.request_id,
        &query.gateway_wg_public_key,
        &query.client_wg_public_key,
        &query.certificate_fingerprint,
    );
    aether::certificates::verify_ml_dsa_87(&public_key, &transcript, &query.signature)
        .map_err(|_| ServiceError::Refused)?;

    let status_epoch = registry.next_status_epoch(&peer.active.pq_certificate_fingerprint);
    let service_key_epoch = registry.state().astra_service_key_epoch;
    let trust_domain_id = registry.state().trust_domain_id;
    let status = planner::client_status(
        trust_domain_id,
        &peer,
        status_epoch,
        service_key_epoch,
        now,
        now + 3_600,
    )
    .map_err(|_| ServiceError::Internal)?
    .sign(&service.service_private_key)
    .map_err(|_| ServiceError::Internal)?;

    registry
        .record(
            crate::audit::AuditEvent::StatusPublished {
                target: peer.name.clone(),
                status_epoch,
            },
            now,
        )
        .map_err(|_| ServiceError::Internal)?;

    Ok(Json(status))
}

/// Every route that needs a hardware credential, refused in one place.
///
/// A named refusal rather than a silent stub: an operator who calls this must
/// learn that the approval path does not exist in this build, not receive
/// something that looks like an approval.
async fn operator_credential_required() -> ServiceError {
    ServiceError::OperatorCredentialUnavailable
}

fn aws_lc_random(buffer: &mut [u8]) -> Result<(), ()> {
    use aws_lc_rs::rand::SecureRandom as _;
    aws_lc_rs::rand::SystemRandom::new()
        .fill(buffer)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv6_budget_counts_prefixes_not_addresses() {
        let mut budget = SourceBudget::default();
        let first: IpAddr = "2001:db8::1".parse().unwrap();
        let second: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        // Same /64: the two addresses share one budget.
        for _ in 0..SOURCE_BUDGET {
            assert!(budget.charge(first, 1_000));
        }
        assert!(
            !budget.charge(second, 1_000),
            "a second address in the same /64 must not reset the budget"
        );

        // A different /64 has its own.
        let elsewhere: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(budget.charge(elsewhere, 1_000));
    }

    /// An unbounded map turns a rate limit into a memory-exhaustion
    /// primitive: every fresh source would cost an entry, and an attacker has
    /// as many as they like.
    #[test]
    fn the_source_map_is_bounded_and_refuses_rather_than_growing() {
        let mut budget = SourceBudget::default();
        let mut accepted = 0usize;
        for index in 0..(MAX_TRACKED_SOURCES + 64) {
            let source: IpAddr = format!("2001:db8:{:x}:{:x}::1", index / 65_536, index % 65_536)
                .parse()
                .unwrap();
            if budget.charge(source, 1_000) {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, MAX_TRACKED_SOURCES,
            "past the ceiling a new source is refused, not admitted for free"
        );

        // The next window frees the whole table again.
        let fresh: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(budget.charge(fresh, 1_000 + BUDGET_WINDOW_SECS));
    }

    /// One admitted peer must not be able to spend the authority's signature
    /// budget from a thousand addresses.
    #[test]
    fn an_admitted_peer_has_its_own_budget() {
        let mut budget = SourceBudget::default();
        let peer = WireGuardKey::from_bytes([4; 32]);
        for _ in 0..PEER_BUDGET {
            assert!(budget.charge_peer(&peer, 1_000));
        }
        assert!(!budget.charge_peer(&peer, 1_000));
        assert!(budget.charge_peer(&WireGuardKey::from_bytes([5; 32]), 1_000));
        assert!(budget.charge_peer(&peer, 1_000 + BUDGET_WINDOW_SECS));
    }

    #[test]
    fn a_budget_refills_at_the_next_window() {
        let mut budget = SourceBudget::default();
        let source: IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..SOURCE_BUDGET {
            assert!(budget.charge(source, 1_000));
        }
        assert!(!budget.charge(source, 1_000));
        assert!(budget.charge(source, 1_000 + BUDGET_WINDOW_SECS));
    }

    /// Two distinct IPv4 sources never share a budget.
    #[test]
    fn two_ipv4_sources_have_two_budgets() {
        let mut budget = SourceBudget::default();
        let first: IpAddr = "198.51.100.1".parse().unwrap();
        let second: IpAddr = "198.51.100.2".parse().unwrap();
        for _ in 0..SOURCE_BUDGET {
            assert!(budget.charge(first, 1_000));
        }
        assert!(!budget.charge(first, 1_000));
        assert!(budget.charge(second, 1_000));
    }

    /// The refusal classes are the only thing a caller learns, and none of
    /// them describes a certificate.
    #[test]
    fn every_refusal_maps_to_one_bounded_status() {
        for (error, expected) in [
            (ServiceError::Protocol, StatusCode::BAD_REQUEST),
            (ServiceError::Refused, StatusCode::FORBIDDEN),
            (ServiceError::Throttled, StatusCode::TOO_MANY_REQUESTS),
            (
                ServiceError::OperatorCredentialUnavailable,
                StatusCode::NOT_IMPLEMENTED,
            ),
            (ServiceError::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(error.into_response().status(), expected, "{error:?}");
        }
    }
}
