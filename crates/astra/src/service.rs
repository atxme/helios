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
//! # The companion's out-of-tunnel exchange
//!
//! Four routes serve an operator who has no tunnel: the operation read, and
//! the three capability-bound exchanges of §8.2 — the signer request, the
//! encrypted vault, and the result. They serve **only** the operator
//! operations of [`crate::signing`], which is a separate store from the client
//! renewals; an ordinary renewal identifier is therefore absent rather than
//! filtered out, and receives the same coarse refusal as one nobody issued.
//!
//! # Limite connue : ouvrir une campagne reste une commande locale
//!
//! `POST /v1/campaigns` still answers `501`. §11.6 has an interface ask Astra
//! to **resolve** a campaign over the fleet's current targets, and on an
//! unauthenticated public route that would answer every caller with the
//! domain's inventory. The authentication such a route needs is not settled
//! anywhere in the specification, and inventing one here is how a hole gets
//! built. Campaigns are opened by `astra campaign open`, on the machine that
//! already runs Astra, and deposited for this process to adopt.
//!
//! # The one route reachable without any live certificate
//!
//! `POST /v1/client-rotation/recovery` and the four that follow it serve §7.5.
//! They are the only public surface a client with an **expired** identity can
//! use, and they must be: the tunnel it would otherwise renew through is
//! exactly what expired. They carry no bearer credential and need none — every
//! proof is inside the objects, and the material they return is public.
//!
//! Physical ceremonies cannot be exercised in WSL2 — see
//! [`docs/testing/TESTING.md`](../../../../docs/testing/TESTING.md).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aether::certificates::{
    capability::CapabilityTokens,
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey},
    status::status_query_signing_bytes,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
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
/// Largest body this endpoint writes back (spec §8.2).
///
/// It bounds the encrypted vault too: a vault above this cannot travel the
/// public channel at all, which is a deployment fact worth refusing loudly
/// rather than a download that dies halfway through a ceremony.
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;
/// Largest opaque identifier accepted in a path segment (spec §8.2).
pub const MAX_PATH_IDENTIFIER_BYTES: usize = 128;

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
        "this operation needs the operator approval protocol, whose routes and signing commands \
         are not implemented"
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

    /// The source is canonicalized first: a dual-stack `[::]` listener reports
    /// an IPv4 client as `::ffff:a.b.c.d`, and read as IPv6 every one of them
    /// would share the single `::/64` budget.
    fn key(source: IpAddr) -> [u8; 16] {
        let mut key = [0u8; 16];
        match source.to_canonical() {
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
    /// Its public half, so an object Astra signed can be verified here before
    /// it is handed on. A companion approval is checked against the request
    /// Astra itself signed, and re-deriving that key from the private one at
    /// every call would be the same value computed in two places.
    pub service_public_key: MlDsa87PublicKey,
    /// Renewals waiting for an operator, and those that have one.
    ///
    /// Persisted atomically.  The signed approval request inside it may outlive
    /// its five-minute challenge; a poll re-mints that request and fresh
    /// process-local capability tokens without changing `operation_id`, the
    /// client request or its candidate keys.
    pub operations: Mutex<crate::operations::OperationStore>,
    /// `K_capability`, drawn at start-up (spec §8.2).
    pub capabilities: Mutex<CapabilityTokens>,
    /// The credentials an ordinary renewal may be approved by.
    ///
    /// Read from the signed credential document the companion emits, and
    /// **only** the `active` ones: a request naming a lost or revoked
    /// credential would ask an operator for a touch the verifier then refuses.
    /// Empty means no operator can approve anything, and every renewal is
    /// refused by name rather than left to time out.
    pub approval_credential_ids: Vec<Vec<u8>>,
    /// Epoch of the signed credential registry those identifiers came from.
    ///
    /// This is deliberately not inferred from Astra's general registry: the
    /// companion advances the credential document whenever a key is enrolled,
    /// lost or revoked.  A challenge naming rows from epoch N while signing
    /// epoch N-1 would make the verifier and the authenticator describe two
    /// different allow-lists.
    pub approval_credential_registry_epoch: u64,
    /// The signed document those identifiers came from, whole.
    ///
    /// Whoever runs the approval verifies it under `CA-PQ` themselves, so it
    /// has to travel — an allow-list this service merely asserts would let a
    /// compromised Astra name a credential nobody enrolled. `None` when no
    /// credential document has been copied here, which is also when
    /// `approval_credential_ids` is empty.
    pub approval_credential_registry:
        Option<Box<aether::certificates::approval::CredentialRegistry>>,
    /// Manual campaigns waiting for an operator who has no tunnel (§7.6).
    ///
    /// A store of its own, next to `operations` rather than merged into it,
    /// and the separation carries a rule of §8.2 for free: the public
    /// companion routes look only here, so an ordinary renewal identifier is
    /// absent rather than filtered out by a comparison somebody could forget.
    pub signing: Mutex<crate::signing::SigningOperationStore>,
    /// Recoveries of expired identities in flight (spec §7.5).
    ///
    /// A third store, and separate for the same reason the other two are: a
    /// recovery reaches past a validity period, and an identifier from it must
    /// never resolve on a route that authorizes an ordinary renewal. Absence
    /// carries that rule; a comparison would only describe it.
    pub recoveries: Mutex<crate::recovery::RecoveryStore>,
    /// Serializes the reconciliation file's read-modify-write operations.
    pub reconciliation: Mutex<()>,
    /// The encrypted authority vault, byte for byte as the companion wrote it.
    ///
    /// Astra transports and backs it up; it cannot open it, and nothing in
    /// this container can. `None` when no vault has been copied into the state
    /// volume, which is also when a campaign that rotates an anchor is refused
    /// by name rather than left to fail at the download.
    pub encrypted_vault: Option<Vec<u8>>,
    /// Where this authority's state volume is mounted.
    ///
    /// Held because one operator ceremony writes into it: a delegation the
    /// companion deposits is recorded only after the private halves sealed
    /// beside the registry are proven to match it (spec §9.5). Nothing else
    /// here reads it, and no route exposes it.
    pub state_dir: std::path::PathBuf,
    /// The private veth link to `heliosd`, when the deployment has one.
    ///
    /// It lives here because this is where staging will be driven from: an
    /// approved rotation issues the two leaves, sends the authorization to the
    /// gateway and reads back its signed receipt on this same link (spec §8.3,
    /// amendment of 16 August 2026). The relayed renewal drives this channel;
    /// the public companion transport of §8.2 is the separate out-of-tunnel
    /// path served below.
    pub gateway: Option<crate::gateway::GatewayChannel>,
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
        // Creating a campaign from the public origin is deliberately still
        // refused: §11.6 has an interface ask Astra to *resolve* one over the
        // fleet's current targets, and an unauthenticated route that did that
        // would answer every caller with the domain's inventory. The
        // authentication that route needs is not settled, and inventing one
        // here is how a hole gets built. Campaigns are opened locally, by
        // `astra campaign open`, on the machine that already runs Astra.
        .route("/v1/campaigns", post(operator_credential_required))
        // The recovery of an expired identity (§7.5). Reachable without a
        // tunnel by construction — the tunnel is what expired — and therefore
        // without a bearer credential: every proof is inside the objects.
        .route("/v1/client-rotation/challenge", post(status_challenge))
        .route("/v1/client-rotation/recovery", post(open_recovery))
        .route(
            "/v1/client-rotation/recovery/{operation}",
            get(read_recovery),
        )
        .route(
            "/v1/client-rotation/recovery/{operation}/authorization",
            post(authorize_recovery),
        )
        .route(
            "/v1/client-rotation/recovery/{operation}/grant",
            post(grant_recovery),
        )
        .route(
            "/v1/client-rotation/recovery/{operation}/commit",
            post(commit_recovery),
        )
        // The companion's three capability-bound exchanges, plus the read an
        // interface follows progress with. They serve **only** the operator
        // operations opened out of tunnel: an ordinary renewal identifier is
        // absent from this store, so it receives the same coarse refusal as an
        // identifier nobody ever issued (§8.2).
        .route("/v1/operations/{operation}", get(signing_operation))
        .route("/v1/signer-requests/{operation}", get(signer_request))
        .route("/v1/vaults/{fingerprint}", get(encrypted_vault))
        .route("/v1/signer-results/{operation}", post(signer_result))
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
    approved_random(&mut challenge).map_err(|_| ServiceError::Internal)?;
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
    // Whether a renewal is open for this peer and has not yet produced a
    // candidate. The registry cannot answer it — it only learns of a rotation
    // at staging — so the operation store is asked, and §8.2's distinction
    // between `awaiting_operator` and `pending_grant` survives.
    let awaiting_operator = service
        .operations
        .lock()
        .await
        .awaits_operator(&query.client_wg_public_key, now);
    let status = planner::client_status(
        trust_domain_id,
        &peer,
        planner::RenewalInFlight { awaiting_operator },
        status_epoch,
        service_key_epoch,
        now,
        now + 3_600,
    )
    .map_err(|_| ServiceError::Internal)?
    .sign(&service.service_private_key)
    .map_err(|_| ServiceError::Internal)?;

    // A status query is a read, not an authority decision. Older builds
    // appended `StatusPublished` here, which made the operator's bootstrap
    // witness stale after the first telemetry poll and blocked every restart.
    // Keep the monotonic status epoch durable, but do not grow the fork
    // witness for a read-only response.
    registry.save().map_err(|_| ServiceError::Internal)?;

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

/// The bearer token of §8.2, from the one place it is allowed to travel.
///
/// `Authorization: Bearer <base64url>` and nowhere else — never a URL, never a
/// cookie, never a log line. A token in a path would be in every proxy log and
/// every browser history on the way; that is the whole reason the header is
/// named in the specification rather than left to taste.
fn bearer(headers: &HeaderMap) -> Result<&str, ServiceError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= MAX_PATH_IDENTIFIER_BYTES * 8)
        .ok_or(ServiceError::Protocol)
}

/// One opaque identifier out of a path segment.
///
/// The length ceiling is applied before parsing, so a caller cannot make this
/// process do work proportional to a string it chose.
fn path_id(raw: &str) -> Result<Id16, ServiceError> {
    if raw.len() > MAX_PATH_IDENTIFIER_BYTES {
        return Err(ServiceError::Protocol);
    }
    Id16::parse_hex(raw).map_err(|_| ServiceError::Refused)
}

/// The relying party and its origin, as **the domain** defines them.
///
/// Derived from the registry rather than taken from anything a caller sends:
/// an assertion produced under another relying party would be valid for
/// another domain, and one checked against an origin the message named would
/// be checked against nothing.
async fn relying_party(service: &Arc<AstraService>) -> (String, String) {
    let rp_id = service.registry.lock().await.state().webauthn_rp_id.clone();
    let origin = format!("https://{rp_id}");
    (rp_id, origin)
}

/// Mints this operation's capability tokens and builds its view.
///
/// Three scopes, three tokens, each bound to the operation, to the campaign
/// fingerprint that is also the operator's challenge, and to at most five
/// minutes. The vault token exists only for a scope that makes an anchor sign
/// — an ordinary campaign's token is not a vault-download token, because there
/// is no vault in its grant to match against.
async fn mint_view(
    service: &Arc<AstraService>,
    operation: &crate::signing::SigningOperation,
    now_unix: u64,
) -> crate::signing::SigningOperationView {
    use aether::certificates::capability::{
        CapabilityGrant, CapabilityScope, MAX_CAPABILITY_TOKEN_LIFETIME_SECS,
    };

    let manifest = operation.manifest_fingerprint();
    let vault = operation.vault_fingerprint();
    let expires_at = (now_unix + MAX_CAPABILITY_TOKEN_LIFETIME_SECS).min(operation.expires_at);
    let mut view = crate::signing::SigningOperationView {
        operation_id: operation.operation_id,
        state: operation.state,
        scope: operation.campaign.scope,
        target_count: operation.campaign.targets.len(),
        required_credentials: operation.campaign.required_credentials,
        campaign_fingerprint: manifest,
        created_at: operation.created_at,
        expires_at: operation.expires_at,
        signer_request_token: None,
        vault_token: None,
        signer_result_token: None,
    };
    if expires_at <= now_unix {
        return view;
    }
    let tokens = service.capabilities.lock().await;
    let mint = |scope, vault: Option<Fingerprint>| -> Option<String> {
        let grant = CapabilityGrant::new(
            scope,
            operation.operation_id,
            manifest,
            vault,
            now_unix,
            expires_at,
        )
        .ok()?;
        tokens.issue(&grant, operation.expires_at).ok()
    };
    view.signer_request_token = mint(CapabilityScope::SignerRequestRead, None);
    view.signer_result_token = mint(CapabilityScope::SignerResultSubmit, None);
    view.vault_token =
        vault.and_then(|fingerprint| mint(CapabilityScope::EncryptedVaultRead, Some(fingerprint)));
    view
}

/// Authenticates a bearer against **this** route's own requirement.
///
/// Every field of the requirement is read from the operation Astra holds, and
/// none from the token being checked: a requirement taken out of the
/// credential would require nothing.
async fn authenticate(
    service: &Arc<AstraService>,
    scope: aether::certificates::capability::CapabilityScope,
    operation: &crate::signing::SigningOperation,
    vault: Option<&Fingerprint>,
    token: &str,
    now_unix: u64,
) -> Result<(), ServiceError> {
    let manifest = operation.manifest_fingerprint();
    let requirement = aether::certificates::capability::CapabilityRequirement {
        scope,
        operation_id: &operation.operation_id,
        operation_manifest_fingerprint: &manifest,
        encrypted_vault_fingerprint: vault,
        operation_expires_at: operation.expires_at,
    };
    service
        .capabilities
        .lock()
        .await
        .authenticate(token, &requirement, now_unix)
        .map(|_| ())
        .map_err(|_| ServiceError::Refused)
}

/// `GET /v1/operations/<operation_id>`.
///
/// No token: the identifier is 128 bits from the DRBG and is the secret. What
/// it returns is progress plus freshly minted tokens — never a decision. The
/// interface concludes that a signature succeeded from the signed objects, not
/// from this.
async fn signing_operation(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
) -> Result<Json<crate::signing::SigningOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    Ok(Json(
        operator_operation(&service, &operation_id, now).await?,
    ))
}

/// The read itself, shared by the public origin and the in-tunnel relay.
///
/// Everything above it in the public handler is transport: the rate budget of
/// §8.2, which is charged per real source address and would be a single shared
/// bucket on a link whose only caller is the gateway. The decision is here, so
/// the two channels cannot drift into deciding differently.
pub(crate) async fn operator_operation(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    now: u64,
) -> Result<crate::signing::SigningOperationView, ServiceError> {
    let operations = service.signing.lock().await;
    let operation = operations
        .get(operation_id, now)
        .map_err(|_| ServiceError::Refused)?;
    Ok(mint_view(service, operation, now).await)
}

/// What the companion fetches before it asks for a touch, defined in `aether`.
///
/// There rather than here for the reason [`crate::signing::SigningOperationView`]
/// is: the in-tunnel relay of spec §8.5 names it, and `helios-api` cannot
/// depend on this crate.
pub use aether::certificates::transport::OperatorSignerRequestResponse as SignerRequestResponse;

/// `GET /v1/signer-requests/<operation_id>`, scope `signer_request_read`.
async fn signer_request(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SignerRequestResponse>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    let token = bearer(&headers)?;
    Ok(Json(
        operator_signer_request(&service, &operation_id, token, now).await?,
    ))
}

/// The capability-bound read, shared by both channels (§8.2, §8.5).
pub(crate) async fn operator_signer_request(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    token: &str,
    now: u64,
) -> Result<SignerRequestResponse, ServiceError> {
    use aether::certificates::capability::CapabilityScope;

    let (webauthn_rp_id, webauthn_origin) = relying_party(service).await;
    let credential_registry = service
        .approval_credential_registry
        .clone()
        .ok_or(ServiceError::Refused)?;

    let operations = service.signing.lock().await;
    let operation = operations
        .get(operation_id, now)
        .map_err(|_| ServiceError::Refused)?;
    authenticate(
        service,
        CapabilityScope::SignerRequestRead,
        operation,
        None,
        token,
        now,
    )
    .await?;
    Ok(SignerRequestResponse {
        signer_request: operation.signer_request.clone(),
        campaign: operation.campaign.clone(),
        credential_registry,
        webauthn_rp_id,
        webauthn_origin,
    })
}

/// `GET /v1/vaults/<encrypted_vault_fingerprint>`, scope `encrypted_vault_read`.
///
/// Served encrypted, and that is not a caveat: this process holds no key-slot
/// secret and no PRF output, so there is no other form it could serve. The
/// fingerprint in the path is compared against the one **the operation's
/// signed request names**, so a token cannot be pointed at another file.
async fn encrypted_vault(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    if raw.len() > MAX_PATH_IDENTIFIER_BYTES {
        return Err(ServiceError::Protocol);
    }
    let requested = Fingerprint::parse_hex(&raw).map_err(|_| ServiceError::Refused)?;
    let token = bearer(&headers)?;
    let vault = operator_encrypted_vault(&service, &requested, token, now).await?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        vault,
    )
        .into_response())
}

/// The vault read itself, shared by both channels (§8.2, §8.5).
pub(crate) async fn operator_encrypted_vault(
    service: &Arc<AstraService>,
    requested: &Fingerprint,
    token: &str,
    now: u64,
) -> Result<Vec<u8>, ServiceError> {
    use aether::certificates::capability::CapabilityScope;

    let vault = service
        .encrypted_vault
        .as_ref()
        .ok_or(ServiceError::Refused)?;
    if vault.len() > MAX_RESPONSE_BYTES {
        // A deployment fault, not a caller's: refusing it here beats a
        // truncated vault the companion would fail to open with a message
        // about corruption.
        tracing::error!(
            bytes = vault.len(),
            "the encrypted vault is over the §8.2 response ceiling and cannot travel this channel"
        );
        return Err(ServiceError::Internal);
    }
    // The token names one operation; the operation names one vault. Both must
    // agree with the path, and the path is the only one of the three a caller
    // chose.
    let operations = service.signing.lock().await;
    let mut authorized = None;
    for candidate in operations.awaiting_vault(requested, now) {
        if authenticate(
            service,
            CapabilityScope::EncryptedVaultRead,
            candidate,
            Some(requested),
            token,
            now,
        )
        .await
        .is_ok()
        {
            authorized = Some(candidate);
            break;
        }
    }
    authorized.ok_or(ServiceError::Refused)?;
    if !Fingerprint::of(vault).matches(requested) {
        // The operation names a vault this volume does not hold: the operator
        // copied an older file, or none. Naming it is the whole content.
        tracing::error!(
            requested = %requested,
            held = %Fingerprint::of(vault),
            "the vault this campaign names is not the one in the state volume"
        );
        return Err(ServiceError::Internal);
    }
    Ok(vault.clone())
}

/// `POST /v1/signer-results/<operation_id>`, scope `signer_result_submit`.
///
/// The result is verified against **this operation's own** campaign, which
/// Astra holds — never against one the same message supplied. An identical
/// replay is idempotent; different bytes under the same identifier are a
/// conflict, not a second success.
///
/// # Why the objects land before the approval is spent
///
/// An authority campaign carries `CA-PQ`-signed transition objects (§0.6).
/// They are persisted into the registry **first**, and only then is the
/// approval recorded. The other order has a failed write leave an approval
/// that is already idempotent: the companion's retry would be told «already
/// approved» while the objects it produced were never stored, and `CA-PQ`
/// would have to sign them a second time — which means another ceremony, on a
/// campaign whose window has passed.
///
/// The two locks are taken one after the other, never nested. Every other
/// path in this crate scopes them the same way, and a single nested pair is
/// all a deadlock needs.
async fn signer_result(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    headers: HeaderMap,
    Json(result): Json<Box<aether::certificates::status::AstraSignerResult>>,
) -> Result<Json<crate::signing::SigningOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    let token = bearer(&headers)?;
    Ok(Json(
        operator_signer_result(&service, &operation_id, token, result, now).await?,
    ))
}

/// The submission itself, shared by both channels (§8.2, §8.5).
pub(crate) async fn operator_signer_result(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    token: &str,
    result: Box<aether::certificates::status::AstraSignerResult>,
    now: u64,
) -> Result<crate::signing::SigningOperationView, ServiceError> {
    use aether::certificates::capability::CapabilityScope;

    let operation_id = *operation_id;
    let (webauthn_rp_id, webauthn_origin) = relying_party(service).await;
    let registry = service
        .approval_credential_registry
        .clone()
        .ok_or(ServiceError::Refused)?;

    let verified = {
        let operations = service.signing.lock().await;
        let operation = operations
            .get(&operation_id, now)
            .map_err(|_| ServiceError::Refused)?;
        authenticate(
            service,
            CapabilityScope::SignerResultSubmit,
            operation,
            None,
            token,
            now,
        )
        .await?;
        operations
            .verify_result(
                &operation_id,
                &result,
                &registry,
                &webauthn_rp_id,
                &webauthn_origin,
                now,
            )
            .map_err(|error| {
                tracing::warn!(%operation_id, %error, "operator result refused");
                ServiceError::Refused
            })?
    };

    if !verified.objects.is_empty() {
        let mut domain = service.registry.lock().await;
        let accepted = domain
            .accept_transitions(
                &verified.campaign,
                &verified.objects,
                verified.credential_registry.clone(),
                now,
            )
            .map_err(|error| {
                tracing::error!(
                    %operation_id,
                    %error,
                    "the transitions this campaign produced were refused: the approval is not \
                     spent, and an identical deposit may be retried"
                );
                ServiceError::Refused
            })?;
        tracing::info!(
            %operation_id,
            accepted,
            offered = verified.objects.len(),
            "anchor transitions stored; the service key will build one manifest per peer"
        );
        drop(domain);

        // The signed decision is durable before it reaches the data plane.
        // An identical companion retry replays this relay without creating a
        // second registry entry, which repairs a transient private-channel
        // failure without asking `CA-PQ` to sign again.
        for object in &verified.objects {
            let aether::certificates::transport::TrustUpdateObject::CertificateRevocation(
                revocation,
            ) = object
            else {
                continue;
            };
            let Some(gateway) = service.gateway.as_ref() else {
                tracing::error!(
                    %operation_id,
                    "revocation recorded but no private gateway channel is configured; the \
                     signed decision remains distributable and the data-plane withdrawal must be retried"
                );
                return Err(ServiceError::Internal);
            };
            match gateway.revoke(revocation).await {
                Ok(()) => tracing::info!(%operation_id, "revocation applied on the gateway"),
                Err(error) => {
                    tracing::error!(
                        %operation_id,
                        %error,
                        "revocation recorded but not applied on the gateway; retry the identical signer result"
                    );
                    return Err(ServiceError::Internal);
                }
            }
        }
    }

    if let Some(authorization) = verified.issuer_authorization.clone() {
        let issuer_epoch = authorization.issuer_epoch;
        let mut domain = service.registry.lock().await;
        // Recorded before the approval is marked spent, like the transitions
        // above and for the same reason: a delegation the operator approved
        // and this authority did not write is a ceremony to redo, whereas a
        // spent approval with nothing behind it is a ceremony that cannot be.
        crate::issuer::adopt(
            &mut domain,
            *authorization,
            &crate::issuer::pq_key_path(&service.state_dir, issuer_epoch),
            &crate::issuer::tls_key_path(&service.state_dir, issuer_epoch),
            now,
        )
        .map_err(|error| {
            tracing::error!(
                %operation_id,
                %error,
                "the delegation this campaign produced was refused: the approval is not spent,                  and an identical deposit may be retried"
            );
            ServiceError::Refused
        })?;
        tracing::info!(
            %operation_id,
            issuer_epoch,
            "delegation recorded; restart this authority to issue under it"
        );
    }

    let mut operations = service.signing.lock().await;
    let operation = operations
        .accept_result(&operation_id, *result, &verified, now)
        .map_err(|error| {
            tracing::warn!(%operation_id, %error, "operator result refused");
            ServiceError::Refused
        })?;
    Ok(mint_view(service, operation, now).await)
}

/// `POST /v1/client-rotation/recovery` (spec §7.5).
///
/// The one route a client with no valid certificate may reach. It is
/// unauthenticated in the transport sense and authenticated in every sense
/// that matters: the request carries a signature by the expired generation's
/// private key, answers a challenge this authority issued and consumes, and is
/// checked by the historical validator against the peer the registry already
/// records.
async fn open_recovery(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Json(request): Json<Box<aether::certificates::client::ExpiredCertificateRecoveryRequest>>,
) -> Result<Json<aether::certificates::transport::ExpiredRecoveryOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    crate::recovery::open(&service, request, now)
        .await
        .map(Json)
        .map_err(|error| {
            tracing::warn!(%error, "recovery refused");
            crate::recovery::refusal(&error)
        })
}

/// `GET /v1/client-rotation/recovery/<operation_id>`.
///
/// Everything it returns is public material: two expired leaves, a CSR, a
/// public key, a receipt and a grant. Knowing the identifier confers no
/// ability — the grant installs nothing without the private keys that only the
/// client holds, and the commit needs both of them.
async fn read_recovery(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
) -> Result<Json<aether::certificates::transport::ExpiredRecoveryOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    let recoveries = service.recoveries.lock().await;
    recoveries
        .get(&operation_id, now)
        .map(|operation| Json(operation.view()))
        .map_err(|error| {
            tracing::debug!(%operation_id, %error, "recovery read refused");
            crate::recovery::refusal(&error)
        })
}

/// `POST /v1/client-rotation/recovery/<operation_id>/authorization` (§7.5).
async fn authorize_recovery(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    Json(deposit): Json<aether::certificates::transport::ExpiredRecoveryAuthorizationDeposit>,
) -> Result<Json<aether::certificates::transport::ExpiredRecoveryOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    crate::recovery::authorize(
        &service,
        &operation_id,
        deposit.authorization,
        deposit.evidence,
        now,
    )
    .await
    .map(Json)
    .map_err(|error| {
        tracing::warn!(%operation_id, %error, "recovery authorization refused");
        crate::recovery::refusal(&error)
    })
}

/// `POST /v1/client-rotation/recovery/<operation_id>/grant` (§7.5).
async fn grant_recovery(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    Json(deposit): Json<aether::certificates::transport::ExpiredRecoveryGrantDeposit>,
) -> Result<Json<aether::certificates::transport::ExpiredRecoveryOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    crate::recovery::grant(&service, &operation_id, deposit.grant, now)
        .await
        .map(Json)
        .map_err(|error| {
            tracing::warn!(%operation_id, %error, "recovery grant refused");
            crate::recovery::refusal(&error)
        })
}

/// `POST /v1/client-rotation/recovery/<operation_id>/commit` (§7.3, §7.5).
async fn commit_recovery(
    State(service): State<Arc<AstraService>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    Path(raw): Path<String>,
    Json(deposit): Json<aether::certificates::transport::ExpiredRecoveryCommitDeposit>,
) -> Result<Json<aether::certificates::transport::ExpiredRecoveryOperationView>, ServiceError> {
    let now = now_unix();
    service.charge(source.ip(), now).await?;
    let operation_id = path_id(&raw)?;
    crate::recovery::commit(&service, &operation_id, deposit.commit, now)
        .await
        .map(Json)
        .map_err(|error| {
            tracing::warn!(%operation_id, %error, "recovery commit refused");
            crate::recovery::refusal(&error)
        })
}

/// A public challenge, from the approved DRBG of the specification §2.3.2.
fn approved_random(buffer: &mut [u8]) -> Result<(), ()> {
    aether::random::fill_public(buffer).map_err(|_| ())
}

#[cfg(test)]
mod tests;
