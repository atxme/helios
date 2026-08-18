//! The private Astra ↔ Helios lifecycle channel — spec §8.3, ADR-008 §2.
//!
//! Astra runs in its own container on the gateway. The two processes meet on a
//! veth pair with no default route and no forwarding, and the only thing that
//! crosses it is this API, on a listener of its own:
//!
//! ```text
//! POST /internal/v1/certificates/stage
//! POST /internal/v1/certificates/stage-commit
//! POST /internal/v1/certificates/revoke
//! GET  /internal/v1/certificates/state/<identity>
//! ```
//!
//! # Why a second listener rather than a path on the administration API
//!
//! The administration API of [`crate::router`] admits peers, rewrites the
//! network configuration, drives the firewall and serves the console. None of
//! that is Astra's business, and a shared listener would make "Astra may not
//! call it" a matter of middleware ordering. Two listeners make it a matter of
//! which socket the packet arrived on — and the fallback below refuses every
//! path this one does not serve, so `/api/peers` on the veth is a `404` decided
//! by the router, not by convention.
//!
//! # Why both ends are configured here
//!
//! The server is Helios and the client is Astra, and they live in different
//! crates — but every bound this channel claims has to be declared **on both
//! sides**, exactly as the negotiation port's flow limits are. A refusal of
//! resumption only the server states leaves the client offering tickets to a
//! peer that will never grant one; a TLS-1.3 floor only the client states
//! leaves the server willing to negotiate 1.2 with anything else that dials
//! it. So the two configurations are built by two functions in one file,
//! against one set of constants, and the tests check the pair.
//!
//! # Why the transport is not the authorization
//!
//! mTLS here proves *which process* is talking, and the ephemeral `(EC)DHE`
//! exchange keeps a later theft of either service key from decrypting an old
//! capture. It authorizes nothing: every mutation carries its own ML-DSA-87
//! signature under `CA-PQ` or the delegated issuer, and the registry verifies
//! that signature after the transport has already been passed. Two independent
//! reasons, and this channel is deliberately the weaker of the two — it
//! protects a process boundary on a machine whose kernel both ends already
//! trust, and it is never presented as a defence against `root`.
//!
//! # Why identities are pinned rather than issued by a CA
//!
//! Each end pins the other's certificate **by its exact DER**, configured out
//! of band. Nothing about the peer is learned from the object it authenticates:
//! a certificate arriving on the wire is compared against the pinned bytes and
//! is never a source of trust for itself. No CA on this link also means no
//! second certificate a CA compromise could mint. The transport keys are
//! service identities (spec §8.3): rotating one changes two files and touches
//! neither `CA-PQ` nor any client.
//!
//! # Limites connues
//!
//! - `POST /internal/v1/certificates/stage-commit` is routed and answers `501`
//!   through [`InternalRefusal::RecoveryUnavailable`]. Spec §7.3 accepts a
//!   commit on this link **only** for the recovery of an expired identity, and
//!   only alongside the signed recovery authorization — an object produced by
//!   an operator YubiKey ceremony that no build implements (§12.3). Taking the
//!   commit without it would turn the veth into a second path for an ordinary
//!   commit, which must travel in WireGuard where the source proves the peer.
//!   Delivering `astra-signer`'s signing commands is what unblocks it.
//! - `POST /internal/v1/campaigns/apply` of §8.3 is deliberately **not**
//!   routed: a campaign is applied under an operator approval that does not
//!   exist, and Astra's public `/v1/campaigns` already answers `501` for the
//!   same reason. It is refused by the fallback like any other unknown path
//!   rather than reserved by an empty handler.
//! - The gateway opens no client towards Astra. Spec §7.3 asks it to notify
//!   the authority after purging an uncommitted `pending_grant`; §8.3 defines
//!   no Astra-side route to notify, so the purge is logged and Astra observes
//!   it at its next `GET .../state/<identity>`. Naming that route is a
//!   specification change, not an implementation gap.
//! - HTTP/1.1 only. The channel carries a handful of objects per rotation, so
//!   multiplexing buys nothing, and one advertised ALPN is also what makes an
//!   accidental h2 client fail loudly instead of half-working.
//!
//! What none of this proves is that the veth exists, has no route and forwards
//! nothing: that is a kernel and container fact, and a WSL2 build shows none of
//! it. See [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md).

use std::net::SocketAddr;
use std::sync::Arc;

use aether::certificates::{
    client::ClientCertificateStageAuthorization,
    encoding::{DerCertificate, WireGuardKey},
    revocation::EmergencyCertificateRevocation,
    state::ClientCertificateState,
    x509,
};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};

use crate::certificates::{AstraStageHandler, TrustUpdateRefusal};

/// ALPN of the private channel.
///
/// One protocol, advertised by both ends. Not decoration: this host also runs
/// the administration API and whatever else the operator installed, and a
/// mismatched ALPN fails the handshake instead of delivering a lifecycle body
/// to a server that was never meant to read one.
pub const INTERNAL_ALPN: &[u8] = b"helios-astra-lifecycle/1";

/// Largest body read before deserialization, in both directions.
///
/// The same 64 KiB the public Astra endpoint uses (spec §8.2): a staging
/// authorization carries two certificates, and nothing on this link is larger.
pub const MAX_INTERNAL_BODY_BYTES: usize = 64 * 1024;

/// Path prefix this listener serves. Everything outside it is refused.
pub const INTERNAL_PREFIX: &str = "/internal/v1/certificates/";

pub const STAGE_PATH: &str = "/internal/v1/certificates/stage";
pub const STAGE_COMMIT_PATH: &str = "/internal/v1/certificates/stage-commit";
pub const REVOKE_PATH: &str = "/internal/v1/certificates/revoke";
const STATE_ROUTE: &str = "/internal/v1/certificates/state/:identity";

/// The name the client puts in SNI.
///
/// A constant, in a reserved TLD, because it is **not** how the server is
/// authenticated — the pinned DER is. Deriving it from the veth address would
/// tie the certificate to an address the deployment is free to change, for no
/// security gain.
pub const INTERNAL_SERVER_NAME: &str = "helios-lifecycle.internal";

/// What the private listener answers, and the only statuses it may produce.
///
/// Deliberately finer than the in-tunnel taxonomy, for a reason that does not
/// generalise: the caller here **is** the authority. It already holds the
/// registry these codes describe, so a precise refusal is an operational
/// message to a peer that knows more than the answer could tell it, not an
/// oracle on another peer's generations. Nothing on this enum reaches a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalRefusal {
    /// Unreadable body, wrong version, unparsable identity.
    Protocol,
    /// Well formed and refused: signature, generation, ownership, revocation.
    Rejected,
    /// Known identity, nothing to answer with.
    Unavailable,
    /// The operation needs the signed recovery authorization of spec §7.3,
    /// which needs the operator credential layer that no build implements.
    RecoveryUnavailable,
    /// The gateway failed on its own side.
    Internal,
}

impl InternalRefusal {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Rejected => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::RecoveryUnavailable => StatusCode::NOT_IMPLEMENTED,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<TrustUpdateRefusal> for InternalRefusal {
    fn from(refusal: TrustUpdateRefusal) -> Self {
        match refusal {
            TrustUpdateRefusal::Protocol => Self::Protocol,
            TrustUpdateRefusal::Rejected => Self::Rejected,
            TrustUpdateRefusal::Unavailable => Self::Unavailable,
            TrustUpdateRefusal::Internal => Self::Internal,
        }
    }
}

impl IntoResponse for InternalRefusal {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

/// What the gateway tells the authority about one peer's certificate state.
///
/// The whole answer, and nothing else: no WireGuard private key, no PSK, no
/// TPM secret, no unredacted view of `network.toml` (spec §8.3). The peer's
/// leaves are not here either — Astra issued them; it does not need them read
/// back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificateStateView {
    /// Friendly name, as admission recorded it.
    pub name: String,
    /// Bounded active/next/pending state, exactly as persisted.
    pub state: ClientCertificateState,
}

/// The gateway side of the private channel, implemented by the daemon.
///
/// Staging comes from [`AstraStageHandler`], which already exists as the
/// reserved Astra-to-Helios contract; this trait adds the two other routes
/// rather than declaring a second staging entry point. A trait for the same
/// reason [`crate::certificates::TrustUpdateHandler`] is one: the API process
/// holds no registry lock and no WireGuard backend, so it hands an object to
/// whatever owns the serializer and learns back only a refusal class.
///
/// Note what is **not** a parameter: a caller identity. On this link the
/// authenticated party is Astra, not a peer, so the object's own
/// `client_wg_public_key` names the target — and the registry verifies the
/// ML-DSA-87 signature binding it before writing anything. That is the opposite
/// of the in-tunnel routes, where the source VIP is the proof and the body is
/// only ever compared against it.
#[async_trait]
pub trait AstraChannelHandler: AstraStageHandler {
    /// Applies a signed emergency revocation (spec §10).
    async fn revoke(
        &self,
        revocation: Box<EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal>;

    /// Reads back one peer's bounded state.
    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, TrustUpdateRefusal>;
}

/// Builds the private router — the four routes, and a refusal for the rest.
pub fn router(handler: Arc<dyn AstraChannelHandler>) -> Router {
    Router::new()
        .route(STAGE_PATH, post(stage))
        .route(STAGE_COMMIT_PATH, post(stage_commit))
        .route(REVOKE_PATH, post(revoke))
        .route(STATE_ROUTE, get(peer_state))
        .fallback(refuse_unknown_route)
        .layer(DefaultBodyLimit::max(MAX_INTERNAL_BODY_BYTES))
        .with_state(handler)
}

/// `POST /internal/v1/certificates/stage` (spec §7.2).
async fn stage(State(handler): State<Arc<dyn AstraChannelHandler>>, body: Bytes) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let authorization: ClientCertificateStageAuthorization = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable staging authorization");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.stage_from_astra(Box::new(authorization)).await {
        Ok(receipt) => (StatusCode::OK, Json(*receipt)).into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `POST /internal/v1/certificates/stage-commit`.
///
/// Routed and refused — see the module's known limitations. On this link a
/// commit is legitimate only for the recovery of an expired identity, and only
/// alongside the signed recovery authorization of spec §7.3, which needs the
/// operator credential layer. A named refusal rather than a silent accept.
async fn stage_commit(uri: Uri) -> Response {
    tracing::warn!(
        path = %uri.path(),
        "private channel: a stage commit here needs the signed recovery authorization of §7.3, \
         which this build does not implement; an ordinary commit belongs in the tunnel"
    );
    InternalRefusal::RecoveryUnavailable.into_response()
}

/// `POST /internal/v1/certificates/revoke` (spec §10).
async fn revoke(State(handler): State<Arc<dyn AstraChannelHandler>>, body: Bytes) -> Response {
    if body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let revocation: EmergencyCertificateRevocation = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "private channel: unreadable revocation");
            return InternalRefusal::Protocol.into_response();
        }
    };
    match handler.revoke(Box::new(revocation)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// `GET /internal/v1/certificates/state/<identity>`.
async fn peer_state(
    State(handler): State<Arc<dyn AstraChannelHandler>>,
    Path(identity): Path<String>,
) -> Response {
    let Ok(identity) = WireGuardKey::parse(&identity) else {
        return InternalRefusal::Protocol.into_response();
    };
    match handler.peer_state(&identity).await {
        Ok(view) => (StatusCode::OK, Json(view)).into_response(),
        Err(refusal) => InternalRefusal::from(refusal).into_response(),
    }
}

/// Everything the private listener does not serve.
///
/// The refusal is the point: the administration API, the WebSocket, the
/// embedded console and `/internal/v1/campaigns/apply` all land here. Naming
/// the path in the log turns "Astra probed something it should not" into a
/// readable line rather than a silent `404`.
async fn refuse_unknown_route(uri: Uri) -> StatusCode {
    tracing::warn!(
        path = %uri.path(),
        "private channel: route refused; this listener serves only {}*",
        INTERNAL_PREFIX
    );
    StatusCode::NOT_FOUND
}

/// A transport identity of the private channel: one certificate, one key.
///
/// Not sealed to the TPM, and deliberately so. It authenticates a process on a
/// link whose two ends the host kernel already owns, so sealing would buy
/// nothing against the attacker who matters — while making the lifecycle
/// listener refuse to start on a gateway whose TPM is unavailable, which is
/// exactly the state `heliosd init-trust-domain` was built to survive. The file
/// is `0600`; the authorization is the ML-DSA-87 signature on every object,
/// never this key.
pub struct ChannelIdentity {
    /// The end-entity certificate, DER. The peer pins these exact bytes.
    pub certificate_der: Vec<u8>,
    /// PKCS#8 private key, DER.
    pub private_key_der: Vec<u8>,
}

impl ChannelIdentity {
    fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate_der.clone())
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>, ChannelError> {
        PrivateKeyDer::try_from(self.private_key_der.clone())
            .map_err(|reason| ChannelError::Tls(reason.to_string()))
    }
}

/// What can go wrong on the private channel, on either side.
#[derive(Debug)]
pub enum ChannelError {
    /// The TLS layer refused to build, to connect or to handshake.
    Tls(String),
    /// The pinned peer certificate is not usable as one.
    Pin(String),
    Io(std::io::Error),
    /// The peer answered with a status this client does not accept.
    Status(StatusCode),
    /// The answer was not the object this route returns.
    Body(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(reason) => write!(formatter, "private channel TLS: {reason}"),
            Self::Pin(reason) => write!(formatter, "pinned peer certificate: {reason}"),
            Self::Io(error) => write!(formatter, "private channel input/output: {error}"),
            Self::Status(status) => write!(formatter, "private channel answered {status}"),
            Self::Body(reason) => write!(formatter, "private channel answer: {reason}"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<std::io::Error> for ChannelError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Which end of the handshake a pinned certificate is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedRole {
    /// Astra, dialling the gateway. Must carry `clientAuth`.
    Client,
    /// The gateway, answering. Must carry `serverAuth`.
    Server,
}

/// The only certificate this end will accept from the other.
///
/// A pin, not a chain: `intermediates` must be empty, the end-entity DER must
/// equal the configured bytes, the extended key usage must match the role, and
/// the certificate must be inside its validity window right now. There is no
/// path building because there is no path — and no CA a compromise could use to
/// mint a second acceptable certificate.
#[derive(Debug)]
struct PinnedPeer {
    pinned: Vec<u8>,
    role: PinnedRole,
    not_before: u64,
    not_after: u64,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedPeer {
    fn new(
        pinned: &DerCertificate,
        role: PinnedRole,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, ChannelError> {
        // Parsed once, at configuration time rather than per handshake: a pin
        // that is not a usable certificate is an install error, and finding
        // that out on the first rotation means finding it out at 3 a.m.
        let facts = x509::inspect(pinned).map_err(|error| ChannelError::Pin(error.to_string()))?;
        let usable = match role {
            PinnedRole::Client => facts.is_client_authentication_leaf,
            PinnedRole::Server => facts.is_server_authentication_leaf,
        };
        if !usable {
            return Err(ChannelError::Pin(format!(
                "the pinned certificate declares no extended key usage a {role:?} end can use"
            )));
        }
        if facts.declares_key_usage && !facts.can_digitally_sign {
            return Err(ChannelError::Pin(
                "the pinned certificate declares a key usage that forbids signing a handshake"
                    .into(),
            ));
        }
        Ok(Self {
            pinned: pinned.as_bytes().to_vec(),
            role,
            not_before: facts.not_before,
            not_after: facts.not_after,
            provider,
        })
    }

    /// The pin check itself.
    ///
    /// A plain comparison: the pinned bytes are a public certificate, and
    /// claiming a constant-time one here would be describing a secret that does
    /// not exist.
    fn accept(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            // A chain means the peer expects to be trusted through an issuer.
            // Nothing on this link has one, so the extra certificates could
            // only ever be an attempt to be verified some other way.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        if end_entity.as_ref() != self.pinned.as_slice() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Pinned bytes still expire. Refusing them is what forces the service
        // identity to be rotated instead of quietly outliving its window.
        let now = now.as_secs();
        if now < self.not_before {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now >= self.not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }
        Ok(())
    }

    /// Unreachable through a configuration built here — both ends offer TLS 1.3
    /// alone — and refused again anyway. This second refusal is what still
    /// stands if a future edit widens `protocol_versions`.
    fn refuse_tls12() -> rustls::Error {
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
    }

    fn verify_tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No hint: there is no issuer to name, and naming one would invite the
        // peer to build a chain this verifier refuses anyway.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        debug_assert_eq!(self.role, PinnedRole::Client);
        self.accept(end_entity, intermediates, now)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(Self::refuse_tls12())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        debug_assert_eq!(self.role, PinnedRole::Server);
        // The name is not consulted, and that is the design: the pin is
        // stronger than any SAN check, and tying the certificate to a name
        // would tie it to a veth address the deployment may change.
        self.accept(end_entity, intermediates, now)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(Self::refuse_tls12())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes()
    }
}

/// Named rather than taken from the process default: a global installed by
/// whichever crate got there first is not a decision, and this channel states
/// its guarantees per configuration.
///
/// The TLS 1.2 suites are dropped from the provider itself, not left to
/// version negotiation. `rustls` is compiled with its `tls12` feature for the
/// public HTTPS client, so those suites exist in the binary; restricting the
/// protocol version makes them unreachable, while removing them makes them
/// absent. On a link that carries authority material the difference is worth
/// the two lines: an unreachable suite is one configuration mistake away from
/// being offered, and a suite that is not in the list cannot be.
/// Settles the process-level provider, once, for the crates that cannot name
/// one themselves.
///
/// Two providers are compiled in — `ring` for the negotiation's QUIC stack,
/// AWS-LC for this channel — so `rustls` refuses to pick a default and panics
/// instead of choosing. Everything in this workspace names its provider, but
/// `hyper-rustls` does not: it builds `reqwest`'s configuration through
/// `rustls::ClientConfig::builder()` (`connector.rs:269`), and that call is
/// the one that aborts. Calling this at start-up, before the first HTTP
/// client, replaces a runtime panic with a decision — and it is the same
/// engine the rest of the protocol already draws on.
///
/// Idempotent: a second call, or a provider installed earlier by someone else,
/// is not an error.
pub fn install_process_default_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    Arc::new(provider)
}

/// The gateway's side: serve, and accept only Astra.
///
/// TLS 1.3 alone — `builder_with_protocol_versions` is what removes 1.2, and
/// the pinned verifier refuses a 1.2 signature a second time. No resumption
/// ticket is ever issued and no early data is ever accepted, which is also what
/// removes `psk_ke`: rustls only offers a Diffie-Hellman-less PSK against a
/// ticket, and there are none. Every TLS 1.3 suite the AWS-LC provider carries
/// negotiates `(EC)DHE`.
pub fn server_config(
    identity: &ChannelIdentity,
    pinned_astra_certificate: &DerCertificate,
) -> Result<rustls::ServerConfig, ChannelError> {
    let provider = provider();
    let verifier = PinnedPeer::new(
        pinned_astra_certificate,
        PinnedRole::Client,
        provider.clone(),
    )?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ChannelError::Tls(error.to_string()))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|error| ChannelError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![INTERNAL_ALPN.to_vec()];
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    Ok(tls)
}

/// Astra's side of the same channel: dial, and accept only this gateway.
///
/// The mirror of [`server_config`], and every bound is restated because a bound
/// only one side declares bounds only that side.
pub fn client_config(
    identity: &ChannelIdentity,
    pinned_gateway_certificate: &DerCertificate,
) -> Result<rustls::ClientConfig, ChannelError> {
    let provider = provider();
    let verifier = PinnedPeer::new(
        pinned_gateway_certificate,
        PinnedRole::Server,
        provider.clone(),
    )?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ChannelError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![identity.certificate()], identity.private_key()?)
        .map_err(|error| ChannelError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![INTERNAL_ALPN.to_vec()];
    // No ticket is kept, so none can be offered — and a `psk_ke` resumption the
    // gateway would never grant is never proposed either.
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    Ok(tls)
}

/// Serves the private router until the listener itself fails.
///
/// A refused handshake closes that one connection and is logged; it never takes
/// the listener down, and the listener going down never takes the gateway down.
/// A gateway without an authority is a gateway that works.
pub async fn serve(
    bind: SocketAddr,
    config: rustls::ServerConfig,
    router: Router,
) -> std::io::Result<()> {
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(INTERNAL_ALPN),
        "private Astra channel listening; it serves only {}*",
        INTERNAL_PREFIX
    );
    loop {
        let (stream, source) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%source, %error, "private Astra channel: handshake refused");
                    return;
                }
            };
            let service = TowerToHyperService::new(router);
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%source, %error, "private Astra channel: connection ended");
            }
        });
    }
}

/// Astra's typed client for the routes above.
///
/// It opens one connection per call and closes it. Not thrift: a rotation is a
/// handful of requests an hour, a pooled connection would have to be
/// revalidated against a certificate that may have been rotated meanwhile, and
/// a fresh handshake is the cheapest way to know the pin still holds.
pub struct GatewayLifecycleClient {
    address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
}

impl GatewayLifecycleClient {
    pub fn new(address: SocketAddr, tls: rustls::ClientConfig) -> Self {
        Self {
            address,
            tls: Arc::new(tls),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Hands a staging authorization to the gateway and returns its receipt.
    pub async fn stage(
        &self,
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<aether::certificates::client::GatewayCertificateStageReceipt, ChannelError> {
        let body = serde_json::to_vec(authorization)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self.request("POST", STAGE_PATH, Some(body)).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    /// Applies a signed revocation.
    pub async fn revoke(
        &self,
        revocation: &EmergencyCertificateRevocation,
    ) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(revocation)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        self.request("POST", REVOKE_PATH, Some(body)).await?;
        Ok(())
    }

    /// Reads back one peer's bounded state.
    pub async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, ChannelError> {
        // A WireGuard key is base64 and therefore contains `/`, `+` and `=`: it
        // goes into the path percent-encoded, or it silently becomes several
        // path segments and the route stops matching.
        let path = format!(
            "{INTERNAL_PREFIX}state/{}",
            percent_encode_segment(&identity.to_base64())
        );
        let answer = self.request("GET", &path, None).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, ChannelError> {
        use http_body_util::BodyExt as _;
        use hyper_util::rt::TokioIo;

        let stream = tokio::net::TcpStream::connect(self.address).await?;
        let name = ServerName::try_from(INTERNAL_SERVER_NAME)
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, stream)
            .await
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| ChannelError::Tls(error.to_string()))?;
        // The connection future drives the socket: dropping it before the
        // answer arrives cancels a request that is already in flight.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, INTERNAL_SERVER_NAME)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(Bytes::from(
                body.unwrap_or_default(),
            )))
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let status = response.status();
        // Bounded before it is read into memory, exactly as the server bounds
        // what it accepts: an authority that has been taken over must not be
        // able to make the process that trusts it allocate without end.
        let collected = http_body_util::Limited::new(response.into_body(), MAX_INTERNAL_BODY_BYTES)
            .collect()
            .await
            .map_err(|error| ChannelError::Body(error.to_string()))?
            .to_bytes();
        drop(sender);
        driver.abort();
        if !status.is_success() {
            return Err(ChannelError::Status(status));
        }
        Ok(collected)
    }
}

/// Percent-encodes one path segment.
///
/// Written here rather than pulled in: a WireGuard key is base64, so the only
/// characters that ever need escaping are `+`, `/` and `=`, and a dependency
/// for three replacements would be supply-chain cost for nothing.
fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 8);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::client::{
        ClientCertificateGeneration, GatewayCertificateStageReceipt,
    };
    use aether::certificates::encoding::Fingerprint;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// A disposable transport identity, built exactly as the two `init`
    /// commands build theirs.
    struct Disposable {
        identity: ChannelIdentity,
        certificate: DerCertificate,
    }

    fn disposable(name: &str, role: PinnedRole) -> Disposable {
        let (certificate_der, private_key_der) = self_signed(name, role, 30);
        Disposable {
            certificate: DerCertificate::new(certificate_der.clone()).expect("der"),
            identity: ChannelIdentity {
                certificate_der,
                private_key_der,
            },
        }
    }

    fn self_signed(name: &str, role: PinnedRole, days: i64) -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![match role {
            PinnedRole::Client => ExtendedKeyUsagePurpose::ClientAuth,
            PinnedRole::Server => ExtendedKeyUsagePurpose::ServerAuth,
        }];
        let now = time::OffsetDateTime::now_utc();
        if days >= 0 {
            params.not_before = now - time::Duration::minutes(5);
            params.not_after = now + time::Duration::days(days);
        } else {
            // Entirely in the past: a pin that has run out of window.
            params.not_before = now + time::Duration::days(days * 2);
            params.not_after = now + time::Duration::days(days);
        }
        let key_pair = KeyPair::generate().expect("keygen");
        let certificate = params.self_signed(&key_pair).expect("self-signed");
        (certificate.der().to_vec(), key_pair.serialize_der())
    }

    struct SpyHandler {
        seen: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl AstraStageHandler for SpyHandler {
        async fn stage_from_astra(
            &self,
            _authorization: Box<ClientCertificateStageAuthorization>,
        ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("stage");
            Err(TrustUpdateRefusal::Rejected)
        }
    }

    #[async_trait]
    impl AstraChannelHandler for SpyHandler {
        async fn revoke(
            &self,
            _revocation: Box<EmergencyCertificateRevocation>,
        ) -> Result<(), TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("revoke");
            Err(TrustUpdateRefusal::Rejected)
        }

        async fn peer_state(
            &self,
            _identity: &WireGuardKey,
        ) -> Result<PeerCertificateStateView, TrustUpdateRefusal> {
            self.seen.lock().unwrap().push("peer_state");
            Err(TrustUpdateRefusal::Rejected)
        }
    }

    fn spy() -> Arc<SpyHandler> {
        Arc::new(SpyHandler {
            seen: Mutex::new(Vec::new()),
        })
    }

    async fn status_of(handler: Arc<SpyHandler>, method: &str, uri: &str) -> StatusCode {
        router(handler)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    /// The listener serves the lifecycle and nothing else. Everything the
    /// gateway exposes elsewhere — administration, WebSocket, console — is
    /// refused by the router, not by convention.
    #[tokio::test]
    async fn only_the_certificate_routes_exist() {
        for (method, uri) in [
            ("GET", "/api/status"),
            ("POST", "/api/peers"),
            ("POST", "/api/peers/revoke"),
            ("POST", "/api/network"),
            ("GET", "/api/network"),
            ("POST", "/api/tunnel/start"),
            ("POST", "/api/key-negotiation/release"),
            ("POST", "/api/key-negotiation/trust-update"),
            ("GET", "/ws"),
            ("GET", "/"),
            ("POST", "/internal/v1/campaigns/apply"),
            ("GET", "/internal/v1/certificates"),
            ("GET", "/internal/v1/certificates/state"),
        ] {
            let handler = spy();
            assert_eq!(
                status_of(Arc::clone(&handler), method, uri).await,
                StatusCode::NOT_FOUND,
                "{method} {uri} was served by the private listener"
            );
            assert!(
                handler.seen.lock().unwrap().is_empty(),
                "{method} {uri} reached a handler"
            );
        }
    }

    /// The three live routes reach their handler, and a body the API cannot
    /// read never does.
    #[tokio::test]
    async fn the_live_routes_reach_their_handler() {
        for path in [STAGE_PATH, REVOKE_PATH] {
            let handler = spy();
            assert_eq!(
                status_of(Arc::clone(&handler), "POST", path).await,
                StatusCode::BAD_REQUEST,
                "an empty object is not a lifecycle object"
            );
            assert!(
                handler.seen.lock().unwrap().is_empty(),
                "{path} handed an unreadable body to the registry"
            );
        }

        let handler = spy();
        let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment("AAAA"));
        assert_eq!(
            status_of(Arc::clone(&handler), "GET", &uri).await,
            StatusCode::BAD_REQUEST,
            "a malformed key never reaches the registry"
        );
        assert!(handler.seen.lock().unwrap().is_empty());

        let handler = spy();
        let key = WireGuardKey::from_bytes([7; 32]).to_base64();
        let uri = format!("{INTERNAL_PREFIX}state/{}", percent_encode_segment(&key));
        assert_eq!(
            status_of(Arc::clone(&handler), "GET", &uri).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(handler.seen.lock().unwrap().as_slice(), ["peer_state"]);
    }

    /// A commit on this link needs the signed recovery authorization of §7.3.
    /// It is refused by name — never accepted as an ordinary commit, which must
    /// travel in the tunnel where the source proves the peer.
    #[tokio::test]
    async fn a_commit_is_refused_by_name_rather_than_accepted() {
        let handler = spy();
        assert_eq!(
            status_of(Arc::clone(&handler), "POST", STAGE_COMMIT_PATH).await,
            StatusCode::NOT_IMPLEMENTED
        );
        assert!(handler.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn every_refusal_maps_to_one_bounded_status() {
        for (refusal, expected) in [
            (InternalRefusal::Protocol, StatusCode::BAD_REQUEST),
            (InternalRefusal::Rejected, StatusCode::FORBIDDEN),
            (
                InternalRefusal::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                InternalRefusal::RecoveryUnavailable,
                StatusCode::NOT_IMPLEMENTED,
            ),
            (InternalRefusal::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(refusal.status(), expected, "{refusal:?}");
        }
    }

    /// Both configurations state the same bounds. A bound only one side
    /// declares bounds only that side.
    #[test]
    fn both_ends_refuse_tls12_resumption_and_early_data() {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);

        let server = server_config(&gateway.identity, &astra.certificate).expect("server");
        assert_eq!(server.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
        assert_eq!(
            server.send_tls13_tickets, 0,
            "a ticket is what enables psk_ke"
        );
        assert_eq!(server.max_early_data_size, 0, "0-RTT is replayable");
        assert!(
            server
                .crypto_provider()
                .cipher_suites
                .iter()
                .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
            "the server kept a TLS 1.2 suite"
        );

        let client = client_config(&astra.identity, &gateway.certificate).expect("client");
        assert_eq!(client.alpn_protocols, vec![INTERNAL_ALPN.to_vec()]);
        assert!(!client.enable_early_data, "0-RTT is replayable");
        assert!(
            client
                .crypto_provider()
                .cipher_suites
                .iter()
                .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3),
            "the client kept a TLS 1.2 suite"
        );
    }

    /// A pin has to be usable for the role it is pinned in, and it has to be
    /// alive. Both are checked when the configuration is built, so a bad
    /// install fails at startup rather than on the first rotation.
    #[test]
    fn a_pin_is_refused_when_it_is_the_wrong_role_or_expired() {
        let gateway = disposable(INTERNAL_SERVER_NAME, PinnedRole::Server);
        let astra = disposable("astra.internal", PinnedRole::Client);

        // A `serverAuth` certificate pinned as the dialling identity can never
        // authenticate a client, and vice versa.
        assert!(
            matches!(
                server_config(&gateway.identity, &gateway.certificate),
                Err(ChannelError::Pin(_))
            ),
            "a serverAuth certificate was accepted as the pinned client"
        );
        assert!(
            matches!(
                client_config(&astra.identity, &astra.certificate),
                Err(ChannelError::Pin(_))
            ),
            "a clientAuth certificate was accepted as the pinned server"
        );

        // Well formed, right role, out of its window: refused at the handshake
        // rather than trusted for ever.
        let (stale_der, _) = self_signed("stale.internal", PinnedRole::Server, -1);
        let stale = DerCertificate::new(stale_der).expect("der");
        let verifier = PinnedPeer::new(&stale, PinnedRole::Server, provider()).expect("pin");
        let refusal = verifier.accept(
            &CertificateDer::from(stale.as_bytes().to_vec()),
            &[],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                ))
            ),
            "an expired pin was accepted: {refusal:?}"
        );
    }

    /// The pin is the identity. Another certificate — even a well-formed one
    /// with the same name and the right usage — is refused, and so is a chain
    /// that tries to be verified through an issuer.
    #[test]
    fn an_unpinned_identity_is_refused() {
        let astra = disposable("astra.internal", PinnedRole::Client);
        let impostor = disposable("astra.internal", PinnedRole::Client);
        let verifier =
            PinnedPeer::new(&astra.certificate, PinnedRole::Client, provider()).expect("pin");

        assert!(
            verifier
                .accept(
                    &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
                    &[],
                    UnixTime::now()
                )
                .is_ok(),
            "the pinned identity must be accepted"
        );

        let refusal = verifier.accept(
            &CertificateDer::from(impostor.certificate.as_bytes().to_vec()),
            &[],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                ))
            ),
            "a second certificate with the same name was accepted: {refusal:?}"
        );

        let refusal = verifier.accept(
            &CertificateDer::from(astra.certificate.as_bytes().to_vec()),
            &[CertificateDer::from(
                impostor.certificate.as_bytes().to_vec(),
            )],
            UnixTime::now(),
        );
        assert!(
            matches!(
                refusal,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "a chain was accepted on a link that has no issuer: {refusal:?}"
        );
    }

    /// The TLS 1.2 refusal exists in the verifier as well as in the version
    /// list: the second one still stands if a future edit widens the first.
    #[test]
    fn a_tls12_signature_is_refused_by_the_verifier() {
        assert!(matches!(
            PinnedPeer::refuse_tls12(),
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
        ));
    }

    /// A WireGuard key is base64: unescaped, `/` splits it into path segments
    /// and the route silently stops matching.
    #[test]
    fn a_base64_identity_survives_the_path() {
        let key = WireGuardKey::from_bytes([255; 32]).to_base64();
        assert!(key.contains('/') || key.contains('+') || key.contains('='));
        let encoded = percent_encode_segment(&key);
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('='));
    }

    /// The view carries the bounded state and nothing else — no key, no PSK.
    #[test]
    fn the_state_view_serializes_no_secret() {
        let view = PeerCertificateStateView {
            name: "workstation".into(),
            state: ClientCertificateState::new(ClientCertificateGeneration {
                generation: 4,
                ca_tls_epoch: 1,
                tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
                tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
                pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
                not_before: 0,
                not_after: 1_000_000,
            }),
        };
        let encoded = serde_json::to_string(&view)
            .expect("encode")
            .to_ascii_lowercase();
        for forbidden in ["private", "preshared", "psk", "secret", "sealed"] {
            assert!(
                !encoded.contains(forbidden),
                "the state view mentions « {forbidden} »: {encoded}"
            );
        }
    }
}
