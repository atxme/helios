//! Authenticated QUIC transport for key negotiation.
//!
//! The crate owns no WireGuard backend and no certificate authority. Callers
//! provide DER identities and a transaction handler. This separation keeps
//! the public parser and TLS boundary independently testable.

use std::{
    any::Any,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use aether::key_negotiation::{
    derive_negotiated_psk, static_psk_fingerprint, AuthenticatedKeyNegotiationCommit,
    AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest,
    AuthenticatedKeyNegotiationResponse, KeyNegotiationRequest, KeyNegotiationResponse,
    ProtectionMode, KEY_NEGOTIATION_VERSION, MAX_KEY_NEGOTIATION_MESSAGE_BYTES,
};
use aether::pq::{Kem, MlKem1024Kem};
use aether::SecretString;
use async_trait::async_trait;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroize as _;

/// ALPN prevents another QUIC application on the host from accepting these
/// credentials and messages by accident.
pub const KEY_NEGOTIATION_ALPN: &[u8] = b"helios-key-negotiation/4";
/// Confirmation is bounded independently from transport idle time.
///
/// The client confirms as soon as a WireGuard handshake succeeds with the PSK
/// it has just installed, which takes a second or two. This bound is
/// therefore not a wait anyone lives
/// through — it is how long a **failed** attempt keeps the peer's transaction
/// slot, during which every new negotiation from that client is refused as
/// busy. Three minutes of that was a client locked out for three minutes by a
/// session that had already died; forty-five seconds still leaves twenty
/// times the room a handshake needs.
pub const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(45);
/// Bounds authenticated connection tasks exposed on the public WAN port.
pub const MAX_ACTIVE_NEGOTIATIONS: usize = 128;

/// Handshakes accepted per source address and per window, once its address is
/// validated.
///
/// Address validation stops spoofed floods; it does nothing against an
/// attacker using its own address, which can still make the gateway run TLS
/// handshakes and ML-DSA verifications. This second bound makes that cost
/// linear in the number of addresses an attacker actually holds.
pub const MAX_HANDSHAKES_PER_SOURCE: u32 = 8;

/// Window over which [`MAX_HANDSHAKES_PER_SOURCE`] is counted.
///
/// A legitimate client negotiates once per connection, so eight attempts a
/// minute leaves ample room for retries on a lossy link.
pub const SOURCE_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Secret configuration prepared for the WireGuard peer.
///
/// `None` is meaningful only for classic mode and removes the peer's PSK.
#[derive(Debug)]
pub struct PreparedKeyMaterial {
    pub response: KeyNegotiationResponse,
    pub psk: Option<SecretString>,
}

/// Applies the mode selected by Orion and derives the candidate peer secret.
///
/// The caller still owns transaction serialization, data-plane installation
/// and rollback. This function performs no I/O and is safe to exercise with
/// adversarial inputs.
pub fn prepare_key_material(
    request: &KeyNegotiationRequest,
    gateway_wg_public_key: &str,
    gateway_nonce: [u8; 16],
    static_psk: Option<&str>,
    confirmation_timeout: Duration,
) -> Result<PreparedKeyMaterial, PublicError> {
    use base64::Engine as _;

    request.validate().map_err(|_| PublicError::Protocol)?;
    aether::wg::validate_key(gateway_wg_public_key).map_err(|_| PublicError::Protocol)?;
    let timeout_secs = u32::try_from(confirmation_timeout.as_secs())
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or(PublicError::Protocol)?;

    let mut response = KeyNegotiationResponse {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: request.transaction_id,
        selected_mode: request.mode,
        gateway_wg_public_key: gateway_wg_public_key.to_string(),
        gateway_nonce,
        kem_ciphertext: None,
        confirmation_timeout_secs: timeout_secs,
    };

    let psk = match request.mode {
        ProtectionMode::Classic => None,
        ProtectionMode::StaticPsk => {
            let configured = static_psk.ok_or(PublicError::ModeUnavailable)?;
            let expected = request
                .static_psk_fingerprint
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            let actual =
                static_psk_fingerprint(configured).map_err(|_| PublicError::ModeUnavailable)?;
            if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
                return Err(PublicError::ModeUnavailable);
            }
            Some(SecretString::new(configured.to_string()))
        }
        ProtectionMode::MlKem => {
            let public_key = request
                .kem_public_key
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            let (ciphertext, shared_secret) =
                MlKem1024Kem::encapsulate(public_key).map_err(|_| PublicError::Protocol)?;
            response.kem_ciphertext = Some(ciphertext);
            let psk = derive_negotiated_psk(&shared_secret, request, &response)
                .map_err(|_| PublicError::Protocol)?;
            Some(SecretString::new(
                base64::engine::general_purpose::STANDARD.encode(psk.as_slice()),
            ))
        }
    };

    Ok(PreparedKeyMaterial { response, psk })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

/// DER material loaded from a protected local store.
pub struct TlsIdentity {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}

impl TlsIdentity {
    fn certificates(&self) -> Vec<CertificateDer<'static>> {
        self.certificate_chain
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect()
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>, TransportError> {
        PrivateKeyDer::try_from(self.private_key.clone())
            .map_err(|_| TransportError::InvalidPrivateKey)
    }

    /// Fingerprint of the leaf this end will present.
    ///
    /// Logged when an endpoint is built, and it is the single most useful line
    /// in this crate. A gateway serves the certificate it read **at startup**;
    /// rotating the identity under a running daemon leaves it presenting the
    /// previous one, while every freshly issued profile pins the new one. The
    /// client then refuses the handshake with `BadSignature` — a message that
    /// names a signature and says nothing about the two certificates that no
    /// longer match. Printing both fingerprints turns that into a comparison
    /// anyone can make in one line.
    fn leaf_fingerprint(&self) -> String {
        self.certificate_chain
            .first()
            .map(|leaf| certificate_fingerprint_der(leaf))
            .unwrap_or_else(|| "aucune".into())
    }
}

impl Drop for TlsIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Result of preparing a peer slot. Rollback remains possible until confirm.
pub struct PreparedNegotiation {
    pub response: AuthenticatedKeyNegotiationResponse,
    pub confirmation_timeout: Duration,
}

#[async_trait]
pub trait NegotiationHandler: Send + Sync + 'static {
    async fn prepare(
        &self,
        certificate_sha256: String,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError>;

    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError>;

    async fn rollback(&self, transaction_id: [u8; 16]);

    /// The client hung up after a committed transaction.
    ///
    /// Distinct from [`Self::rollback`], which undoes a transaction that never
    /// completed: here the tunnel existed and is now over. The gateway can
    /// release the slot immediately instead of waiting for handshakes to stop.
    async fn disconnected(&self, transaction_id: [u8; 16]);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServerMessage {
    Response {
        response: Box<AuthenticatedKeyNegotiationResponse>,
    },
    Committed {
        commit: AuthenticatedKeyNegotiationCommit,
    },
    Error {
        error: PublicError,
    },
}

/// Deliberately coarse error sent to an unauthenticated network boundary.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", content = "message", rename_all = "snake_case")]
pub enum PublicError {
    #[error("request was rejected")]
    Rejected,
    #[error("peer certificate is not bound to this WireGuard identity")]
    IdentityMismatch,
    #[error("protection mode is unavailable for this peer")]
    ModeUnavailable,
    #[error("selected protection mode is below the peer security floor")]
    Downgrade,
    #[error("another key negotiation is already active for this peer")]
    Busy,
    #[error("data-plane configuration failed")]
    DataPlane,
    #[error("protocol message is invalid")]
    Protocol,
}

/// Builds a QUIC server requiring a client certificate rooted in `client_ca`.
/// Transport of an exchange that carries **large** material over an unknown
/// path.
///
/// A negotiation moves several kilobytes in a couple of round-trips: an
/// ML-KEM-1024 ciphertext, an ML-DSA-65 signature of 3 309 bytes, two
/// certificates. QUIC cuts all that into datagrams, and their size is the
/// whole question — throughput is irrelevant here, reaching the other end is
/// not.
///
/// quinn probes upward by default (up to 1 452 bytes). That probe succeeds on
/// a LAN and then betrays: the client mounts its WireGuard interface, which
/// captures the route with a smaller MTU, and every datagram sized by the
/// earlier probe comes back as `WSAEMSGSIZE` — an exchange that worked in the
/// lab and fails at the customer's, on the renegotiation rather than the
/// first attempt.
///
/// Pinning the size to 1 200 bytes removes the question. It is the floor
/// RFC 9000 §14 imposes on every QUIC path: a network unable to carry it
/// cannot carry QUIC at all. The cost is a few extra datagrams for the PQ
/// material, on an exchange that happens once per connection.
fn pinned_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);
    transport.initial_mtu(SAFE_UDP_PAYLOAD);
    transport.min_mtu(SAFE_UDP_PAYLOAD);
    // The connection outlives the exchange: once committed, it becomes the
    // liveness link whose closure tells the gateway to release the PSK slot
    // ([`SessionLink`]). It then carries **nothing** — which QUIC, left to its
    // defaults, reads as death after 30 seconds of silence.
    //
    // That is exactly what happened: the gateway released the slot half a
    // minute into every tunnel, the client kept its own, and the session went
    // on working until the next WireGuard rekey — then died, two to three
    // minutes in, for no reason either end announced. Keep-alives are what
    // make silence mean "still here".
    transport.keep_alive_interval(Some(LINK_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        LINK_IDLE_TIMEOUT
            .try_into()
            .expect("the idle timeout fits QUIC's varint"),
    ));
    transport
}

/// Datagram size every QUIC path must carry (RFC 9000 §14).
const SAFE_UDP_PAYLOAD: u16 = 1200;

/// Beat that keeps the liveness link alive.
///
/// Comfortably under [`LINK_IDLE_TIMEOUT`] so that losing one or two beats
/// does not kill a tunnel. Two small datagrams per ten seconds and per client
/// is a negligible price for the property they buy: the gateway holds the PSK
/// for exactly as long as the client is there, and not one second less.
const LINK_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Silence after which the link is considered dead.
///
/// Three missed beats. Short enough that the gateway frees the slot of a
/// client that truly vanished — a crash, a laptop lid — rather than waiting
/// for handshakes to go stale 150 s later.
const LINK_IDLE_TIMEOUT: Duration = Duration::from_secs(35);

/// Time allowed for the QUIC handshake with the negotiation service.
///
/// Generous for a mutual-TLS handshake on a residential link, and short
/// enough that an unreachable port is reported rather than waited on: this is
/// the very first thing a client does, and the port is not the WireGuard one
/// — forgetting to forward it is the ordinary mistake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for the gateway's negotiation answer.
///
/// It covers an ML-KEM-1024 encapsulation, an ML-DSA-65 signature and, above
/// all, installing the PSK on the data plane — which the gateway does
/// **before** answering. Fifteen seconds leaves room for a loaded machine
/// without ever looking like a hang.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn server_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    client_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
    let client_ca_der = client_ca.clone();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(client_ca))
        .map_err(|_| TransportError::InvalidCertificate)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.certificates(), identity.private_key()?)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![KEY_NEGOTIATION_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = pinned_transport();
    transport.max_concurrent_bidi_streams(1u32.into());
    // The gateway answers with the bulkiest half of the exchange — ciphertext
    // and signature — so the size limit matters at least as much here as on
    // the client side.
    config.transport = Arc::new(transport);
    let endpoint = Endpoint::server(config, bind).map_err(TransportError::Io)?;
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(KEY_NEGOTIATION_ALPN),
        served_certificate_sha256 = %identity.leaf_fingerprint(),
        client_ca_sha256 = %certificate_fingerprint_der(&client_ca_der),
        datagram_bytes = SAFE_UDP_PAYLOAD,
        "quic: key-negotiation server endpoint ready"
    );
    Ok(endpoint)
}

/// Builds a client endpoint with mutual TLS credentials.
pub fn client_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    gateway_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
    let mut endpoint = Endpoint::client(bind).map_err(TransportError::Io)?;
    endpoint.set_default_client_config(client_config(identity, gateway_ca)?);
    Ok(endpoint)
}

/// Same, on a socket the caller has already opened **and configured**.
///
/// Orion needs this because binding is not the whole story on Windows: the
/// session has to survive its own tunnel coming up, and only a socket forced
/// onto a chosen interface does. Letting the caller hand over a ready socket
/// keeps every platform quirk on its side of the boundary — this crate speaks
/// QUIC, it does not enumerate routing tables.
pub fn client_endpoint_on_socket(
    socket: std::net::UdpSocket,
    identity: &TlsIdentity,
    gateway_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(TransportError::Io)?;
    endpoint.set_default_client_config(client_config(identity, gateway_ca)?);
    Ok(endpoint)
}

fn client_config(
    identity: &TlsIdentity,
    gateway_ca: Vec<u8>,
) -> Result<quinn::ClientConfig, TransportError> {
    // Both halves of the trust decision, before a single packet leaves: the
    // certificate this client will present, and the only authority it will
    // accept in return. A handshake refused for `BadSignature` is read against
    // these two values and the ones the gateway prints on its side.
    tracing::info!(
        client_certificate_sha256 = %identity.leaf_fingerprint(),
        pinned_gateway_ca_sha256 = %certificate_fingerprint_der(&gateway_ca),
        alpn = %String::from_utf8_lossy(KEY_NEGOTIATION_ALPN),
        datagram_bytes = SAFE_UDP_PAYLOAD,
        "quic: key-negotiation client credentials loaded"
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(gateway_ca))
        .map_err(|_| TransportError::InvalidCertificate)?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.certificates(), identity.private_key()?)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![KEY_NEGOTIATION_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(pinned_transport()));
    Ok(client_config)
}

/// Serves connections until the endpoint is closed.
/// Counts recent handshakes per source address.
///
/// Deliberately a plain map behind a mutex rather than a background sweeper:
/// entries are pruned on insertion, so an address that stops talking costs
/// nothing, and the map never outgrows the number of addresses seen within one
/// window.
#[derive(Default)]
struct SourceLimiter {
    seen: std::collections::HashMap<std::net::IpAddr, (Instant, u32)>,
}

impl SourceLimiter {
    /// `true` if this address may open one more handshake.
    fn admit(&mut self, source: std::net::IpAddr, now: Instant) -> bool {
        self.seen
            .retain(|_, (started, _)| now.duration_since(*started) < SOURCE_RATE_WINDOW);
        let entry = self.seen.entry(source).or_insert((now, 0));
        if now.duration_since(entry.0) >= SOURCE_RATE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= MAX_HANDSHAKES_PER_SOURCE
    }
}

/// Serves the public negotiation port.
///
/// # Cost before authentication
///
/// Everything this port does — TLS 1.3, ML-DSA-65 verification, ML-KEM
/// encapsulation — is expensive, and all of it happens before the gateway
/// knows whether the peer is legitimate. That asymmetry is the DoS: a few
/// spoofed packets buy an attacker a lot of gateway CPU.
///
/// Two bounds, in the order that matters:
///
/// 1. **Address validation (QUIC Retry).** An `Incoming` whose address is not
///    yet validated is answered with a Retry packet, which costs a token and
///    no state. The peer must echo the token from that same address, so a
///    spoofed source never reaches the TLS handshake at all.
/// 2. **Per-source rate limit.** Validation proves the address is real, not
///    that it is friendly. Beyond [`MAX_HANDSHAKES_PER_SOURCE`] per window,
///    further handshakes from that address are refused.
///
/// [`MAX_ACTIVE_NEGOTIATIONS`] then bounds concurrency for what gets through.
pub async fn serve(endpoint: Endpoint, handler: Arc<dyn NegotiationHandler>) {
    let capacity = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_NEGOTIATIONS));
    let limiter = Arc::new(std::sync::Mutex::new(SourceLimiter::default()));

    while let Some(incoming) = endpoint.accept().await {
        // Before any allocation or cryptography: prove the address is real.
        if !incoming.remote_address_validated() {
            let remote = incoming.remote_address();
            if incoming.retry().is_err() {
                tracing::info!(%remote, "quic: retry refused for an already-validated peer");
            }
            continue;
        }

        let source = incoming.remote_address().ip();
        let admitted = limiter
            .lock()
            .map(|mut limiter| limiter.admit(source, Instant::now()))
            // A poisoned lock must not open the port wide: refuse instead.
            .unwrap_or(false);
        if !admitted {
            tracing::warn!(%source, "key-negotiation handshake rate exceeded for this address");
            incoming.refuse();
            continue;
        }

        let permit = match Arc::clone(&capacity).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                incoming.refuse();
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            if let Err(error) = handle_connection(incoming, handler, permit).await {
                // `aborted by peer` means the **client** hung up, and the text
                // that follows is its own error crossing the wire. Naming the
                // direction stops an operator reading a client-side refusal as
                // a gateway fault.
                tracing::warn!(
                    %remote,
                    error = %error,
                    detail = ?error,
                    "quic: key-negotiation connection rejected"
                );
            }
        });
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    handler: Arc<dyn NegotiationHandler>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), TransportError> {
    let started = Instant::now();
    let remote = incoming.remote_address();
    let connection = incoming.await.map_err(TransportError::Connection)?;
    let fingerprint = peer_certificate_sha256(&connection)?;
    // The fingerprint is what `heliosd peer add` was given: printing it here
    // makes an admission mismatch a comparison rather than a deduction.
    tracing::info!(
        %remote,
        elapsed_ms = started.elapsed().as_millis(),
        rtt_ms = connection.rtt().as_millis(),
        client_certificate_sha256 = %fingerprint,
        "quic: client handshake accepted"
    );
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(TransportError::Connection)?;
    let request: AuthenticatedKeyNegotiationRequest = read_frame(&mut recv).await?;
    if let Err(error) = request.request.validate() {
        write_frame(
            &mut send,
            &ServerMessage::Error {
                error: PublicError::Protocol,
            },
        )
        .await?;
        return Err(TransportError::Protocol(error.to_string()));
    }

    let transaction_id = request.request.transaction_id;
    let prepared = match handler.prepare(fingerprint, request).await {
        Ok(prepared) => prepared,
        Err(error) => {
            handler.rollback(transaction_id).await;
            write_frame(&mut send, &ServerMessage::Error { error }).await?;
            return Ok(());
        }
    };
    if let Err(error) = write_frame(
        &mut send,
        &ServerMessage::Response {
            response: Box::new(prepared.response),
        },
    )
    .await
    {
        handler.rollback(transaction_id).await;
        return Err(error);
    }

    let confirmation = tokio::time::timeout(
        prepared.confirmation_timeout,
        read_frame::<AuthenticatedKeyNegotiationConfirmation>(&mut recv),
    )
    .await;
    match confirmation {
        Ok(Ok(message))
            if message.confirmation.protocol_version == KEY_NEGOTIATION_VERSION
                && message.confirmation.transaction_id == transaction_id =>
        {
            let commit = match handler.confirm(message).await {
                Ok(commit) => commit,
                Err(error) => {
                    handler.rollback(transaction_id).await;
                    write_frame(
                        &mut send,
                        &ServerMessage::Error {
                            error: error.clone(),
                        },
                    )
                    .await?;
                    return Err(TransportError::Protocol(error.to_string()));
                }
            };
            let delivery = async {
                write_frame(&mut send, &ServerMessage::Committed { commit }).await?;
                send.finish().map_err(TransportError::ClosedStream)?;
                tokio::time::timeout(Duration::from_secs(5), send.stopped())
                    .await
                    .map_err(|_| TransportError::CommitDeliveryTimeout)?
                    .map_err(TransportError::Stopped)
            }
            .await;
            if let Err(error) = delivery {
                handler.rollback(transaction_id).await;
                return Err(error);
            }

            // The expensive part is over: release the concurrency permit
            // before waiting, so a long-lived tunnel does not hold a slot
            // that only exists to bound handshake cost.
            drop(permit);

            // From here the connection is a liveness link. Its closure — an
            // explicit disconnect, a crash, or a dead network — is what tells
            // the gateway to release the slot without waiting 150 s for
            // handshakes to go stale.
            connection.closed().await;
            handler.disconnected(transaction_id).await;
        }
        _ => handler.rollback(transaction_id).await,
    }
    Ok(())
}

/// Live link kept open for as long as the tunnel is meant to exist.
///
/// # Why the session outlives the negotiation
///
/// WireGuard is connectionless: when one end goes away, the other only finds
/// out when handshakes stop being answered — up to 150 s later. For that whole
/// window Orion shows a tunnel that is already dead, and Helios keeps a PSK
/// slot for a peer that is gone.
///
/// The QUIC connection that carried the negotiation solves this for free. It
/// is authenticated, it is already there, and **its closure is a signal**:
/// whoever hangs up — deliberately, or by crashing — is noticed by the other
/// end within a round-trip rather than within two and a half minutes.
#[derive(Clone)]
pub struct SessionLink {
    connection: Connection,
}

impl SessionLink {
    /// Resolves as soon as the peer closes the link, whatever the reason.
    pub async fn closed(&self) {
        self.connection.closed().await;
    }

    /// Hangs up, telling the peer the tunnel is going down now.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"tunnel closed by peer");
    }
}

/// Active client session. Confirmation consumes it to prevent duplicate commit.
pub struct ClientSession {
    _endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    transaction_id: [u8; 16],
}

impl ClientSession {
    pub async fn confirm(
        mut self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<(AuthenticatedKeyNegotiationCommit, SessionLink), TransportError> {
        if confirmation.confirmation.protocol_version != KEY_NEGOTIATION_VERSION
            || confirmation.confirmation.transaction_id != self.transaction_id
        {
            return Err(TransportError::Protocol(
                "client confirmation does not match the active transaction".into(),
            ));
        }
        write_frame(&mut self.send, &confirmation).await?;
        self.send.finish().map_err(TransportError::ClosedStream)?;
        let committed = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame::<ServerMessage>(&mut self.recv),
        )
        .await
        .map_err(|_| TransportError::CommitTimeout)??;
        let commit = match committed {
            ServerMessage::Committed { commit } if commit.transaction_id == self.transaction_id => {
                commit
            }
            ServerMessage::Error { error } => return Err(TransportError::Rejected(error)),
            _ => {
                return Err(TransportError::Protocol(
                    "server returned an invalid commit acknowledgment".into(),
                ))
            }
        };
        // The connection is handed back rather than dropped: from here on it
        // is the link whose closure tells the gateway this tunnel is over.
        Ok((
            commit,
            SessionLink {
                connection: self.connection,
            },
        ))
    }
}

pub async fn negotiate(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    request: &AuthenticatedKeyNegotiationRequest,
) -> Result<(AuthenticatedKeyNegotiationResponse, ClientSession), TransportError> {
    request
        .request
        .validate()
        .map_err(|error| TransportError::Protocol(error.to_string()))?;
    // Bounded, both of them. QUIC only gives up on its own when *nothing*
    // arrives; a gateway whose service answers at the transport level and
    // then says nothing — because it is holding a stale transaction for this
    // peer, say — leaves the client waiting for good. That wait has no
    // visible end: the interface is up, the UI announces «connexion…», and
    // nothing ever contradicts it.
    let started = Instant::now();
    tracing::info!(
        %remote,
        %server_name,
        local = ?endpoint.local_addr().ok(),
        timeout_s = CONNECT_TIMEOUT.as_secs(),
        "quic: opening the key-negotiation connection"
    );
    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(TransportError::Connect)?;
    let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Err(_) => {
            tracing::warn!(
                %remote,
                %server_name,
                udp_port = remote.port(),
                timeout_s = CONNECT_TIMEOUT.as_secs(),
                "quic: no handshake answer — unreachable port, or this UDP port \
                 not forwarded to the gateway"
            );
            return Err(TransportError::ConnectTimeout(
                remote,
                CONNECT_TIMEOUT.as_secs(),
            ));
        }
        // The whole reason this arm is written out rather than left to `?`.
        // Everything the exchange can be blamed on lives in this error, and it
        // used to reach no log at all: the caller turned it into a UI event,
        // the file recorded three dial attempts and not one cause.
        Ok(Err(error)) => {
            tracing::warn!(
                %remote,
                %server_name,
                elapsed_ms = started.elapsed().as_millis(),
                error = %error,
                detail = ?error,
                "quic: handshake refused — on `invalid peer certificate` compare \
                 the pinned gateway CA logged above with the certificate the \
                 gateway logs at startup; they differ after an identity rotation \
                 the daemon has not been restarted for"
            );
            return Err(TransportError::Connection(error));
        }
        Ok(Ok(connection)) => connection,
    };
    tracing::info!(
        %remote,
        %server_name,
        elapsed_ms = started.elapsed().as_millis(),
        rtt_ms = connection.rtt().as_millis(),
        gateway_certificate_sha256 = %peer_certificate_sha256(&connection)
            .unwrap_or_else(|_| "absente".into()),
        "quic: handshake complete, gateway certificate accepted"
    );
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(TransportError::Connection)?;
    write_frame(&mut send, request).await?;
    let answer = match tokio::time::timeout(
        RESPONSE_TIMEOUT,
        read_frame::<ServerMessage>(&mut recv),
    )
    .await
    {
        Err(_) => {
            // A gateway that answered at the transport level and then said
            // nothing: reached, authenticated, and stuck — most often on a
            // stale transaction still held for this peer.
            tracing::warn!(
                %remote,
                timeout_s = RESPONSE_TIMEOUT.as_secs(),
                rtt_ms = connection.rtt().as_millis(),
                "quic: connection established but no negotiation answer"
            );
            return Err(TransportError::ResponseTimeout(RESPONSE_TIMEOUT.as_secs()));
        }
        Ok(answer) => answer?,
    };
    match answer {
        ServerMessage::Response { response } => Ok((
            *response,
            ClientSession {
                _endpoint: endpoint.clone(),
                connection,
                send,
                recv,
                transaction_id: request.request.transaction_id,
            },
        )),
        ServerMessage::Error { error } => Err(TransportError::Rejected(error)),
        ServerMessage::Committed { .. } => Err(TransportError::Protocol(
            "server committed before sending negotiation material".into(),
        )),
    }
}

fn peer_certificate_sha256(connection: &Connection) -> Result<String, TransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::MissingPeerCertificate)?;
    certificate_fingerprint(identity.as_ref())
}

fn certificate_fingerprint(identity: &dyn Any) -> Result<String, TransportError> {
    let chain = identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .ok_or(TransportError::MissingPeerCertificate)?;
    let leaf = chain
        .first()
        .ok_or(TransportError::MissingPeerCertificate)?;
    Ok(certificate_fingerprint_der(leaf.as_ref()))
}

/// SHA-256 fingerprint used to bind a certificate to an admitted WireGuard peer.
pub fn certificate_fingerprint_der(bytes: &[u8]) -> String {
    hex::encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes))
}

async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    message: &T,
) -> Result<(), TransportError> {
    let bytes =
        serde_json::to_vec(message).map_err(|error| TransportError::Protocol(error.to_string()))?;
    if bytes.len() > MAX_KEY_NEGOTIATION_MESSAGE_BYTES {
        return Err(TransportError::MessageTooLarge);
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(TransportError::Write)?;
    send.write_all(&bytes)
        .await
        .map_err(TransportError::Write)?;
    // Frame sizes are the practical half of an MTU problem: the PQ material is
    // what makes these messages tens of datagrams long, and a run that stops
    // after the first frame is a path that will not carry the second.
    tracing::info!(
        message = short_type_name::<T>(),
        bytes = bytes.len(),
        "quic: frame sent"
    );
    Ok(())
}

/// Message type without its module path, for a log line.
fn short_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full)
}

async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, TransportError> {
    let mut length = [0u8; 4];
    recv.read_exact(&mut length)
        .await
        .map_err(TransportError::Read)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_KEY_NEGOTIATION_MESSAGE_BYTES {
        return Err(TransportError::MessageTooLarge);
    }
    let mut bytes = vec![0u8; length];
    recv.read_exact(&mut bytes)
        .await
        .map_err(TransportError::Read)?;
    tracing::info!(
        message = short_type_name::<T>(),
        bytes = length,
        "quic: frame received"
    );
    serde_json::from_slice(&bytes).map_err(|error| TransportError::Protocol(error.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("invalid PKCS#8 private key")]
    InvalidPrivateKey,
    #[error("peer did not present a certificate")]
    MissingPeerCertificate,
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("QUIC connect configuration failed: {0}")]
    Connect(quinn::ConnectError),
    #[error("QUIC connection failed: {0}")]
    Connection(quinn::ConnectionError),
    #[error("QUIC stream is already closed: {0}")]
    ClosedStream(quinn::ClosedStream),
    #[error("QUIC write failed: {0}")]
    Write(quinn::WriteError),
    #[error("QUIC read failed: {0}")]
    Read(quinn::ReadExactError),
    #[error(
        "no answer from the key-negotiation service at {0} after {1} s — check that its UDP port \
         is reachable (it is a port of its own, distinct from WireGuard's)"
    )]
    ConnectTimeout(SocketAddr, u64),
    #[error(
        "the gateway accepted the connection but did not answer the negotiation request within \
         {0} s"
    )]
    ResponseTimeout(u64),
    #[error("timed out while waiting for the key-negotiation commit acknowledgment")]
    CommitTimeout,
    #[error("timed out while delivering the key-negotiation commit acknowledgment")]
    CommitDeliveryTimeout,
    #[error("peer stopped the commit acknowledgment stream: {0}")]
    Stopped(quinn::StoppedError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("protocol message exceeds its bound")]
    MessageTooLarge,
    #[error("server rejected negotiation: {0}")]
    Rejected(PublicError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Horloge des tests : les requêtes doivent être fraîches pour passer la
    /// fenêtre anti-rejeu.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    use aether::key_negotiation::{
        authenticate_commit, authenticate_confirmation, authenticate_request,
        authenticate_response, generate_ml_dsa_65_keypair, issue_pq_certificate, PqCertificate,
        PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_NONCE_LEN, PQ_CERTIFICATE_VERSION,
    };
    use base64::Engine as _;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// Address validation proves an address is real, not that it is
    /// friendly. This bound is what keeps a validated attacker's CPU cost
    /// linear in the number of addresses it actually holds.
    #[test]
    fn a_single_source_cannot_buy_unlimited_handshakes() {
        let mut limiter = SourceLimiter::default();
        let attacker: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let bystander: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let start = Instant::now();

        for attempt in 1..=MAX_HANDSHAKES_PER_SOURCE {
            assert!(
                limiter.admit(attacker, start),
                "attempt {attempt} is within the budget"
            );
        }
        assert!(
            !limiter.admit(attacker, start),
            "the budget must run out for this address"
        );
        // One noisy address must not deny the service to everyone else.
        assert!(limiter.admit(bystander, start));

        // The window slides: the budget comes back rather than banning.
        let later = start + SOURCE_RATE_WINDOW + Duration::from_secs(1);
        assert!(limiter.admit(attacker, later));
        assert!(
            limiter.seen.len() <= 2,
            "expired entries must be pruned rather than accumulate"
        );
    }

    #[test]
    fn all_modes_prepare_exactly_one_wireguard_slot_state() {
        let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);

        let classic = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: [1; 16],
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            client_nonce: [2; 16],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: None,
        };
        let prepared = prepare_key_material(
            &classic,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&static_psk),
            DEFAULT_CONFIRMATION_TIMEOUT,
        )
        .unwrap();
        assert!(prepared.psk.is_none());

        let mut static_request = classic.clone();
        static_request.mode = ProtectionMode::StaticPsk;
        static_request.static_psk_fingerprint = Some(static_psk_fingerprint(&static_psk).unwrap());
        let prepared = prepare_key_material(
            &static_request,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&static_psk),
            DEFAULT_CONFIRMATION_TIMEOUT,
        )
        .unwrap();
        assert_eq!(prepared.psk.unwrap().expose(), static_psk);

        let (_secret_key, public_key) = MlKem1024Kem::generate().unwrap();
        let mut kem_request = classic;
        kem_request.mode = ProtectionMode::MlKem;
        kem_request.kem_public_key = Some(public_key);
        let prepared = prepare_key_material(
            &kem_request,
            GATEWAY_WG_KEY,
            [3; 16],
            None,
            DEFAULT_CONFIRMATION_TIMEOUT,
        )
        .unwrap();
        assert!(prepared.psk.is_some());
        assert!(prepared.response.kem_ciphertext.is_some());
    }

    #[test]
    fn static_mode_rejects_another_psk_fingerprint() {
        let configured = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let other = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: [1; 16],
            mode: ProtectionMode::StaticPsk,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            client_nonce: [2; 16],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: Some(static_psk_fingerprint(&other).unwrap()),
        };
        assert!(matches!(
            prepare_key_material(
                &request,
                GATEWAY_WG_KEY,
                [3; 16],
                Some(&configured),
                DEFAULT_CONFIRMATION_TIMEOUT
            ),
            Err(PublicError::ModeUnavailable)
        ));
    }

    struct TestPki {
        ca_der: Vec<u8>,
        server: TlsIdentity,
        client: TlsIdentity,
        client_fingerprint: String,
        client_pq_certificate: PqCertificate,
        client_pq_private_key: Vec<u8>,
        gateway_pq_certificate: PqCertificate,
        gateway_pq_private_key: Vec<u8>,
    }

    fn pq_identity(
        subject: &str,
        role: PqCertificateRole,
        wireguard_public_key: &str,
    ) -> (PqCertificate, Vec<u8>) {
        let (private_key, public_key) = generate_ml_dsa_65_keypair().unwrap();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [9; 16],
                subject: subject.into(),
                issuer: subject.into(),
                role,
                wireguard_public_key: wireguard_public_key.into(),
                ml_dsa_65_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_65_signature: String::new(),
            },
            private_key.as_slice(),
        )
        .unwrap();
        (certificate, private_key.to_vec())
    }

    fn test_pki() -> TestPki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        fn leaf(
            name: &str,
            usage: ExtendedKeyUsagePurpose,
            ca: &Certificate,
            ca_key: &KeyPair,
        ) -> (Vec<u8>, Vec<u8>) {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, ca, ca_key).unwrap();
            (cert.der().to_vec(), key.serialize_der())
        }

        let ca_der = ca.der().to_vec();
        let (server_cert, server_key) = leaf(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (client_cert, client_key) =
            leaf("orion", ExtendedKeyUsagePurpose::ClientAuth, &ca, &ca_key);
        let (client_pq_certificate, client_pq_private_key) =
            pq_identity("orion", PqCertificateRole::Client, CLIENT_WG_KEY);
        let (gateway_pq_certificate, gateway_pq_private_key) =
            pq_identity("localhost", PqCertificateRole::Gateway, GATEWAY_WG_KEY);
        TestPki {
            ca_der,
            server: TlsIdentity {
                certificate_chain: vec![server_cert, ca.der().to_vec()],
                private_key: server_key,
            },
            client_fingerprint: certificate_fingerprint_der(&client_cert),
            client: TlsIdentity {
                certificate_chain: vec![client_cert, ca.der().to_vec()],
                private_key: client_key,
            },
            client_pq_certificate,
            client_pq_private_key,
            gateway_pq_certificate,
            gateway_pq_private_key,
        }
    }

    struct Handler {
        expected_fingerprint: String,
        confirmed: AtomicBool,
        rolled_back: AtomicBool,
        disconnected: AtomicBool,
        gateway_pq_certificate: PqCertificate,
        gateway_pq_private_key: Vec<u8>,
    }

    #[async_trait]
    impl NegotiationHandler for Handler {
        async fn prepare(
            &self,
            certificate_sha256: String,
            request: AuthenticatedKeyNegotiationRequest,
        ) -> Result<PreparedNegotiation, PublicError> {
            if certificate_sha256 != self.expected_fingerprint {
                return Err(PublicError::IdentityMismatch);
            }
            Ok(PreparedNegotiation {
                response: authenticate_response(
                    KeyNegotiationResponse {
                        protocol_version: KEY_NEGOTIATION_VERSION,
                        transaction_id: request.request.transaction_id,
                        selected_mode: request.request.mode,
                        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
                        gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
                        kem_ciphertext: None,
                        confirmation_timeout_secs: 2,
                    },
                    self.gateway_pq_certificate.clone(),
                    &self.gateway_pq_private_key,
                )
                .map_err(|_| PublicError::Protocol)?,
                confirmation_timeout: Duration::from_secs(2),
            })
        }

        async fn confirm(
            &self,
            confirmation: AuthenticatedKeyNegotiationConfirmation,
        ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
            self.confirmed.store(true, Ordering::SeqCst);
            authenticate_commit(
                confirmation.confirmation.transaction_id,
                &self.gateway_pq_private_key,
            )
            .map_err(|_| PublicError::Protocol)
        }

        async fn disconnected(&self, _transaction_id: [u8; 16]) {
            self.disconnected.store(true, Ordering::SeqCst);
        }

        async fn rollback(&self, _transaction_id: [u8; 16]) {
            self.rolled_back.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn mutual_tls_negotiation_is_confirmed_on_the_same_stream() {
        let pki = test_pki();
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.server,
            pki.ca_der.clone(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handler = Arc::new(Handler {
            expected_fingerprint: pki.client_fingerprint,
            confirmed: AtomicBool::new(false),
            rolled_back: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            gateway_pq_certificate: pki.gateway_pq_certificate.clone(),
            gateway_pq_private_key: pki.gateway_pq_private_key.clone(),
        });
        let served = Arc::clone(&handler);
        let task = tokio::spawn(serve(server, served));

        let client =
            client_endpoint("127.0.0.1:0".parse().unwrap(), &pki.client, pki.ca_der).unwrap();
        let request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: [1; KEY_NEGOTIATION_NONCE_LEN],
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            client_nonce: [2; KEY_NEGOTIATION_NONCE_LEN],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: None,
        };
        let authenticated_request = authenticate_request(
            request.clone(),
            pki.client_pq_certificate,
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (response, session) =
            negotiate(&client, server_addr, "localhost", &authenticated_request)
                .await
                .unwrap();
        response
            .response
            .validate_for(&request, GATEWAY_WG_KEY)
            .unwrap();
        let confirmation =
            authenticate_confirmation(request.transaction_id, &pki.client_pq_private_key).unwrap();
        let (commit, link) = session.confirm(confirmation).await.unwrap();
        commit
            .verify(&pki.gateway_pq_certificate.ml_dsa_65_public_key)
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler.confirmed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!handler.rolled_back.load(Ordering::SeqCst));

        // The link is what tells the gateway the tunnel is over. Closing it
        // must be noticed within a round-trip — the whole point is not waiting
        // 150 s for WireGuard handshakes to go stale.
        assert!(
            !handler.disconnected.load(Ordering::SeqCst),
            "a live link must not look like a departure"
        );
        link.close();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !handler.disconnected.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closing the link must be seen at once");
        assert!(
            !handler.rolled_back.load(Ordering::SeqCst),
            "a committed tunnel ending is not a rollback"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    #[tokio::test]
    async fn closing_an_unconfirmed_session_requests_rollback() {
        let pki = test_pki();
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.server,
            pki.ca_der.clone(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handler = Arc::new(Handler {
            expected_fingerprint: pki.client_fingerprint,
            confirmed: AtomicBool::new(false),
            rolled_back: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            gateway_pq_certificate: pki.gateway_pq_certificate.clone(),
            gateway_pq_private_key: pki.gateway_pq_private_key.clone(),
        });
        let task = tokio::spawn(serve(
            server,
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        ));
        let client =
            client_endpoint("127.0.0.1:0".parse().unwrap(), &pki.client, pki.ca_der).unwrap();
        let request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id: [4; KEY_NEGOTIATION_NONCE_LEN],
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            client_nonce: [5; KEY_NEGOTIATION_NONCE_LEN],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: None,
        };
        let authenticated_request = authenticate_request(
            request,
            pki.client_pq_certificate,
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (_, session) = negotiate(&client, server_addr, "localhost", &authenticated_request)
            .await
            .unwrap();
        drop(session);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler.rolled_back.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!handler.confirmed.load(Ordering::SeqCst));
        client.close(0u32.into(), b"test complete");
        task.abort();
    }
}
