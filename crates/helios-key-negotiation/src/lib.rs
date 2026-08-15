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
    commitments_match, derive_negotiated_psk, static_psk_commitment,
    AuthenticatedKeyNegotiationCommit, AuthenticatedKeyNegotiationConfirmation,
    AuthenticatedKeyNegotiationRequest, AuthenticatedKeyNegotiationResponse,
    KeyNegotiationChallenge, KeyNegotiationRequest, KeyNegotiationResponse, ProtectionMode,
    KEY_NEGOTIATION_VERSION, MAX_KEY_NEGOTIATION_MESSAGE_BYTES, SERVER_CHALLENGE_LEN,
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
pub const KEY_NEGOTIATION_ALPN: &[u8] = b"helios-key-negotiation/5";
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

/// Bounds concurrent **negotiations** on the public WAN port.
///
/// Not a tunnel ceiling. Since v5 the connection is closed right after the
/// commit, so it lives for one transaction — a few hundred milliseconds in
/// the nominal case. In v4 the same number bounded the tunnels themselves,
/// because every connected client held its connection open for the life of
/// its tunnel.
pub const MAX_ACTIVE_NEGOTIATIONS: usize = 128;

/// How long a gateway-issued challenge stays usable.
///
/// It lives in the connection's own state, so this bound only matters for a
/// client that asks for one and then dawdles. Long enough to cover an
/// ML-KEM keygen and an ML-DSA-87 signature on a slow laptop, short enough
/// that a connection cannot sit on a valid authorization.
pub const CHALLENGE_VALIDITY: Duration = Duration::from_secs(45);

/// Handshakes accepted per source address and per window, once its address is
/// validated.
///
/// Address validation stops spoofed floods; it does nothing against an
/// attacker using its own address, which can still make the gateway run TLS
/// handshakes and ML-DSA verifications. This second bound makes that cost
/// linear in the number of addresses an attacker actually holds.
pub const MAX_HANDSHAKES_PER_SOURCE: u32 = 8;

/// Negotiations one admitted identity may open per [`SOURCE_RATE_WINDOW`].
///
/// Charged after mTLS, when the peer has a name. The address budget below
/// bounds anonymous traffic; this one bounds an authenticated peer that
/// roams, whose every attempt still costs an ML-DSA-87 verification and an
/// ML-KEM encapsulation.
pub const MAX_NEGOTIATIONS_PER_IDENTITY: u32 = 8;

/// Longest a negotiation connection may live, from address validation.
///
/// Not renewable, and unrelated to the idle timeout: a peer that keeps
/// sending well-formed frames is never idle, so an idle timeout alone lets a
/// connection — and the concurrency permit it holds — live for ever. With
/// only 128 permits, a handful of such connections is the whole service.
///
/// Sized above the sum of the phases it must contain: a challenge round trip,
/// a preparation, and up to a 45-second wait for the confirming WireGuard
/// handshake.
pub const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(90);

/// Window over which [`MAX_HANDSHAKES_PER_SOURCE`] is counted.
///
/// A legitimate client negotiates once per connection, so eight attempts a
/// minute leaves ample room for retries on a lossy link.
pub const SOURCE_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Secret configuration prepared for the WireGuard peer.
///
/// Since `classic` stopped being a negotiable mode, every negotiation that
/// gets this far produces a key: `psk` is always `Some` here. The `Option`
/// remains because the data-plane call it feeds also uses `None` to *clear* a
/// slot, which is a different operation reached by a different path.
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
        server_challenge: request.server_challenge,
        selected_mode: request.mode,
        gateway_wg_public_key: gateway_wg_public_key.to_string(),
        client_wg_public_key: request.client_wg_public_key.clone(),
        gateway_nonce,
        kem_ciphertext: None,
        confirmation_timeout_secs: timeout_secs,
        // `static_psk` never expires: the value belongs to both peers'
        // configuration, not to this transaction.
        psk_lifetime_secs: match request.mode {
            ProtectionMode::StaticPsk => 0,
            _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
        },
    };

    let psk = match request.mode {
        // Unreachable through the public port, where `validate()` refuses it
        // before anything is prepared. Kept as an explicit refusal rather than
        // an `unreachable!()`: this function is also reachable from tests and
        // tooling, and a mode that yields no PSK must never silently produce a
        // prepared slot.
        ProtectionMode::Classic => return Err(PublicError::Rejected),
        ProtectionMode::StaticPsk => {
            // `Rejected`, not a mode-specific code: whether the peer has no
            // static PSK configured, or has one that does not match, is
            // exactly the sort of state the public boundary must not reveal.
            let configured = static_psk.ok_or(PublicError::Rejected)?;
            let presented = request
                .static_psk_commitment
                .as_deref()
                .ok_or(PublicError::Protocol)?;
            // Recomputed for this transaction, so the comparison proves
            // possession *now* rather than matching a stable identifier an
            // observer could have harvested from an earlier negotiation.
            let expected = static_psk_commitment(
                configured,
                &request.transaction_id,
                &request.client_nonce,
                &request.server_challenge,
                &request.client_wg_public_key,
                gateway_wg_public_key,
            )
            .map_err(|_| PublicError::Rejected)?;
            if !commitments_match(&expected, presented) {
                return Err(PublicError::Rejected);
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

/// What the gateway announces in a challenge, before anyone is authenticated.
///
/// Public by construction: both values are already in every client profile.
/// Announcing them lets a client detect a wrong or substituted endpoint
/// before spending an ML-DSA-87 signature on it.
#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    pub wg_public_key: String,
    pub server_name: String,
}

#[async_trait]
pub trait NegotiationHandler: Send + Sync + 'static {
    /// Identity to put in a challenge. Must be what the gateway actually
    /// serves, not what its configuration file says it should serve.
    fn announced_identity(&self) -> GatewayIdentity;

    /// The one admitted peer this TLS certificate belongs to, if any.
    ///
    /// Called as soon as mTLS names the peer and **before** a challenge is
    /// issued (spec §4.4, §7.3): an unknown fingerprint must not cost the
    /// gateway a CSPRNG read and a frame, and an admitted identity must not
    /// get to choose which peer it probes. The WireGuard key in the request
    /// is then checked against this answer — it is never itself a lookup key
    /// into the peer table.
    async fn resolve_admitted_peer(&self, certificate_sha256: &str) -> Option<String>;

    async fn prepare(
        &self,
        certificate_sha256: String,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError>;

    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError>;

    /// Undoes a transaction that never reached its commit.
    ///
    /// Only callable **before** the commit is signed. After that point there
    /// is no rollback: see the ordering in `heliosd::key_negotiation`.
    ///
    /// The peer's WireGuard key is passed alongside the identifier because
    /// this must also undo a `prepare` that was **destroyed part-way
    /// through** and therefore never recorded its transaction. The
    /// implementation matches on the identifier the slot itself carries, so
    /// a call naming a transaction that no longer owns the slot is a no-op.
    async fn rollback(&self, transaction_id: [u8; 16], client_wg_public_key: &str);
}

/// What a client sends.
///
/// Tagged, and the tag set is now exactly one transaction: challenge,
/// request, confirmation. The v5 `release` used to be the port's second entry
/// point; it moved into the WireGuard tunnel (spec §7.5), so the historic tag
/// no longer decodes and the frame is refused as a protocol error before any
/// handler runs — which is what a withdrawn message should look like on the
/// wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientMessage {
    ChallengeRequest {
        protocol_version: u16,
    },
    Request {
        request: Box<AuthenticatedKeyNegotiationRequest>,
    },
    Confirmation {
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServerMessage {
    Challenge {
        challenge: KeyNegotiationChallenge,
    },
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
///
/// # Why there are only three
///
/// v4 exposed seven. Three of them — `identity_mismatch`, `downgrade`,
/// `busy` — answered questions an attacker had no right to ask: they let
/// anyone enumerate admitted peers and read their security floor from a
/// public port, by sending requests and reading which refusal came back.
///
/// v5 keeps the causes and stops publishing them. Every pre-installation
/// refusal is [`Self::Rejected`], whatever produced it: unknown peer, wrong
/// TLS fingerprint, invalid or unadmitted PQ certificate, bad signature,
/// missing or spent challenge, clock outside the window, mode below the
/// floor, concurrent transaction, wrong gateway. The real reason is named in
/// the gateway's protected journal, where an operator reads it and an
/// attacker does not.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", content = "message", rename_all = "snake_case")]
pub enum PublicError {
    /// Malformed frame, encoding or version — decided before authentication.
    #[error("protocol message is invalid")]
    Protocol,
    /// Any refusal **before** the slot is installed.
    #[error("request was rejected")]
    Rejected,
    /// Failure at or after slot installation.
    ///
    /// Only ever observable by a peer that is already authenticated and
    /// admitted, so it tells an outsider nothing.
    #[error("the gateway could not complete an authenticated request")]
    Internal,
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
    // Between the response and the confirmation the client is waiting on a
    // WireGuard handshake, and neither end sends anything for as long as that
    // takes. QUIC's default reads 30 seconds of that silence as death and
    // tears down a connection that is doing exactly what the protocol asks.
    //
    // This is *not* a liveness signal, and nothing about the tunnel depends
    // on it. In v4 the connection was the liveness link and its closure
    // released the PSK slot — which released it half a minute into every
    // tunnel, and the session then worked until the next WireGuard rekey and
    // died two to three minutes in for no reason either end announced. v5
    // closes the connection after the commit and reads liveness from the data
    // plane; this timeout only bounds a transaction.
    transport.max_idle_timeout(Some(
        TRANSACTION_IDLE_TIMEOUT
            .try_into()
            .expect("the idle timeout fits QUIC's varint"),
    ));
    // Nothing in this protocol ever opens a unidirectional stream. Leaving
    // quinn's default in place would let a peer open a hundred of them and
    // hold receive buffers the exchange has no use for. Set on **both** sides:
    // a limit only the gateway announces bounds only the gateway.
    transport.max_concurrent_uni_streams(0u32.into());
    // The receive windows bound what one connection can make its peer buffer
    // before a frame length is even parsed.
    transport.stream_receive_window(RECEIVE_WINDOW.into());
    transport.receive_window(RECEIVE_WINDOW.into());
    transport
}

/// Flow-control window, per stream and per connection (spec §4.1).
///
/// Three maximum frames — `3 × (4 + 65 536)` — which is the most either end
/// legitimately has in flight, and neither ever keeps more than one complete
/// unprocessed frame per direction. Far below quinn's default, which is sized
/// for bulk transfer rather than for a two-round-trip exchange.
const RECEIVE_WINDOW: u32 = 3 * (4 + MAX_KEY_NEGOTIATION_MESSAGE_BYTES as u32);

/// Datagram size every QUIC path must carry (RFC 9000 §14).
const SAFE_UDP_PAYLOAD: u16 = 1200;

/// Silence after which a **transaction** connection is abandoned.
///
/// This is not a liveness mechanism, and nothing about the tunnel depends on
/// it: since v5 the connection is closed as soon as the commit is delivered,
/// and a PSK is never released because a connection went away.
///
/// It exists for one reason. Between the response and the confirmation the
/// client is waiting on a WireGuard handshake and neither end sends anything
/// — up to [`DEFAULT_CONFIRMATION_TIMEOUT`]. QUIC's own default of thirty
/// seconds would tear the connection down in the middle of that wait, which
/// would look exactly like a gateway that stopped answering. Sixty seconds
/// clears the confirmation window with room to spare.
///
/// The v4 keep-alive is gone with the link it kept alive. Nothing here should
/// ever be reintroduced as a way of inferring that a peer is still there:
/// that question is now answered by the data plane
/// (`helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS`).
///
/// Fifty seconds is the value §4.5 fixes. It sits above the 45-second
/// confirmation window it has to clear and below the 90-second ceiling, which
/// is the whole of what it must satisfy.
const TRANSACTION_IDLE_TIMEOUT: Duration = Duration::from_secs(50);

/// Time allowed for the QUIC handshake with the negotiation service.
///
/// Generous for a mutual-TLS handshake on a residential link, and short
/// enough that an unreachable port is reported rather than waited on: this is
/// the very first thing a client does, and the port is not the WireGuard one
/// — forgetting to forward it is the ordinary mistake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for a peer to take the last frame before the connection goes.
const COMMIT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Time allowed for the gateway's challenge.
///
/// It costs the gateway one RNG read and no signature, so anything slower
/// than this is a path problem rather than a load problem.
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

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
    // Session resumption and 0-RTT are forbidden (spec §4.1). Every
    // connection redoes the full mutual TLS and presents the current client
    // certificate, so no identity inherited from a ticket can bypass current
    // validity or current admission. rustls issues tickets by default, which
    // is precisely the behaviour being refused here.
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = pinned_transport();
    // Exactly one, opened by Orion. A second is a protocol error.
    transport.max_concurrent_bidi_streams(1u32.into());
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
    // The client half of the same refusal: no ticket is kept, so none can be
    // offered. `Arc::new(NoClientSessionStorage)` is what rustls calls "do not
    // resume"; leaving the default in place would have the client volunteer a
    // resumption the gateway is configured never to grant.
    tls.resumption = rustls::client::Resumption::disabled();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = pinned_transport();
    // The gateway never opens a stream to the client, so the client accepts
    // none: the single bidirectional stream is Orion's, in Orion's direction.
    transport.max_concurrent_bidi_streams(0u32.into());
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// Serves connections until the endpoint is closed.
/// The bucket a source address is counted in.
///
/// IPv4 is counted per address. IPv6 is counted per **`/64`**, because that is
/// the smallest block an ordinary subscriber is handed: counting per exact
/// address would let one host walk through 2^64 of them and never reach the
/// limit, which makes the whole per-source budget decorative on IPv6.
///
/// The trade-off is deliberate and stated: several legitimate clients behind
/// one `/64` share one budget, exactly as several clients behind one IPv4 NAT
/// already do.
fn rate_bucket(source: std::net::IpAddr) -> std::net::IpAddr {
    match source {
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
        std::net::IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

/// Counts recent events per key, over a sliding window.
///
/// Deliberately a plain map behind a mutex rather than a background sweeper:
/// entries are pruned on insertion, so a key that stops appearing costs
/// nothing, and the map never outgrows the number of keys seen within one
/// window.
struct RateLimiter<K> {
    seen: std::collections::HashMap<K, (Instant, u32)>,
    budget: u32,
}

impl<K: std::hash::Hash + Eq> RateLimiter<K> {
    fn new(budget: u32) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            budget,
        }
    }

    /// `true` if this key may consume one more unit of budget.
    fn admit(&mut self, key: K, now: Instant) -> bool {
        self.seen
            .retain(|_, (started, _)| now.duration_since(*started) < SOURCE_RATE_WINDOW);
        let entry = self.seen.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= SOURCE_RATE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.budget
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
    let limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_HANDSHAKES_PER_SOURCE,
    )));
    // Counted once mTLS has named a peer, which is a different question from
    // the address budget above. A holder of one admitted certificate roaming
    // across addresses — or simply behind a large provider — would otherwise
    // face no limit at all, and every negotiation it opens costs the gateway
    // an ML-DSA-87 verification and an ML-KEM encapsulation.
    let per_identity = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        MAX_NEGOTIATIONS_PER_IDENTITY,
    )));

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
            .map(|mut limiter| limiter.admit(rate_bucket(source), Instant::now()))
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
        let per_identity = Arc::clone(&per_identity);
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            // The absolute ceiling. `handle_connection` bounds each phase it
            // waits on, but the sum of well-behaved phases is not itself
            // bounded — this is what makes it so.
            let served = tokio::time::timeout(
                MAX_CONNECTION_LIFETIME,
                handle_connection(incoming, handler, permit, per_identity),
            )
            .await
            .unwrap_or_else(|_| Err(TransportError::Protocol(absolute_lifetime_reached())));
            if let Err(error) = served {
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

fn absolute_lifetime_reached() -> String {
    format!(
        "connection exceeded its {} s absolute lifetime",
        MAX_CONNECTION_LIFETIME.as_secs()
    )
}

/// The absolute lifetime of one connection, as a point in time.
///
/// Each phase clamps its own timeout against what is left of it, so the
/// ceiling is normally reached on an ordinary code path — one that rolls
/// back, answers, and releases its permit. The `timeout` wrapping the whole
/// connection stays as a backstop, but it must not be the mechanism that
/// usually fires: destroying a future runs no code.
#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn starting_now() -> Self {
        Self(Instant::now() + MAX_CONNECTION_LIFETIME)
    }

    /// `phase`, or whatever is left of the connection's life, whichever is
    /// shorter. Zero once the ceiling has passed, which every `timeout`
    /// treats as an immediate expiry.
    fn clamp(self, phase: Duration) -> Duration {
        phase.min(self.remaining())
    }

    fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
}

/// Undoes an unresolved transaction even when the task carrying it is
/// destroyed rather than returned from.
///
/// # Why the ordinary exit paths are not enough
///
/// Every exit from [`handle_connection`] already rolls back. None of them
/// runs when the future is **dropped**, and one is dropped on purpose: the
/// `timeout` enforcing the 90-second ceiling. The interval that matters is
/// the wait for the confirmation — up to 45 seconds in which nothing happens
/// but the client thinking. A connection destroyed there used to leave the
/// candidate PSK posed, the peer reserved and the transaction in the active
/// table with nothing left to resolve it: that peer could not negotiate again
/// until the daemon restarted, and reaching the state cost an admitted client
/// one connection it simply never finished.
///
/// # Why it spawns
///
/// `Drop` cannot await. The rollback is guarded by the transaction identifier
/// the slot itself carries, so running it a moment late is a no-op rather
/// than a write — which is what makes detaching it safe.
struct RollbackGuard {
    handler: Arc<dyn NegotiationHandler>,
    transaction_id: [u8; 16],
    public_key: String,
    armed: bool,
}

impl RollbackGuard {
    fn arm(
        handler: Arc<dyn NegotiationHandler>,
        transaction_id: [u8; 16],
        public_key: String,
    ) -> Self {
        Self {
            handler,
            transaction_id,
            public_key,
            armed: true,
        }
    }

    /// Rolls back now, waiting for it, and disarms **once it has returned**.
    ///
    /// The order is the whole point. Disarming first — the obvious way to
    /// write this — reopens the hole the guard exists to close: the rollback
    /// is an `await`, the absolute ceiling can destroy the task inside it, and
    /// `Drop` would then find a guard that has already declared itself done.
    /// The candidate would stay posed with no record of it.
    ///
    /// This makes a double rollback possible, and that is fine: undoing is
    /// keyed on the identifier the slot itself carries, so the second call
    /// finds a slot that is no longer its own and writes nothing.
    async fn roll_back(&mut self) {
        if !self.armed {
            return;
        }
        self.handler
            .rollback(self.transaction_id, &self.public_key)
            .await;
        self.armed = false;
    }

    /// The commit is signed. There is nothing left that may be undone.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(
            transaction = %hex::encode(self.transaction_id),
            peer = %self.public_key,
            "connection destroyed with a candidate PSK posed; rolling back out of band"
        );
        let handler = Arc::clone(&self.handler);
        let transaction_id = self.transaction_id;
        let public_key = std::mem::take(&mut self.public_key);
        // `Handle::try_current` rather than `tokio::spawn`, which panics with
        // no runtime. There is one here in every case that matters; during
        // shutdown there may not be, and a panic inside `Drop` would be a
        // worse outcome than a slot the next start clears anyway.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { handler.rollback(transaction_id, &public_key).await });
        }
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    handler: Arc<dyn NegotiationHandler>,
    permit: tokio::sync::OwnedSemaphorePermit,
    per_identity: Arc<std::sync::Mutex<RateLimiter<String>>>,
) -> Result<(), TransportError> {
    let started = Instant::now();
    let deadline = Deadline::starting_now();
    let remote = incoming.remote_address();
    let connection = incoming.await.map_err(TransportError::Connection)?;
    let fingerprint = peer_certificate_sha256(&connection)?;
    // Resolved before anything is spent on this connection (spec §4.4, §7.3).
    // Two properties come out of doing it here rather than at `prepare`: an
    // unknown fingerprint never costs a challenge, and an admitted identity
    // is bound to **its** peer from this point on — the WireGuard key in the
    // request is checked against this answer instead of being a lookup key of
    // its own, so one admitted client cannot aim a negotiation at another.
    let Some(admitted_peer) = handler.resolve_admitted_peer(&fingerprint).await else {
        tracing::warn!(
            %remote,
            client_certificate_sha256 = %fingerprint,
            "quic: certificate signed by the client CA but not admitted for any peer"
        );
        connection.close(0u32.into(), b"rejected");
        return Err(TransportError::Protocol(
            "client certificate is not admitted for any peer".into(),
        ));
    };
    // Now that mTLS has named an *admitted* peer, charge it. A per-address
    // budget does not bound a single admitted identity that roams.
    let within_budget = per_identity
        .lock()
        .map(|mut limiter| limiter.admit(fingerprint.clone(), Instant::now()))
        // A poisoned lock must not open the port wide: refuse instead.
        .unwrap_or(false);
    if !within_budget {
        tracing::warn!(
            %remote,
            client_certificate_sha256 = %fingerprint,
            "key-negotiation rate exceeded for this admitted identity"
        );
        connection.close(0u32.into(), b"rate");
        return Err(TransportError::Protocol(
            "negotiation rate exceeded for this identity".into(),
        ));
    }
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

    // The challenge lives here — in this task's stack, for this connection —
    // and nowhere else. That is the whole anti-replay design of v5, and it is
    // why it needed no global table, no persistence and no counter: an
    // `Option` owned by a single task is consumed exactly once by
    // construction, so two requests bearing the same challenge cannot both be
    // accepted even in principle. The 128-connection ceiling already bounds
    // how many can exist.
    let mut issued_challenge: Option<[u8; SERVER_CHALLENGE_LEN]> = None;
    let mut challenge_requests = 0u32;
    let challenge_deadline = Instant::now() + CHALLENGE_VALIDITY;

    let request = loop {
        // Nothing before the request has a phase timeout of its own: the
        // challenge round-trip is short and the client sets the pace. What it
        // must not do is outlast the connection, so the read is bounded by
        // what is left of the absolute lifetime and expires as an error
        // rather than as a destroyed task.
        let frame =
            tokio::time::timeout(deadline.remaining(), read_frame::<ClientMessage>(&mut recv))
                .await
                .map_err(|_| TransportError::Protocol(absolute_lifetime_reached()))??;
        match frame {
            ClientMessage::ChallengeRequest { protocol_version } => {
                // Exactly one per connection. Each costs a CSPRNG read and a
                // frame, and answering an unbounded stream of them is free
                // work for an attacker who never intends to negotiate. The
                // previous code merely replaced the live challenge, which
                // bounded how many were *valid* at once but not how many the
                // gateway would produce.
                if challenge_requests > 0 {
                    write_frame(
                        &mut send,
                        &ServerMessage::Error {
                            error: PublicError::Protocol,
                        },
                    )
                    .await?;
                    return Err(TransportError::Protocol(
                        "a connection may request only one challenge".into(),
                    ));
                }
                challenge_requests += 1;
                if protocol_version != KEY_NEGOTIATION_VERSION {
                    write_frame(
                        &mut send,
                        &ServerMessage::Error {
                            error: PublicError::Protocol,
                        },
                    )
                    .await?;
                    return Err(TransportError::Protocol(format!(
                        "unsupported protocol version {protocol_version}"
                    )));
                }
                let challenge = random_challenge()?;
                issued_challenge = Some(challenge);
                let identity = handler.announced_identity();
                write_frame(
                    &mut send,
                    &ServerMessage::Challenge {
                        challenge: KeyNegotiationChallenge {
                            protocol_version: KEY_NEGOTIATION_VERSION,
                            server_challenge: challenge,
                            gateway_wg_public_key: identity.wg_public_key,
                            server_name: identity.server_name,
                            expires_in_secs: CHALLENGE_VALIDITY.as_secs() as u32,
                        },
                    },
                )
                .await?;
            }
            ClientMessage::Request { request } => {
                if let Err(error) = consume_challenge(
                    &mut issued_challenge,
                    challenge_deadline,
                    request.request.server_challenge,
                ) {
                    write_frame(&mut send, &ServerMessage::Error { error }).await?;
                    return Ok(());
                }
                break *request;
            }
            ClientMessage::Confirmation { .. } => {
                write_frame(
                    &mut send,
                    &ServerMessage::Error {
                        error: PublicError::Protocol,
                    },
                )
                .await?;
                return Err(TransportError::Protocol(
                    "confirmation received before any negotiation".into(),
                ));
            }
        }
    };

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
    // The request may only speak for the peer mTLS already bound it to.
    if request.request.client_wg_public_key != admitted_peer {
        write_frame(
            &mut send,
            &ServerMessage::Error {
                error: PublicError::Rejected,
            },
        )
        .await?;
        return Err(TransportError::Protocol(
            "request names a WireGuard key other than the one this certificate is admitted for"
                .into(),
        ));
    }

    let transaction_id = request.request.transaction_id;
    let server_challenge = request.request.server_challenge;
    // Armed before `prepare`, not after it. `prepare` reserves the peer's
    // slot and poses the candidate on the data plane before it returns, so
    // the interval it occupies is one where an abandoned connection has
    // something to undo.
    let mut guard = RollbackGuard::arm(
        Arc::clone(&handler),
        transaction_id,
        request.request.client_wg_public_key.clone(),
    );
    let prepared = match handler.prepare(fingerprint, request).await {
        Ok(prepared) => prepared,
        Err(error) => {
            guard.roll_back().await;
            write_frame(&mut send, &ServerMessage::Error { error }).await?;
            // The error is the final application frame, just like a commit.
            // Returning immediately drops the stream before the peer has read
            // it; Quinn then reports a connection loss and hides the public
            // `rejected` result that was actually sent.
            drain_then_close(&connection, &mut send, "negotiation rejected").await;
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
        guard.roll_back().await;
        return Err(error);
    }

    // Clamped to whatever is left of the absolute lifetime. The confirmation
    // wait is the long one — up to 45 s — so it is the phase that would
    // otherwise run past the 90 s ceiling and have the connection destroyed
    // under it. Bounding it here means the deadline is reached on an ordinary
    // code path, with the rollback the ceiling itself cannot perform.
    let confirmation = tokio::time::timeout(
        deadline.clamp(prepared.confirmation_timeout),
        read_frame::<ClientMessage>(&mut recv),
    )
    .await;
    let message = match confirmation {
        Ok(Ok(ClientMessage::Confirmation { confirmation }))
            if confirmation.confirmation.protocol_version == KEY_NEGOTIATION_VERSION
                && confirmation.confirmation.transaction_id == transaction_id
                && confirmation.confirmation.server_challenge == server_challenge =>
        {
            confirmation
        }
        // Timed out, unreadable, or not the transaction we are holding.
        _ => {
            guard.roll_back().await;
            return Ok(());
        }
    };

    // Point of no return. `confirm` persists the floor and signs the commit,
    // in that order; once it returns Ok there is no rollback, and none of the
    // failures below may reach for one. A commit that cannot be delivered
    // leaves the slot armed on this side and the client renegotiates — which
    // converges — whereas restoring the slot behind a signed commit would put
    // a valid, verifiable commit in a client's hands against a gateway that
    // had undone everything. That was the v4 behaviour, and it is the double
    // semantics v5 exists to remove.
    //
    // Disarmed only *after* `confirm` returns `Ok`: if the task is destroyed
    // during `confirm` itself the candidate must still come back, and if
    // `confirm` succeeded there is nothing left that may be undone.
    let commit = match handler.confirm(message).await {
        Ok(commit) => commit,
        Err(error) => {
            guard.roll_back().await;
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
    guard.disarm();

    if let Err(error) = write_frame(&mut send, &ServerMessage::Committed { commit }).await {
        tracing::warn!(
            %remote,
            transaction = %hex::encode(transaction_id),
            error = %error,
            "commit could not be sent; the slot stays armed and the client will \
             renegotiate — this is not a rollback"
        );
        return Err(error);
    }

    // Closed, not kept. The connection carried a transaction and that
    // transaction is over; nothing about the tunnel depends on it any more.
    // Liveness is read from the data plane by both ends.
    //
    // The drain is not politeness: closing a QUIC connection discards data
    // the peer has not read, so hanging up straight after the write loses the
    // commit on a fast local path. A lost commit is survivable — the client
    // renegotiates — but losing it *every* time would make the nominal case
    // the degraded one.
    drain_then_close(&connection, &mut send, "negotiation committed").await;
    drop(permit);
    Ok(())
}

/// Finishes a stream, waits for the peer to have taken it, then hangs up.
///
/// Failures are logged and swallowed: this runs after the point of no return,
/// where there is nothing left to undo and nothing useful to return.
async fn drain_then_close(connection: &Connection, send: &mut SendStream, reason: &'static str) {
    if let Err(error) = send.finish() {
        tracing::debug!(%error, "stream already closed by the peer");
    }
    match tokio::time::timeout(COMMIT_DELIVERY_TIMEOUT, send.stopped()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::debug!(%error, "peer reset the stream before acknowledging it"),
        Err(_) => tracing::warn!(
            timeout_s = COMMIT_DELIVERY_TIMEOUT.as_secs(),
            "peer never acknowledged the final frame"
        ),
    }
    connection.close(0u32.into(), reason.as_bytes());
}

/// Checks a presented challenge against the one this connection issued, and
/// spends it.
///
/// `Option::take` is the atomic consumption the specification asks for: the
/// value is owned by one task, so a second request carrying the same
/// challenge finds `None`. No lock is involved because there is nothing to
/// share.
///
/// Every failure is [`PublicError::Rejected`] — absent, expired, mismatched
/// and already-spent are indistinguishable on the wire, and the caller
/// journals which one it was.
fn consume_challenge(
    issued: &mut Option<[u8; SERVER_CHALLENGE_LEN]>,
    deadline: Instant,
    presented: [u8; SERVER_CHALLENGE_LEN],
) -> Result<(), PublicError> {
    let Some(expected) = issued.take() else {
        tracing::warn!("key negotiation: request without a live challenge on this connection");
        return Err(PublicError::Rejected);
    };
    if Instant::now() > deadline {
        tracing::warn!("key negotiation: challenge expired before it was used");
        return Err(PublicError::Rejected);
    }
    if expected != presented {
        tracing::warn!("key negotiation: request carries a challenge this connection never issued");
        return Err(PublicError::Rejected);
    }
    Ok(())
}

fn random_challenge() -> Result<[u8; SERVER_CHALLENGE_LEN], TransportError> {
    use aws_lc_rs::rand::SecureRandom as _;
    let mut challenge = [0u8; SERVER_CHALLENGE_LEN];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| TransportError::Protocol("system RNG failed to produce a challenge".into()))?;
    Ok(challenge)
}

/// Active client session. Confirmation consumes it to prevent duplicate commit.
pub struct ClientSession {
    _endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    transaction_id: [u8; 16],
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
}

impl ClientSession {
    /// Sends the confirmation and reads the commit, then **hangs up**.
    ///
    /// v4 handed the connection back as a liveness link. v5 does not: the
    /// transaction is the whole purpose of the connection, and keeping it
    /// open tied the life of a tunnel to the life of a control connection on
    /// a WAN path. Any network blip longer than 35 seconds killed a healthy
    /// tunnel.
    pub async fn confirm(
        mut self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, TransportError> {
        if confirmation.confirmation.protocol_version != KEY_NEGOTIATION_VERSION
            || confirmation.confirmation.transaction_id != self.transaction_id
            || confirmation.confirmation.server_challenge != self.server_challenge
        {
            return Err(TransportError::Protocol(
                "client confirmation does not match the active transaction".into(),
            ));
        }
        write_frame(
            &mut self.send,
            &ClientMessage::Confirmation { confirmation },
        )
        .await?;
        self.send.finish().map_err(TransportError::ClosedStream)?;
        let committed = tokio::time::timeout(
            Duration::from_secs(5),
            read_frame::<ServerMessage>(&mut self.recv),
        )
        .await
        .map_err(|_| TransportError::CommitTimeout)??;
        let commit = match committed {
            ServerMessage::Committed { commit }
                if commit.transaction_id == self.transaction_id
                    && commit.server_challenge == self.server_challenge =>
            {
                commit
            }
            ServerMessage::Error { error } => return Err(TransportError::Rejected(error)),
            _ => {
                return Err(TransportError::Protocol(
                    "server returned an invalid commit acknowledgment".into(),
                ))
            }
        };
        self.connection.close(0u32.into(), b"negotiation committed");
        Ok(commit)
    }
}

/// Opens a connection, takes a challenge, and returns it with the streams.
///
/// One entry point now: the port carries a negotiation and nothing else. It
/// used to be shared with the `release`, which authenticated the same way
/// before that command moved into the WireGuard tunnel (spec §7.5).
async fn open_with_challenge(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
) -> Result<(Connection, SendStream, RecvStream, KeyNegotiationChallenge), TransportError> {
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
    write_frame(
        &mut send,
        &ClientMessage::ChallengeRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
        },
    )
    .await?;
    let challenge =
        match tokio::time::timeout(CHALLENGE_TIMEOUT, read_frame::<ServerMessage>(&mut recv))
            .await
            .map_err(|_| TransportError::ResponseTimeout(CHALLENGE_TIMEOUT.as_secs()))??
        {
            ServerMessage::Challenge { challenge } => challenge,
            ServerMessage::Error { error } => return Err(TransportError::Rejected(error)),
            _ => {
                return Err(TransportError::Protocol(
                    "gateway answered a challenge request with something else".into(),
                ))
            }
        };
    Ok((connection, send, recv, challenge))
}

/// Asks the gateway for a challenge and checks the identity it announces.
///
/// The check happens here, before any signature is produced: reaching the
/// wrong gateway and reaching a substituted one look identical from the
/// client, and both are cheaper to detect now than after an ML-DSA-87
/// operation.
pub async fn request_challenge(
    endpoint: &Endpoint,
    remote: SocketAddr,
    server_name: &str,
    expected_gateway_wg_public_key: &str,
) -> Result<PendingChallenge, TransportError> {
    let (connection, send, recv, challenge) =
        open_with_challenge(endpoint, remote, server_name).await?;
    challenge
        .validate_against(expected_gateway_wg_public_key, server_name)
        .map_err(|error| {
            tracing::warn!(
                %remote,
                announced_wg_public_key = %challenge.gateway_wg_public_key,
                announced_server_name = %challenge.server_name,
                expected_wg_public_key = %expected_gateway_wg_public_key,
                expected_server_name = %server_name,
                "quic: the gateway announces an identity the profile does not pin"
            );
            TransportError::Protocol(error.to_string())
        })?;
    Ok(PendingChallenge {
        connection,
        send,
        recv,
        challenge,
    })
}

/// A challenge in hand, on a connection ready to carry one transaction.
pub struct PendingChallenge {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    challenge: KeyNegotiationChallenge,
}

impl PendingChallenge {
    pub fn server_challenge(&self) -> [u8; SERVER_CHALLENGE_LEN] {
        self.challenge.server_challenge
    }
}

/// Sends the signed request on the connection that issued its challenge.
///
/// The challenge and the connection are inseparable: a request is only valid
/// on the connection whose challenge it carries, so this consumes the
/// [`PendingChallenge`] rather than taking an endpoint.
pub async fn negotiate(
    endpoint: &Endpoint,
    pending: PendingChallenge,
    request: &AuthenticatedKeyNegotiationRequest,
) -> Result<(AuthenticatedKeyNegotiationResponse, ClientSession), TransportError> {
    request
        .request
        .validate()
        .map_err(|error| TransportError::Protocol(error.to_string()))?;
    if request.request.server_challenge != pending.challenge.server_challenge {
        return Err(TransportError::Protocol(
            "request does not carry the challenge issued on this connection".into(),
        ));
    }
    let PendingChallenge {
        connection,
        mut send,
        mut recv,
        challenge,
    } = pending;

    write_frame(
        &mut send,
        &ClientMessage::Request {
            request: Box::new(request.clone()),
        },
    )
    .await?;
    // Bounded. QUIC only gives up on its own when *nothing* arrives; a gateway
    // whose service answers at the transport level and then says nothing —
    // because it is holding a stale transaction for this peer, say — leaves
    // the client waiting for good. That wait has no visible end: the
    // interface is up, the UI announces «connexion…», and nothing ever
    // contradicts it.
    let answer = match tokio::time::timeout(
        RESPONSE_TIMEOUT,
        read_frame::<ServerMessage>(&mut recv),
    )
    .await
    {
        Err(_) => {
            tracing::warn!(
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
                server_challenge: challenge.server_challenge,
            },
        )),
        ServerMessage::Error { error } => Err(TransportError::Rejected(error)),
        _ => Err(TransportError::Protocol(
            "server answered a negotiation request out of order".into(),
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
        authenticate_response, generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate,
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
    const TEST_SERVER_NAME: &str = "gateway.test";
    const TEST_CHALLENGE: [u8; SERVER_CHALLENGE_LEN] = [5; SERVER_CHALLENGE_LEN];
    const GATEWAY_CERT_FINGERPRINT: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// The cheapest request a v5 decoder accepts.
    ///
    /// Was a `classic` request until that mode stopped being negotiable.
    /// `static_psk` costs one HMAC to build, where `ml_kem` costs a keypair.
    fn simple_request(transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN]) -> KeyNegotiationRequest {
        let mut request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: TEST_CHALLENGE,
            transaction_id,
            mode: ProtectionMode::StaticPsk,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: TEST_SERVER_NAME.into(),
            gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
            client_nonce: [2; KEY_NEGOTIATION_NONCE_LEN],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_commitment: None,
        };
        let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        request.static_psk_commitment = Some(commitment(&psk, &request));
        request
    }

    /// Address validation proves an address is real, not that it is
    /// friendly. This bound is what keeps a validated attacker's CPU cost
    /// linear in the number of addresses it actually holds.
    #[test]
    fn a_single_source_cannot_buy_unlimited_handshakes() {
        let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
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

    /// Counting IPv6 per exact address is the same as not counting it.
    ///
    /// A subscriber is routinely handed a `/64`, which is 2^64 addresses: an
    /// attacker with one of those can spend a fresh source for every single
    /// handshake and never meet the budget. Bucketing by prefix is what makes
    /// the IPv6 limit mean anything at all.
    #[test]
    fn an_ipv6_attacker_cannot_walk_out_of_its_own_budget() {
        let mut limiter = RateLimiter::new(MAX_HANDSHAKES_PER_SOURCE);
        let start = Instant::now();

        // Every attempt from a different address inside one /64.
        for attempt in 0..=MAX_HANDSHAKES_PER_SOURCE {
            let source: std::net::IpAddr =
                format!("2001:db8:1:1::{:x}", attempt + 1).parse().unwrap();
            let admitted = limiter.admit(rate_bucket(source), start);
            if attempt == MAX_HANDSHAKES_PER_SOURCE {
                assert!(!admitted, "the whole /64 shares one budget");
            } else {
                assert!(admitted, "attempt {attempt} is within the budget");
            }
        }

        // A neighbouring /64 is a different subscriber and keeps its own.
        let neighbour: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        assert!(limiter.admit(rate_bucket(neighbour), start));
    }

    /// The concurrency permit is held for the whole connection, so a
    /// connection that never ends is a permit that never returns.
    #[test]
    fn the_absolute_lifetime_covers_every_phase_it_must_contain() {
        // A challenge round trip, then a preparation, then the longest
        // confirmation wait a client may be told to observe.
        let phases = CHALLENGE_TIMEOUT
            + RESPONSE_TIMEOUT
            + Duration::from_secs(aether::key_negotiation::MAX_CONFIRMATION_TIMEOUT_SECS as u64);
        assert!(
            MAX_CONNECTION_LIFETIME >= phases,
            "an honest negotiation must never be cut short by the ceiling meant for hostile ones"
        );
        assert!(
            MAX_CONNECTION_LIFETIME > TRANSACTION_IDLE_TIMEOUT,
            "the ceiling exists because the idle timeout cannot bound a busy connection"
        );
    }

    #[test]
    fn all_modes_prepare_exactly_one_wireguard_slot_state() {
        let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);

        let base = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: TEST_CHALLENGE,
            transaction_id: [1; 16],
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_WG_KEY.into(),
            gateway_wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: TEST_SERVER_NAME.into(),
            gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
            client_nonce: [2; 16],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_commitment: None,
        };
        // Every other mode prepares a slot. `classic` prepares nothing,
        // because it no longer exists as a negotiation outcome: a tunnel with
        // no preshared key is a plain WireGuard profile.
        //
        // `Protocol`, not `Rejected`: this is a decoding refusal, and it says
        // nothing about the peer. That the mode is retired is public
        // knowledge, unlike a peer's floor or its admission status.
        assert!(matches!(
            prepare_key_material(
                &base,
                GATEWAY_WG_KEY,
                [3; 16],
                Some(&static_psk),
                DEFAULT_CONFIRMATION_TIMEOUT,
            ),
            Err(PublicError::Protocol)
        ));

        let mut static_request = base.clone();
        static_request.mode = ProtectionMode::StaticPsk;
        static_request.static_psk_commitment = Some(commitment(&static_psk, &static_request));
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
        let mut kem_request = base;
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

    /// Recomputes an engagement exactly as the gateway will.
    fn commitment(psk: &str, request: &KeyNegotiationRequest) -> String {
        static_psk_commitment(
            psk,
            &request.transaction_id,
            &request.client_nonce,
            &request.server_challenge,
            &request.client_wg_public_key,
            GATEWAY_WG_KEY,
        )
        .unwrap()
    }

    /// L'engagement prouve la possession **pour cette transaction** : celui
    /// d'un autre PSK ne passe pas, et rien dans le refus ne dit lequel des
    /// deux cas — pas de PSK configuré, ou mauvais PSK — s'est produit.
    #[test]
    fn static_mode_rejects_another_psk_commitment() {
        let configured = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let other = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let mut request = simple_request([1; 16]);
        request.mode = ProtectionMode::StaticPsk;
        request.static_psk_commitment = Some(commitment(&other, &request));
        assert!(matches!(
            prepare_key_material(
                &request,
                GATEWAY_WG_KEY,
                [3; 16],
                Some(&configured),
                DEFAULT_CONFIRMATION_TIMEOUT
            ),
            Err(PublicError::Rejected)
        ));

        // Le bon PSK, lui, passe — sinon le test ci-dessus ne prouverait rien.
        request.static_psk_commitment = Some(commitment(&configured, &request));
        assert!(prepare_key_material(
            &request,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&configured),
            DEFAULT_CONFIRMATION_TIMEOUT
        )
        .is_ok());
    }

    /// Deux transactions, le **même** PSK : deux engagements différents. C'est
    /// ce qui remplace l'empreinte stable de la v4, corrélable d'une session à
    /// l'autre par un simple observateur du port public.
    #[test]
    fn the_same_static_psk_commits_differently_each_transaction() {
        let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let first = simple_request([1; 16]);
        let mut second = simple_request([2; 16]);
        second.server_challenge = [6; SERVER_CHALLENGE_LEN];
        assert_ne!(commitment(&psk, &first), commitment(&psk, &second));
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
        let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [9; 16],
                subject: subject.into(),
                issuer: subject.into(),
                role,
                wireguard_public_key: wireguard_public_key.into(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
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
        reject_prepare: AtomicBool,
        confirmed: AtomicBool,
        rolled_back: AtomicBool,
        /// How many rollbacks actually ran to completion.
        rollbacks: std::sync::atomic::AtomicUsize,
        /// Held open by default; a test can close it to park a rollback on an
        /// `await` and then destroy the task sitting there.
        rollback_gate: tokio::sync::Semaphore,
        gateway_pq_certificate: PqCertificate,
        gateway_pq_private_key: Vec<u8>,
    }

    impl Handler {
        fn new(pki: &TestPki) -> Self {
            Self::with_rollback_permits(pki, tokio::sync::Semaphore::MAX_PERMITS)
        }

        /// A handler whose `rollback` blocks until the test lets it through.
        fn with_blocked_rollback(pki: &TestPki) -> Self {
            Self::with_rollback_permits(pki, 0)
        }

        fn with_rollback_permits(pki: &TestPki, permits: usize) -> Self {
            Self {
                expected_fingerprint: pki.client_fingerprint.clone(),
                reject_prepare: AtomicBool::new(false),
                confirmed: AtomicBool::new(false),
                rolled_back: AtomicBool::new(false),
                rollbacks: std::sync::atomic::AtomicUsize::new(0),
                rollback_gate: tokio::sync::Semaphore::new(permits),
                gateway_pq_certificate: pki.gateway_pq_certificate.clone(),
                gateway_pq_private_key: pki.gateway_pq_private_key.clone(),
            }
        }
    }

    #[async_trait]
    impl NegotiationHandler for Handler {
        fn announced_identity(&self) -> GatewayIdentity {
            GatewayIdentity {
                wg_public_key: GATEWAY_WG_KEY.into(),
                server_name: "localhost".into(),
            }
        }

        async fn prepare(
            &self,
            certificate_sha256: String,
            request: AuthenticatedKeyNegotiationRequest,
        ) -> Result<PreparedNegotiation, PublicError> {
            // A wrong TLS fingerprint is `Rejected` like every other
            // pre-installation refusal: the public boundary must not let a
            // caller tell an unknown peer from a mismatched certificate.
            if certificate_sha256 != self.expected_fingerprint {
                return Err(PublicError::Rejected);
            }
            if self.reject_prepare.load(Ordering::SeqCst) {
                return Err(PublicError::Rejected);
            }
            Ok(PreparedNegotiation {
                response: authenticate_response(
                    KeyNegotiationResponse {
                        protocol_version: KEY_NEGOTIATION_VERSION,
                        transaction_id: request.request.transaction_id,
                        server_challenge: request.request.server_challenge,
                        selected_mode: request.request.mode,
                        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
                        client_wg_public_key: request.request.client_wg_public_key.clone(),
                        gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
                        kem_ciphertext: None,
                        confirmation_timeout_secs: 2,
                        psk_lifetime_secs: match request.request.mode {
                            ProtectionMode::StaticPsk => 0,
                            _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
                        },
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
                confirmation.confirmation.server_challenge,
                confirmation.confirmation.transaction_id,
                &self.gateway_pq_private_key,
            )
            .map_err(|_| PublicError::Internal)
        }

        async fn resolve_admitted_peer(&self, certificate_sha256: &str) -> Option<String> {
            (certificate_sha256 == self.expected_fingerprint).then(|| CLIENT_WG_KEY.to_string())
        }

        async fn rollback(&self, _transaction_id: [u8; 16], _public_key: &str) {
            // The suspension point a real rollback has — it writes to the
            // data plane — and the one a cancelled task can be destroyed in.
            let _permit = self.rollback_gate.acquire().await;
            self.rolled_back.store(true, Ordering::SeqCst);
            self.rollbacks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The rollback survives the destruction of the task that owned it.
    ///
    /// This is what the absolute-lifetime timeout does to a connection still
    /// waiting for its confirmation: it drops the future, and dropping a
    /// future runs none of the exit paths. Before the guard existed that left
    /// the candidate PSK posed and the peer reserved, with nothing left able
    /// to resolve either — one unfinished connection locked an admitted peer
    /// out until the daemon restarted.
    #[tokio::test]
    async fn a_destroyed_connection_still_rolls_its_candidate_back() {
        let pki = test_pki();
        let handler = Arc::new(Handler::new(&pki));
        drop(RollbackGuard::arm(
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
            [3; 16],
            CLIENT_WG_KEY.into(),
        ));

        // `Drop` cannot await, so it spawns; yielding is what lets that run.
        tokio::task::yield_now().await;

        assert!(
            handler.rolled_back.load(Ordering::SeqCst),
            "a candidate must be undone even when nothing returns from the connection"
        );
    }

    #[tokio::test]
    async fn a_disarmed_guard_never_undoes_a_signed_commit() {
        let pki = test_pki();
        let handler = Arc::new(Handler::new(&pki));
        let mut guard = RollbackGuard::arm(
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
            [3; 16],
            CLIENT_WG_KEY.into(),
        );
        guard.disarm();
        drop(guard);

        tokio::task::yield_now().await;

        assert!(
            !handler.rolled_back.load(Ordering::SeqCst),
            "past the point of no return there is nothing to undo, and undoing it would hand a \
             client a valid commit against a gateway that had restored the previous state"
        );
    }

    /// A rollback destroyed **inside its own await** must be run again.
    ///
    /// The guard used to clear `armed` before awaiting the rollback, which
    /// reintroduced the hole it exists to close: the ceiling fires while the
    /// rollback is writing to the data plane, the task is destroyed, and
    /// `Drop` finds a guard that has already declared itself finished. The
    /// candidate stays posed and the peer stays reserved — and on the gateway
    /// side that window is real, because undoing removes the transaction
    /// record *before* it awaits the restore.
    #[tokio::test]
    async fn a_rollback_destroyed_inside_its_own_await_is_run_again() {
        let pki = test_pki();
        let handler = Arc::new(Handler::with_blocked_rollback(&pki));

        let task = tokio::spawn({
            let handler = Arc::clone(&handler) as Arc<dyn NegotiationHandler>;
            async move {
                let mut guard = RollbackGuard::arm(handler, [4; 16], CLIENT_WG_KEY.into());
                guard.roll_back().await;
            }
        });
        // Let it reach the suspension point inside `rollback`, then destroy
        // it there — which is exactly what the absolute ceiling does.
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert_eq!(
            handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the first attempt must not have completed, or this proves nothing"
        );

        handler.rollback_gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            while handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a rollback destroyed part-way through must be retried by the guard");
    }

    /// No phase may outlive the connection that carries it.
    ///
    /// The 45-second confirmation wait is the one that would: a client that
    /// dawdles before requesting leaves less than 45 seconds of budget, and
    /// the ceiling would then fire during the wait — destroying the task
    /// instead of timing the phase out. Clamping keeps the exit on an
    /// ordinary code path.
    #[test]
    fn a_phase_is_clamped_to_what_is_left_of_the_connection() {
        let nearly_over = Deadline(Instant::now() + Duration::from_secs(2));
        assert!(
            nearly_over.clamp(Duration::from_secs(45)) <= Duration::from_secs(2),
            "the confirmation wait must not outlast the connection's ceiling"
        );

        let over = Deadline(Instant::now() - Duration::from_secs(1));
        assert_eq!(
            over.clamp(Duration::from_secs(45)),
            Duration::ZERO,
            "past the ceiling every phase expires at once, rather than saturating backwards"
        );
    }

    /// Monte le service et rend l'endpoint client, pour ne pas répéter huit
    /// lignes de PKI dans chaque test.
    fn bench(
        pki: &TestPki,
    ) -> (
        Arc<Handler>,
        tokio::task::JoinHandle<()>,
        Endpoint,
        SocketAddr,
    ) {
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.server,
            pki.ca_der.clone(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handler = Arc::new(Handler::new(pki));
        let task = tokio::spawn(serve(
            server,
            Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        ));
        let client = client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &pki.client,
            pki.ca_der.clone(),
        )
        .unwrap();
        (handler, task, client, server_addr)
    }

    /// The nominal v5 sequence is challenge, request, response, confirmation,
    /// commit, then **closure**. The connection does not outlive the
    /// transaction, and closing it does not remove any PSK.
    #[tokio::test]
    async fn a_negotiation_ends_with_a_commit_and_a_closed_connection() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let challenge = pending.server_challenge();
        assert_ne!(
            challenge, [0u8; SERVER_CHALLENGE_LEN],
            "un challenge nul ne prouverait rien"
        );

        let mut request = simple_request([1; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = challenge;
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request.clone(),
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (response, session) = negotiate(&client, pending, &authenticated_request)
            .await
            .unwrap();
        response
            .response
            .validate_for(&request, GATEWAY_WG_KEY)
            .unwrap();

        let confirmation = authenticate_confirmation(
            challenge,
            request.transaction_id,
            &pki.client_pq_private_key,
        )
        .unwrap();
        let commit = session.confirm(confirmation).await.unwrap();
        commit
            .verify(&pki.gateway_pq_certificate.ml_dsa_87_public_key)
            .unwrap();
        assert_eq!(commit.server_challenge, challenge);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler.confirmed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        // The key v5 property: the connection is over, and that says nothing
        // about the tunnel. In v4 the same closure released the slot; here it
        // must not trigger rollback, and this port can no longer remove a PSK.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !handler.rolled_back.load(Ordering::SeqCst),
            "closing the connection after commit must not undo anything"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// A terminal refusal must arrive as the public protocol error, not as a
    /// transport reset. Dropping the send stream immediately after writing
    /// this frame made Quinn discard it and Orion reported `connection lost`.
    #[tokio::test]
    async fn a_prepare_refusal_is_delivered_before_the_connection_closes() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);
        handler.reject_prepare.store(true, Ordering::SeqCst);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([9; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = pending.server_challenge();
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();

        match negotiate(&client, pending, &authenticated_request).await {
            Err(TransportError::Rejected(PublicError::Rejected)) => {}
            Err(error) => {
                panic!("the framed refusal must survive graceful connection teardown: {error}")
            }
            Ok(_) => panic!("a handler refusal must not produce a negotiated session"),
        }

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Le challenge est à usage unique : le rejouer sur une seconde connexion
    /// échoue, ce qui est exactement la propriété que la v4 n'avait pas.
    #[tokio::test]
    async fn a_challenge_cannot_be_replayed_on_another_connection() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let stolen = pending.server_challenge();
        drop(pending);

        // Nouvelle connexion, donc nouveau challenge — mais on présente
        // l'ancien, entièrement signé.
        let second = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([7; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = stolen;
        request.server_name = "localhost".into();
        let replayed = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let outcome = negotiate(&client, second, &replayed).await.err();
        assert!(
            matches!(outcome, Some(TransportError::Protocol(_))),
            "une requête portant le challenge d'une autre connexion doit être refusée : {outcome:?}"
        );
        assert!(!handler.confirmed.load(Ordering::SeqCst));

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Le client refuse une gateway qui annonce une autre identité, avant
    /// d'avoir produit la moindre signature.
    #[tokio::test]
    async fn a_gateway_announcing_another_identity_is_refused_before_signing() {
        let pki = test_pki();
        let (_handler, task, client, server_addr) = bench(&pki);

        let outcome = request_challenge(&client, server_addr, "localhost", CLIENT_WG_KEY)
            .await
            .err();
        assert!(
            matches!(outcome, Some(TransportError::Protocol(_))),
            "l'identité annoncée doit être comparée au profil : {outcome:?}"
        );

        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// `release` has left this port: the legacy tag no longer decodes.
    ///
    /// Merely not sending it is insufficient. An outdated Orion and a migrated
    /// gateway must fail explicitly rather than silently. Rejection happens in
    /// the parser, before any handler, without revealing slot state.
    #[tokio::test]
    async fn the_legacy_quic_release_message_is_refused_as_a_protocol_error() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let PendingChallenge {
            connection,
            mut send,
            mut recv,
            challenge,
        } = pending;

        // The message exactly as v5 carried it before August 8, 2026.
        let legacy = serde_json::json!({
            "type": "release",
            "release": {
                "release": {
                    "protocol_version": KEY_NEGOTIATION_VERSION,
                    "server_challenge": challenge.server_challenge,
                    "installed_transaction_id": vec![4u8; KEY_NEGOTIATION_NONCE_LEN],
                    "client_wg_public_key": CLIENT_WG_KEY,
                    "gateway_wg_public_key": GATEWAY_WG_KEY,
                    "timestamp_unix": test_now(),
                },
                "certificate": pki.client_pq_certificate,
                "ml_dsa_87_signature": "",
            },
        });
        write_frame(&mut send, &legacy).await.unwrap();
        let _ = send.finish();

        // The gateway closes without acknowledging anything: `released` no
        // longer exists.
        let answer = tokio::time::timeout(
            Duration::from_secs(2),
            read_frame::<ServerMessage>(&mut recv),
        )
        .await
        .unwrap();
        assert!(
            answer.is_err(),
            "a removed tag must not produce an application response: {answer:?}"
        );
        assert!(!handler.rolled_back.load(Ordering::SeqCst));

        connection.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        task.abort();
    }

    /// Une session abandonnée avant confirmation doit être défaite : c'est le
    /// rollback, qui n'existe que **avant** la signature du commit.
    #[tokio::test]
    async fn closing_an_unconfirmed_session_requests_rollback() {
        let pki = test_pki();
        let (handler, task, client, server_addr) = bench(&pki);

        let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
            .await
            .unwrap();
        let mut request = simple_request([4; KEY_NEGOTIATION_NONCE_LEN]);
        request.server_challenge = pending.server_challenge();
        request.server_name = "localhost".into();
        let authenticated_request = authenticate_request(
            request,
            pki.client_pq_certificate.clone(),
            &pki.client_pq_private_key,
        )
        .unwrap();
        let (_, session) = negotiate(&client, pending, &authenticated_request)
            .await
            .unwrap();
        drop(session);

        tokio::time::timeout(Duration::from_secs(5), async {
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
