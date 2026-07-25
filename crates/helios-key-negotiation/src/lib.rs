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
pub const KEY_NEGOTIATION_ALPN: &[u8] = b"helios-key-negotiation/2";
/// Confirmation is bounded independently from transport idle time.
pub const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(180);
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
pub fn server_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    client_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
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
    let transport = Arc::get_mut(&mut config.transport)
        .ok_or_else(|| TransportError::Tls("shared transport config".into()))?;
    transport.max_concurrent_bidi_streams(1u32.into());
    Endpoint::server(config, bind).map_err(TransportError::Io)
}

/// Builds a client endpoint with mutual TLS credentials.
pub fn client_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    gateway_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
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
    let mut endpoint = Endpoint::client(bind).map_err(TransportError::Io)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok(endpoint)
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
            if incoming.retry().is_err() {
                tracing::debug!("key-negotiation retry refused for an already-validated peer");
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
            let _permit = permit;
            if let Err(error) = handle_connection(incoming, handler).await {
                tracing::warn!("key-negotiation connection rejected: {error}");
            }
        });
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    handler: Arc<dyn NegotiationHandler>,
) -> Result<(), TransportError> {
    let connection = incoming.await.map_err(TransportError::Connection)?;
    let fingerprint = peer_certificate_sha256(&connection)?;
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
            write_frame(&mut send, &ServerMessage::Error { error }).await?;
            return Ok(());
        }
    };
    write_frame(
        &mut send,
        &ServerMessage::Response {
            response: Box::new(prepared.response),
        },
    )
    .await?;

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
            write_frame(&mut send, &ServerMessage::Committed { commit }).await?;
            send.finish().map_err(TransportError::ClosedStream)?;
            tokio::time::timeout(Duration::from_secs(5), send.stopped())
                .await
                .map_err(|_| TransportError::CommitDeliveryTimeout)?
                .map_err(TransportError::Stopped)?;
        }
        _ => handler.rollback(transaction_id).await,
    }
    Ok(())
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
    ) -> Result<AuthenticatedKeyNegotiationCommit, TransportError> {
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
        let _keep_alive = self.connection;
        Ok(commit)
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
    let connection = endpoint
        .connect(remote, server_name)
        .map_err(TransportError::Connect)?
        .await
        .map_err(TransportError::Connection)?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(TransportError::Connection)?;
    write_frame(&mut send, request).await?;
    match read_frame::<ServerMessage>(&mut recv).await? {
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
    Ok(())
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
        let commit = session.confirm(confirmation).await.unwrap();
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
