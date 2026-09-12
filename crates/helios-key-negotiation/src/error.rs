use std::net::SocketAddr;

/// Deliberately coarse error sent to an unauthenticated network boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(tag = "code", content = "message", rename_all = "snake_case")]
pub enum PublicError {
    /// Malformed frame, encoding or version — decided before authentication.
    #[error("protocol message is invalid")]
    Protocol,
    /// Any refusal before the slot is installed.
    #[error("request was rejected")]
    Rejected,
    /// Failure at or after slot installation.
    #[error("the gateway could not complete an authenticated request")]
    Internal,
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
