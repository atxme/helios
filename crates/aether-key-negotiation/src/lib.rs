//! Authenticated QUIC transport for key negotiation.
//!
//! The crate owns no WireGuard backend and no certificate authority. Callers
//! provide DER identities and a transaction handler. This separation keeps
//! the public parser and TLS boundary independently testable.

mod client;
mod endpoint;
mod error;
mod framing;
mod identity;
mod rate_limit;
mod server;
mod transaction;

#[cfg(test)]
mod tests;

pub use client::{negotiate, request_challenge, ClientSession, PendingChallenge};
pub use endpoint::{
    client_endpoint, client_endpoint_on_socket, dual_stack_server_endpoint, server_endpoint,
    ListenFamilies,
};
pub use error::{PublicError, TransportError};
pub use identity::{certificate_fingerprint_der, TlsIdentity};
pub use server::{
    prepare_key_material, serve, GatewayIdentity, NegotiationHandler, PreparedKeyMaterial,
    PreparedNegotiation,
};

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
pub const DEFAULT_CONFIRMATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

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
pub const CHALLENGE_VALIDITY: std::time::Duration = std::time::Duration::from_secs(45);

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
pub const MAX_CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(90);

/// Window over which [`MAX_HANDSHAKES_PER_SOURCE`] is counted.
///
/// A legitimate client negotiates once per connection, so eight attempts a
/// minute leaves ample room for retries on a lossy link.
pub const SOURCE_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
