use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{Endpoint, TokioRuntime};
use rustls::{pki_types::CertificateDer, RootCertStore};

use crate::{error::TransportError, identity::TlsIdentity, KEY_NEGOTIATION_ALPN};

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
pub(crate) fn pinned_transport() -> quinn::TransportConfig {
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
const RECEIVE_WINDOW: u32 =
    3 * (4 + aether::key_negotiation::MAX_KEY_NEGOTIATION_MESSAGE_BYTES as u32);

/// Datagram size every QUIC path must carry (RFC 9000 §14).
///
/// It holds on IPv6 as well: with the 40-byte IPv6 header and the 8-byte UDP
/// header a datagram is 1 248 bytes on the wire, under the 1 280 every IPv6
/// link must carry (RFC 8200 §5) — so the dual-stack listener needs no second
/// value.
const SAFE_UDP_PAYLOAD: u16 = 1200;

/// IPv6 header (40) + UDP header (8) + the pinned payload, against the IPv6
/// minimum link MTU: checked at compile time so the value cannot drift past it.
const _: () = assert!(40 + 8 + SAFE_UDP_PAYLOAD as usize <= 1280);

/// Silence after which a **transaction** connection is abandoned.
///
/// This is not a liveness mechanism, and nothing about the tunnel depends on
/// it: since v5 the connection is closed as soon as the commit is delivered,
/// and a PSK is never released because a connection went away.
///
/// It exists for one reason. Between the response and the confirmation the
/// client is waiting on a WireGuard handshake and neither end sends anything
/// — up to [`crate::DEFAULT_CONFIRMATION_TIMEOUT`]. QUIC's own default of thirty
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
pub(crate) const TRANSACTION_IDLE_TIMEOUT: Duration = Duration::from_secs(50);

/// Time allowed for the QUIC handshake with the negotiation service.
///
/// Generous for a mutual-TLS handshake on a residential link, and short
/// enough that an unreachable port is reported rather than waited on: this is
/// the very first thing a client does, and the port is not the WireGuard one
/// — forgetting to forward it is the ordinary mistake.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for a peer to take the last frame before the connection goes.
pub(crate) const COMMIT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Time allowed for the gateway's challenge.
///
/// It costs the gateway one RNG read and no signature, so anything slower
/// than this is a path problem rather than a load problem.
pub(crate) const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Time allowed for the gateway's negotiation answer.
///
/// It covers an ML-KEM-1024 encapsulation, an ML-DSA-65 signature and, above
/// all, installing the PSK on the data plane — which the gateway does
/// **before** answering. Fifteen seconds leaves room for a loaded machine
/// without ever looking like a hang.
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Builds the endpoint the key-negotiation port serves.
///
/// `client_cas` is a **set**, and it mirrors the PQ half of the very same
/// handshake: the operator admission CA issues first-generation leaves, a
/// renewed leaf chains to the domain's own `CA-TLS` through Astra's delegated
/// intermediate, and during a §9.4 overlap the successor anchor is legitimate
/// too. A verifier holding one of them alone refuses leaves the registry
/// itself considers presentable — a lockout, not a refusal.
///
/// # Known limitation: the set is fixed for the life of the endpoint
///
/// The caller reads it once, as it already does for the served identity, and
/// for the same reason: rebuilding the endpoint under live PSK slots is not
/// something this crate offers. A client renewal never moves the set — only a
/// §9.4 rotation does, and its overlap lasts a month, so the restart that
/// carries the successor has ample room before the outgoing anchor retires.
pub fn server_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    client_cas: &[Vec<u8>],
) -> Result<Endpoint, TransportError> {
    let config = server_config(identity, client_cas)?;
    let endpoint = Endpoint::server(config, bind).map_err(TransportError::Io)?;
    log_server_ready(bind, identity, client_cas);
    Ok(endpoint)
}

/// Which address families the gateway's negotiation listener serves.
///
/// A transport capability, not a security boundary: every bound on the port —
/// Retry, the per-source and per-identity budgets, the lifetime — applies the
/// same way whichever family a client arrives on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenFamilies {
    /// One `[::]` socket with `IPV6_V6ONLY` off: IPv6 clients natively, IPv4
    /// clients as `::ffff:a.b.c.d`, which the server canonicalizes before
    /// counting or logging them.
    DualStack,
    /// The host cannot open an IPv6 socket at all, so the listener serves
    /// IPv4 alone. `reason` carries the operating system's own answer.
    Ipv4Only { reason: String },
}

impl ListenFamilies {
    /// What a failed attempt at the dual-stack socket means for the listener.
    ///
    /// Only one answer degrades instead of failing: the kernel refusing the
    /// IPv6 address family outright (`EAFNOSUPPORT`, as on a host booted with
    /// `ipv6.disable=1`). Refusing to start there would take IPv4 negotiation
    /// down with it, for a capability the host never had. Every other error —
    /// the port already in use, a permission refused — comes back unchanged
    /// and fails the listener exactly as it did before IPv6.
    ///
    /// Outside Unix nothing degrades: the gateway is a Linux daemon, and no
    /// other platform's error code is mapped here without a host to prove it.
    pub fn after_dual_stack_error(error: std::io::Error) -> Result<Self, std::io::Error> {
        if ipv6_is_unsupported(&error) {
            Ok(Self::Ipv4Only {
                reason: format!("IPv6 sockets are unavailable on this host: {error}"),
            })
        } else {
            Err(error)
        }
    }
}

impl std::fmt::Display for ListenFamilies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DualStack => f.write_str("IPv6 and IPv4 (dual-stack [::])"),
            Self::Ipv4Only { reason } => write!(f, "IPv4 only ({reason})"),
        }
    }
}

#[cfg(unix)]
fn ipv6_is_unsupported(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

#[cfg(not(unix))]
fn ipv6_is_unsupported(_error: &std::io::Error) -> bool {
    false
}

/// Builds the gateway's negotiation endpoint on every family the host offers.
///
/// One socket, not two. A dual-stack `[::]:port` carries IPv6 natively and
/// IPv4 as `::ffff:a.b.c.d`; quinn drives it as any other IPv6 socket, and
/// `quinn-udp` already forbids fragmentation for mapped destinations. Two
/// endpoints would each hold their own connection table and Retry key, and
/// the budgets of [`crate::serve`] would have to be shared across two accept
/// loops by hand — twice the state for no gain.
///
/// `IPV6_V6ONLY` is cleared explicitly rather than inherited: Linux takes the
/// default from `net.ipv6.bindv6only`, and a host where it is `1` would
/// silently stop answering every IPv4 client.
///
/// When the host has no IPv6 at all, the listener falls back to `0.0.0.0` and
/// says so ([`ListenFamilies::after_dual_stack_error`]); the caller gets back
/// which of the two it got, to name it in its own startup line.
pub fn dual_stack_server_endpoint(
    port: u16,
    identity: &TlsIdentity,
    client_cas: &[Vec<u8>],
) -> Result<(Endpoint, ListenFamilies), TransportError> {
    // The configuration first, as `server_endpoint` does: a refused identity
    // or CA set must fail before any socket is bound.
    let config = server_config(identity, client_cas)?;
    let (socket, families) = match dual_stack_socket(port) {
        Ok(socket) => (socket, ListenFamilies::DualStack),
        Err(error) => {
            let families =
                ListenFamilies::after_dual_stack_error(error).map_err(TransportError::Io)?;
            tracing::warn!(
                port,
                %families,
                "quic: the key-negotiation listener cannot open IPv6 and serves IPv4 only"
            );
            let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
                .map_err(TransportError::Io)?;
            (socket, families)
        }
    };
    let bind = socket.local_addr().map_err(TransportError::Io)?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(TransportError::Io)?;
    log_server_ready(bind, identity, client_cas);
    Ok((endpoint, families))
}

/// `[::]:port`, accepting IPv4 clients as mapped addresses.
fn dual_stack_socket(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(socket.into())
}

/// The server half of the transport contract, independent of any socket.
fn server_config(
    identity: &TlsIdentity,
    client_cas: &[Vec<u8>],
) -> Result<quinn::ServerConfig, TransportError> {
    // Fail closed: an empty set would build a verifier no client can satisfy,
    // and rustls would accept the configuration.
    if client_cas.is_empty() {
        return Err(TransportError::InvalidCertificate);
    }
    let mut roots = RootCertStore::empty();
    for client_ca in client_cas {
        roots
            .add(CertificateDer::from(client_ca.clone()))
            .map_err(|_| TransportError::InvalidCertificate)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|error| TransportError::Tls(error.to_string()))?;
    // The workspace intentionally carries both rustls providers: the public
    // QUIC path remains on `ring`, while the private Astra link uses AWS-LC.
    // Never ask rustls to guess a process-wide default from unified Cargo
    // features — a workspace test (or a future binary) can enable both.
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| TransportError::Tls(error.to_string()))?
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
    Ok(config)
}

fn log_server_ready(bind: SocketAddr, identity: &TlsIdentity, client_cas: &[Vec<u8>]) {
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(KEY_NEGOTIATION_ALPN),
        served_certificate_sha256 = %identity.leaf_fingerprint(),
        client_ca_sha256 = %client_cas
            .iter()
            .map(|client_ca| crate::identity::certificate_fingerprint_der(client_ca).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        datagram_bytes = SAFE_UDP_PAYLOAD,
        "quic: key-negotiation server endpoint ready"
    );
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
        Arc::new(TokioRuntime),
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
        pinned_gateway_ca_sha256 = %crate::identity::certificate_fingerprint_der(&gateway_ca),
        alpn = %String::from_utf8_lossy(KEY_NEGOTIATION_ALPN),
        datagram_bytes = SAFE_UDP_PAYLOAD,
        "quic: key-negotiation client credentials loaded"
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(gateway_ca))
        .map_err(|_| TransportError::InvalidCertificate)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| TransportError::Tls(error.to_string()))?
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
