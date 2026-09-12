use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Endpoint, TokioRuntime};
use rustls::{pki_types::CertificateDer, RootCertStore};

use crate::{identity::TlsIdentity, TransportError, KEY_NEGOTIATION_ALPN};

const RECEIVE_WINDOW: u32 =
    3 * (4 + aether::key_negotiation::MAX_KEY_NEGOTIATION_MESSAGE_BYTES as u32);
const SAFE_UDP_PAYLOAD: u16 = 1200;
pub(crate) const TRANSACTION_IDLE_TIMEOUT: Duration = Duration::from_secs(50);
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const COMMIT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn pinned_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);
    transport.initial_mtu(SAFE_UDP_PAYLOAD);
    transport.min_mtu(SAFE_UDP_PAYLOAD);
    transport.max_idle_timeout(Some(
        TRANSACTION_IDLE_TIMEOUT
            .try_into()
            .expect("the idle timeout fits QUIC's varint"),
    ));
    transport.max_concurrent_uni_streams(0u32.into());
    transport.stream_receive_window(RECEIVE_WINDOW.into());
    transport.receive_window(RECEIVE_WINDOW.into());
    transport
}

pub fn server_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    client_cas: &[Vec<u8>],
) -> Result<Endpoint, TransportError> {
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
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| TransportError::Tls(error.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.certificates(), identity.private_key()?)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    tls.alpn_protocols = vec![KEY_NEGOTIATION_ALPN.to_vec()];
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = pinned_transport();
    transport.max_concurrent_bidi_streams(1u32.into());
    config.transport = Arc::new(transport);
    let endpoint = Endpoint::server(config, bind).map_err(TransportError::Io)?;
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(KEY_NEGOTIATION_ALPN),
        served_certificate_sha256 = %identity.leaf_fingerprint(),
        client_ca_sha256 = %client_cas
            .iter()
            .map(|client_ca| crate::certificate_fingerprint_der(client_ca).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        datagram_bytes = SAFE_UDP_PAYLOAD,
        "quic: key-negotiation server endpoint ready"
    );
    Ok(endpoint)
}

pub fn client_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    gateway_ca: Vec<u8>,
) -> Result<Endpoint, TransportError> {
    let mut endpoint = Endpoint::client(bind).map_err(TransportError::Io)?;
    endpoint.set_default_client_config(client_config(identity, gateway_ca)?);
    Ok(endpoint)
}

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
    tracing::info!(
        client_certificate_sha256 = %identity.leaf_fingerprint(),
        pinned_gateway_ca_sha256 = %crate::certificate_fingerprint_der(&gateway_ca),
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
    tls.resumption = rustls::client::Resumption::disabled();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = pinned_transport();
    transport.max_concurrent_bidi_streams(0u32.into());
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}
