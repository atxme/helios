//! The transport both directions share: channel identities, the pinned
//! verification of the one peer each end accepts, the TLS configurations,
//! the listener, and the pinned HTTP client both clients are built on.

use super::*;

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
    /// The authority refused the step in progress with its own sentence, which
    /// names what has not happened yet (F14 lot 6b). The sentence is the
    /// operator's to read, so it is kept rather than reduced to a status.
    Plan(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(reason) => write!(formatter, "private channel TLS: {reason}"),
            Self::Pin(reason) => write!(formatter, "pinned peer certificate: {reason}"),
            Self::Io(error) => write!(formatter, "private channel input/output: {error}"),
            Self::Status(status) => write!(formatter, "private channel answered {status}"),
            Self::Body(reason) => write!(formatter, "private channel answer: {reason}"),
            Self::Plan(reason) => write!(formatter, "private channel refused the step: {reason}"),
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
pub(super) enum PinnedRole {
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
pub(super) struct PinnedPeer {
    pinned: Vec<u8>,
    role: PinnedRole,
    not_before: u64,
    not_after: u64,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedPeer {
    pub(super) fn new(
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
    pub(super) fn accept(
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
    pub(super) fn refuse_tls12() -> rustls::Error {
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

pub(super) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
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
///
/// `prefix` is the only path space the router serves; it is named in the log so
/// the two directions of the veth are told apart at a glance.
pub async fn serve(
    bind: SocketAddr,
    config: rustls::ServerConfig,
    router: Router,
    prefix: &'static str,
) -> std::io::Result<()> {
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        alpn = %String::from_utf8_lossy(INTERNAL_ALPN),
        "private lifecycle channel listening; it serves only {prefix}*"
    );
    loop {
        let (stream, source) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%source, %error, "private lifecycle channel: handshake refused");
                    return;
                }
            };
            let service = TowerToHyperService::new(router);
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%source, %error, "private lifecycle channel: connection ended");
            }
        });
    }
}

/// One pinned mTLS connection, opened per call, on either direction of the
/// veth.
///
/// Both typed clients are built on this because both carry the same bounds: a
/// bounded response, a `Host` and SNI that match the pinned identity, and a
/// connection driver that outlives the request in flight. A second copy of
/// this plumbing is how one direction quietly stops bounding its answers.
pub(super) struct PinnedHttpClient {
    pub(super) address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    /// SNI and `Host`. Not how the peer is authenticated — the pinned DER is —
    /// but it must match the certificate the peer was built with.
    server_name: &'static str,
}

impl PinnedHttpClient {
    pub(super) fn new(
        address: SocketAddr,
        tls: rustls::ClientConfig,
        server_name: &'static str,
    ) -> Self {
        Self {
            address,
            tls: Arc::new(tls),
            server_name,
        }
    }

    /// `bearer` carries a capability token when the route requires one. It is
    /// set on the header and nowhere else: never a query parameter, never a
    /// path segment, never a log line (spec §8.2).
    pub(super) async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
    ) -> Result<Bytes, ChannelError> {
        self.request_bounded(method, path, body, bearer, MAX_INTERNAL_BODY_BYTES)
            .await
    }

    /// The same call under a caller-chosen answer ceiling.
    ///
    /// The operator surface needs the 128 KiB ceiling of §8.5, including for a
    /// large campaign description and its encrypted vault. The limit is still
    /// applied before the answer is read into memory, so an authority that has
    /// been taken over cannot make this process allocate without end.
    pub(super) async fn request_bounded(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
        max_answer_bytes: usize,
    ) -> Result<Bytes, ChannelError> {
        let (status, answer) = self
            .exchange(method, path, body, bearer, max_answer_bytes)
            .await?;
        if !status.is_success() {
            return Err(ChannelError::Status(status));
        }
        Ok(answer)
    }

    /// One request, and the status and the bounded body it answered with,
    /// whatever the status. For the routes whose refusal carries a sentence.
    pub(super) async fn exchange(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
        max_answer_bytes: usize,
    ) -> Result<(StatusCode, Bytes), ChannelError> {
        use http_body_util::BodyExt as _;
        use hyper_util::rt::TokioIo;

        let stream = tokio::net::TcpStream::connect(self.address).await?;
        let name = ServerName::try_from(self.server_name)
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

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, self.server_name)
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = builder
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
        let collected = http_body_util::Limited::new(response.into_body(), max_answer_bytes)
            .collect()
            .await
            .map_err(|error| ChannelError::Body(error.to_string()))?
            .to_bytes();
        drop(sender);
        driver.abort();
        Ok((status, collected))
    }
}

/// Percent-encodes one path segment.
///
/// Written here rather than pulled in: a WireGuard key is base64, so the only
/// characters that ever need escaping are `+`, `/` and `=`, and a dependency
/// for three replacements would be supply-chain cost for nothing.
pub(super) fn percent_encode_segment(value: &str) -> String {
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
