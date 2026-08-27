//! End-to-end proof of the private Astra ↔ Helios channel (spec §8.3).
//!
//! Both configurations are built from `helios_api::internal`, and both are
//! exercised against each other over a real loopback socket: a real TLS
//! handshake, a real HTTP request, real refusals. This is the strongest thing
//! that can be shown without a gateway — what it does **not** show is the veth
//! itself, which has no default route and forwards nothing. That is a kernel
//! and container fact; see `docs/testing/TESTING.md`.

use std::net::SocketAddr;
use std::sync::Arc;

use aether::certificates::client::{
    ClientCertificateGeneration, ClientCertificateStageAuthorization,
    GatewayCertificateStageReceipt,
};
use aether::certificates::encoding::{DerCertificate, Fingerprint, WireGuardKey};
use aether::certificates::gateway::pq_certificate_fingerprint;
use aether::certificates::revocation::EmergencyCertificateRevocation;
use aether::certificates::state::ClientCertificateState;
use aether::key_negotiation::{
    generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
    PQ_CERTIFICATE_VERSION,
};
use astra::gateway::GatewayChannel;
use async_trait::async_trait;
use base64::Engine as _;
use helios_api::certificates::{AstraStageHandler, TrustUpdateRefusal};
use helios_api::internal::{
    AstraChannelHandler, ChannelIdentity, GatewayIdentityView, PeerCertificateStateView,
};

/// The leaf this fake gateway serves.
///
/// Signed, because a PQ certificate's fingerprint covers its signature: an
/// unsigned placeholder has no fingerprint at all, and the round trip below
/// checks that the fingerprint the authority recomputes is the one the gateway
/// sent.
fn served_leaf() -> PqCertificate {
    let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [0x31; 16],
            subject: "gateway".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: WireGuardKey::from_bytes([0x11; 32]).to_base64(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(&subject_public),
            not_before_unix: 0,
            not_after_unix: 1_000_000,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .expect("signed leaf")
}

/// A handler that records what it was asked and refuses everything.
///
/// The registry's own decisions are proven by `helios-provisioning` and by
/// `heliosd`; what this file proves is that the request crossed a pinned,
/// mutually authenticated TLS 1.3 link and reached the right method.
struct Recorder {
    seen: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl AstraStageHandler for Recorder {
    async fn stage_from_astra(
        &self,
        authorization: Box<ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("stage {}", authorization.client_wg_public_key));
        Err(TrustUpdateRefusal::Rejected)
    }
}

#[async_trait]
impl AstraChannelHandler for Recorder {
    async fn revoke(
        &self,
        revocation: Box<EmergencyCertificateRevocation>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("revoke {}", revocation.identity_key));
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn distribute(
        &self,
        distribution: Box<helios_api::internal::TrustDistribution>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen.lock().unwrap().push(format!(
            "distribute {}",
            distribution.manifest.client_wg_public_key
        ));
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn commit_recovery(
        &self,
        relayed: Box<helios_api::internal::RelayedStageCommit>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.seen.lock().unwrap().push(format!(
            "commit_recovery {}",
            relayed.commit.client_wg_public_key
        ));
        Err(TrustUpdateRefusal::Rejected)
    }

    async fn gateway_identity(&self) -> Result<GatewayIdentityView, TrustUpdateRefusal> {
        self.seen.lock().unwrap().push("identity".into());
        let pq_certificate = served_leaf();
        Ok(GatewayIdentityView {
            pq_certificate_fingerprint: pq_certificate_fingerprint(&pq_certificate)
                .expect("fingerprint"),
            pq_certificate,
            tls_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
                b"gateway tls in service",
            ),
            active_gateway_identity_epoch: 3,
            gateway_decision_epoch: 7,
        })
    }

    async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, TrustUpdateRefusal> {
        self.seen.lock().unwrap().push(format!("state {identity}"));
        Ok(PeerCertificateStateView {
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
            active_pq_certificate: served_leaf(),
        })
    }
}

/// Astra's transport identity in a disposable state directory.
fn astra_identity(state_dir: &std::path::Path) -> DerCertificate {
    astra::gateway::initialize(state_dir, false).expect("astra transport identity")
}

/// The gateway's, built exactly as `heliosd init-astra-channel` builds it.
fn gateway_identity() -> (ChannelIdentity, DerCertificate) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    let mut params =
        CertificateParams::new(vec![helios_api::internal::INTERNAL_SERVER_NAME.to_string()])
            .expect("params");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    let key_pair = KeyPair::generate().expect("keygen");
    let certificate = params.self_signed(&key_pair).expect("self-signed");
    let der = certificate.der().to_vec();
    (
        ChannelIdentity {
            certificate_der: der.clone(),
            private_key_der: key_pair.serialize_der(),
        },
        DerCertificate::new(der).expect("der"),
    )
}

/// Starts the listener on an ephemeral port and returns where it landed.
async fn listen(
    identity: &ChannelIdentity,
    pinned_astra: &DerCertificate,
    handler: Arc<Recorder>,
) -> SocketAddr {
    let config = helios_api::internal::server_config(identity, pinned_astra).expect("server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let router = helios_api::internal::router(handler);
    tokio::spawn(async move {
        let _ = helios_api::internal::serve(
            address,
            config,
            router,
            helios_api::internal::INTERNAL_PREFIX,
        )
        .await;
    });
    // The listener is spawned; give it the moment it needs to bind before the
    // first dial, rather than racing it and reporting a connection refusal as
    // a pinning failure.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    address
}

fn recorder() -> Arc<Recorder> {
    Arc::new(Recorder {
        seen: std::sync::Mutex::new(Vec::new()),
    })
}

/// The nominal path: Astra dials, the pin holds on both sides, and the request
/// reaches the handler that owns the registry.
#[tokio::test]
async fn a_pinned_astra_reaches_the_lifecycle_and_nothing_else() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let astra_certificate = astra_identity(state_dir.path());
    let (gateway, gateway_certificate) = gateway_identity();
    let handler = recorder();
    let address = listen(&gateway, &astra_certificate, Arc::clone(&handler)).await;

    let channel = GatewayChannel::open(state_dir.path(), address, &gateway_certificate)
        .expect("channel opens");

    let identity = WireGuardKey::from_bytes([3; 32]);
    let view = channel.peer_state(&identity).await.expect("peer state");
    assert_eq!(view.name, "workstation");
    assert_eq!(view.state.active.generation, 4);
    assert_eq!(
        handler.seen.lock().unwrap().as_slice(),
        [format!("state {identity}")]
    );
}

/// An identity the gateway does not pin never reaches a handler: the
/// handshake fails, and it fails before any body is read.
#[tokio::test]
async fn an_unpinned_client_is_refused_at_the_handshake() {
    let pinned_dir = tempfile::tempdir().expect("state dir");
    let impostor_dir = tempfile::tempdir().expect("state dir");
    let pinned = astra_identity(pinned_dir.path());
    let _impostor = astra_identity(impostor_dir.path());
    let (gateway, gateway_certificate) = gateway_identity();
    let handler = recorder();
    let address = listen(&gateway, &pinned, Arc::clone(&handler)).await;

    // Same shape, same usage, same name — a different key, so different bytes.
    let channel = GatewayChannel::open(impostor_dir.path(), address, &gateway_certificate)
        .expect("channel opens: the client cannot know it is not pinned");
    let refusal = channel.peer_state(&WireGuardKey::from_bytes([3; 32])).await;
    assert!(
        refusal.is_err(),
        "an unpinned client identity was served: {refusal:?}"
    );
    assert!(
        handler.seen.lock().unwrap().is_empty(),
        "an unpinned client reached a handler"
    );
}

/// Astra pins the gateway too. A second gateway on the same address — one that
/// holds a valid, well-formed, correctly named certificate — is refused.
#[tokio::test]
async fn an_unpinned_gateway_is_refused_by_astra() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let astra_certificate = astra_identity(state_dir.path());
    let (gateway, _served) = gateway_identity();
    let (_other, other_certificate) = gateway_identity();
    let handler = recorder();
    let address = listen(&gateway, &astra_certificate, Arc::clone(&handler)).await;

    let channel =
        GatewayChannel::open(state_dir.path(), address, &other_certificate).expect("channel opens");
    let refusal = channel.peer_state(&WireGuardKey::from_bytes([3; 32])).await;
    assert!(
        refusal.is_err(),
        "Astra accepted a gateway it does not pin: {refusal:?}"
    );
}

/// A TLS 1.2 client is refused. The floor is stated on both sides, and this
/// checks the side that actually terminates the handshake.
#[tokio::test]
async fn a_tls12_client_is_refused() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let astra_certificate = astra_identity(state_dir.path());
    let (gateway, gateway_certificate) = gateway_identity();
    let handler = recorder();
    let address = listen(&gateway, &astra_certificate, Arc::clone(&handler)).await;

    // Everything the real client does, except the version list: TLS 1.2 only.
    let identity = ChannelIdentity {
        certificate_der: std::fs::read(
            state_dir
                .path()
                .join(astra::gateway::CHANNEL_CERTIFICATE_FILE),
        )
        .expect("certificate"),
        private_key_der: std::fs::read(state_dir.path().join(astra::gateway::CHANNEL_KEY_FILE))
            .expect("key"),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls 1.2 client")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything(gateway_certificate)))
        .with_client_auth_cert(
            vec![rustls::pki_types::CertificateDer::from(
                identity.certificate_der.clone(),
            )],
            rustls::pki_types::PrivateKeyDer::try_from(identity.private_key_der.clone())
                .expect("key"),
        )
        .expect("client");
    tls.alpn_protocols = vec![helios_api::internal::INTERNAL_ALPN.to_vec()];

    let stream = tokio::net::TcpStream::connect(address).await.expect("tcp");
    let name = rustls::pki_types::ServerName::try_from(helios_api::internal::INTERNAL_SERVER_NAME)
        .expect("name");
    let refusal = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, stream)
        .await;
    assert!(
        refusal.is_err(),
        "the gateway completed a TLS 1.2 handshake on the private channel"
    );
    assert!(handler.seen.lock().unwrap().is_empty());
}

/// The gateway issues no resumption ticket, so nothing can resume — and
/// `psk_ke`, the Diffie-Hellman-less mode, has no ticket to travel on.
///
/// Checked against a client that *does* keep sessions: with the default
/// `ClientConfig`, rustls would offer a ticket the second time. Both handshakes
/// come back full, which is the observable form of "no ticket was ever issued".
#[tokio::test]
async fn no_connection_ever_resumes() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let astra_certificate = astra_identity(state_dir.path());
    let (gateway, gateway_certificate) = gateway_identity();
    let handler = recorder();
    let address = listen(&gateway, &astra_certificate, Arc::clone(&handler)).await;

    let identity = ChannelIdentity {
        certificate_der: std::fs::read(
            state_dir
                .path()
                .join(astra::gateway::CHANNEL_CERTIFICATE_FILE),
        )
        .expect("certificate"),
        private_key_der: std::fs::read(state_dir.path().join(astra::gateway::CHANNEL_KEY_FILE))
            .expect("key"),
    };
    let mut tls =
        helios_api::internal::client_config(&identity, &gateway_certificate).expect("client");
    // Deliberately the opposite of what the shipped client does: this one
    // remembers sessions, so a ticket would be offered if one were granted.
    tls.resumption = rustls::client::Resumption::in_memory_sessions(8);
    let tls = Arc::new(tls);

    for attempt in 1..=2 {
        let stream = tokio::net::TcpStream::connect(address).await.expect("tcp");
        let name =
            rustls::pki_types::ServerName::try_from(helios_api::internal::INTERNAL_SERVER_NAME)
                .expect("name");
        let stream = tokio_rustls::TlsConnector::from(Arc::clone(&tls))
            .connect(name, stream)
            .await
            .expect("handshake");
        let (_, connection) = stream.get_ref();
        assert_eq!(
            connection.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "connection {attempt} resumed: the gateway handed out a ticket"
        );
        assert_eq!(
            connection.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }
}

/// An unreachable gateway is an error on the call, never on the open: the two
/// processes have two lifetimes, and the veth may come up after either.
#[tokio::test]
async fn an_unreachable_gateway_fails_the_call_and_not_the_startup() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let _astra_certificate = astra_identity(state_dir.path());
    let (_gateway, gateway_certificate) = gateway_identity();

    // A port nothing listens on: bound, its address read, then released.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);

    let channel = GatewayChannel::open(state_dir.path(), address, &gateway_certificate)
        .expect("opening the channel performs no network input/output");
    assert!(channel
        .peer_state(&WireGuardKey::from_bytes([3; 32]))
        .await
        .is_err());
}

/// A verifier that accepts the pinned gateway without a version floor.
///
/// It exists so the TLS 1.2 test isolates the **version**: refusing for a
/// pinning reason would prove nothing about the floor.
#[derive(Debug)]
struct AcceptAnything(DerCertificate);

impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_bytes() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
