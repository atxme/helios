//! The real Orion client against the real gateway handler. The only file
//! that needs the `orion-core` dev-dependency (CRATE-REORGANIZATION §7).

use super::super::*;
use super::fixtures::*;
use aether::TunnelState;
use orion_core::backend::{EventSink, VpnBackend, VpnController};
use orion_core::events::{ClientEvent, PskKind};
use orion_core::ClientProfile;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Notify;

/// TLS material for the interoperability test.
///
/// One CA signs both leaves, exactly as the operator's does: the gateway
/// authenticates the client against it, and Orion pins the server
/// certificate as its trust anchor.
struct TestTls {
    ca_der: Vec<u8>,
    server: aether_key_negotiation::TlsIdentity,
    client_certificate: Vec<u8>,
    client_key: Vec<u8>,
}

fn test_tls() -> TestTls {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_certificate = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_certificate = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    TestTls {
        ca_der: ca.der().to_vec(),
        server: aether_key_negotiation::TlsIdentity {
            certificate_chain: vec![server_certificate.der().to_vec(), ca.der().to_vec()],
            private_key: server_key.serialize_der(),
        },
        client_certificate: client_certificate.der().to_vec(),
        client_key: client_key.serialize_der(),
    }
}

/// Provides the client identity from memory, as the Windows store would.
struct TestIdentities(orion_core::key_negotiation::ClientIdentity);

#[async_trait::async_trait]
impl orion_core::key_negotiation::IdentityProvider for TestIdentities {
    async fn load(
        &self,
        _identity: &str,
    ) -> anyhow::Result<orion_core::key_negotiation::ClientIdentity> {
        Ok(orion_core::key_negotiation::ClientIdentity {
            certificate_chain: self.0.certificate_chain.clone(),
            private_key: self.0.private_key.clone(),
            pq_certificate: self.0.pq_certificate.clone(),
            pq_private_key: self.0.pq_private_key.clone(),
        })
    }
}

/// Records what Orion installs and exposes a fresh handshake only when the
/// test reports that both ends have observed one.
#[derive(Default)]
struct ClientDataPlane {
    mounted: StdMutex<Option<ClientProfile>>,
    polled_stale_handshake: Notify,
    fresh_handshake: AtomicBool,
}

#[async_trait::async_trait]
impl VpnBackend for ClientDataPlane {
    async fn up(&self, profile: &ClientProfile, _sink: &EventSink) -> Result<()> {
        profile.validate_for_data_plane()?;
        *self.mounted.lock().unwrap() = Some(profile.duplicate());
        Ok(())
    }

    async fn down(&self, _sink: &EventSink) -> Result<()> {
        self.mounted.lock().unwrap().take();
        Ok(())
    }

    async fn rekey_peer(&self, _profile: &ClientProfile, _sink: &EventSink) -> Result<()> {
        panic!("initial negotiation must not rekey an existing session")
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        Some(0)
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        if self.fresh_handshake.load(Ordering::SeqCst) {
            return Some(Duration::ZERO);
        }
        self.polled_stale_handshake.notify_one();
        Some(Duration::from_secs(60))
    }

    fn adapter_is_up(&self) -> bool {
        self.mounted.lock().unwrap().is_some()
    }

    fn kind(&self) -> &'static str {
        "interop-test"
    }
}

/// **The interoperability test**: the real gateway handler against the
/// real Orion client, over a real QUIC socket.
///
/// Unit tests on either side cannot show what matters here. The gateway
/// derives the PSK from the shared secret it encapsulated; Orion derives
/// it from the secret it decapsulated. Both call `derive_negotiated_psk`
/// with what they believe the transcript to be — and if those two beliefs
/// diverge by one field, both sides still succeed, install *different*
/// PSKs, and every WireGuard handshake fails afterwards with no error
/// pointing at the cause. Comparing the two values is the only way to
/// know they agree.
/// Both certificate shapes are exercised, because both are legal and the
/// gateway alone decides which it serves: self-signed while it carries no
/// trust domain, issued by `CA-PQ` once it does (ADR-008 §13.1). A client
/// that only ever met the first refuses every gateway an authority exists
/// for, and nothing below the wire would say so.
#[tokio::test]
async fn the_gateway_and_orion_derive_the_same_psk() {
    end_to_end_negotiation(
        GatewayLeaf::SelfSigned,
        ClientFamily::Ipv4,
        Connection::Commit,
    )
    .await;
}

#[tokio::test]
async fn the_gateway_and_orion_derive_the_same_psk_under_a_trust_domain() {
    end_to_end_negotiation(
        GatewayLeaf::IssuedByCaPq,
        ClientFamily::Ipv4,
        Connection::Commit,
    )
    .await;
}

/// The same exchange from an Orion that reaches the gateway over IPv6: an
/// IPv6-only uplink, or a profile naming a `[v6]:port` endpoint. The
/// listener is the one `heliosd` opens, so the IPv4 tests above prove it
/// still answers IPv4 and this one proves it now answers IPv6 too.
#[tokio::test]
async fn the_gateway_and_orion_derive_the_same_psk_over_ipv6() {
    end_to_end_negotiation(
        GatewayLeaf::SelfSigned,
        ClientFamily::Ipv6,
        Connection::Commit,
    )
    .await;
}

#[tokio::test]
async fn orion_preserves_the_wireguard_endpoint_on_a_separate_host() {
    end_to_end_negotiation(
        GatewayLeaf::SelfSigned,
        ClientFamily::Ipv4,
        Connection::SeparateWireGuardHost,
    )
    .await;
}

#[tokio::test]
async fn disconnecting_orion_before_a_fresh_handshake_rolls_back_the_gateway_candidate() {
    end_to_end_negotiation(
        GatewayLeaf::SelfSigned,
        ClientFamily::Ipv4,
        Connection::DisconnectBeforeHandshake,
    )
    .await;
}

/// The address family Orion reaches the dual-stack listener on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientFamily {
    Ipv4,
    Ipv6,
}

impl ClientFamily {
    /// The endpoint string a profile would carry for this family.
    fn endpoint(self, port: u16) -> String {
        match self {
            Self::Ipv4 => format!("127.0.0.1:{port}"),
            Self::Ipv6 => format!("[::1]:{port}"),
        }
    }
}

/// Which authority signs the leaf the gateway serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayLeaf {
    SelfSigned,
    IssuedByCaPq,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Connection {
    Commit,
    SeparateWireGuardHost,
    DisconnectBeforeHandshake,
}

async fn end_to_end_negotiation(leaf: GatewayLeaf, family: ClientFamily, scenario: Connection) {
    use aether::key_negotiation::PqCertificateRole;

    let gateway_wg = aether::wg::generate_keypair().unwrap();
    let client_wg = aether::wg::generate_keypair().unwrap();

    // PQ identities bound to those WireGuard keys, as the operator CA
    // issues them.
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_pq_private, client_pq_public) = generate_ml_dsa_87_keypair().unwrap();
    let client_pq_certificate = certificate(
        "orion",
        PqCertificateRole::Client,
        &client_wg.public_key,
        &client_pq_public,
        ca_private.as_slice(),
    );
    let (gateway_pq_private, gateway_pq_public) = generate_ml_dsa_87_keypair().unwrap();
    let gateway_pq_certificate = match leaf {
        // Issuer **is** subject: the pinned bytes are the whole of the
        // trust, with no anchor above them.
        GatewayLeaf::SelfSigned => self_signed_gateway_certificate(
            "localhost",
            &gateway_wg.public_key,
            &gateway_pq_public,
            gateway_pq_private.as_slice(),
        ),
        GatewayLeaf::IssuedByCaPq => certificate(
            "localhost",
            PqCertificateRole::Gateway,
            &gateway_wg.public_key,
            &gateway_pq_public,
            ca_private.as_slice(),
        ),
    };

    let tls = test_tls();
    let mut network = NetworkConfig::default();
    network.peers.push(aether::WgPeer {
        name: "orion".into(),
        public_key: client_wg.public_key.clone(),
        address: "100.64.1.2/32".into(),
        address_v6: None,
        admin: false,
        preshared_key: None,
        key_negotiation_certificate_sha256: Some(
            aether_key_negotiation::certificate_fingerprint_der(&tls.client_certificate),
        ),
        key_negotiation_pq_certificate_sha256: Some(client_pq_certificate.fingerprint().unwrap()),
        minimum_key_negotiation_mode: Some(ProtectionMode::MlKem),
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });

    // Captures what the gateway actually installs on its data plane, and
    // lets the test say when the peer handshakes.
    let (plane, psk_tx, handshake_tx) = TestDataPlane::spawn();

    let handler = Arc::new(GatewayHandler {
        network: Arc::new(RwLock::new(network)),
        psk_tx,
        handshake_tx,
        gateway_public_key: gateway_wg.public_key.clone(),
        client_pq_ca_public_key: ca_public.clone(),
        registry: None,
        gateway_pq_certificate: gateway_pq_certificate.clone(),
        served_certificate_fingerprint: gateway_pq_certificate.fingerprint().unwrap(),
        gateway_pq_private_key: Zeroizing::new(gateway_pq_private.to_vec()),
        dry_run: true,
        static_psks: RwLock::new(HashMap::new()),
        transactions: Mutex::new(TransactionState::default()),
    });

    // The listener `start` opens, not a loopback-only stand-in.
    let (server, families) = aether_key_negotiation::dual_stack_server_endpoint(
        0,
        &tls.server,
        std::slice::from_ref(&tls.ca_der),
    )
    .unwrap();
    if family == ClientFamily::Ipv6 {
        // Without IPv6 there is nothing to prove, and nothing must pass as if
        // it had been proven: the skip is named on stderr.
        if let ListenFamilies::Ipv4Only { reason } = &families {
            eprintln!("SKIPPED: the listener serves IPv4 only on this host ({reason})");
            return;
        }
        if let Err(error) = std::net::UdpSocket::bind("[::1]:0") {
            eprintln!("SKIPPED: [::1] cannot be bound on this host ({error})");
            return;
        }
    }
    let address = server.local_addr().unwrap();
    let served = tokio::spawn(aether_key_negotiation::serve(server, handler.clone()));

    // From here on, everything runs through the client Orion actually
    // ships — same module, same code path as a real connection.
    let identities = TestIdentities(orion_core::key_negotiation::ClientIdentity {
        certificate_chain: vec![tls.client_certificate.clone()],
        private_key: tls.client_key.clone(),
        pq_certificate: serde_json::to_vec(&client_pq_certificate).unwrap(),
        pq_private_key: client_pq_private.to_vec(),
    });
    let wireguard_endpoint = if scenario == Connection::SeparateWireGuardHost {
        "127.0.0.2:51820".to_string()
    } else {
        family.endpoint(51820)
    };
    let profile = ClientProfile {
        name: "orion".into(),
        endpoint: wireguard_endpoint.clone(),
        private_key: client_wg.private_key.duplicate(),
        peer_public_key: gateway_wg.public_key.clone(),
        address: Some("100.64.1.2/32".into()),
        key_negotiation: Some(orion_core::KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: family.endpoint(address.port()),
            server_name: "localhost".into(),
            gateway_ca_der: base64::engine::general_purpose::STANDARD.encode(&tls.ca_der),
            gateway_pq_certificate: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&gateway_pq_certificate).unwrap()),
            identity: "orion".into(),
            // Only the `CA-PQ` anchor is read on this path; the rest of
            // the block belongs to renewal, which this test does not
            // reach. Filled with well-formed placeholders rather than
            // left out, so the shape stays the one a real profile has.
            trust: match leaf {
                GatewayLeaf::SelfSigned => None,
                GatewayLeaf::IssuedByCaPq => Some(orion_core::TrustMaterial {
                    trust_domain_id: "00112233445566778899aabbccddeeff".into(),
                    ca_epoch: 1,
                    ca_pq_public_key: base64::engine::general_purpose::STANDARD.encode(&ca_public),
                    ca_tls_epoch: 1,
                    client_tls_ca_der: base64::engine::general_purpose::STANDARD
                        .encode(&tls.ca_der),
                    client_generation: 1,
                    astra_authority_url: "https://astra.helios.local".into(),
                    webauthn_rp_id: "astra.helios.local".into(),
                    astra_policy_fingerprint: "11".repeat(32),
                    credential_registry_epoch: 1,
                    astra_credential_bindings: Vec::new(),
                    astra_service_key_epoch: 1,
                    astra_service_public_key: base64::engine::general_purpose::STANDARD
                        .encode(&ca_public),
                    active_gateway_identity_epoch: 1,
                    gateway_decision_epoch: 1,
                }),
            },
        }),
        ..ClientProfile::default()
    };

    let backend = Arc::new(ClientDataPlane::default());
    let controller =
        VpnController::new(backend.clone()).with_key_negotiation_identities(Arc::new(identities));
    let (send_event, mut events) = mpsc::unbounded_channel();
    let sink: EventSink = Arc::new(move |event| {
        let _ = send_event.send(event);
    });
    controller.connect(profile, sink.clone()).await;
    tokio::time::timeout(
        Duration::from_secs(10),
        backend.polled_stale_handshake.notified(),
    )
    .await
    .expect("Orion installs a PSK and polls its WireGuard backend");
    assert_eq!(controller.state(), TunnelState::Connecting);
    assert!(controller.adapter_is_up());
    let transaction_id = {
        let mut state = handler.transactions.lock().await;
        let SlotState::Preparing { transaction_id, .. } = &state.slot(&client_wg.public_key).state
        else {
            panic!("a stale handshake may not commit the candidate");
        };
        *transaction_id
    };

    // The gateway installs before answering: its value is already here.
    let writes = plane.writes().await;
    let [Some(gateway_psk)] = writes.as_slice() else {
        panic!("expected one gateway PSK installation before the response");
    };
    {
        let mounted = backend.mounted.lock().unwrap();
        let mounted = mounted.as_ref().expect("Orion installed a PSK");
        assert_eq!(mounted.endpoint, wireguard_endpoint);
        assert!(mounted.preshared_key_is_negotiated);
        let client_psk = mounted.preshared_key.as_ref().expect("ML-KEM yields a PSK");
        assert!(
            client_psk.expose() == gateway_psk,
            "both ends must derive the same PSK"
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(client_psk.expose())
                .unwrap()
                .len(),
            32
        );
    }

    if scenario == Connection::DisconnectBeforeHandshake {
        controller.disconnect(sink).await.expect("disconnect Orion");
        assert_eq!(controller.state(), TunnelState::Down);
        assert!(!controller.adapter_is_up());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    &handler
                        .transactions
                        .lock()
                        .await
                        .slot(&client_wg.public_key)
                        .state,
                    SlotState::Empty
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dropping the pending QUIC session rolls back the gateway");
        assert!(matches!(plane.writes().await.as_slice(), [Some(_), None]));
        served.abort();
        return;
    }

    // What a real client does between the response and the confirmation:
    // mount the tunnel with the candidate PSK and handshake. The gateway
    // reads that handshake back and it is the only proof in the exchange
    // that involves the peer's WireGuard private key.
    plane.handshake_happens().await;
    backend.fresh_handshake.store(true, Ordering::SeqCst);
    let mut protection = None;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await.expect("Orion state event") {
                ClientEvent::StateChanged {
                    state: TunnelState::Up,
                } => break,
                ClientEvent::Protection { psk } => protection = Some(psk),
                ClientEvent::Error { message } => panic!("Orion failed: {message}"),
                _ => {}
            }
        }
    })
    .await
    .expect("Orion declares the tunnel up after the gateway's commit");
    assert_eq!(protection, Some(PskKind::MlKem));
    assert_eq!(controller.state(), TunnelState::Up);
    assert_eq!(controller.mounted_profile().await.as_deref(), Some("orion"));
    let mut state = handler.transactions.lock().await;
    let SlotState::Committed(committed) = &state.slot(&client_wg.public_key).state else {
        panic!("the gateway commits the transaction Orion confirms");
    };
    assert_eq!(committed.transaction_id, transaction_id);

    served.abort();
}
