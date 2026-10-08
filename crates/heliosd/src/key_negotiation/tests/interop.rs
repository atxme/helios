//! The real Orion client against the real gateway handler. The only file
//! that needs the `orion-core` dev-dependency (CRATE-REORGANIZATION §7).

use super::super::*;
use super::fixtures::*;

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
    end_to_end_negotiation(GatewayLeaf::SelfSigned, ClientFamily::Ipv4).await;
}

#[tokio::test]
async fn the_gateway_and_orion_derive_the_same_psk_under_a_trust_domain() {
    end_to_end_negotiation(GatewayLeaf::IssuedByCaPq, ClientFamily::Ipv4).await;
}

/// The same exchange from an Orion that reaches the gateway over IPv6: an
/// IPv6-only uplink, or a profile naming a `[v6]:port` endpoint. The
/// listener is the one `heliosd` opens, so the IPv4 tests above prove it
/// still answers IPv4 and this one proves it now answers IPv6 too.
#[tokio::test]
async fn the_gateway_and_orion_derive_the_same_psk_over_ipv6() {
    end_to_end_negotiation(GatewayLeaf::SelfSigned, ClientFamily::Ipv6).await;
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

async fn end_to_end_negotiation(leaf: GatewayLeaf, family: ClientFamily) {
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
        minimum_key_negotiation_mode: ProtectionMode::MlKem,
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
    let served = tokio::spawn(aether_key_negotiation::serve(server, handler));

    // From here on, everything runs through the client Orion actually
    // ships — same module, same code path as a real connection.
    let identities = TestIdentities(orion_core::key_negotiation::ClientIdentity {
        certificate_chain: vec![tls.client_certificate.clone()],
        private_key: tls.client_key.clone(),
        pq_certificate: serde_json::to_vec(&client_pq_certificate).unwrap(),
        pq_private_key: client_pq_private.to_vec(),
    });
    let profile = orion_core::ClientProfile {
        name: "orion".into(),
        endpoint: family.endpoint(address.port()),
        private_key: client_wg.private_key.expose().to_string(),
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
        ..orion_core::ClientProfile::default()
    };

    let negotiated = orion_core::key_negotiation::prepare_for_profile(&profile, &identities)
        .await
        .expect("Orion negotiates with the real gateway handler");

    let client_psk = negotiated
        .psk
        .as_ref()
        .map(|secret| secret.expose().to_string())
        .expect("ML-KEM yields a PSK");

    // The gateway installs before answering: its value is already here.
    let gateway_psk = plane
        .writes()
        .await
        .last()
        .cloned()
        .flatten()
        .expect("the gateway installed a PSK before replying");

    assert_eq!(
        client_psk, gateway_psk,
        "both ends must derive the same PSK — differing values would fail every \
             WireGuard handshake with nothing to point at the cause"
    );
    // A 32-byte secret, base64: anything shorter would mean a truncated
    // derivation that still compares equal on both sides.
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&client_psk)
            .unwrap()
            .len(),
        32
    );

    // What a real client does between the response and the confirmation:
    // mount the tunnel with the candidate PSK and handshake. The gateway
    // reads that handshake back and it is the only proof in the exchange
    // that involves the peer's WireGuard private key.
    plane.handshake_happens().await;

    negotiated
        .confirm()
        .await
        .expect("the gateway commits the transaction Orion confirms");
    served.abort();
}
