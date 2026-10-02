//! Shared fixtures of the key-negotiation tests.

use super::super::*;

pub(super) use aether::key_negotiation::{
    authenticate_confirmation, authenticate_request, generate_ml_dsa_87_keypair,
    issue_pq_certificate, AuthenticatedKeyNegotiationRequest, KeyNegotiationRequest, PqCertificate,
    PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_VERSION, PQ_CERTIFICATE_VERSION,
};

/// Horloge des tests : les requêtes doivent être fraîches pour passer la
/// fenêtre anti-rejeu.
pub(super) fn test_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(super) const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
pub(super) const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
pub(super) const CERTIFICATE_FINGERPRINT: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(super) struct PqFixture {
    pub(super) client_ca_public_key: Vec<u8>,
    pub(super) client_certificate: PqCertificate,
    pub(super) client_private_key: Vec<u8>,
    pub(super) gateway_certificate: PqCertificate,
    pub(super) gateway_private_key: Vec<u8>,
}

pub(super) fn certificate(
    subject: &str,
    role: PqCertificateRole,
    wireguard_key: &str,
    public_key: &[u8],
    issuer_private_key: &[u8],
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [8; 16],
            subject: subject.into(),
            issuer: "test-ca".into(),
            role,
            wireguard_public_key: wireguard_key.into(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            not_before_unix: 1,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        issuer_private_key,
    )
    .unwrap()
}

/// The leaf a gateway with no trust domain serves.
///
/// [`certificate`] always writes `test-ca` as the issuer, which is right
/// for a client leaf and wrong for this one: naming an authority that did
/// not sign it is a shape no gateway serves, and it hides which of the two
/// verification paths a test actually took.
pub(super) fn self_signed_gateway_certificate(
    subject: &str,
    wireguard_key: &str,
    public_key: &[u8],
    private_key: &[u8],
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [9; 16],
            subject: subject.into(),
            issuer: subject.into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: wireguard_key.into(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            not_before_unix: 1,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        private_key,
    )
    .unwrap()
}

pub(super) fn pq_fixture() -> PqFixture {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let client_certificate = certificate(
        "orion",
        PqCertificateRole::Client,
        CLIENT_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
    let gateway_certificate = certificate(
        "gateway",
        PqCertificateRole::Gateway,
        GATEWAY_KEY,
        &gateway_public,
        gateway_private.as_slice(),
    );
    PqFixture {
        client_ca_public_key: ca_public,
        client_certificate,
        client_private_key: client_private.to_vec(),
        gateway_certificate,
        gateway_private_key: gateway_private.to_vec(),
    }
}

pub(super) const TEST_CHALLENGE: [u8; SERVER_CHALLENGE_LEN] = [5; SERVER_CHALLENGE_LEN];

pub(super) fn request(
    transaction_id: [u8; 16],
    fixture: &PqFixture,
) -> AuthenticatedKeyNegotiationRequest {
    // `ml_kem`: the mode that leaves an owned slot, which is what most of
    // these tests are about. `classic` used to serve here and no longer
    // decodes at all.
    request_in_mode(transaction_id, fixture, ProtectionMode::MlKem, None)
}

/// Sends a signed `release` the way Orion does: through the internal API.
///
/// The caller key is passed separately, exactly as `require_peer` supplies
/// it after resolving the source VIP — the body's copy is only ever
/// compared against it.
pub(super) async fn release_in_tunnel(
    handler: &GatewayHandler,
    fixture: &PqFixture,
    installed_transaction_id: [u8; 16],
) -> Result<(), PskReleaseRefusal> {
    use helios_api::key_negotiation::PskReleaseHandler as _;

    let release = aether::key_negotiation::authenticate_release(
        aether::key_negotiation::PskRelease {
            protocol_version: KEY_NEGOTIATION_VERSION,
            installed_transaction_id,
            client_wg_public_key: CLIENT_KEY.into(),
            gateway_wg_public_key: GATEWAY_KEY.into(),
        },
        fixture.client_certificate.clone(),
        &fixture.client_private_key,
    )
    .unwrap();
    handler.release(CLIENT_KEY, release).await
}

/// The same request in a chosen mode, with the static commitment when one
/// is needed.
pub(super) fn request_in_mode(
    transaction_id: [u8; 16],
    fixture: &PqFixture,
    mode: ProtectionMode,
    static_psk: Option<&str>,
) -> AuthenticatedKeyNegotiationRequest {
    let client_nonce = [2; 16];
    let static_psk_commitment = static_psk.map(|psk| {
        aether::key_negotiation::static_psk_commitment(
            psk,
            &transaction_id,
            &client_nonce,
            &TEST_CHALLENGE,
            CLIENT_KEY,
            GATEWAY_KEY,
        )
        .unwrap()
    });
    let kem_public_key = (mode == ProtectionMode::MlKem).then(|| {
        use aether::Kem as _;
        aether::MlKem1024Kem::generate().unwrap().1
    });
    let request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge: TEST_CHALLENGE,
        transaction_id,
        mode,
        client_wg_public_key: CLIENT_KEY.to_string(),
        // Named, and checked against what the handler actually serves.
        gateway_wg_public_key: GATEWAY_KEY.to_string(),
        server_name: fixture.gateway_certificate.subject.clone(),
        gateway_certificate_fingerprint: fixture.gateway_certificate.fingerprint().unwrap(),
        client_nonce,
        timestamp_unix: test_now(),
        kem_public_key,
        static_psk_commitment,
    };
    authenticate_request(
        request,
        fixture.client_certificate.clone(),
        &fixture.client_private_key,
    )
    .unwrap()
}

/// A data plane the test drives, answering both gateway channels.
///
/// The handshake it reports is the pivot of every commit: since v5 the
/// gateway refuses to sign unless it observes one strictly newer than the
/// value read before the candidate PSK was posed. A test that wants a
/// commit must therefore say so — which is the point, because the absence
/// of that call is exactly the attack the check exists to stop.
pub(super) struct TestDataPlane {
    /// Every PSK write the data plane received, in order.
    pub(super) applied: Arc<Mutex<Vec<Option<String>>>>,
    /// When set, every write is acknowledged as a failure.
    pub(super) failing: Arc<Mutex<bool>>,
    pub(super) handshake: Arc<Mutex<Option<std::time::SystemTime>>>,
    /// Fed from a counter rather than the wall clock: two calls to
    /// `SystemTime::now()` can return the same instant on a coarse clock,
    /// and "strictly newer" would then be false for a handshake that did
    /// happen.
    pub(super) tick: Arc<Mutex<u64>>,
}

impl TestDataPlane {
    pub(super) fn spawn() -> (
        Self,
        mpsc::Sender<InstallPskRequest>,
        mpsc::Sender<aether::ObserveHandshakeRequest>,
    ) {
        let applied = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let failing = Arc::new(Mutex::new(false));
        let handshake = Arc::new(Mutex::new(None));
        let (psk_tx, mut psk_rx) = mpsc::channel::<InstallPskRequest>(8);
        let writes = Arc::clone(&applied);
        let refuse = Arc::clone(&failing);
        tokio::spawn(async move {
            while let Some(request) = psk_rx.recv().await {
                writes
                    .lock()
                    .await
                    .push(request.psk.map(|secret| secret.expose().to_string()));
                let answer = if *refuse.lock().await {
                    Err("data plane refused".to_string())
                } else {
                    Ok(())
                };
                let _ = request.reply.send(answer);
            }
        });
        let (handshake_tx, mut handshake_rx) = mpsc::channel::<aether::ObserveHandshakeRequest>(8);
        let reported = Arc::clone(&handshake);
        tokio::spawn(async move {
            while let Some(request) = handshake_rx.recv().await {
                let answer = *reported.lock().await;
                let _ = request.reply.send(Ok(answer));
            }
        });
        (
            Self {
                applied,
                failing,
                handshake,
                tick: Arc::new(Mutex::new(0)),
            },
            psk_tx,
            handshake_tx,
        )
    }

    pub(super) async fn start_failing(&self) {
        *self.failing.lock().await = true;
    }

    /// Reports a handshake strictly newer than any reported before.
    pub(super) async fn handshake_happens(&self) {
        let mut tick = self.tick.lock().await;
        *tick += 1;
        *self.handshake.lock().await =
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(*tick));
    }

    pub(super) async fn writes(&self) -> Vec<Option<String>> {
        self.applied.lock().await.clone()
    }
}

pub(super) fn network(previous_psk: &str, pq_fingerprint: &str) -> NetworkConfig {
    let mut network = NetworkConfig::default();
    network.peers.push(aether::WgPeer {
        name: "orion".into(),
        public_key: CLIENT_KEY.into(),
        address: "100.64.1.2/32".into(),
        address_v6: None,
        admin: false,
        preshared_key: Some(previous_psk.into()),
        key_negotiation_certificate_sha256: Some(CERTIFICATE_FINGERPRINT.into()),
        key_negotiation_pq_certificate_sha256: Some(pq_fingerprint.into()),
        minimum_key_negotiation_mode: ProtectionMode::Classic,
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    });
    network
}

/// Builds a handler over a fresh fake data plane, with one admitted peer.
pub(super) fn gateway_with(
    fixture: &PqFixture,
    previous_psk: &str,
    floor: ProtectionMode,
) -> (GatewayHandler, TestDataPlane) {
    let mut configured = network(
        previous_psk,
        &fixture.client_certificate.fingerprint().unwrap(),
    );
    configured.peers[0].minimum_key_negotiation_mode = floor;
    let (plane, psk_tx, handshake_tx) = TestDataPlane::spawn();
    let handler = GatewayHandler {
        network: Arc::new(RwLock::new(configured)),
        psk_tx,
        handshake_tx,
        gateway_public_key: GATEWAY_KEY.into(),
        client_pq_ca_public_key: fixture.client_ca_public_key.clone(),
        registry: None,
        gateway_pq_certificate: fixture.gateway_certificate.clone(),
        served_certificate_fingerprint: fixture.gateway_certificate.fingerprint().unwrap(),
        gateway_pq_private_key: Zeroizing::new(fixture.gateway_private_key.clone()),
        dry_run: true,
        static_psks: RwLock::new(HashMap::from([(
            CLIENT_KEY.into(),
            SecretString::new(previous_psk),
        )])),
        transactions: Mutex::new(TransactionState::default()),
    };
    (handler, plane)
}
