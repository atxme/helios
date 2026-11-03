use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use quinn::Endpoint;

use aether::key_negotiation::{
    authenticate_commit, authenticate_response, generate_ml_dsa_87_keypair, issue_pq_certificate,
    static_psk_commitment, AuthenticatedKeyNegotiationCommit,
    AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest,
    KeyNegotiationRequest, KeyNegotiationResponse, PqCertificate, PqCertificateRole,
    ProtectionMode, KEY_NEGOTIATION_NONCE_LEN, KEY_NEGOTIATION_VERSION, PQ_CERTIFICATE_VERSION,
    SERVER_CHALLENGE_LEN,
};
use async_trait::async_trait;
use base64::Engine as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};

use crate::{
    certificate_fingerprint_der, client_endpoint, serve, server_endpoint, GatewayIdentity,
    NegotiationHandler, PreparedNegotiation, PublicError, TlsIdentity,
};

/// Horloge des tests : les requêtes doivent être fraîches pour passer la
/// fenêtre anti-rejeu.
pub(super) fn test_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub(crate) const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
pub(crate) const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
pub(super) const TEST_SERVER_NAME: &str = "gateway.test";
pub(super) const TEST_CHALLENGE: [u8; SERVER_CHALLENGE_LEN] = [5; SERVER_CHALLENGE_LEN];
pub(super) const GATEWAY_CERT_FINGERPRINT: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// The cheapest request a v5 decoder accepts.
///
/// Was a `classic` request until that mode stopped being negotiable.
/// `static_psk` costs one HMAC to build, where `ml_kem` costs a keypair.
pub(crate) fn simple_request(
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
) -> KeyNegotiationRequest {
    let mut request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge: TEST_CHALLENGE,
        transaction_id,
        mode: ProtectionMode::StaticPsk,
        client_wg_public_key: CLIENT_WG_KEY.into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
        server_name: TEST_SERVER_NAME.into(),
        gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
        client_nonce: [2; KEY_NEGOTIATION_NONCE_LEN],
        timestamp_unix: test_now(),
        kem_public_key: None,
        static_psk_commitment: None,
    };
    let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    request.static_psk_commitment = Some(commitment(&psk, &request));
    request
}
/// Recomputes an engagement exactly as the gateway will.
pub(super) fn commitment(psk: &str, request: &KeyNegotiationRequest) -> String {
    static_psk_commitment(
        psk,
        &request.transaction_id,
        &request.client_nonce,
        &request.server_challenge,
        &request.client_wg_public_key,
        GATEWAY_WG_KEY,
    )
    .unwrap()
}
pub(crate) struct TestPki {
    pub(crate) ca_der: Vec<u8>,
    pub(crate) server: TlsIdentity,
    pub(crate) client: TlsIdentity,
    pub(crate) client_fingerprint: String,
    pub(crate) client_pq_certificate: PqCertificate,
    pub(crate) client_pq_private_key: Vec<u8>,
    pub(crate) gateway_pq_certificate: PqCertificate,
    pub(crate) gateway_pq_private_key: Vec<u8>,
}

pub(super) fn pq_identity(
    subject: &str,
    role: PqCertificateRole,
    wireguard_public_key: &str,
) -> (PqCertificate, Vec<u8>) {
    let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [9; 16],
            subject: subject.into(),
            issuer: subject.into(),
            role,
            wireguard_public_key: wireguard_public_key.into(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
            not_before_unix: 1,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        private_key.as_slice(),
    )
    .unwrap();
    (certificate, private_key.to_vec())
}

pub(crate) fn test_pki() -> TestPki {
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
        let issuer = Issuer::from_ca_cert_der(ca.der(), ca_key).unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
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

/// A second client authority, independent from the one that issued the
/// server identity in [`test_pki`].
///
/// A renewed Orion leaf has exactly this shape: it chains to the domain
/// `CA-TLS`, while the gateway leaf and the first client generation still
/// belong to their original authorities.
pub(super) fn independent_client_identity(name: &str) -> (Vec<u8>, TlsIdentity) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec![name.into()]).unwrap();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_ca_cert_der(ca.der(), &ca_key).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    (
        ca.der().to_vec(),
        TlsIdentity {
            certificate_chain: vec![leaf.der().to_vec(), ca.der().to_vec()],
            private_key: leaf_key.serialize_der(),
        },
    )
}
pub(crate) struct Handler {
    pub(super) expected_fingerprint: String,
    pub(super) reject_prepare: AtomicBool,
    pub(crate) confirmed: AtomicBool,
    pub(super) rolled_back: AtomicBool,
    /// How many rollbacks actually ran to completion.
    pub(super) rollbacks: std::sync::atomic::AtomicUsize,
    /// Signals each rollback as it enters the backend, before it can block.
    pub(crate) rollback_started: tokio::sync::Semaphore,
    /// Signals each backend rollback that has returned.
    pub(crate) rollback_completed: tokio::sync::Semaphore,
    /// Exact ownership claims passed by the real connection handler.
    pub(crate) rollback_events: std::sync::Mutex<Vec<([u8; 16], String)>>,
    /// Held open by default; a test can close it to park a rollback on an
    /// `await` and then destroy the task sitting there.
    pub(crate) rollback_gate: tokio::sync::Semaphore,
    /// Lets a transport test close the client after confirmation is accepted
    /// but before the handler returns the signed commit.
    pub(crate) confirm_started: tokio::sync::Semaphore,
    pub(crate) confirm_returned: tokio::sync::Semaphore,
    pub(crate) confirm_gate: tokio::sync::Semaphore,
    pub(super) gateway_pq_certificate: PqCertificate,
    pub(super) gateway_pq_private_key: Vec<u8>,
    /// Every canonical connection source the server handed to the handler.
    pub(super) sources: std::sync::Mutex<Vec<std::net::IpAddr>>,
}

impl Handler {
    pub(crate) fn new(pki: &TestPki) -> Self {
        Self::with_permits(
            pki,
            tokio::sync::Semaphore::MAX_PERMITS,
            tokio::sync::Semaphore::MAX_PERMITS,
        )
    }

    /// A handler whose `rollback` blocks until the test lets it through.
    pub(crate) fn with_blocked_rollback(pki: &TestPki) -> Self {
        Self::with_permits(pki, 0, tokio::sync::Semaphore::MAX_PERMITS)
    }

    /// A handler whose authenticated confirmation waits for an explicit test
    /// signal before producing the signed commit.
    pub(crate) fn with_blocked_confirm(pki: &TestPki) -> Self {
        Self::with_permits(pki, tokio::sync::Semaphore::MAX_PERMITS, 0)
    }

    fn with_permits(pki: &TestPki, rollback_permits: usize, confirm_permits: usize) -> Self {
        Self {
            expected_fingerprint: pki.client_fingerprint.clone(),
            reject_prepare: AtomicBool::new(false),
            confirmed: AtomicBool::new(false),
            rolled_back: AtomicBool::new(false),
            rollbacks: std::sync::atomic::AtomicUsize::new(0),
            rollback_started: tokio::sync::Semaphore::new(0),
            rollback_completed: tokio::sync::Semaphore::new(0),
            rollback_events: std::sync::Mutex::new(Vec::new()),
            rollback_gate: tokio::sync::Semaphore::new(rollback_permits),
            confirm_started: tokio::sync::Semaphore::new(0),
            confirm_returned: tokio::sync::Semaphore::new(0),
            confirm_gate: tokio::sync::Semaphore::new(confirm_permits),
            gateway_pq_certificate: pki.gateway_pq_certificate.clone(),
            gateway_pq_private_key: pki.gateway_pq_private_key.clone(),
            sources: Default::default(),
        }
    }
}

#[async_trait]
impl NegotiationHandler for Handler {
    fn announced_identity(&self) -> GatewayIdentity {
        GatewayIdentity {
            wg_public_key: GATEWAY_WG_KEY.into(),
            server_name: "localhost".into(),
        }
    }

    async fn prepare(
        &self,
        certificate_sha256: String,
        source: std::net::IpAddr,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError> {
        self.sources.lock().unwrap().push(source);
        // A wrong TLS fingerprint is `Rejected` like every other
        // pre-installation refusal: the public boundary must not let a
        // caller tell an unknown peer from a mismatched certificate.
        if certificate_sha256 != self.expected_fingerprint {
            return Err(PublicError::Rejected);
        }
        if self.reject_prepare.load(Ordering::SeqCst) {
            return Err(PublicError::Rejected);
        }
        Ok(PreparedNegotiation {
            response: authenticate_response(
                KeyNegotiationResponse {
                    protocol_version: KEY_NEGOTIATION_VERSION,
                    transaction_id: request.request.transaction_id,
                    server_challenge: request.request.server_challenge,
                    selected_mode: request.request.mode,
                    gateway_wg_public_key: GATEWAY_WG_KEY.into(),
                    client_wg_public_key: request.request.client_wg_public_key.clone(),
                    gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
                    kem_ciphertext: None,
                    confirmation_timeout_secs: 2,
                    psk_lifetime_secs: match request.request.mode {
                        ProtectionMode::StaticPsk => 0,
                        _ => aether::key_negotiation::NEGOTIATED_PSK_LIFETIME_SECS,
                    },
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
        self.confirm_started.add_permits(1);
        let _permit = self
            .confirm_gate
            .acquire()
            .await
            .expect("confirm gate closed");
        let commit = authenticate_commit(
            confirmation.confirmation.server_challenge,
            confirmation.confirmation.transaction_id,
            &self.gateway_pq_private_key,
        )
        .map_err(|_| PublicError::Internal)?;
        self.confirm_returned.add_permits(1);
        Ok(commit)
    }

    async fn resolve_admitted_peer(
        &self,
        certificate_sha256: &str,
        source: std::net::IpAddr,
    ) -> Option<String> {
        self.sources.lock().unwrap().push(source);
        (certificate_sha256 == self.expected_fingerprint).then(|| CLIENT_WG_KEY.to_string())
    }

    async fn rollback(&self, transaction_id: [u8; 16], public_key: &str) {
        self.rollback_events
            .lock()
            .unwrap()
            .push((transaction_id, public_key.to_string()));
        self.rollback_started.add_permits(1);
        // The suspension point a real rollback has — it writes to the
        // data plane — and the one a cancelled task can be destroyed in.
        let _permit = self.rollback_gate.acquire().await;
        self.rolled_back.store(true, Ordering::SeqCst);
        self.rollbacks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.rollback_completed.add_permits(1);
    }
}
/// Monte le service et rend l'endpoint client, pour ne pas répéter huit
/// lignes de PKI dans chaque test.
pub(super) fn bench(
    pki: &TestPki,
) -> (
    Arc<Handler>,
    tokio::task::JoinHandle<()>,
    Endpoint,
    SocketAddr,
) {
    let server = server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &pki.server,
        std::slice::from_ref(&pki.ca_der),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    let handler = Arc::new(Handler::new(pki));
    let task = tokio::spawn(serve(
        server,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));
    let client = client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &pki.client,
        pki.ca_der.clone(),
    )
    .unwrap();
    (handler, task, client, server_addr)
}
