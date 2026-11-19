use super::*;
use crate::key_negotiation::{ClientIdentity, IdentityProvider};
use aether::key_negotiation::{
    PqCertificate, PqCertificateRole, ProtectionMode, PQ_CERTIFICATE_VERSION,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;
use tokio::time::Instant;

fn profile() -> ClientProfile {
    let gateway = STANDARD.encode([7; 32]);
    // Only the decoded shape is needed here. The protected store refuses
    // before Orion opens a socket or validates the gateway's response.
    let leaf = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [1; 16],
        subject: "gateway.example".into(),
        issuer: "gateway.example".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: gateway.clone(),
        ml_dsa_87_public_key: String::new(),
        not_before_unix: 1,
        not_after_unix: 2,
        ml_dsa_87_signature: String::new(),
    };
    ClientProfile {
        name: "protected-profile".into(),
        endpoint: "gateway.example:51820".into(),
        private_key: STANDARD.encode([9; 32]).into(),
        peer_public_key: gateway,
        key_negotiation: Some(crate::KeyNegotiationSettings {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: "GATEWAY.example.:51821".into(),
            server_name: "gateway.example".into(),
            gateway_ca_der: STANDARD.encode(b"fixture CA"),
            gateway_pq_certificate: STANDARD.encode(serde_json::to_vec(&leaf).unwrap()),
            identity: "sealed-client".into(),
            trust: None,
        }),
        ..ClientProfile::default()
    }
}

struct RefusingIdentities {
    failures: StdMutex<VecDeque<&'static str>>,
    calls: StdMutex<Vec<Instant>>,
}

impl RefusingIdentities {
    fn new(failures: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            failures: StdMutex::new(failures.into_iter().collect()),
            calls: StdMutex::default(),
        }
    }
}

#[async_trait]
impl IdentityProvider for RefusingIdentities {
    async fn load(&self, identity: &str) -> anyhow::Result<ClientIdentity> {
        assert_eq!(identity, "sealed-client");
        self.calls.lock().unwrap().push(Instant::now());
        let refusal = self
            .failures
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected identity load");
        Err(anyhow::anyhow!(refusal))
    }
}

#[tokio::test(start_paused = true)]
async fn temporary_identity_failures_reach_every_attempt_without_mounting() {
    let identities = RefusingIdentities::new(["store busy", "file locked", "store still busy"]);
    let backend: Arc<dyn VpnBackend> = Arc::new(dryrun::DryRunBackend::default());
    let installed = Mutex::new(None);
    let lost = Arc::new(AtomicBool::new(false));
    let sink: EventSink = Arc::new(|_| {});
    let start = Instant::now();
    let error = connect_with_key_negotiation(
        &backend,
        &profile(),
        &sink,
        Some(&identities),
        &installed,
        &lost,
    )
    .await
    .unwrap_err();

    assert_eq!(
        *identities.calls.lock().unwrap(),
        [
            start,
            start + KEY_NEGOTIATION_RETRY_DELAY,
            start + 2 * KEY_NEGOTIATION_RETRY_DELAY,
        ]
    );
    assert_eq!(Instant::now(), start + 2 * KEY_NEGOTIATION_RETRY_DELAY);
    assert_eq!(error.root_cause().to_string(), "store still busy");
    assert!(installed.lock().await.is_none());
    assert!(!backend.adapter_is_up());
}

#[tokio::test(start_paused = true)]
async fn a_terminal_error_on_the_retry_stops_before_the_third_attempt() {
    let identities = RefusingIdentities::new(["store busy", "invalid PKCS#8 private key"]);
    let backend: Arc<dyn VpnBackend> = Arc::new(dryrun::DryRunBackend::default());
    let sink: EventSink = Arc::new(|_| {});
    let start = Instant::now();
    let error = connect_with_key_negotiation(
        &backend,
        &profile(),
        &sink,
        Some(&identities),
        &Mutex::new(None),
        &Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap_err();

    assert_eq!(
        *identities.calls.lock().unwrap(),
        [start, start + KEY_NEGOTIATION_RETRY_DELAY]
    );
    assert_eq!(Instant::now(), start + KEY_NEGOTIATION_RETRY_DELAY);
    assert_eq!(error.root_cause().to_string(), "invalid PKCS#8 private key");
    assert!(!backend.adapter_is_up());
}

#[tokio::test]
async fn wireguard_endpoint_errors_precede_identity_access() {
    let identities = RefusingIdentities::new([]);
    for (endpoint, expected) in [
        ("gateway.example:0", "port UDP absent ou nul"),
        ("different-host-without-a-port", "invalide"),
    ] {
        let mut profile = profile();
        profile.endpoint = endpoint.into();
        let error = prepare_attempt(&profile, &identities)
            .await
            .err()
            .expect("endpoint rejected");
        let detail = format!("{error:#}");
        assert!(detail.contains(endpoint), "{detail}");
        assert!(detail.contains(expected), "{detail}");
    }
    assert!(identities.calls.lock().unwrap().is_empty());
}
