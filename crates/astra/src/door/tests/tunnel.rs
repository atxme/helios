//! The tunnel's connector, through Astra's real private router.
//!
//! The production listener is the pinned Astra–gateway mTLS channel; these
//! loopback tests exercise the router, its extractor and the handler behind
//! it, not that TLS boundary (`private_channel.rs` covers it).

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use astra_channel::{OperatorOpenAction, OperatorOpenRequest, RelayedOperatorOpen};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

pub(super) struct PrivateListener {
    pub(super) address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PrivateListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Astra's private router, the one `astra run` serves the gateway.
pub(super) async fn listen(service: Arc<AstraService>) -> PrivateListener {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let router = crate::renewal::router::router(service);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    PrivateListener { address, task }
}

/// One `POST` to the opening route, raw, as the gateway's client sends it.
async fn post_open(listener: &PrivateListener, body: &[u8]) -> (u16, Vec<u8>) {
    post_to(listener, astra_channel::OPERATOR_OPEN_ROUTE, body).await
}

pub(super) async fn post_to(
    listener: &PrivateListener,
    route: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(listener.address).await.expect("connect");
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            route,
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("head");
        stream.write_all(body).await.expect("body");
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.expect("answer");
        answer
    })
    .await
    .expect("the private route answers");
    let split = answer
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("headers");
    let status = String::from_utf8_lossy(&answer[..split])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    (status, answer[split + 4..].to_vec())
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn administrator() -> OperatorIdentity {
    OperatorIdentity::WireGuard {
        public_key: tunnel_key(),
    }
}

fn relayed_fleet_opening() -> Vec<u8> {
    serde_json::to_vec(&RelayedOperatorOpen {
        operator: administrator(),
        request: OperatorOpenRequest {
            action: OperatorOpenAction::FleetLeafs,
            reason: "quarterly rotation".into(),
            requested_by: "alice".into(),
            window_secs: 300,
        },
    })
    .expect("relayed opening")
}

/// A coarse refusal: the class, and not a word about why.
fn coarse(body: &[u8], class: ServiceError) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).ok()
        == Some(serde_json::json!({ "error": class.to_string() }))
}

#[tokio::test]
async fn a_tunnel_open_lands_in_pending() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    // `OperatorOpened` refuses unknown fields: the console-only facts of an
    // opening (its URL, its subject) are not in this answer.
    let opened: OperatorOpened = serde_json::from_slice(&body).expect("the tunnel's answer");
    assert_eq!(opened.scope, CampaignScope::FleetLeafs);
    assert_eq!(opened.target_count, PEERS.len());

    let pending = service.signing.lock().await.pending(wall_clock());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, opened.operation_id);
    assert_eq!(
        pending[0].requested_by,
        format!("alice — pair wireguard:{}", tunnel_key())
    );
}

/// The tunnel's enum has no console action, so the body is refused before
/// the door is reached — and the refusal names neither the action nor the
/// ones that exist.
#[tokio::test]
async fn a_tunnel_open_of_a_console_action_is_refused_coarsely() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let body = serde_json::json!({
        "operator": administrator(),
        "request": {
            "action": "chain_open",
            "reason": "quarterly rotation",
            "requested_by": "alice",
        },
    });
    let (status, answer) = post_open(&listener, body.to_string().as_bytes()).await;
    assert_eq!(status, 400);
    assert!(
        coarse(&answer, ServiceError::Protocol),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(service
        .signing
        .lock()
        .await
        .pending(wall_clock())
        .is_empty());
    assert!(!plan_path(dir.path()).exists());
}

/// A text the door refuses is the caller's own malformed input: the tunnel
/// answers it as a coarse `400`, like an empty one.
#[tokio::test]
async fn a_tunnel_open_with_a_hidden_character_is_refused_coarsely() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    for (reason, requested_by) in [
        (
            "quarterly rotation".to_string(),
            "alice\u{202E}".to_string(),
        ),
        ("a".repeat(MAX_REASON_CHARS + 1), "alice".to_string()),
    ] {
        let body = serde_json::to_vec(&RelayedOperatorOpen {
            operator: administrator(),
            request: OperatorOpenRequest {
                action: OperatorOpenAction::FleetLeafs,
                reason,
                requested_by,
                window_secs: 300,
            },
        })
        .expect("relayed opening");
        let (status, answer) = post_open(&listener, &body).await;
        assert_eq!(status, 400);
        assert!(
            coarse(&answer, ServiceError::Protocol),
            "{}",
            String::from_utf8_lossy(&answer)
        );
    }
    assert!(service
        .signing
        .lock()
        .await
        .pending(wall_clock())
        .is_empty());
}

/// A refusal at the door crosses back as its class; the sentence that says
/// which campaign is already open stays in the service log.
#[tokio::test]
async fn a_refused_tunnel_open_answers_its_class_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (first, _) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(first, 200);
    let (status, answer) = post_open(&listener, &relayed_fleet_opening()).await;
    assert_eq!(status, 403);
    assert!(
        coarse(&answer, ServiceError::Refused),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(service.signing.lock().await.pending(wall_clock()).len(), 1);
}

fn relayed_delegation_opening() -> Vec<u8> {
    serde_json::to_vec(&RelayedOperatorOpen {
        operator: administrator(),
        request: OperatorOpenRequest {
            action: OperatorOpenAction::IssuerDelegation,
            reason: "after a CA replacement".into(),
            requested_by: "alice".into(),
            window_secs: 300,
        },
    })
    .expect("relayed opening")
}

#[tokio::test]
async fn tunnel_may_open_a_delegation_and_gets_its_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = post_open(&listener, &relayed_delegation_opening()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let opened: OperatorOpened = serde_json::from_slice(&body).expect("the tunnel's answer");
    assert_eq!(opened.scope, CampaignScope::IssuerDelegation);
    let request: crate::issuer::IssuerDelegationRequest = serde_json::from_str(
        opened
            .delegation_request
            .as_deref()
            .expect("the opening carries the public request"),
    )
    .expect("the request is JSON");
    assert_eq!(request.issuer_epoch, 1);
    assert!(crate::issuer::pq_key_path(dir.path(), 1).exists());
    assert_eq!(service.signing.lock().await.pending(wall_clock()).len(), 1);

    let campaign = service
        .signing
        .lock()
        .await
        .get(&opened.operation_id, wall_clock())
        .expect("operation held")
        .campaign
        .as_ref()
        .clone();
    assert_eq!(campaign.targets[0].epoch, request.issuer_epoch);
    let public_key =
        aether::certificates::encoding::MlDsa87PublicKey::parse(&request.pq_issuer_public_key)
            .expect("public key");
    assert_eq!(
        campaign.targets[0].active_pq_certificate_fingerprint,
        Fingerprint::of(public_key.as_bytes())
    );

    // Nothing private rides along: the answer holds the public request only.
    assert!(!String::from_utf8_lossy(&body).contains("PRIVATE"));
}

#[tokio::test]
async fn a_second_tunnel_delegation_is_already_open_and_keeps_the_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;

    let (first, _) = post_open(&listener, &relayed_delegation_opening()).await;
    assert_eq!(first, 200);
    let pq = crate::issuer::pq_key_path(dir.path(), 1);
    let tls = crate::issuer::tls_key_path(dir.path(), 1);
    let (pq_before, tls_before) = (
        std::fs::read(&pq).expect("pq key"),
        std::fs::read(&tls).expect("tls key"),
    );

    let (status, answer) = post_open(&listener, &relayed_delegation_opening()).await;
    assert_eq!(status, 403);
    assert!(
        coarse(&answer, ServiceError::Refused),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(std::fs::read(&pq).expect("pq key"), pq_before);
    assert_eq!(std::fs::read(&tls).expect("tls key"), tls_before);
}

async fn read_status(listener: &PrivateListener) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(&astra_channel::RelayedOperatorCampaign {
        operator: administrator(),
    })
    .expect("relayed read");
    post_to(listener, astra_channel::OPERATOR_STATUS_ROUTE, &body).await
}

#[tokio::test]
async fn status_reports_a_rotation_in_flight_and_the_serving_issuer() {
    use crate::registry::{CaPqRotation, ClientTlsCaRotation};
    use aether::certificates::state::{AstraIssuerState, IssuerLifecycle};

    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture_with_ca_tls(dir.path());
    let delegated = delegated_material();
    let serving = delegation(&delegated, 1);
    let (_, next_ca) = generate_ml_dsa_87_keypair().expect("next CA-PQ");
    let mut recorded = delegation(&delegated, 2);
    recorded.ca_epoch = 2;
    recorded.not_after = NOW * 3;
    let (recorded_for_state, next_for_state) = (recorded.clone(), next_ca.clone());
    rewrite_registry(&service, |state| {
        state.ca_rotation = Some(CaPqRotation {
            next_ca_epoch: 2,
            next_ca_public_key: next_for_state,
            activation_at: NOW,
            retire_active_at: NOW + 10,
        });
        state.ca_tls_rotation = Some(ClientTlsCaRotation {
            next_ca_tls_epoch: 2,
            next_ca_tls_fingerprint: Fingerprint::of(b"next tls ca"),
            activation_at: NOW,
            retire_active_at: NOW + 10,
        });
        state.issuer = Some(AstraIssuerState {
            issuer_epoch: 2,
            authorization: recorded_for_state,
            state: IssuerLifecycle::Active,
        });
    })
    .await;
    *service.issuer.write().expect("issuer lock") =
        Some(Arc::new(crate::issuer::DelegatedIssuer::new(
            serving,
            zeroize::Zeroizing::new(Vec::new()),
            zeroize::Zeroizing::new(Vec::new()),
        )));
    // The served document, at an epoch the registry's bootstrap floor (1) is
    // not: the status must report what Astra serves.
    *service
        .approval_credentials
        .write()
        .expect("credentials lock") = Arc::new(crate::service::ApprovalCredentials::from_document(
        Box::new(aether::certificates::approval::CredentialRegistry {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            ca_epoch: 1,
            credential_registry_epoch: 7,
            bindings: Vec::new(),
        }),
    ));
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = read_status(&listener).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let report: astra_channel::OperatorAuthorityStatus =
        serde_json::from_slice(&body).expect("the status");
    let anchor = service
        .registry
        .lock()
        .await
        .state()
        .ca_public_key
        .authority_fingerprint();
    assert_eq!(report.ca_epoch, 1);
    assert_eq!(report.ca_fingerprint, anchor);
    assert_eq!(
        report.next_ca_fingerprint,
        Some(next_ca.authority_fingerprint())
    );
    assert_eq!(report.ca_tls_epoch, 1);
    assert_eq!(
        report.ca_tls_fingerprint,
        Some(Fingerprint::of(b"client tls ca"))
    );
    assert_eq!(
        report.next_ca_tls_fingerprint,
        Some(Fingerprint::of(b"next tls ca"))
    );
    assert_eq!(
        report.vault_copy_fingerprint,
        Some(Fingerprint::of(b"placeholder encrypted vault"))
    );
    assert_eq!(report.credential_registry_epoch, Some(7));
    let issuer = report.issuer.expect("a delegation is recorded");
    assert_eq!(issuer.recorded_epoch, 2);
    assert_eq!(issuer.serving_epoch, Some(1));
    assert_eq!(issuer.ca_epoch, 2);
    assert_eq!(issuer.ca_tls_epoch, 1);
    assert_eq!(issuer.not_after, NOW * 3);
}

#[tokio::test]
async fn status_without_a_delegation_or_vault_says_so() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    *service.encrypted_vault.write().expect("vault lock") = None;
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = read_status(&listener).await;
    assert_eq!(status, 200);
    let report: astra_channel::OperatorAuthorityStatus =
        serde_json::from_slice(&body).expect("the status");
    assert_eq!(report.issuer, None);
    assert_eq!(report.vault_copy_fingerprint, None);
    assert_eq!(report.next_ca_fingerprint, None);
    assert_eq!(report.ca_tls_fingerprint, None);
    // The fixture serves no credential document: no epoch to report, which is
    // not the registry's floor of 1.
    assert_eq!(report.credential_registry_epoch, None);
}

#[tokio::test]
async fn status_carries_nothing_secret() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    let listener = listen(Arc::clone(&service)).await;
    let (first, _) = post_open(&listener, &relayed_delegation_opening()).await;
    assert_eq!(first, 200);

    let (status, body) = read_status(&listener).await;
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    let text = value.to_string().to_lowercase();
    for forbidden in ["token", "private", "secret", "capability", "key"] {
        assert!(!text.contains(forbidden), "{forbidden} in {text}");
    }
    // Fingerprints and epochs only: every value is a number, a hex string,
    // an object of those, or null.
    assert!(value.get("vault_copy_fingerprint").is_some());
}

/// A refused opening must not rewrite the files of the epoch: with no vault
/// copy the door refuses before it draws a key.
#[tokio::test]
async fn a_delegation_opening_refused_for_lack_of_a_vault_leaves_the_key_files() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = fixture(dir.path());
    *service.encrypted_vault.write().expect("vault lock") = None;
    let listener = listen(Arc::clone(&service)).await;

    let (status, body) = post_open(&listener, &relayed_delegation_opening()).await;
    assert_ne!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(!crate::issuer::pq_key_path(dir.path(), 1).exists());
    assert!(!crate::issuer::tls_key_path(dir.path(), 1).exists());
    assert!(service
        .signing
        .lock()
        .await
        .pending(wall_clock())
        .is_empty());
}

/// One approving credential of the fixture's document: a software ES256 key, which
/// proves the protocol and says nothing of a physical authenticator.
fn approving_credential(
    ca_private: &[u8],
    serial: u8,
) -> (
    rcgen::KeyPair,
    aether::certificates::approval::AstraCredentialBinding,
) {
    use aether::certificates::approval::{AstraCredentialBinding, CredentialState};

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ES256 key");
    let point = key.public_key_raw();
    assert_eq!(point.len(), 65, "uncompressed ES256 point");
    let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose.extend_from_slice(&point[1..33]);
    cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose.extend_from_slice(&point[33..65]);
    let binding = AstraCredentialBinding {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id: vec![serial; 16],
        credential_public_key: cose,
        aaguid: [0; 16],
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        state: CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: NOW - 10,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(ca_private)
    .expect("signed binding");
    (key, binding)
}

/// A credential's real answer to a campaign, as `verify` will check it.
fn assertion_for(
    key: &rcgen::KeyPair,
    binding: &aether::certificates::approval::AstraCredentialBinding,
    campaign: &aether::certificates::status::AstraRotationCampaign,
) -> aether::certificates::status::CredentialAssertion {
    use base64::Engine as _;
    use rcgen::SigningKey as _;

    let mut authenticator_data = Fingerprint::of(b"astra.example").as_bytes().to_vec();
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&1u32.to_be_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://astra.example","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(campaign.fingerprint().as_bytes()),
    )
    .into_bytes();
    let mut message = authenticator_data.clone();
    message.extend_from_slice(Fingerprint::of(&client_data_json).as_bytes());
    let assertion = aether::certificates::webauthn::WebAuthnAssertion {
        authenticator_data,
        client_data_json,
        signature: key.sign(&message).expect("ES256 assertion"),
    };
    aether::certificates::status::CredentialAssertion {
        credential_id: binding.credential_id.clone(),
        credential_fingerprint: binding.fingerprint(),
        assertion_fingerprint: assertion.fingerprint(),
        assertion,
    }
}

/// A deposit Astra has every reason to accept, up to the write. A failed save
/// answers 403 and an identical deposit is to be retried, so memory must still say
/// what the file says: otherwise the status read reports the rotation as held, the
/// operator's vault moves on that word, and a restart of Astra forgets it.
#[tokio::test]
async fn a_failed_save_of_a_deposit_leaves_nothing_in_flight() {
    use aether::certificates::approval::CredentialRegistry;
    use aether::certificates::authority::ClientTlsCaTransition;
    use aether::certificates::capability::{CapabilityGrant, CapabilityScope};
    use aether::certificates::status::{AstraSignerResult, CampaignApproval};
    use aether::certificates::transport::TrustUpdateObject;
    use aether::certificates::window::TransitionWindow;

    let dir = tempfile::tempdir().expect("temp dir");
    let active = Fingerprint::of(b"client tls ca");
    let (mut built, ca_private) = build_service_with_ca(dir.path(), Some(active), None);
    let (first_key, first) = approving_credential(&ca_private, 1);
    let (second_key, second) = approving_credential(&ca_private, 2);
    let registry = CredentialRegistry {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        ca_epoch: 1,
        credential_registry_epoch: 1,
        bindings: vec![first.clone(), second.clone()],
    };
    built.approval_credentials = RwLock::new(Arc::new(crate::service::ApprovalCredentials {
        ids: vec![first.credential_id.clone(), second.credential_id.clone()],
        epoch: 1,
        registry: Some(Box::new(registry)),
    }));
    let service = Arc::new(built);

    let opened = opened(
        service
            .door(
                console(),
                DoorRequest::TrustAuthorities { text: text() },
                NOW,
            )
            .await,
    );
    let campaign = campaign_of(&service, &opened).await;
    let operation_id = opened.operation_id;

    let transition = ClientTlsCaTransition {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        current_ca_tls_epoch: 1,
        next_ca_tls_epoch: 2,
        active_client_tls_ca_fingerprint: active,
        next_client_tls_ca_certificate: aether::certificates::test_x509::client_material(
            "successor",
        )
        .authority,
        window: TransitionWindow::new(NOW, NOW + 1_000, NOW + 2_000).expect("window"),
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("signed transition");
    let incoming = transition.next_client_tls_ca_certificate.fingerprint();
    let result = Box::new(AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(CampaignApproval {
            campaign_id: campaign.campaign_id,
            campaign_fingerprint: campaign.fingerprint(),
            required_credentials: campaign.required_credentials,
            approved_at: NOW,
            approvals: vec![
                assertion_for(&first_key, &first, &campaign),
                assertion_for(&second_key, &second, &campaign),
            ],
        }),
        objects: vec![TrustUpdateObject::ClientTlsCaTransition(Box::new(
            transition,
        ))],
        credential_registry: None,
        issuer_authorization: None,
    });
    let token = {
        let operations = service.signing.lock().await;
        let operation = operations.get(&operation_id, NOW).expect("operation held");
        let grant = CapabilityGrant::new(
            CapabilityScope::SignerResultSubmit,
            operation_id,
            operation.manifest_fingerprint(),
            None,
            NOW,
            NOW + 120,
        )
        .expect("grant");
        service
            .capabilities
            .lock()
            .await
            .issue(&grant, operation.expires_at)
            .expect("token")
    };

    let state_of = || async {
        serde_json::to_vec(service.registry.lock().await.state()).expect("state encoded")
    };
    let before = state_of().await;
    // Something in the way of the rename: the write fails, whoever runs this.
    let registry_path = dir.path().join("registry.json");
    std::fs::remove_file(&registry_path).expect("registry file");
    std::fs::create_dir(&registry_path).expect("in the way");

    let refused = crate::service::operator_signer_result(
        &service,
        &operation_id,
        &token,
        result.clone(),
        NOW,
    )
    .await;

    assert_eq!(refused.err(), Some(crate::service::ServiceError::Refused));
    assert_eq!(state_of().await, before, "memory says what the file says");
    let listener = listen(Arc::clone(&service)).await;
    let (status, body) = read_status(&listener).await;
    assert_eq!(status, 200);
    let report: astra_channel::OperatorAuthorityStatus =
        serde_json::from_slice(&body).expect("the status");
    assert_eq!(report.next_ca_tls_fingerprint, None);

    // The volume comes back: the identical deposit is what was promised to work.
    std::fs::remove_dir(&registry_path).expect("out of the way");
    crate::service::operator_signer_result(&service, &operation_id, &token, result, NOW)
        .await
        .expect("the identical deposit lands");
    let (_, body) = read_status(&listener).await;
    let report: astra_channel::OperatorAuthorityStatus =
        serde_json::from_slice(&body).expect("the status");
    assert_eq!(report.next_ca_tls_fingerprint, Some(incoming));
}
