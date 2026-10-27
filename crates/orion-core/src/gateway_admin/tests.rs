use super::*;
use aether::certificates::encoding::DerCertificate;
use aether::key_negotiation::{
    generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
    PQ_CERTIFICATE_VERSION,
};
use base64::engine::general_purpose::STANDARD;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const GATEWAY_KEY: &str = "GatewayKeyGatewayKeyGatewayKeyGatewayKey000=";
const CLIENT_KEY: &str = "ClientKeyClientKeyClientKeyClientKeyClie0000=";

struct Leaves {
    tls: DerCertificate,
    pq: PqCertificate,
}

fn leaves() -> Leaves {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["poste".to_string()]).unwrap();
    let tls = DerCertificate::new(params.self_signed(&key).unwrap().der().to_vec()).unwrap();
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (_, leaf_public) = generate_ml_dsa_87_keypair().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pq = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [5; 16],
            subject: "poste".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: CLIENT_KEY.into(),
            ml_dsa_87_public_key: STANDARD.encode(leaf_public),
            not_before_unix: now - 60,
            not_after_unix: now + 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &ca_private,
    )
    .unwrap();
    Leaves { tls, pq }
}

fn admission_of(leaves: &Leaves) -> PeerAdmission {
    PeerAdmission {
        name: "poste d'alice".into(),
        public_key: CLIENT_KEY.into(),
        admin: false,
        minimum_key_negotiation_mode: ProtectionMode::MlKem,
        key_negotiation_certificate: STANDARD.encode(leaves.tls.as_bytes()),
        key_negotiation_pq_certificate: STANDARD.encode(serde_json::to_vec(&leaves.pq).unwrap()),
    }
}

fn admission() -> PeerAdmission {
    admission_of(&leaves())
}

/// The body the gateway's `PeerAdmitRequest` reads (`helios-api`, route
/// `POST /api/peers`): its field names are frozen here because that crate keeps
/// its `routes` module private, so its type cannot be deserialized from this
/// one. The two digests are what the gateway recomputes from the leaves and
/// compares before it records anything.
#[test]
fn the_admission_body_matches_the_gateway_contract() {
    let leaves = leaves();
    let admission = admission_of(&leaves);
    let body: serde_json::Value =
        serde_json::from_slice(&admission_body(&admission).unwrap()).unwrap();
    let expected = serde_json::json!({
        "name": "poste d'alice",
        "public_key": CLIENT_KEY,
        "admin": false,
        "minimum_key_negotiation_mode": "ml_kem",
        "key_negotiation_certificate": admission.key_negotiation_certificate,
        "key_negotiation_pq_certificate": admission.key_negotiation_pq_certificate,
        "key_negotiation_certificate_sha256": leaves.tls.fingerprint().to_hex(),
        "key_negotiation_pq_certificate_sha256":
            aether::certificates::gateway::pq_certificate_fingerprint(&leaves.pq)
                .unwrap()
                .to_hex(),
    });
    assert_eq!(body, expected);
}

#[test]
fn an_admission_with_unreadable_leaves_is_refused_before_any_request() {
    let mut broken = admission();
    broken.key_negotiation_certificate = "not base64 !".into();
    assert!(matches!(
        admission_body(&broken),
        Err(GatewayAdminError::Invalid(_))
    ));
    let mut broken = admission();
    broken.key_negotiation_pq_certificate = STANDARD.encode(b"{}");
    assert!(matches!(
        admission_body(&broken),
        Err(GatewayAdminError::Invalid(_))
    ));
}

#[test]
fn the_status_decides_the_error() {
    assert_eq!(status_error(401, b""), GatewayAdminError::Forbidden);
    assert_eq!(status_error(403, b""), GatewayAdminError::Forbidden);
    assert_eq!(
        status_error(409, b"name taken"),
        GatewayAdminError::Refused {
            status: 409,
            reason: Some("name taken".into())
        }
    );
    assert_eq!(
        status_error(500, b""),
        GatewayAdminError::Refused {
            status: 500,
            reason: None
        }
    );
}

#[test]
fn a_forbidden_admission_names_the_admin_flag() {
    let message = GatewayAdminError::Forbidden.to_string();
    assert!(message.contains("`admin`"), "{message}");
    assert!(message.contains("pair"), "{message}");
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

type Routes = Vec<(&'static str, u16, String)>;

/// A gateway that answers from a table and records every request line.
async fn fake_gateway(routes: Routes) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let address = listener.local_addr().expect("address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                request.extend_from_slice(&chunk[..read]);
                if read == 0 || request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&request).into_owned();
            let line = text.lines().next().unwrap_or_default().to_string();
            recorded.lock().expect("lock").push(line.clone());
            let path = line.split_whitespace().nth(1).unwrap_or_default();
            let (status, body) = routes
                .iter()
                .find(|(route, _, _)| *route == path)
                .map(|(_, status, body)| (*status, body.clone()))
                .unwrap_or((404, String::new()));
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{address}"), seen)
}

#[tokio::test]
async fn an_unreachable_gateway_is_its_own_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let base = format!("http://127.0.0.1:{port}");
    assert_eq!(
        admitted_keys(&client(), &base).await.unwrap_err(),
        GatewayAdminError::Unreachable
    );
    assert_eq!(
        admit_peer(&client(), &base, &admission())
            .await
            .unwrap_err(),
        GatewayAdminError::Unreachable
    );
}

#[tokio::test]
async fn a_gateway_refusing_the_peer_is_forbidden() {
    let (base, _) = fake_gateway(vec![("/api/peers", 403, "secret detail".into())]).await;
    let error = admit_peer(&client(), &base, &admission())
        .await
        .unwrap_err();
    assert_eq!(error, GatewayAdminError::Forbidden);
    assert!(!format!("{error:?}{error}").contains("secret detail"));
}

#[tokio::test]
async fn an_admission_the_gateway_accepts_returns_nothing() {
    let (base, seen) = fake_gateway(vec![("/api/peers", 200, "{}".into())]).await;
    admit_peer(&client(), &format!("{base}/"), &admission())
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["POST /api/peers HTTP/1.1"]
    );
}

#[tokio::test]
async fn the_admitted_keys_are_those_of_the_peers() {
    let network = serde_json::json!({
        "wg_public_key": GATEWAY_KEY, "wg_address": "100.64.0.1/10",
        "peers": [
            {"public_key": "AAA", "address": "100.64.1.2/32"},
            {"public_key": " BBB ", "address": "100.64.1.3/32"}
        ]
    });
    let (base, _) = fake_gateway(vec![("/api/network", 200, network.to_string())]).await;
    assert_eq!(
        admitted_keys(&client(), &base).await.unwrap(),
        ["AAA", "BBB"]
    );
}

fn negotiation_view(bound_to: &str) -> String {
    serde_json::json!({
        "port": 51821, "server_name": "vpn.example.net",
        "gateway_ca_der": "Y2E=", "gateway_pq_certificate": "cHE=",
        "pq_certificate_sha256": "sha", "wireguard_public_key": bound_to
    })
    .to_string()
}

fn network_view(wg_public_key: Option<&str>) -> String {
    serde_json::json!({
        "wg_public_key": wg_public_key, "wg_address": "100.64.0.1/10",
        "peers": [{"public_key": CLIENT_KEY, "address": "100.64.1.2/32",
                   "address_v6": " "}]
    })
    .to_string()
}

#[tokio::test]
async fn the_negotiation_needs_no_client_key() {
    let (base, seen) = fake_gateway(vec![
        ("/api/network", 200, network_view(Some(GATEWAY_KEY))),
        ("/api/key-negotiation", 200, negotiation_view(GATEWAY_KEY)),
    ])
    .await;
    let material = gateway_negotiation(&client(), &base).await.unwrap();
    assert_eq!(material.server_name, "vpn.example.net");
    assert_eq!(material.negotiation_port, Some(51821));
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_certificate_bound_to_another_identity_is_refused() {
    let (base, _) = fake_gateway(vec![
        ("/api/network", 200, network_view(Some(GATEWAY_KEY))),
        ("/api/key-negotiation", 200, negotiation_view("Other")),
    ])
    .await;
    assert!(matches!(
        gateway_negotiation(&client(), &base).await,
        Err(GatewayAdminError::Invalid(_))
    ));
    let (base, _) = fake_gateway(vec![
        ("/api/network", 200, network_view(None)),
        ("/api/key-negotiation", 200, negotiation_view(GATEWAY_KEY)),
    ])
    .await;
    assert!(matches!(
        gateway_negotiation(&client(), &base).await,
        Err(GatewayAdminError::Invalid(_))
    ));
}

#[tokio::test]
async fn the_material_names_the_peer_and_tolerates_a_missing_trust_block() {
    let trust_path: &'static str =
        "/api/key-negotiation/trust-enrolment/ClientKeyClientKeyClientKeyClientKeyClie0000%3D";
    let (base, _) = fake_gateway(vec![
        ("/api/network", 200, network_view(Some(GATEWAY_KEY))),
        ("/api/key-negotiation", 200, negotiation_view(GATEWAY_KEY)),
        (trust_path, 404, String::new()),
    ])
    .await;
    let (material, admission) = gateway_material(&client(), &base, CLIENT_KEY)
        .await
        .unwrap();
    assert_eq!(material.wireguard_public_key, GATEWAY_KEY);
    assert_eq!(admission.address, "100.64.1.2/32");
    assert_eq!(admission.address_v6, None);
    assert_eq!(
        admission.heliosd_url.as_deref(),
        Some(format!("http://100.64.0.1:{}", aether::API_PORT).as_str())
    );
    assert!(admission.trust.is_none());

    let error = gateway_material(&client(), &base, "UnknownKey")
        .await
        .err()
        .unwrap();
    assert!(matches!(error, GatewayAdminError::Invalid(_)), "{error:?}");
}

#[test]
fn a_reason_is_bounded_and_stripped_of_control_characters() {
    let long = "x".repeat(500);
    let reason = reason_of(format!("  peer\u{1b}[31m {long}\n").as_bytes()).unwrap();
    assert_eq!(reason.chars().count(), MAX_REASON_CHARS);
    assert!(reason.starts_with("peer[31m x"), "{reason}");
    assert_eq!(reason_of(b" \n "), None);
}

#[tokio::test]
async fn a_conflicting_admission_shows_the_gateways_reason() {
    let (base, _) = fake_gateway(vec![(
        "/api/peers",
        409,
        "peer name 'alice' is already taken".into(),
    )])
    .await;
    let error = admit_peer(&client(), &base, &admission())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        GatewayAdminError::Refused {
            status: 409,
            reason: Some("peer name 'alice' is already taken".into())
        }
    );
    assert_eq!(
        error.to_string(),
        "La gateway a refusé la demande (HTTP 409) : peer name 'alice' is already taken"
    );
}

/// The caller's client is the one that talks: its default header reaches the
/// gateway, which a client built inside the module could never carry.
#[tokio::test]
async fn the_callers_client_is_the_one_used() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"peers\":[],\"wg_address\":\"\"}")
            .await
            .unwrap();
        String::from_utf8_lossy(&buffer[..read]).to_ascii_lowercase()
    });
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-caller-client", "marker".parse().unwrap());
    let caller = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    let _ = admitted_keys(&caller, &base).await;
    assert!(server.await.unwrap().contains("x-caller-client: marker"));
}
