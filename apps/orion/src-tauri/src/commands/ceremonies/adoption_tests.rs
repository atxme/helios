use super::*;
use crate::commands::test_support::gateway_test_profile;
use aether::certificates::encoding::WireGuardKey;
use orion_engine::{client::EngineClient, ProfileView};

async fn engine_for(
    state: &str,
    profile: ProfileView,
) -> (EngineClient, tokio::task::JoinHandle<()>) {
    let (client, mut engine) = crate::commands::test_support::scripted_engine().await;
    let state = state.to_string();
    let task = tokio::spawn(async move {
        engine
            .reply(|command| match command {
                EngineCommand::GetState => Ok(EngineReply::State(state)),
                _ => panic!("expected tunnel state"),
            })
            .await;
        engine
            .reply(|command| match command {
                EngineCommand::GetConfig => Ok(EngineReply::Config(ConfigView {
                    profiles: vec![profile],
                    selected: Some("gateway".into()),
                    locked: Vec::new(),
                    vault_error: None,
                })),
                _ => panic!("expected profile configuration"),
            })
            .await;
    });
    (client, task)
}

async fn gateway_http(
    leaf: &aether::key_negotiation::PqCertificate,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let network_key = leaf.wireguard_public_key.clone();
    let server_name = leaf.subject.clone();
    let leaf_json = serde_json::to_string(leaf).expect("leaf JSON");
    let server = tokio::spawn(async move {
        for path in ["/api/network", "/api/key-negotiation"] {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .expect("gateway request deadline")
                    .expect("gateway request");
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).await.expect("request headers");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            let request_line = String::from_utf8_lossy(&request);
            assert!(request_line
                .lines()
                .next()
                .is_some_and(|line| line.split_whitespace().nth(1) == Some(path)));
            let body = if path == "/api/network" {
                serde_json::json!({
                    "wg_public_key": network_key,
                    "wg_address": "100.64.0.1",
                    "peers": []
                })
                .to_string()
            } else {
                serde_json::json!({
                    "port": 443,
                    "server_name": server_name,
                    "gateway_ca_der": "",
                    "gateway_pq_certificate": leaf_json,
                    "pq_certificate_sha256": "",
                    "wireguard_public_key": network_key
                })
                .to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response");
        }
    });
    (address, server)
}

async fn signed_leaf(
    domain: &astra_operator::operations::fixtures::Domain,
) -> aether::key_negotiation::PqCertificate {
    use aether::certificates::webauthn::SALT_LEN;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    use astra_operator::authenticator::Authenticator;
    use base64::Engine as _;

    let credential = domain.keys[0].credential_id();
    let vault = astra_operator::store::load(&domain.path).expect("fixture vault");
    let salt: [u8; SALT_LEN] = base64::engine::general_purpose::STANDARD
        .decode(&vault.salt)
        .expect("vault salt")
        .try_into()
        .expect("fixed-length salt");
    let opened = domain.keys[0]
        .derive(&vault.rp_id, std::slice::from_ref(&credential), &salt, "")
        .expect("fixture security key opens its slot");
    let secrets = vault
        .open(&credential, &opened.secret)
        .expect("fixture vault opens");
    let ca_private = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(&secrets.ca_pq_private_key)
            .expect("fixture CA-PQ key"),
    );
    let certificate = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [0x37; 16],
        subject: "gateway.helios.test".into(),
        issuer: "helios-ca-pq".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: astra_operator::operations::fixtures::gateway_key().to_base64(),
        ml_dsa_87_public_key: vault.ca_pq_public_key.clone(),
        not_before_unix: 0,
        not_after_unix: 4_000_000_000,
        ml_dsa_87_signature: String::new(),
    };
    on_work_stack("orion-test-gateway-leaf", "signature fixture", move || {
        aether::key_negotiation::issue_pq_certificate(certificate, &ca_private)
            .map_err(|error| error.to_string())
    })
    .await
    .expect("signed fixture leaf")
}

#[tokio::test]
async fn adoption_fetches_and_verifies_the_signed_gateway_leaf_before_recording_it() {
    let domain = astra_operator::operations::fixtures::domain();
    let mut relay = domain.relay();
    let relay_path = astra_operator::handoff::path_beside(&domain.path);
    relay.gateway_wg_public_key = None;
    relay.server_name = None;
    astra_operator::handoff::save(&relay_path, &relay).expect("unbound relay");
    let leaf = signed_leaf(&domain).await;
    let (gateway, server) = gateway_http(&leaf).await;
    let peer_key = leaf.wireguard_public_key.clone();
    let (engine, engine_task) = engine_for("up", gateway_test_profile(&gateway, peer_key)).await;

    adopt_connected_gateway_from(&engine, domain.path.clone())
        .await
        .expect("the signed leaf of the connected gateway is adopted");

    server.await.expect("gateway server");
    engine_task.await.expect("scripted engine");
    let relay = astra_operator::handoff::load(&relay_path).expect("updated relay");
    assert_eq!(relay.server_name.as_deref(), Some(leaf.subject.as_str()));
    assert_eq!(
        relay.gateway_wg_public_key.as_deref(),
        Some(leaf.wireguard_public_key.as_str())
    );
}

#[tokio::test]
async fn adoption_refuses_a_leaf_that_does_not_name_the_connected_profile_key() {
    let domain = astra_operator::operations::fixtures::domain();
    let leaf = signed_leaf(&domain).await;
    let (gateway, server) = gateway_http(&leaf).await;
    let other_key = WireGuardKey::from_bytes([0x62; 32]).to_base64();
    let (engine, engine_task) = engine_for("up", gateway_test_profile(&gateway, other_key)).await;
    let before = std::fs::read(astra_operator::handoff::path_beside(&domain.path))
        .expect("relay before adoption");

    let error = adopt_connected_gateway_from(&engine, domain.path.clone())
        .await
        .expect_err("another tunnel identity is refused");

    assert!(error.contains("la gateway qui répond n'est pas celle du profil connecté"));
    assert_eq!(
        std::fs::read(astra_operator::handoff::path_beside(&domain.path))
            .expect("relay after refusal"),
        before
    );
    server.await.expect("gateway server");
    engine_task.await.expect("scripted engine");
}

#[tokio::test]
async fn adoption_stops_before_http_when_the_tunnel_is_not_up() {
    let domain = astra_operator::operations::fixtures::domain();
    let peer_key = astra_operator::operations::fixtures::gateway_key().to_base64();
    let (engine, engine_task) = engine_for(
        "connecting",
        gateway_test_profile("http://127.0.0.1:1", peer_key),
    )
    .await;

    let error = adopt_connected_gateway_from(&engine, domain.path.clone())
        .await
        .expect_err("a tunnel that is not up cannot carry adoption");

    assert_eq!(error, NO_CONNECTED_GATEWAY);
    engine_task.await.expect("scripted engine");
}

#[tokio::test]
async fn adoption_rejects_a_tampered_leaf_for_the_connected_key_without_writing() {
    let domain = astra_operator::operations::fixtures::domain();
    let mut leaf = signed_leaf(&domain).await;
    leaf.serial[0] ^= 1;
    let (gateway, server) = gateway_http(&leaf).await;
    let (engine, engine_task) = engine_for(
        "up",
        gateway_test_profile(&gateway, leaf.wireguard_public_key),
    )
    .await;
    let relay_path = astra_operator::handoff::path_beside(&domain.path);
    let before = std::fs::read(&relay_path).expect("relay before adoption");

    let error = adopt_connected_gateway_from(&engine, domain.path.clone())
        .await
        .expect_err("a leaf with a modified signed field is refused");

    assert!(
        error.contains("ne vérifie pas sous le CA-PQ du domaine"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&relay_path).expect("relay after refusal"),
        before
    );
    server.await.expect("gateway server");
    engine_task.await.expect("scripted engine");
}
