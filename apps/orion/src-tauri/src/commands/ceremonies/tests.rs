use super::*;
use orion_engine::ProfileView;

const REFUSAL: &str = "Connectez d'abord le profil de la gateway, avec un pair administrateur : \
                       l'admission passe par le tunnel.";

fn profile(name: &str, heliosd_url: Option<&str>) -> ProfileView {
    ProfileView {
        name: name.into(),
        endpoint: "vpn.example.net:51820".into(),
        peer_public_key: String::new(),
        address: None,
        address_v6: None,
        allowed_ips: String::new(),
        persistent_keepalive: 25,
        heliosd_url: heliosd_url.map(str::to_string),
        ssh_target: None,
        dns: None,
        key_negotiation: None,
        mode: "service".into(),
        profile_type: "classic".into(),
        public_key: None,
        has_private_key: false,
        has_static_psk: false,
        ipv6_uncaptured_full_tunnel: false,
    }
}

fn gateway_url(state: &str, view: &ConfigView) -> Result<String, String> {
    gateway_profile(state, view).map(|(url, _)| url)
}

fn view(selected: Option<&str>, profiles: Vec<ProfileView>) -> ConfigView {
    ConfigView {
        profiles,
        selected: selected.map(str::to_string),
        locked: Vec::new(),
        vault_error: None,
    }
}

#[test]
fn no_connected_profile_means_no_gateway_url() {
    let gateway = profile("gateway", Some("http://100.64.0.1:8080"));
    let selected = view(Some("gateway"), vec![gateway.clone()]);

    // Only an established tunnel carries the admission.
    for state in [
        "down",
        "connecting",
        "failed",
        "captive_portal",
        "",
        "garbage",
    ] {
        assert_eq!(
            gateway_url(state, &selected),
            Err(REFUSAL.to_string()),
            "{state}"
        );
    }
    // No selection, a selection that names nothing, and a profile without a
    // control-plane address are each a refusal too.
    assert_eq!(
        gateway_url("up", &view(None, vec![gateway.clone()])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url("up", &view(Some("other"), vec![gateway.clone()])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url("up", &view(Some("bare"), vec![profile("bare", None)])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url(
            "up",
            &view(Some("blank"), vec![profile("blank", Some(" "))])
        ),
        Err(REFUSAL.to_string())
    );
}

#[test]
fn a_connected_profile_gives_its_gateway_url() {
    let selected = view(
        Some("gateway"),
        vec![
            profile("other", Some("http://100.64.0.9:8080")),
            profile("gateway", Some("http://100.64.0.1:8080")),
        ],
    );
    assert_eq!(
        gateway_url("up", &selected),
        Ok("http://100.64.0.1:8080".to_string())
    );
}

fn status(
    gesture: aether::certificates::operator_session::GestureState,
) -> aether::certificates::operator_session::OperatorStatus {
    use aether::certificates::operator_session::{OperationKind, OperatorStatus, RemoteState};
    OperatorStatus::new(
        aether::certificates::encoding::Id16::new([6; 16]).expect("id"),
        3,
        OperationKind::AddKey,
        RemoteState::AwaitingOperator,
        gesture,
    )
}

/// A key-less write waits for the open ceremony to end: that ceremony read
/// the vault before its key and writes it after.
#[test]
fn a_key_less_write_waits_for_the_open_ceremony() {
    use aether::certificates::operator_session::{GestureState, KeyPurpose};

    assert_eq!(no_open_ceremony(None), Ok(()));
    for ended in [
        GestureState::Done,
        GestureState::Cancelled,
        GestureState::Failed,
    ] {
        assert_eq!(no_open_ceremony(Some(&status(ended))), Ok(()), "{ended:?}");
    }
    for open in [
        GestureState::Verifying,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::OpenVault,
        },
        GestureState::ProcessingKey { index: 1, of: 2 },
        GestureState::Signing,
    ] {
        assert_eq!(
            no_open_ceremony(Some(&status(open))),
            Err(CEREMONY_OPEN.to_string()),
            "{open:?}"
        );
    }
}

fn gateway_leaf(subject: &str, key: &str) -> aether::key_negotiation::PqCertificate {
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [9; 16],
        subject: subject.into(),
        issuer: "helios-ca-pq".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: key.into(),
        ml_dsa_87_public_key: String::new(),
        not_before_unix: 0,
        not_after_unix: 1,
        ml_dsa_87_signature: String::new(),
    }
}

fn answered(server_name: &str, key: &str) -> orion_core::enrollment_draft::GatewayMaterial {
    orion_core::enrollment_draft::GatewayMaterial {
        server_name: server_name.into(),
        gateway_ca_der: String::new(),
        gateway_pq_certificate: String::new(),
        wireguard_public_key: key.into(),
        pq_certificate_sha256: String::new(),
        negotiation_port: None,
    }
}

/// The leaf adopted is the tunnel's gateway: its key, the key the gateway
/// answers with and the connected profile's peer key are one, compared as
/// keys and not as strings.
#[test]
fn only_the_tunnel_gateway_is_adopted() {
    use aether::certificates::encoding::WireGuardKey;

    let tunnel = WireGuardKey::from_bytes([0x11; 32]).to_base64();
    let other = WireGuardKey::from_bytes([0x22; 32]).to_base64();
    let name = "gateway.example";
    let refused = Err("la gateway qui répond n'est pas celle du profil connecté".to_string());

    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &tunnel),
            &answered(name, &format!(" {tunnel} ")),
            &format!("{tunnel}\n"),
        ),
        Ok(())
    );
    // Another gateway behind the tunnel, a leaf for another gateway, another
    // name, a key that does not parse.
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &other),
            &answered(name, &other),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &other),
            &answered(name, &tunnel),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf("other.example", &tunnel),
            &answered(name, &tunnel),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, "garbage"),
            &answered(name, "garbage"),
            "garbage"
        ),
        refused
    );
}

#[test]
fn own_key_comes_from_the_domain_profile() {
    use crate::operator::peers::own_key_of;

    let url = "http://100.64.0.1:8080";
    let mut domain = profile("domaine", Some(url));
    domain.public_key = Some(" OWNKEY= ".into());
    let mut other = profile("autre", Some("http://100.64.9.1:8080"));
    other.public_key = Some("OTHERKEY=".into());

    assert_eq!(
        own_key_of(
            &view(Some("domaine"), vec![other.clone(), domain.clone()]),
            Some(url)
        )
        .as_deref(),
        Some("OWNKEY="),
        "the selected profile is the connected one: its public half, trimmed"
    );
    assert_eq!(
        own_key_of(&view(Some("domaine"), vec![domain.clone()]), None),
        None,
        "no connected gateway, no key"
    );
    assert_eq!(
        own_key_of(
            &view(Some("autre"), vec![domain.clone(), other.clone()]),
            Some(url)
        ),
        None,
        "a selected profile that is not the connected one shows no key"
    );
    domain.public_key = None;
    assert_eq!(
        own_key_of(&view(Some("domaine"), vec![domain]), Some(url)),
        None
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Query {
    State,
    Config,
}

async fn engine_replies(
    replies: impl IntoIterator<Item = (Query, Result<EngineReply, String>)>,
) -> (EngineClient, tokio::task::JoinHandle<()>) {
    use crate::commands::test_support::scripted_engine;

    let (client, mut engine) = scripted_engine().await;
    let replies: Vec<_> = replies.into_iter().collect();
    let engine = tokio::spawn(async move {
        for (query, reply) in replies {
            engine
                .reply(|command| {
                    let command = match command {
                        EngineCommand::GetState => Query::State,
                        EngineCommand::GetConfig => Query::Config,
                        _ => panic!("unexpected command"),
                    };
                    assert_eq!(command, query);
                    reply
                })
                .await;
        }
    });
    (client, engine)
}

async fn loopback_gateway(
    request_count: usize,
    answer: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback listener");
    let address = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let server = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept().await.expect("loopback request");
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).await.expect("request headers");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            if !answer {
                continue;
            }
            let request_line = String::from_utf8_lossy(&request);
            let path = request_line
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("HTTP request path");
            let body = match path {
                "/api/certificates/operator/pending" => r#"{"operations":[]}"#,
                "/api/certificates/operator/status" => {
                    r#"{"ca_epoch":4,"ca_fingerprint":"ca-pq","ca_tls_epoch":2,"revoked_peers":[]}"#
                }
                "/api/certificates" => {
                    r#"{"now_unix":123,"ca_fingerprint":"ca-pq","ca_epoch":4,"ca_tls_epoch":2,"peers":[{"name":"laptop","wg_public_key":"workstation-key","not_before":1,"not_after":999,"revoked":false,"pending":{}}]}"#
                }
                "/api/network" => {
                    r#"{"wg_public_key":"gateway-key","wg_address":"10.0.0.1","peers":[{"name":"laptop","public_key":"workstation-key","address":"10.0.0.2"}]}"#
                }
                other => panic!("unexpected read-only gateway path: {other}"),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("gateway response");
        }
        })
        .await
        .expect("gateway requests complete within the test deadline");
    });
    (address, server)
}

async fn pending_gateway(status: u16, body: &str) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback listener");
    let address = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let body = body.to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                .await
                .expect("pending request arrives")
                .expect("accept pending request");
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.expect("request headers");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(String::from_utf8_lossy(&request)
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("GET /api/certificates/operator/pending ")));
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            503 => "Unavailable",
            _ => "Test",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("pending response");
        drop(stream);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "a gateway must be read only once per list refresh"
        );
    });
    (address, server)
}

fn pending_operation(reason: &str, byte: char) -> String {
    format!(
        r#"{{"operation_id":"{byte}0000000000000000000000000000000","scope":"fleet_leafs","reason":"{reason}","requested_by":"operator","target_count":2,"required_credentials":1,"campaign_fingerprint":"{}","created_at":10,"expires_at":20}}"#,
        "a".repeat(64)
    )
}

fn selected_profile() -> ConfigView {
    let mut primary = profile("primary", Some(" http://127.0.0.1:1 "));
    primary.peer_public_key = " gateway-key ".into();
    primary.public_key = Some(" workstation-key ".into());
    let mut other = profile("unselected", Some("http://127.0.0.1:2"));
    other.peer_public_key = "another-gateway".into();
    other.public_key = Some("another-workstation".into());
    view(Some("primary"), vec![other, primary])
}

#[tokio::test]
async fn connected_target_resolves_gateway_and_workstation_from_the_same_profile() {
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("up".into()))),
        (Query::Config, Ok(EngineReply::Config(selected_profile()))),
    ])
    .await;

    let target = connected_target_from(&client)
        .await
        .expect("connected target");
    assert_eq!(target.address, "http://127.0.0.1:1");
    assert_eq!(target.peer_key, "gateway-key");
    assert_eq!(target.own_key.as_deref(), Some("workstation-key"));
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn wrong_engine_reply_cannot_supply_a_gateway_target() {
    for replies in [
        vec![(Query::State, Ok(EngineReply::Config(selected_profile())))],
        vec![
            (Query::State, Ok(EngineReply::State("up".into()))),
            (Query::Config, Ok(EngineReply::State("up".into()))),
        ],
    ] {
        let (client, engine) = engine_replies(replies).await;
        let error = connected_target_from(&client)
            .await
            .expect_err("fail closed on mismatched reply");
        assert_eq!(error, unexpected_engine_reply());
        engine.await.expect("scripted engine");
    }
}

#[tokio::test]
async fn domain_defaults_use_only_the_selected_profile_and_refuse_wrong_replies() {
    let mut selected = profile("selected", None);
    selected.endpoint = "VPN.Example.net:443".into();
    let mut other = profile("other", None);
    other.endpoint = "other.example.org".into();
    let (client, engine) = engine_replies([(
        Query::Config,
        Ok(EngineReply::Config(view(
            Some("selected"),
            vec![other, selected],
        ))),
    )])
    .await;

    let defaults = operator_domain_defaults_from(&client)
        .await
        .expect("selected profile defaults");
    assert_eq!(defaults.rp_id.as_deref(), Some("vpn.example.net"));
    engine.await.expect("scripted engine");

    let (client, engine) =
        engine_replies([(Query::Config, Ok(EngineReply::State("up".into())))]).await;
    let error = operator_domain_defaults_from(&client)
        .await
        .expect_err("mismatched engine reply is refused");
    assert_eq!(error, unexpected_engine_reply());
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn pending_operations_deduplicate_gateway_urls_and_return_their_campaigns() {
    let first = pending_operation("first campaign", '1');
    let first_body = format!(r#"{{"operations":[{first}]}}"#);
    let (gateway, server) = pending_gateway(200, &first_body).await;
    let primary = profile("primary", Some(&gateway));
    let duplicate = profile("duplicate", Some(&gateway));
    let (client, engine) = engine_replies([(
        Query::Config,
        Ok(EngineReply::Config(view(None, vec![primary, duplicate]))),
    )])
    .await;

    let pending = operator_pending_operations_from(&client)
        .await
        .expect("deduplicated pending campaigns");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].reason, "first campaign");
    engine.await.expect("scripted engine");
    server.await.expect("one gateway request");
}

#[tokio::test]
async fn pending_operations_aggregate_campaigns_across_gateways_in_profile_order() {
    let first_body = format!(r#"{{"operations":[{}]}}"#, pending_operation("first", '1'));
    let second_body = format!(r#"{{"operations":[{}]}}"#, pending_operation("second", '2'));
    let (first, first_server) = pending_gateway(200, &first_body).await;
    let (second, second_server) = pending_gateway(200, &second_body).await;
    let (client, engine) = engine_replies([(
        Query::Config,
        Ok(EngineReply::Config(view(
            None,
            vec![
                profile("first", Some(&first)),
                profile("second", Some(&second)),
            ],
        ))),
    )])
    .await;

    let pending = operator_pending_operations_from(&client)
        .await
        .expect("campaigns from both gateways");
    assert_eq!(
        pending
            .iter()
            .map(|item| item.reason.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    engine.await.expect("scripted engine");
    first_server.await.expect("first gateway request");
    second_server.await.expect("second gateway request");
}

#[tokio::test]
async fn pending_operations_keep_reachable_campaigns_when_another_gateway_refuses() {
    let success_body = format!(
        r#"{{"operations":[{}]}}"#,
        pending_operation("available", '3')
    );
    let (refusing, refusing_server) = pending_gateway(403, "{}").await;
    let (available, available_server) = pending_gateway(200, &success_body).await;
    let (client, engine) = engine_replies([(
        Query::Config,
        Ok(EngineReply::Config(view(
            None,
            vec![
                profile("refusing", Some(&refusing)),
                profile("available", Some(&available)),
            ],
        ))),
    )])
    .await;

    let pending = operator_pending_operations_from(&client)
        .await
        .expect("partial results are still readable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].reason, "available");
    engine.await.expect("scripted engine");
    refusing_server.await.expect("refusal response");
    available_server.await.expect("successful response");
}

#[tokio::test]
async fn pending_operations_return_empty_when_all_gateways_refuse_or_are_unreachable() {
    let (refusing, refusing_server) = pending_gateway(503, "{}").await;
    let (offline, offline_server) = loopback_gateway(1, false).await;
    let (client, engine) = engine_replies([(
        Query::Config,
        Ok(EngineReply::Config(view(
            None,
            vec![
                profile("refusing", Some(&refusing)),
                profile("offline", Some(&offline)),
            ],
        ))),
    )])
    .await;

    let pending = operator_pending_operations_from(&client)
        .await
        .expect("unreachable gateways mean nothing pending");
    assert!(pending.is_empty());
    engine.await.expect("scripted engine");
    refusing_server.await.expect("refusal response");
    offline_server.await.expect("dropped gateway connection");
}

#[tokio::test]
async fn pending_operations_refuse_a_mismatched_engine_reply() {
    let (client, engine) =
        engine_replies([(Query::Config, Ok(EngineReply::State("up".into())))]).await;
    let error = operator_pending_operations_from(&client)
        .await
        .expect_err("wrong reply is refused");
    assert_eq!(error, unexpected_engine_reply());
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn rotations_still_report_the_local_vault_when_the_gateway_is_offline() {
    use orion_core::operator_rotations::Reach;

    let domain = astra_operator::operations::fixtures::domain();
    let vault_bytes = std::fs::read(&domain.path).expect("fixture vault");
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("down".into()))),
        (Query::Config, Ok(EngineReply::Config(selected_profile()))),
    ])
    .await;
    let overview = rotations_overview(&client, Ok(domain.path.clone()))
        .await
        .expect("offline overview");

    assert!(!overview.tunnel);
    assert!(matches!(overview.pending, Reach::Unreachable));
    assert!(matches!(overview.authority, Reach::Unreachable));
    assert!(matches!(overview.domain, Reach::Unreachable));
    assert!(overview.vault_error.is_none());
    let vault = overview.vault.expect("public vault overview");
    assert!(vault.bootstrapped);
    assert!(vault.credentials_complete);
    assert_eq!(vault.slots.len(), domain.keys.len());
    assert_eq!(domain.touches(), 0);
    assert_eq!(
        std::fs::read(&domain.path).expect("unchanged vault"),
        vault_bytes
    );
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn rotations_preserve_an_invalid_vault_location_as_a_separate_error() {
    let (client, engine) = engine_replies([(Query::State, Err("engine unavailable".into()))]).await;
    let overview = rotations_overview(&client, Err("invalid path".into()))
        .await
        .expect("partial overview");

    assert!(!overview.tunnel);
    assert!(overview.vault.is_none());
    assert_eq!(overview.vault_error, Some("emplacement"));
    engine.await.expect("scripted engine");

    let domain = astra_operator::operations::fixtures::domain();
    let unreadable = domain.path.with_file_name("unreadable.vault");
    std::fs::write(&unreadable, b"not a vault").expect("invalid vault fixture");
    let (client, engine) = engine_replies([(Query::State, Err("engine unavailable".into()))]).await;
    let overview = rotations_overview(&client, Ok(unreadable.clone()))
        .await
        .expect("partial overview");

    assert!(!overview.tunnel);
    assert!(overview.vault.is_none());
    assert_eq!(overview.vault_error, Some("illisible"));
    std::fs::remove_file(unreadable).expect("remove invalid vault fixture");
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn rotations_keep_the_selected_loopback_gateway_but_refuse_unreachable_reads() {
    use orion_core::operator_rotations::Reach;

    let mut fixture = selected_profile();
    let (gateway, server) = loopback_gateway(4, false).await;
    fixture.profiles[1].heliosd_url = Some(gateway);
    let domain = astra_operator::operations::fixtures::domain();
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("up".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture))),
    ])
    .await;

    let overview = rotations_overview(&client, Ok(domain.path.clone()))
        .await
        .expect("partial overview");

    assert!(overview.tunnel);
    assert!(matches!(overview.pending, Reach::Unreachable));
    assert!(matches!(overview.authority, Reach::Unreachable));
    assert!(matches!(overview.domain, Reach::Unreachable));
    assert!(matches!(overview.workstations, Reach::Unreachable));
    assert!(overview.vault_error.is_none());
    assert!(overview.vault.is_some());
    assert_eq!(domain.touches(), 0);
    server.await.expect("loopback server");
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn rotations_show_valid_loopback_reads_without_opening_vault_keys() {
    use orion_core::operator_rotations::Reach;

    let mut fixture = selected_profile();
    let (gateway, server) = loopback_gateway(4, true).await;
    fixture.profiles[1].heliosd_url = Some(gateway);
    let domain = astra_operator::operations::fixtures::domain();
    let vault_bytes = std::fs::read(&domain.path).expect("fixture vault");
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("up".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture))),
    ])
    .await;

    let overview = rotations_overview(&client, Ok(domain.path.clone()))
        .await
        .expect("overview from read-only responses");

    assert!(overview.tunnel);
    assert!(matches!(overview.pending, Reach::Ok(ref pending) if pending.is_empty()));
    assert!(matches!(overview.authority, Reach::Ok(ref status) if status.ca_epoch == 4));
    assert!(matches!(overview.domain, Reach::Ok(ref view) if view.ca_epoch == 4));
    assert!(matches!(overview.workstations, Reach::Ok(ref peers)
        if peers.len() == 1 && peers[0].name == "laptop" && peers[0].not_after == 999));
    assert!(overview.vault.is_some());
    assert_eq!(domain.touches(), 0);
    assert_eq!(
        std::fs::read(&domain.path).expect("unchanged fixture vault"),
        vault_bytes
    );
    server.await.expect("loopback server");
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn peers_without_a_tunnel_show_neither_gateway_data_nor_a_workstation_key() {
    use orion_core::operator_rotations::Reach;

    let fixture = selected_profile();
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("down".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture.clone()))),
    ])
    .await;
    let overview = peers_overview(&client, &fixture, Err("invalid path".into()))
        .await
        .expect("partial overview");

    assert!(matches!(overview.certificates, Reach::Unreachable));
    assert!(matches!(overview.admitted, Reach::Unreachable));
    assert!(matches!(overview.astra_revoked, Reach::Unreachable));
    assert!(matches!(overview.pending_revocations, Reach::Unreachable));
    assert!(overview.local_pending.is_none());
    assert!(overview.own_key.is_none());
    assert!(overview.now_unix.is_none());
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn peers_keep_the_connected_profile_key_when_its_loopback_gateway_refuses_reads() {
    use orion_core::operator_rotations::Reach;

    let mut fixture = selected_profile();
    let (gateway, server) = loopback_gateway(4, false).await;
    fixture.profiles[1].heliosd_url = Some(gateway);
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("up".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture.clone()))),
    ])
    .await;

    let overview = peers_overview(&client, &fixture, Err("invalid path".into()))
        .await
        .expect("partial overview");

    assert!(matches!(overview.certificates, Reach::Unreachable));
    assert!(matches!(overview.admitted, Reach::Unreachable));
    assert!(matches!(overview.astra_revoked, Reach::Unreachable));
    assert!(matches!(overview.pending_revocations, Reach::Unreachable));
    assert_eq!(overview.own_key.as_deref(), Some("workstation-key"));
    assert!(overview.now_unix.is_none());
    assert!(overview.local_pending.is_none());
    server.await.expect("loopback server");
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn peers_show_valid_loopback_reads_and_only_public_peer_data() {
    use orion_core::operator_rotations::Reach;

    let mut fixture = selected_profile();
    let (gateway, server) = loopback_gateway(4, true).await;
    fixture.profiles[1].heliosd_url = Some(gateway);
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("up".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture.clone()))),
    ])
    .await;

    let overview = peers_overview(&client, &fixture, Err("invalid path".into()))
        .await
        .expect("overview from read-only responses");

    assert!(
        matches!(overview.certificates, Reach::Ok(ref peers) if peers.len() == 1 && peers[0].name == "laptop")
    );
    assert!(
        matches!(overview.admitted, Reach::Ok(ref peers) if peers.len() == 1 && peers[0].name == "laptop")
    );
    assert!(matches!(overview.astra_revoked, Reach::Ok(ref keys) if keys.is_empty()));
    assert!(matches!(overview.pending_revocations, Reach::Ok(ref keys) if keys.is_empty()));
    assert_eq!(overview.own_key.as_deref(), Some("workstation-key"));
    assert_eq!(overview.now_unix, Some(123));
    assert!(overview.local_pending.is_none());
    server.await.expect("loopback server");
    engine.await.expect("scripted engine");
}

#[tokio::test]
async fn reading_peers_offline_does_not_create_a_missing_vault_directory() {
    let domain = astra_operator::operations::fixtures::domain();
    let directory = domain.path.with_file_name("missing");
    let missing = directory.join("authority-vault.json");
    let fixture = selected_profile();
    let (client, engine) = engine_replies([
        (Query::State, Ok(EngineReply::State("down".into()))),
        (Query::Config, Ok(EngineReply::Config(fixture.clone()))),
    ])
    .await;

    let overview = peers_overview(&client, &fixture, Ok(missing))
        .await
        .expect("offline overview");

    assert!(overview.local_pending.is_none());
    assert!(overview.own_key.is_none());
    assert!(!directory.exists());
    engine.await.expect("scripted engine");
}
