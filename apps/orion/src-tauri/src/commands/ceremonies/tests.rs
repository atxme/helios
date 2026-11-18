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
        key_negotiation: None,
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
    use orion_engine::session::{accept_hello, SessionToken};
    use orion_engine::{limits, read_frame, write_frame, ClientFrame, EngineFrame};

    let token = SessionToken::parse(&"a".repeat(64)).expect("fixture session token");
    let (client, fake) = tokio::io::duplex(8192);
    let (client, _events) = orion_engine::client::connect(client, &token)
        .await
        .expect("start IPC client");
    let replies: Vec<_> = replies.into_iter().collect();
    let engine = tokio::spawn(async move {
        let (reader, mut writer) = tokio::io::split(fake);
        let mut reader = tokio::io::BufReader::new(reader);
        accept_hello(&mut reader, &token)
            .await
            .expect("client hello");
        for (query, reply) in replies {
            let frame = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                read_frame::<_, ClientFrame>(&mut reader, limits::REQUEST_BYTES),
            )
            .await
            .expect("command arrives within test deadline")
            .expect("read command")
            .expect("client still connected");
            let ClientFrame::Request { id, command } = frame else {
                panic!("expected a command after the initial hello");
            };
            let command = match *command {
                EngineCommand::GetState => Query::State,
                EngineCommand::GetConfig => Query::Config,
                _ => panic!("unexpected command"),
            };
            assert_eq!(command, query);
            write_frame(
                &mut writer,
                &EngineFrame::Reply {
                    id,
                    result: reply.map(Box::new),
                },
                limits::REPLY_BYTES,
            )
            .await
            .expect("send reply");
        }
    });
    (client, engine)
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
