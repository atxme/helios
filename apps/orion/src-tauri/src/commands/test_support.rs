use orion_engine::client::{connect, EngineClient};
use orion_engine::session::{accept_hello, SessionToken};
use orion_engine::{
    limits, read_frame, write_frame, ClientFrame, EngineCommand, EngineFrame, EngineReply,
    ProfileView,
};
use std::time::Duration;
use tokio::{
    io::{
        AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream,
        ReadHalf, WriteHalf,
    },
    net::TcpListener,
};

pub(super) struct ScriptedEngine {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: WriteHalf<DuplexStream>,
}

/// Opens an authenticated, framed engine session without starting a process.
pub(super) async fn scripted_engine() -> (EngineClient, ScriptedEngine) {
    let token = SessionToken::parse(&"a".repeat(64)).expect("fixture session token");
    let (ui, engine) = tokio::io::duplex(8192);
    let (client, _events) = connect(ui, &token).await.expect("start IPC client");
    let (reader, writer) = tokio::io::split(engine);
    let mut reader = BufReader::new(reader);
    accept_hello(&mut reader, &token)
        .await
        .expect("client hello");
    (client, ScriptedEngine { reader, writer })
}

impl ScriptedEngine {
    pub(super) async fn reply(
        &mut self,
        respond: impl FnOnce(EngineCommand) -> Result<EngineReply, String>,
    ) {
        let frame = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame::<_, ClientFrame>(&mut self.reader, limits::REQUEST_BYTES),
        )
        .await
        .expect("command arrives within test deadline")
        .expect("read command")
        .expect("client still connected");
        let ClientFrame::Request { id, command } = frame else {
            panic!("expected a command after the initial hello");
        };
        let result = respond(*command);
        write_frame(
            &mut self.writer,
            &EngineFrame::Reply {
                id,
                result: result.map(Box::new),
            },
            limits::REPLY_BYTES,
        )
        .await
        .expect("send reply");
    }
}

pub(super) async fn answer_gateway(
    listener: &TcpListener,
    method_and_path: &str,
    status: &str,
    body: &str,
) -> Vec<u8> {
    let (mut stream, _) = listener.accept().await.expect("gateway request");
    let mut reader = BufReader::new(&mut stream);
    let mut headers = String::new();
    loop {
        assert_ne!(reader.read_line(&mut headers).await.unwrap(), 0);
        if headers.ends_with("\r\n\r\n") {
            break;
        }
    }
    assert!(headers.starts_with(method_and_path), "{headers}");
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| {
            value.trim().parse().expect("content length")
        });
    let mut request = vec![0; length];
    reader.read_exact(&mut request).await.unwrap();
    stream.write_all(format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    ).as_bytes()).await.unwrap();
    request
}

pub(super) fn gateway_test_profile(url: &str, peer_key: String) -> ProfileView {
    ProfileView {
        name: "gateway".into(),
        endpoint: "gateway.example:51820".into(),
        peer_public_key: peer_key,
        address: None,
        address_v6: None,
        allowed_ips: "0.0.0.0/0".into(),
        persistent_keepalive: 25,
        heliosd_url: Some(url.into()),
        ssh_target: None,
        key_negotiation: None,
        mode: "service".into(),
        profile_type: "classic".into(),
        public_key: None,
        has_private_key: false,
        has_static_psk: false,
        ipv6_uncaptured_full_tunnel: false,
        dns: None,
    }
}

/// Builds Tauri command state with a chosen fixture vault and a scripted connected profile.
#[cfg(not(windows))]
pub(super) async fn app_with_gateway(
    domain: &astra_operator::operations::fixtures::Domain,
    gateway: &TcpListener,
    peer_key: aether::certificates::encoding::WireGuardKey,
    lookups: usize,
) -> (
    tauri::App<tauri::test::MockRuntime>,
    tokio::task::JoinHandle<()>,
) {
    use crate::{operator::location::VaultLocation, AppState};
    use orion_engine::ConfigView;
    use std::sync::Arc;
    use tauri::Manager;

    let (client, mut engine) = scripted_engine().await;
    let base = format!("http://{}", gateway.local_addr().expect("gateway address"));
    let profile = gateway_test_profile(&base, peer_key.to_base64());
    let engine_task = tokio::spawn(async move {
        for _ in 0..lookups {
            engine
                .reply(|command| match command {
                    EngineCommand::GetState => Ok(EngineReply::State("up".into())),
                    _ => panic!("expected tunnel state"),
                })
                .await;
            engine
                .reply(|command| match command {
                    EngineCommand::GetConfig => Ok(EngineReply::Config(ConfigView {
                        selected: Some(profile.name.clone()),
                        profiles: vec![profile.clone()],
                        locked: Vec::new(),
                        vault_error: None,
                    })),
                    _ => panic!("expected profile configuration"),
                })
                .await;
        }
    });
    let vault_location = VaultLocation::at(domain.path.with_file_name("orion-vault-settings.json"));
    vault_location
        .choose(domain.path.clone())
        .expect("choose fixture vault");
    let app = tauri::test::mock_app();
    assert!(app.manage(AppState {
        client,
        vault_location,
        operator: Default::default(),
        chain_opened: Arc::default(),
        pending_profile_paths: Default::default(),
        quitting: Default::default(),
        tunnel_taken_down: Default::default(),
        engine_lost: Default::default(),
    }));
    (app, engine_task)
}

#[cfg(not(windows))]
pub(super) async fn wait_for_operator_key(
    operator: &crate::operator::OperatorCeremony,
) -> aether::certificates::operator_session::OperatorStatus {
    use aether::certificates::operator_session::GestureState;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = operator.status().await.expect("active ceremony");
            assert!(!status.gesture.is_terminal(), "{status:?}");
            if matches!(status.gesture, GestureState::AwaitingKey { .. }) {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ceremony waits for a key")
}
