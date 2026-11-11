//! Following the gateway live over its WebSocket: `watch`, and the scenarios
//! that drive a transition and wait for the state it should reach.

use super::*;

pub(super) fn ws_url(base: &str) -> String {
    base.replace("http://", "ws://")
        .replace("https://", "wss://")
        + "/ws"
}

// ─── Commands ─────────────────────────────────────────────────────────────────

pub(super) async fn cmd_watch(api: &transport::Api) -> Result<()> {
    let url = ws_url(&api.base);
    println!("\x1b[2m↳ {}\x1b[0m", api.describe());
    #[cfg(unix)]
    if let Some(socket) = &api.socket {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .with_context(|| format!("could not connect to {}", socket.display()))?;
        let (stream, _) = tokio_tungstenite::client_async(url.as_str(), stream)
            .await
            .context("WebSocket handshake over the local socket")?;
        return watch_events(stream).await;
    }
    let (stream, _) = connect_async(&url)
        .await
        .context("could not connect — is heliosd running?")?;
    watch_events(stream).await
}

async fn watch_events<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: WebSocketStream<S>,
) -> Result<()> {
    println!("\x1b[2m↳ connected — Ctrl-C to quit\x1b[0m\n");
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; return Ok(()); }
            message = stream.next() => {
                let Some(message) = message else { return Ok(()); };
                if let Ok(Message::Text(text)) = message {
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    print_ws_event(&hh_mm_ss(), &v);
                }
            }
        }
    }
}

pub(super) fn print_ws_event(ts: &str, v: &Value) {
    match v["type"].as_str().unwrap_or("?") {
        "state_changed" => {
            let state = v["state"].as_str().unwrap_or("?");
            println!("{}  {}  {}", ts, state_dot(state), colored_state(state));
        }
        "log" => {
            let level = v["level"].as_str().unwrap_or("info");
            let msg = v["message"].as_str().unwrap_or("");
            let lc = match level {
                "error" => format!("\x1b[31m{level}\x1b[0m"),
                "warn" => format!("\x1b[33m{level}\x1b[0m"),
                _ => format!("\x1b[90m{level}\x1b[0m"),
            };
            println!("{}  [{}]  {}", ts, lc, msg);
        }
        other => println!("{}  {}  {}", ts, other, v),
    }
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

async fn wait_state(
    client: &Client,
    base: &str,
    target: &str,
    timeout_secs: u64,
) -> Result<Duration> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    loop {
        let elapsed = start.elapsed();
        if elapsed > timeout {
            anyhow::bail!("timeout: state '{target}' not reached within {timeout_secs}s");
        }
        if api_status(client, base).await?.state == target {
            return Ok(elapsed);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

pub(super) async fn scenario_nominal(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    println!("\n\x1b[1mNominal scenario\x1b[0m");
    println!("────────────────");

    let s = api_status(client, base).await?;
    println!(
        "  1/4  initial state              {} ({})",
        ok(),
        colored_state(&s.state)
    );

    let response = api_post(client, base, "/api/tunnel/start").await?;
    ensure_command(response, "bringing up the interface")?;
    println!("  2/4  connecting…               {} command sent", ok());
    let target = if s.dry_run { "connecting" } else { "up" };
    let t = wait_state(client, base, target, 5).await?;
    println!(
        "       state {target:<10}          {} in {:.0}ms",
        ok(),
        t.as_millis()
    );

    println!("  3/4  2s pause…");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("       {}  ok", ok());

    let response = api_post(client, base, "/api/tunnel/stop").await?;
    ensure_command(response, "stopping the interface")?;
    println!("  4/4  disconnecting…            {} command sent", ok());
    let t = wait_state(client, base, "down", 5).await?;
    println!(
        "       kill switch               {} in {:.0}ms",
        ok(),
        t.as_millis()
    );

    println!(
        "\n  {} nominal completed in \x1b[1m{:.2}s\x1b[0m\n",
        ok(),
        t0.elapsed().as_secs_f32()
    );
    Ok(())
}

pub(super) async fn scenario_flap(client: &Client, base: &str) -> Result<()> {
    let t0 = Instant::now();
    let cycles = 5u32;
    println!("\n\x1b[1mFlap scenario\x1b[0m (×{cycles})");
    println!("─────────────");

    let mut up_times = Vec::new();
    let mut down_times = Vec::new();
    let target = if api_status(client, base).await?.dry_run {
        "connecting"
    } else {
        "up"
    };

    for i in 1..=cycles {
        let response = api_post(client, base, "/api/tunnel/start").await?;
        ensure_command(response, "bringing up the interface")?;
        let tu = wait_state(client, base, target, 5).await?;
        up_times.push(tu.as_millis());

        let response = api_post(client, base, "/api/tunnel/stop").await?;
        ensure_command(response, "stopping the interface")?;
        let td = wait_state(client, base, "down", 5).await?;
        down_times.push(td.as_millis());

        println!(
            "  cycle {i}/{cycles}  up={:>4}ms  down={:>4}ms  {}",
            tu.as_millis(),
            td.as_millis(),
            ok()
        );
    }

    let avg_up = up_times.iter().sum::<u128>() / up_times.len() as u128;
    let avg_down = down_times.iter().sum::<u128>() / down_times.len() as u128;
    let max_up = up_times.iter().max().copied().unwrap_or(0);
    let max_down = down_times.iter().max().copied().unwrap_or(0);

    println!();
    println!("  average  up={avg_up}ms  down={avg_down}ms");
    println!("  max      up={max_up}ms  down={max_down}ms");
    println!(
        "\n  {} flap completed in \x1b[1m{:.2}s\x1b[0m\n",
        ok(),
        t0.elapsed().as_secs_f32()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    const MOCK_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_client() -> Client {
        Client::builder()
            .no_proxy()
            .build()
            .expect("test HTTP client")
    }

    fn status(state: &str) -> String {
        serde_json::json!({
            "state": state,
            "version": "test",
            "wan_ifaces": [],
            "lan_ifaces": [],
            "wg_peers": [],
            "allow_ssh_from": [],
            "peers": [],
            "wg_iface": "helios0",
            "dry_run": true,
            "split_tunnel_cidrs": [],
            "mss_clamp": null,
            "captive_portal_gateway": null
        })
        .to_string()
    }

    fn command(ok: bool) -> String {
        serde_json::json!({"ok": ok, "error": if ok { None } else { Some("refused") }}).to_string()
    }

    /// One connection per request keeps ordering and request paths explicit.
    async fn http_server(
        responses: Vec<(&'static str, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().expect("listener address");
        let task = tokio::spawn(async move {
            let mut paths = Vec::new();
            for (expected_path, body) in responses {
                let (mut stream, _) = tokio::time::timeout(MOCK_TIMEOUT, listener.accept())
                    .await
                    .expect("HTTP client connects")
                    .expect("accept local HTTP connection");
                let mut request = Vec::new();
                let mut buffer = [0; 2048];
                loop {
                    let count = tokio::time::timeout(MOCK_TIMEOUT, stream.read(&mut buffer))
                        .await
                        .expect("HTTP request arrives")
                        .expect("read HTTP request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end + 4]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let first_line = request.lines().next().unwrap_or_default();
                let path = first_line.split_whitespace().nth(1).unwrap_or_default();
                assert_eq!(path, expected_path, "unexpected request: {first_line}");
                paths.push(path.to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write HTTP response");
            }
            paths
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn watch_events_accepts_text_events_and_returns_on_websocket_close() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket client");
            let mut websocket = accept_async(stream).await.expect("websocket handshake");
            for message in [
                Message::Text(r#"{"type":"state_changed","state":"up"}"#.into()),
                Message::Text(r#"{"type":"log","level":"error","message":"failed"}"#.into()),
                Message::Text(r#"{"type":"log","message":"default level"}"#.into()),
                Message::Text(r#"{"type":"future"}"#.into()),
                Message::Text("not-json".into()),
                Message::Binary(vec![0, 1, 2].into()),
            ] {
                websocket.send(message).await.expect("send websocket event");
            }
            websocket.close(None).await.expect("close websocket");
        });

        let (websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .expect("connect websocket client");
        tokio::time::timeout(MOCK_TIMEOUT, watch_events(websocket))
            .await
            .expect("watch exits after peer closes")
            .expect("closed websocket is a normal end");
        server.await.expect("websocket server completes");
    }

    #[tokio::test]
    async fn wait_state_reads_the_target_and_reports_timeout() {
        let (base, server) = http_server(vec![("/api/status", status("up"))]).await;
        let elapsed = wait_state(&test_client(), &base, "up", 1)
            .await
            .expect("target state arrives");
        assert!(elapsed < MOCK_TIMEOUT);
        assert_eq!(
            server.await.expect("HTTP server completes"),
            ["/api/status"]
        );

        let error = wait_state(&test_client(), "http://127.0.0.1:1", "down", 0)
            .await
            .expect_err("zero timeout must expire");
        assert!(error.to_string().contains("timeout: state 'down'"));
    }

    #[tokio::test]
    async fn flap_scenario_completes_five_dry_run_cycles() {
        let mut responses = vec![("/api/status", status("down"))];
        for _ in 0..5 {
            responses.extend([
                ("/api/tunnel/start", command(true)),
                ("/api/status", status("connecting")),
                ("/api/tunnel/stop", command(true)),
                ("/api/status", status("down")),
            ]);
        }
        let (base, server) = http_server(responses).await;
        scenario_flap(&test_client(), &base)
            .await
            .expect("all five cycles complete");
        let paths = server.await.expect("HTTP server completes");
        assert_eq!(paths.len(), 21);
        assert_eq!(paths[0], "/api/status");
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == "/api/tunnel/start")
                .count(),
            5
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == "/api/tunnel/stop")
                .count(),
            5
        );
    }

    #[tokio::test]
    async fn flap_scenario_stops_on_a_refused_start_command() {
        let (base, server) = http_server(vec![
            ("/api/status", status("down")),
            ("/api/tunnel/start", command(false)),
        ])
        .await;
        let error = scenario_flap(&test_client(), &base)
            .await
            .expect_err("refused start must abort the scenario");
        assert!(error
            .to_string()
            .contains("bringing up the interface refused: refused"));
        assert_eq!(
            server.await.expect("HTTP server completes"),
            ["/api/status", "/api/tunnel/start"]
        );
    }

    #[tokio::test]
    async fn nominal_scenario_starts_waits_stops_and_reaches_down() {
        let (base, server) = http_server(vec![
            ("/api/status", status("down")),
            ("/api/tunnel/start", command(true)),
            ("/api/status", status("connecting")),
            ("/api/tunnel/stop", command(true)),
            ("/api/status", status("down")),
        ])
        .await;
        scenario_nominal(&test_client(), &base)
            .await
            .expect("nominal tunnel lifecycle completes");
        assert_eq!(
            server.await.expect("HTTP server completes"),
            [
                "/api/status",
                "/api/tunnel/start",
                "/api/status",
                "/api/tunnel/stop",
                "/api/status"
            ]
        );
    }
}
