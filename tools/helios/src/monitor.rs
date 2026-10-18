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
