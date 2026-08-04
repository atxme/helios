//! Consumption of heliosd's web API — **only after the tunnel is mounted**.
//!
//! Reminder of the invariant: heliosd's web server lives *behind* WireGuard.
//! It's only reachable once the tunnel is `Up`. This loop is therefore only
//! started by the shell on the transition to `Up`, and cancelled as soon as
//! disconnection occurs.
//!
//! For the scaffold, we query `GET /api/status` (proof of reachability) and
//! report reachable/unreachable transitions. The rich telemetry stream
//! (WebSocket `/ws` → rates/SA) is a later refinement.

use std::time::Duration;

use tokio::sync::watch;

use crate::backend::EventSink;
use crate::events::ClientEvent;

/// Polling period of the internal heliosd API.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Max delay of a status request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Telemetry loop: polls `heliosd_url/api/status` until cancelled via
/// `cancel`. Only emits a log on a **change** of reachability (anti-noise).
///
/// `heliosd_url` must be the internal URL reachable behind the tunnel
/// (e.g. `http://10.10.0.1:8080`).
pub async fn run(heliosd_url: String, sink: EventSink, mut cancel: watch::Receiver<bool>) {
    run_with_timing(
        heliosd_url,
        sink,
        &mut cancel,
        POLL_INTERVAL,
        REQUEST_TIMEOUT,
    )
    .await;
}

async fn run_with_timing(
    heliosd_url: String,
    sink: EventSink,
    cancel: &mut watch::Receiver<bool>,
    poll_interval: Duration,
    request_timeout: Duration,
) {
    let client = match reqwest::Client::builder().timeout(request_timeout).build() {
        Ok(c) => c,
        Err(e) => {
            sink(ClientEvent::Error {
                message: format!("client HTTP télémétrie: {e}"),
            });
            return;
        }
    };
    let status_url = format!("{}/api/status", heliosd_url.trim_end_matches('/'));
    let mut last_reachable: Option<bool> = None;

    loop {
        let reachable = matches!(
            client.get(&status_url).send().await,
            Ok(r) if r.status().is_success()
        );
        if last_reachable != Some(reachable) {
            last_reachable = Some(reachable);
            if reachable {
                sink(ClientEvent::log(
                    "info",
                    format!("télémétrie : heliosd joignable ({heliosd_url})"),
                ));
            } else {
                sink(ClientEvent::log(
                    "warn",
                    "télémétrie : heliosd injoignable derrière le tunnel".to_string(),
                ));
            }
        }

        tokio::select! {
            _ = cancel.changed() => break,
            _ = tokio::time::sleep(poll_interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn status_server(
        statuses: Vec<u16>,
        stop: watch::Sender<bool>,
        paths: Arc<Mutex<Vec<String>>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for status in statuses {
                let (mut stream, _) = listener.accept().await.expect("status request");
                let mut request = vec![0u8; 2048];
                let read = stream.read(&mut request).await.expect("read request");
                let first_line = String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                paths.lock().unwrap().push(first_line);
                let reason = if status < 400 {
                    "No Content"
                } else {
                    "Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
            let _ = stop.send(true);
        });
        (format!("http://{address}/"), task)
    }

    #[tokio::test]
    async fn reports_only_reachability_transitions_and_uses_the_status_path() {
        let (stop, mut cancel) = watch::channel(false);
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (url, server) = status_server(vec![503, 204, 204], stop, Arc::clone(&paths)).await;
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let sink: EventSink = Arc::new(move |event| captured.lock().unwrap().push(event));

        run_with_timing(
            url,
            sink,
            &mut cancel,
            Duration::from_millis(1),
            Duration::from_secs(1),
        )
        .await;
        server.await.unwrap();

        let messages: Vec<String> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                ClientEvent::Log { message, .. } => Some(message.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(messages.len(), 2, "the repeated success must stay silent");
        assert!(messages[0].contains("injoignable"));
        assert!(messages[1].contains("joignable"));
        assert!(
            paths
                .lock()
                .unwrap()
                .iter()
                .all(|line| line.starts_with("GET /api/status ")),
            "trailing slashes must not produce a double slash"
        );
    }

    #[tokio::test]
    async fn a_connection_failure_is_reported_and_cancellation_stops_the_loop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve local address");
        let address = listener.local_addr().unwrap();
        drop(listener);

        let (stop, mut cancel) = watch::channel(false);
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let stop_from_sink = stop.clone();
        let sink: EventSink = Arc::new(move |event| {
            captured.lock().unwrap().push(event);
            let _ = stop_from_sink.send(true);
        });

        run_with_timing(
            format!("http://{address}"),
            sink,
            &mut cancel,
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .await;

        assert!(matches!(
            events.lock().unwrap().as_slice(),
            [ClientEvent::Log { level, message }] if level == "warn" && message.contains("injoignable")
        ));
    }
}
