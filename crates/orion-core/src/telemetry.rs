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
    let client = match reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() {
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
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }
    }
}
