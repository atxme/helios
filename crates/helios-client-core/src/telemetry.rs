//! Consommation de l'API web de heliosd — **uniquement après montage du tunnel**.
//!
//! Rappel de l'invariant : le serveur web de heliosd vit *derrière* l'IPsec. Il
//! n'est joignable que lorsque le tunnel est `Up`. Cette boucle n'est donc lancée
//! par le shell que sur la transition vers `Up`, et annulée dès la déconnexion.
//!
//! Pour le scaffold, on interroge `GET /api/status` (preuve de joignabilité) et
//! on signale les transitions accessible/injoignable. Le flux télémétrie riche
//! (WebSocket `/ws` → débits/SA) est un raffinement ultérieur.

use std::time::Duration;

use tokio::sync::watch;

use crate::backend::EventSink;
use crate::events::ClientEvent;

/// Période de sondage de l'API heliosd interne.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Délai max d'une requête de statut.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Boucle de télémétrie : sonde `heliosd_url/api/status` jusqu'à annulation via
/// `cancel`. N'émet un log que sur **changement** de joignabilité (anti-bruit).
///
/// `heliosd_url` doit être l'URL interne joignable derrière le tunnel
/// (ex. `http://10.10.0.1:8080`).
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
