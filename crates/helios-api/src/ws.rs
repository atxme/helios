//! Handler WebSocket : diffuse les [`HeliosEvent`] en JSON vers chaque client.
//!
//! À la connexion, l'état courant est envoyé en premier pour que l'UI s'initialise
//! sans attendre le prochain événement. On souscrit au broadcast AVANT de lire
//! l'état pour éviter de manquer une transition simultanée.

use aether::HeliosEvent;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;

pub async fn handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    // Souscrire d'abord, puis lire l'état : zéro risque de manquer une transition.
    let mut rx = state.event_tx.subscribe();

    let current = *state.tunnel_state.read().await;
    let init = HeliosEvent::StateChanged { state: current };
    if let Ok(msg) = serde_json::to_string(&init) {
        if socket.send(Message::Text(msg)).await.is_err() {
            return;
        }
    }

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Ok(msg) = serde_json::to_string(&event) {
                    if socket.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
            }
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(_)) => continue,
        }
    }
}
