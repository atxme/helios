//! WebSocket handler: streams [`HeliosEvent`] as JSON to each client.
//!
//! On connection, the current state is sent first so the UI can initialize
//! without waiting for the next event. We subscribe to the broadcast BEFORE
//! reading the state, to avoid missing a simultaneous transition.

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
    // Subscribe first, then read the state: zero risk of missing a transition.
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
