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

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{NetworkConfig, OrchestratorCmd, TunnelState};
    use futures_util::StreamExt as _;
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc, RwLock};

    fn state() -> AppState {
        let network_config = NetworkConfig::default();
        let policy = network_config.firewall_policy();
        let network = Arc::new(RwLock::new(network_config));
        let (event_tx, _) = broadcast::channel::<HeliosEvent>(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel::<OrchestratorCmd>(4);
        let (psk_tx, _psk_rx) = mpsc::channel(4);
        AppState::new(
            network,
            true,
            Arc::new(RwLock::new(TunnelState::Connecting)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        )
    }

    #[tokio::test]
    async fn websocket_sends_current_state_before_live_events() {
        let state = state();
        let events = state.event_tx.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                crate::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        });

        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .expect("connect websocket");
        let initial = socket.next().await.unwrap().unwrap().into_text().unwrap();
        let initial: serde_json::Value = serde_json::from_str(&initial).unwrap();
        assert_eq!(
            initial,
            serde_json::json!({ "type": "state_changed", "state": "connecting" })
        );

        events
            .send(HeliosEvent::StateChanged {
                state: TunnelState::Up,
            })
            .unwrap();
        let live = socket.next().await.unwrap().unwrap().into_text().unwrap();
        let live: serde_json::Value = serde_json::from_str(&live).unwrap();
        assert_eq!(
            live,
            serde_json::json!({ "type": "state_changed", "state": "up" })
        );

        drop(socket);
        server.abort();
    }
}
