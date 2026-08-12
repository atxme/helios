//! Identity and authorization of the calling WireGuard peer.
//!
//! WireGuard authenticates the source against `AllowedIPs`. The API therefore
//! ties the socket's real source address to the configuration's single `/32`
//! VIP. No proxy header is ever consulted.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Authenticated identity of an API caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub source: IpAddr,
    pub name: String,
    pub public_key: Option<String>,
    pub admin: bool,
    pub dev_loopback: bool,
}

impl Caller {
    fn dev() -> Self {
        Self {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: "dev-loopback".into(),
            public_key: None,
            admin: true,
            dev_loopback: true,
        }
    }
}

/// Requires a known WireGuard peer. In `--dev`, the loopback address stands in
/// as an explicit simulated identity so the UI and campaigns stay usable.
pub async fn require_peer(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    match resolve(&state, source_of(&request)).await {
        Some(caller) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        None => {
            // A refusal is the only actionable trace of an access attempt: the
            // WireGuard kernel module rejects unknown handshakes without
            // reporting anything back up. Without this line, the operator
            // would see nothing at all.
            tracing::warn!(
                source = ?source_of(&request),
                uri = %request.uri(),
                "access denied: source address not tied to an admitted peer"
            );
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/// Resolves the source of a raw socket service to an admitted WireGuard peer.
///
/// Raw TCP/UDP speedtest connections do not carry HTTP's `ConnectInfo`, so
/// they use the same source-VIP lookup directly. Keeping this lookup here
/// prevents the socket service from growing a second, weaker identity table.
pub async fn resolve_source(state: &AppState, source: IpAddr) -> Option<Caller> {
    resolve(state, Some(source)).await
}

/// Additionally requires the `admin` permission and a consistent browser origin.
pub async fn require_admin(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !same_origin(&request) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match resolve(&state, source_of(&request)).await {
        Some(caller) if caller.admin => {
            tracing::info!(
                pair = %caller.name,
                source = %caller.source,
                "admin command authenticated via WireGuard"
            );
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Some(caller) => {
            tracing::warn!(
                pair = %caller.name,
                source = %caller.source,
                uri = %request.uri(),
                "mutation denied: peer admitted but not an administrator"
            );
            StatusCode::FORBIDDEN.into_response()
        }
        None => {
            tracing::warn!(
                source = ?source_of(&request),
                uri = %request.uri(),
                "mutation denied: source address not tied to an admitted peer"
            );
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

fn source_of(request: &Request) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
}

async fn resolve(state: &AppState, source: Option<IpAddr>) -> Option<Caller> {
    if state.dry_run && source.is_none_or(|ip| ip.is_loopback()) {
        return Some(Caller::dev());
    }
    let source = source?;
    let network = state.network.read().await;
    let mut matching = network.peers.iter().filter(|peer| {
        peer.address
            .split_once('/')
            .is_some_and(|(host, prefix)| prefix == "32" && host == source.to_string())
    });
    let peer = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    Some(Caller {
        source,
        name: peer.name.clone(),
        public_key: Some(peer.public_key.clone()),
        admin: peer.admin,
        dev_loopback: false,
    })
}

/// For a browser request, the origin must exactly match the `Host`
/// authority. Native clients without `Origin` remain admitted.
fn same_origin(request: &Request) -> bool {
    let Some(origin) = request.headers().get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some(host) = request.headers().get(header::HOST) else {
        return false;
    };
    let Ok(host) = host.to_str() else {
        return false;
    };
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(|authority| authority == host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{NetworkConfig, TunnelState, WgPeer};
    use axum::body::Body;
    use tokio::sync::{broadcast, mpsc, RwLock};

    fn state(admin: bool, dry_run: bool) -> AppState {
        let network = NetworkConfig {
            peers: vec![WgPeer {
                name: "workstation".into(),
                public_key: "public-key".into(),
                address: "100.64.1.2/32".into(),
                admin,
                preshared_key: None,
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..NetworkConfig::default()
        };
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(1);
        let (cmd_tx, _) = mpsc::channel(1);
        let (psk_tx, _) = mpsc::channel(1);
        AppState::new(
            std::sync::Arc::new(RwLock::new(network)),
            dry_run,
            std::sync::Arc::new(RwLock::new(TunnelState::Down)),
            event_tx,
            cmd_tx,
            psk_tx,
            std::sync::Arc::new(RwLock::new(policy)),
        )
    }

    fn request(source: &str) -> Request {
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(ConnectInfo(
            source.parse::<SocketAddr>().expect("test address"),
        ));
        request
    }

    #[tokio::test]
    async fn ties_the_vip_to_the_wireguard_key() {
        let caller = resolve(&state(true, false), source_of(&request("100.64.1.2:4242")))
            .await
            .expect("expected peer");
        assert_eq!(caller.public_key.as_deref(), Some("public-key"));
        assert!(caller.admin);
    }

    #[tokio::test]
    async fn unknown_peer_and_real_loopback_are_refused() {
        assert!(
            resolve(&state(true, false), source_of(&request("100.64.1.3:4242")))
                .await
                .is_none()
        );
        assert!(
            resolve(&state(true, false), source_of(&request("127.0.0.1:4242")))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn dev_loopback_is_a_simulated_admin() {
        let caller = resolve(&state(false, true), source_of(&request("127.0.0.1:4242")))
            .await
            .expect("dev identity");
        assert!(caller.admin);
        assert!(caller.dev_loopback);
    }

    #[test]
    fn cross_origin_is_refused() {
        let request = Request::builder()
            .header(header::HOST, "100.64.0.1:8080")
            .header(header::ORIGIN, "https://hostile.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&request));
    }
}
