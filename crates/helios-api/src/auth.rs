//! Identité et autorisation du pair WireGuard appelant.
//!
//! WireGuard authentifie la source contre les `AllowedIPs`. L’API rattache
//! donc l’adresse source réelle du socket à l’unique VIP `/32` de la
//! configuration. Aucun en-tête de proxy n’est consulté.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Identité authentifiée d’un appelant de l’API.
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
            name: "boucle-locale-dev".into(),
            public_key: None,
            admin: true,
            dev_loopback: true,
        }
    }
}

/// Exige un pair WireGuard connu. En `--dev`, la boucle locale constitue une
/// identité simulée explicite afin que l’IHM et les campagnes restent jouables.
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
            // Un refus est la seule trace exploitable d'une tentative d'accès :
            // le module noyau WireGuard, lui, rejette les handshakes inconnus
            // sans rien remonter. Sans cette ligne, l'opérateur ne verrait rien.
            tracing::warn!(
                source = ?source_of(&request),
                uri = %request.uri(),
                "accès refusé : adresse source non rattachée à un pair admis"
            );
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/// Exige en plus la permission `admin` et une origine navigateur cohérente.
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
                "commande d’administration authentifiée par WireGuard"
            );
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Some(caller) => {
            tracing::warn!(
                pair = %caller.name,
                source = %caller.source,
                uri = %request.uri(),
                "mutation refusée : pair admis mais non administrateur"
            );
            StatusCode::FORBIDDEN.into_response()
        }
        None => {
            tracing::warn!(
                source = ?source_of(&request),
                uri = %request.uri(),
                "mutation refusée : adresse source non rattachée à un pair admis"
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

/// Avec une requête de navigateur, l’origine doit être exactement l’autorité
/// du `Host`. Les clients natifs sans `Origin` restent admis.
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
                name: "poste".into(),
                public_key: "cle-publique".into(),
                address: "100.64.1.2/32".into(),
                admin,
                preshared_key: None,
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
            source.parse::<SocketAddr>().expect("adresse de test"),
        ));
        request
    }

    #[tokio::test]
    async fn rattache_la_vip_a_la_cle_wireguard() {
        let caller = resolve(&state(true, false), source_of(&request("100.64.1.2:4242")))
            .await
            .expect("pair attendu");
        assert_eq!(caller.public_key.as_deref(), Some("cle-publique"));
        assert!(caller.admin);
    }

    #[tokio::test]
    async fn pair_inconnu_et_boucle_reelle_refuses() {
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
    async fn boucle_dev_est_un_admin_simule() {
        let caller = resolve(&state(false, true), source_of(&request("127.0.0.1:4242")))
            .await
            .expect("identité dev");
        assert!(caller.admin);
        assert!(caller.dev_loopback);
    }

    #[test]
    fn origine_croisee_refusee() {
        let request = Request::builder()
            .header(header::HOST, "100.64.0.1:8080")
            .header(header::ORIGIN, "https://hostile.example")
            .body(Body::empty())
            .unwrap();
        assert!(!same_origin(&request));
    }
}
