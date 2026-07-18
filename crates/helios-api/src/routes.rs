use aether::{NetworkConfig, OrchestratorCmd};
use axum::{extract::State, http::StatusCode, Json};
use helios_firewall::ruleset;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub version: &'static str,
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub wg_peers: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub peers: Vec<PeerSummary>,
    pub wg_iface: String,
    pub wg_listen_port: Option<u16>,
    pub dry_run: bool,
    pub split_tunnel_cidrs: Vec<String>,
    pub mss_clamp: Option<u16>,
    pub captive_portal_gateway: Option<String>,
}

/// Un pair WireGuard autorisé, tel qu'exposé à l'IHM.
/// La clé publique est publique par nature ; le PSK n'est jamais exposé,
/// on n'en publie que la présence.
#[derive(Serialize, Clone)]
pub struct PeerSummary {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub post_quantum: bool,
}

#[derive(Serialize)]
pub struct CmdResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CmdResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

#[derive(Serialize)]
pub struct FirewallRulesResponse {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

#[derive(Deserialize)]
pub struct ApplyRulesRequest {
    pub rules: String,
}

#[derive(Deserialize)]
pub struct SplitTunnelRequest {
    pub cidrs: Vec<String>,
}

#[derive(Deserialize)]
pub struct GatewayKeyRequest {
    /// Nouvelle clé privée Curve25519 de la gateway, en base64.
    pub private_key: String,
}

/// Remplace la clé privée WireGuard de la gateway et la rescelle.
///
/// **Joignable uniquement à travers le tunnel** : comme toute cette API, le
/// pare-feu la restreint à `admin_iface`. Une rotation d'identité ne doit pas
/// pouvoir être tentée depuis l'Internet.
///
/// Le secret de scellement TPM ne transite pas par ce crate : on se contente de
/// valider la forme et de transmettre à l'orchestrateur, seul détenteur du
/// secret. Ici on refuse tôt ce qui est manifestement invalide, pour ne pas
/// faire voyager une clé absurde jusqu'au TPM.
pub async fn gateway_key_set(
    State(s): State<AppState>,
    Json(body): Json<GatewayKeyRequest>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    use base64::Engine as _;

    let key = body.private_key.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("clé non décodable : {e}")))?;
    if raw.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "clé de {} octets au lieu de 32 — ce n'est pas une clé Curve25519",
                raw.len()
            ),
        ));
    }

    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::UpdateGatewayKey(key.to_string()))
        .await
        .is_ok();
    Ok(Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    }))
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let network = s.network.read().await;

    let peers: Vec<PeerSummary> = network
        .peers
        .iter()
        .map(|p| PeerSummary {
            name: p.name.clone(),
            public_key: p.public_key.clone(),
            address: p.address.clone(),
            post_quantum: p.preshared_key.is_some(),
        })
        .collect();

    Json(StatusResponse {
        state: state.as_str().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        wan_iface: network.wan_iface.clone(),
        lan_ifaces: network.lan_ifaces.clone(),
        wg_peers: network.wg_peers(),
        allow_ssh_from: network.allow_ssh_from.clone(),
        peers,
        wg_iface: network.wg_iface.clone(),
        wg_listen_port: policy.wg_listen_port,
        dry_run: s.dry_run,
        split_tunnel_cidrs: policy.split_tunnel_cidrs.clone(),
        mss_clamp: policy.mss_clamp,
        captive_portal_gateway: policy.captive_portal_gateway.clone(),
    })
}

/// Retourne la configuration réseau courante.
pub async fn network_get(State(s): State<AppState>) -> Json<NetworkConfig> {
    let network = s.network.read().await;
    Json(network.clone())
}

/// Recharge la configuration réseau à chaud (JSON).
/// Persiste sur disque et envoie `LoadNetworkConfig` à l'orchestrateur.
pub async fn network_set(
    State(s): State<AppState>,
    Json(new_config): Json<NetworkConfig>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    if let Err(e) = new_config.save() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::LoadNetworkConfig(Box::new(new_config)))
        .await
        .is_ok();
    Ok(Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    }))
}

pub async fn tunnel_start(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Connect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn firewall_rules_get(State(s): State<AppState>) -> Json<FirewallRulesResponse> {
    let state = *s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let rs = ruleset::render(&policy, state);

    let verdict_str = match rs.default_verdict {
        ruleset::Verdict::Drop => "drop",
        ruleset::Verdict::Accept => "accept",
    };

    // Rendu fidèle à ce que le backend Netlink applique réellement : trois
    // chaînes à hook, chacune avec sa politique par défaut.
    let mut lines = vec!["table inet helios {".to_string()];
    for kind in [
        ruleset::ChainKind::Input,
        ruleset::ChainKind::Forward,
        ruleset::ChainKind::Output,
    ] {
        let name = kind.as_str();
        lines.push(format!("  chain {name} {{"));
        lines.push(format!(
            "    type filter hook {name} priority filter; policy {verdict_str};"
        ));
        for rule in rs.chain(kind) {
            match &rule.note {
                Some(note) => lines.push(format!("    {rule}  # {note}")),
                None => lines.push(format!("    {rule}")),
            }
        }
        lines.push("  }".to_string());
    }
    if let Some(mss) = rs.mss_clamp {
        lines.push(format!(
            "  # MSS clamping demandé ({mss}) — non appliqué par le backend Netlink"
        ));
    }
    lines.push("}".to_string());

    Json(FirewallRulesResponse {
        rules: lines.join("\n"),
        default_verdict: verdict_str.to_string(),
        dry_run: s.dry_run,
    })
}

pub async fn firewall_rules_apply(
    State(s): State<AppState>,
    Json(body): Json<ApplyRulesRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::ApplyFirewallRules(body.rules))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn captive_portal_release(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::AcknowledgeCaptivePortal)
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn split_tunnel_set(
    State(s): State<AppState>,
    Json(body): Json<SplitTunnelRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::SetSplitTunnel(body.cidrs))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aether::{NetworkConfig, OrchestratorCmd, TunnelState, WgPeer};
    use axum::extract::State;
    use tokio::sync::{broadcast, mpsc, RwLock};

    use super::*;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn network() -> NetworkConfig {
        NetworkConfig {
            wan_iface: "eth0".into(),
            lan_ifaces: vec!["lan0".into()],
            admin_iface: Some("helios0".into()),
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            wg_listen_port: 51820,
            peers: vec![WgPeer {
                name: "poste-test".into(),
                public_key: PEER_KEY.into(),
                address: "100.64.1.2/32".into(),
                preshared_key: Some("secret-pq-ne-doit-pas-sortir".into()),
            }],
            ..NetworkConfig::default()
        }
    }

    fn app_state(state: TunnelState) -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
        let network = network();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let policy = network.firewall_policy();
        (
            AppState::new(
                Arc::new(RwLock::new(network)),
                true,
                Arc::new(RwLock::new(state)),
                event_tx,
                cmd_tx,
                Arc::new(RwLock::new(policy)),
            ),
            cmd_rx,
        )
    }

    #[tokio::test]
    async fn status_expose_les_donnees_utiles_sans_le_psk() {
        let (app, _cmd_rx) = app_state(TunnelState::Up);

        let response = status(State(app)).await.0;

        assert_eq!(response.state, "up");
        assert_eq!(response.wg_listen_port, Some(51820));
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peers[0].name, "poste-test");
        assert!(response.peers[0].post_quantum);
        let payload = serde_json::to_string(&response).unwrap();
        assert!(!payload.contains("secret-pq-ne-doit-pas-sortir"));
    }

    #[tokio::test]
    async fn routes_de_commande_transmettent_l_intention_exacte() {
        let (app, mut cmd_rx) = app_state(TunnelState::Down);

        assert!(tunnel_start(State(app.clone())).await.0.ok);
        assert!(matches!(
            cmd_rx.recv().await,
            Some(OrchestratorCmd::Connect)
        ));

        assert!(
            split_tunnel_set(
                State(app.clone()),
                Json(SplitTunnelRequest {
                    cidrs: vec!["10.0.0.0/8".into()]
                }),
            )
            .await
            .0
            .ok
        );
        match cmd_rx.recv().await {
            Some(OrchestratorCmd::SetSplitTunnel(cidrs)) => assert_eq!(cidrs, ["10.0.0.0/8"]),
            other => panic!("commande inattendue : {other:?}"),
        }

        assert!(tunnel_stop(State(app)).await.0.ok);
        assert!(matches!(
            cmd_rx.recv().await,
            Some(OrchestratorCmd::Disconnect)
        ));
    }

    #[tokio::test]
    async fn rendu_pare_feu_reste_fail_closed_hors_tunnel_actif() {
        let (app, _cmd_rx) = app_state(TunnelState::Down);

        let response = firewall_rules_get(State(app)).await.0;

        assert_eq!(response.default_verdict, "drop");
        assert!(response.rules.contains("udp dport 51820 accept"));
        assert!(!response.rules.contains("secret-pq-ne-doit-pas-sortir"));
    }

    #[tokio::test]
    async fn erreur_explicite_si_orchestrateur_absent() {
        let (app, cmd_rx) = app_state(TunnelState::Down);
        drop(cmd_rx);

        let response = tunnel_start(State(app)).await.0;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("orchestrateur injoignable"));
    }
}
