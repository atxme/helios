use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    Json,
};
use helios_core::{profiles, NetworkConfig, OrchestratorCmd};
use helios_firewall::ruleset;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pqc_level: String,
    pub reserved: bool,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub version: &'static str,
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub ike_peers: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub connections: Vec<ConnectionSummary>,
    pub dry_run: bool,
    pub profiles: Vec<ProfileSummary>,
    pub active_profile: Option<String>,
    pub split_tunnel_cidrs: Vec<String>,
    pub mss_clamp: Option<u16>,
    pub captive_portal_gateway: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ConnectionSummary {
    pub name: String,
    pub remote_addr: String,
    pub local_id: Option<String>,
    pub remote_id: Option<String>,
    pub ike_proposal: String,
    pub esp_proposal: String,
}

#[derive(Serialize)]
pub struct CmdResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CmdResponse {
    fn ok() -> Self { Self { ok: true, error: None } }
    fn err(msg: impl Into<String>) -> Self { Self { ok: false, error: Some(msg.into()) } }
}

#[derive(Serialize)]
pub struct FirewallRulesResponse {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

#[derive(Deserialize, Default)]
pub struct StartRequest {
    pub profile: Option<String>,
}

#[derive(Deserialize)]
pub struct CustomProposalRequest {
    pub ike_proposal: String,
    pub esp_proposal: String,
}

#[derive(Deserialize)]
pub struct ApplyRulesRequest {
    pub rules: String,
}

#[derive(Deserialize)]
pub struct SplitTunnelRequest {
    pub cidrs: Vec<String>,
}

fn hybrid_proposals() -> (String, String) {
    let p = profiles::find("hybrid").expect("profil hybride manquant");
    (p.ike_proposal.to_string(), p.esp_proposal.to_string())
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    let effective = s.effective_proposals.read().await;
    let policy = s.policy.read().await;
    let network = s.network.read().await;

    let (default_ike, default_esp) = hybrid_proposals();
    let connections: Vec<ConnectionSummary> = network.connections.iter().map(|c| {
        let (ike, esp) = effective.clone()
            .unwrap_or_else(|| (default_ike.clone(), default_esp.clone()));
        ConnectionSummary {
            name: c.name.clone(),
            remote_addr: c.remote_addr.clone(),
            local_id: c.local_id.clone(),
            remote_id: c.remote_id.clone(),
            ike_proposal: ike,
            esp_proposal: esp,
        }
    }).collect();

    let active_ike = effective.as_ref()
        .map(|(ike, _)| ike.as_str())
        .unwrap_or(&default_ike);
    let active_profile = profiles::detect(active_ike).map(|p| p.id.to_string());

    let profile_list = profiles::PROFILES.iter().map(|p| ProfileSummary {
        id: p.id.to_string(),
        name: p.name.to_string(),
        description: p.description.to_string(),
        pqc_level: format!("{:?}", p.pqc_level),
        reserved: p.reserved,
    }).collect();

    Json(StatusResponse {
        state: state.as_str().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        wan_iface: network.wan_iface.clone(),
        lan_ifaces: network.lan_ifaces.clone(),
        ike_peers: network.ike_peers(),
        allow_ssh_from: network.allow_ssh_from.clone(),
        connections,
        dry_run: s.dry_run,
        profiles: profile_list,
        active_profile,
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
    let ok = s.cmd_tx.send(OrchestratorCmd::LoadNetworkConfig(new_config)).await.is_ok();
    Ok(Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") }))
}

pub async fn tunnel_start(State(s): State<AppState>, body: Bytes) -> Json<CmdResponse> {
    let profile = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<StartRequest>(&body).ok().and_then(|r| r.profile)
    };

    let cmd = match profile {
        Some(id) => OrchestratorCmd::ConnectWithProfile(id),
        None => OrchestratorCmd::Connect,
    };
    let ok = s.cmd_tx.send(cmd).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}

pub async fn connection_apply(
    State(s): State<AppState>,
    Json(body): Json<CustomProposalRequest>,
) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::ConnectWithCustom {
        ike_proposal: body.ike_proposal,
        esp_proposal: body.esp_proposal,
    }).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}

pub async fn firewall_rules_get(State(s): State<AppState>) -> Json<FirewallRulesResponse> {
    let state = *s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let rs = ruleset::render(&policy, state);

    let verdict_str = match rs.default_verdict {
        ruleset::Verdict::Drop   => "drop",
        ruleset::Verdict::Accept => "accept",
    };

    let mut lines = vec![
        "table inet helios_kill {".to_string(),
        "  chain forward {".to_string(),
        format!("    type filter hook forward priority filter; policy {verdict_str};"),
    ];
    for rule in &rs.rules {
        lines.push(format!("    {rule}"));
    }
    lines.push("  }".to_string());
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
    let ok = s.cmd_tx.send(OrchestratorCmd::ApplyFirewallRules(body.rules)).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}

pub async fn captive_portal_release(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::AcknowledgeCaptivePortal).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}

pub async fn split_tunnel_set(
    State(s): State<AppState>,
    Json(body): Json<SplitTunnelRequest>,
) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::SetSplitTunnel(body.cidrs)).await.is_ok();
    Json(if ok { CmdResponse::ok() } else { CmdResponse::err("orchestrateur injoignable") })
}
