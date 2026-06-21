use axum::{body::Bytes, extract::State, Json};
use helios_core::{profiles, OrchestratorCmd};
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

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    let effective = s.effective_proposals.read().await;

    let connections: Vec<ConnectionSummary> = s.config.connections.iter().map(|c| {
        let (ike, esp) = effective.clone()
            .unwrap_or_else(|| (c.ike_proposal.clone(), c.esp_proposal.clone()));
        ConnectionSummary {
            name: c.name.clone(),
            remote_addr: c.remote_addr.clone(),
            local_id: c.local_id.clone(),
            remote_id: c.remote_id.clone(),
            ike_proposal: ike,
            esp_proposal: esp,
        }
    }).collect();

    let active_profile = connections.first()
        .and_then(|c| profiles::detect(&c.ike_proposal))
        .map(|p| p.id.to_string());

    let profile_list = profiles::PROFILES.iter().map(|p| ProfileSummary {
        id: p.id.to_string(),
        name: p.name.to_string(),
        description: p.description.to_string(),
        pqc_level: format!("{:?}", p.pqc_level),
        reserved: p.reserved,
    }).collect();

    Json(StatusResponse {
        state: format!("{:?}", *state).to_lowercase(),
        version: env!("CARGO_PKG_VERSION"),
        wan_iface: s.config.firewall.wan_iface.clone(),
        lan_ifaces: s.config.firewall.lan_ifaces.clone(),
        ike_peers: s.config.firewall.ike_peers.clone(),
        allow_ssh_from: s.config.firewall.allow_ssh_from.clone(),
        connections,
        dry_run: s.config.general.dry_run,
        profiles: profile_list,
        active_profile,
    })
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
    Json(CmdResponse { ok })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(CmdResponse { ok })
}

/// Applique des propositions IKE/ESP personnalisées et déclenche un re-clé.
pub async fn connection_apply(
    State(s): State<AppState>,
    Json(body): Json<CustomProposalRequest>,
) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::ConnectWithCustom {
        ike_proposal: body.ike_proposal,
        esp_proposal: body.esp_proposal,
    }).await.is_ok();
    Json(CmdResponse { ok })
}

/// Renvoie le jeu de règles nftables rendu pour l'état courant.
pub async fn firewall_rules_get(State(s): State<AppState>) -> Json<FirewallRulesResponse> {
    let state = *s.tunnel_state.read().await;
    let policy = s.config.firewall_policy();
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
        dry_run: s.config.general.dry_run,
    })
}

/// Applique un jeu de règles nftables personnalisé (dry-run = log seulement).
pub async fn firewall_rules_apply(
    State(s): State<AppState>,
    Json(body): Json<ApplyRulesRequest>,
) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::ApplyFirewallRules(body.rules)).await.is_ok();
    Json(CmdResponse { ok })
}
