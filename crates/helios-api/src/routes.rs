use axum::{extract::State, Json};
use helios_core::OrchestratorCmd;
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub version: &'static str,
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub ike_peers: Vec<String>,
    pub connections: Vec<ConnectionSummary>,
    pub dry_run: bool,
}

#[derive(Serialize)]
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

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    Json(StatusResponse {
        state: format!("{:?}", *state).to_lowercase(),
        version: env!("CARGO_PKG_VERSION"),
        wan_iface: s.config.firewall.wan_iface.clone(),
        lan_ifaces: s.config.firewall.lan_ifaces.clone(),
        ike_peers: s.config.firewall.ike_peers.clone(),
        connections: s
            .config
            .connections
            .iter()
            .map(|c| ConnectionSummary {
                name: c.name.clone(),
                remote_addr: c.remote_addr.clone(),
                local_id: c.local_id.clone(),
                remote_id: c.remote_id.clone(),
                ike_proposal: c.ike_proposal.clone(),
                esp_proposal: c.esp_proposal.clone(),
            })
            .collect(),
        dry_run: s.config.general.dry_run,
    })
}

pub async fn tunnel_start(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Connect).await.is_ok();
    Json(CmdResponse { ok })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(CmdResponse { ok })
}
