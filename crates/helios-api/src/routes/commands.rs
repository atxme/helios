//! Orchestrator commands and their uniform answer.

use super::*;

#[derive(Serialize)]
pub struct CmdResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CmdResponse {
    pub(super) fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }
    pub(super) fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

pub async fn tunnel_start(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Connect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrator unreachable")
    })
}
