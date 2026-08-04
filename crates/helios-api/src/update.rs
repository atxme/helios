//! Administration API for signed application updates.

use aether::sig::SignedBinaryRelease;
use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use helios_update::{FinalizedRelease, UpdateStatus};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRequest {
    pub manifest: SignedBinaryRelease,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRequest {
    pub release_sequence: u64,
    pub offset: u64,
    pub data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceRequest {
    pub release_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    pub release_sequence: u64,
    pub confirmation: String,
}

#[derive(Serialize)]
pub struct StageResponse {
    pub release: FinalizedRelease,
}

#[derive(Serialize)]
pub struct ChunkResponse {
    pub next_offset: u64,
}

#[derive(Serialize)]
pub struct ActivationResponse {
    pub accepted: bool,
    pub release_sequence: u64,
}

pub async fn status(
    State(state): State<AppState>,
) -> Result<Json<UpdateStatus>, (StatusCode, String)> {
    state.updates.status().map(Json).map_err(internal_error)
}

pub async fn stage(
    State(state): State<AppState>,
    Json(request): Json<StageRequest>,
) -> Result<Json<StageResponse>, (StatusCode, String)> {
    state
        .updates
        .stage_manifest(&request.manifest)
        .map(|release| Json(StageResponse { release }))
        .map_err(rejected)
}

pub async fn chunk(
    State(state): State<AppState>,
    Json(request): Json<ChunkRequest>,
) -> Result<Json<ChunkResponse>, (StatusCode, String)> {
    let data = STANDARD.decode(request.data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid base64 fragment: {e}"),
        )
    })?;
    state
        .updates
        .append_chunk(request.release_sequence, request.offset, &data)
        .map(|next_offset| Json(ChunkResponse { next_offset }))
        .map_err(rejected)
}

pub async fn finalize(
    State(state): State<AppState>,
    Json(request): Json<SequenceRequest>,
) -> Result<Json<StageResponse>, (StatusCode, String)> {
    state
        .updates
        .finalize(request.release_sequence)
        .map(|release| Json(StageResponse { release }))
        .map_err(rejected)
}

pub async fn activate(
    State(state): State<AppState>,
    Json(request): Json<ActivateRequest>,
) -> Result<(StatusCode, Json<ActivationResponse>), (StatusCode, String)> {
    state
        .updates
        .request_activation(request.release_sequence, &request.confirmation)
        .map(|()| {
            (
                StatusCode::ACCEPTED,
                Json(ActivationResponse {
                    accepted: true,
                    release_sequence: request.release_sequence,
                }),
            )
        })
        .map_err(rejected)
}

fn rejected(error: aether::HeliosError) -> (StatusCode, String) {
    (StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
}

fn internal_error(error: aether::HeliosError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{HeliosEvent, NetworkConfig, OrchestratorCmd, TunnelState};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc, RwLock};

    fn state(name: &str) -> (AppState, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "helios-api-update-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let layout = helios_update::UpdateLayout {
            staging_root: root.join("staging"),
            install_root: root.join("releases"),
            current_link: root.join("current"),
            state_path: root.join("staging/state.json"),
            activation_path: root.join("staging/activate.json"),
            ready_path: root.join("ready"),
            channel: "testing".into(),
            target: helios_update::BUILD_TARGET.into(),
        };
        let network_config = NetworkConfig::default();
        let policy = network_config.firewall_policy();
        let network = Arc::new(RwLock::new(network_config));
        let (event_tx, _) = broadcast::channel::<HeliosEvent>(4);
        let (cmd_tx, _cmd_rx) = mpsc::channel::<OrchestratorCmd>(4);
        let (psk_tx, _psk_rx) = mpsc::channel(4);
        let mut state = AppState::new(
            network,
            true,
            Arc::new(RwLock::new(TunnelState::Down)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        state.updates = helios_update::UpdateStore::new(layout);
        (state, root)
    }

    #[tokio::test]
    async fn empty_update_status_is_returned_as_json() {
        let (state, root) = state("status");

        let Json(status) = status(State(state)).await.expect("empty status");
        assert_eq!(status.highest_confirmed_sequence, 0);
        assert!(status.staged.is_empty());
        assert_eq!(status.activation_pending, None);
        assert_eq!(status.channel, "testing");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn chunk_rejects_bad_base64_before_touching_the_update_store() {
        let (state, root) = state("base64");
        let error = match chunk(
            State(state),
            Json(ChunkRequest {
                release_sequence: 7,
                offset: 0,
                data: "%%%".into(),
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("invalid base64 was accepted"),
        };

        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("invalid base64 fragment"));
        assert!(
            !root.exists(),
            "decoding failure must not create staging state"
        );
    }

    #[tokio::test]
    async fn store_rejections_are_422_for_chunk_finalize_and_activation() {
        let (state, root) = state("rejections");

        let chunk_error = match chunk(
            State(state.clone()),
            Json(ChunkRequest {
                release_sequence: 9,
                offset: 0,
                data: STANDARD.encode(b"fragment"),
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("unstaged release accepted a chunk"),
        };
        assert_eq!(chunk_error.0, StatusCode::UNPROCESSABLE_ENTITY);

        let finalize_error = match finalize(
            State(state.clone()),
            Json(SequenceRequest {
                release_sequence: 9,
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("unstaged release was finalized"),
        };
        assert_eq!(finalize_error.0, StatusCode::UNPROCESSABLE_ENTITY);

        let activation_error = match activate(
            State(state),
            Json(ActivateRequest {
                release_sequence: 9,
                confirmation: "wrong".into(),
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("bad activation confirmation was accepted"),
        };
        assert_eq!(activation_error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(activation_error
            .1
            .contains("incorrect activation confirmation"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn error_mapping_separates_rejection_from_internal_failure() {
        let rejected = rejected(aether::HeliosError::Update("invalid manifest".into()));
        assert_eq!(rejected.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(rejected.1.contains("invalid manifest"));

        let internal = internal_error(aether::HeliosError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        )));
        assert_eq!(internal.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(internal.1.contains("denied"));
    }

    #[test]
    fn request_documents_reject_unknown_fields() {
        assert!(serde_json::from_str::<ChunkRequest>(
            r#"{"release_sequence":1,"offset":0,"data":"YQ==","extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ActivateRequest>(
            r#"{"release_sequence":1,"confirmation":"INSTALLER 1","extra":true}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<SequenceRequest>(r#"{"release_sequence":1,"extra":true}"#)
                .is_err()
        );
    }
}
