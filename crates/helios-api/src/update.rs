//! API d’administration des mises à jour applicatives signées.

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
            format!("fragment base64 invalide : {e}"),
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
