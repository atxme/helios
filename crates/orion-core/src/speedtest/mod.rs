//! Measures the usable WireGuard path between Orion and its Helios gateway.
//!
//! The gateway service is reachable only through WireGuard, so every measured
//! byte follows the same route as the user's traffic. The production path uses
//! `std::net` TCP/UDP sockets directly: HTTP headers, body parsing, repeated
//! requests and Tokio wake-ups are outside the timed data path.
//!
//! A run collects robust UDP RTT samples, prepares four persistent TCP flows,
//! then measures each requested direction for a configurable interval long
//! enough for TCP to reach steady state. UDP uses fixed WireGuard-safe
//! datagrams and reports loss where sequence counters are available. The old
//! HTTP adapter remains only for controlled compatibility tests; Orion's
//! command never selects it.

use aether::speedtest::Pacer;
use std::{
    io::{Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{future::try_join_all, StreamExt as _};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};

/// Fixed in-tunnel HTTP destination retained for the compatibility adapter.
///
/// The production speedtest uses [`aether::DEFAULT_WG_SPEEDTEST_ADDR`] and a
/// raw socket. It is deliberately not read from the editable profile.
pub const DEFAULT_GATEWAY_URL: &str = aether::DEFAULT_WG_API_URL;

/// Transport selected for the raw measurement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpeedTestMode {
    Tcp,
    Udp,
    Full,
}

impl SpeedTestMode {
    /// Parses the value received from the Tauri UI.
    pub fn parse(value: &str) -> Result<Self, SpeedTestError> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "full" => Ok(Self::Full),
            other => Err(SpeedTestError::InvalidMode(other.to_string())),
        }
    }
}

/// Progress emitted while the raw socket test is running.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SpeedTestProgress {
    pub phase: SpeedTestPhase,
    pub fraction: f64,
    pub current_mbps: f64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub message: String,
}

/// A phase is intentionally explicit so the UI never infers direction from
/// a half-filled progress bar.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpeedTestPhase {
    Preparing,
    Latency,
    TcpDownload,
    TcpUpload,
    UdpDownload,
    UdpUpload,
    Complete,
}

/// Callback used by the Tauri shell to relay progress without putting a UI
/// concern into the transport engine.
pub type SpeedTestProgressSink = Arc<dyn Fn(SpeedTestProgress) + Send + Sync>;

/// Number of RTT observations retained after the two warm-up requests.
pub const LATENCY_SAMPLES: usize = 11;
/// Independent HTTP/1/TCP flows used to fill the path without depending on a
/// single congestion window.
pub const PARALLEL_STREAMS: usize = 4;
/// Independent windows per direction. The median rejects a transient spike or
/// scheduler pause without hiding a consistently unstable path.
pub const MEASUREMENT_ROUNDS: usize = 3;
/// Nominal duration of one measured window.
pub const ROUND_DURATION: Duration = Duration::from_millis(1_500);
/// Total measured traffic ceiling per direction. Calibration and connection
/// warm-up are small and bounded separately by [`MAX_CHUNK_BYTES`].
pub const MAX_MEASURED_BYTES_PER_DIRECTION: u64 = 1024 * 1024 * 1024;
/// Per-request timeout. A path slower than this cannot produce a meaningful
/// interactive speedtest and must fail explicitly.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const LATENCY_WARMUP_SAMPLES: usize = 2;
const LATENCY_SAMPLE_GAP: Duration = Duration::from_millis(20);
const MIN_CHUNK_BYTES: usize = 32 * 1024;
const MAX_CHUNK_BYTES: usize = 32 * 1024 * 1024;
const CALIBRATION_MIN_DURATION: Duration = Duration::from_millis(120);
const TARGET_CHUNK_DURATION: Duration = Duration::from_millis(350);
const CONNECTION_WARMUP_BYTES: usize = 256 * 1024;
const ERROR_BODY_LIMIT: usize = 4 * 1024;

/// How long a UDP leg waits for the gateway to admit its session.
///
/// The hello and the ready are two datagrams on the very service whose loss
/// the leg is about to measure, so the handshake needs the patience of the
/// latency probe rather than the 100 ms the data loops poll on. Without it a
/// single dropped frame — routine on a tunnel that has just carried twenty
/// seconds of TCP at line rate — ended the whole run.
const UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
/// Gap between two hellos while the gateway has not answered.
///
/// Above the round trip of any path this test is meant for, so a retry is a
/// reaction to a lost frame and not a second copy racing the first.
const UDP_HANDSHAKE_RETRY: Duration = Duration::from_millis(250);

mod failure;
mod http;
mod raw;
mod udp;
mod wire;

pub use http::run_at;

// What the sibling modules and the tests name of each other, through
// `use super::*`.
use self::{failure::*, raw::*, udp::*, wire::*};
// Only the tests name the HTTP engine's configuration.
#[cfg(test)]
use self::http::*;

/// Result shown by the Orion speedtest screen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpeedTestResult {
    /// Median round-trip time to the gateway, in milliseconds.
    pub latency_ms: f64,
    /// Median absolute deviation of the RTT samples.
    pub jitter_ms: f64,
    /// 95th percentile of the RTT samples.
    pub latency_p95_ms: f64,
    /// Median gateway-to-Orion rate across the measured windows.
    pub download_mbps: f64,
    /// Median Orion-to-gateway rate across the measured windows.
    pub upload_mbps: f64,
    /// Coefficient of variation of the download windows.
    pub download_variation_pct: f64,
    /// Coefficient of variation of the upload windows.
    pub upload_variation_pct: f64,
    /// Total wall-clock time for the complete run.
    pub duration_ms: u64,
    /// Bytes counted in measured windows; calibration is excluded.
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub parallel_streams: usize,
    pub measurement_rounds: usize,
    /// Primary raw-socket result. HTTP compatibility probes leave this at
    /// `None`; the Orion command always returns the direct TCP/UDP values.
    pub mode: SpeedTestMode,
    pub tcp_download_mbps: Option<f64>,
    pub tcp_upload_mbps: Option<f64>,
    pub udp_download_mbps: Option<f64>,
    pub udp_upload_mbps: Option<f64>,
    pub udp_loss_pct: Option<f64>,
    pub udp_jitter_ms: Option<f64>,
    pub tcp_streams: usize,
    pub test_duration_secs: u16,
}

/// Failures returned to the Tauri shell and rendered by the UI.
#[derive(Debug, thiserror::Error)]
pub enum SpeedTestError {
    #[error("mode de speedtest invalide : {0}")]
    InvalidMode(String),
    #[error(
        "le mode {0} exige un débit de référence : sans mesure TCP préalable, \
         une perte UDP ne mesure que l'écart entre l'émetteur et le lien"
    )]
    MissingQualityRate(&'static str),
    #[error("URL de la gateway invalide : {0}")]
    InvalidUrl(String),
    #[error("transport du speedtest impossible : {0}")]
    Transport(String),
    #[error(
        "la gateway ne sert pas le speedtest Helios sur le port {port} ({detail}). Soit heliosd \
         n’a pas pu s’y lier — un autre programme l’occupe, iperf3 en écoute sur \
         0.0.0.0:{port} étant le cas courant —, soit le service est tombé. Le journal de heliosd \
         le dit : « raw speedtest »"
    )]
    ServiceAbsent { port: u16, detail: String },
    #[error(
        "aucune réponse de la gateway sur le port {port} ({detail}). Les paquets partent dans le \
         tunnel et rien ne revient — ni donnée, ni refus. Soit heliosd n’écoute pas sur l’adresse \
         du tunnel — son journal l’annonce : « raw speedtest on … » —, soit le pare-feu de la \
         gateway n’ouvre pas ce port sur l’interface WireGuard. Sur la gateway : \
         `ss -lntup | grep {port}` et `nft list chain inet helios input`"
    )]
    Unreachable { port: u16, detail: String },
    #[error("la gateway a refusé le speedtest (HTTP {status}) : {body}")]
    Rejected { status: u16, body: String },
    #[error("réponse du speedtest illisible : {0}")]
    BadResponse(String),
}

/// Runs the raw-socket measurement against the gateway's in-tunnel service.
pub async fn run() -> Result<SpeedTestResult, SpeedTestError> {
    run_with_progress(
        SpeedTestMode::Full,
        aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
        None,
        Arc::new(|_| {}),
    )
    .await
}

/// Runs the direct TCP/UDP test and streams progress to the caller.
/// Runs the direct TCP/UDP test and streams progress to the caller.
///
/// `quality_rate_mbps` overrides the rate the UDP legs are driven at. Leave it
/// `None` in [`SpeedTestMode::Full`], where the rate is derived from the TCP
/// throughput just measured — that is the reference that makes a loss figure
/// mean something. [`SpeedTestMode::Udp`] has no such reference and therefore
/// **requires** the override; without it the run is refused rather than
/// reporting the loss of an unpaced blast.
pub async fn run_with_progress(
    mode: SpeedTestMode,
    duration_secs: u16,
    quality_rate_mbps: Option<f64>,
    progress: SpeedTestProgressSink,
) -> Result<SpeedTestResult, SpeedTestError> {
    validate_raw_duration(duration_secs)?;
    if matches!(mode, SpeedTestMode::Udp) && quality_rate_mbps.is_none() {
        return Err(SpeedTestError::MissingQualityRate("udp"));
    }
    tokio::task::spawn_blocking(move || {
        run_raw_blocking(mode, duration_secs, quality_rate_mbps, progress)
    })
    .await
    .map_err(|error| SpeedTestError::Transport(error.to_string()))?
}

fn percentile_sorted(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let rank = ((values.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
    values[rank]
}

fn coefficient_of_variation_pct(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean <= f64::EPSILON {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt() / mean * 100.0
}

fn rate_mbps(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    bytes as f64 * 8.0 / seconds / 1_000_000.0
}

fn saturating_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests;
