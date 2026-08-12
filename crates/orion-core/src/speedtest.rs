//! Measures the usable WireGuard path between Orion and its Helios gateway.
//!
//! The gateway API is reachable only through WireGuard, so every byte measured
//! here follows the same route as the user's traffic. The engine deliberately
//! avoids a fixed, single transfer: TCP slow start and a payload that is too
//! short can under-report a fast path by an order of magnitude.
//!
//! A run therefore has four stages:
//!
//! 1. warm the HTTP connection, then collect enough RTT samples for a robust
//!    median and median absolute deviation;
//! 2. calibrate a chunk size independently in each direction;
//! 3. warm four HTTP/1 connections so the measured windows start at steady
//!    state;
//! 4. run three bounded windows and report their median rate and variation.
//!
//! Bodies are streamed and counted, never accumulated on download. Uploads
//! share one immutable buffer between workers. Both the request size and the
//! total measured traffic are bounded.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{future::try_join_all, StreamExt as _};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};

/// Fixed in-tunnel API destination used by the performance probe.
///
/// The endpoint is deliberately not read from the editable profile: the
/// speedtest is valid only when this request reaches Helios through the
/// already-mounted WireGuard interface. The route itself is authenticated by
/// the gateway's WireGuard peer middleware.
pub const DEFAULT_GATEWAY_URL: &str = aether::DEFAULT_WG_API_URL;

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

#[derive(Debug, Clone, Copy)]
struct EngineConfig {
    latency_warmups: usize,
    latency_samples: usize,
    latency_gap: Duration,
    parallel_streams: usize,
    rounds: usize,
    round_duration: Duration,
    min_chunk_bytes: usize,
    max_chunk_bytes: usize,
    calibration_min_duration: Duration,
    target_chunk_duration: Duration,
    connection_warmup_bytes: usize,
    max_measured_bytes: u64,
    request_timeout: Duration,
}

const STANDARD_CONFIG: EngineConfig = EngineConfig {
    latency_warmups: LATENCY_WARMUP_SAMPLES,
    latency_samples: LATENCY_SAMPLES,
    latency_gap: LATENCY_SAMPLE_GAP,
    parallel_streams: PARALLEL_STREAMS,
    rounds: MEASUREMENT_ROUNDS,
    round_duration: ROUND_DURATION,
    min_chunk_bytes: MIN_CHUNK_BYTES,
    max_chunk_bytes: MAX_CHUNK_BYTES,
    calibration_min_duration: CALIBRATION_MIN_DURATION,
    target_chunk_duration: TARGET_CHUNK_DURATION,
    connection_warmup_bytes: CONNECTION_WARMUP_BYTES,
    max_measured_bytes: MAX_MEASURED_BYTES_PER_DIRECTION,
    request_timeout: REQUEST_TIMEOUT,
};

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
}

/// Failures returned to the Tauri shell and rendered by the UI.
#[derive(Debug, thiserror::Error)]
pub enum SpeedTestError {
    #[error("URL de la gateway invalide : {0}")]
    InvalidUrl(String),
    #[error("transport du speedtest impossible : {0}")]
    Transport(String),
    #[error("la gateway a refusé le speedtest (HTTP {status}) : {body}")]
    Rejected { status: u16, body: String },
    #[error("réponse du speedtest illisible : {0}")]
    BadResponse(String),
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Download,
    Upload,
}

#[derive(Debug, Clone, Copy)]
struct TransferMeasurement {
    bytes: u64,
    elapsed: Duration,
}

impl TransferMeasurement {
    fn mbps(self) -> f64 {
        rate_mbps(self.bytes, self.elapsed)
    }
}

#[derive(Debug)]
struct DirectionMeasurement {
    mbps: f64,
    variation_pct: f64,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct RoundPlan {
    chunk_bytes: usize,
    upload_payload: Option<Arc<Bytes>>,
    workers: usize,
    duration: Duration,
    byte_budget: u64,
}

/// Runs the standard adaptive measurement against the gateway's in-tunnel API.
pub async fn run() -> Result<SpeedTestResult, SpeedTestError> {
    run_at(DEFAULT_GATEWAY_URL).await
}

/// Runs a measurement against an explicit URL.
///
/// This narrow entry point exists for local engine tests and controlled
/// diagnostics. The Orion UI never supplies a URL; production calls use
/// [`run`], which targets the gateway address inside WireGuard.
pub async fn run_at(gateway_url: &str) -> Result<SpeedTestResult, SpeedTestError> {
    run_with_config(gateway_url, STANDARD_CONFIG).await
}

async fn run_with_config(
    gateway_url: &str,
    config: EngineConfig,
) -> Result<SpeedTestResult, SpeedTestError> {
    validate_config(config)?;
    let base = reqwest::Url::parse(gateway_url.trim_end_matches('/'))
        .map_err(|error| SpeedTestError::InvalidUrl(error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(SpeedTestError::InvalidUrl(
            "seuls http:// et https:// sont acceptés".into(),
        ));
    }

    // Environment proxies would move the request away from WireGuard and make
    // the number meaningless. HTTP/1 is forced so four workers represent four
    // independent TCP congestion windows rather than four HTTP/2 streams on a
    // single connection.
    let client = Client::builder()
        .timeout(config.request_timeout)
        .connect_timeout(config.request_timeout.min(Duration::from_secs(5)))
        .tcp_nodelay(true)
        .http1_only()
        .pool_max_idle_per_host(config.parallel_streams)
        .no_proxy()
        .build()
        .map_err(|error| SpeedTestError::Transport(error.to_string()))?;
    let started = Instant::now();

    let (latency_ms, jitter_ms, latency_p95_ms) = measure_latency(&client, &base, config).await?;
    let download = measure_direction(Direction::Download, &client, &base, config).await?;
    let upload = measure_direction(Direction::Upload, &client, &base, config).await?;

    Ok(SpeedTestResult {
        latency_ms,
        jitter_ms,
        latency_p95_ms,
        download_mbps: download.mbps,
        upload_mbps: upload.mbps,
        download_variation_pct: download.variation_pct,
        upload_variation_pct: upload.variation_pct,
        duration_ms: saturating_millis(started.elapsed()),
        download_bytes: download.bytes,
        upload_bytes: upload.bytes,
        parallel_streams: config.parallel_streams,
        measurement_rounds: config.rounds,
    })
}

fn validate_config(config: EngineConfig) -> Result<(), SpeedTestError> {
    if config.latency_samples == 0
        || config.parallel_streams == 0
        || config.rounds == 0
        || config.min_chunk_bytes == 0
        || config.min_chunk_bytes > config.max_chunk_bytes
        || config.round_duration.is_zero()
        || config.max_measured_bytes / (config.rounds as u64) < config.min_chunk_bytes as u64
    {
        return Err(SpeedTestError::BadResponse(
            "configuration interne du speedtest invalide".into(),
        ));
    }
    Ok(())
}

async fn measure_latency(
    client: &Client,
    base: &reqwest::Url,
    config: EngineConfig,
) -> Result<(f64, f64, f64), SpeedTestError> {
    let url = endpoint(base, "/api/speedtest/ping");
    for _ in 0..config.latency_warmups {
        ping_once(client, url.clone()).await?;
    }

    let mut samples = Vec::with_capacity(config.latency_samples);
    for index in 0..config.latency_samples {
        samples.push(ping_once(client, url.clone()).await?.as_secs_f64() * 1_000.0);
        if index + 1 < config.latency_samples && !config.latency_gap.is_zero() {
            tokio::time::sleep(config.latency_gap).await;
        }
    }
    samples.sort_by(f64::total_cmp);
    let median = percentile_sorted(&samples, 0.5);
    let p95 = percentile_sorted(&samples, 0.95);
    let mut deviations: Vec<f64> = samples
        .iter()
        .map(|sample| (sample - median).abs())
        .collect();
    deviations.sort_by(f64::total_cmp);
    let jitter = percentile_sorted(&deviations, 0.5);
    Ok((median, jitter, p95))
}

async fn ping_once(client: &Client, url: reqwest::Url) -> Result<Duration, SpeedTestError> {
    let started = Instant::now();
    let response = client
        .get(url)
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .send()
        .await
        .map_err(transport_error)?;
    ensure_success(response).await?;
    Ok(started.elapsed())
}

async fn measure_direction(
    direction: Direction,
    client: &Client,
    base: &reqwest::Url,
    config: EngineConfig,
) -> Result<DirectionMeasurement, SpeedTestError> {
    let chunk_bytes = calibrate_chunk(direction, client, base, config).await?;
    let upload_payload =
        matches!(direction, Direction::Upload).then(|| Arc::new(upload_payload(chunk_bytes)));
    warm_connections(
        direction,
        client,
        base,
        chunk_bytes.min(config.connection_warmup_bytes),
        config.parallel_streams,
    )
    .await?;

    let per_round_budget = config.max_measured_bytes / config.rounds as u64;
    let round_plan = RoundPlan {
        chunk_bytes,
        upload_payload,
        workers: config.parallel_streams,
        duration: config.round_duration,
        byte_budget: per_round_budget,
    };
    let mut rounds = Vec::with_capacity(config.rounds);
    for _ in 0..config.rounds {
        rounds.push(measured_round(direction, client, base, round_plan.clone()).await?);
    }

    let bytes = rounds.iter().map(|round| round.bytes).sum();
    let mut rates: Vec<f64> = rounds.iter().map(|round| round.mbps()).collect();
    let variation_pct = coefficient_of_variation_pct(&rates);
    rates.sort_by(f64::total_cmp);
    Ok(DirectionMeasurement {
        mbps: percentile_sorted(&rates, 0.5),
        variation_pct,
        bytes,
    })
}

async fn calibrate_chunk(
    direction: Direction,
    client: &Client,
    base: &reqwest::Url,
    config: EngineConfig,
) -> Result<usize, SpeedTestError> {
    let mut bytes = config.min_chunk_bytes;
    loop {
        let payload = matches!(direction, Direction::Upload).then(|| upload_payload(bytes));
        let elapsed = transfer_once(direction, client, base, bytes, payload).await?;
        if elapsed >= config.calibration_min_duration || bytes >= config.max_chunk_bytes {
            let bytes_per_second = bytes as f64 / elapsed.as_secs_f64().max(f64::EPSILON);
            let target = bytes_per_second * config.target_chunk_duration.as_secs_f64();
            return Ok(align_chunk_size(
                target as usize,
                config.min_chunk_bytes,
                config.max_chunk_bytes,
            ));
        }
        bytes = bytes.saturating_mul(4).min(config.max_chunk_bytes);
    }
}

async fn warm_connections(
    direction: Direction,
    client: &Client,
    base: &reqwest::Url,
    bytes: usize,
    workers: usize,
) -> Result<(), SpeedTestError> {
    let payload = matches!(direction, Direction::Upload).then(|| upload_payload(bytes));
    let tasks = (0..workers).map(|_| {
        let payload = payload.clone();
        async move {
            transfer_once(direction, client, base, bytes, payload).await?;
            Ok::<(), SpeedTestError>(())
        }
    });
    try_join_all(tasks).await.map(|_| ())
}

async fn measured_round(
    direction: Direction,
    client: &Client,
    base: &reqwest::Url,
    plan: RoundPlan,
) -> Result<TransferMeasurement, SpeedTestError> {
    let reserved = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let deadline = started + plan.duration;
    let tasks = (0..plan.workers).map(|_| {
        let reserved = Arc::clone(&reserved);
        let completed = Arc::clone(&completed);
        let payload = plan.upload_payload.clone();
        async move {
            loop {
                if Instant::now() >= deadline
                    || !reserve_bytes(&reserved, plan.chunk_bytes as u64, plan.byte_budget)
                {
                    break;
                }
                transfer_once(
                    direction,
                    client,
                    base,
                    plan.chunk_bytes,
                    payload.as_deref().cloned(),
                )
                .await?;
                completed.fetch_add(plan.chunk_bytes as u64, Ordering::Relaxed);
            }
            Ok::<(), SpeedTestError>(())
        }
    });
    try_join_all(tasks).await?;
    let elapsed = started.elapsed();
    let bytes = completed.load(Ordering::Relaxed);
    if bytes == 0 {
        return Err(SpeedTestError::BadResponse(
            "aucune donnée mesurée pendant la fenêtre de débit".into(),
        ));
    }
    Ok(TransferMeasurement { bytes, elapsed })
}

async fn transfer_once(
    direction: Direction,
    client: &Client,
    base: &reqwest::Url,
    bytes: usize,
    upload_payload: Option<Bytes>,
) -> Result<Duration, SpeedTestError> {
    match direction {
        Direction::Download => download_once(client, base, bytes).await,
        Direction::Upload => {
            let payload = upload_payload.unwrap_or_else(|| upload_payload_fn(bytes));
            upload_once(client, base, bytes, payload).await
        }
    }
}

async fn download_once(
    client: &Client,
    base: &reqwest::Url,
    expected_bytes: usize,
) -> Result<Duration, SpeedTestError> {
    let response = client
        .get(with_bytes_query(
            base,
            "/api/speedtest/download",
            expected_bytes,
        ))
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(transport_error)?;
    let response = success_or_error(response).await?;
    if response.content_length() != Some(expected_bytes as u64) {
        return Err(SpeedTestError::BadResponse(
            "la gateway n’annonce pas la taille de téléchargement demandée".into(),
        ));
    }

    // Headers and request latency are excluded from the payload throughput.
    // The multi-window phase itself still includes request turnover, so the
    // final aggregate remains an honest application-level rate.
    let started = Instant::now();
    consume_exact_body(response, expected_bytes).await?;
    Ok(started.elapsed())
}

async fn upload_once(
    client: &Client,
    base: &reqwest::Url,
    expected_bytes: usize,
    payload: Bytes,
) -> Result<Duration, SpeedTestError> {
    let started = Instant::now();
    let response = client
        .post(with_bytes_query(
            base,
            "/api/speedtest/upload",
            expected_bytes,
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .body(payload)
        .send()
        .await
        .map_err(transport_error)?;
    let response = success_or_error(response).await?;
    consume_exact_body(response, 0).await?;
    Ok(started.elapsed())
}

async fn consume_exact_body(
    response: Response,
    expected_bytes: usize,
) -> Result<(), SpeedTestError> {
    let mut received = 0usize;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| SpeedTestError::BadResponse(error.to_string()))?;
        received = received
            .checked_add(chunk.len())
            .ok_or_else(|| SpeedTestError::BadResponse("taille de réponse débordée".into()))?;
        if received > expected_bytes {
            return Err(SpeedTestError::BadResponse(
                "la réponse dépasse la taille demandée".into(),
            ));
        }
    }
    if received != expected_bytes {
        return Err(SpeedTestError::BadResponse(format!(
            "la réponse a livré {received} octets au lieu de {expected_bytes}"
        )));
    }
    Ok(())
}

fn upload_payload(bytes: usize) -> Bytes {
    upload_payload_fn(bytes)
}

fn upload_payload_fn(bytes: usize) -> Bytes {
    // Built before every timed transfer family and cloned by reference-counted
    // `Bytes` in measured rounds. Allocation and page initialization therefore
    // never enter the reported upload rate.
    Bytes::from(vec![0x5a; bytes])
}

fn reserve_bytes(counter: &AtomicU64, bytes: u64, limit: u64) -> bool {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(bytes).filter(|next| *next <= limit)
        })
        .is_ok()
}

fn align_chunk_size(value: usize, minimum: usize, maximum: usize) -> usize {
    const ALIGNMENT: usize = 64 * 1024;
    let clamped = value.clamp(minimum, maximum);
    clamped
        .saturating_add(ALIGNMENT - 1)
        .checked_div(ALIGNMENT)
        .unwrap_or(1)
        .saturating_mul(ALIGNMENT)
        .clamp(minimum, maximum)
}

fn endpoint(base: &reqwest::Url, path: &str) -> reqwest::Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url
}

fn with_bytes_query(base: &reqwest::Url, path: &str, bytes: usize) -> reqwest::Url {
    let mut url = endpoint(base, path);
    url.set_query(Some(&format!("bytes={bytes}")));
    url
}

async fn success_or_error(response: Response) -> Result<Response, SpeedTestError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| SpeedTestError::BadResponse(error.to_string()))?;
        let remaining = ERROR_BODY_LIMIT.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Err(SpeedTestError::Rejected {
        status: status.as_u16(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

async fn ensure_success(response: Response) -> Result<(), SpeedTestError> {
    let response = success_or_error(response).await?;
    consume_exact_body(response, 0).await
}

fn transport_error(error: reqwest::Error) -> SpeedTestError {
    SpeedTestError::Transport(error.to_string())
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
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn adaptive_engine_uses_latency_and_both_transfer_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let paths = Arc::new(Mutex::new(Vec::new()));
        let captured_paths = Arc::clone(&paths);
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let paths = Arc::clone(&captured_paths);
                tokio::spawn(async move {
                    serve_one_request(stream, paths).await;
                });
            }
        });

        let config = EngineConfig {
            latency_warmups: 1,
            latency_samples: 3,
            latency_gap: Duration::ZERO,
            parallel_streams: 2,
            rounds: 2,
            round_duration: Duration::from_millis(15),
            min_chunk_bytes: 1024,
            max_chunk_bytes: 1024,
            calibration_min_duration: Duration::ZERO,
            target_chunk_duration: Duration::from_millis(1),
            connection_warmup_bytes: 1024,
            max_measured_bytes: 64 * 1024,
            request_timeout: Duration::from_secs(5),
        };
        let result = run_with_config(&format!("http://{address}/ignored"), config)
            .await
            .expect("speedtest");
        server.abort();

        assert!(result.download_bytes > 0);
        assert!(result.upload_bytes > 0);
        assert!(result.download_mbps > 0.0);
        assert!(result.upload_mbps > 0.0);
        assert_eq!(result.parallel_streams, 2);
        assert_eq!(result.measurement_rounds, 2);
        let paths = paths.lock().unwrap();
        assert!(paths.iter().any(|path| path == "/api/speedtest/ping"));
        assert!(paths
            .iter()
            .any(|path| path.starts_with("/api/speedtest/download?bytes=")));
        assert!(paths
            .iter()
            .any(|path| path.starts_with("/api/speedtest/upload?bytes=")));
    }

    async fn serve_one_request(mut stream: tokio::net::TcpStream, paths: Arc<Mutex<Vec<String>>>) {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.expect("request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("headers")
            + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let first_line = headers.lines().next().expect("request line");
        let mut words = first_line.split_whitespace();
        let method = words.next().expect("method");
        let path = words.next().expect("path").to_string();
        paths.lock().unwrap().push(path.clone());
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or_default();
        let already_read = request.len() - header_end;
        if content_length > already_read {
            let mut remaining = vec![0u8; content_length - already_read];
            stream.read_exact(&mut remaining).await.expect("upload");
        }

        if path.starts_with("/api/speedtest/download") {
            let bytes = query_bytes(&path);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("download headers");
            stream
                .write_all(&vec![0x31; bytes])
                .await
                .expect("download body");
        } else {
            assert!(method == "GET" || content_length == query_bytes(&path));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("response");
        }
    }

    fn query_bytes(path: &str) -> usize {
        path.split_once("bytes=")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or_default()
    }

    #[test]
    fn robust_statistics_reject_order_and_express_variation() {
        let mut values = vec![900.0, 100.0, 110.0];
        assert!(coefficient_of_variation_pct(&values) > 90.0);
        values.sort_by(f64::total_cmp);
        assert_eq!(percentile_sorted(&values, 0.5), 110.0);
        assert_eq!(percentile_sorted(&values, 0.95), 900.0);
    }

    #[test]
    fn chunk_sizes_are_aligned_and_bounded() {
        assert_eq!(align_chunk_size(1, 32 * 1024, 1024 * 1024), 64 * 1024);
        assert_eq!(
            align_chunk_size(usize::MAX, 32 * 1024, 1024 * 1024),
            1024 * 1024
        );
    }

    #[tokio::test]
    async fn rejects_non_http_urls_before_network_access() {
        let error = run_at("file:///etc/hosts").await.expect_err("invalid URL");
        assert!(matches!(error, SpeedTestError::InvalidUrl(_)));
    }
}
