//! The HTTP engine: calibrated rounds of parallel transfers against the
//! gateway's speed-test routes.

use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) struct EngineConfig {
    pub(super) latency_warmups: usize,
    pub(super) latency_samples: usize,
    pub(super) latency_gap: Duration,
    pub(super) parallel_streams: usize,
    pub(super) rounds: usize,
    pub(super) round_duration: Duration,
    pub(super) min_chunk_bytes: usize,
    pub(super) max_chunk_bytes: usize,
    pub(super) calibration_min_duration: Duration,
    pub(super) target_chunk_duration: Duration,
    pub(super) connection_warmup_bytes: usize,
    pub(super) max_measured_bytes: u64,
    pub(super) request_timeout: Duration,
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

/// Runs a measurement against an explicit URL.
///
/// This narrow entry point exists for local engine tests and controlled
/// diagnostics. The Orion UI never supplies a URL; production calls use
/// [`run`], which targets the gateway address inside WireGuard.
pub async fn run_at(gateway_url: &str) -> Result<SpeedTestResult, SpeedTestError> {
    run_with_config(gateway_url, STANDARD_CONFIG).await
}

pub(super) async fn run_with_config(
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
        mode: SpeedTestMode::Tcp,
        tcp_download_mbps: Some(download.mbps),
        tcp_upload_mbps: Some(upload.mbps),
        udp_download_mbps: None,
        udp_upload_mbps: None,
        udp_loss_pct: None,
        udp_jitter_ms: None,
        tcp_streams: config.parallel_streams,
        test_duration_secs: 0,
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

pub(super) fn align_chunk_size(value: usize, minimum: usize, maximum: usize) -> usize {
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
