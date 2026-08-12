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

/// Runs the raw-socket measurement against the gateway's in-tunnel service.
pub async fn run() -> Result<SpeedTestResult, SpeedTestError> {
    run_with_progress(
        SpeedTestMode::Full,
        aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
        Arc::new(|_| {}),
    )
    .await
}

/// Runs the direct TCP/UDP test and streams progress to the caller.
pub async fn run_with_progress(
    mode: SpeedTestMode,
    duration_secs: u16,
    progress: SpeedTestProgressSink,
) -> Result<SpeedTestResult, SpeedTestError> {
    validate_raw_duration(duration_secs)?;
    tokio::task::spawn_blocking(move || run_raw_blocking(mode, duration_secs, progress))
        .await
        .map_err(|error| SpeedTestError::Transport(error.to_string()))?
}

fn run_raw_blocking(
    mode: SpeedTestMode,
    duration_secs: u16,
    progress: SpeedTestProgressSink,
) -> Result<SpeedTestResult, SpeedTestError> {
    let target: SocketAddr = aether::DEFAULT_WG_SPEEDTEST_ADDR
        .parse()
        .map_err(|error| SpeedTestError::InvalidUrl(format!("cible socket invalide : {error}")))?;
    run_raw_blocking_at(target, mode, duration_secs, progress)
}

fn run_raw_blocking_at(
    target: SocketAddr,
    mode: SpeedTestMode,
    duration_secs: u16,
    progress: SpeedTestProgressSink,
) -> Result<SpeedTestResult, SpeedTestError> {
    let started = Instant::now();
    emit_progress(
        &progress,
        SpeedTestPhase::Preparing,
        0.0,
        0.0,
        0,
        started,
        "Préparation des sockets directes",
    );

    emit_progress(
        &progress,
        SpeedTestPhase::Latency,
        0.0,
        0.0,
        0,
        started,
        "Mesure de la latence UDP",
    );
    let (latency_ms, jitter_ms, latency_p95_ms) = measure_raw_latency(target)?;

    let tcp_download = if matches!(mode, SpeedTestMode::Tcp | SpeedTestMode::Full) {
        Some(measure_raw_tcp(
            target,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
            duration_secs,
            SpeedTestPhase::TcpDownload,
            &progress,
            started,
        )?)
    } else {
        None
    };
    let tcp_upload = if matches!(mode, SpeedTestMode::Tcp | SpeedTestMode::Full) {
        Some(measure_raw_tcp(
            target,
            aether::speedtest::SPEEDTEST_MODE_UPLOAD,
            duration_secs,
            SpeedTestPhase::TcpUpload,
            &progress,
            started,
        )?)
    } else {
        None
    };
    let udp_download = if matches!(mode, SpeedTestMode::Udp | SpeedTestMode::Full) {
        Some(measure_raw_udp(
            target,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
            duration_secs,
            SpeedTestPhase::UdpDownload,
            &progress,
            started,
        )?)
    } else {
        None
    };
    let udp_upload = if matches!(mode, SpeedTestMode::Udp | SpeedTestMode::Full) {
        Some(measure_raw_udp(
            target,
            aether::speedtest::SPEEDTEST_MODE_UPLOAD,
            duration_secs,
            SpeedTestPhase::UdpUpload,
            &progress,
            started,
        )?)
    } else {
        None
    };

    let tcp_down_mbps = tcp_download.as_ref().map(|measurement| measurement.mbps);
    let tcp_up_mbps = tcp_upload.as_ref().map(|measurement| measurement.mbps);
    let udp_down_mbps = udp_download.as_ref().map(|measurement| measurement.mbps);
    let udp_up_mbps = udp_upload.as_ref().map(|measurement| measurement.mbps);
    let udp_loss_pct = [udp_download.as_ref(), udp_upload.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|measurement| measurement.loss_pct)
        .reduce(|left, right| (left + right) / 2.0);
    let udp_jitter_ms = [udp_download.as_ref(), udp_upload.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|measurement| measurement.jitter_ms)
        .reduce(|left, right| (left + right) / 2.0);
    let download_mbps = tcp_down_mbps.or(udp_down_mbps).unwrap_or_default();
    let upload_mbps = tcp_up_mbps.or(udp_up_mbps).unwrap_or_default();
    let download_bytes = tcp_download
        .as_ref()
        .map_or(0, |measurement| measurement.bytes)
        .saturating_add(
            udp_download
                .as_ref()
                .map_or(0, |measurement| measurement.bytes),
        );
    let upload_bytes = tcp_upload
        .as_ref()
        .map_or(0, |measurement| measurement.bytes)
        .saturating_add(
            udp_upload
                .as_ref()
                .map_or(0, |measurement| measurement.bytes),
        );
    let duration_ms = saturating_millis(started.elapsed());
    let result = SpeedTestResult {
        latency_ms,
        jitter_ms,
        latency_p95_ms,
        download_mbps,
        upload_mbps,
        download_variation_pct: 0.0,
        upload_variation_pct: 0.0,
        duration_ms,
        download_bytes,
        upload_bytes,
        parallel_streams: aether::speedtest::SPEEDTEST_TCP_STREAMS,
        measurement_rounds: 1,
        mode,
        tcp_download_mbps: tcp_down_mbps,
        tcp_upload_mbps: tcp_up_mbps,
        udp_download_mbps: udp_down_mbps,
        udp_upload_mbps: udp_up_mbps,
        udp_loss_pct,
        udp_jitter_ms,
        tcp_streams: aether::speedtest::SPEEDTEST_TCP_STREAMS,
        test_duration_secs: duration_secs,
    };
    emit_progress(
        &progress,
        SpeedTestPhase::Complete,
        1.0,
        result
            .tcp_download_mbps
            .or(result.udp_download_mbps)
            .unwrap_or_default(),
        result.download_bytes.saturating_add(result.upload_bytes),
        started,
        "Mesure terminée",
    );
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
struct RawMeasurement {
    mbps: f64,
    bytes: u64,
    loss_pct: Option<f64>,
    jitter_ms: Option<f64>,
}

fn measure_raw_latency(target: SocketAddr) -> Result<(f64, f64, f64), SpeedTestError> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(raw_transport)?;
    socket.connect(target).map_err(raw_transport)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(raw_transport)?;
    let mut samples = Vec::with_capacity(11);
    let mut response = [0u8; aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES];
    for _ in 0..11 {
        let session = next_session();
        let request = udp_frame(aether::speedtest::UDP_KIND_PING, 0, session, 0, 0, &[]);
        let started = Instant::now();
        socket.send(&request).map_err(raw_transport)?;
        let length = socket.recv(&mut response).map_err(raw_transport)?;
        let frame = parse_client_udp_frame(&response[..length])
            .ok_or_else(|| SpeedTestError::BadResponse("pong UDP invalide".into()))?;
        if frame.kind != aether::speedtest::UDP_KIND_PONG || frame.session != session {
            return Err(SpeedTestError::BadResponse("pong UDP inattendu".into()));
        }
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    samples.sort_by(f64::total_cmp);
    let median = percentile_sorted(&samples, 0.5);
    let mut deviations: Vec<f64> = samples
        .iter()
        .map(|sample| (sample - median).abs())
        .collect();
    deviations.sort_by(f64::total_cmp);
    Ok((
        median,
        percentile_sorted(&deviations, 0.5),
        percentile_sorted(&samples, 0.95),
    ))
}

fn measure_raw_tcp(
    target: SocketAddr,
    mode: u8,
    duration_secs: u16,
    phase: SpeedTestPhase,
    progress: &SpeedTestProgressSink,
    global_started: Instant,
) -> Result<RawMeasurement, SpeedTestError> {
    let counter = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(aether::speedtest::SPEEDTEST_TCP_STREAMS + 1));
    let mut workers = Vec::with_capacity(aether::speedtest::SPEEDTEST_TCP_STREAMS);
    for _ in 0..aether::speedtest::SPEEDTEST_TCP_STREAMS {
        let counter = Arc::clone(&counter);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            raw_tcp_stream(target, mode, duration_secs, barrier, counter)
        }));
    }
    // All TCP connections and their control handshakes are complete. The
    // timed interval starts only now, exactly like an iperf3 data interval;
    // TCP setup latency cannot dilute the throughput number.
    barrier.wait();
    let measurement_started = Instant::now();
    let phase_progress = Arc::clone(progress);
    let phase_counter = Arc::clone(&counter);
    let phase_finished = Arc::clone(&finished);
    let monitor_started = measurement_started;
    let monitor = thread::spawn(move || {
        while !phase_finished.load(Ordering::Acquire) {
            let elapsed = monitor_started.elapsed();
            let bytes = phase_counter.load(Ordering::Relaxed);
            emit_progress(
                &phase_progress,
                phase,
                (elapsed.as_secs_f64() / f64::from(duration_secs as u32)).min(1.0),
                rate_mbps(bytes, elapsed),
                bytes,
                global_started,
                phase_message(phase),
            );
            thread::sleep(Duration::from_millis(250));
        }
    });
    let mut bytes = 0u64;
    let mut first_error = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(value)) => bytes = bytes.saturating_add(value),
            Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
            Ok(Err(_)) => {}
            Err(_) if first_error.is_none() => first_error = Some("flux TCP interrompu".into()),
            Err(_) => {}
        }
    }
    finished.store(true, Ordering::Release);
    let _ = monitor.join();
    if let Some(error) = first_error {
        return Err(SpeedTestError::Transport(error));
    }
    let elapsed = monitor_started.elapsed();
    if bytes == 0 {
        return Err(SpeedTestError::BadResponse("aucun octet TCP mesuré".into()));
    }
    emit_progress(
        progress,
        phase,
        1.0,
        rate_mbps(bytes, elapsed),
        bytes,
        global_started,
        phase_message(phase),
    );
    Ok(RawMeasurement {
        mbps: rate_mbps(bytes, elapsed),
        bytes,
        loss_pct: None,
        jitter_ms: None,
    })
}

fn raw_tcp_stream(
    target: SocketAddr,
    mode: u8,
    duration_secs: u16,
    barrier: Arc<Barrier>,
    counter: Arc<AtomicU64>,
) -> Result<u64, String> {
    let session = next_session();
    // Every worker reaches the barrier, even when its connection or control
    // handshake fails. Otherwise the parent and the other streams could wait
    // forever for a peer that already returned an error.
    let prepared = (|| -> Result<TcpStream, String> {
        let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        stream
            .set_nodelay(true)
            .and_then(|_| {
                stream.set_read_timeout(Some(Duration::from_secs(u64::from(duration_secs) + 5)))
            })
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&tcp_control(
                aether::speedtest::TCP_KIND_HELLO,
                mode,
                duration_secs,
                session,
            ))
            .map_err(|error| error.to_string())?;
        let mut ready = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
        stream
            .read_exact(&mut ready)
            .map_err(|error| error.to_string())?;
        let (kind, ready_mode, ready_duration, ready_session) =
            parse_tcp_control(&ready).map_err(|error| error.to_string())?;
        if (kind, ready_mode, ready_duration, ready_session)
            != (
                aether::speedtest::TCP_KIND_READY,
                mode,
                duration_secs,
                session,
            )
        {
            return Err("réponse de préparation TCP invalide".into());
        }
        Ok(stream)
    })();
    barrier.wait();
    let mut stream = prepared?;
    stream
        .write_all(&tcp_control(
            aether::speedtest::TCP_KIND_GO,
            mode,
            duration_secs,
            session,
        ))
        .map_err(|error| error.to_string())?;
    let mut bytes = 0u64;
    match mode {
        aether::speedtest::SPEEDTEST_MODE_DOWNLOAD => {
            let mut buffer = vec![0u8; aether::speedtest::SPEEDTEST_TCP_BUFFER_BYTES];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        bytes = bytes.saturating_add(read as u64);
                        counter.fetch_add(read as u64, Ordering::Relaxed);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        aether::speedtest::SPEEDTEST_MODE_UPLOAD => {
            let buffer = raw_buffer();
            let deadline = Instant::now() + Duration::from_secs(u64::from(duration_secs));
            while Instant::now() < deadline {
                let written = stream.write(&buffer).map_err(|error| error.to_string())?;
                if written == 0 {
                    break;
                }
                bytes = bytes.saturating_add(written as u64);
                counter.fetch_add(written as u64, Ordering::Relaxed);
            }
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())?;
        }
        _ => return Err("direction TCP invalide".into()),
    }
    Ok(bytes)
}

fn measure_raw_udp(
    target: SocketAddr,
    mode: u8,
    duration_secs: u16,
    phase: SpeedTestPhase,
    progress: &SpeedTestProgressSink,
    global_started: Instant,
) -> Result<RawMeasurement, SpeedTestError> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(raw_transport)?;
    socket.connect(target).map_err(raw_transport)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(raw_transport)?;
    let session = next_session();
    socket
        .send(&udp_frame(
            aether::speedtest::UDP_KIND_HELLO,
            mode,
            session,
            0,
            duration_secs,
            &[],
        ))
        .map_err(raw_transport)?;
    let mut received = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    loop {
        let length = socket.recv(&mut received).map_err(raw_transport)?;
        let frame = parse_client_udp_frame(&received[..length])
            .ok_or_else(|| SpeedTestError::BadResponse("préparation UDP invalide".into()))?;
        if frame.kind == aether::speedtest::UDP_KIND_READY
            && frame.session == session
            && frame.mode == mode
        {
            break;
        }
    }
    socket
        .send(&udp_frame(
            aether::speedtest::UDP_KIND_GO,
            mode,
            session,
            0,
            duration_secs,
            &[],
        ))
        .map_err(raw_transport)?;
    let started = Instant::now();
    match mode {
        aether::speedtest::SPEEDTEST_MODE_DOWNLOAD => measure_udp_download(
            &socket,
            session,
            duration_secs,
            phase,
            progress,
            global_started,
            started,
        ),
        aether::speedtest::SPEEDTEST_MODE_UPLOAD => measure_udp_upload(
            &socket,
            session,
            duration_secs,
            phase,
            progress,
            global_started,
            started,
        ),
        _ => Err(SpeedTestError::BadResponse("direction UDP invalide".into())),
    }
}

fn measure_udp_download(
    socket: &UdpSocket,
    session: u64,
    duration_secs: u16,
    phase: SpeedTestPhase,
    progress: &SpeedTestProgressSink,
    global_started: Instant,
    started: Instant,
) -> Result<RawMeasurement, SpeedTestError> {
    let mut packet = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    let deadline = started + Duration::from_secs(u64::from(duration_secs) + 2);
    let mut bytes = 0u64;
    let mut packets = 0u64;
    let mut sent_packets = None;
    let mut last_packet = None;
    let mut last_interval: Option<f64> = None;
    let mut jitter_sum = 0.0;
    let mut jitter_samples = 0u64;
    let mut last_report = Instant::now();
    while Instant::now() < deadline {
        match socket.recv(&mut packet) {
            Ok(length) => {
                let Some(frame) = parse_client_udp_frame(&packet[..length]) else {
                    continue;
                };
                if frame.session != session {
                    continue;
                }
                if frame.kind == aether::speedtest::UDP_KIND_DATA {
                    let now = Instant::now();
                    if let Some(previous) = last_packet.replace(now) {
                        let interval = now.duration_since(previous).as_secs_f64() * 1_000.0;
                        if let Some(previous_interval) = last_interval {
                            jitter_sum += (interval - previous_interval).abs();
                            jitter_samples = jitter_samples.saturating_add(1);
                        }
                        last_interval = Some(interval);
                    }
                    packets = packets.saturating_add(1);
                    bytes = bytes.saturating_add(frame.payload.len() as u64);
                } else if frame.kind == aether::speedtest::UDP_KIND_END {
                    if frame.payload.len() >= 16 {
                        sent_packets = Some(u64::from_be_bytes(
                            frame.payload[..8].try_into().unwrap_or_default(),
                        ));
                    }
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(raw_transport(error)),
        }
        if last_report.elapsed() >= Duration::from_millis(250) {
            emit_progress(
                progress,
                phase,
                (started.elapsed().as_secs_f64() / f64::from(duration_secs as u32)).min(1.0),
                rate_mbps(bytes, started.elapsed()),
                bytes,
                global_started,
                phase_message(phase),
            );
            last_report = Instant::now();
        }
    }
    if bytes == 0 {
        return Err(SpeedTestError::BadResponse(
            "aucun datagram UDP reçu".into(),
        ));
    }
    let elapsed = started.elapsed();
    let loss_pct = sent_packets.map(|sent| {
        if sent == 0 {
            0.0
        } else {
            sent.saturating_sub(packets) as f64 * 100.0 / sent as f64
        }
    });
    let jitter_ms = (jitter_samples > 0).then_some(jitter_sum / jitter_samples as f64);
    let result = RawMeasurement {
        mbps: rate_mbps(bytes, elapsed),
        bytes,
        loss_pct,
        jitter_ms,
    };
    emit_progress(
        progress,
        phase,
        1.0,
        result.mbps,
        bytes,
        global_started,
        phase_message(phase),
    );
    Ok(result)
}

fn measure_udp_upload(
    socket: &UdpSocket,
    session: u64,
    duration_secs: u16,
    phase: SpeedTestPhase,
    progress: &SpeedTestProgressSink,
    global_started: Instant,
    started: Instant,
) -> Result<RawMeasurement, SpeedTestError> {
    let payload_len = aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES
        - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES;
    let payload = raw_buffer();
    let mut packet = vec![0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES];
    packet[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..]
        .copy_from_slice(&payload[..payload_len]);
    let deadline = started + Duration::from_secs(u64::from(duration_secs));
    let mut bytes = 0u64;
    let mut sequence = 0u64;
    let mut last_report = Instant::now();
    while Instant::now() < deadline {
        write_udp_header(
            &mut packet,
            aether::speedtest::UDP_KIND_DATA,
            aether::speedtest::SPEEDTEST_MODE_UPLOAD,
            session,
            sequence,
            duration_secs,
        );
        let sent = socket.send(&packet).map_err(raw_transport)?;
        if sent < aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES {
            continue;
        }
        sequence = sequence.saturating_add(1);
        bytes = bytes.saturating_add((sent - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES) as u64);
        if last_report.elapsed() >= Duration::from_millis(250) {
            emit_progress(
                progress,
                phase,
                (started.elapsed().as_secs_f64() / f64::from(duration_secs as u32)).min(1.0),
                rate_mbps(bytes, started.elapsed()),
                bytes,
                global_started,
                phase_message(phase),
            );
            last_report = Instant::now();
        }
    }
    socket
        .send(&udp_frame(
            aether::speedtest::UDP_KIND_FINISH,
            aether::speedtest::SPEEDTEST_MODE_UPLOAD,
            session,
            sequence,
            0,
            &[],
        ))
        .map_err(raw_transport)?;
    let mut summary = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    let receiver = loop {
        match socket.recv(&mut summary) {
            Ok(length) => {
                let Some(frame) = parse_client_udp_frame(&summary[..length]) else {
                    continue;
                };
                if frame.kind == aether::speedtest::UDP_KIND_SUMMARY
                    && frame.session == session
                    && frame.payload.len() >= 16
                {
                    break Some((
                        u64::from_be_bytes(frame.payload[..8].try_into().unwrap_or_default()),
                        u64::from_be_bytes(frame.payload[8..16].try_into().unwrap_or_default()),
                    ));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break None
            }
            Err(error) => return Err(raw_transport(error)),
        }
    };
    let elapsed = started.elapsed();
    let loss_pct = receiver.map(|(_, packets)| {
        if sequence == 0 {
            0.0
        } else {
            sequence.saturating_sub(packets) as f64 * 100.0 / sequence as f64
        }
    });
    let result = RawMeasurement {
        mbps: rate_mbps(bytes, elapsed),
        bytes,
        loss_pct,
        jitter_ms: None,
    };
    emit_progress(
        progress,
        phase,
        1.0,
        result.mbps,
        bytes,
        global_started,
        phase_message(phase),
    );
    Ok(result)
}

fn emit_progress(
    sink: &SpeedTestProgressSink,
    phase: SpeedTestPhase,
    fraction: f64,
    current_mbps: f64,
    bytes: u64,
    started: Instant,
    message: &str,
) {
    sink(SpeedTestProgress {
        phase,
        fraction: fraction.clamp(0.0, 1.0),
        current_mbps,
        bytes,
        elapsed_ms: saturating_millis(started.elapsed()),
        message: message.to_string(),
    });
}

fn phase_message(phase: SpeedTestPhase) -> &'static str {
    match phase {
        SpeedTestPhase::Preparing => "Préparation des sockets directes",
        SpeedTestPhase::Latency => "Mesure de la latence UDP",
        SpeedTestPhase::TcpDownload => "TCP descendant · flux continus",
        SpeedTestPhase::TcpUpload => "TCP montant · flux continus",
        SpeedTestPhase::UdpDownload => "UDP descendant · perte et jitter",
        SpeedTestPhase::UdpUpload => "UDP montant · perte et jitter",
        SpeedTestPhase::Complete => "Mesure terminée",
    }
}

fn validate_raw_duration(duration_secs: u16) -> Result<(), SpeedTestError> {
    if !(1..=aether::speedtest::SPEEDTEST_MAX_DURATION_SECS).contains(&duration_secs) {
        return Err(SpeedTestError::BadResponse(format!(
            "durée comprise entre 1 et {} secondes",
            aether::speedtest::SPEEDTEST_MAX_DURATION_SECS
        )));
    }
    Ok(())
}

fn next_session() -> u64 {
    static SESSION: AtomicU64 = AtomicU64::new(1);
    SESSION.fetch_add(1, Ordering::Relaxed)
}

fn raw_transport(error: std::io::Error) -> SpeedTestError {
    SpeedTestError::Transport(error.to_string())
}

fn udp_frame(
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0u8; aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES + payload.len()];
    write_udp_header(&mut frame, kind, mode, session, sequence, duration);
    frame[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..].copy_from_slice(payload);
    frame
}

fn write_udp_header(
    frame: &mut [u8],
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
) {
    frame[..8].copy_from_slice(&aether::speedtest::SPEEDTEST_MAGIC);
    frame[8] = aether::speedtest::SPEEDTEST_PROTOCOL_VERSION;
    frame[9] = kind;
    frame[10] = mode;
    frame[11] = 0;
    frame[12..20].copy_from_slice(&session.to_be_bytes());
    frame[20..28].copy_from_slice(&sequence.to_be_bytes());
    frame[28..30].copy_from_slice(&duration.to_be_bytes());
    frame[30..32].fill(0);
}

fn tcp_control(
    kind: u8,
    mode: u8,
    duration: u16,
    session: u64,
) -> [u8; aether::speedtest::TCP_CONTROL_BYTES] {
    let mut frame = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
    frame[..8].copy_from_slice(&aether::speedtest::SPEEDTEST_MAGIC);
    frame[8] = aether::speedtest::SPEEDTEST_PROTOCOL_VERSION;
    frame[9] = kind;
    frame[10] = mode;
    frame[12..14].copy_from_slice(&duration.to_be_bytes());
    frame[16..24].copy_from_slice(&session.to_be_bytes());
    frame
}

fn parse_tcp_control(
    frame: &[u8; aether::speedtest::TCP_CONTROL_BYTES],
) -> anyhow::Result<(u8, u8, u16, u64)> {
    anyhow::ensure!(
        frame[..8] == aether::speedtest::SPEEDTEST_MAGIC,
        "invalid speedtest TCP magic"
    );
    anyhow::ensure!(
        frame[8] == aether::speedtest::SPEEDTEST_PROTOCOL_VERSION,
        "unsupported speedtest TCP version"
    );
    Ok((
        frame[9],
        frame[10],
        u16::from_be_bytes(frame[12..14].try_into()?),
        u64::from_be_bytes(frame[16..24].try_into()?),
    ))
}

fn raw_buffer() -> Vec<u8> {
    let mut buffer = vec![0u8; aether::speedtest::SPEEDTEST_TCP_BUFFER_BYTES];
    fill_payload(&mut buffer);
    buffer
}

fn fill_payload(buffer: &mut [u8]) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for chunk in buffer.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
}

struct ClientUdpFrame<'a> {
    kind: u8,
    mode: u8,
    session: u64,
    payload: &'a [u8],
}

fn parse_client_udp_frame(packet: &[u8]) -> Option<ClientUdpFrame<'_>> {
    if packet.len() < aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES
        || packet[..8] != aether::speedtest::SPEEDTEST_MAGIC
        || packet[8] != aether::speedtest::SPEEDTEST_PROTOCOL_VERSION
    {
        return None;
    }
    Some(ClientUdpFrame {
        kind: packet[9],
        mode: packet[10],
        session: u64::from_be_bytes(packet[12..20].try_into().ok()?),
        payload: &packet[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..],
    })
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
    use std::{
        net::{Shutdown, TcpListener, TcpStream, UdpSocket},
        sync::Mutex,
    };
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

    #[test]
    fn raw_tcp_engine_counts_persistent_socket_bytes_and_reports_progress() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("tcp listener");
        let address = tcp_listener.local_addr().expect("tcp address");
        let udp_socket = UdpSocket::bind(address).expect("udp listener");
        udp_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("udp timeout");

        let udp_thread = std::thread::spawn(move || {
            let mut packet = [0u8; aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES];
            for _ in 0..11 {
                let (length, peer) = udp_socket.recv_from(&mut packet).expect("udp ping");
                let frame = parse_client_udp_frame(&packet[..length]).expect("ping frame");
                assert_eq!(frame.kind, aether::speedtest::UDP_KIND_PING);
                udp_socket
                    .send_to(
                        &udp_frame(
                            aether::speedtest::UDP_KIND_PONG,
                            0,
                            frame.session,
                            0,
                            0,
                            &[],
                        ),
                        peer,
                    )
                    .expect("udp pong");
            }
        });

        let tcp_thread = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..(aether::speedtest::SPEEDTEST_TCP_STREAMS * 2) {
                let (stream, _) = tcp_listener.accept().expect("tcp connection");
                handlers.push(std::thread::spawn(move || {
                    serve_direct_tcp_for_test(stream)
                }));
            }
            for handler in handlers {
                handler.join().expect("tcp handler");
            }
        });

        let progress = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&progress);
        let result = run_raw_blocking_at(
            address,
            SpeedTestMode::Tcp,
            1,
            Arc::new(move |update| captured.lock().unwrap().push(update)),
        )
        .expect("raw tcp speedtest");

        tcp_thread.join().expect("tcp server");
        udp_thread.join().expect("udp server");
        assert_eq!(result.mode, SpeedTestMode::Tcp);
        assert!(result.tcp_download_mbps.is_some_and(|rate| rate > 0.0));
        assert!(result.tcp_upload_mbps.is_some_and(|rate| rate > 0.0));
        assert!(progress
            .lock()
            .unwrap()
            .iter()
            .any(|update| update.phase == SpeedTestPhase::TcpDownload));
    }

    #[test]
    fn raw_udp_engine_reports_socket_rate_and_loss_counters() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("udp listener");
        let address = socket.local_addr().expect("udp address");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("udp timeout");
        let server = std::thread::spawn(move || {
            let mut packet = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
            for _ in 0..11 {
                let (length, peer) = socket.recv_from(&mut packet).expect("udp ping");
                let frame = parse_client_udp_frame(&packet[..length]).expect("ping frame");
                assert_eq!(frame.kind, aether::speedtest::UDP_KIND_PING);
                socket
                    .send_to(
                        &udp_frame(
                            aether::speedtest::UDP_KIND_PONG,
                            0,
                            frame.session,
                            0,
                            0,
                            &[],
                        ),
                        peer,
                    )
                    .expect("udp pong");
            }

            let (length, peer) = socket.recv_from(&mut packet).expect("download hello");
            let frame = parse_client_udp_frame(&packet[..length]).expect("download hello frame");
            assert_eq!(frame.kind, aether::speedtest::UDP_KIND_HELLO);
            assert_eq!(frame.mode, aether::speedtest::SPEEDTEST_MODE_DOWNLOAD);
            let download_mode = frame.mode;
            let download_session = frame.session;
            socket
                .send_to(
                    &udp_frame(
                        aether::speedtest::UDP_KIND_READY,
                        download_mode,
                        download_session,
                        0,
                        1,
                        &[],
                    ),
                    peer,
                )
                .expect("download ready");
            let (length, _) = socket.recv_from(&mut packet).expect("download go");
            let go = parse_client_udp_frame(&packet[..length]).expect("download go frame");
            assert_eq!(go.kind, aether::speedtest::UDP_KIND_GO);

            let payload = vec![
                0x42;
                aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES
                    - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES
            ];
            let sent_packets = 64u64;
            for sequence in 0..sent_packets {
                socket
                    .send_to(
                        &udp_frame(
                            aether::speedtest::UDP_KIND_DATA,
                            download_mode,
                            download_session,
                            sequence,
                            1,
                            &payload,
                        ),
                        peer,
                    )
                    .expect("download data");
            }
            let mut end_payload = [0u8; 16];
            end_payload[..8].copy_from_slice(&sent_packets.to_be_bytes());
            end_payload[8..].copy_from_slice(&(sent_packets * payload.len() as u64).to_be_bytes());
            socket
                .send_to(
                    &udp_frame(
                        aether::speedtest::UDP_KIND_END,
                        download_mode,
                        download_session,
                        sent_packets,
                        1,
                        &end_payload,
                    ),
                    peer,
                )
                .expect("download end");

            let (length, peer) = socket.recv_from(&mut packet).expect("upload hello");
            let frame = parse_client_udp_frame(&packet[..length]).expect("upload hello frame");
            assert_eq!(frame.kind, aether::speedtest::UDP_KIND_HELLO);
            assert_eq!(frame.mode, aether::speedtest::SPEEDTEST_MODE_UPLOAD);
            let upload_mode = frame.mode;
            let upload_session = frame.session;
            socket
                .send_to(
                    &udp_frame(
                        aether::speedtest::UDP_KIND_READY,
                        upload_mode,
                        upload_session,
                        0,
                        1,
                        &[],
                    ),
                    peer,
                )
                .expect("upload ready");
            let (length, _) = socket.recv_from(&mut packet).expect("upload go");
            let go = parse_client_udp_frame(&packet[..length]).expect("upload go frame");
            assert_eq!(go.kind, aether::speedtest::UDP_KIND_GO);
            let mut received_packets = 0u64;
            let mut received_bytes = 0u64;
            loop {
                let (length, _) = socket.recv_from(&mut packet).expect("upload data");
                let frame = parse_client_udp_frame(&packet[..length]).expect("upload frame");
                if frame.kind == aether::speedtest::UDP_KIND_FINISH {
                    break;
                }
                if frame.kind == aether::speedtest::UDP_KIND_DATA {
                    received_packets = received_packets.saturating_add(1);
                    received_bytes = received_bytes.saturating_add(frame.payload.len() as u64);
                }
            }
            let mut summary = [0u8; 16];
            summary[..8].copy_from_slice(&received_bytes.to_be_bytes());
            summary[8..].copy_from_slice(&received_packets.to_be_bytes());
            socket
                .send_to(
                    &udp_frame(
                        aether::speedtest::UDP_KIND_SUMMARY,
                        aether::speedtest::SPEEDTEST_MODE_UPLOAD,
                        upload_session,
                        received_packets,
                        0,
                        &summary,
                    ),
                    peer,
                )
                .expect("upload summary");
        });

        let result = run_raw_blocking_at(address, SpeedTestMode::Udp, 1, Arc::new(|_| {}))
            .expect("raw udp speedtest");
        server.join().expect("udp server");

        assert_eq!(result.mode, SpeedTestMode::Udp);
        assert!(result.udp_download_mbps.is_some_and(|rate| rate > 0.0));
        assert!(result.udp_upload_mbps.is_some_and(|rate| rate > 0.0));
        assert!(result
            .udp_loss_pct
            .is_some_and(|loss| (0.0..=100.0).contains(&loss)));
    }

    fn serve_direct_tcp_for_test(mut stream: TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("tcp timeout");
        let mut hello = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
        stream.read_exact(&mut hello).expect("tcp hello");
        let (kind, mode, duration, session) = parse_tcp_control(&hello).expect("hello frame");
        assert_eq!(kind, aether::speedtest::TCP_KIND_HELLO);
        stream
            .write_all(&tcp_control(
                aether::speedtest::TCP_KIND_READY,
                mode,
                duration,
                session,
            ))
            .expect("tcp ready");
        let mut go = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
        stream.read_exact(&mut go).expect("tcp go");
        let (kind, go_mode, go_duration, go_session) = parse_tcp_control(&go).expect("go frame");
        assert_eq!(kind, aether::speedtest::TCP_KIND_GO);
        assert_eq!(
            (go_mode, go_duration, go_session),
            (mode, duration, session)
        );
        if mode == aether::speedtest::SPEEDTEST_MODE_DOWNLOAD {
            let buffer = vec![0x5a; 64 * 1024];
            let deadline = Instant::now() + Duration::from_secs(u64::from(duration));
            while Instant::now() < deadline {
                stream.write_all(&buffer).expect("tcp payload");
            }
            stream.shutdown(Shutdown::Write).expect("tcp shutdown");
        } else {
            let mut buffer = vec![0u8; 64 * 1024];
            while stream.read(&mut buffer).expect("tcp upload") != 0 {}
        }
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
