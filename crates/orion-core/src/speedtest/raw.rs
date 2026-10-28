//! The raw engine: one session driven over plain sockets, its latency
//! probe and its TCP transfers, and the progress it reports.

use super::*;

pub(super) fn run_raw_blocking(
    mode: SpeedTestMode,
    duration_secs: u16,
    quality_rate_mbps: Option<f64>,
    progress: SpeedTestProgressSink,
) -> Result<SpeedTestResult, SpeedTestError> {
    let target: SocketAddr = aether::DEFAULT_WG_SPEEDTEST_ADDR
        .parse()
        .map_err(|error| SpeedTestError::InvalidUrl(format!("cible socket invalide : {error}")))?;
    run_raw_blocking_at(target, mode, duration_secs, quality_rate_mbps, progress)
}

pub(super) fn run_raw_blocking_at(
    target: SocketAddr,
    mode: SpeedTestMode,
    duration_secs: u16,
    quality_rate_mbps: Option<f64>,
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
    // From here on every frame carries the ping, the first one included.
    let progress = with_latency(progress, latency_ms);
    emit_progress(
        &progress,
        SpeedTestPhase::Latency,
        1.0,
        0.0,
        0,
        started,
        "Mesure de la latence UDP",
    );

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
    // Each quality leg is driven just under the throughput its own direction
    // reached. Reusing one figure for both would probe a 500/50 line at 425
    // Mb/s upstream and report the pacer's own loss as the path's.
    let quality_rate = |measured: Option<&RawMeasurement>| -> Result<f64, SpeedTestError> {
        match (measured, quality_rate_mbps) {
            (Some(reference), _) => Ok(aether::speedtest::quality_rate_mbps(reference.mbps)),
            (None, Some(explicit)) => Ok(aether::speedtest::quality_rate_mbps(explicit)),
            (None, None) => Err(SpeedTestError::MissingQualityRate("udp")),
        }
    };
    // Shorter than a throughput leg: loss and jitter at a known rate settle in
    // seconds, and four full-length legs made the run a 80-second wait.
    let quality_secs = duration_secs.min(aether::speedtest::SPEEDTEST_QUALITY_DURATION_SECS);
    let udp_download = if matches!(mode, SpeedTestMode::Udp | SpeedTestMode::Full) {
        Some(measure_raw_udp(
            target,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
            quality_secs,
            quality_rate(tcp_download.as_ref())?,
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
            quality_secs,
            quality_rate(tcp_upload.as_ref())?,
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
pub(super) struct RawMeasurement {
    pub(super) mbps: f64,
    pub(super) bytes: u64,
    pub(super) loss_pct: Option<f64>,
    pub(super) jitter_ms: Option<f64>,
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
        let request = udp_frame(
            aether::speedtest::UDP_KIND_PING,
            0,
            session,
            0,
            0,
            aether::speedtest::SPEEDTEST_RATE_UNPACED,
            &[],
        );
        let started = Instant::now();
        socket.send(&request).map_err(raw_udp_transport)?;
        let length = socket.recv(&mut response).map_err(raw_udp_transport)?;
        let frame = parse_client_udp_frame(&response[..length])
            .ok_or_else(|| service_absent("réponse UDP illisible"))?;
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
        // A connection that never completes is the same fact as a latency
        // probe that never answers, and deserves the same sentence rather than
        // « os error 10060 ».
        let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))
            .map_err(foreign_or_transport)?;
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
            .map_err(foreign_or_transport)?;
        let mut ready = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
        // The one place a foreign listener shows itself: the connection was
        // accepted, our control frame went out, and the answer never came —
        // because whatever is on this port does not speak this protocol.
        stream
            .read_exact(&mut ready)
            .map_err(foreign_or_transport)?;
        let (kind, ready_mode, ready_duration, ready_session) =
            parse_tcp_control(&ready).map_err(|error| {
                // Sixteen bytes arrived and they are not ours. Same conclusion
                // as a reset, reached from the other side: the port answers,
                // and not with Helios.
                foreign_service(&error.to_string())
            })?;
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

pub(super) fn emit_progress(
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
        latency_ms: None,
    });
}

/// The same sink, with the measured ping stamped on every frame it forwards.
fn with_latency(sink: SpeedTestProgressSink, latency_ms: f64) -> SpeedTestProgressSink {
    Arc::new(move |mut update: SpeedTestProgress| {
        update.latency_ms = Some(latency_ms);
        sink(update)
    })
}

pub(super) fn phase_message(phase: SpeedTestPhase) -> &'static str {
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

pub(super) fn validate_raw_duration(duration_secs: u16) -> Result<(), SpeedTestError> {
    if !(1..=aether::speedtest::SPEEDTEST_MAX_DURATION_SECS).contains(&duration_secs) {
        return Err(SpeedTestError::BadResponse(format!(
            "durée comprise entre 1 et {} secondes",
            aether::speedtest::SPEEDTEST_MAX_DURATION_SECS
        )));
    }
    Ok(())
}

pub(super) fn next_session() -> u64 {
    static SESSION: AtomicU64 = AtomicU64::new(1);
    SESSION.fetch_add(1, Ordering::Relaxed)
}
