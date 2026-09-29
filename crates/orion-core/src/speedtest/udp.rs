//! The raw engine's UDP transfers, in both directions.

use super::*;

/// Runs one UDP quality leg at a **known** sending rate.
///
/// `rate_mbps` is not a nicety: loss and jitter only describe the path when
/// the sender's speed is fixed and below capacity. Driven flat out, both ends
/// report the difference between the sender's syscall loop and the link, which
/// on a healthy tunnel reads as ~80 % loss. See
/// [`aether::speedtest::SPEEDTEST_RATE_UNPACED`].
pub(super) fn measure_raw_udp(
    target: SocketAddr,
    mode: u8,
    duration_secs: u16,
    rate_mbps: f64,
    phase: SpeedTestPhase,
    progress: &SpeedTestProgressSink,
    global_started: Instant,
) -> Result<RawMeasurement, SpeedTestError> {
    let rate = aether::speedtest::encode_rate(rate_mbps);
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(raw_transport)?;
    socket.connect(target).map_err(raw_transport)?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(raw_transport)?;
    let session = next_session();
    let hello = udp_frame(
        aether::speedtest::UDP_KIND_HELLO,
        mode,
        session,
        0,
        duration_secs,
        rate,
        &[],
    );
    socket.send(&hello).map_err(raw_udp_transport)?;
    let mut received = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    // The socket polls on the 100 ms timeout the data loops need; the
    // handshake gets its own deadline on top of it, and re-sends its hello
    // rather than reading one expired poll as a dead gateway.
    let handshake_deadline = Instant::now() + UDP_HANDSHAKE_TIMEOUT;
    let mut last_hello = Instant::now();
    loop {
        match socket.recv(&mut received) {
            Ok(length) => {
                let frame = parse_client_udp_frame(&received[..length]).ok_or_else(|| {
                    SpeedTestError::BadResponse("préparation UDP invalide".into())
                })?;
                if frame.kind == aether::speedtest::UDP_KIND_READY
                    && frame.session == session
                    && frame.mode == mode
                {
                    break;
                }
            }
            Err(error) if looks_unanswered(&error) => {}
            Err(error) => return Err(raw_udp_transport(error)),
        }
        if Instant::now() >= handshake_deadline {
            return Err(unreachable(&format!(
                "la session UDP n'a pas été acceptée en {} s",
                UDP_HANDSHAKE_TIMEOUT.as_secs()
            )));
        }
        if last_hello.elapsed() >= UDP_HANDSHAKE_RETRY {
            socket.send(&hello).map_err(raw_udp_transport)?;
            last_hello = Instant::now();
        }
    }
    socket
        .send(&udp_frame(
            aether::speedtest::UDP_KIND_GO,
            mode,
            session,
            0,
            duration_secs,
            rate,
            &[],
        ))
        .map_err(raw_udp_transport)?;
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
            rate,
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
            Err(error) => return Err(raw_udp_transport(error)),
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

// Session identity, leg shape and progress plumbing, none of which outlive
// the call: a struct here would be a parameter list with a name.
#[allow(clippy::too_many_arguments)]
fn measure_udp_upload(
    socket: &UdpSocket,
    session: u64,
    duration_secs: u16,
    rate: u16,
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
    let mut pacer = Pacer::new(aether::speedtest::decode_rate(rate), packet.len(), started);
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
            rate,
        );
        let sent = socket.send(&packet).map_err(raw_udp_transport)?;
        if sent < aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES {
            continue;
        }
        sequence = sequence.saturating_add(1);
        bytes = bytes.saturating_add((sent - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES) as u64);
        pacer.after_sending(sequence, deadline);
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
            aether::speedtest::SPEEDTEST_RATE_UNPACED,
            &[],
        ))
        .map_err(raw_udp_transport)?;
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
            Err(error) => return Err(raw_udp_transport(error)),
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
    // The gateway's count, not ours. `bytes` is what this process handed to
    // `send()`, which the kernel accepts long after the link stopped carrying
    // it: an upload figure taken from it describes the local socket buffer and
    // can exceed the line by an order of magnitude. What crossed the tunnel is
    // what the receiver counted.
    let delivered = receiver.map(|(received, _)| received).unwrap_or(bytes);
    let result = RawMeasurement {
        mbps: rate_mbps(delivered, elapsed),
        bytes: delivered,
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
