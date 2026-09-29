use super::*;
use std::{
    net::{Shutdown, TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Silence and a reset are different facts about the gateway.
///
/// A reset means something answered on the speedtest port — another
/// service, or the host refusing. A timeout means the probe left and
/// nothing came back at all: the packets are dropped, or they arrive where
/// nothing is bound. The operator's next move differs, so the two must not
/// share a sentence — and neither may be reported as a bare `os error`.
#[test]
fn a_gateway_that_never_answers_is_named_rather_than_reported_as_an_os_error() {
    for kind in [std::io::ErrorKind::TimedOut, std::io::ErrorKind::WouldBlock] {
        let error = raw_udp_transport(std::io::Error::new(kind, "os error 10060"));
        assert!(
            matches!(error, SpeedTestError::Unreachable { port, .. }
                    if port == aether::speedtest::SPEEDTEST_PORT),
            "{kind:?} must be named unreachable, got {error}"
        );
        assert!(error.to_string().contains("pare-feu"));
    }

    let reset = raw_udp_transport(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "os error 10054",
    ));
    assert!(matches!(reset, SpeedTestError::ServiceAbsent { .. }));

    // Anything else keeps its own words: inventing a diagnosis for a
    // failure we have not identified would send the operator to the wrong
    // machine.
    let other = raw_udp_transport(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "refusé",
    ));
    assert!(matches!(other, SpeedTestError::Transport(_)));
}

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
                        aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
        // No UDP leg runs in this mode, so no reference is needed.
        None,
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

/// A lost HELLO must not end the run.
///
/// The handshake that opens a UDP leg runs over the same lossy datagram
/// service the leg measures: one dropped frame — routine on a tunnel that
/// has just carried twenty seconds of TCP at line rate — and the client
/// would otherwise die on the 100 ms poll timeout the data loops need,
/// reporting Windows' « os error 10060 » for what is a single lost packet.
#[test]
fn udp_leg_retransmits_its_hello_until_the_gateway_is_ready() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp listener");
    let address = socket.local_addr().expect("udp address");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("udp timeout");
    let server = std::thread::spawn(move || {
        let mut packet = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
        // The first hello is dropped on the floor, as the path would.
        let (length, _) = socket.recv_from(&mut packet).expect("first hello");
        let first = parse_client_udp_frame(&packet[..length]).expect("first hello frame");
        assert_eq!(first.kind, aether::speedtest::UDP_KIND_HELLO);

        let (length, peer) = socket.recv_from(&mut packet).expect("second hello");
        let hello = parse_client_udp_frame(&packet[..length]).expect("second hello frame");
        assert_eq!(hello.kind, aether::speedtest::UDP_KIND_HELLO);
        assert_eq!(hello.mode, aether::speedtest::SPEEDTEST_MODE_DOWNLOAD);
        let (mode, session) = (hello.mode, hello.session);
        socket
            .send_to(
                &udp_frame(
                    aether::speedtest::UDP_KIND_READY,
                    mode,
                    session,
                    0,
                    1,
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
                    &[],
                ),
                peer,
            )
            .expect("ready");
        let (length, _) = socket.recv_from(&mut packet).expect("go");
        let go = parse_client_udp_frame(&packet[..length]).expect("go frame");
        assert_eq!(go.kind, aether::speedtest::UDP_KIND_GO);

        let payload = vec![
            0x42;
            aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES
                - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES
        ];
        let sent_packets = 16u64;
        for sequence in 0..sent_packets {
            socket
                .send_to(
                    &udp_frame(
                        aether::speedtest::UDP_KIND_DATA,
                        mode,
                        session,
                        sequence,
                        1,
                        aether::speedtest::SPEEDTEST_RATE_UNPACED,
                        &payload,
                    ),
                    peer,
                )
                .expect("data");
        }
        let mut end_payload = [0u8; 16];
        end_payload[..8].copy_from_slice(&sent_packets.to_be_bytes());
        end_payload[8..].copy_from_slice(&(sent_packets * payload.len() as u64).to_be_bytes());
        socket
            .send_to(
                &udp_frame(
                    aether::speedtest::UDP_KIND_END,
                    mode,
                    session,
                    sent_packets,
                    1,
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
                    &end_payload,
                ),
                peer,
            )
            .expect("end");
    });

    let started = Instant::now();
    let measurement = measure_raw_udp(
        address,
        aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
        1,
        50.0,
        SpeedTestPhase::UdpDownload,
        &(Arc::new(|_| {}) as SpeedTestProgressSink),
        started,
    )
    .expect("the leg survives one lost hello");
    server.join().expect("udp server");
    assert!(measurement.bytes > 0);
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
                        aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
                        aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
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
                    aether::speedtest::SPEEDTEST_RATE_UNPACED,
                    &summary,
                ),
                peer,
            )
            .expect("upload summary");
    });

    // UDP alone has no TCP throughput to pace against, so the reference
    // is supplied explicitly — the engine refuses the mode without one.
    let result = run_raw_blocking_at(address, SpeedTestMode::Udp, 1, Some(50.0), Arc::new(|_| {}))
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
                format!("HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n")
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
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
