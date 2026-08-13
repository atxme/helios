//! Bounded in-tunnel transfers used by Orion's performance screen.
//!
//! These routes are behind [`crate::auth::require_peer`]. The source VIP is
//! therefore the authentication; no profile name, public key or additional
//! token is accepted from the client. Bodies are streamed in both directions:
//! allocating an entire test payload on every request would benchmark the
//! gateway allocator as much as the WireGuard path.

use std::{
    collections::HashMap,
    convert::Infallible,
    io::{Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock,
    },
    thread,
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::{Query, Request},
    http::{header, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::{stream, StreamExt as _};
use serde::Deserialize;

use crate::{auth, AppState};

const TCP_READ_TIMEOUT: Duration = Duration::from_secs(35);
const UDP_READ_TIMEOUT: Duration = Duration::from_millis(100);
const UDP_END_REPETITIONS: usize = 5;
const UDP_END_GAP: Duration = Duration::from_millis(20);

/// Starts the raw TCP/UDP service used by Orion's primary speedtest.
///
/// Only the control handshake is handled by the service boundary. Once a
/// session is admitted, the measurement runs in blocking OS threads and uses
/// `std::net` directly: no HTTP parser, response body stream or Tokio wake-up
/// sits between the socket and the byte counter.
pub async fn serve_raw(
    state: AppState,
    bind: &str,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let bind = bind.to_string();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || serve_raw_blocking(state, &bind, handle, shutdown))
        .await
        .map_err(|error| anyhow::anyhow!("raw speedtest task stopped: {error}"))??;
    Ok(())
}

fn serve_raw_blocking(
    state: AppState,
    bind: &str,
    runtime: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let tcp = TcpListener::bind(bind)
        .map_err(|error| anyhow::anyhow!("binding raw speedtest TCP on {bind}: {error}"))?;
    let udp = UdpSocket::bind(bind)
        .map_err(|error| anyhow::anyhow!("binding raw speedtest UDP on {bind}: {error}"))?;
    tcp.set_nonblocking(true)?;
    udp.set_read_timeout(Some(UDP_READ_TIMEOUT))?;
    tracing::info!("raw speedtest TCP/UDP listening on {bind}");

    let tcp_state = state.clone();
    let tcp_runtime = runtime.clone();
    let tcp_shutdown = Arc::clone(&shutdown);
    let tcp_thread = thread::spawn(move || {
        while !tcp_shutdown.load(Ordering::Acquire) {
            let stream = match tcp.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(UDP_READ_TIMEOUT);
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "raw speedtest TCP listener ended");
                    break;
                }
            };
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            let admitted = tcp_runtime
                .block_on(auth::resolve_source(&tcp_state, peer.ip()))
                .is_some();
            if !admitted {
                tracing::warn!(source = %peer, "raw speedtest TCP refused: unknown WireGuard peer");
                continue;
            }
            thread::spawn(move || {
                if let Err(error) = handle_tcp_session(stream) {
                    tracing::debug!(source = %peer, %error, "raw speedtest TCP session ended");
                }
            });
        }
    });

    let result = run_udp_server(udp, state, runtime, shutdown);
    let _ = tcp_thread.join();
    result
}

fn handle_tcp_session(mut stream: TcpStream) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(TCP_READ_TIMEOUT))?;
    let mut hello = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
    stream.read_exact(&mut hello)?;
    let (kind, mode, duration, session) = parse_tcp_control(&hello)?;
    anyhow::ensure!(
        kind == aether::speedtest::TCP_KIND_HELLO,
        "invalid speedtest TCP hello"
    );
    validate_mode(mode)?;
    let duration = validate_duration(duration)?;
    stream.write_all(&tcp_control(
        aether::speedtest::TCP_KIND_READY,
        mode,
        duration,
        session,
    ))?;
    let mut go = [0u8; aether::speedtest::TCP_CONTROL_BYTES];
    stream.read_exact(&mut go)?;
    let (kind, go_mode, go_duration, go_session) = parse_tcp_control(&go)?;
    anyhow::ensure!(
        kind == aether::speedtest::TCP_KIND_GO,
        "invalid speedtest TCP start"
    );
    anyhow::ensure!(
        (go_mode, go_duration, go_session) == (mode, duration, session),
        "speedtest TCP start does not match its hello"
    );

    let deadline = Instant::now() + Duration::from_secs(u64::from(duration));
    match mode {
        aether::speedtest::SPEEDTEST_MODE_DOWNLOAD => {
            let buffer = raw_buffer();
            while Instant::now() < deadline {
                if stream.write(&buffer)? == 0 {
                    break;
                }
            }
            stream.shutdown(Shutdown::Write)?;
        }
        aether::speedtest::SPEEDTEST_MODE_UPLOAD => {
            let mut buffer = vec![0u8; aether::speedtest::SPEEDTEST_TCP_BUFFER_BYTES];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        _ => unreachable!("validate_mode checked the TCP mode"),
    }
    Ok(())
}

fn run_udp_server(
    socket: UdpSocket,
    state: AppState,
    runtime: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut buffer = [0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    let mut sessions = HashMap::<(SocketAddr, u64), UdpSession>::new();
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let now = Instant::now();
        let expired: Vec<_> = sessions
            .iter()
            .filter_map(|(key, session)| {
                session
                    .deadline
                    .is_some_and(|deadline| deadline <= now)
                    .then_some(*key)
            })
            .collect();
        for key in expired {
            if let Some(session) = sessions.remove(&key) {
                if session.mode == aether::speedtest::SPEEDTEST_MODE_UPLOAD {
                    send_udp_summary(
                        &socket,
                        session.address,
                        session.session,
                        session.received_bytes,
                        session.received_packets,
                    );
                }
            }
        }

        let (length, address) = match socket.recv_from(&mut buffer) {
            Ok(value) => value,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        };
        let Some(frame) = parse_udp_frame(&buffer[..length]) else {
            continue;
        };
        if frame.kind == aether::speedtest::UDP_KIND_PING {
            if runtime
                .block_on(auth::resolve_source(&state, address.ip()))
                .is_some()
            {
                send_udp_frame(
                    &socket,
                    address,
                    aether::speedtest::UDP_KIND_PONG,
                    0,
                    frame.session,
                    0,
                    0,
                    &[],
                );
            }
            continue;
        }
        if frame.kind == aether::speedtest::UDP_KIND_HELLO {
            if runtime
                .block_on(auth::resolve_source(&state, address.ip()))
                .is_none()
            {
                tracing::warn!(source = %address, "raw speedtest UDP refused: unknown WireGuard peer");
                continue;
            }
            if validate_mode(frame.mode).is_err() || validate_duration(frame.duration).is_err() {
                continue;
            }
            let key = (address, frame.session);
            sessions.insert(
                key,
                UdpSession {
                    address,
                    session: frame.session,
                    mode: frame.mode,
                    duration: frame.duration,
                    deadline: None,
                    received_bytes: 0,
                    received_packets: 0,
                },
            );
            send_udp_frame(
                &socket,
                address,
                aether::speedtest::UDP_KIND_READY,
                frame.mode,
                frame.session,
                0,
                frame.duration,
                &[],
            );
            continue;
        }

        let key = (address, frame.session);
        match frame.kind {
            aether::speedtest::UDP_KIND_GO => {
                let Some(session) = sessions.get_mut(&key) else {
                    continue;
                };
                let deadline = Instant::now() + Duration::from_secs(u64::from(session.duration));
                session.deadline = Some(deadline);
                if session.mode == aether::speedtest::SPEEDTEST_MODE_DOWNLOAD {
                    let sender = socket.try_clone()?;
                    let address = session.address;
                    let session_id = session.session;
                    let duration = session.duration;
                    thread::spawn(move || send_udp_download(sender, address, session_id, duration));
                }
            }
            aether::speedtest::UDP_KIND_DATA => {
                let Some(session) = sessions.get_mut(&key) else {
                    continue;
                };
                if session.mode == aether::speedtest::SPEEDTEST_MODE_UPLOAD
                    && session
                        .deadline
                        .is_some_and(|deadline| deadline > Instant::now())
                {
                    session.received_packets = session.received_packets.saturating_add(1);
                    session.received_bytes = session
                        .received_bytes
                        .saturating_add(frame.payload.len() as u64);
                }
            }
            aether::speedtest::UDP_KIND_FINISH => {
                let Some(session) = sessions.get_mut(&key) else {
                    continue;
                };
                if session.mode == aether::speedtest::SPEEDTEST_MODE_UPLOAD {
                    // Keep the slot for a short drain period: UDP data can
                    // arrive after FINISH even though both were emitted in
                    // order by the same client socket.
                    session.deadline = Some(Instant::now() + Duration::from_millis(100));
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct UdpSession {
    address: SocketAddr,
    session: u64,
    mode: u8,
    duration: u16,
    deadline: Option<Instant>,
    received_bytes: u64,
    received_packets: u64,
}

fn send_udp_download(socket: UdpSocket, address: SocketAddr, session: u64, duration: u16) {
    let mut packet = vec![0u8; aether::speedtest::SPEEDTEST_UDP_DATAGRAM_BYTES];
    let payload_len = packet.len() - aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES;
    fill_payload(&mut packet[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..]);
    let deadline = Instant::now() + Duration::from_secs(u64::from(duration));
    let mut sequence = 0u64;
    let mut bytes = 0u64;
    while Instant::now() < deadline {
        write_udp_header(
            &mut packet,
            aether::speedtest::UDP_KIND_DATA,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
            session,
            sequence,
            duration,
        );
        if socket.send_to(&packet, address).is_err() {
            return;
        }
        sequence = sequence.saturating_add(1);
        bytes = bytes.saturating_add(payload_len as u64);
    }
    let mut end_payload = [0u8; 16];
    end_payload[..8].copy_from_slice(&sequence.to_be_bytes());
    end_payload[8..].copy_from_slice(&bytes.to_be_bytes());
    for _ in 0..UDP_END_REPETITIONS {
        send_udp_frame(
            &socket,
            address,
            aether::speedtest::UDP_KIND_END,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD,
            session,
            sequence,
            duration,
            &end_payload,
        );
        thread::sleep(UDP_END_GAP);
    }
}

fn send_udp_summary(
    socket: &UdpSocket,
    address: SocketAddr,
    session: u64,
    bytes: u64,
    packets: u64,
) {
    let mut payload = [0u8; 16];
    payload[..8].copy_from_slice(&bytes.to_be_bytes());
    payload[8..].copy_from_slice(&packets.to_be_bytes());
    send_udp_frame(
        socket,
        address,
        aether::speedtest::UDP_KIND_SUMMARY,
        aether::speedtest::SPEEDTEST_MODE_UPLOAD,
        session,
        packets,
        0,
        &payload,
    );
}

fn send_udp_frame(
    socket: &UdpSocket,
    address: SocketAddr,
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
    payload: &[u8],
) {
    let mut packet = vec![0u8; aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES + payload.len()];
    write_udp_header(&mut packet, kind, mode, session, sequence, duration);
    packet[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..].copy_from_slice(payload);
    let _ = socket.send_to(&packet, address);
}

struct UdpFrame<'a> {
    kind: u8,
    mode: u8,
    session: u64,
    duration: u16,
    payload: &'a [u8],
}

fn parse_udp_frame(packet: &[u8]) -> Option<UdpFrame<'_>> {
    if packet.len() < aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES
        || packet[..8] != aether::speedtest::SPEEDTEST_MAGIC
        || packet[8] != aether::speedtest::SPEEDTEST_PROTOCOL_VERSION
    {
        return None;
    }
    Some(UdpFrame {
        kind: packet[9],
        mode: packet[10],
        session: u64::from_be_bytes(packet[12..20].try_into().ok()?),
        duration: u16::from_be_bytes(packet[28..30].try_into().ok()?),
        payload: &packet[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..],
    })
}

fn write_udp_header(
    packet: &mut [u8],
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
) {
    packet[..8].copy_from_slice(&aether::speedtest::SPEEDTEST_MAGIC);
    packet[8] = aether::speedtest::SPEEDTEST_PROTOCOL_VERSION;
    packet[9] = kind;
    packet[10] = mode;
    packet[11] = 0;
    packet[12..20].copy_from_slice(&session.to_be_bytes());
    packet[20..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..30].copy_from_slice(&duration.to_be_bytes());
    packet[30..32].fill(0);
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

fn validate_mode(mode: u8) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            mode,
            aether::speedtest::SPEEDTEST_MODE_DOWNLOAD | aether::speedtest::SPEEDTEST_MODE_UPLOAD
        ),
        "unsupported speedtest direction"
    );
    Ok(())
}

fn validate_duration(duration: u16) -> anyhow::Result<u16> {
    anyhow::ensure!(
        (1..=aether::speedtest::SPEEDTEST_MAX_DURATION_SECS).contains(&duration),
        "invalid speedtest duration"
    );
    Ok(duration)
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

/// Maximum payload accepted in either direction of one request.
pub const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
/// Safe default for a manual probe. Orion always sends its calibrated size.
pub const DEFAULT_TRANSFER_BYTES: usize = 8 * 1024 * 1024;
// Large frames keep userspace polling and reference-count churn negligible on
// multi-gigabit links; socket backpressure still slices them for the network.
const STREAM_CHUNK_BYTES: usize = 1024 * 1024;

/// One deterministic non-repeating chunk, generated once for the process.
/// WireGuard itself does not compress, but a realistic payload also prevents a
/// future HTTP middleware from making the benchmark accidentally optimistic.
static DOWNLOAD_CHUNK: LazyLock<Bytes> = LazyLock::new(|| {
    let mut data = vec![0u8; STREAM_CHUNK_BYTES];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for block in data.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        block.copy_from_slice(&state.to_le_bytes());
    }
    Bytes::from(data)
});

#[derive(Debug, Deserialize)]
pub struct TransferQuery {
    bytes: Option<usize>,
}

impl TransferQuery {
    fn requested_bytes(&self) -> Result<usize, (StatusCode, String)> {
        let bytes = self.bytes.unwrap_or(DEFAULT_TRANSFER_BYTES);
        if bytes == 0 || bytes > MAX_TRANSFER_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "la taille du speedtest doit être comprise entre 1 et {MAX_TRANSFER_BYTES} octets"
                ),
            ));
        }
        Ok(bytes)
    }
}

/// A cheap authenticated round-trip probe.
pub async fn ping() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Streams a bounded payload to the client without a per-request large buffer.
pub async fn download(
    Query(query): Query<TransferQuery>,
) -> Result<Response, (StatusCode, String)> {
    let bytes = query.requested_bytes()?;
    let stream = stream::unfold(
        (bytes, DOWNLOAD_CHUNK.clone()),
        |(remaining, chunk)| async move {
            if remaining == 0 {
                return None;
            }
            let emitted = remaining.min(chunk.len());
            Some((
                Ok::<Bytes, Infallible>(chunk.slice(..emitted)),
                (remaining - emitted, chunk),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.to_string()).expect("decimal content length is valid"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    Ok(response)
}

/// Streams and discards a bounded upload, acknowledging only after every byte
/// reached the application. The response therefore cannot race ahead of data
/// still buffered in the server's socket.
pub async fn upload(
    Query(query): Query<TransferQuery>,
    request: Request,
) -> Result<StatusCode, (StatusCode, String)> {
    let expected = query.requested_bytes()?;
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            (
                StatusCode::LENGTH_REQUIRED,
                "le speedtest exige une taille de corps explicite".to_string(),
            )
        })?;
    if declared != expected {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("le speedtest annonce {declared} octets, {expected} étaient attendus"),
        ));
    }

    let mut received = 0usize;
    let mut body = request.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                format!("corps du speedtest interrompu : {error}"),
            )
        })?;
        received = received.checked_add(chunk.len()).ok_or_else(|| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "taille du speedtest débordée".to_string(),
            )
        })?;
        if received > expected {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "le corps du speedtest dépasse la taille annoncée".to_string(),
            ));
        }
    }
    if received != expected {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("le speedtest a reçu {received} octets, {expected} étaient attendus"),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        let network = Arc::new(tokio::sync::RwLock::new(aether::NetworkConfig::default()));
        let tunnel_state = Arc::new(tokio::sync::RwLock::new(aether::TunnelState::Down));
        let policy = Arc::new(tokio::sync::RwLock::new(
            aether::NetworkConfig::default().firewall_policy(),
        ));
        let (event_tx, _) = tokio::sync::broadcast::channel(4);
        let (cmd_tx, _) = tokio::sync::mpsc::channel(4);
        let (psk_tx, _) = tokio::sync::mpsc::channel(4);
        AppState::new(
            network,
            true,
            tunnel_state,
            event_tx,
            cmd_tx,
            psk_tx,
            policy,
        )
    }

    #[test]
    fn transfer_sizes_are_bounded_before_stream_creation() {
        assert!(TransferQuery { bytes: Some(0) }.requested_bytes().is_err());
        assert!(TransferQuery {
            bytes: Some(MAX_TRANSFER_BYTES + 1)
        }
        .requested_bytes()
        .is_err());
        assert_eq!(
            TransferQuery { bytes: None }
                .requested_bytes()
                .expect("default size"),
            DEFAULT_TRANSFER_BYTES
        );
    }

    #[test]
    fn download_chunk_is_not_a_repeated_byte_pattern() {
        assert_eq!(DOWNLOAD_CHUNK.len(), STREAM_CHUNK_BYTES);
        assert!(DOWNLOAD_CHUNK.windows(2).any(|pair| pair[0] != pair[1]));
    }

    #[tokio::test]
    async fn raw_server_stops_its_blocking_listeners_on_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let served = tokio::spawn(serve_raw(
            test_state(),
            "127.0.0.1:0",
            Arc::clone(&shutdown),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), served)
            .await
            .expect("raw listeners must not keep heliosd alive")
            .expect("raw server task")
            .expect("clean raw server shutdown");
    }
}
