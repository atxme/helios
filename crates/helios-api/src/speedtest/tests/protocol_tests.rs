//! Loopback coverage of the gateway's raw speedtest protocol.
use super::*;
use aether::speedtest::*;
use tokio::time;

fn tcp_session() -> (TcpStream, thread::JoinHandle<anyhow::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("TCP listener");
    let client = TcpStream::connect(listener.local_addr().expect("address")).expect("client");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let (server, _) = listener.accept().expect("server connection");
    (client, thread::spawn(move || handle_tcp_session(server)))
}

fn read_control(client: &mut TcpStream) -> (u8, u8, u16, u64) {
    let mut frame = [0; TCP_CONTROL_BYTES];
    client.read_exact(&mut frame).expect("control frame");
    parse_tcp_control(&frame).expect("valid control")
}

#[test]
fn tcp_upload_accepts_a_matching_start_and_the_entire_stream() {
    let (mut client, server) = tcp_session();
    client
        .write_all(&tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 42))
        .unwrap();
    assert_eq!(
        read_control(&mut client),
        (TCP_KIND_READY, SPEEDTEST_MODE_UPLOAD, 1, 42)
    );
    client
        .write_all(&tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_UPLOAD, 1, 42))
        .unwrap();
    client.write_all(b"test payload").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    server
        .join()
        .expect("server thread")
        .expect("upload accepted");
}

#[test]
fn tcp_download_sends_payload_then_closes_its_write_side() {
    let (mut client, server) = tcp_session();
    client
        .write_all(&tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_DOWNLOAD, 1, 13))
        .unwrap();
    assert_eq!(
        read_control(&mut client),
        (TCP_KIND_READY, SPEEDTEST_MODE_DOWNLOAD, 1, 13)
    );
    client
        .write_all(&tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_DOWNLOAD, 1, 13))
        .unwrap();
    let mut buf = [0; 16384];
    let mut total = 0usize;
    loop {
        let n = client.read(&mut buf).expect("download data");
        if n == 0 {
            break;
        }
        total += n;
    }
    assert!(total > 0, "a download must carry data");
    server
        .join()
        .expect("server thread")
        .expect("download accepted");
}

#[test]
fn tcp_refuses_invalid_hellos_before_ready() {
    let mut bad_magic = tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 1);
    bad_magic[0] ^= 1;
    let mut bad_version = tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 1);
    bad_version[8] = SPEEDTEST_PROTOCOL_VERSION.wrapping_add(1);
    let cases = [
        bad_magic,
        bad_version,
        tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_UPLOAD, 1, 1),
        tcp_control(TCP_KIND_HELLO, 0, 1, 1),
        tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 0, 1),
        tcp_control(
            TCP_KIND_HELLO,
            SPEEDTEST_MODE_UPLOAD,
            SPEEDTEST_MAX_DURATION_SECS + 1,
            1,
        ),
    ];
    for frame in cases {
        let (mut client, server) = tcp_session();
        client.write_all(&frame).unwrap();
        let error = server
            .join()
            .expect("server thread")
            .expect_err("invalid hello");
        let mut response = [0; TCP_CONTROL_BYTES];
        assert_eq!(
            client.read(&mut response).unwrap(),
            0,
            "rejected hello returned ready: {error}"
        );
    }
}

#[test]
fn tcp_refuses_starts_that_do_not_match_the_accepted_hello() {
    for go in [
        tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 42),
        tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_DOWNLOAD, 1, 42),
        tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_UPLOAD, 2, 42),
        tcp_control(TCP_KIND_GO, SPEEDTEST_MODE_UPLOAD, 1, 43),
    ] {
        let (mut client, server) = tcp_session();
        client
            .write_all(&tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 42))
            .unwrap();
        assert_eq!(
            read_control(&mut client),
            (TCP_KIND_READY, SPEEDTEST_MODE_UPLOAD, 1, 42)
        );
        client.write_all(&go).unwrap();
        assert!(server.join().expect("server thread").is_err());
    }
}

#[test]
fn udp_parser_refuses_truncated_bad_magic_and_wrong_version() {
    let mut frame = vec![0; SPEEDTEST_UDP_HEADER_BYTES];
    write_udp_header(
        &mut frame,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        7,
        0,
        1,
        0,
    );
    assert!(parse_udp_frame(&frame[..SPEEDTEST_UDP_HEADER_BYTES - 1]).is_none());
    let mut bad = frame.clone();
    bad[0] ^= 1;
    assert!(parse_udp_frame(&bad).is_none());
    bad = frame;
    bad[8] = SPEEDTEST_PROTOCOL_VERSION.wrapping_add(1);
    assert!(parse_udp_frame(&bad).is_none());
}

struct UdpServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<anyhow::Result<()>>>,
}
impl UdpServer {
    fn start(state: AppState) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("server socket");
        socket.set_read_timeout(Some(UDP_READ_TIMEOUT)).unwrap();
        let address = socket.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let runtime = tokio::runtime::Handle::current();
        let worker = thread::spawn(move || run_udp_server(socket, state, runtime, stop));
        Self {
            address,
            shutdown,
            worker: Some(worker),
        }
    }
}
impl Drop for UdpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("UDP server thread")
            .expect("UDP server stops");
    }
}
fn udp_client() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(350)))
        .unwrap();
    socket
}
fn udp_send(
    socket: &UdpSocket,
    address: SocketAddr,
    kind: u8,
    mode: u8,
    session: u64,
    duration: u16,
    payload: &[u8],
) {
    send_udp_frame(socket, address, kind, mode, session, 0, duration, payload);
}
fn udp_receive(socket: &UdpSocket) -> Vec<u8> {
    let mut packet = vec![0; SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    let n = socket.recv(&mut packet).expect("UDP response");
    packet.truncate(n);
    packet
}
fn no_udp_response(socket: &UdpSocket) {
    let mut packet = [0; SPEEDTEST_UDP_DATAGRAM_BYTES + 64];
    let error = socket.recv(&mut packet).expect_err("no response expected");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_rejects_unknown_sources_even_for_ping_and_hello() {
    let mut state = test_state();
    state.dry_run = false;
    let server = UdpServer::start(state);
    let client = udp_client();
    udp_send(&client, server.address, UDP_KIND_PING, 0, 1, 0, &[]);
    no_udp_response(&client);
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        1,
        1,
        &[],
    );
    no_udp_response(&client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_ping_and_hello_check_protocol_and_limits_before_ready() {
    let server = UdpServer::start(test_state());
    let client = udp_client();
    client.send_to(b"truncated", server.address).unwrap();
    udp_send(&client, server.address, UDP_KIND_HELLO, 0, 5, 1, &[]);
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        5,
        0,
        &[],
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        5,
        SPEEDTEST_MAX_DURATION_SECS + 1,
        &[],
    );
    no_udp_response(&client);
    udp_send(&client, server.address, UDP_KIND_PING, 0, 7, 0, &[]);
    let pong = udp_receive(&client);
    let frame = parse_udp_frame(&pong).unwrap();
    assert_eq!((frame.kind, frame.session), (UDP_KIND_PONG, 7));
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        5,
        1,
        &[],
    );
    let ready = udp_receive(&client);
    let frame = parse_udp_frame(&ready).unwrap();
    assert_eq!(
        (frame.kind, frame.mode, frame.session, frame.duration),
        (UDP_KIND_READY, SPEEDTEST_MODE_UPLOAD, 5, 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_upload_counts_only_started_data_from_the_owning_socket_and_session() {
    let server = UdpServer::start(test_state());
    let client = udp_client();
    let stranger = udp_client();
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        &[],
    );
    assert_eq!(
        parse_udp_frame(&udp_receive(&client)).unwrap().kind,
        UDP_KIND_READY
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        b"before",
    );
    udp_send(
        &stranger,
        server.address,
        UDP_KIND_GO,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        &[],
    );
    udp_send(
        &stranger,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        b"foreign",
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_GO,
        SPEEDTEST_MODE_UPLOAD,
        9,
        1,
        &[],
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_GO,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        &[],
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        b"abc",
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        b"de",
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_FINISH,
        SPEEDTEST_MODE_UPLOAD,
        8,
        1,
        &[],
    );
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let summary = udp_receive(&client);
    let frame = parse_udp_frame(&summary).unwrap();
    assert_eq!((frame.kind, frame.session), (UDP_KIND_SUMMARY, 8));
    assert_eq!(
        u64::from_be_bytes(frame.payload[..8].try_into().unwrap()),
        5
    );
    assert_eq!(
        u64::from_be_bytes(frame.payload[8..16].try_into().unwrap()),
        2
    );
    no_udp_response(&stranger);
}

#[test]
fn tcp_incomplete_control_frame_is_rejected() {
    let (mut client, server) = tcp_session();
    client
        .write_all(&tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 42)[..8])
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert!(server.join().expect("server thread").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_download_reports_the_data_it_sent() {
    let server = UdpServer::start(test_state());
    let client = udp_client();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut hello = [0; SPEEDTEST_UDP_HEADER_BYTES];
    write_udp_header(
        &mut hello,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_DOWNLOAD,
        18,
        0,
        1,
        encode_rate(1.0),
    );
    client.send_to(&hello, server.address).unwrap();
    assert_eq!(
        parse_udp_frame(&udp_receive(&client)).unwrap().kind,
        UDP_KIND_READY
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_GO,
        SPEEDTEST_MODE_DOWNLOAD,
        18,
        1,
        &[],
    );
    let mut packets = 0u64;
    let mut bytes = 0u64;
    loop {
        let datagram = udp_receive(&client);
        let frame = parse_udp_frame(&datagram).expect("gateway datagram");
        assert_eq!(frame.session, 18);
        match frame.kind {
            UDP_KIND_DATA => {
                packets += 1;
                bytes += frame.payload.len() as u64;
                assert_eq!(frame.rate, encode_rate(1.0));
            }
            UDP_KIND_END => {
                let sent_packets = u64::from_be_bytes(frame.payload[..8].try_into().unwrap());
                let sent_bytes = u64::from_be_bytes(frame.payload[8..16].try_into().unwrap());
                assert!(packets > 0);
                assert!(
                    sent_packets >= packets,
                    "UDP may lose data, never create it"
                );
                assert_eq!(
                    sent_bytes,
                    sent_packets
                        * (SPEEDTEST_UDP_DATAGRAM_BYTES - SPEEDTEST_UDP_HEADER_BYTES) as u64
                );
                assert_eq!(
                    bytes,
                    packets * (SPEEDTEST_UDP_DATAGRAM_BYTES - SPEEDTEST_UDP_HEADER_BYTES) as u64
                );
                break;
            }
            other => panic!("unexpected UDP frame kind {other}"),
        }
    }
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The server's TCP and UDP listeners bind the same tunnel address. Reserve
/// both protocols first so this test never needs the production port.
fn free_raw_address() -> SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).expect("reserve UDP port");
    drop((tcp, udp));
    address
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_listeners_accept_loopback_only_in_development_mode() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for dry_run in [true, false] {
        let mut state = test_state();
        state.dry_run = dry_run;
        let address = free_raw_address();
        let shutdown = Arc::new(AtomicBool::new(false));
        let _stop = StopOnDrop(Arc::clone(&shutdown));
        let task = tokio::spawn(serve_raw(state, address, Arc::clone(&shutdown)));
        let mut tcp = time::timeout(Duration::from_secs(3), async {
            loop {
                match tokio::net::TcpStream::connect(address).await {
                    Ok(stream) => break stream,
                    Err(_) => time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("TCP listener starts");
        tcp.write_all(&tcp_control(TCP_KIND_HELLO, SPEEDTEST_MODE_UPLOAD, 1, 52))
            .await
            .unwrap();
        let mut answer = [0; TCP_CONTROL_BYTES];
        let received = time::timeout(Duration::from_secs(2), tcp.read_exact(&mut answer))
            .await
            .expect("TCP decision");
        if dry_run {
            received.expect("ready for loopback development client");
            assert_eq!(
                parse_tcp_control(&answer).unwrap(),
                (TCP_KIND_READY, SPEEDTEST_MODE_UPLOAD, 1, 52)
            );
        } else {
            assert!(
                received.is_err(),
                "unknown source must not receive TCP ready"
            );
        }
        drop(tcp);

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ping = [0; SPEEDTEST_UDP_HEADER_BYTES];
        write_udp_header(&mut ping, UDP_KIND_PING, 0, 53, 0, 0, 0);
        udp.send_to(&ping, address).await.unwrap();
        let mut buffer = [0; SPEEDTEST_UDP_DATAGRAM_BYTES];
        let result = time::timeout(Duration::from_millis(400), udp.recv_from(&mut buffer)).await;
        if dry_run {
            let (length, _) = result.expect("UDP decision").unwrap();
            assert_eq!(
                parse_udp_frame(&buffer[..length]).unwrap().kind,
                UDP_KIND_PONG
            );
        } else {
            assert!(result.is_err(), "unknown source must not receive UDP pong");
        }
        shutdown.store(true, Ordering::Release);
        time::timeout(Duration::from_secs(3), task)
            .await
            .expect("server stops")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_upload_drains_late_data_then_forgets_the_session() {
    let server = UdpServer::start(test_state());
    let client = udp_client();
    udp_send(
        &client,
        server.address,
        UDP_KIND_HELLO,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        &[],
    );
    assert_eq!(
        parse_udp_frame(&udp_receive(&client)).unwrap().kind,
        UDP_KIND_READY
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_GO,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        &[],
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        b"abc",
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_FINISH,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        &[],
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_DATA,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        b"late",
    );
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let summary = udp_receive(&client);
    let frame = parse_udp_frame(&summary).unwrap();
    assert_eq!(frame.kind, UDP_KIND_SUMMARY);
    assert_eq!(
        u64::from_be_bytes(frame.payload[..8].try_into().unwrap()),
        7
    );
    assert_eq!(
        u64::from_be_bytes(frame.payload[8..16].try_into().unwrap()),
        2
    );
    udp_send(
        &client,
        server.address,
        UDP_KIND_FINISH,
        SPEEDTEST_MODE_UPLOAD,
        29,
        1,
        &[],
    );
    client
        .set_read_timeout(Some(Duration::from_millis(350)))
        .unwrap();
    no_udp_response(&client);
}
