//! The raw engine's framing: TCP control lines and UDP datagram headers.

pub(super) fn udp_frame(
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
    rate: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0u8; aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES + payload.len()];
    write_udp_header(&mut frame, kind, mode, session, sequence, duration, rate);
    frame[aether::speedtest::SPEEDTEST_UDP_HEADER_BYTES..].copy_from_slice(payload);
    frame
}

pub(super) fn write_udp_header(
    frame: &mut [u8],
    kind: u8,
    mode: u8,
    session: u64,
    sequence: u64,
    duration: u16,
    rate: u16,
) {
    frame[..8].copy_from_slice(&aether::speedtest::SPEEDTEST_MAGIC);
    frame[8] = aether::speedtest::SPEEDTEST_PROTOCOL_VERSION;
    frame[9] = kind;
    frame[10] = mode;
    frame[11] = 0;
    frame[12..20].copy_from_slice(&session.to_be_bytes());
    frame[20..28].copy_from_slice(&sequence.to_be_bytes());
    frame[28..30].copy_from_slice(&duration.to_be_bytes());
    frame[30..32].copy_from_slice(&rate.to_be_bytes());
}

pub(super) fn tcp_control(
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

pub(super) fn parse_tcp_control(
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

pub(super) fn raw_buffer() -> Vec<u8> {
    let mut buffer = vec![0u8; aether::speedtest::SPEEDTEST_TCP_BUFFER_BYTES];
    fill_payload(&mut buffer);
    buffer
}

fn fill_payload(buffer: &mut [u8]) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for chunk in buffer.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *chunk = state.to_le_bytes();
    }
}

pub(super) struct ClientUdpFrame<'a> {
    pub(super) kind: u8,
    pub(super) mode: u8,
    pub(super) session: u64,
    pub(super) payload: &'a [u8],
}

pub(super) fn parse_client_udp_frame(packet: &[u8]) -> Option<ClientUdpFrame<'_>> {
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
