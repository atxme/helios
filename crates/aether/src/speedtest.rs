//! Wire format and limits for the raw in-tunnel speedtest service.
//!
//! This is deliberately separate from the HTTP API. The speedtest counts
//! bytes written to and read from TCP/UDP sockets, so control frames are only
//! used to establish a short-lived measurement and never enter its counters.

/// TCP and UDP port of the raw in-tunnel speedtest service.
pub const SPEEDTEST_PORT: u16 = 5201;
/// Protocol version. A mismatch is rejected before a stream can send data.
pub const SPEEDTEST_PROTOCOL_VERSION: u8 = 1;
/// Magic shared by the TCP and UDP control frames.
pub const SPEEDTEST_MAGIC: [u8; 8] = *b"HELIOSST";
/// Default duration of one direction, long enough for TCP to reach cruise.
pub const SPEEDTEST_DEFAULT_DURATION_SECS: u16 = 8;
/// Absolute upper bound accepted by the gateway and Orion.
pub const SPEEDTEST_MAX_DURATION_SECS: u16 = 30;
/// Number of independent TCP congestion windows used by the default test.
pub const SPEEDTEST_TCP_STREAMS: usize = 4;
/// Large userspace buffer, allocated before timing starts.
pub const SPEEDTEST_TCP_BUFFER_BYTES: usize = 1024 * 1024;
/// WireGuard-safe UDP payload size.
pub const SPEEDTEST_UDP_DATAGRAM_BYTES: usize = 1200;
/// Fixed UDP control header: magic, version/kind/mode, session, sequence and
/// duration. Data payload starts immediately after this header.
pub const SPEEDTEST_UDP_HEADER_BYTES: usize = 32;

/// Fixed in-tunnel address used by Orion when the gateway uses the default
/// network configuration.
pub const DEFAULT_WG_SPEEDTEST_ADDR: &str = "100.64.0.1:5201";

/// TCP control frame size.
pub const TCP_CONTROL_BYTES: usize = 24;
/// TCP hello sent by the client.
pub const TCP_KIND_HELLO: u8 = 1;
/// TCP ready response sent by the gateway.
pub const TCP_KIND_READY: u8 = 2;
/// TCP go frame sent after all parallel flows are prepared.
pub const TCP_KIND_GO: u8 = 3;

/// UDP ping request.
pub const UDP_KIND_PING: u8 = 1;
/// UDP pong response.
pub const UDP_KIND_PONG: u8 = 2;
/// UDP session hello.
pub const UDP_KIND_HELLO: u8 = 3;
/// UDP session ready response.
pub const UDP_KIND_READY: u8 = 4;
/// Starts a prepared UDP session.
pub const UDP_KIND_GO: u8 = 5;
/// Raw measured UDP data.
pub const UDP_KIND_DATA: u8 = 6;
/// Marks the end of a UDP download and carries the sender counters.
pub const UDP_KIND_END: u8 = 7;
/// Ends an upload and asks for the receiver counters.
pub const UDP_KIND_FINISH: u8 = 8;
/// Carries the receiver counters for an upload.
pub const UDP_KIND_SUMMARY: u8 = 9;

/// Direction of a raw transfer.
pub const SPEEDTEST_MODE_DOWNLOAD: u8 = 1;
pub const SPEEDTEST_MODE_UPLOAD: u8 = 2;
