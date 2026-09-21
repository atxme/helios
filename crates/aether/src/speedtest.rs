//! Wire format and limits for the raw in-tunnel speedtest service.
//!
//! This is deliberately separate from the HTTP API. The speedtest counts
//! bytes written to and read from TCP/UDP sockets, so control frames are only
//! used to establish a short-lived measurement and never enter its counters.

use std::time::{Duration, Instant};

/// TCP and UDP port of the raw in-tunnel speedtest service.
///
/// This lives in the IANA private/dynamic range and stays distinct from
/// WireGuard (`51820`), key negotiation (`51821`) and iperf3 (`5201`).
/// Operators use iperf3 to cross-check the built-in measurement, and a
/// wildcard listener would otherwise prevent Helios from binding to its
/// tunnel VIP.
pub const SPEEDTEST_PORT: u16 = 55182;
/// Protocol version. A mismatch is rejected before a stream can send data.
///
/// Version 2 added the paced-rate field to the UDP header. The bump is
/// deliberate rather than a silent reuse of two zero bytes: a v2 client
/// against a v1 gateway would have its pacing request ignored and receive the
/// unpaced blast v1 always sent, which reports ~80 % loss on a healthy path.
/// A refused handshake names the mismatch; a wrong number does not.
pub const SPEEDTEST_PROTOCOL_VERSION: u8 = 2;
/// Magic shared by the TCP and UDP control frames.
pub const SPEEDTEST_MAGIC: [u8; 8] = *b"HELIOSST";
/// Duration of one **throughput** direction, long enough for TCP to reach
/// cruise without making the whole run a wait.
pub const SPEEDTEST_DEFAULT_DURATION_SECS: u16 = 10;
/// Duration of one **quality** direction.
///
/// Shorter than a throughput leg on purpose: loss and jitter at a known rate
/// stabilise in a couple of seconds, whereas TCP needs time to open its
/// window. Four legs at the throughput duration made a 80-second run.
pub const SPEEDTEST_QUALITY_DURATION_SECS: u16 = 5;
/// Absolute upper bound accepted by the gateway and Orion.
pub const SPEEDTEST_MAX_DURATION_SECS: u16 = 30;
/// Number of independent TCP congestion windows used by the default test.
pub const SPEEDTEST_TCP_STREAMS: usize = 4;
/// Large userspace buffer, allocated before timing starts.
pub const SPEEDTEST_TCP_BUFFER_BYTES: usize = 1024 * 1024;
/// WireGuard-safe UDP payload size.
pub const SPEEDTEST_UDP_DATAGRAM_BYTES: usize = 1200;
/// Fixed UDP control header: magic, version/kind/mode, session, sequence,
/// duration and paced rate. Data payload starts immediately after this header.
pub const SPEEDTEST_UDP_HEADER_BYTES: usize = 32;

/// Unit of the paced-rate field, in bits per second.
///
/// The field is a `u16` in hundreds of kilobits: it reaches 6.5 Gb/s and still
/// resolves a 100 kb/s uplink. Plain megabits would have rounded every line
/// under 1 Mb/s down to zero — which this protocol reads as "do not pace".
pub const SPEEDTEST_RATE_UNIT_BPS: u64 = 100_000;

/// Pacing disabled: the sender emits as fast as the socket accepts.
///
/// # Why an unpaced sender cannot measure a path
///
/// It measures the *sender's* syscall loop, and everything the path cannot
/// carry is dropped. The loss figure that comes back is the ratio between
/// those two speeds, not a property of the link: on a perfectly healthy
/// gigabit tunnel it lands around 80 %. Only [`SPEEDTEST_MODE_DOWNLOAD`] and
/// [`SPEEDTEST_MODE_UPLOAD`] legs driven at a **known** rate produce a loss
/// number that means anything, which is why every quality leg carries one.
pub const SPEEDTEST_RATE_UNPACED: u16 = 0;

/// Share of the measured throughput a quality leg is driven at.
///
/// Below the capacity found by TCP, so that loss reports the path's own
/// behaviour rather than the queue overflowing. At or above it, every run on
/// a saturated link would read as faulty.
pub const SPEEDTEST_QUALITY_RATE_RATIO: f64 = 0.85;

/// Floor for a quality leg, in Mb/s.
///
/// A path whose TCP throughput collapsed still has to be probed at something:
/// pacing at a fraction of nearly zero would send a handful of datagrams and
/// call the result a loss measurement.
pub const SPEEDTEST_QUALITY_MIN_MBPS: f64 = 1.0;

/// Ceiling for a quality leg, in Mb/s.
///
/// Beyond this the userspace pacer becomes the limit rather than the path,
/// and the loss it reports would be its own. Loss and jitter do not need line
/// rate to be meaningful.
pub const SPEEDTEST_QUALITY_MAX_MBPS: f64 = 400.0;

/// Encodes a rate in Mb/s into the header field, clamped to what it can hold.
pub fn encode_rate(mbps: f64) -> u16 {
    if !mbps.is_finite() || mbps <= 0.0 {
        return SPEEDTEST_RATE_UNPACED;
    }
    let units = (mbps * 1_000_000.0 / SPEEDTEST_RATE_UNIT_BPS as f64).round();
    // Never round a real request down to "unpaced": that is the one value
    // that changes the meaning of the field rather than its precision.
    units.clamp(1.0, f64::from(u16::MAX)) as u16
}

/// Decodes the header field into bits per second. `None` means unpaced.
pub fn decode_rate(units: u16) -> Option<u64> {
    (units != SPEEDTEST_RATE_UNPACED).then(|| u64::from(units) * SPEEDTEST_RATE_UNIT_BPS)
}

/// Rate a quality leg should be driven at, given the throughput just measured.
pub fn quality_rate_mbps(throughput_mbps: f64) -> f64 {
    if !throughput_mbps.is_finite() || throughput_mbps <= 0.0 {
        return SPEEDTEST_QUALITY_MIN_MBPS;
    }
    (throughput_mbps * SPEEDTEST_QUALITY_RATE_RATIO)
        .clamp(SPEEDTEST_QUALITY_MIN_MBPS, SPEEDTEST_QUALITY_MAX_MBPS)
}

/// Fixed in-tunnel address used by Orion when the gateway uses the default
/// network configuration.
pub const DEFAULT_WG_SPEEDTEST_ADDR: &str = "100.64.0.1:55182";

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

/// Smallest delay worth handing to the OS scheduler.
///
/// A paced 100 Mb/s leg owes one datagram every ~96 µs, and no platform
/// sleeps that briefly — Windows rounds up to the timer resolution, which is
/// milliseconds. Sleeping per datagram would therefore *undershoot* the
/// requested rate by an order of magnitude. So the pacer only sleeps once it
/// is at least this far ahead of schedule, and sends back-to-back until then:
/// the leg comes out as short bursts whose average is the requested rate.
const PACER_MIN_SLEEP: Duration = Duration::from_millis(1);

/// Drives a datagram sender at a requested rate.
///
/// # Why both ends need one
///
/// A UDP leg exists to report loss and jitter, and neither means anything
/// unless the sending rate is known — see [`SPEEDTEST_RATE_UNPACED`]. The
/// pacer keeps a schedule in absolute time rather than sleeping a fixed
/// amount between datagrams: a sleep that overshoots is then absorbed by the
/// following burst instead of accumulating over the whole leg.
pub struct Pacer {
    /// `None` leaves the sender unpaced — kept as a representable state
    /// because the peer may legitimately request it.
    per_packet: Option<Duration>,
    started: Instant,
}

impl Pacer {
    /// `rate_bps` of `None`, or a packet size of zero, means no pacing.
    pub fn new(rate_bps: Option<u64>, packet_bytes: usize, started: Instant) -> Self {
        let per_packet = match (rate_bps, packet_bytes) {
            (Some(bps), bytes) if bps > 0 && bytes > 0 => {
                Some(Duration::from_secs_f64(bytes as f64 * 8.0 / bps as f64))
            }
            _ => None,
        };
        Self {
            per_packet,
            started,
        }
    }

    /// Blocks until the schedule allows the next datagram.
    ///
    /// `sent` is the number of datagrams already emitted, so the deadline for
    /// the next one is `started + sent * per_packet`. `hard_deadline` caps the
    /// wait: a leg that is ending must not sleep past its own end.
    pub fn after_sending(&mut self, sent: u64, hard_deadline: Instant) {
        let Some(per_packet) = self.per_packet else {
            return;
        };
        let Some(target) = per_packet
            .checked_mul(u32::try_from(sent).unwrap_or(u32::MAX))
            .map(|offset| self.started + offset)
        else {
            return;
        };
        let target = target.min(hard_deadline);
        let now = Instant::now();
        if target <= now {
            return;
        }
        let wait = target - now;
        if wait >= PACER_MIN_SLEEP {
            std::thread::sleep(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_target_uses_the_private_helios_port() {
        let target: std::net::SocketAddr = DEFAULT_WG_SPEEDTEST_ADDR
            .parse()
            .expect("default speedtest target");
        assert_eq!(target.port(), SPEEDTEST_PORT);
        assert!((49152..=65535).contains(&SPEEDTEST_PORT));
        assert_ne!(SPEEDTEST_PORT, 5201, "iperf3 owns its default port");
    }

    /// The one value that changes the field's meaning rather than its
    /// precision is `0`. A slow but real line must never encode to it.
    #[test]
    fn a_real_rate_never_encodes_to_unpaced() {
        assert_eq!(encode_rate(0.0), SPEEDTEST_RATE_UNPACED);
        assert_eq!(encode_rate(-1.0), SPEEDTEST_RATE_UNPACED);
        assert_eq!(encode_rate(f64::NAN), SPEEDTEST_RATE_UNPACED);
        for mbps in [0.001, 0.01, 0.05, 0.1, 1.0, 250.0, 6_553.5, 100_000.0] {
            assert_ne!(encode_rate(mbps), SPEEDTEST_RATE_UNPACED, "{mbps} Mb/s");
        }
    }

    #[test]
    fn encoding_round_trips_within_the_unit() {
        for mbps in [1.0, 12.5, 100.0, 943.2] {
            let bps = decode_rate(encode_rate(mbps)).expect("paced");
            let error = (bps as f64 - mbps * 1_000_000.0).abs();
            assert!(error <= SPEEDTEST_RATE_UNIT_BPS as f64, "{mbps} Mb/s");
        }
    }

    #[test]
    fn decoding_zero_means_unpaced() {
        assert_eq!(decode_rate(SPEEDTEST_RATE_UNPACED), None);
    }

    /// The property the loss figure rests on. Ten 1200-byte datagrams at
    /// 1 Mb/s owe 96 ms; the pacer may run up to one `PACER_MIN_SLEEP` ahead
    /// of that schedule and no more.
    #[test]
    fn a_paced_sender_cannot_outrun_its_schedule() {
        let started = Instant::now();
        let mut pacer = Pacer::new(Some(1_000_000), SPEEDTEST_UDP_DATAGRAM_BYTES, started);
        for sent in 1..=10 {
            pacer.after_sending(sent, started + Duration::from_secs(5));
        }
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(85), "{elapsed:?}");
    }

    #[test]
    fn an_unpaced_sender_never_sleeps() {
        let started = Instant::now();
        let mut pacer = Pacer::new(None, SPEEDTEST_UDP_DATAGRAM_BYTES, started);
        for sent in 1..=10_000 {
            pacer.after_sending(sent, started + Duration::from_secs(5));
        }
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    /// A leg that is ending must not sleep past its own end: at 1 kb/s one
    /// datagram owes 9.6 s, which would otherwise outlive the measurement.
    #[test]
    fn the_hard_deadline_caps_the_wait() {
        let started = Instant::now();
        let mut pacer = Pacer::new(Some(1_000), SPEEDTEST_UDP_DATAGRAM_BYTES, started);
        pacer.after_sending(1, started + Duration::from_millis(40));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    /// A quality leg is always driven at *something*: a collapsed path still
    /// has to be probed, and a very fast one must not outrun the pacer.
    #[test]
    fn quality_rate_stays_between_its_floor_and_ceiling() {
        assert_eq!(quality_rate_mbps(0.0), SPEEDTEST_QUALITY_MIN_MBPS);
        assert_eq!(quality_rate_mbps(-5.0), SPEEDTEST_QUALITY_MIN_MBPS);
        assert_eq!(quality_rate_mbps(0.1), SPEEDTEST_QUALITY_MIN_MBPS);
        assert_eq!(quality_rate_mbps(10_000.0), SPEEDTEST_QUALITY_MAX_MBPS);
        // In between it stays under the measured throughput, which is the
        // whole point: at or above it, a saturated link reads as faulty.
        let paced = quality_rate_mbps(100.0);
        assert!(paced < 100.0 && paced > 50.0, "{paced}");
    }
}
