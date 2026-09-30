//! How a raw-socket error is told apart: an absent service, an unreachable
//! gateway, or a foreign listener on the port.

use super::*;

pub(super) fn raw_transport(error: std::io::Error) -> SpeedTestError {
    SpeedTestError::Transport(error.to_string())
}

/// A UDP failure, named for what it most likely is.
///
/// Applied to the latency probe, which is the **first** thing a run does: a
/// gateway with no speedtest service is therefore reported before ten seconds
/// of throughput are attempted against it.
pub(super) fn raw_udp_transport(error: std::io::Error) -> SpeedTestError {
    if looks_like_a_foreign_listener(&error) {
        service_absent(&error.to_string())
    } else if looks_unanswered(&error) {
        unreachable(&error.to_string())
    } else {
        SpeedTestError::Transport(error.to_string())
    }
}

/// The rendered text of [`SpeedTestError::ServiceAbsent`].
///
/// The worker threads exchange failures as strings — they cross a barrier and
/// a `join` — so the diagnosis is rendered here rather than carried as a type
/// and re-wrapped at every layer.
pub(super) fn foreign_service(detail: &str) -> String {
    service_absent(detail).to_string()
}

/// The refusal that names what a reset on this port actually means.
pub(super) fn service_absent(detail: &str) -> SpeedTestError {
    SpeedTestError::ServiceAbsent {
        port: aether::speedtest::SPEEDTEST_PORT,
        detail: detail.to_string(),
    }
}

/// The refusal that names what **silence** on this port actually means.
pub(super) fn unreachable(detail: &str) -> SpeedTestError {
    SpeedTestError::Unreachable {
        port: aether::speedtest::SPEEDTEST_PORT,
        detail: detail.to_string(),
    }
}

/// Whether a failure means "the probe left and nothing came back".
///
/// The counterpart of [`looks_like_a_foreign_listener`], and its opposite
/// remedy. A reset says a machine answered — something is on the port, or the
/// host refused. Silence says the packets are being dropped, or that they are
/// arriving where nothing is bound: on the gateway, either the firewall does
/// not open the speedtest port on the tunnel interface, or `heliosd` bound its
/// listeners elsewhere. Both are facts about the gateway, and neither is worth
/// retrying from the client.
///
/// A connected UDP socket surfaces the exhausted read timeout as `TimedOut` on
/// Windows (`os error 10060`) and as `WouldBlock` on Unix; `TcpStream::
/// connect_timeout` reports its own expiry as `TimedOut` on both.
pub(super) fn looks_unanswered(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// A control-channel I/O failure, named for what it most likely is.
pub(super) fn foreign_or_transport(error: std::io::Error) -> String {
    if looks_like_a_foreign_listener(&error) {
        foreign_service(&error.to_string())
    } else if looks_unanswered(&error) {
        unreachable(&error.to_string()).to_string()
    } else {
        error.to_string()
    }
}

/// Whether a failure means "nothing of ours is on this port".
///
/// The distinction matters because the two have opposite remedies. A path
/// problem is transient and worth retrying; a port served by something else —
/// or by nothing at all — is a fact about the gateway, and an operator faced
/// with « une connexion existante a dû être fermée par l’hôte distant » has
/// no reason to go and read heliosd’s journal, which is where the answer is.
///
/// Both transports land here, for two different reasons that mean the same
/// thing:
///
/// - **TCP**: the connection is accepted, then dies as soon as our control
///   frame arrives — a service that speaks another protocol reading sixteen
///   bytes of nonsense and hanging up;
/// - **UDP**: there is no socket at all, the host answers ICMP port
///   unreachable, and Windows surfaces that on the *next* `recv` of a
///   connected socket as `WSAECONNRESET` — the very `os error 10054` this
///   diagnosis exists for.
fn looks_like_a_foreign_listener(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
    )
}
