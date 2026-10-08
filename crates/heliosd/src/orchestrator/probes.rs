//! Probes kept for the real WireGuard backend: captive portal and MTU.

use super::*;

// ─── Probes kept: wired to the future real WireGuard backend (target-only) ───
// Captive portal detection will rely on these probes during real bring-up.
// Not used in the current dry-run path.
#[allow(dead_code)]
async fn probe_captive_portal(wan_iface: &str) -> Option<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        tcp_http_probe("connectivitycheck.gstatic.com", 80, "/generate_204"),
    )
    .await
    .ok()??;

    if result == 204 {
        return None;
    }

    let gateway = get_default_gateway(wan_iface)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    Some(gateway)
}

#[allow(dead_code)]
async fn tcp_http_probe(host: &str, port: u16, path: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.ok()?;
    let header = std::str::from_utf8(&buf[..n]).ok()?;
    header.split_whitespace().nth(1)?.parse().ok()
}

#[allow(dead_code)]
async fn get_default_gateway(wan_iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["route", "show", "default", "dev", wan_iface])
        .output()
        .await
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|&w| w != "via")
        .nth(1)
        .map(str::to_string)
}

pub(super) async fn spawn_mtu_probe_if_up(
    wan_iface: &str,
    dry_run: bool,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
) {
    if *shared_state.read().await == TunnelState::Up {
        spawn_mtu_probe(
            wan_iface.to_string(),
            event_tx.clone(),
            internal_tx.clone(),
            dry_run,
        );
    }
}

fn spawn_mtu_probe(
    wan_iface: String,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
    dry_run: bool,
) {
    tokio::spawn(async move {
        let transport = if dry_run {
            aether::mtu::MTU_TRANSPORT_DEFAUT
        } else {
            mtu_transport(&wan_iface)
        };
        let TunnelMss {
            tunnel_mtu: mtu,
            ipv4: mss,
            ipv6: mss_v6,
        } = tunnel_mss(transport);
        match mss_v6 {
            Some(mss_v6) => info!(
                "PMTUD: tunnel MTU = {mtu} bytes, TCP MSS = {mss} over IPv4, {mss_v6} over IPv6"
            ),
            None => info!(
                "PMTUD: tunnel MTU = {mtu} bytes, TCP MSS = {mss} over IPv4, no IPv6 below {} bytes",
                aether::mtu::MTU_MIN_IPV6
            ),
        }
        // The clamp holds the IPv4 value: it is the only family the gateway
        // forwards, and the firewall IR has no IPv6 clamp yet.
        let _ = event_tx.send(HeliosEvent::MtuDiscovered { mtu, mss });
        let _ = internal_tx.send(OrchestratorCmd::SetMssClamp(mss)).await;
    });
}

/// What the MTU probe derives from the transport's MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TunnelMss {
    /// MTU of the tunnel interface: the value `wg_config` sets on it.
    pub(super) tunnel_mtu: u16,
    /// TCP MSS over IPv4 inside the tunnel.
    pub(super) ipv4: u16,
    /// TCP MSS over IPv6 inside the tunnel; `None` when the tunnel is too
    /// narrow to carry IPv6.
    pub(super) ipv6: Option<u16>,
}

/// Tunnel MTU and per-family TCP MSS for a transport of `mtu_transport`
/// bytes.
///
/// The tunnel MTU comes from [`aether::mtu::tunnel_mtu`], the computation
/// that sizes the interface: its WireGuard overhead is the 80 bytes of an
/// IPv6 outer header, whatever family the endpoint uses. Deriving the MSS
/// from any other estimate would announce segments the interface cannot
/// carry. The MSS then removes the inner headers of each family.
pub(super) fn tunnel_mss(mtu_transport: u32) -> TunnelMss {
    let tunnel_mtu = aether::mtu::tunnel_mtu(mtu_transport);
    TunnelMss {
        tunnel_mtu: u16::try_from(tunnel_mtu).unwrap_or(u16::MAX),
        ipv4: aether::mtu::mss_ipv4(tunnel_mtu),
        ipv6: aether::mtu::mss_ipv6(tunnel_mtu),
    }
}

/// WAN link MTU, read from sysfs.
///
/// Blocking read accepted: `wg_config` is called on the interface bring-up
/// path, before any networking, and the file is in memory. An unreadable
/// WAN — wrong name, interface not yet created — falls back to standard
/// Ethernet, which restores the behavior from before this setting.
pub(super) fn mtu_transport(wan_iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or_else(|| {
            warn!(
                "MTU of {wan_iface} unreadable — falling back to {} bytes",
                aether::mtu::MTU_TRANSPORT_DEFAUT
            );
            aether::mtu::MTU_TRANSPORT_DEFAUT
        })
}

pub(super) fn parse_proc_net_dev(content: &str, iface: &str) -> Option<(u64, u64, u64, u64)> {
    for line in content.lines() {
        let Some((name, rest)) = line.trim_start().split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        return Some((
            fields[0].parse().ok()?,
            fields[8].parse().ok()?,
            fields[1].parse().ok()?,
            fields[9].parse().ok()?,
        ));
    }
    None
}
