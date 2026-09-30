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
        let mss = if dry_run {
            1380u16
        } else {
            discover_mss(&wan_iface).await.unwrap_or(1380)
        };
        let mtu = mss + 40;
        info!("PMTUD: optimal MSS = {mss} bytes (estimated MTU = {mtu})");
        let _ = event_tx.send(HeliosEvent::MtuDiscovered { mtu, mss });
        let _ = internal_tx.send(OrchestratorCmd::SetMssClamp(mss)).await;
    });
}

pub(super) async fn discover_mss(wan_iface: &str) -> Option<u16> {
    let mtu_str = tokio::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .await
        .ok()?;
    let mtu: u16 = mtu_str.trim().parse().ok()?;
    // WireGuard: ~60 bytes of overhead (header + UDP/IP) + 40 for the TCP/IP header.
    Some(mtu.saturating_sub(100).max(576))
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
