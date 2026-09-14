//! The WAN interface: resolving `wan_iface = "auto"`, and explaining it.
//!
//! `show-uplink` exists to print what `resolve_uplink` would choose and why,
//! so the two live together. `resolve_uplink` is also the daemon's first
//! bootstrap step and `status`'s, which is why it is `pub(crate)`.

use aether::NetworkConfig;
use anyhow::Context;
use tracing::{info, warn};

use crate::uplink;

/// Resolves `wan_iface = "auto"` against the kernel, once.
///
/// Substituted into the in-memory configuration, so everything downstream —
/// the firewall policy, the hot reload, the API view — sees a real interface
/// name rather than a marker. The file keeps `auto`: it describes the
/// operator's intent, not the machine's current cabling.
pub(crate) fn resolve_uplink(network: &mut NetworkConfig) -> anyhow::Result<()> {
    if !network.wan_iface_is_auto() {
        return Ok(());
    }
    let selection = uplink::resolve().context("choosing the WAN interface")?;
    for warning in &selection.warnings {
        warn!("{warning}");
    }
    info!(
        interfaces = %selection.interfaces.join(", "),
        preferred = %selection.preferred(),
        reason = %selection.reason,
        "WAN interfaces enumerated from the kernel — all of them are permitted"
    );
    network.wan_ifaces = selection.interfaces;
    Ok(())
}

/// Prints what `wan_iface = "auto"` would choose, and why.
pub(crate) fn show_uplink() -> anyhow::Result<()> {
    let facts = uplink::observe(
        std::path::Path::new("/sys/class/net"),
        std::path::Path::new("/proc"),
    )
    .context("reading the kernel's network state")?;
    for interface in facts.iter().filter(|facts| facts.physical) {
        println!(
            "{:<12} {:<9} carrier={} default_route={}",
            interface.name,
            if interface.wireless {
                "wireless"
            } else {
                "wired"
            },
            u8::from(interface.carrier),
            match interface.default_route_metric {
                Some(metric) => format!("metric {metric}"),
                None => "none".to_string(),
            }
        );
    }
    println!();
    match uplink::select(&facts) {
        Ok(selection) => {
            for warning in &selection.warnings {
                println!("attention : {warning}");
            }
            println!("permises : {}", selection.interfaces.join(", "));
            println!(
                "préférée : {} — {}",
                selection.preferred(),
                selection.reason
            );
        }
        Err(error) => println!("aucune interface retenue : {error}"),
    }
    Ok(())
}
