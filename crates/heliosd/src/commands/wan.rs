//! The WAN interface: resolving `wan_iface = "auto"`, and explaining it.
//!
//! `show-uplink` exists to print what `resolve_uplink` would choose and why,
//! so the two live together. `resolve_uplink` is also the daemon's first
//! bootstrap step and `status`'s, which is why it is `pub(crate)`.

use aether::NetworkConfig;
use anyhow::Context;
use tracing::{info, warn};

use crate::uplink;

/// Resolves `wan_iface = "auto"` against the kernel, at startup.
///
/// The orchestrator keeps the result in step with the kernel afterwards
/// (`orchestrator::uplinks`). Substituted into the in-memory configuration, so everything downstream —
/// the firewall policy, the hot reload, the API view — sees a real interface
/// name rather than a marker. The file keeps `auto`: it describes the
/// operator's intent, not the machine's current cabling.
pub(crate) fn resolve_uplink(network: &mut NetworkConfig) -> anyhow::Result<()> {
    resolve_uplink_with(network, uplink::resolve)
}

fn resolve_uplink_with(
    network: &mut NetworkConfig,
    resolve: impl FnOnce() -> Result<uplink::Selection, uplink::UplinkError>,
) -> anyhow::Result<()> {
    if !network.wan_iface_is_auto() {
        return Ok(());
    }
    let selection = resolve().context("choosing the WAN interface")?;
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
    for line in uplink_report(&facts) {
        println!("{line}");
    }
    Ok(())
}

fn uplink_report(facts: &[uplink::InterfaceFacts]) -> Vec<String> {
    let mut report = Vec::new();
    for interface in facts.iter().filter(|facts| facts.physical) {
        report.push(format!(
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
        ));
    }
    report.push(String::new());
    match uplink::select(facts) {
        Ok(selection) => {
            for warning in &selection.warnings {
                report.push(format!("attention : {warning}"));
            }
            report.push(format!("permises : {}", selection.interfaces.join(", ")));
            report.push(format!(
                "préférée : {} — {}",
                selection.preferred(),
                selection.reason
            ));
        }
        Err(error) => report.push(format!("aucune interface retenue : {error}")),
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use uplink::{InterfaceFacts, Selection, SelectionReason};

    fn facts(
        name: &str,
        physical: bool,
        wireless: bool,
        carrier: bool,
        metric: Option<u32>,
    ) -> InterfaceFacts {
        InterfaceFacts {
            name: name.to_string(),
            physical,
            wireless,
            carrier,
            default_route_metric: metric,
        }
    }

    #[test]
    fn named_wan_does_not_enumerate_or_replace_the_operator_choice() {
        let mut network = NetworkConfig {
            wan_ifaces: vec!["eth9".into()],
            ..NetworkConfig::default()
        };
        let result = resolve_uplink_with(&mut network, || {
            panic!("a named WAN must not inspect the kernel")
        });

        assert!(result.is_ok());
        assert_eq!(network.wan_ifaces, ["eth9"]);
    }

    #[test]
    fn automatic_wan_keeps_every_resolved_uplink_in_selection_order() {
        let mut network = NetworkConfig {
            wan_ifaces: vec!["auto".into()],
            ..NetworkConfig::default()
        };
        let selection = Selection {
            interfaces: vec!["eth0".into(), "wlan0".into()],
            reason: SelectionReason::WiredDefaultRoute,
            warnings: Vec::new(),
        };
        let result = resolve_uplink_with(&mut network, || Ok(selection));

        assert!(result.is_ok());
        assert_eq!(network.wan_ifaces, ["eth0", "wlan0"]);
    }

    #[test]
    fn automatic_wan_preserves_resolution_failure_context_and_config() {
        let mut network = NetworkConfig {
            wan_ifaces: vec!["auto".into()],
            ..NetworkConfig::default()
        };
        let result = resolve_uplink_with(&mut network, || {
            Err(uplink::UplinkError::NoPhysicalInterface)
        });
        let message = result
            .expect_err("missing physical uplink is fatal")
            .to_string();

        assert!(message.contains("choosing the WAN interface"));
        assert_eq!(network.wan_ifaces, ["auto"]);
    }

    #[test]
    fn report_lists_physical_interfaces_and_selected_order_with_warning() {
        let facts = [
            facts("lo", false, false, true, Some(0)),
            facts("eth0", true, false, true, None),
            facts("wlan0", true, true, true, Some(10)),
        ];

        let report = uplink_report(&facts);

        assert_eq!(report.len(), 6);
        assert!(report[0].starts_with("eth0"));
        assert!(report[1].starts_with("wlan0"));
        assert_eq!(report[2], "");
        assert!(report[3].starts_with("attention :"));
        assert_eq!(report[4], "permises : wlan0, eth0");
        assert!(report[5].starts_with("préférée : wlan0"));
    }

    #[test]
    fn report_explains_when_no_physical_uplink_exists() {
        let report = uplink_report(&[facts("lo", false, false, true, None)]);

        assert_eq!(report.len(), 2);
        assert_eq!(report[0], "");
        assert!(report[1].starts_with("aucune interface retenue :"));
    }
}
