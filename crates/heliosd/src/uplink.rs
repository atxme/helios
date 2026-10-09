//! Enumerating the WAN interfaces from what the kernel says.
//!
//! `wan_iface = "auto"` in `network.toml` resolves here, at startup, to **every
//! usable uplink**, ordered with the one the kernel currently routes through
//! first and a wired link ahead of a wireless one at equal footing.
//!
//! # All of them are permitted, none is selected
//!
//! The firewall opens every rule that names the WAN once per interface. A
//! gateway with a cable and a radio therefore keeps working when the cable is
//! unplugged: the kernel moves its default route to the radio and the rules
//! are already there — no restart, no reload, no window during which the
//! kill-switch drops what it was meant to pass.
//!
//! That is why this returns a list rather than a choice. Naming one interface
//! and binding the whole ruleset to it makes the firewall the thing that
//! breaks a failover, which is the opposite of its job.
//!
//! # Where the preference actually lives
//!
//! Not here. What decides where a packet leaves is the routing table, and a
//! preference between two live uplinks is a route metric —
//! NetworkManager and systemd-networkd already give a wired link a better one
//! than a wireless one, so plugging a cable moves the traffic by itself.
//!
//! The order returned follows that: lowest default-route metric first, wired
//! breaking ties, interfaces the kernel routes nothing through last. Only the
//! things that watch a single interface use it — MTU probing and throughput
//! telemetry, where summing two links would describe neither.
//!
//! When the medium and the metrics disagree — a wired link with carrier, while
//! the kernel prefers the wireless one — [`Selection::warnings`] says so,
//! naming both and their metrics. Nothing here overrides it: reordering a list
//! the firewall permits in full would change nothing at all, and the operator's
//! lever is the metric.
//!
//! # After startup
//!
//! The same selection is re-run every two seconds by the orchestrator's
//! uplink watcher (`orchestrator::uplinks`): an interface that gains or loses
//! its carrier, or an adapter plugged in later, enters or leaves the set, and
//! the whole ruleset is rebuilt in one atomic transaction — the hot-reload
//! path, never an incremental edit.

use std::collections::BTreeMap;
use std::path::Path;

/// What the kernel says about one interface.
///
/// Facts only, and deliberately separated from the reading: the ordering below
/// is where the decisions are, and it is exercised without a kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFacts {
    pub name: String,
    /// Backed by a real device. Excludes `lo`, bridges, `veth`, WireGuard and
    /// every other virtual interface, which have no `device` link in sysfs.
    pub physical: bool,
    /// Driven by cfg80211/mac80211, or the legacy wireless extensions.
    ///
    /// The ARPHRD type does not answer this: a Wi-Fi interface reports type 1,
    /// exactly like Ethernet. The `phy80211` link does, and `wireless/` covers
    /// the drivers that predate it.
    pub wireless: bool,
    /// Link-level carrier — a cable in a socket, or an association.
    pub carrier: bool,
    /// Lowest metric among the default routes leaving through it.
    ///
    /// `None` means the kernel currently routes nothing default through it,
    /// which before DHCP answers is the ordinary state of a working uplink.
    pub default_route_metric: Option<u32>,
}

impl InterfaceFacts {
    fn usable(&self) -> bool {
        self.physical && self.carrier
    }
}

/// Why an interface was chosen, in the operator's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// It holds the best default route, and it is wired.
    WiredDefaultRoute,
    /// It holds the best default route, and it is wireless.
    WirelessDefaultRoute,
    /// No default route exists yet; it is the wired link with carrier.
    WiredCarrierOnly,
    /// No default route, no wired link with carrier: the wireless one.
    WirelessCarrierOnly,
}

impl std::fmt::Display for SelectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WiredDefaultRoute => "wired, holds the best default route",
            Self::WirelessDefaultRoute => "wireless, holds the best default route",
            Self::WiredCarrierOnly => "wired with carrier, no default route yet",
            Self::WirelessCarrierOnly => "wireless with carrier, no default route yet",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Every usable uplink, most-preferred first. All of them are permitted.
    pub interfaces: Vec<String>,
    /// Why the first one is first.
    pub reason: SelectionReason,
    /// What an operator should know, and what nothing else would tell them.
    pub warnings: Vec<String>,
}

impl Selection {
    /// The uplink the kernel currently routes through, as far as we can tell.
    pub fn preferred(&self) -> &str {
        self.interfaces.first().map(String::as_str).unwrap_or("")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UplinkError {
    #[error(
        "`wan_iface = \"auto\"` mais le noyau ne présente aucune interface physique : sur cette \
         machine il faut nommer l'interface explicitement"
    )]
    NoPhysicalInterface,
    #[error(
        "`wan_iface = \"auto\"` mais aucune interface physique n'a de porteuse : {0}. Brancher un \
         câble, associer le Wi-Fi, ou nommer l'interface explicitement"
    )]
    NoCarrier(String),
    #[error("lecture de l'état réseau du noyau : {0}")]
    Io(#[from] std::io::Error),
}

/// Enumerates the usable uplinks, most-preferred first.
///
/// Pure: everything it decides on is in `facts`.
pub fn select(facts: &[InterfaceFacts]) -> Result<Selection, UplinkError> {
    let mut usable: Vec<&InterfaceFacts> = facts.iter().filter(|facts| facts.usable()).collect();
    if !facts.iter().any(|facts| facts.physical) {
        return Err(UplinkError::NoPhysicalInterface);
    }
    if usable.is_empty() {
        let seen: Vec<&str> = facts
            .iter()
            .filter(|facts| facts.physical)
            .map(|facts| facts.name.as_str())
            .collect();
        return Err(UplinkError::NoCarrier(seen.join(", ")));
    }

    // The kernel's own order: lowest default-route metric first, then the
    // medium as a tie-break, then the name so the result never depends on the
    // order sysfs happened to be read in. Interfaces the kernel routes nothing
    // through sort last — they are still permitted, because that is exactly
    // what a link waiting for a lease needs.
    usable.sort_by(|left, right| {
        (
            left.default_route_metric.unwrap_or(u32::MAX),
            u8::from(left.wireless),
            &left.name,
        )
            .cmp(&(
                right.default_route_metric.unwrap_or(u32::MAX),
                u8::from(right.wireless),
                &right.name,
            ))
    });

    let first = usable[0];
    let reason = match (first.default_route_metric.is_some(), first.wireless) {
        (true, false) => SelectionReason::WiredDefaultRoute,
        (true, true) => SelectionReason::WirelessDefaultRoute,
        (false, false) => SelectionReason::WiredCarrierOnly,
        (false, true) => SelectionReason::WirelessCarrierOnly,
    };

    let mut warnings = warnings_for(first, &usable);
    if first.default_route_metric.is_none() {
        warnings.push(format!(
            "no default route on any interface yet: « {} » leads on carrier alone. Every uplink \
             below is permitted, so the firewall will not be what blocks the one the kernel \
             finally picks",
            first.name
        ));
    }

    Ok(Selection {
        interfaces: usable.iter().map(|facts| facts.name.clone()).collect(),
        reason,
        warnings,
    })
}

/// What the operator would otherwise have to work out from `ip route`.
fn warnings_for(chosen: &InterfaceFacts, usable: &[&InterfaceFacts]) -> Vec<String> {
    let mut warnings = Vec::new();
    if !chosen.wireless {
        return warnings;
    }
    // A cable is in, and the kernel still prefers the radio. That is a routing
    // preference, and routing is not configured here — but nothing else on the
    // box is going to point at it either.
    for wired in usable.iter().filter(|facts| !facts.wireless) {
        warnings.push(match wired.default_route_metric {
            Some(metric) => format!(
                "« {} » is wired and routed (metric {metric}) but the kernel prefers « {} » \
                 (metric {}): both are permitted, but the traffic takes the second. The \
                 preference lives in the routing metrics, not here",
                wired.name,
                chosen.name,
                chosen.default_route_metric.unwrap_or(u32::MAX)
            ),
            None => format!(
                "« {} » is wired and has carrier but the kernel routes nothing through it: the \
                 cable is in a socket that gives no route",
                wired.name
            ),
        });
    }
    warnings
}

/// Reads the facts from `/sys` and `/proc`, then selects.
pub fn resolve() -> Result<Selection, UplinkError> {
    select(&observe(Path::new("/sys/class/net"), Path::new("/proc"))?)
}

/// Gathers what the kernel exposes about every interface.
///
/// Paths are parameters so the reading is exercised against a fixture rather
/// than against whatever this machine happens to have plugged in.
pub fn observe(sys_class_net: &Path, proc_dir: &Path) -> std::io::Result<Vec<InterfaceFacts>> {
    let routes = default_route_metrics(proc_dir);
    let mut facts = Vec::new();
    let Ok(entries) = std::fs::read_dir(sys_class_net) else {
        return Ok(facts);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        facts.push(InterfaceFacts {
            physical: path.join("device").exists(),
            wireless: path.join("phy80211").exists() || path.join("wireless").exists(),
            // `carrier` is unreadable while the interface is administratively
            // down, and that reads the same as no carrier — which it is, for
            // our purposes: nothing leaves through a down interface.
            carrier: read_trimmed(&path.join("carrier")).as_deref() == Some("1"),
            default_route_metric: routes.get(&name).copied(),
            name,
        });
    }
    facts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(facts)
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

/// Lowest default-route metric per interface, IPv4 and IPv6 together.
///
/// `/proc/net/route` and `/proc/net/ipv6_route` rather than a netlink dump:
/// the answer is one line each, the format has been stable for decades, and
/// this runs once at startup. A default route is the one whose destination is
/// all zeros — with a zero prefix length on IPv6, since `::/0` and a host
/// route to `::` are not the same thing.
fn default_route_metrics(proc_dir: &Path) -> BTreeMap<String, u32> {
    let mut metrics: BTreeMap<String, u32> = BTreeMap::new();
    let mut record = |iface: &str, metric: u32| {
        metrics
            .entry(iface.to_string())
            .and_modify(|known| *known = (*known).min(metric))
            .or_insert(metric);
    };

    if let Ok(table) = std::fs::read_to_string(proc_dir.join("net/route")) {
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask …
            if fields.len() < 7 || fields[1] != "00000000" {
                continue;
            }
            record(fields[0], fields[6].parse().unwrap_or(u32::MAX));
        }
    }

    if let Ok(table) = std::fs::read_to_string(proc_dir.join("net/ipv6_route")) {
        for line in table.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // dst dstlen src srclen nexthop metric refcnt use flags iface
            if fields.len() < 10 {
                continue;
            }
            let (destination, prefix_len, metric, iface) =
                (fields[0], fields[1], fields[5], fields[9]);
            if destination.bytes().any(|byte| byte != b'0') || prefix_len != "00" {
                continue;
            }
            record(iface, u32::from_str_radix(metric, 16).unwrap_or(u32::MAX));
        }
    }
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, wireless: bool, carrier: bool, metric: Option<u32>) -> InterfaceFacts {
        InterfaceFacts {
            name: name.into(),
            physical: true,
            wireless,
            carrier,
            default_route_metric: metric,
        }
    }

    fn virtual_iface(name: &str) -> InterfaceFacts {
        InterfaceFacts {
            name: name.into(),
            physical: false,
            wireless: false,
            carrier: true,
            default_route_metric: Some(0),
        }
    }

    /// The case this exists for: a cable and a radio, both routed, and the
    /// usual metrics. The cable wins — and it wins because the kernel already
    /// prefers it, which is what makes the choice safe.
    #[test]
    fn a_routed_cable_beats_a_routed_radio() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(600)),
            iface("eth0", false, true, Some(100)),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "eth0");
        assert_eq!(chosen.reason, SelectionReason::WiredDefaultRoute);
        assert!(chosen.warnings.is_empty());
    }

    /// Equal metrics is the only place the medium overrides anything, and it
    /// overrides nothing the kernel had decided.
    #[test]
    fn the_medium_breaks_a_tie() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(100)),
            iface("eth0", false, true, Some(100)),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "eth0");
    }

    /// The kernel prefers the radio despite a routed cable. We follow it —
    /// naming the wired interface, both metrics and where the preference is
    /// actually set. Picking the cable here would drop every packet the kernel
    /// sends out the radio.
    #[test]
    fn a_kernel_that_prefers_the_radio_is_followed_and_reported() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(50)),
            iface("eth0", false, true, Some(300)),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "wlan0");
        assert_eq!(chosen.reason, SelectionReason::WirelessDefaultRoute);
        let warning = chosen.warnings.join(" ");
        assert!(warning.contains("eth0"), "the wired interface is named");
        assert!(
            warning.contains("300") && warning.contains("50"),
            "as are both metrics"
        );
    }

    /// A cable in a socket that gives no route, while the radio does. Said
    /// plainly, because `ip route` is the only other place it shows.
    #[test]
    fn a_cable_with_carrier_and_no_route_is_reported() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(600)),
            iface("eth0", false, true, None),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "wlan0");
        assert!(chosen.warnings.join(" ").contains("no route"));
    }

    /// Before DHCP answers nothing is routed, and the medium is all there is.
    /// The wired link wins outright, and the choice says it was made blind.
    #[test]
    fn before_any_route_exists_the_cable_wins_outright() {
        let chosen = select(&[
            iface("wlan0", true, true, None),
            iface("eth0", false, true, None),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "eth0");
        assert_eq!(chosen.reason, SelectionReason::WiredCarrierOnly);
        assert!(chosen.warnings.join(" ").contains("carrier alone"));
    }

    /// A cable that is unplugged is not an uplink, however wired it is.
    #[test]
    fn a_wired_interface_without_carrier_is_not_chosen() {
        let chosen = select(&[
            iface("eth0", false, false, None),
            iface("wlan0", true, true, Some(600)),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "wlan0");
    }

    /// Virtual interfaces are never uplinks — `docker0` holds a route and a
    /// carrier, and choosing it would masquerade the whole tunnel into a
    /// bridge.
    #[test]
    fn virtual_interfaces_are_never_uplinks() {
        let chosen = select(&[
            virtual_iface("docker0"),
            virtual_iface("helios0"),
            iface("eth0", false, true, Some(100)),
        ])
        .expect("select");
        assert_eq!(chosen.preferred(), "eth0");
    }

    /// Nothing plugged in anywhere is an error naming what was seen, never a
    /// guess: a wrong `wan_iface` is a gateway that drops its own egress.
    #[test]
    fn no_carrier_anywhere_is_an_error_that_names_the_candidates() {
        let error = select(&[
            iface("eth0", false, false, None),
            iface("wlan0", true, false, None),
        ])
        .expect_err("no carrier");
        let text = error.to_string();
        assert!(text.contains("eth0") && text.contains("wlan0"));
    }

    /// A machine with no physical interface at all is a different failure, and
    /// deserves a different sentence.
    #[test]
    fn a_machine_without_a_physical_interface_says_so() {
        assert!(matches!(
            select(&[virtual_iface("lo")]),
            Err(UplinkError::NoPhysicalInterface)
        ));
    }

    /// The reading, against a sysfs and a procfs built by hand: the markers
    /// are what a Wi-Fi interface is told apart by, and the ARPHRD type is not
    /// one of them.
    #[test]
    fn the_kernel_markers_are_read_as_the_kernel_writes_them() {
        let root = tempfile::tempdir().expect("temp dir");
        let net = root.path().join("sys/class/net");
        let proc = root.path().join("proc");
        std::fs::create_dir_all(proc.join("net")).expect("proc");

        for (name, physical, wireless, carrier) in [
            ("eth0", true, false, "1"),
            ("wlan0", true, true, "1"),
            ("docker0", false, false, "0"),
            ("lo", false, false, "1"),
        ] {
            let path = net.join(name);
            std::fs::create_dir_all(&path).expect("iface");
            std::fs::write(path.join("carrier"), carrier).expect("carrier");
            // Both a Wi-Fi and an Ethernet card report ARPHRD type 1; only the
            // `phy80211` link tells them apart.
            std::fs::write(path.join("type"), "1").expect("type");
            if physical {
                std::fs::create_dir_all(path.join("device")).expect("device");
            }
            if wireless {
                std::fs::create_dir_all(path.join("phy80211")).expect("phy80211");
            }
        }
        std::fs::write(
            proc.join("net/route"),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t0104A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             wlan0\t00000000\t0104A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t0004A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
        )
        .expect("route");

        let facts = observe(&net, &proc).expect("observe");
        let by_name: BTreeMap<&str, &InterfaceFacts> = facts
            .iter()
            .map(|facts| (facts.name.as_str(), facts))
            .collect();

        assert!(by_name["eth0"].physical && !by_name["eth0"].wireless);
        assert!(by_name["wlan0"].physical && by_name["wlan0"].wireless);
        assert!(!by_name["docker0"].physical, "a bridge is not an uplink");
        assert!(!by_name["lo"].physical);
        assert_eq!(by_name["eth0"].default_route_metric, Some(100));
        assert_eq!(by_name["wlan0"].default_route_metric, Some(600));

        let chosen = select(&facts).expect("select");
        assert_eq!(chosen.preferred(), "eth0");
        assert_eq!(chosen.reason, SelectionReason::WiredDefaultRoute);
    }

    /// An IPv6-only uplink is routed too, and its metric is hexadecimal.
    #[test]
    fn an_ipv6_default_route_counts() {
        let root = tempfile::tempdir().expect("temp dir");
        let net = root.path().join("sys/class/net");
        let proc = root.path().join("proc");
        std::fs::create_dir_all(proc.join("net")).expect("proc");
        let path = net.join("eth0");
        std::fs::create_dir_all(path.join("device")).expect("iface");
        std::fs::write(path.join("carrier"), "1").expect("carrier");

        std::fs::write(
            proc.join("net/ipv6_route"),
            // A host route to `::` is not a default route; `::/0` is.
            "00000000000000000000000000000000 80 00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00000400 00000000 00000000 00000001 eth0\n\
             00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
             fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0\n",
        )
        .expect("ipv6 route");

        let facts = observe(&net, &proc).expect("observe");
        assert_eq!(facts[0].default_route_metric, Some(0x400));
    }
    /// The point of the whole change: both links are permitted, so the
    /// firewall is not what breaks a failover. The order says which one the
    /// traffic takes; the list says which ones are allowed to.
    #[test]
    fn both_links_are_permitted_and_the_cable_leads() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(600)),
            iface("eth0", false, true, Some(100)),
        ])
        .expect("select");
        assert_eq!(chosen.interfaces, vec!["eth0", "wlan0"]);
    }

    /// The cable is unplugged: its rule disappears with it, the radio leads,
    /// and nothing had to be restarted for the radio's rule to exist — it was
    /// already there.
    #[test]
    fn losing_the_cable_leaves_the_radio_permitted() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(600)),
            iface("eth0", false, false, None),
        ])
        .expect("select");
        assert_eq!(chosen.interfaces, vec!["wlan0"]);
        assert_eq!(chosen.reason, SelectionReason::WirelessDefaultRoute);
    }

    /// A link waiting for its lease is permitted too. Refusing it would mean
    /// the firewall drops the very first DHCP exchange that would have given
    /// it a route — and the interface could never become usable.
    #[test]
    fn a_link_without_a_route_is_still_permitted() {
        let chosen = select(&[
            iface("wlan0", true, true, Some(600)),
            iface("eth0", false, true, None),
        ])
        .expect("select");
        assert!(chosen.interfaces.contains(&"eth0".to_string()));
        assert_eq!(
            chosen.preferred(),
            "wlan0",
            "but the traffic takes the routed one"
        );
    }

    /// The order never depends on the order sysfs was read in: two interfaces
    /// that tie on metric and medium sort by name, so a ruleset is the same
    /// from one boot to the next.
    #[test]
    fn the_order_is_stable_across_readings() {
        let facts = vec![
            iface("eth1", false, true, Some(100)),
            iface("eth0", false, true, Some(100)),
        ];
        let forwards = select(&facts).expect("select");
        let mut backwards = facts;
        backwards.reverse();
        assert_eq!(
            forwards.interfaces,
            select(&backwards).expect("select").interfaces
        );
        assert_eq!(forwards.interfaces, vec!["eth0", "eth1"]);
    }
}
