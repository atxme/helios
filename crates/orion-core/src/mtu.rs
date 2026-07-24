//! MTU of the link carrying the tunnel, on the client side.
//!
//! The computation itself lives in [`aether::mtu`], shared with the gateway.
//! This module only provides the input: the transport's MTU.
//!
//! # Why the client, and not just the gateway
//!
//! WireGuard's MTU is **per interface**. Since the gateway only has one for
//! all its clients, it can't serve a different value to each. On the client
//! side, however, an interface only carries one peer: its MTU can therefore
//! hug the path exactly. This is what makes a machine on a 1500 link and
//! another on a 1280 link simultaneously functional, without configuration.
//!
//! # Known limitation: Linux only
//!
//! Detection relies on `/proc/net/route` and `/sys/class/net`, absent
//! elsewhere. On Windows and macOS, [`mtu_transport`] returns `None` and the
//! backend keeps WireGuard's default (1420) — the behavior before this
//! module, correct as long as the transport is at 1500, and falling short
//! below that.
//!
//! What would unblock these platforms: `GetIfEntry2` on Windows,
//! `getifaddrs` on macOS, or an interface-enumeration dependency. None is in
//! the workspace today, and none is verifiable from the Linux test target —
//! adding it without being able to exercise it would shift the risk without
//! reducing it.

/// MTU of the link carrying the default route, or `None` if undeterminable.
///
/// The default route is the right reference for a road-warrior client: its
/// gateway is remote, hence reachable through it. A deployment where the
/// gateway is on the LAN would take a connected route, but its MTU is then
/// that of the same physical interface.
pub fn mtu_transport() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let iface = default_route_iface(&table)?;
        let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu")).ok()?;
        raw.trim().parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Interface carrying the default route, extracted from `/proc/net/route`.
///
/// The format is tabular: `Iface Destination Gateway Flags …`, addresses in
/// little-endian hexadecimal. The default route is the one whose
/// destination is zero.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn default_route_iface(table: &str) -> Option<&str> {
    table
        .lines()
        .skip(1) // header line
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let destination = fields.next()?;
            // `u32::from_str_radix` rather than a comparison to "00000000":
            // the kernel may zero-pad differently depending on the version.
            (u32::from_str_radix(destination, 16).ok()? == 0).then_some(iface)
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t01004E0A\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00004E0A\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0";

    #[test]
    fn the_default_route_is_recognized() {
        assert_eq!(default_route_iface(TABLE), Some("eth0"));
    }

    #[test]
    fn a_table_without_a_default_route_returns_nothing() {
        let no_default = "Iface\tDestination\tGateway\n\
             eth0\t00004E0A\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0";
        assert_eq!(default_route_iface(no_default), None);
    }

    #[test]
    fn the_first_default_route_wins() {
        // Several defaults coexist when two links are up; the kernel orders
        // them by increasing metric, so the first one is the active one.
        let two = "Iface\tDestination\tGateway\n\
             wlan0\t00000000\t01004E0A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0";
        assert_eq!(default_route_iface(two), Some("wlan0"));
    }

    #[test]
    fn an_empty_or_truncated_table_does_not_panic() {
        assert_eq!(default_route_iface(""), None);
        assert_eq!(default_route_iface("Iface\tDestination"), None);
        assert_eq!(default_route_iface("Iface\neth0"), None);
        assert_eq!(default_route_iface("Iface\neth0\tPASDELHEXA"), None);
    }
}
