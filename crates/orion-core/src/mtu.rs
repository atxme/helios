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
//! # Which link
//!
//! On Linux, the one carrying the default route (`/proc/net/route`,
//! `/sys/class/net`).
//!
//! On Windows, the one the routing table would pick to reach the gateway's
//! endpoint **without** crossing the tunnel adapter — the same lookup that
//! pins the key-negotiation socket ([`crate::net_pin`]), so the MTU is read
//! on the interface the encrypted packets actually leave through. Avoiding
//! the tunnel matters on a reconnection: its adapter still holds the default
//! route at metric 0, and its own MTU says nothing about the transport. The
//! IP-layer MTU of the endpoint's family is read (`GetIpInterfaceEntry`,
//! `NlMtu`), since a link can carry IPv4 and IPv6 with different values.
//!
//! # Known limitation: macOS
//!
//! [`mtu_transport`] returns `None` there and the backend keeps WireGuard's
//! default (1420) — correct as long as the transport is at 1500, and falling
//! short below that. What would unblock it: `getifaddrs` and the routing
//! socket, written from a macOS target able to exercise them.
//!
//! The Windows path is not exercisable from the Linux test target
//! (`docs/testing/TESTING.md`, Limites connues): only the choice of the
//! reference destination runs here.

use std::net::IpAddr;
#[cfg(any(windows, test))]
use std::net::Ipv4Addr;

/// MTU of the link carrying the tunnel's transport, or `None` if
/// undeterminable.
///
/// `endpoint` is the gateway's address and `tunnel_ifname` the adapter to
/// look past; only Windows uses them (see the module documentation).
///
/// On Linux, the default route is the right reference for a road-warrior
/// client: its gateway is remote, hence reachable through it. A deployment
/// where the gateway is on the LAN would take a connected route, but its MTU
/// is then that of the same physical interface.
pub fn mtu_transport(endpoint: Option<IpAddr>, tunnel_ifname: &str) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let _ = (endpoint, tunnel_ifname);
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let iface = default_route_iface(&table)?;
        let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu")).ok()?;
        raw.trim().parse().ok()
    }
    #[cfg(windows)]
    {
        windows_impl::mtu_towards(reference_destination(endpoint), tunnel_ifname)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (endpoint, tunnel_ifname);
        None
    }
}

/// Destination whose route designates the transport link.
///
/// The endpoint when known — a gateway on the LAN is reached through an
/// on-link route, not the default one. Without it, the unspecified address,
/// which only a `/0` covers: the default route.
#[cfg(any(windows, test))]
fn reference_destination(endpoint: Option<IpAddr>) -> IpAddr {
    endpoint.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

#[cfg(windows)]
mod windows_impl {
    use std::net::IpAddr;

    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
        },
        Networking::WinSock::{AF_INET, AF_INET6},
    };

    use crate::net_pin::windows_impl::{best_interface_avoiding, interface_index};

    /// IP-layer MTU of the interface reaching `destination` off the tunnel.
    pub(super) fn mtu_towards(destination: IpAddr, tunnel_ifname: &str) -> Option<u32> {
        let tunnel = interface_index(tunnel_ifname);
        let index = match best_interface_avoiding(destination, tunnel) {
            Ok(Some(index)) => index,
            Ok(None) => {
                tracing::warn!(
                    %destination,
                    "transport MTU: no off-tunnel route — WireGuard's default MTU is kept"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(
                    %destination,
                    %error,
                    "transport MTU: routing table unreadable — WireGuard's default MTU is kept"
                );
                return None;
            }
        };

        // `InitializeIpInterfaceEntry` first, as documented: it sets every
        // field to its "unspecified" value, after which the family and the
        // index alone designate the row to read.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = match destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        row.InterfaceIndex = index;
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != 0 {
            tracing::warn!(
                interface_index = index,
                status,
                "transport MTU: GetIpInterfaceEntry failed — WireGuard's default MTU is kept"
            );
            return None;
        }
        tracing::info!(
            interface_index = index,
            mtu = row.NlMtu,
            "transport MTU read"
        );
        (row.NlMtu > 0).then_some(row.NlMtu)
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
    fn the_endpoint_designates_the_transport_link() {
        // A gateway on the LAN is reached through its on-link route: looking
        // up the default route instead would read another interface's MTU.
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44));
        assert_eq!(reference_destination(Some(lan)), lan);
        let v6 = "2001:db8::1".parse().unwrap();
        assert_eq!(reference_destination(Some(v6)), v6);
    }

    #[test]
    fn without_an_endpoint_the_default_route_is_the_reference() {
        // Only a `/0` covers the unspecified address.
        assert_eq!(
            reference_destination(None),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn an_empty_or_truncated_table_does_not_panic() {
        assert_eq!(default_route_iface(""), None);
        assert_eq!(default_route_iface("Iface\tDestination"), None);
        assert_eq!(default_route_iface("Iface\neth0"), None);
        assert_eq!(default_route_iface("Iface\neth0\tPASDELHEXA"), None);
    }
}
