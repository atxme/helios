//! Keeps the key-negotiation socket off the tunnel it is about to establish.
//!
//! # The failure this exists for
//!
//! The negotiation session is opened **before** the WireGuard interface comes
//! up, and has to survive it: the confirmation is only sent once a fresh
//! handshake has been observed, and the connection then becomes the liveness
//! link held for the tunnel's whole lifetime.
//!
//! In between, the interface captures `AllowedIPs`. On Windows that means a
//! `0.0.0.0/0` route on the tunnel with interface metric 0, installed by
//! `wireguard_nt::Adapter::set_default_route` — and **no `/32` exclusion for
//! the gateway endpoint**, because `defguard_wireguard_rs::wgapi_windows`
//! implements `configure_peer_routing` as a no-op. WireGuard-NT avoids the
//! routing loop for its own socket, inside the driver; no other socket in the
//! system benefits from that.
//!
//! A socket bound to `0.0.0.0` therefore changes egress interface underneath
//! the live session: its source address flips from the physical address to the
//! tunnel VIP, and the gateway sees a QUIC **connection migration** in the
//! middle of a transaction. The confirmation is lost, the gateway holds the
//! peer until its 45 s timeout, and every retry inside that window is refused.
//!
//! # Why pinning rather than a route exclusion
//!
//! Adding a `/32` route for the gateway through the physical default gateway —
//! what `wg-quick` does — would work too, but it mutates global routing state
//! that then has to be torn down on every exit path, crash included. Pinning
//! touches nothing outside our own socket.
//!
//! It is also the architecturally correct answer: the liveness link must not
//! ride inside the tunnel it is there to watch, or it stops measuring anything
//! independent of it.
//!
//! # Limite connue
//!
//! Only Windows is pinned. Elsewhere the socket is returned bound as-is, which
//! is correct for the dry-run backend and unverified for a Linux Orion — a
//! configuration that is a development target, not a shipped one. Pinning
//! there would go through `SO_BINDTODEVICE`, and would need a Linux client
//! actually mounting a tunnel to be worth anything.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use anyhow::{Context, Result};

/// Name of the WireGuard interface Orion creates.
///
/// Lives here rather than in the backend because the pinning needs it on
/// builds that carry no WireGuard backend at all: the negotiation is not a
/// compile-time feature, so the socket it opens must be able to name the
/// interface it has to avoid.
pub const TUNNEL_IFNAME: &str = "orion0";

/// Opens the UDP socket carrying a key negotiation towards `remote`.
///
/// The returned socket is bound to the wildcard address of `remote`'s family
/// and, where the platform allows it, forced onto the interface that reaches
/// `remote` **without** crossing `tunnel_ifname`.
pub fn negotiation_socket(remote: SocketAddr, tunnel_ifname: &str) -> Result<UdpSocket> {
    let bind = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind)
        .with_context(|| format!("binding the key-negotiation socket on {bind}"))?;
    pin_to_off_tunnel_interface(&socket, remote, tunnel_ifname)?;
    Ok(socket)
}

/// Compares the first `prefix_len` bits of two addresses.
///
/// Lives outside the Windows module, and is the only piece of this file the
/// regression can execute: everything else is a Win32 call. A longest-prefix
/// match that quietly mishandles a partial byte would pin the socket to the
/// wrong interface, which is indistinguishable from the bug being fixed.
#[cfg(any(windows, test))]
fn matches_prefix(address: &[u8], prefix: &[u8], prefix_len: u8) -> bool {
    let full = (prefix_len / 8) as usize;
    if address.len() < full || prefix.len() < full {
        return false;
    }
    if address[..full] != prefix[..full] {
        return false;
    }
    let remainder = prefix_len % 8;
    if remainder == 0 {
        return true;
    }
    if address.len() <= full || prefix.len() <= full {
        return false;
    }
    let mask = 0xffu8 << (8 - remainder);
    address[full] & mask == prefix[full] & mask
}

#[cfg(not(windows))]
fn pin_to_off_tunnel_interface(
    _socket: &UdpSocket,
    _remote: SocketAddr,
    _tunnel_ifname: &str,
) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn pin_to_off_tunnel_interface(
    socket: &UdpSocket,
    remote: SocketAddr,
    tunnel_ifname: &str,
) -> Result<()> {
    use std::os::windows::io::AsRawSocket as _;

    let tunnel = windows_impl::interface_index(tunnel_ifname);
    let Some(chosen) = windows_impl::best_interface_avoiding(remote.ip(), tunnel)? else {
        // No route to the gateway that avoids the tunnel. Refusing here would
        // turn a reconnection into a hard failure on a machine whose only
        // route genuinely is the tunnel; the negotiation is left to try, and
        // the transport error that follows names the endpoint.
        tracing::warn!(
            %remote,
            tunnel = %tunnel_ifname,
            "key negotiation: no off-tunnel route to the gateway — the socket stays unpinned"
        );
        return Ok(());
    };
    windows_impl::set_unicast_interface(socket.as_raw_socket(), remote.ip(), chosen)
        .with_context(|| format!("pinning the key-negotiation socket to interface {chosen}"))?;
    tracing::info!(
        %remote,
        interface_index = chosen,
        tunnel = %tunnel_ifname,
        tunnel_interface_index = ?tunnel,
        "key negotiation: socket pinned off-tunnel"
    );
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use std::net::IpAddr;

    use anyhow::{anyhow, Result};
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, FreeMibTable,
            GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
        },
        Networking::WinSock::{setsockopt, AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, SOCKET},
    };

    /// `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, absent from `windows-sys`.
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;

    /// Interface index of an adapter designated by its alias, if it exists.
    ///
    /// Absent is a normal answer, not a failure: on the very first connection
    /// the tunnel adapter has never been created, and there is then nothing to
    /// avoid.
    pub fn interface_index(alias: &str) -> Option<u32> {
        let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = unsafe { std::mem::zeroed() };
        if unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) } != 0 {
            return None;
        }
        let mut index = 0u32;
        if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != 0 {
            return None;
        }
        Some(index)
    }

    /// Best route to `destination` among those not carried by `avoided`.
    ///
    /// Longest prefix first, then lowest metric — the kernel's own order, minus
    /// the interface we refuse to use. A longest-prefix match rather than
    /// "pick the default route": a gateway reached over the LAN, which is the
    /// ordinary home setup behind a port forward, is on-link and has no
    /// default route to be found under.
    pub fn best_interface_avoiding(
        destination: IpAddr,
        avoided: Option<u32>,
    ) -> Result<Option<u32>> {
        let family = match destination {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIpForwardTable2(family, &mut table) };
        if status != 0 || table.is_null() {
            return Err(anyhow!("GetIpForwardTable2 failed with status {status}"));
        }
        // The table is owned by the OS from here on: every exit path below has
        // to reach the `FreeMibTable` at the end, so the loop only computes.
        let mut best: Option<(u8, u32, u32)> = None;
        unsafe {
            let rows =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for row in rows {
                if Some(row.InterfaceIndex) == avoided {
                    continue;
                }
                let prefix_len = row.DestinationPrefix.PrefixLength;
                if !covers(destination, &row.DestinationPrefix.Prefix, prefix_len) {
                    continue;
                }
                let candidate = (prefix_len, row.Metric, row.InterfaceIndex);
                let better = match best {
                    None => true,
                    // Longer prefix wins; at equal length, lower metric wins.
                    Some((length, metric, _)) => {
                        prefix_len > length || (prefix_len == length && row.Metric < metric)
                    }
                };
                if better {
                    best = Some(candidate);
                }
            }
            FreeMibTable(table.cast());
        }
        Ok(best.map(|(_, _, index)| index))
    }

    /// `true` if `destination` falls inside the prefix carried by `raw`.
    unsafe fn covers(
        destination: IpAddr,
        raw: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET,
        prefix_len: u8,
    ) -> bool {
        match destination {
            IpAddr::V4(address) => {
                if unsafe { raw.si_family } != AF_INET {
                    return false;
                }
                let prefix = unsafe { raw.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
                super::matches_prefix(&address.octets(), &prefix, prefix_len)
            }
            IpAddr::V6(address) => {
                if unsafe { raw.si_family } != AF_INET6 {
                    return false;
                }
                let prefix = unsafe { raw.Ipv6.sin6_addr.u.Byte };
                super::matches_prefix(&address.octets(), &prefix, prefix_len)
            }
        }
    }

    /// Forces every packet of this socket out of `index`, routing table aside.
    pub fn set_unicast_interface(socket: u64, destination: IpAddr, index: u32) -> Result<()> {
        let (level, option, value) = match destination {
            // Documented Windows quirk: the IPv4 option takes the index in
            // **network** byte order, the IPv6 one in host order. Getting this
            // wrong silently pins to an interface that does not exist, and the
            // socket then sends nowhere at all.
            IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF, index.to_be()),
            IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF, index),
        };
        let raw = value.to_ne_bytes();
        let status = unsafe {
            setsockopt(
                socket as SOCKET,
                level,
                option,
                raw.as_ptr(),
                raw.len() as i32,
            )
        };
        if status != 0 {
            return Err(anyhow!(
                "setsockopt(UNICAST_IF) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::matches_prefix;
    #[cfg(windows)]
    use super::negotiation_socket;
    #[cfg(windows)]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn prefix_comparison_accepts_the_default_route() {
        // A `/0` matches everything. It has to stay a candidate: on a gateway
        // reached over the internet, the default route is the only route that
        // covers it, and skipping it would leave the socket unpinned.
        assert!(matches_prefix(&[192, 168, 1, 44], &[0, 0, 0, 0], 0));
        assert!(matches_prefix(&[86, 229, 12, 86], &[0, 0, 0, 0], 0));
    }

    #[test]
    fn prefix_comparison_handles_whole_bytes() {
        // The on-link case: a gateway on the LAN behind a port forward, which
        // has no default route above it to be found under.
        assert!(matches_prefix(&[192, 168, 1, 44], &[192, 168, 1, 0], 24));
        assert!(!matches_prefix(&[192, 168, 2, 44], &[192, 168, 1, 0], 24));
        assert!(matches_prefix(&[10, 4, 0, 1], &[10, 0, 0, 0], 8));
    }

    #[test]
    fn prefix_comparison_handles_partial_bytes() {
        // `/28` keeps the four high bits of the last byte. Comparing whole
        // bytes only would accept the whole `/24` and pin to a route that
        // does not actually cover the gateway.
        assert!(matches_prefix(&[10, 0, 0, 20], &[10, 0, 0, 16], 28));
        assert!(!matches_prefix(&[10, 0, 0, 40], &[10, 0, 0, 16], 28));
        // A host route is the longest possible match and must stay exact.
        assert!(matches_prefix(&[86, 229, 12, 86], &[86, 229, 12, 86], 32));
        assert!(!matches_prefix(&[86, 229, 12, 87], &[86, 229, 12, 86], 32));
    }

    #[test]
    fn prefix_comparison_refuses_a_prefix_longer_than_the_address() {
        // A malformed table row must not index out of bounds: this runs on
        // whatever the OS hands back, and a panic here would take the
        // negotiation down with it.
        assert!(!matches_prefix(&[10, 0, 0, 1], &[10, 0, 0, 1], 64));
        assert!(!matches_prefix(&[10, 0, 0, 1], &[10, 0], 24));
        assert!(!matches_prefix(&[10], &[10], 9));
        assert!(!matches_prefix(&[10, 1], &[11, 1], 9));
    }

    #[cfg(windows)]
    #[test]
    fn negotiation_socket_uses_the_remote_address_family() {
        let socket = negotiation_socket(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            "orion-adapter-that-does-not-exist",
        )
        .unwrap();

        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    #[cfg(windows)]
    #[test]
    fn windows_route_lookup_handles_absent_and_avoided_interfaces() {
        assert_eq!(
            super::windows_impl::interface_index("orion-adapter-that-does-not-exist"),
            None
        );
        let route =
            super::windows_impl::best_interface_avoiding(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                .unwrap();
        let avoided = route.expect("Windows must have a route to its loopback");
        let alternative = super::windows_impl::best_interface_avoiding(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(avoided),
        )
        .unwrap();
        assert_ne!(alternative, Some(avoided));
    }
}
