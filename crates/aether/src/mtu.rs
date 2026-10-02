//! WireGuard tunnel MTU computation.
//!
//! WireGuard defaults to 1420, which assumes a 1500-byte transport. As soon
//! as the link carrying the tunnel is narrower — WSL2 at 1280, PPPoE at
//! 1492, IPv6 tunnels, mobile networks — encrypted packets exceed the
//! transport MTU and are **silently dropped**.
//!
//! The symptom is misleading: the handshake goes through (small packets),
//! short requests too, and only large ones disappear — an ML-KEM
//! ciphertext, for example. The diagnosis then looks like an application
//! failure.
//!
//! # Why the computation lives here
//!
//! Both ends need it and must agree: the gateway for its interface, Orion
//! for its own. Sharing it avoids two arithmetics that diverge.
//!
//! # What this module does not solve
//!
//! WireGuard's MTU is **per interface, not per peer**. Since the gateway has
//! only one interface for all its clients, it cannot serve a different MTU
//! to each: it takes a value derived from its WAN, and clients whose path is
//! narrower fall under MSS clamping (TCP) or PMTUD (UDP). On the client
//! side, however, an interface carries only one peer: the MTU there is
//! therefore exactly that of the path.
//!
//! Jumbo frames are not handled: a jumbo frame only exists if *every* hop
//! accepts it, which excludes a road-warrior client reaching the gateway
//! over the Internet, where the PMTU is in practice ≤ 1500.

/// WireGuard encapsulation overhead, in bytes.
///
/// Breakdown: IPv6 header (40) + UDP (8) + WireGuard header (16) + Poly1305
/// tag (16). In IPv4 the header is only 20 bytes, i.e. 60 in total.
///
/// We systematically keep the IPv6 case, the costlier one. Distinguishing
/// the two families would gain 20 bytes of payload, at the cost of a
/// decision made at runtime based on the peer's address — getting it wrong
/// costs a tunnel that silently loses its large packets, which is not worth
/// it.
pub const SURCOUT_WIREGUARD: u32 = 80;

/// Floor MTU, in bytes.
///
/// 576 is the minimum an IPv4 host must accept (RFC 791). A floor at 1280 —
/// the IPv6 minimum — would here be counterproductive: on a transport
/// already at 1280, it would cancel out the computation and reproduce
/// exactly the failure this module fixes.
pub const MTU_PLANCHER: u32 = 576;

/// Default MTU of a transport whose value could not be read.
pub const MTU_TRANSPORT_DEFAUT: u32 = 1500;

/// Smallest MTU a link must offer to carry IPv6 (RFC 8200 §5).
///
/// Unlike [`MTU_PLANCHER`], this is not a floor the computation applies: a
/// tunnel narrower than this still carries IPv4. Linux removes IPv6 from an
/// interface whose MTU drops below it, so the gateway does not install its
/// IPv6 tunnel address on such an interface (`ADRESSAGE-IPV6.md` §6.2).
pub const MTU_MIN_IPV6: u32 = 1280;

/// Whether a tunnel of this MTU can carry IPv6.
///
/// ```
/// use aether::mtu::{carries_ipv6, tunnel_mtu};
/// assert!(carries_ipv6(tunnel_mtu(1500)));
/// assert!(!carries_ipv6(tunnel_mtu(1280))); // WSL2: IPv4 only
/// ```
pub fn carries_ipv6(tunnel_mtu: u32) -> bool {
    tunnel_mtu >= MTU_MIN_IPV6
}

/// IPv4 (20) and TCP (20) headers without options, in bytes.
pub const TCP_IPV4_HEADERS: u32 = 40;

/// IPv6 (40) and TCP (20) headers without options, in bytes.
pub const TCP_IPV6_HEADERS: u32 = 60;

/// MSS of TCP over IPv4 inside a tunnel of this MTU.
///
/// The argument is the **tunnel** MTU — what [`tunnel_mtu`] returns and the
/// interface carries — not the transport's: the WireGuard overhead is already
/// out of it. Saturates at `u16::MAX`, the largest MSS TCP can announce.
///
/// ```
/// use aether::mtu::{mss_ipv4, tunnel_mtu};
/// assert_eq!(mss_ipv4(tunnel_mtu(1500)), 1380);
/// ```
pub fn mss_ipv4(tunnel_mtu: u32) -> u16 {
    saturate_mss(tunnel_mtu.saturating_sub(TCP_IPV4_HEADERS))
}

/// MSS of TCP over IPv6 inside a tunnel of this MTU, or `None` when the
/// tunnel cannot carry IPv6 at all ([`carries_ipv6`]).
///
/// Twenty bytes below [`mss_ipv4`]: an IPv6 header is 40 bytes, not 20.
/// Reusing the IPv4 value for IPv6 would announce segments 20 bytes too large
/// for the tunnel.
///
/// ```
/// use aether::mtu::{mss_ipv6, tunnel_mtu};
/// assert_eq!(mss_ipv6(tunnel_mtu(1500)), Some(1360));
/// assert_eq!(mss_ipv6(tunnel_mtu(1280)), None); // WSL2: IPv4 only
/// ```
pub fn mss_ipv6(tunnel_mtu: u32) -> Option<u16> {
    carries_ipv6(tunnel_mtu).then(|| saturate_mss(tunnel_mtu - TCP_IPV6_HEADERS))
}

fn saturate_mss(mss: u32) -> u16 {
    u16::try_from(mss).unwrap_or(u16::MAX)
}

/// MTU to set on the WireGuard interface, derived from the MTU of the link
/// carrying it.
///
/// ```
/// use aether::mtu::tunnel_mtu;
/// assert_eq!(tunnel_mtu(1500), 1420); // Ethernet: the usual value
/// assert_eq!(tunnel_mtu(1280), 1200); // WSL2: where the default fails
/// ```
pub fn tunnel_mtu(mtu_transport: u32) -> u32 {
    mtu_transport
        .saturating_sub(SURCOUT_WIREGUARD)
        .max(MTU_PLANCHER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ethernet_case_gives_the_usual_value() {
        // 1420 is WireGuard's default: on a transport at 1500, the
        // computation must fall back to it, otherwise it changes nominal
        // behavior.
        assert_eq!(tunnel_mtu(1500), 1420);
    }

    #[test]
    fn a_narrow_transport_is_reduced_and_not_floored_at_1280() {
        // Non-regression of the bug observed on target: a floor at 1280
        // would have left 1280 here, i.e. exactly the transport's MTU —
        // hence encrypted packets systematically too large.
        assert_eq!(tunnel_mtu(1280), 1200);
        assert!(tunnel_mtu(1280) < 1280);
    }

    #[test]
    fn the_overhead_covers_the_measurement_on_hardware() {
        // Measured on target, transport at 1280: 1220 passes, 1221 fails.
        // The real IPv4 overhead is therefore 60 bytes, and the chosen value
        // must stay under this limit to also cover IPv6.
        let measured_ipv4_limit = 1280 - 60;
        assert!(tunnel_mtu(1280) <= measured_ipv4_limit);
    }

    #[test]
    fn ipv6_needs_a_transport_of_at_least_1360_bytes() {
        // 1360 − 80 = 1280, the IPv6 minimum: one byte less and the tunnel
        // is IPv4-only.
        assert!(carries_ipv6(tunnel_mtu(1360)));
        assert!(!carries_ipv6(tunnel_mtu(1359)));
        assert!(carries_ipv6(tunnel_mtu(1492)), "PPPoE still carries IPv6");
    }

    #[test]
    fn the_mss_depends_on_the_inner_family() {
        // Ethernet: 1420 in the tunnel, 1380 over IPv4, 1360 over IPv6.
        let mtu = tunnel_mtu(1500);
        assert_eq!(mss_ipv4(mtu), 1380);
        assert_eq!(mss_ipv6(mtu), Some(1360));
        assert_eq!(
            u32::from(mss_ipv4(mtu)) - u32::from(mss_ipv6(mtu).unwrap()),
            20,
            "the IPv6 header is 20 bytes larger"
        );
    }

    #[test]
    fn a_full_segment_fills_the_tunnel_exactly() {
        // MSS + headers = tunnel MTU, for both families: one byte more and
        // the segment no longer fits in the interface.
        for transport in [1360, 1492, 1500, 9000] {
            let mtu = tunnel_mtu(transport);
            assert_eq!(u32::from(mss_ipv4(mtu)) + TCP_IPV4_HEADERS, mtu);
            assert_eq!(u32::from(mss_ipv6(mtu).unwrap()) + TCP_IPV6_HEADERS, mtu);
        }
    }

    #[test]
    fn no_ipv6_mss_below_the_ipv6_minimum() {
        // The threshold is the one `carries_ipv6` applies, on the tunnel MTU.
        assert_eq!(mss_ipv6(MTU_MIN_IPV6), Some(1220));
        assert_eq!(mss_ipv6(MTU_MIN_IPV6 - 1), None);
        assert_eq!(mss_ipv6(tunnel_mtu(1280)), None);
        // IPv4 still has one there.
        assert_eq!(mss_ipv4(tunnel_mtu(1280)), 1160);
    }

    #[test]
    fn the_floor_mtu_gives_the_classic_ipv4_mss() {
        // 576 − 40 = 536, the default MSS of RFC 879.
        assert_eq!(mss_ipv4(tunnel_mtu(0)), 536);
        assert_eq!(mss_ipv6(tunnel_mtu(0)), None);
    }

    #[test]
    fn the_mss_saturates_instead_of_wrapping() {
        assert_eq!(mss_ipv4(0), 0);
        assert_eq!(mss_ipv4(u32::MAX), u16::MAX);
        assert_eq!(mss_ipv6(u32::MAX), Some(u16::MAX));
    }

    #[test]
    fn pppoe_is_accounted_for() {
        assert_eq!(tunnel_mtu(1492), 1412);
    }

    #[test]
    fn an_absurd_transport_does_not_overflow() {
        assert_eq!(tunnel_mtu(0), MTU_PLANCHER);
        assert_eq!(tunnel_mtu(10), MTU_PLANCHER);
    }

    #[test]
    fn a_local_jumbo_frame_is_passed_through_uncapped() {
        // Gateway and client on the same jumbo LAN: the computation must not
        // cap what the link actually allows.
        assert_eq!(tunnel_mtu(9000), 8920);
    }
}
