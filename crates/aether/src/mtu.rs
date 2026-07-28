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
