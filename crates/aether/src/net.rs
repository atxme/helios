//! Canonical tunnel addresses: the gateway's IPv6 prefix and a peer's VIPs.
//!
//! `network.toml` carries addresses as text (`address = "100.64.98.223/32"`,
//! `wg_address_v6 = "fd3c:91a2:7e04::1/64"`). This module is where that text
//! becomes a typed value, and where the rules of
//! `docs/specification/ADRESSAGE-IPV6.md` (§2.4, §3.2, §5.2) live, so that a
//! value of these types is already one the specification accepts.
//!
//! # What each type guarantees
//!
//! - [`TunnelPrefixV6`]: an ULA `fd00::/8` `/64` with Subnet ID `0000`, whose
//!   host `::1` is the gateway. A `fc00::/8` prefix (L bit clear), a global
//!   prefix, any other length or any other gateway host cannot be built.
//! - [`PeerVips`]: exactly one IPv4 VIP and at most one IPv6 VIP. Two fields
//!   rather than a list, so "no IPv4" and "two IPv6" cannot be written.
//!
//! Whether a peer's IPv6 VIP belongs to the gateway's prefix is a separate
//! check, [`PeerVips::check_against`]: the prefix is gateway configuration,
//! not something a peer's own record carries.
//!
//! [`Ipv6TunnelStatus`] is the other side of the prefix: whether the gateway
//! actually installed it on its data plane, or why not (§6.2).
//!
//! # Representation
//!
//! Hosts are `std::net` addresses. The only prefix arithmetic needed is a
//! fixed `/64` split, done on `u128`; a general CIDR type would accept
//! lengths and host bits that every constructor here then has to refuse
//! again.
//!
//! # Text forms
//!
//! Prefix lengths are read in their canonical decimal form only (`/32`, not
//! `/032` or `/+32`), and an IPv4 host only in dotted decimal without leading
//! zeros, so an accepted IPv4 VIP renders back to the exact text it was read
//! from. IPv6 text is rendered in the RFC 5952 form `std` produces: a
//! hand-written `FD3C:91A2:7E04:0::1/64` is accepted and written back as
//! `fd3c:91a2:7e04::1/64`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Interface identifier of the gateway inside its tunnel prefix (`<prefix>::1`).
pub const GATEWAY_IID: u64 = 1;

/// First interface identifier of the reserved subnet anycast range (RFC 5453).
///
/// The specification excludes every identifier from this one upwards (§3.2),
/// which is wider than RFC 5453 alone; the extra values cost nothing out of
/// 2^64.
pub const FIRST_RESERVED_ANYCAST_IID: u64 = 0xfdff_ffff_ffff_ff80;

/// Mask of the network half of a `/64`.
const NETWORK_MASK: u128 = !(u64::MAX as u128);

/// Every refusal of this module, each naming what was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("`{0}` carries a zone identifier: a tunnel address is not scoped to a link")]
    ZoneId(String),
    #[error("`{0}` is not in address/length form")]
    MissingPrefixLength(String),
    #[error("`{0}` is not a canonical decimal prefix length")]
    InvalidPrefixLength(String),
    #[error("`{0}` is not an IP address")]
    InvalidAddress(String),
    #[error("{0} is an IPv4 address where an IPv6 one is required")]
    NotIpv6(Ipv4Addr),
    #[error("{0} is an IPv6 address where an IPv4 one is required")]
    NotIpv4(Ipv6Addr),
    #[error("prefix length /{found} where /{expected} is required")]
    WrongPrefixLength { expected: u8, found: u8 },
    #[error("{0} is in fc00::/8, whose L bit is clear and which RFC 4193 leaves undefined")]
    UndefinedUla(Ipv6Addr),
    #[error("{0} is not an ULA: the tunnel prefix must be in fd00::/8")]
    NotUla(Ipv6Addr),
    #[error("{0} has a non-zero Subnet ID: the tunnel prefix is fdXX:XXXX:XXXX:0000::/64")]
    NonZeroSubnetId(Ipv6Addr),
    #[error("{0} is not host ::1 of its /64: the gateway is always <prefix>::1")]
    GatewayNotHostOne(Ipv6Addr),
    #[error("peer VIP {vip} is outside the tunnel prefix {prefix}")]
    OutsideTunnelPrefix {
        vip: Ipv6Addr,
        prefix: TunnelPrefixV6,
    },
    #[error("peer VIP {0} is the gateway's own address")]
    GatewayAddress(Ipv6Addr),
    #[error("interface identifier {0:#x} is excluded (subnet-router or reserved anycast)")]
    ExcludedIid(u64),
    #[error("peer VIP {0} declared while the gateway has no IPv6 tunnel prefix")]
    V6WithoutTunnelPrefix(Ipv6Addr),
}

/// Whether an interface identifier may never be a peer's (§3.2).
///
/// `0` is the subnet-router anycast (RFC 4291), `1` the gateway, and
/// everything from [`FIRST_RESERVED_ANYCAST_IID`] up the reserved anycast
/// range (RFC 5453).
pub const fn is_excluded_iid(iid: u64) -> bool {
    iid == 0 || iid == GATEWAY_IID || iid >= FIRST_RESERVED_ANYCAST_IID
}

/// The gateway's IPv6 tunnel prefix: an ULA `/64` whose host `::1` is the
/// gateway (§2.4).
///
/// Persisted as `wg_address_v6 = "fdXX:XXXX:XXXX::1/64"`, which is also its
/// [`Display`](fmt::Display) and [`FromStr`] form, and its serde form.
/// Construction refuses anything else; there is no way to build one around an
/// arbitrary address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelPrefixV6(Ipv6Addr);

impl TunnelPrefixV6 {
    /// The only prefix length accepted for the tunnel.
    pub const PREFIX_LEN: u8 = 64;

    /// The prefix `fd<global_id>:0000::/64`.
    ///
    /// The Global ID is drawn once by the operator command that writes it to
    /// `network.toml` (§2.5); drawing it is not this type's business. Forty
    /// bits by construction: every value is a valid prefix.
    pub fn from_global_id(global_id: [u8; 5]) -> Self {
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1..6].copy_from_slice(&global_id);
        Self(Ipv6Addr::from(octets))
    }

    /// Validates a gateway address that claims to be `<prefix>::1` of an ULA
    /// `/64`, the prefix length having been checked already.
    fn from_gateway(gateway: Ipv6Addr) -> Result<Self, AddressError> {
        let octets = gateway.octets();
        match octets[0] {
            0xfd => {}
            0xfc => return Err(AddressError::UndefinedUla(gateway)),
            _ => return Err(AddressError::NotUla(gateway)),
        }
        if octets[6..8] != [0, 0] {
            return Err(AddressError::NonZeroSubnetId(gateway));
        }
        if iid(gateway) != GATEWAY_IID {
            return Err(AddressError::GatewayNotHostOne(gateway));
        }
        Ok(Self(network(gateway)))
    }

    /// The network address, `<prefix>::`.
    pub fn network(&self) -> Ipv6Addr {
        self.0
    }

    /// The gateway's address, `<prefix>::1`.
    pub fn gateway(&self) -> Ipv6Addr {
        self.host(GATEWAY_IID)
    }

    /// Whether `addr` lies in this `/64`, whatever its interface identifier.
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        network(addr) == self.0
    }

    /// The peer VIP `<prefix>:<iid>`, refused when `iid` is excluded (§3.2).
    ///
    /// The building block of the IPv6 derivation: an excluded identifier is
    /// what makes the caller move on to its next probe.
    pub fn peer_vip(&self, iid: u64) -> Result<Ipv6Addr, AddressError> {
        if is_excluded_iid(iid) {
            return Err(AddressError::ExcludedIid(iid));
        }
        Ok(self.host(iid))
    }

    /// Checks that `vip` may be a peer's IPv6 VIP under this prefix: inside
    /// it, not the gateway, and not an excluded identifier (§5.2).
    pub fn check_peer_vip(&self, vip: Ipv6Addr) -> Result<(), AddressError> {
        if !self.contains(vip) {
            return Err(AddressError::OutsideTunnelPrefix { vip, prefix: *self });
        }
        let iid = iid(vip);
        if iid == GATEWAY_IID {
            return Err(AddressError::GatewayAddress(vip));
        }
        if is_excluded_iid(iid) {
            return Err(AddressError::ExcludedIid(iid));
        }
        Ok(())
    }

    fn host(&self, iid: u64) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.0) | u128::from(iid))
    }
}

impl fmt::Display for TunnelPrefixV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.gateway(), Self::PREFIX_LEN)
    }
}

impl FromStr for TunnelPrefixV6 {
    type Err = AddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (addr, len) = split_cidr(text)?;
        let gateway = match addr {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(v4) => return Err(AddressError::NotIpv6(v4)),
        };
        if len != Self::PREFIX_LEN {
            return Err(AddressError::WrongPrefixLength {
                expected: Self::PREFIX_LEN,
                found: len,
            });
        }
        Self::from_gateway(gateway)
    }
}

impl serde::Serialize for TunnelPrefixV6 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for TunnelPrefixV6 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Every address a peer owns inside the tunnel (§4).
///
/// Persisted as two separate keys, `address = "a.b.c.d/32"` and the optional
/// `address_v6 = "…/128"`, read by [`PeerVips::parse`] and written back by
/// [`PeerVips::address`] and [`PeerVips::address_v6`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerVips {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}

impl PeerVips {
    /// Reads the persisted `address` and `address_v6` of a peer.
    ///
    /// Only the shape is checked here; whether `address_v6` fits the
    /// gateway's prefix is [`Self::check_against`].
    pub fn parse(address: &str, address_v6: Option<&str>) -> Result<Self, AddressError> {
        Ok(Self {
            v4: parse_vip_v4(address)?,
            v6: address_v6.map(parse_vip_v6).transpose()?,
        })
    }

    /// The persisted `address`: `a.b.c.d/32`.
    pub fn address(&self) -> String {
        format!("{}/32", self.v4)
    }

    /// The persisted `address_v6`, `…/128`, when the peer has one.
    pub fn address_v6(&self) -> Option<String> {
        self.v6.map(format_vip_v6)
    }

    /// Checks the IPv6 VIP against the gateway's prefix (§5.2).
    ///
    /// A peer without an IPv6 VIP always passes. One with an IPv6 VIP needs a
    /// gateway prefix, and must fit it as [`TunnelPrefixV6::check_peer_vip`]
    /// requires.
    pub fn check_against(&self, prefix: Option<&TunnelPrefixV6>) -> Result<(), AddressError> {
        match (self.v6, prefix) {
            (None, _) => Ok(()),
            (Some(vip), None) => Err(AddressError::V6WithoutTunnelPrefix(vip)),
            (Some(vip), Some(prefix)) => prefix.check_peer_vip(vip),
        }
    }
}

/// Reads a peer's IPv4 VIP: one host, written `a.b.c.d/32`.
///
/// The same rule as `NetworkConfig::validate_peer_identities`: a broader
/// prefix would make the source → peer association ambiguous.
pub fn parse_vip_v4(text: &str) -> Result<Ipv4Addr, AddressError> {
    let (addr, len) = split_cidr(text)?;
    let addr = match addr {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => return Err(AddressError::NotIpv4(v6)),
    };
    if len != 32 {
        return Err(AddressError::WrongPrefixLength {
            expected: 32,
            found: len,
        });
    }
    Ok(addr)
}

/// Reads a peer's IPv6 VIP: one host, written `…/128` (§2.3).
pub fn parse_vip_v6(text: &str) -> Result<Ipv6Addr, AddressError> {
    let (addr, len) = split_cidr(text)?;
    let addr = match addr {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(v4) => return Err(AddressError::NotIpv6(v4)),
    };
    if len != 128 {
        return Err(AddressError::WrongPrefixLength {
            expected: 128,
            found: len,
        });
    }
    Ok(addr)
}

/// Writes a peer's IPv6 VIP as it is persisted: `…/128`, in the RFC 5952
/// form `std` renders, the inverse of [`parse_vip_v6`].
pub fn format_vip_v6(vip: Ipv6Addr) -> String {
    format!("{vip}/128")
}

/// The form a network source must take before it is compared or counted.
///
/// A dual-stack `[::]` socket reports an IPv4 client as `::ffff:a.b.c.d`.
/// Compared as IPv6, that source matches no IPv4 VIP, `::ffff:127.0.0.1` is
/// not a loopback, and every IPv4 client lands in the same `::/64` bucket.
/// Canonicalizing maps it back to `a.b.c.d`. Only the IPv4-mapped form is
/// rewritten: the deprecated IPv4-compatible `::a.b.c.d` stays IPv6, as does
/// every native IPv6 address.
pub fn canonical_source(source: IpAddr) -> IpAddr {
    source.to_canonical()
}

/// What the gateway's last bring-up did with IPv6 inside the tunnel (§6.2).
///
/// Published by `heliosd` and read by the API, which reports it as
/// `"installed"`, `"not_configured"` or `{"unavailable": {"reason": …}}`.
/// `Unavailable` is the visible degraded state: the gateway runs IPv4-only,
/// and its peers' IPv6 VIPs are not in their `AllowedIPs`, so WireGuard drops
/// their IPv6 traffic exactly as for a peer without one. It opens nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6TunnelStatus {
    /// No `wg_address_v6`: the gateway behaves exactly as without IPv6
    /// (§2.2). Also the value before the first bring-up.
    #[default]
    NotConfigured,
    /// `<prefix>::1/64` is on the interface and the peers' `/128` are in
    /// their `AllowedIPs`.
    Installed,
    /// A prefix is configured but could not be installed.
    Unavailable(Ipv6Unavailable),
}

/// Why a configured IPv6 tunnel prefix was not installed (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Ipv6Unavailable {
    /// The interface MTU is below the IPv6 minimum; Linux would strip IPv6
    /// from the interface.
    #[error(
        "the tunnel MTU of {tunnel_mtu} bytes is below the {minimum} bytes IPv6 requires (RFC 8200)"
    )]
    TunnelMtuTooSmall { tunnel_mtu: u32, minimum: u32 },
    /// The kernel has IPv6 disabled for new interfaces.
    #[error("the kernel has IPv6 disabled ({setting} = 1)")]
    DisabledByKernel { setting: String },
    /// The kernel has no IPv6 stack at all (booted with `ipv6.disable=1`, or
    /// built without it).
    #[error("the kernel has no IPv6 stack ({path} does not exist)")]
    NoKernelSupport { path: String },
    /// The bring-up with the IPv6 address failed, and the one without it
    /// succeeded.
    #[error("bringing the interface up with {address} failed ({detail}); it came up without it")]
    AddressRefused { address: String, detail: String },
}

/// Splits `address/length`, refusing a zone identifier and any length not
/// written in canonical decimal.
fn split_cidr(text: &str) -> Result<(IpAddr, u8), AddressError> {
    if text.contains('%') {
        return Err(AddressError::ZoneId(text.to_string()));
    }
    let (addr, len) = text
        .split_once('/')
        .ok_or_else(|| AddressError::MissingPrefixLength(text.to_string()))?;
    let addr = addr
        .parse::<IpAddr>()
        .map_err(|_| AddressError::InvalidAddress(addr.to_string()))?;
    let canonical = !len.is_empty()
        && len.bytes().all(|byte| byte.is_ascii_digit())
        && (len == "0" || !len.starts_with('0'));
    let len = canonical
        .then(|| len.parse::<u8>().ok())
        .flatten()
        .ok_or_else(|| AddressError::InvalidPrefixLength(len.to_string()))?;
    Ok((addr, len))
}

fn network(addr: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(addr) & NETWORK_MASK)
}

fn iid(addr: Ipv6Addr) -> u64 {
    // Truncation is the point: the low 64 bits are the interface identifier.
    u128::from(addr) as u64
}

#[cfg(test)]
mod tests;
