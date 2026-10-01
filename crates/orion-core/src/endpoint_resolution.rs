//! Turns a gateway endpoint into the ordered addresses Orion dials.
//!
//! # One resolution, not two
//!
//! A profile names its gateway by `host:port`, and the host is often a name
//! carrying both an `A` and an `AAAA` record. Orion used to resolve it twice,
//! independently: once for the key negotiation (`tokio::net::lookup_host`,
//! first result) and once inside `defguard_wireguard_rs` when the peer
//! endpoint was set (`to_socket_addrs().next()`, first result again). Two
//! `getaddrinfo` calls may answer in a different order, so the negotiation
//! and the tunnel could land on two different address families — and an
//! unreachable `AAAA` failed the negotiation outright, with no second try.
//!
//! This module resolves a host **once** per connection attempt into an
//! ordered candidate list (RFC 8305 §4), and the data plane is then handed a
//! **literal** address, never a name.
//!
//! # Order
//!
//! RFC 8305 §4 starts from the list the system resolver returns, already
//! sorted by destination address selection (RFC 6724, which `getaddrinfo`
//! applies on Windows and glibc), and interleaves the families from there:
//! whichever family comes first is followed by the first address of the
//! other, and so on. On a host with working IPv6 the resolver puts the
//! `AAAA` first, so IPv6 is tried first and IPv4 follows. The resolver's
//! choice of the *first* family is kept rather than forcing IPv6: on a host
//! whose resolver already knows IPv6 is unusable it sorts IPv4 first, and a
//! tunnel endpoint chosen without a race (no negotiation) would otherwise be
//! pinned to the dead family.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

/// Address family of a candidate, as written in Orion's logs.
pub fn family(address: &SocketAddr) -> &'static str {
    match address.ip() {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

/// Orders resolved addresses for connection attempts (RFC 8305 §4).
///
/// - an address with port `0` is dropped — it was never usable, and the
///   previous `find(port != 0)` skipped it the same way;
/// - an IPv4-mapped IPv6 address is read as the IPv4 address it carries: a
///   socket of the IPv6 family cannot reach it on Windows, where
///   `IPV6_V6ONLY` is the default, and it duplicates the `A` record anyway;
/// - duplicates keep their first position only;
/// - families are interleaved, starting with the family of the first
///   address, each family keeping the relative order the resolver gave it.
pub fn rfc8305_order(resolved: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut unique: Vec<SocketAddr> = Vec::new();
    for address in resolved {
        if address.port() == 0 {
            continue;
        }
        // Rebuilt only when the family changes: an IPv6 address keeps its
        // scope identifier, which a link-local candidate cannot lose.
        let address = match address.ip().to_canonical() {
            IpAddr::V4(v4) if address.is_ipv6() => SocketAddr::new(IpAddr::V4(v4), address.port()),
            _ => address,
        };
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let Some(first) = unique.first() else {
        return unique;
    };
    let leads_with_v6 = first.is_ipv6();
    let (mut leading, mut trailing): (Vec<SocketAddr>, Vec<SocketAddr>) = unique
        .into_iter()
        .partition(|address| address.is_ipv6() == leads_with_v6);
    let mut ordered = Vec::with_capacity(leading.len() + trailing.len());
    leading.reverse();
    trailing.reverse();
    loop {
        match (leading.pop(), trailing.pop()) {
            (None, None) => break,
            (lead, trail) => ordered.extend(lead.into_iter().chain(trail)),
        }
    }
    ordered
}

/// Resolves `endpoint` (`host:port`, `[v6]:port` or `v4:port`) once, into
/// the [`rfc8305_order`] of its addresses.
///
/// A literal address short-circuits the resolver: nothing is queried, and
/// the result is that address alone. Never empty on success.
pub async fn resolve_candidates(endpoint: &str) -> Result<Vec<SocketAddr>> {
    let resolved: Vec<SocketAddr> = match endpoint.parse::<SocketAddr>() {
        Ok(literal) => vec![literal],
        Err(_) => tokio::net::lookup_host(endpoint)
            .await
            .with_context(|| format!("resolving {endpoint}"))?
            .collect(),
    };
    let ordered = rfc8305_order(resolved);
    if ordered.is_empty() {
        anyhow::bail!("{endpoint} resolved to no usable address");
    }
    Ok(ordered)
}

/// The literal socket address a backend installs as the WireGuard endpoint.
///
/// A backend never resolves a name: the connection controller has already
/// chosen the address — the one that negotiated, or the first candidate of a
/// single resolution — and anything else here would be a second
/// `getaddrinfo` free to pick another family.
pub fn literal_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let address = endpoint.parse::<SocketAddr>().map_err(|_| {
        anyhow::anyhow!(
            "a literal IP:port is expected here — the connection controller resolves the \
             gateway name before the data plane"
        )
    })?;
    if address.port() == 0 {
        anyhow::bail!("the UDP port must be greater than zero");
    }
    Ok(address)
}

/// Host part of `host:port`, brackets removed, or `None` without a port.
fn host_of(endpoint: &str) -> Option<&str> {
    let (host, _) = endpoint.trim().rsplit_once(':')?;
    Some(host.trim_start_matches('[').trim_end_matches(']'))
}

/// Do two endpoints name the same host, whatever their ports?
///
/// The profile carries two endpoints — WireGuard and key negotiation — that
/// usually share a host on different ports. When they do, the address that
/// negotiated is the WireGuard endpoint too, and the name is resolved once.
/// Compared as written (case and a final dot aside): two different names are
/// two hosts, each resolved once, never merged.
pub fn same_host(left: &str, right: &str) -> bool {
    match (host_of(left), host_of(right)) {
        (Some(left), Some(right)) => left
            .trim_end_matches('.')
            .eq_ignore_ascii_case(right.trim_end_matches('.')),
        _ => false,
    }
}

/// Port of `host:port`, if it is a valid non-zero UDP port.
pub fn port_of(endpoint: &str) -> Option<u16> {
    let (_, port) = endpoint.trim().rsplit_once(':')?;
    port.parse::<u16>().ok().filter(|port| *port != 0)
}

#[cfg(test)]
mod tests;
