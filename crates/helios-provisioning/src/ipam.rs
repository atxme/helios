//! Virtual address (VIP) assignment, IPv4 and IPv6 (ADR-001 §4,
//! `ADRESSAGE-IPV6.md` §3 and §3 bis).
//!
//! WireGuard has no Config Payload: the gateway must choose the client's
//! VIP. Rather than drawing one at random, it **derives** candidates from the
//! one stable and unique identifier of a WireGuard peer, its Curve25519
//! public key:
//!
//! ```text
//! VIP4 = 100.64.0.0/10 | BLAKE3(public_key || n)[0..22 bits]
//! VIP6 = <prefix>/64   | BLAKE3("helios-ipam-v6-v1" || public_key || n)[0..8]
//! ```
//!
//! `n` is a probing counter, one per family, that only moves past a
//! collision or an excluded identifier.
//!
//! # Derivation chooses, persistence keeps
//!
//! The derivation serves to **choose** an address, never to find it again.
//! Admission chooses once and writes the result to `network.toml`, and from
//! then on that declaration is the peer's address: provisioning reads it
//! back (`crate::session`). Deriving it again later could only disagree — a
//! collision resolved at admission against a peer that was not connected
//! lands on a later counter, which a re-derivation against another table
//! does not reproduce.
//!
//! # One view, one allocation point
//!
//! `AddressView` is the only collision table, for both families, and
//! `AddressView::new` its only constructor; `AddressView::assign` is the only
//! allocation point. All three are crate-private and called by
//! `crate::admission` alone, so no other path can choose an address
//! (§3 bis.2, rules 1 and 2). The live data plane enters the view as an
//! input, [`LivePeer`], rather than as a second table.
//!
//! ```compile_fail
//! // Outside this crate, nothing can build the view, hence allocate.
//! let _ = helios_provisioning::ipam::AddressView::new;
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aether::net::{PeerVips, TunnelPrefixV6};
use aether::NetworkConfig;

/// RFC 6598 (CGNAT) shared range: `100.64.0.0/10`, ~4.19M addresses.
///
/// Chosen to collide with neither residential routers (`192.168/16`) nor
/// enterprise networks (`10/8`). A `/16` was considered then rejected: 7.3%
/// collision rate at 100 clients (ADR-001, §4).
const CGNAT_BASE: u32 = 0x6440_0000; // 100.64.0.0
/// /10 prefix → 22 usable host bits.
const HOST_BITS: u32 = 22;
const HOST_MASK: u32 = (1 << HOST_BITS) - 1;

/// Number of assignable addresses in the range, excluding reserved ones (see below).
pub const POOL_SIZE: u32 = 1 << HOST_BITS;

/// Number of VIP anti-collision probes, per family (§3.3).
///
/// One bound for every admission path: two different bounds would make the
/// chosen address depend on the path taken, whereas the whole point of
/// derivation is that it's the same everywhere.
pub const MAX_VIP_PROBES: u32 = 64;

/// Assignment errors.
#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    /// The pool is saturated, or collision resolution ran out of attempts.
    #[error("no free VIP after {0} attempts")]
    Exhausted(u32),
}

/// Derives candidate address n° `counter` for this public key.
///
/// Deterministic: the same `(pubkey, counter)` ⇒ the same address, on every
/// gateway and after every restart. `counter` only comes into play to work
/// around a collision (rare case); at `counter = 0` we get the client's
/// "natural" VIP.
pub fn derive_cgnat_ip(pubkey: &[u8], counter: u32) -> Ipv4Addr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pubkey);
    hasher.update(&counter.to_le_bytes());
    let digest = hasher.finalize();

    let mut first4 = [0u8; 4];
    first4.copy_from_slice(&digest.as_bytes()[..4]);
    let host = u32::from_le_bytes(first4) & HOST_MASK;

    Ipv4Addr::from(CGNAT_BASE | normalize_host(host))
}

/// Domain separator of the IPv6 derivation (`ADRESSAGE-IPV6.md` §3.1).
///
/// The IPv4 derivation hashes `pubkey || n` with no prefix; this one hashes
/// `"helios-ipam-v6-v1" || pubkey || n`, so the two never share an input.
/// Frozen: changing it renumbers every peer's IPv6 VIP.
pub const IPV6_DOMAIN: &[u8] = b"helios-ipam-v6-v1";

/// Derives candidate interface identifier n° `counter` for this public key.
///
/// `BLAKE3(IPV6_DOMAIN || pubkey || counter_le32)[0..8]`, the eight bytes in
/// address order: they are the low half of the VIP as written, so the
/// identifier `fdff:ffff:ffff:ff80` of §3.2 compares as the number
/// `0xfdff_ffff_ffff_ff80`. Deterministic like [`derive_cgnat_ip`], and on a
/// counter of its own: an IPv4 collision does not move it (§3.3).
pub fn derive_ula_iid(pubkey: &[u8], counter: u32) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IPV6_DOMAIN);
    hasher.update(pubkey);
    hasher.update(&counter.to_le_bytes());
    let digest = hasher.finalize();

    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(first8)
}

/// Discards the reserved hosts of the `/10`: `.0` (network address) and the
/// all-ones host (broadcast). These two cases are deterministically remapped
/// to valid hosts rather than drawn again, so an unusable VIP is never assigned.
fn normalize_host(host: u32) -> u32 {
    match host {
        0 => 1,
        h if h == HOST_MASK => HOST_MASK - 1,
        h => h,
    }
}

/// One peer of the live WireGuard table, as the data plane reports it.
///
/// Borrowed rather than owned: the daemon adapts its own snapshot type
/// (`helios_wireguard::PeerStatus`) without this crate depending on the data
/// plane.
#[derive(Debug, Clone, Copy)]
pub struct LivePeer<'a> {
    /// Raw Curve25519 public key, 32 bytes.
    pub public_key: &'a [u8],
    /// `AllowedIPs` as the data plane reports them, `address/length`.
    pub allowed_ips: &'a [String],
}

/// Who holds an address of the view.
#[derive(Debug)]
enum Holder {
    /// The gateway itself: no peer may take its address. Losing it would cut
    /// the control plane, the only channel that could repair the mistake.
    Gateway,
    /// A peer, by raw public key.
    Peer(Vec<u8>),
}

/// The one collision table of the IPAM, both families (§3 bis.2, rule 2).
///
/// The union of:
/// - the addresses `network.toml` declares (`address`, `address_v6`);
/// - the `AllowedIPs` of the live WireGuard table, every family;
/// - the reservations: the host of `wg_address`, and in the IPv6 prefix every
///   address that may not be a peer's — `<prefix>::1` and the identifiers
///   §3.2 excludes.
///
/// The two reserved hosts of the `/10` never get this far: the IPv4
/// derivation remaps them before they are candidates ([`derive_cgnat_ip`]).
///
/// A peer never collides with itself: an address its own key holds is free
/// for it.
pub(crate) struct AddressView {
    prefix_v6: Option<TunnelPrefixV6>,
    held: Vec<(IpAddr, Holder)>,
}

impl AddressView {
    /// Builds the view from the declared configuration and a live snapshot.
    ///
    /// An entry that cannot be read — a malformed `address` inherited from a
    /// manual edit, an `AllowedIPs` that is not an address — cannot collide
    /// with a derived VIP: it is skipped rather than blocking every
    /// admission. `NetworkConfig::validate` refuses the first at load anyway.
    pub(crate) fn new(config: &NetworkConfig, live: &[LivePeer<'_>]) -> Self {
        let mut held = Vec::with_capacity(1 + 2 * config.peers.len());
        if let Some(gateway) = host_of(&config.wg_address) {
            held.push((gateway, Holder::Gateway));
        }
        for peer in &config.peers {
            let owner = decode_key(&peer.public_key);
            if let Some(v4) = host_of(&peer.address) {
                held.push((v4, Holder::Peer(owner.clone())));
            }
            if let Some(v6) = peer.address_v6 {
                held.push((IpAddr::V6(v6), Holder::Peer(owner)));
            }
        }
        for peer in live {
            for allowed in peer.allowed_ips {
                if let Some(host) = host_of(allowed) {
                    held.push((host, Holder::Peer(peer.public_key.to_vec())));
                }
            }
        }
        Self {
            prefix_v6: config.wg_address_v6,
            held,
        }
    }

    /// The single allocation point: the complete VIPs of the peer `pubkey`.
    ///
    /// `declared` is what `network.toml` already holds for this peer, `None`
    /// for a first admission. A declared address is returned as is, never
    /// renumbered (rule 5); only a missing family is allocated, and
    /// allocating one never touches the other (rules 6 and 7). The IPv6 VIP
    /// exists only when the gateway has a tunnel prefix.
    pub(crate) fn assign(
        &self,
        pubkey: &[u8],
        declared: Option<PeerVips>,
    ) -> Result<PeerVips, IpamError> {
        let v4 = match declared {
            Some(declared) => declared.v4,
            None => self.probe(pubkey, |n| derive_cgnat_ip(pubkey, n))?,
        };
        let v6 = match (declared.and_then(|declared| declared.v6), self.prefix_v6) {
            (Some(kept), _) => Some(kept),
            (None, Some(prefix)) => {
                Some(self.probe_v6(&prefix, pubkey, |n| derive_ula_iid(pubkey, n))?)
            }
            (None, None) => None,
        };
        Ok(PeerVips { v4, v6 })
    }

    /// Probes the IPv6 identifiers `iid_at(0)`, `iid_at(1)`, … inside
    /// `prefix`. Separate from [`Self::assign`] so the exclusions and the
    /// bound can be exercised on chosen identifiers.
    fn probe_v6(
        &self,
        prefix: &TunnelPrefixV6,
        pubkey: &[u8],
        iid_at: impl Fn(u32) -> u64,
    ) -> Result<Ipv6Addr, IpamError> {
        let network = u128::from(prefix.network());
        self.probe(pubkey, |n| Ipv6Addr::from(network | u128::from(iid_at(n))))
    }

    /// Returns the first of `candidate(0)`, `candidate(1)`, … that is free
    /// for `pubkey`, within [`MAX_VIP_PROBES`] attempts — a collision is
    /// astronomically unlikely, but the loop never runs forever.
    fn probe<A>(&self, pubkey: &[u8], candidate: impl Fn(u32) -> A) -> Result<A, IpamError>
    where
        A: Copy + Into<IpAddr> + fmt::Display,
    {
        for counter in 0..MAX_VIP_PROBES {
            let vip = candidate(counter);
            if self.is_free_for(vip.into(), pubkey) {
                if counter > 0 {
                    tracing::warn!(counter, %vip, "VIP collision resolved via re-derivation");
                }
                return Ok(vip);
            }
        }
        Err(IpamError::Exhausted(MAX_VIP_PROBES))
    }

    /// Whether `addr` may be given to `pubkey`.
    fn is_free_for(&self, addr: IpAddr, pubkey: &[u8]) -> bool {
        if let (IpAddr::V6(v6), Some(prefix)) = (addr, &self.prefix_v6) {
            // `::1`, the excluded identifiers, and anything outside the
            // prefix: what `check_peer_vip` refuses no peer may hold.
            if prefix.check_peer_vip(v6).is_err() {
                return false;
            }
        }
        !self.held.iter().any(|(held, holder)| {
            *held == addr
                && match holder {
                    Holder::Gateway => true,
                    Holder::Peer(owner) => owner.as_slice() != pubkey,
                }
        })
    }
}

/// Host part of a CIDR address (`100.64.1.2/32` → `100.64.1.2`).
fn host_of(cidr: &str) -> Option<IpAddr> {
    cidr.trim().split('/').next()?.trim().parse().ok()
}

/// Raw bytes of a base64 public key, empty if it is unreadable.
///
/// The IPAM derives the VIP from the bytes, never from the encoding. An
/// unreadable key cannot reach here through admission, which validates
/// first; the case only remains for entries inherited from a manual edit of
/// `network.toml`. An empty owner is nobody's key, so its address stays
/// held against everyone.
pub(crate) fn decode_key(public_key: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::net::is_excluded_iid;

    /// The prefix of the specification's own example (§5.1).
    const PREFIX: &str = "fd3c:91a2:7e04::1/64";

    fn prefix() -> TunnelPrefixV6 {
        PREFIX.parse().expect("the specification's example prefix")
    }

    fn b64(key: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    fn declared(key: &[u8], v4: Ipv4Addr, v6: Option<Ipv6Addr>) -> aether::WgPeer {
        aether::WgPeer {
            name: b64(key),
            public_key: b64(key),
            address: format!("{v4}/32"),
            address_v6: v6,
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }
    }

    fn gateway(prefix_v6: Option<TunnelPrefixV6>, peers: Vec<aether::WgPeer>) -> NetworkConfig {
        NetworkConfig {
            wg_address: "100.64.0.1/10".into(),
            wg_address_v6: prefix_v6,
            peers,
            ..NetworkConfig::default()
        }
    }

    fn vip6(iid: u64) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(prefix().network()) | u128::from(iid))
    }

    #[test]
    fn vip_within_the_cgnat_range() {
        // Everything that comes out must belong to 100.64.0.0/10.
        for seed in 0u8..50 {
            let vip = derive_cgnat_ip(&[seed; 32], 0);
            let oct = vip.octets();
            assert_eq!(oct[0], 100, "vip={vip}");
            assert!((64..=127).contains(&oct[1]), "vip={vip} outside /10");
        }
    }

    #[test]
    fn deterministic_derivation() {
        let pk = [7u8; 32];
        assert_eq!(derive_cgnat_ip(&pk, 0), derive_cgnat_ip(&pk, 0));
        // Two different keys ⇒ (almost always) two different VIPs.
        assert_ne!(
            derive_cgnat_ip(&[1u8; 32], 0),
            derive_cgnat_ip(&[2u8; 32], 0)
        );
    }

    /// §9 criterion 3, through the allocation point: two gateways, or one
    /// before and after a restart, start from empty views and agree on both
    /// families.
    #[test]
    fn the_same_key_gets_the_same_vips_on_two_instances() {
        let pk = [42u8; 32];
        let first = AddressView::new(&gateway(Some(prefix()), vec![]), &[])
            .assign(&pk, None)
            .unwrap();
        let second = AddressView::new(&gateway(Some(prefix()), vec![]), &[])
            .assign(&pk, None)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.v4, derive_cgnat_ip(&pk, 0));
        assert_eq!(first.v6, Some(vip6(derive_ula_iid(&pk, 0))));
    }

    /// A gateway without `wg_address_v6` allocates exactly what it did
    /// before IPv6: the IPv4 VIP, and nothing else (§2.2).
    #[test]
    fn without_a_tunnel_prefix_no_ipv6_vip_is_allocated() {
        let pk = [42u8; 32];
        let vips = AddressView::new(&gateway(None, vec![]), &[])
            .assign(&pk, None)
            .unwrap();
        assert_eq!(
            vips,
            PeerVips {
                v4: derive_cgnat_ip(&pk, 0),
                v6: None
            }
        );
    }

    /// A declared peer collides even when it is not connected: this is
    /// what the live table alone missed (§3 bis.1).
    #[test]
    fn a_declared_peer_holds_its_address_while_disconnected() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let natural_b = derive_cgnat_ip(&pk_b, 0);
        let config = gateway(None, vec![declared(&pk_a, natural_b, None)]);

        let vips = AddressView::new(&config, &[]).assign(&pk_b, None).unwrap();
        assert_eq!(
            vips.v4,
            derive_cgnat_ip(&pk_b, 1),
            "B falls back to counter 1"
        );
    }

    /// The live table counts too, every family: a peer the data plane still
    /// carries holds its addresses even if the file no longer declares it.
    #[test]
    fn the_live_table_holds_its_allowed_ips_in_both_families() {
        let pk_live = [8u8; 32];
        let pk = [7u8; 32];
        let allowed = vec![
            format!("{}/32", derive_cgnat_ip(&pk, 0)),
            format!("{}/128", vip6(derive_ula_iid(&pk, 0))),
            "not-an-address".to_string(),
        ];
        let live = [LivePeer {
            public_key: &pk_live,
            allowed_ips: &allowed,
        }];

        let vips = AddressView::new(&gateway(Some(prefix()), vec![]), &live)
            .assign(&pk, None)
            .unwrap();
        assert_eq!(vips.v4, derive_cgnat_ip(&pk, 1));
        assert_eq!(vips.v6, Some(vip6(derive_ula_iid(&pk, 1))));
    }

    /// If the address is already MINE — declared or live — I keep it: a
    /// peer never collides with itself.
    #[test]
    fn a_peer_does_not_collide_with_itself() {
        let pk = [9u8; 32];
        let v4 = derive_cgnat_ip(&pk, 0);
        let v6 = vip6(derive_ula_iid(&pk, 0));
        let config = gateway(Some(prefix()), vec![declared(&pk, v4, Some(v6))]);
        let allowed = vec![format!("{v4}/32"), format!("{v6}/128")];
        let live = [LivePeer {
            public_key: &pk,
            allowed_ips: &allowed,
        }];

        let vips = AddressView::new(&config, &live).assign(&pk, None).unwrap();
        assert_eq!(vips, PeerVips { v4, v6: Some(v6) });
    }

    /// The gateway's IPv4 address is reserved: taking it away would cut the
    /// control plane.
    #[test]
    fn the_gateways_ipv4_address_is_reserved() {
        let pk = [9u8; 32];
        let natural = derive_cgnat_ip(&pk, 0);
        let config = NetworkConfig {
            wg_address: format!("{natural}/10"),
            ..NetworkConfig::default()
        };
        let vips = AddressView::new(&config, &[]).assign(&pk, None).unwrap();
        assert_eq!(vips.v4, derive_cgnat_ip(&pk, 1));
    }

    /// §9 criterion 4, at the allocation point: an IPv4 collision moves the
    /// IPv4 counter only.
    #[test]
    fn the_two_families_probe_on_independent_counters() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let config = gateway(
            Some(prefix()),
            vec![declared(&pk_a, derive_cgnat_ip(&pk_b, 0), None)],
        );
        let vips = AddressView::new(&config, &[]).assign(&pk_b, None).unwrap();
        assert_eq!(vips.v4, derive_cgnat_ip(&pk_b, 1));
        assert_eq!(
            vips.v6,
            Some(vip6(derive_ula_iid(&pk_b, 0))),
            "the IPv6 counter did not move"
        );
    }

    /// Rules 5 to 7: a declared address is never renumbered, and only the
    /// missing family is allocated.
    #[test]
    fn a_declared_peer_keeps_its_addresses_and_only_gains_the_missing_family() {
        let pk = [5u8; 32];
        // Not what the derivation would choose, on purpose.
        let kept_v4: Ipv4Addr = "100.64.1.2".parse().unwrap();
        let view = AddressView::new(&gateway(Some(prefix()), vec![]), &[]);

        let completed = view
            .assign(
                &pk,
                Some(PeerVips {
                    v4: kept_v4,
                    v6: None,
                }),
            )
            .unwrap();
        assert_eq!(completed.v4, kept_v4, "the IPv4 VIP is not touched");
        assert_eq!(completed.v6, Some(vip6(derive_ula_iid(&pk, 0))));

        let kept_v6 = vip6(0x1234);
        let unchanged = PeerVips {
            v4: kept_v4,
            v6: Some(kept_v6),
        };
        assert_eq!(view.assign(&pk, Some(unchanged)).unwrap(), unchanged);

        let without_prefix = AddressView::new(&gateway(None, vec![]), &[]);
        let v4_only = PeerVips {
            v4: kept_v4,
            v6: None,
        };
        assert_eq!(without_prefix.assign(&pk, Some(v4_only)).unwrap(), v4_only);
    }

    /// §9 criterion 5: `0`, `1` and the reserved anycast range are skipped,
    /// each one still counting as a probe.
    #[test]
    fn excluded_identifiers_are_skipped() {
        let pk = [3u8; 32];
        let view = AddressView::new(&gateway(Some(prefix()), vec![]), &[]);
        let sequence = [
            0,
            1,
            0xfdff_ffff_ffff_ff80,
            0xffff_ffff_ffff_ffff,
            0x8a1f_3b2c_9d40_e517,
        ];
        let vip = view
            .probe_v6(&prefix(), &pk, |n| sequence[n as usize])
            .unwrap();
        assert_eq!(vip, vip6(0x8a1f_3b2c_9d40_e517));
        // The last identifier below the excluded range is a peer's.
        assert_eq!(
            view.probe_v6(&prefix(), &pk, |_| 0xfdff_ffff_ffff_ff7f)
                .unwrap(),
            vip6(0xfdff_ffff_ffff_ff7f)
        );
    }

    /// The same exclusion on the real derivation: this key's natural
    /// identifier falls in the reserved anycast range, so its VIP is its
    /// counter-1 identifier.
    #[test]
    fn a_key_whose_natural_identifier_is_excluded_moves_to_the_next() {
        let mut pk = [0u8; 32];
        pk[0] = 1;
        pk[1] = 1;
        assert_eq!(derive_ula_iid(&pk, 0), 0xfeec_6513_240e_4e72);
        assert!(is_excluded_iid(derive_ula_iid(&pk, 0)));

        let vips = AddressView::new(&gateway(Some(prefix()), vec![]), &[])
            .assign(&pk, None)
            .unwrap();
        assert_eq!(vips.v6, Some(vip6(derive_ula_iid(&pk, 1))));
        assert_eq!(vips.v4, derive_cgnat_ip(&pk, 0), "IPv4 unaffected");
    }

    /// §9 criterion 5: the bound is `MAX_VIP_PROBES` identifiers, excluded
    /// ones included, then `Exhausted`.
    #[test]
    fn ipv6_probing_stops_at_the_bound() {
        let pk = [3u8; 32];
        let view = AddressView::new(&gateway(Some(prefix()), vec![]), &[]);
        let last_chance = |n: u32| if n + 1 == MAX_VIP_PROBES { 0x42 } else { 0 };
        assert_eq!(
            view.probe_v6(&prefix(), &pk, last_chance).unwrap(),
            vip6(0x42)
        );
        let one_too_far = |n: u32| if n == MAX_VIP_PROBES { 0x42 } else { 1 };
        assert!(matches!(
            view.probe_v6(&prefix(), &pk, one_too_far),
            Err(IpamError::Exhausted(MAX_VIP_PROBES))
        ));
    }

    #[test]
    fn ipv4_probing_stops_at_the_bound() {
        let pk = [6u8; 32];
        let squatters = (0..MAX_VIP_PROBES)
            .map(|n| {
                let mut other = [0xeeu8; 32];
                other[..4].copy_from_slice(&n.to_le_bytes());
                declared(&other, derive_cgnat_ip(&pk, n), None)
            })
            .collect();
        let view = AddressView::new(&gateway(None, squatters), &[]);
        assert!(matches!(
            view.assign(&pk, None),
            Err(IpamError::Exhausted(MAX_VIP_PROBES))
        ));
    }

    #[test]
    fn never_a_reserved_host() {
        assert_eq!(normalize_host(0), 1);
        assert_eq!(normalize_host(HOST_MASK), HOST_MASK - 1);
        assert_eq!(normalize_host(1234), 1234);
    }

    /// Freezes the IPv6 formula of §3.1: a change of separator, of input
    /// order, of counter encoding or of byte order renumbers every peer, and
    /// fails here first.
    #[test]
    fn the_ipv6_derivation_matches_its_known_answer() {
        let pk = [7u8; 32];
        assert_eq!(derive_ula_iid(&pk, 0), 0xf545_e478_0e88_7a7f);
        assert_eq!(derive_ula_iid(&pk, 1), 0x12c2_1cf4_ff2f_77b7);
        assert_eq!(
            AddressView::new(&gateway(Some(prefix()), vec![]), &[])
                .assign(&pk, None)
                .unwrap()
                .v6,
            Some(
                "fd3c:91a2:7e04:0:f545:e478:e88:7a7f"
                    .parse::<Ipv6Addr>()
                    .unwrap()
            )
        );

        // The same value spelled out from the specification's formula, on
        // the one-shot API rather than the incremental hasher.
        let mut input = Vec::new();
        input.extend_from_slice(b"helios-ipam-v6-v1");
        input.extend_from_slice(&pk);
        input.extend_from_slice(&0u32.to_le_bytes());
        let digest = blake3::hash(&input);
        let mut first8 = [0u8; 8];
        first8.copy_from_slice(&digest.as_bytes()[..8]);
        assert_eq!(u64::from_be_bytes(first8), derive_ula_iid(&pk, 0));
    }

    /// §9 criterion 3: no state enters the derivation, so two gateways —
    /// or one gateway before and after a restart — derive the same identifier.
    #[test]
    fn the_ipv6_derivation_is_deterministic() {
        let pk = [42u8; 32];
        let first_instance: Vec<u64> = (0..4).map(|n| derive_ula_iid(&pk, n)).collect();
        let second_instance: Vec<u64> = (0..4).map(|n| derive_ula_iid(&pk, n)).collect();
        assert_eq!(first_instance, second_instance);
        assert_ne!(derive_ula_iid(&[1u8; 32], 0), derive_ula_iid(&[2u8; 32], 0));
        assert_ne!(derive_ula_iid(&pk, 0), derive_ula_iid(&pk, 1));
    }

    /// §9 criterion 4: the separator keeps the two families on different
    /// inputs. Without it, the IPv6 identifier would begin with the very
    /// bytes the IPv4 VIP is cut from.
    #[test]
    fn the_ipv4_and_ipv6_derivations_are_independent() {
        for seed in 0u8..32 {
            let pk = [seed; 32];
            let mut unseparated = blake3::Hasher::new();
            unseparated.update(&pk);
            unseparated.update(&0u32.to_le_bytes());
            let shared = unseparated.finalize();
            let mut first8 = [0u8; 8];
            first8.copy_from_slice(&shared.as_bytes()[..8]);

            assert_ne!(
                derive_ula_iid(&pk, 0),
                u64::from_be_bytes(first8),
                "the IPv6 identifier must not come from the IPv4 input"
            );
        }
    }
}
