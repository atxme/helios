//! Deterministic, **stateless** virtual address (VIP) assignment (ADR-001, §4).
//!
//! WireGuard has no Config Payload: the gateway must choose the client's
//! VIP. Rather than keeping a database (SQL/file) to back up, migrate, and
//! corrupt, we **derive** the VIP from the one stable and unique identifier
//! of a WireGuard peer: its Curve25519 public key.
//!
//! ```text
//! VIP = 100.64.0.0/10 | BLAKE3(public_key)[0..22 bits]
//! ```
//!
//! The only "state" is the kernel's live peer table, consulted at enrollment
//! to resolve the rare collisions (§4). Nothing is persisted: after a
//! restart, every client recovers its VIP by re-derivation.

use std::net::Ipv4Addr;

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

/// Number of VIP anti-collision probes.
///
/// Shared by enrollment and admission: two different bounds would make the
/// chosen address depend on the path taken, whereas the whole point of
/// derivation is that it's the same everywhere.
pub const MAX_VIP_PROBES: u32 = 64;

/// Read-only view of the kernel's live WireGuard peer table.
///
/// Abstracted as a trait to stay **testable on WSL2**: the real
/// (target) implementation will query the kernel via
/// `defguard_wireguard_rs`; tests supply a fake in-memory table. The gateway
/// never persists this information — it gets rebuilt as clients reconnect.
pub trait PeerTable {
    /// Is VIP `addr` already assigned to a peer whose public key **differs**
    /// from `pubkey`? (A peer never collides with itself.)
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool;
}

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

/// Assigns a VIP to `pubkey`, avoiding collisions with the live table.
///
/// Probes `derive_cgnat_ip(pubkey, i)` for `i = 0, 1, 2, …` and returns the
/// first address not held by an **other** key. `max_probes` bounds the loop
/// (collision astronomically unlikely, but we never loop forever). Stateless:
/// the only source of truth is `table`.
pub fn assign_vip<T: PeerTable>(
    table: &T,
    pubkey: &[u8],
    max_probes: u32,
) -> Result<Ipv4Addr, IpamError> {
    for i in 0..max_probes {
        let candidate = derive_cgnat_ip(pubkey, i);
        if !table.is_taken_by_other(candidate, pubkey) {
            if i > 0 {
                tracing::warn!(
                    counter = i,
                    vip = %candidate,
                    "VIP collision resolved via re-derivation"
                );
            }
            return Ok(candidate);
        }
    }
    Err(IpamError::Exhausted(max_probes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fake in-memory peer table: `VIP -> owner public key`.
    #[derive(Default)]
    struct FakeTable {
        owners: HashMap<Ipv4Addr, Vec<u8>>,
    }
    impl FakeTable {
        fn insert(&mut self, addr: Ipv4Addr, pubkey: &[u8]) {
            self.owners.insert(addr, pubkey.to_vec());
        }
    }
    impl PeerTable for FakeTable {
        fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
            self.owners
                .get(&addr)
                .map(|owner| owner != pubkey)
                .unwrap_or(false)
        }
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

    #[test]
    fn same_client_recovers_its_vip_after_a_reboot() {
        // Empty table = "after restart" state: no persistence.
        let table = FakeTable::default();
        let pk = [42u8; 32];
        let before = assign_vip(&table, &pk, 64).unwrap();
        let after = assign_vip(&FakeTable::default(), &pk, 64).unwrap();
        assert_eq!(
            before, after,
            "the VIP must be stable without state on disk"
        );
    }

    #[test]
    fn collision_resolved_by_re_derivation() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        // Force a collision: occupy B's natural VIP with A.
        let vip_b_natural = derive_cgnat_ip(&pk_b, 0);
        let mut table = FakeTable::default();
        table.insert(vip_b_natural, &pk_a);

        let vip_b = assign_vip(&table, &pk_b, 64).unwrap();
        assert_ne!(vip_b, vip_b_natural, "B must avoid the VIP taken by A");
        assert_eq!(
            vip_b,
            derive_cgnat_ip(&pk_b, 1),
            "B falls back to counter 1"
        );
    }

    #[test]
    fn client_does_not_collide_with_itself() {
        // If the VIP is already MINE (reconnection), I keep it — no drift.
        let pk = [9u8; 32];
        let vip = derive_cgnat_ip(&pk, 0);
        let mut table = FakeTable::default();
        table.insert(vip, &pk);
        assert_eq!(assign_vip(&table, &pk, 64).unwrap(), vip);
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
