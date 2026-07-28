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
}
