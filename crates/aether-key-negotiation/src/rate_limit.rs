use std::{collections::HashMap, hash::Hash, net::IpAddr, time::Instant};

use crate::SOURCE_RATE_WINDOW;

/// The bucket a source address is counted in.
///
/// IPv4 is counted per address. IPv6 is counted per **`/64`**, because that is
/// the smallest block an ordinary subscriber is handed: counting per exact
/// address would let one host walk through 2^64 of them and never reach the
/// limit, which makes the whole per-source budget decorative on IPv6.
///
/// The trade-off is deliberate and stated: several legitimate clients behind
/// one `/64` share one budget, exactly as several clients behind one IPv4 NAT
/// already do.
///
/// The source is canonicalized first. A dual-stack `[::]` socket reports an
/// IPv4 client as `::ffff:a.b.c.d`, whose first 64 bits are all zero: taken
/// as IPv6, every IPv4 client on the Internet would land in the single bucket
/// `::/64` and one of them could exhaust it for all the others.
pub(crate) fn rate_bucket(source: IpAddr) -> IpAddr {
    match source.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

/// Counts recent events per key, over a sliding window.
///
/// Deliberately a plain map behind a mutex rather than a background sweeper:
/// entries are pruned on insertion, so a key that stops appearing costs
/// nothing, and the map never outgrows the number of keys seen within one
/// window.
pub(crate) struct RateLimiter<K> {
    pub(crate) seen: HashMap<K, (Instant, u32)>,
    budget: u32,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub(crate) fn new(budget: u32) -> Self {
        Self {
            seen: HashMap::new(),
            budget,
        }
    }

    /// `true` if this key may consume one more unit of budget.
    pub(crate) fn admit(&mut self, key: K, now: Instant) -> bool {
        self.seen
            .retain(|_, (started, _)| now.duration_since(*started) < SOURCE_RATE_WINDOW);
        let entry = self.seen.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= SOURCE_RATE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.budget
    }
}
