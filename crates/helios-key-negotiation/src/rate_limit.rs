use std::{collections::HashMap, hash::Hash, net::IpAddr, time::Instant};

use crate::SOURCE_RATE_WINDOW;

pub(crate) fn rate_bucket(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

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
