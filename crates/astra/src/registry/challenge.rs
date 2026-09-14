//! Single-use challenges for the public status and recovery routes.
//!
//! Nothing here touches the registry or its file: the store is in memory, it
//! is bounded, and it is dropped with the process.

use std::collections::BTreeMap;

/// Lifetime of a public status challenge: 60 seconds, single use (spec §8.2).
pub const CHALLENGE_LIFETIME_SECS: u64 = 60;

/// Single-use challenges for the public status and recovery routes.
///
/// In memory and bounded: a challenge is a permission to spend one signature
/// verification, not a durable object. Restarting Astra invalidates the ones
/// in flight, which is the correct outcome — the client simply asks again.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    issued: BTreeMap<[u8; 32], u64>,
    capacity: usize,
}

impl ChallengeStore {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            issued: BTreeMap::new(),
            capacity,
        }
    }

    /// Records a freshly generated challenge.
    ///
    /// Returns `false` when the store is full: refusing is better than
    /// evicting, because eviction would let a flood of requests invalidate
    /// the challenges of legitimate clients.
    pub fn issue(&mut self, challenge: [u8; 32], now_unix: u64) -> bool {
        self.expire(now_unix);
        if self.issued.len() >= self.capacity {
            return false;
        }
        self.issued
            .insert(challenge, now_unix + CHALLENGE_LIFETIME_SECS);
        true
    }

    /// Consumes a challenge exactly once.
    pub fn consume(&mut self, challenge: &[u8; 32], now_unix: u64) -> bool {
        self.expire(now_unix);
        match self.issued.remove(challenge) {
            Some(expires_at) => now_unix < expires_at,
            None => false,
        }
    }

    fn expire(&mut self, now_unix: u64) {
        self.issued.retain(|_, expires_at| now_unix < *expires_at);
    }
}
