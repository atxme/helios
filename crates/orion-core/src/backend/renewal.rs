//! When the negotiated PSK is renewed (design 2026-10-09 §2).
//!
//! At 80 % of its lifetime or of its byte ceiling, whichever comes first. The
//! gateway reclaims at 100 %; the remaining 20 % is the room failed renewals
//! are retried in.

use std::time::{Duration, Instant, SystemTime};

use aether::key_negotiation::{psk_renewal_after_bytes, psk_renewal_after_secs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalTrigger {
    Lifetime,
    Volume,
    Manual,
}

impl RenewalTrigger {
    /// The cause, as the event log names it.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Lifetime => "durée de vie à 80 %",
            Self::Volume => "volume à 80 %",
            Self::Manual => "demande manuelle",
        }
    }
}

/// Age and transfer of the PSK in place, measured from its commit.
#[derive(Debug, Clone)]
pub struct RenewalClock {
    committed_at: Instant,
    committed_wall: SystemTime,
    bytes_baseline: Option<u64>,
    /// The previous reading, to tell a counter that went backwards (peer
    /// re-created) from one that is merely below the baseline.
    last_bytes: Option<u64>,
}

impl RenewalClock {
    pub fn start(now: Instant, wall: SystemTime, bytes: Option<u64>) -> Self {
        Self {
            committed_at: now,
            committed_wall: wall,
            bytes_baseline: bytes,
            last_bytes: bytes,
        }
    }

    /// Is a renewal due, and why?
    ///
    /// Two clocks, the earliest deadline wins (spec §12.3): the monotonic one
    /// may skip a suspend, the wall one may be moved back. A wall clock behind
    /// the commit reads as no time at all, never as a later deadline.
    pub fn due(
        &mut self,
        now: Instant,
        wall: SystemTime,
        bytes: Option<u64>,
    ) -> Option<RenewalTrigger> {
        let monotonic = now.saturating_duration_since(self.committed_at);
        let walled = wall
            .duration_since(self.committed_wall)
            .unwrap_or(Duration::ZERO);
        if monotonic.max(walled) >= Duration::from_secs(psk_renewal_after_secs()) {
            return Some(RenewalTrigger::Lifetime);
        }
        let total = bytes?;
        let went_backwards = self.last_bytes.is_some_and(|last| total < last);
        self.last_bytes = Some(total);
        match self.bytes_baseline {
            Some(baseline) if total >= baseline && !went_backwards => {
                (total - baseline >= psk_renewal_after_bytes()).then_some(RenewalTrigger::Volume)
            }
            // First reading, or a counter that went backwards: count from here.
            _ => {
                self.bytes_baseline = Some(total);
                None
            }
        }
    }
}

/// Upper bound between two renewal attempts.
pub const RETRY_CEILING: Duration = Duration::from_secs(15 * 60);

/// Pause before attempt `failures + 1`: 1, 2, 4, 8, then 15 minutes.
pub fn retry_delay(failures: u32) -> Duration {
    let minutes = 1u64
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_secs(minutes.saturating_mul(60)).min(RETRY_CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn clock() -> (RenewalClock, Instant, SystemTime) {
        let now = Instant::now();
        let wall = SystemTime::now();
        (RenewalClock::start(now, wall, Some(0)), now, wall)
    }

    #[test]
    fn nothing_is_due_before_eighty_percent() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_119);
        assert_eq!(clock.due(now + later, wall + later, Some(79 * GIB)), None);
    }

    #[test]
    fn the_lifetime_triggers_at_nineteen_hours_twelve() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_120);
        assert_eq!(
            clock.due(now + later, wall + later, Some(0)),
            Some(RenewalTrigger::Lifetime)
        );
    }

    #[test]
    fn a_suspend_seen_only_by_the_wall_clock_still_counts() {
        let (mut clock, now, wall) = clock();
        let asleep = Duration::from_secs(70_000);
        assert_eq!(
            clock.due(now + Duration::from_secs(10), wall + asleep, Some(0)),
            Some(RenewalTrigger::Lifetime)
        );
    }

    #[test]
    fn a_wall_clock_moved_back_never_delays_the_deadline() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_120);
        assert_eq!(
            clock.due(now + later, wall - Duration::from_secs(3600), Some(0)),
            Some(RenewalTrigger::Lifetime)
        );
    }

    #[test]
    fn the_volume_triggers_at_eighty_gib() {
        let (mut clock, now, wall) = clock();
        assert_eq!(
            clock.due(now, wall, Some(80 * GIB)),
            Some(RenewalTrigger::Volume)
        );
    }

    #[test]
    fn an_unreadable_counter_only_leaves_the_lifetime() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut clock = RenewalClock::start(now, wall, None);
        assert_eq!(clock.due(now, wall, None), None);
        assert_eq!(
            clock.due(now, wall, Some(500 * GIB)),
            None,
            "first reading is a baseline"
        );
        assert_eq!(
            clock.due(now, wall, Some(580 * GIB)),
            Some(RenewalTrigger::Volume)
        );
    }

    #[test]
    fn a_counter_that_went_backwards_rebases() {
        let (mut clock, now, wall) = clock();
        clock.due(now, wall, Some(70 * GIB));
        assert_eq!(clock.due(now, wall, Some(GIB)), None);
        assert_eq!(
            clock.due(now, wall, Some(80 * GIB)),
            None,
            "79 GiB since the rebase"
        );
    }

    #[test]
    fn retries_back_off_up_to_fifteen_minutes() {
        let minutes: Vec<u64> = (1..=7).map(|n| retry_delay(n).as_secs() / 60).collect();
        assert_eq!(minutes, vec![1, 2, 4, 8, 15, 15, 15]);
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(15 * 60));
    }
}
