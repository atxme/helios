//! Time, generations and the renewal window — spec §4.
//!
//! Three rules that every object in this module depends on, and that are
//! written once here so no verifier restates them slightly differently:
//!
//! - a transition window is `not_before < activation_at < not_after`, with an
//!   overlap of at most 30 days;
//! - a generation counter moves by exactly one; equal is a replay only if the
//!   signed bytes are identical, lower is a rollback, higher is a skip;
//! - the renewal window opens at 80 % of the *cryptographic* validity of the
//!   active leaf, computed with checked arithmetic.
//!
//! Every comparison takes the clock as an argument. The caller reads it
//! **once** per validation and passes the same value everywhere: a validator
//! that reads the clock twice can accept a window whose start it checked
//! against one instant and whose end it checked against another.

use serde::{Deserialize, Serialize};

use super::CertificateError;

/// Widest overlap between an outgoing and an incoming identity: 30 days.
pub const MAX_OVERLAP_SECS: u64 = 2_592_000;

/// Longest lease a client staging may hold the `next` slot: 24 hours.
pub const MAX_STAGE_LEASE_SECS: u64 = 24 * 3600;

/// Longest life of a certificate request before it must be reissued.
pub const MAX_REQUEST_LIFETIME_SECS: u64 = 24 * 3600;

/// Longest life of an expired-identity recovery request: five minutes.
pub const MAX_RECOVERY_REQUEST_LIFETIME_SECS: u64 = 300;

/// Percentage of the validity elapsed when the ordinary renewal window opens.
pub const RENEWAL_OPENS_AT_PERCENT: u64 = 80;

/// Fraction elapsed past which an unfinished renewal is a persistent alert.
pub const RENEWAL_WARNING_PERCENT: u64 = 90;

/// Fraction elapsed past which an unfinished renewal is critical.
pub const RENEWAL_CRITICAL_PERCENT: u64 = 95;

/// The three instants of a transition, checked together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionWindow {
    pub not_before: u64,
    pub activation_at: u64,
    pub not_after: u64,
}

/// Where a window sits relative to one reading of the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowPhase {
    /// Before `not_before`: the object is future and is not installed.
    Future,
    /// Between `not_before` and `activation_at`: prepared, never served.
    Prepared,
    /// Between `activation_at` and `not_after`: both identities acceptable.
    Overlap,
    /// At `not_after`: the incoming identity is the only one left.
    Promoted,
}

impl TransitionWindow {
    pub fn new(
        not_before: u64,
        activation_at: u64,
        not_after: u64,
    ) -> Result<Self, CertificateError> {
        let window = Self {
            not_before,
            activation_at,
            not_after,
        };
        window.validate()?;
        Ok(window)
    }

    /// Refuses a window before anything is written (spec §4.1).
    ///
    /// The overlap is bounded on both sides: strictly positive, because a
    /// transition with no overlap cuts every client that has not yet observed
    /// it; and at most 30 days, because during the overlap two identities are
    /// acceptable and that surface must not be open indefinitely.
    pub fn validate(&self) -> Result<(), CertificateError> {
        if !(self.not_before < self.activation_at && self.activation_at < self.not_after) {
            return Err(CertificateError::InvalidWindow);
        }
        let overlap = self
            .not_after
            .checked_sub(self.activation_at)
            .ok_or(CertificateError::InvalidWindow)?;
        if overlap > MAX_OVERLAP_SECS {
            return Err(CertificateError::OverlapTooLong {
                overlap_secs: overlap,
                maximum_secs: MAX_OVERLAP_SECS,
            });
        }
        Ok(())
    }

    pub fn phase(&self, now_unix: u64) -> WindowPhase {
        if now_unix < self.not_before {
            WindowPhase::Future
        } else if now_unix < self.activation_at {
            WindowPhase::Prepared
        } else if now_unix < self.not_after {
            WindowPhase::Overlap
        } else {
            WindowPhase::Promoted
        }
    }

    pub fn overlap_secs(&self) -> u64 {
        self.not_after.saturating_sub(self.activation_at)
    }
}

/// Validity period of one certificate, as the issuer wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityPeriod {
    pub not_before: u64,
    pub not_after: u64,
}

impl ValidityPeriod {
    pub fn new(not_before: u64, not_after: u64) -> Result<Self, CertificateError> {
        let period = Self {
            not_before,
            not_after,
        };
        period.validate()?;
        Ok(period)
    }

    pub fn validate(&self) -> Result<(), CertificateError> {
        if self.not_after <= self.not_before {
            return Err(CertificateError::InvalidValidityPeriod);
        }
        Ok(())
    }

    pub fn lifetime_secs(&self) -> Result<u64, CertificateError> {
        self.not_after
            .checked_sub(self.not_before)
            .filter(|lifetime| *lifetime > 0)
            .ok_or(CertificateError::InvalidValidityPeriod)
    }

    pub fn contains(&self, now_unix: u64) -> bool {
        self.not_before <= now_unix && now_unix < self.not_after
    }

    /// Instant at which the ordinary renewal window opens (spec §4.3).
    ///
    /// ```text
    /// renewal_at = not_before + floor(lifetime * 80 / 100)
    /// ```
    ///
    /// Every step is checked, and the result is asserted to stay strictly
    /// before `not_after`: a saturating multiplication on a certificate with an
    /// absurd `not_after` would otherwise place the renewal *after* the
    /// expiry it exists to prevent.
    pub fn renewal_at(&self) -> Result<u64, CertificateError> {
        self.fraction_at(RENEWAL_OPENS_AT_PERCENT)
    }

    /// Instant at which an unfinished renewal becomes a persistent alert.
    pub fn warning_at(&self) -> Result<u64, CertificateError> {
        self.fraction_at(RENEWAL_WARNING_PERCENT)
    }

    /// Instant at which an unfinished renewal becomes critical.
    pub fn critical_at(&self) -> Result<u64, CertificateError> {
        self.fraction_at(RENEWAL_CRITICAL_PERCENT)
    }

    fn fraction_at(&self, percent: u64) -> Result<u64, CertificateError> {
        let lifetime = self.lifetime_secs()?;
        let elapsed = lifetime
            .checked_mul(percent)
            .ok_or(CertificateError::ArithmeticOverflow)?
            / 100;
        let instant = self
            .not_before
            .checked_add(elapsed)
            .ok_or(CertificateError::ArithmeticOverflow)?;
        if instant >= self.not_after {
            return Err(CertificateError::ArithmeticOverflow);
        }
        Ok(instant)
    }

    /// How far into its validity the certificate is, in percent, capped at 100.
    ///
    /// Used by the interfaces to say `renewal_due`, `warning` or `critical`
    /// without each of them redoing the arithmetic.
    pub fn elapsed_percent(&self, now_unix: u64) -> Result<u64, CertificateError> {
        let lifetime = self.lifetime_secs()?;
        if now_unix <= self.not_before {
            return Ok(0);
        }
        let elapsed = now_unix - self.not_before;
        if elapsed >= lifetime {
            return Ok(100);
        }
        Ok(elapsed
            .checked_mul(100)
            .ok_or(CertificateError::ArithmeticOverflow)?
            / lifetime)
    }

    /// Where this certificate sits on the renewal ladder, at one reading of
    /// the clock.
    ///
    /// Every interface that reports a leaf answers this question, and each one
    /// answering it for itself is how a console and a planner end up
    /// disagreeing about the same certificate. The thresholds are the
    /// protocol's own — 80 / 90 / 95 % — so a screen that says *renouvellement
    /// dû* is saying exactly what opens the window.
    ///
    /// A period so short that `fraction_at` overflows falls back to
    /// `not_after`: the phase then degrades to [`ValidityPhase::Valid`] until
    /// expiry rather than raising. This is a display, and a certificate whose
    /// arithmetic does not hold is refused where it is *installed*, not here.
    pub fn phase(&self, now_unix: u64) -> ValidityPhase {
        if now_unix < self.not_before {
            return ValidityPhase::NotYetValid;
        }
        if now_unix >= self.not_after {
            return ValidityPhase::Expired;
        }
        if now_unix >= self.critical_at().unwrap_or(self.not_after) {
            ValidityPhase::Critical
        } else if now_unix >= self.warning_at().unwrap_or(self.not_after) {
            ValidityPhase::Warning
        } else if now_unix >= self.renewal_at().unwrap_or(self.not_after) {
            ValidityPhase::RenewalDue
        } else {
            ValidityPhase::Valid
        }
    }
}

/// Where a certificate stands on the renewal ladder of spec §4.3.
///
/// Shared by every surface that reports a leaf — the Helios console, Orion's
/// inventory, the planner — because the alternative is each of them writing
/// the same three comparisons and one of them eventually writing `>` where the
/// others wrote `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityPhase {
    /// Prepared for later: its validity has not started.
    NotYetValid,
    Valid,
    /// Past 80 %: the renewal window is open.
    RenewalDue,
    /// Past 90 %.
    Warning,
    /// Past 95 %.
    Critical,
    Expired,
}

/// What a proposed generation is, relative to the persisted one (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationStep {
    /// Exactly `current + 1`: the only value an ordinary transition carries.
    Sequential,
    /// Equal to `current`: a replay, idempotent **only** if the signed bytes
    /// are byte-for-byte identical. The caller still has to compare them.
    Repeat,
}

/// Classifies a proposed generation, refusing rollbacks and skips.
///
/// A skip is refused rather than tolerated: the intermediate transitions carry
/// decisions — an abort tombstone, a CA change — that a client which jumped
/// over them never persisted. Accepting `current + 2` would leave two ends
/// disagreeing about what happened in between.
pub fn classify_generation(
    current: u64,
    proposed: u64,
) -> Result<GenerationStep, CertificateError> {
    if proposed == current {
        return Ok(GenerationStep::Repeat);
    }
    if proposed < current {
        return Err(CertificateError::GenerationRollback { current, proposed });
    }
    let expected = current
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;
    if proposed != expected {
        return Err(CertificateError::GenerationSkipped {
            current,
            proposed,
            expected,
        });
    }
    Ok(GenerationStep::Sequential)
}

/// Requires exactly `current + 1`, with no idempotent replay accepted.
///
/// Used where a repeat has no meaning — a fresh issuance rather than the
/// installation of a distributed object.
pub fn require_next_generation(current: u64, proposed: u64) -> Result<(), CertificateError> {
    match classify_generation(current, proposed)? {
        GenerationStep::Sequential => Ok(()),
        GenerationStep::Repeat => Err(CertificateError::GenerationConflict {
            generation: proposed,
        }),
    }
}

/// Checks a lease: positive, bounded, and inside every deadline it depends on.
///
/// `bounds` are the instants the lease must not outlive — a request's own
/// expiry and the activation of the transition it prepares (spec §7.2).
pub fn validate_lease(
    issued_at: u64,
    expires_at: u64,
    maximum_secs: u64,
    bounds: &[u64],
) -> Result<(), CertificateError> {
    if expires_at <= issued_at {
        return Err(CertificateError::InvalidLease);
    }
    let duration = expires_at - issued_at;
    if duration > maximum_secs {
        return Err(CertificateError::LeaseTooLong {
            duration_secs: duration,
            maximum_secs,
        });
    }
    if bounds.iter().any(|bound| expires_at > *bound) {
        return Err(CertificateError::InvalidLease);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(not_before: u64, activation_at: u64, not_after: u64) -> TransitionWindow {
        TransitionWindow {
            not_before,
            activation_at,
            not_after,
        }
    }

    #[test]
    fn a_window_must_be_strictly_ordered() {
        assert!(window(10, 20, 30).validate().is_ok());
        for invalid in [
            window(20, 20, 30),
            window(10, 30, 30),
            window(30, 20, 10),
            window(10, 5, 30),
        ] {
            assert!(
                matches!(invalid.validate(), Err(CertificateError::InvalidWindow)),
                "accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn an_overlap_longer_than_thirty_days_is_refused() {
        let exact = window(0, 1, 1 + MAX_OVERLAP_SECS);
        assert!(exact.validate().is_ok());
        let too_long = window(0, 1, 2 + MAX_OVERLAP_SECS);
        assert!(matches!(
            too_long.validate(),
            Err(CertificateError::OverlapTooLong { .. })
        ));
    }

    #[test]
    fn each_phase_of_a_window_is_named_by_one_clock_reading() {
        let window = window(10, 20, 30);
        assert_eq!(window.phase(9), WindowPhase::Future);
        assert_eq!(window.phase(10), WindowPhase::Prepared);
        assert_eq!(window.phase(19), WindowPhase::Prepared);
        assert_eq!(window.phase(20), WindowPhase::Overlap);
        assert_eq!(window.phase(29), WindowPhase::Overlap);
        assert_eq!(window.phase(30), WindowPhase::Promoted);
        assert_eq!(window.phase(u64::MAX), WindowPhase::Promoted);
    }

    /// The 80 % arithmetic of spec §4.3, including the shape that overflows.
    #[test]
    fn the_renewal_instant_is_eighty_percent_of_the_validity() {
        let period = ValidityPeriod::new(1_000, 1_100).expect("period");
        assert_eq!(period.renewal_at().expect("renewal"), 1_080);
        assert_eq!(period.warning_at().expect("warning"), 1_090);
        assert_eq!(period.critical_at().expect("critical"), 1_095);

        // Rounds down, and never lands on the expiry itself.
        let odd = ValidityPeriod::new(0, 3).expect("period");
        assert_eq!(odd.renewal_at().expect("renewal"), 2);
    }

    #[test]
    fn a_validity_period_that_would_overflow_is_refused_rather_than_saturated() {
        // `lifetime * 80` overflows well before `lifetime` itself does, which
        // is exactly the multiplication a saturating implementation would hide.
        let period = ValidityPeriod::new(0, u64::MAX).expect("period");
        assert!(matches!(
            period.renewal_at(),
            Err(CertificateError::ArithmeticOverflow)
        ));
        assert!(matches!(
            ValidityPeriod::new(10, 10),
            Err(CertificateError::InvalidValidityPeriod)
        ));
        assert!(matches!(
            ValidityPeriod::new(11, 10),
            Err(CertificateError::InvalidValidityPeriod)
        ));
    }

    #[test]
    fn elapsed_percent_is_clamped_at_both_ends() {
        let period = ValidityPeriod::new(100, 200).expect("period");
        assert_eq!(period.elapsed_percent(50).expect("percent"), 0);
        assert_eq!(period.elapsed_percent(150).expect("percent"), 50);
        assert_eq!(period.elapsed_percent(1_000).expect("percent"), 100);
    }

    #[test]
    fn a_generation_moves_by_exactly_one() {
        assert_eq!(
            classify_generation(4, 5).expect("sequential"),
            GenerationStep::Sequential
        );
        assert_eq!(
            classify_generation(4, 4).expect("repeat"),
            GenerationStep::Repeat
        );
        assert!(matches!(
            classify_generation(4, 3),
            Err(CertificateError::GenerationRollback { .. })
        ));
        assert!(matches!(
            classify_generation(4, 6),
            Err(CertificateError::GenerationSkipped { .. })
        ));
    }

    /// A counter one step from the end of its space must not wrap.
    #[test]
    fn a_generation_near_the_maximum_refuses_instead_of_wrapping() {
        assert!(matches!(
            classify_generation(u64::MAX, 0),
            Err(CertificateError::GenerationRollback { .. })
        ));
        assert!(matches!(
            classify_generation(u64::MAX, u64::MAX),
            Ok(GenerationStep::Repeat)
        ));
    }

    #[test]
    fn a_repeat_is_a_conflict_where_replay_has_no_meaning() {
        assert!(require_next_generation(4, 5).is_ok());
        assert!(matches!(
            require_next_generation(4, 4),
            Err(CertificateError::GenerationConflict { .. })
        ));
    }

    #[test]
    fn a_lease_is_bounded_by_its_duration_and_by_every_deadline_it_depends_on() {
        assert!(validate_lease(100, 200, MAX_STAGE_LEASE_SECS, &[300, 400]).is_ok());
        assert!(matches!(
            validate_lease(100, 100, MAX_STAGE_LEASE_SECS, &[]),
            Err(CertificateError::InvalidLease)
        ));
        assert!(matches!(
            validate_lease(0, MAX_STAGE_LEASE_SECS + 1, MAX_STAGE_LEASE_SECS, &[]),
            Err(CertificateError::LeaseTooLong { .. })
        ));
        assert!(matches!(
            validate_lease(100, 200, MAX_STAGE_LEASE_SECS, &[150]),
            Err(CertificateError::InvalidLease)
        ));
    }
}
