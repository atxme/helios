//! PSK rotation without bricking the peer (ADR-001, "PSK rotation without a brick").
//!
//! # The trap
//!
//! WireGuard has **only one PSK slot per peer**. It's impossible to accept
//! the old and the new one at the same time: there is no "make-before-break".
//! If the two ends fall out of sync, the handshake fails, the tunnel drops —
//! and with it the control channel that would have allowed resynchronizing.
//! On a remote appliance, this means a physical intervention.
//!
//! # The fix: local revert on timeout
//!
//! Changing a live peer's PSK **does not break the ongoing session**: the
//! session keys are already derived. The new PSK is only used at the next
//! handshake, ≤ 2 min later. Each end then applies, **without needing to
//! communicate**:
//!
//! > no successful handshake [`REVERT_AFTER`] after installing `PSK_new`
//! > → revert to `PSK_old`.
//!
//! Two local, deterministic timers converge to the same state. The worst
//! case is a temporary denial of service, never a brick nor a leak.
//!
//! Time is **injected** (`now`) rather than read from the clock: the logic
//! is thus entirely deterministic and testable without waiting three minutes.

use std::time::Duration;

use aether::enroll::Psk;

/// Delay beyond which an unconfirmed PSK is abandoned.
///
/// 180 s = WireGuard's `REJECT_AFTER_TIME`: past this delay, if no handshake
/// has succeeded, it's because the new PSK isn't shared by the peer.
pub const REVERT_AFTER: Duration = Duration::from_secs(180);

/// Rotation state for a given peer.
#[derive(Debug, Default)]
pub enum RotationState {
    /// No PSK installed (classical tunnel only, not yet PQ-upgraded).
    #[default]
    None,
    /// A PSK confirmed by at least one successful handshake.
    Stable { psk: Psk },
    /// A new PSK installed, awaiting confirmation.
    Pending {
        new_psk: Psk,
        /// Kept so we can roll back. `None` if we started from nothing.
        previous: Option<Psk>,
        /// Age of the installation, fed by the caller.
        installed_since: Duration,
    },
}

/// What the caller must apply to the data plane after a transition.
#[derive(Debug, PartialEq, Eq)]
pub enum RotationAction {
    /// Nothing to do.
    Nothing,
    /// Install this PSK on the peer (base64), or remove it if `None`.
    InstallPsk(Option<String>),
}

impl RotationState {
    /// Currently active PSK, if there is one.
    pub fn active(&self) -> Option<&Psk> {
        match self {
            RotationState::None => None,
            RotationState::Stable { psk } => Some(psk),
            // While pending, it is indeed the new one that is installed on the peer.
            RotationState::Pending { new_psk, .. } => Some(new_psk),
        }
    }

    /// Is a rotation currently awaiting confirmation?
    pub fn is_pending(&self) -> bool {
        matches!(self, RotationState::Pending { .. })
    }

    /// Installs a new PSK coming from a provisioning.
    ///
    /// The old one is kept: as long as the new one isn't confirmed by a
    /// handshake, we must be able to fall back to it.
    pub fn install(&mut self, new_psk: Psk) -> RotationAction {
        let previous = match std::mem::replace(self, RotationState::None) {
            RotationState::None => None,
            RotationState::Stable { psk } => Some(psk),
            // Rotation during a rotation: keep the *confirmed* old one, not
            // the never-validated intermediate one — otherwise a revert
            // would take us back to a PSK we don't know works.
            RotationState::Pending { previous, .. } => previous,
        };

        let action = RotationAction::InstallPsk(Some(aether::enroll::psk_to_base64(&new_psk)));
        *self = RotationState::Pending {
            new_psk,
            previous,
            installed_since: Duration::ZERO,
        };
        action
    }

    /// A handshake succeeded: the active PSK is confirmed.
    ///
    /// **Idempotent.** The poller signals a fresh handshake on every tick:
    /// this method must only touch the state if there is actually a
    /// rotation to confirm. Taking the state unconditionally (`mem::replace`)
    /// would lose the PSK starting on the second call.
    pub fn on_handshake_success(&mut self) -> RotationAction {
        if !self.is_pending() {
            return RotationAction::Nothing;
        }
        if let RotationState::Pending { new_psk, .. } = std::mem::replace(self, RotationState::None)
        {
            *self = RotationState::Stable { psk: new_psk };
        }
        RotationAction::Nothing
    }

    /// Advances time. To be called from the polling loop.
    ///
    /// Returns the action to apply: a revert if the delay is exceeded.
    pub fn tick(&mut self, elapsed: Duration) -> RotationAction {
        let RotationState::Pending {
            previous,
            installed_since,
            ..
        } = self
        else {
            return RotationAction::Nothing;
        };

        *installed_since += elapsed;
        if *installed_since < REVERT_AFTER {
            return RotationAction::Nothing;
        }

        // Delay exceeded without a handshake: the peer manifestly doesn't
        // have the same PSK. Revert to the previous state, which did work.
        let previous = previous.take();
        let action =
            RotationAction::InstallPsk(previous.as_ref().map(aether::enroll::psk_to_base64));
        *self = match previous {
            Some(psk) => RotationState::Stable { psk },
            None => RotationState::None,
        };
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn psk(b: u8) -> Psk {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn installation_then_confirmation() {
        let mut st = RotationState::default();
        assert!(st.active().is_none());

        let action = st.install(psk(1));
        assert!(matches!(action, RotationAction::InstallPsk(Some(_))));
        assert!(st.is_pending());
        assert_eq!(**st.active().unwrap(), [1u8; 32]);

        st.on_handshake_success();
        assert!(!st.is_pending(), "a successful handshake confirms the PSK");
        assert_eq!(**st.active().unwrap(), [1u8; 32]);
    }

    /// The core of the anti-brick fix: without confirmation, we revert alone
    /// to the previous state, with no need to talk to the peer.
    #[test]
    fn automatic_revert_without_a_handshake() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success(); // PSK 1 confirmed

        st.install(psk(2)); // rotation to PSK 2
        assert_eq!(**st.active().unwrap(), [2u8; 32]);

        // Before the delay: we wait, nothing moves.
        assert_eq!(st.tick(Duration::from_secs(179)), RotationAction::Nothing);
        assert!(st.is_pending());

        // Delay exceeded without a handshake: revert to the PSK that worked.
        let action = st.tick(Duration::from_secs(2));
        assert!(matches!(action, RotationAction::InstallPsk(Some(_))));
        assert_eq!(
            **st.active().unwrap(),
            [1u8; 32],
            "reverted to the confirmed PSK"
        );
        assert!(!st.is_pending());
    }

    #[test]
    fn confirmation_just_before_the_delay_cancels_the_revert() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success();
        st.install(psk(2));

        st.tick(Duration::from_secs(179));
        st.on_handshake_success(); // the peer does have PSK 2

        // Time keeps passing: no revert must ever occur again.
        assert_eq!(st.tick(Duration::from_secs(600)), RotationAction::Nothing);
        assert_eq!(**st.active().unwrap(), [2u8; 32]);
    }

    /// First PSK never confirmed: the revert must remove the PSK and go
    /// back to the classical tunnel, not install a nonexistent PSK.
    #[test]
    fn revert_from_nothing_removes_the_psk() {
        let mut st = RotationState::default();
        st.install(psk(1));
        let action = st.tick(REVERT_AFTER);
        assert_eq!(
            action,
            RotationAction::InstallPsk(None),
            "with no prior PSK, the PSK is removed and the tunnel stays classical"
        );
        assert!(st.active().is_none());
    }

    /// A rotation that overwrites another must not use a never-validated PSK
    /// as a safety net: we keep the last *confirmed* PSK.
    #[test]
    fn rotation_during_rotation_keeps_the_last_confirmed_psk() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success(); // 1 confirmed

        st.install(psk(2)); // never confirmed
        st.install(psk(3)); // overwrites 2

        st.tick(REVERT_AFTER);
        assert_eq!(
            **st.active().unwrap(),
            [1u8; 32],
            "the revert must fall back to the last actually validated PSK"
        );
    }

    /// The poller signals a fresh handshake on EVERY tick (every 10 s):
    /// confirming an already-confirmed PSK must absolutely not lose it.
    #[test]
    fn repeated_confirmations_are_idempotent() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success();
        assert_eq!(**st.active().unwrap(), [1u8; 32]);

        for _ in 0..5 {
            st.on_handshake_success();
            assert_eq!(
                **st.active().expect("the confirmed PSK must never disappear"),
                [1u8; 32]
            );
        }
    }

    #[test]
    fn tick_without_an_ongoing_rotation_does_nothing() {
        let mut st = RotationState::default();
        assert_eq!(st.tick(Duration::from_secs(999)), RotationAction::Nothing);

        st.install(psk(1));
        st.on_handshake_success();
        assert_eq!(st.tick(Duration::from_secs(999)), RotationAction::Nothing);
    }
}
