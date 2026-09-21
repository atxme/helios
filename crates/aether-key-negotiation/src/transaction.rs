use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::server::NegotiationHandler;

/// The absolute lifetime of one connection, as a point in time.
///
/// Each phase clamps its own timeout against what is left of it, so the
/// ceiling is normally reached on an ordinary code path — one that rolls
/// back, answers, and releases its permit. The `timeout` wrapping the whole
/// connection stays as a backstop, but it must not be the mechanism that
/// usually fires: destroying a future runs no code.
#[derive(Clone, Copy)]
pub(crate) struct Deadline(pub(crate) Instant);

impl Deadline {
    pub(crate) fn starting_now() -> Self {
        Self(Instant::now() + crate::MAX_CONNECTION_LIFETIME)
    }

    /// `phase`, or whatever is left of the connection's life, whichever is
    /// shorter. Zero once the ceiling has passed, which every `timeout`
    /// treats as an immediate expiry.
    pub(crate) fn clamp(self, phase: Duration) -> Duration {
        phase.min(self.remaining())
    }

    pub(crate) fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
}

/// Undoes an unresolved transaction even when the task carrying it is
/// destroyed rather than returned from.
///
/// # Why the ordinary exit paths are not enough
///
/// Every exit from `handle_connection` already rolls back. None of them
/// runs when the future is **dropped**, and one is dropped on purpose: the
/// `timeout` enforcing the 90-second ceiling. The interval that matters is
/// the wait for the confirmation — up to 45 seconds in which nothing happens
/// but the client thinking. A connection destroyed there used to leave the
/// candidate PSK posed, the peer reserved and the transaction in the active
/// table with nothing left to resolve it: that peer could not negotiate again
/// until the daemon restarted, and reaching the state cost an admitted client
/// one connection it simply never finished.
///
/// # Why it spawns
///
/// `Drop` cannot await. The rollback is guarded by the transaction identifier
/// the slot itself carries, so running it a moment late is a no-op rather
/// than a write — which is what makes detaching it safe.
pub(crate) struct RollbackGuard {
    handler: Arc<dyn NegotiationHandler>,
    transaction_id: [u8; 16],
    public_key: String,
    armed: bool,
}

impl RollbackGuard {
    pub(crate) fn arm(
        handler: Arc<dyn NegotiationHandler>,
        transaction_id: [u8; 16],
        public_key: String,
    ) -> Self {
        Self {
            handler,
            transaction_id,
            public_key,
            armed: true,
        }
    }

    /// Rolls back now, waiting for it, and disarms **once it has returned**.
    ///
    /// The order is the whole point. Disarming first — the obvious way to
    /// write this — reopens the hole the guard exists to close: the rollback
    /// is an `await`, the absolute ceiling can destroy the task inside it, and
    /// `Drop` would then find a guard that has already declared itself done.
    /// The candidate would stay posed with no record of it.
    ///
    /// This makes a double rollback possible, and that is fine: undoing is
    /// keyed on the identifier the slot itself carries, so the second call
    /// finds a slot that is no longer its own and writes nothing.
    pub(crate) async fn roll_back(&mut self) {
        if !self.armed {
            return;
        }
        self.handler
            .rollback(self.transaction_id, &self.public_key)
            .await;
        self.armed = false;
    }

    /// The commit is signed. There is nothing left that may be undone.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(
            transaction = %hex::encode(self.transaction_id),
            peer = %self.public_key,
            "connection destroyed with a candidate PSK posed; rolling back out of band"
        );
        let handler = Arc::clone(&self.handler);
        let transaction_id = self.transaction_id;
        let public_key = std::mem::take(&mut self.public_key);
        // `Handle::try_current` rather than `tokio::spawn`, which panics with
        // no runtime. There is one here in every case that matters; during
        // shutdown there may not be, and a panic inside `Drop` would be a
        // worse outcome than a slot the next start clears anyway.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { handler.rollback(transaction_id, &public_key).await });
        }
    }
}
