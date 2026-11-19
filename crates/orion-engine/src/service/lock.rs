//! The lock state machine: a session or power event locks every `nomade`
//! profile again, and takes down the tunnel that was mounted with one.
//!
//! A `service` tunnel is left alone: its manifest was never sealed under a
//! passphrase, and nothing a lock forgets applies to it.

use std::sync::atomic::Ordering;

use orion_core::{
    vault::{registry::ProfileMode, VaultError},
    ClientConfig,
};

use super::EngineService;
use crate::events::EventQueue;

/// What the platform reported. Each one locks the `nomade` profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    SessionLock,
    SessionLogoff,
    SessionDisconnect,
    Suspend,
    EngineExit,
}

impl EngineService {
    /// Locks every `nomade` profile, and takes down the tunnel if it is one.
    ///
    /// The order is the security order. The lock generation moves first, so an
    /// unlock whose dialog is still open refuses to keep its key. The tunnel
    /// comes down before the keys are forgotten. Last, the configuration is
    /// read again: forgetting the keys leaves the profiles in memory, and a
    /// profile the engine still holds is one it could connect without asking.
    pub async fn on_lock_event(&self, event: LockEvent, events: &EventQueue) {
        self.lock_generation.fetch_add(1, Ordering::AcqRel);
        if self.mounted_profile_is_nomad().await {
            // A failed disconnection is already on the event stream: the
            // controller reports it there. The keys are forgotten either way.
            let _ = self.stop_connection(events.sink()).await;
        }
        self.drop_unlocked_keys().await;
        tracing::info!(event = ?event, "nomad profiles locked");
    }

    /// Forgets every unlocked key, and reads the configuration again.
    ///
    /// Forgetting the keys leaves the profiles in memory, and a profile the
    /// engine still holds is one it could connect without asking. Callers must
    /// not hold the configuration lock.
    pub(super) async fn drop_unlocked_keys(&self) {
        self.store.forget_unlocked();
        if self.reload_config().await.is_err() {
            // The store cannot be read without its root, and the profiles it
            // would return are the ones still in memory. Dropping them all
            // keeps a nomad key out of memory; the next reload restores them.
            *self.config.lock().await = ClientConfig::default();
        }
    }

    /// The lock generation now. Read before a passphrase dialog, then checked
    /// with [`Self::lock_landed_since`] once the store has been written.
    pub(super) fn generation(&self) -> u64 {
        self.lock_generation.load(Ordering::Acquire)
    }

    /// Whether a lock event has landed since `generation` was read.
    pub(super) fn lock_landed_since(&self, generation: u64) -> bool {
        self.generation() != generation
    }

    /// Drops the keys a gesture took after a lock, and returns the refusal.
    ///
    /// The store took its key after the lock had already forgotten the keys,
    /// so the one it holds now is the one to drop.
    pub(super) async fn refuse_locked(&self, name: &str) -> String {
        self.drop_unlocked_keys().await;
        VaultError::ProfileLocked(name.to_string()).to_string()
    }

    /// Settles a gesture that asked for a passphrase: a lock that landed in the
    /// meantime wins, whatever the gesture's own outcome. Callers must not hold
    /// the configuration lock.
    pub(super) async fn settle_gesture<T>(
        &self,
        name: &str,
        generation: u64,
        outcome: Result<T, String>,
    ) -> Result<T, String> {
        if self.lock_landed_since(generation) {
            return Err(self.refuse_locked(name).await);
        }
        outcome
    }

    /// Turns the store's lock watch on or off. Off, an unlock is refused.
    pub fn set_lock_watch(&self, active: bool) {
        self.store.set_lock_watch(active);
    }

    /// Whether the tunnel mounted now belongs to a `nomade` profile.
    ///
    /// A registry that cannot be read counts as nomad: the tunnel is taken
    /// down rather than left up on a guess.
    async fn mounted_profile_is_nomad(&self) -> bool {
        let Some(name) = self.controller.mounted_profile().await else {
            return false;
        };
        !matches!(
            self.store.mode_of(&name),
            Ok(Some(ProfileMode::Service)) | Ok(None)
        )
    }
}
