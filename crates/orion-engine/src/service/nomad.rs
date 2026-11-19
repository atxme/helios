//! The `nomade` profile in the engine: asking for its passphrase, opening it,
//! and the three gestures that seal a profile under one or take it back.
//!
//! The passphrase is asked through the engine's [`PassphraseSource`], on a
//! blocking thread: a native dialog waits for the user, and the key derivation
//! costs hundreds of thousands of iterations. It is handed to the store as a
//! `&str`, used once, and dropped; nothing here returns it, logs it or puts it
//! in a view.

use std::sync::{atomic::Ordering, Arc};

use orion_core::vault::{
    passphrase, registry::ProfileMode, ProfileStore, PromptPurpose, VaultError,
};
use zeroize::Zeroizing;

use super::EngineService;
use crate::view::ConfigView;

/// What the screen shows when the user cancels a prompt. A cancel is the
/// user's decision, so it is worded as an outcome rather than a fault.
const CANCELLED: &str = "Saisie annulée.";

/// Turns a store failure into the message the screen shows.
fn store_message(error: VaultError) -> String {
    match error {
        VaultError::PassphraseCancelled => CANCELLED.to_string(),
        other => other.to_string(),
    }
}

fn interrupted(error: tokio::task::JoinError) -> String {
    format!("opération interrompue : {error}")
}

impl EngineService {
    /// Asks the passphrase source for one passphrase.
    pub(super) async fn ask_passphrase(
        &self,
        profile: &str,
        purpose: PromptPurpose,
    ) -> Result<Zeroizing<String>, String> {
        let source = Arc::clone(&self.passphrases);
        let profile = profile.to_string();
        tokio::task::spawn_blocking(move || source.ask(&profile, &purpose))
            .await
            .map_err(interrupted)?
            .map_err(store_message)
    }

    /// Asks for a **new** passphrase, twice.
    ///
    /// A passphrase the policy refuses is asked again, with the reason as the
    /// prompt's `Retry`, until one is accepted or the user cancels. The second
    /// entry must match the first once normalised, and a mismatch is refused
    /// here, before the store is touched.
    pub(super) async fn new_passphrase(&self, profile: &str) -> Result<Zeroizing<String>, String> {
        let mut purpose = PromptPurpose::New;
        let candidate = loop {
            let candidate = self.ask_passphrase(profile, purpose).await?;
            match passphrase::accept(&candidate) {
                Ok(_) => break candidate,
                Err(refusal) => purpose = PromptPurpose::Retry(refusal.to_string()),
            }
        };
        let confirmation = self.ask_passphrase(profile, PromptPurpose::Confirm).await?;
        let same = passphrase::normalise(&confirmation).as_str()
            == passphrase::normalise(&candidate).as_str();
        if !same {
            return Err(VaultError::PassphraseMismatch.to_string());
        }
        Ok(candidate)
    }

    /// Opens `name` if it is a `nomade` profile this session has not opened.
    ///
    /// A `service` profile, an unknown name and an unlocked `nomade` one need
    /// nothing and ask nothing. Otherwise the passphrase is asked for with
    /// `purpose`, and the profile is opened with it. The configuration is read
    /// again afterwards, so the profile appears in it.
    ///
    /// `store.unlock` answers `Ok` for an unknown name and keeps a profile
    /// locked when a lock lands during the unlock, so the outcome is checked
    /// here, not assumed.
    pub(super) async fn unlock_if_nomad(
        &self,
        name: &str,
        purpose: PromptPurpose,
    ) -> Result<(), String> {
        let nomad = matches!(
            self.store.mode_of(name).map_err(store_message)?,
            Some(ProfileMode::Nomad { .. })
        );
        if !nomad || self.store.is_unlocked(name) {
            return Ok(());
        }
        // Read before the dialog: a lock that lands while it is open must win,
        // and the store only sees locks that land during its own derivation.
        let generation = self.lock_generation.load(Ordering::Acquire);
        let passphrase = self.ask_passphrase(name, purpose).await?;
        let store = Arc::clone(&self.store);
        let profile = name.to_string();
        tokio::task::spawn_blocking(move || store.unlock(&profile, passphrase.as_str()))
            .await
            .map_err(interrupted)?
            .map_err(store_message)?;
        if self.lock_generation.load(Ordering::Acquire) != generation {
            // The store took the key after the lock had already forgotten the
            // keys, so the key it holds now is the one to drop.
            self.store.forget_unlocked();
            return Err(VaultError::ProfileLocked(name.to_string()).to_string());
        }
        if !self.store.is_unlocked(name) {
            return Err(VaultError::ProfileLocked(name.to_string()).to_string());
        }
        self.reload_config().await
    }

    /// Reads the configuration from the vault again, after a change to what
    /// it holds: an unlock, a switch, a passphrase change.
    pub(super) async fn reload_config(&self) -> Result<(), String> {
        let mut config = self.config.lock().await;
        *config = self.store.load().map_err(store_message)?;
        Ok(())
    }

    /// Runs one store operation on a blocking thread.
    pub(super) async fn in_store<T, F>(&self, work: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&ProfileStore) -> Result<T, VaultError> + Send + 'static,
    {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || work(&store))
            .await
            .map_err(interrupted)?
            .map_err(store_message)
    }

    /// Refuses a name the vault does not hold, before anything is asked.
    fn require_known(&self, name: &str) -> Result<(), String> {
        match self.store.mode_of(name).map_err(store_message)? {
            Some(_) => Ok(()),
            None => Err(VaultError::UnknownProfile(name.to_string()).to_string()),
        }
    }

    /// Seals a `service` profile under a new passphrase (spec §5.7).
    pub async fn make_nomad(&self, name: String) -> Result<ConfigView, String> {
        self.require_known(&name)?;
        let passphrase = self.new_passphrase(&name).await?;
        self.in_store(move |store| store.make_nomad(&name, passphrase.as_str()))
            .await?;
        self.reload_config().await?;
        Ok(self.config_view_now().await)
    }

    /// Sets a new passphrase on a `nomade` profile. A locked one is opened
    /// first, with its current passphrase.
    pub async fn change_passphrase(&self, name: String) -> Result<ConfigView, String> {
        self.require_known(&name)?;
        self.unlock_if_nomad(&name, PromptPurpose::Current).await?;
        let passphrase = self.new_passphrase(&name).await?;
        self.in_store(move |store| store.make_nomad(&name, passphrase.as_str()))
            .await?;
        self.reload_config().await?;
        Ok(self.config_view_now().await)
    }

    /// Takes an unlocked `nomade` profile back to `service`. A locked one is
    /// opened first, with its current passphrase.
    pub async fn make_service(&self, name: String) -> Result<ConfigView, String> {
        self.require_known(&name)?;
        self.unlock_if_nomad(&name, PromptPurpose::Current).await?;
        self.in_store(move |store| store.make_service(&name))
            .await?;
        self.reload_config().await?;
        Ok(self.config_view_now().await)
    }
}

#[cfg(test)]
mod tests;
