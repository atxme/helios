//! Provisioning (TOFU) and ticket-authorized resealing.

use crate::{
    blob_store::{BlobStore, TpmState},
    reseal_ticket::ResealTicket,
    secret::SecretKey,
    tpm_interface::TpmSealer,
    Result,
};

/// First boot in a trusted environment (factory): generates a secret,
/// seals it against the current PCRs, persists blob + initial state.
pub(crate) fn provision<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<SecretKey> {
    let secret = SecretKey::generate()?;
    let blob = tpm.seal(&secret)?;
    store.store_blob(&blob)?;
    store.store_state(&TpmState { version: 0 })?;
    tracing::info!("TOFU provisioning completed — secret sealed on current PCR state");
    Ok(secret)
}

/// Post-OTA resealing: only succeeds if a valid signed ticket authorizes the
/// operation. A **new** secret is generated and sealed on the new PCRs (the
/// old one is unrecoverable since unseal failed); the ticket is consumed.
pub(crate) fn reseal<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<SecretKey> {
    let ticket: ResealTicket = store
        .load_ticket()?
        .ok_or(crate::TpmError::UnsealFailedNoTicket)?;

    let current_pcr = tpm.current_pcr_digest()?;
    let mut state = store.load_state()?;

    // Verifies publisher signature + anti-replay (version) + optional PCR binding.
    ticket.verify(state.version, &current_pcr)?;

    let secret = SecretKey::generate()?;
    let blob = tpm.seal(&secret)?;
    store.store_blob(&blob)?;

    state.version = ticket.version();
    store.store_state(&state)?;
    store.consume_ticket()?;

    tracing::warn!(
        version = ticket.version(),
        "post-OTA resealing authorized by ticket — new secret sealed"
    );
    Ok(secret)
}
