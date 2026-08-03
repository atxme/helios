//! Provisioning (TOFU), ticket-authorized resealing, and the update window.

use crate::{
    blob_store::{BlobStore, TpmState},
    reseal_ticket::ResealTicket,
    secret::SecretKey,
    tpm_interface::TpmSealer,
    update_window::{anchor_of, WindowMarker, WindowPayload},
    Result, TpmError,
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
    let ticket: ResealTicket = store.load_ticket()?.ok_or(TpmError::UnsealFailedNoTicket)?;

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

/// Arms an update window carrying `secret` across one planned reboot.
///
/// Called with a secret that has just been unsealed nominally: there is no
/// path here from a boot that failed to unseal, which is what keeps the
/// window from becoming a way to *create* trust rather than carry it.
pub(crate) fn arm_window<T: TpmSealer>(
    tpm: &mut T,
    store: &BlobStore<'_>,
    secret: &SecretKey,
    deadline: u64,
) -> Result<()> {
    let anchor = anchor_of(
        store
            .load_blob()?
            .ok_or(TpmError::MissingBlobOnField)?
            .as_bytes(),
    );
    let payload = WindowPayload {
        deadline,
        anchor,
        secret: secret.clone(),
    };
    let marker = WindowMarker { deadline, anchor };

    // The marker contains no secret and is persisted first. If power fails
    // before the TPM write there is no live window; if it fails afterwards,
    // the timer already has everything it needs to revoke the NV payload.
    store.store_window_marker(&crate::tpm_interface::SealedBlob::from_bytes(
        marker.encode(),
    ))?;
    if let Err(error) = tpm.arm_update_window(&payload.encode()) {
        // A TPM command can take effect even if its response is lost. Treat
        // every arm error as an uncertain live payload and compensate by
        // overwriting the slot. Keep the marker if compensation also fails,
        // so the expiry service can retry instead of losing the only durable
        // indication that a secret may still be present.
        if let Err(cleanup) = tpm.revoke_update_window() {
            return Err(TpmError::UpdateWindowCleanupFailed(format!(
                "arming failed ({error}); uncertain NV payload could not be revoked ({cleanup})"
            )));
        }
        if let Err(cleanup) = store.remove_window_marker() {
            tracing::warn!(%cleanup, "inert update-window marker could not be removed after failed arm");
        }
        return Err(error);
    }
    tracing::warn!(deadline, "update window armed — reboot before it expires");
    Ok(())
}

/// Disarms the window: overwrites its TPM payload, then removes the marker.
///
/// The order is the invariant. Revoking first means an interrupted disarm
/// leaves a dead window and a stale marker; removing first could leave a live
/// TPM payload with no deadline visible to the expiry service.
pub(crate) fn disarm_window<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<()> {
    tpm.revoke_update_window()?;
    store.remove_window_marker()
}

/// Consumes an armed window: recovers the **same** secret and reseals it
/// against the PCR state the machine has just booted into.
///
/// This is the whole point — no new secret, so every vault encrypted under it
/// stays readable and no client is re-enrolled.
pub(crate) fn consume_window<T: TpmSealer>(
    tpm: &mut T,
    store: &BlobStore<'_>,
    now: u64,
) -> Result<SecretKey> {
    let marker = store
        .load_window_marker()?
        .ok_or(TpmError::UpdateWindowUnavailable)?;
    let anchor = anchor_of(
        store
            .load_blob()?
            .ok_or(TpmError::MissingBlobOnField)?
            .as_bytes(),
    );

    let marker = WindowMarker::decode(marker.as_bytes())?;
    // Reject stale or substituted metadata before asking the TPM to release
    // the secret. The protected payload is cross-checked immediately after.
    marker.accept(now, &anchor)?;

    let plaintext = tpm.unseal_update_window()?;
    let payload = WindowPayload::decode(&plaintext)?;
    marker.matches_payload(&payload)?;
    payload.accept(now, &anchor)?;

    // Reseal on the new PCR state **before** revoking: if this fails, the
    // window must stay usable so the operator can retry within this same
    // boot. A revoked window plus an unwritten nominal blob would be the state
    // with no way out.
    let resealed = tpm.seal(&payload.secret)?;
    store.store_blob(&resealed)?;

    if let Err(error) = tpm.revoke_update_window() {
        // The nominal blob is already durable and carries the right secret.
        // Falling through to a ticket now would overwrite it with a new one.
        return Err(TpmError::UpdateWindowCleanupFailed(error.to_string()));
    }
    if let Err(error) = store.remove_window_marker() {
        // The TPM payload is gone, so a stale marker is harmless and will be
        // removed by the next nominal boot. Do not destroy availability over
        // cleanup that no longer protects a secret.
        tracing::warn!(%error, "update-window marker could not be removed after TPM revocation");
    }

    tracing::warn!(
        "update window consumed — the same secret was resealed on the new PCR state; \
         no vault was re-keyed"
    );
    Ok(payload.secret)
}
