//! Provisionnement (TOFU) et rescellement autorisé par billet.

use crate::{
    blob_store::{BlobStore, TpmState},
    reseal_ticket::ResealTicket,
    secret::SecretKey,
    tpm_interface::TpmSealer,
    Result,
};

/// Premier boot en environnement de confiance (usine) : génère un secret,
/// le scelle contre les PCR courants, persiste blob + état initial.
pub(crate) fn provision<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<SecretKey> {
    let secret = SecretKey::generate()?;
    let blob = tpm.seal(&secret)?;
    store.store_blob(&blob)?;
    store.store_state(&TpmState { version: 0 })?;
    tracing::info!("provisionnement TOFU effectué — secret scellé sur l'état PCR courant");
    Ok(secret)
}

/// Rescellement post-OTA : ne réussit que si un billet signé valide autorise
/// l'opération. Un **nouveau** secret est généré et scellé sur les nouveaux PCR
/// (l'ancien est irrécupérable, l'unseal ayant échoué) ; le billet est consommé.
pub(crate) fn reseal<T: TpmSealer>(tpm: &mut T, store: &BlobStore<'_>) -> Result<SecretKey> {
    let ticket: ResealTicket = store
        .load_ticket()?
        .ok_or(crate::TpmError::UnsealFailedNoTicket)?;

    let current_pcr = tpm.current_pcr_digest()?;
    let mut state = store.load_state()?;

    // Vérifie signature éditeur + anti-rejeu (version) + liaison PCR optionnelle.
    ticket.verify(state.version, &current_pcr)?;

    let secret = SecretKey::generate()?;
    let blob = tpm.seal(&secret)?;
    store.store_blob(&blob)?;

    state.version = ticket.version;
    store.store_state(&state)?;
    store.consume_ticket()?;

    tracing::warn!(
        version = ticket.version,
        "rescellement post-OTA autorisé par billet — nouveau secret scellé"
    );
    Ok(secret)
}
