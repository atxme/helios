//! Signing credential bindings from the vault's key-slot table.

use super::*;

/// Rebuilds the whole credential document from the vault's key-slot table.
///
/// Called by every gesture that changes that table, in the **same** operation
/// (spec §2.4). The table is the input, so a binding for a slot the vault no
/// longer holds cannot be produced: withdrawn credentials keep a row, and it
/// says `revoked`.
///
/// `previous` carries the epochs and the states a decision already recorded.
/// A credential once `revoked` stays `revoked` — [`AstraCredentialBinding::
/// supersedes`] refuses the walk-back at the consumer, and refusing to produce
/// it here means the consumer never has to.
pub fn sign_credential_bindings(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
    now_unix: u64,
) -> Result<CredentialRegistry> {
    if let Some(previous) = previous {
        let current_ca = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
        previous.verify(
            &current_ca,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            previous.credential_registry_epoch,
        )?;
    }
    sign_credential_bindings_from_verified_previous(
        vault, opening, identity, previous, overrides, now_unix,
    )
}

/// Signs a new snapshot after the caller proved the previous one.
///
/// Kept separate for `CA-PQ` rotation: there the previous snapshot verifies
/// under the outgoing anchor, while the result must be signed under the new
/// one after the vault body has moved.
pub(super) fn sign_credential_bindings_from_verified_previous(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
    now_unix: u64,
) -> Result<CredentialRegistry> {
    let registry_epoch = previous
        .map(|previous| previous.credential_registry_epoch)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let mut bindings = Vec::new();

        // One row per slot present, then one per credential that left. The two
        // loops are the whole invariant: the first cannot describe an absent
        // slot, and the second cannot describe a present one as revoked.
        for slot in &vault.slots {
            let credential_id = slot.credential_id()?;
            let state = state_of(&credential_id, previous, overrides)?;
            bindings.push(sign_binding(
                identity,
                credential_id,
                slot.credential_public_key()?,
                slot.aaguid,
                state,
                previous,
                registry_epoch,
                now_unix,
                &ca_pq_private_key,
            )?);
        }
        for old in previous
            .map(|previous| previous.bindings.as_slice())
            .unwrap_or_default()
        {
            if vault.slot_for_credential(&old.credential_id).is_ok() {
                continue;
            }
            bindings.push(sign_binding(
                identity,
                old.credential_id.clone(),
                old.credential_public_key.clone(),
                old.aaguid,
                CredentialState::Revoked,
                previous,
                registry_epoch,
                now_unix,
                &ca_pq_private_key,
            )?);
        }

        Ok(CredentialRegistry {
            trust_domain_id: identity.trust_domain_id,
            gateway_wg_public_key: identity.gateway_wg_public_key,
            ca_epoch: identity.ca_epoch,
            credential_registry_epoch: registry_epoch,
            bindings,
        })
    })
}

/// The state one credential carries into the new document.
///
/// A revocation is terminal: an override that tried to walk one back is
/// refused rather than applied, because the consumers refuse it too and a
/// document nobody accepts is worse than a command that failed.
fn state_of(
    credential_id: &[u8],
    previous: Option<&CredentialRegistry>,
    overrides: &[(Vec<u8>, CredentialState)],
) -> Result<CredentialState> {
    let recorded = previous
        .and_then(|previous| previous.binding(credential_id))
        .map(|binding| binding.state);
    let requested = overrides
        .iter()
        .find(|(id, _)| id.as_slice() == credential_id)
        .map(|(_, state)| *state);
    match (recorded, requested) {
        (Some(CredentialState::Revoked), Some(state)) if state != CredentialState::Revoked => {
            Err(GestureError::Anchors(
                "une révocation est définitive : ce credential ne redevient pas actif".into(),
            ))
        }
        (_, Some(state)) => Ok(state),
        (Some(state), None) => Ok(state),
        (None, None) => Ok(CredentialState::Active),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_binding(
    identity: &DomainIdentity,
    credential_id: Vec<u8>,
    credential_public_key: Vec<u8>,
    aaguid: [u8; 16],
    state: CredentialState,
    previous: Option<&CredentialRegistry>,
    registry_epoch: u64,
    now_unix: u64,
    ca_pq_private_key: &[u8],
) -> Result<AstraCredentialBinding> {
    let recorded = previous.and_then(|previous| previous.binding(&credential_id));
    // The per-credential counter moves only when this credential's decision
    // moves. A counter that advanced with the registry would say every token
    // changed each time any one of them did.
    let credential_epoch = match recorded {
        Some(recorded) if recorded.state == state => recorded.credential_epoch,
        Some(recorded) => recorded
            .credential_epoch
            .checked_add(1)
            .ok_or(CertificateError::ArithmeticOverflow)?,
        None => 1,
    };
    let created_at = recorded
        .filter(|recorded| recorded.state == state)
        .map(|recorded| recorded.created_at)
        .unwrap_or(now_unix);

    let binding = AstraCredentialBinding {
        format_version: CERTIFICATE_FORMAT_VERSION,
        credential_id,
        credential_public_key,
        aaguid,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        state,
        credential_epoch,
        credential_registry_epoch: registry_epoch,
        ca_epoch: identity.ca_epoch,
        created_at,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(ca_pq_private_key)?;
    binding.supersedes(recorded)?;
    Ok(binding)
}
