//! Rotating the `CA-PQ` anchor.

use super::*;

/// What an anchor rotation produced.
pub struct RotatedAnchor {
    pub transition: CaTransition,
    pub next_ca_public_key: MlDsa87PublicKey,
    pub bindings: CredentialRegistry,
}

/// Rotates `CA-PQ`, under two distinct credentials (spec §9.1, §2.4).
///
/// Two signatures, and they answer different questions: the outgoing anchor
/// vouches for its successor, and the successor proves it holds its own key. A
/// caller with only one of them cannot produce a valid object, which is what
/// [`CaTransition::verify`] enforces at the far end.
///
/// The key-slots do not move: every credential that opened the vault before
/// opens it after. Only the body changes, and the clear `ca_pq_public_key`
/// moves in the same write.
///
/// The credential bindings are re-signed here too, under the **new** anchor
/// and the new `ca_epoch`. Leaving them behind would leave the domain holding
/// approvals verifiable only under an anchor it has just replaced.
pub fn rotate_ca_pq(
    vault: &mut AuthorityVault,
    openings: &[&crate::authenticator::Opened],
    identity: &DomainIdentity,
    previous: Option<&CredentialRegistry>,
    window: TransitionWindow,
    now_unix: u64,
) -> Result<RotatedAnchor> {
    if openings.len() != ANCHOR_ROTATION_CREDENTIALS {
        return Err(GestureError::Anchors(format!(
            "une rotation d'ancre exige {ANCHOR_ROTATION_CREDENTIALS} confirmations, {} \
             fournie(s)",
            openings.len()
        )));
    }
    if openings[0].credential_id == openings[1].credential_id {
        return Err(GestureError::Anchors(
            "les deux confirmations viennent de la même clé : elles doivent venir de deux objets \
             distincts"
                .into(),
        ));
    }
    // Both must genuinely open the vault, before anything is generated: an
    // operator whose second key does not work should find out now and not
    // after the anchor has moved.
    for opening in openings {
        let secrets = vault.open(&opening.credential_id, &opening.secret)?;
        drop(secrets);
    }
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
    window.validate()?;
    let next_ca_epoch = identity
        .ca_epoch
        .checked_add(1)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    let (next_private_key, next_public_key) = generate_ml_dsa_87_keypair()?;
    let current_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
    let transition = with_anchors(vault, openings[0], |secrets| {
        let current_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let transition = CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            current_ca_epoch: identity.ca_epoch,
            next_ca_epoch,
            current_ca_fingerprint: current_public_key.authority_fingerprint(),
            next_ca_public_key: next_public_key.clone(),
            next_ca_fingerprint: next_public_key.authority_fingerprint(),
            window,
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&current_private_key, &next_private_key)?;
        transition.verify(
            &current_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
        )?;

        // The `CA-TLS` key rides through unchanged: §9.1 rotates the operator
        // anchor, and §9.4 is a separate transition with its own overlap. A
        // rotation that quietly replaced both would invalidate every mTLS
        // chain in the fleet on an operation nobody scheduled for it.
        Ok((
            transition,
            AuthoritySecrets {
                ca_pq_private_key: encode(&next_private_key),
                ca_pq_public_key: next_public_key.to_base64(),
                ca_tls_private_key: secrets.ca_tls_private_key.clone(),
                retained_ca_tls: secrets.retained_ca_tls.clone(),
            },
        ))
    })?;
    let (transition, next_secrets) = transition;

    vault.replace_anchors(
        &openings[0].credential_id,
        &openings[0].secret,
        &next_secrets,
    )?;

    let rotated_identity = DomainIdentity {
        ca_epoch: next_ca_epoch,
        ..identity.clone()
    };
    let bindings = sign_credential_bindings_from_verified_previous(
        vault,
        openings[0],
        &rotated_identity,
        previous,
        &[],
        now_unix,
    )?;

    Ok(RotatedAnchor {
        transition,
        next_ca_public_key: next_public_key,
        bindings,
    })
}
