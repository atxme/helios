//! Signing an emergency revocation under `CA-PQ`.

use super::*;

/// How close to its retirement a revocation signed under the outgoing `CA-PQ`
/// may be made. Inside this margin the fleet may already have stopped trusting
/// the key, and a revocation that verifies nowhere is worse than none.
pub const OUTGOING_REVOCATION_MARGIN_SECS: u64 = 3600;

/// Operator-controlled contents of an emergency revocation (spec §10.1).
pub struct RevocationDecision {
    pub scope: RevocationScope,
    pub identity_key: WireGuardKey,
    pub server_name: Option<String>,
    pub revocation_epoch: u64,
    pub revoked_tls: Option<(Fingerprint, u64)>,
    pub revoked_pq: Option<(Fingerprint, u64)>,
    pub effective_at: u64,
    pub reason: RevocationReason,
    /// The one transition a revoked identity will still accept (spec §10.1).
    ///
    /// Naming it here is what makes the withdrawal recoverable: without it the
    /// state is terminal on every holder, and the service stays down until the
    /// trust domain is rebuilt.
    pub replacement_transition_fingerprint: Option<Fingerprint>,
}

/// The `CA-PQ` a revocation is signed under: the one Astra checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAnchor {
    /// The vault's current anchor.
    Current,
    /// The outgoing anchor, kept until the rotation's `not_after`.
    Outgoing,
}

/// Why no revocation can be signed under the anchor Astra checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAnchorRefusal {
    /// Inside the margin, or Astra still on the outgoing anchor with no key
    /// kept. The second is when the outgoing anchor stops being accepted.
    NotBefore(u64),
    /// Astra serves an anchor this vault holds no key for.
    UnknownAnchor,
}

/// Chooses the `CA-PQ` a revocation is signed under, from the anchor Astra
/// serves and the epoch it serves it at.
///
/// `current_ca_epoch` is the vault's current epoch (`DomainIdentity::ca_epoch`):
/// the vault does not store it. `overlap_not_after` is the gateway's
/// `ca_retire_active_at`, when a rotation overlap runs.
pub fn revocation_anchor(
    vault: &AuthorityVault,
    astra_ca_fingerprint: &Fingerprint,
    astra_ca_epoch: u64,
    current_ca_epoch: u64,
    overlap_not_after: Option<u64>,
    now_unix: u64,
) -> std::result::Result<RevocationAnchor, RevocationAnchorRefusal> {
    use RevocationAnchorRefusal::{NotBefore, UnknownAnchor};

    if let Ok(current) = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()) {
        if current.authority_fingerprint() == *astra_ca_fingerprint {
            return if astra_ca_epoch == current_ca_epoch {
                Ok(RevocationAnchor::Current)
            } else {
                Err(UnknownAnchor)
            };
        }
    }
    match (
        vault.retained_outgoing_ca_pq_public.as_ref(),
        vault.retained_outgoing_ca_pq_public(),
    ) {
        // A kept key whose clear copy does not read as a key is refused by the
        // unlock anyway; here it simply matches nothing.
        (Some(_), None) => Err(UnknownAnchor),
        (Some(_), Some((outgoing, ca_epoch, not_after))) => {
            if outgoing.authority_fingerprint() != *astra_ca_fingerprint
                || ca_epoch != astra_ca_epoch
            {
                return Err(UnknownAnchor);
            }
            if now_unix < not_after.saturating_sub(OUTGOING_REVOCATION_MARGIN_SECS) {
                Ok(RevocationAnchor::Outgoing)
            } else {
                Err(NotBefore(not_after))
            }
        }
        // A vault from before the outgoing key was kept: Astra is on the
        // previous epoch, and the gateway says when that overlap ends.
        (None, _) => match (current_ca_epoch.checked_sub(1), overlap_not_after) {
            (Some(previous), Some(end)) if previous == astra_ca_epoch => Err(NotBefore(end)),
            _ => Err(UnknownAnchor),
        },
    }
}

/// Signs an emergency revocation with the `CA-PQ` named by `anchor`.
///
/// A delegated online issuer may renew an admitted identity, but it may never
/// withdraw one. Requiring an already-opened vault here keeps that boundary in
/// the function signature.
///
/// Under [`RevocationAnchor::Outgoing`] the revocation takes its epoch from the
/// kept key, never from `identity.ca_epoch`, and verifies under that key. The
/// caller is expected to have obtained `anchor` from [`revocation_anchor`].
pub fn sign_revocation(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &RevocationDecision,
    current_revocation_epoch: u64,
    anchor: RevocationAnchor,
) -> Result<EmergencyCertificateRevocation> {
    if decision.revoked_tls.is_none() && decision.revoked_pq.is_none() {
        return Err(GestureError::Anchors(
            "une révocation doit nommer au moins une feuille".into(),
        ));
    }
    match anchor {
        RevocationAnchor::Current => with_anchors(vault, opening, |secrets| {
            let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
            sign_under(
                identity,
                identity.ca_epoch,
                decision,
                &ca_pq_private_key,
                ca_pq_public_key,
                current_revocation_epoch,
            )
        }),
        RevocationAnchor::Outgoing => vault
            .with_retained_outgoing_ca_pq(&opening.credential_id, &opening.secret, |retained| {
                let private_key = decode(&retained.private_key, "clé privée CA-PQ sortante")?;
                let public_key = MlDsa87PublicKey::parse(retained.public_key.trim())?;
                sign_under(
                    identity,
                    retained.ca_epoch,
                    decision,
                    &private_key,
                    &public_key,
                    current_revocation_epoch,
                )
            })?
            .ok_or_else(|| {
                GestureError::Anchors(
                    "aucune CA-PQ sortante gardée : la révocation ne peut pas être signée sous elle"
                        .into(),
                )
            }),
    }
}

fn sign_under(
    identity: &DomainIdentity,
    ca_epoch: u64,
    decision: &RevocationDecision,
    private_key: &[u8],
    public_key: &MlDsa87PublicKey,
    current_revocation_epoch: u64,
) -> Result<EmergencyCertificateRevocation> {
    let revocation = EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: identity.trust_domain_id,
        ca_epoch,
        scope: decision.scope,
        identity_key: decision.identity_key,
        server_name: decision.server_name.clone(),
        revocation_epoch: decision.revocation_epoch,
        revoked_tls_fingerprint: decision.revoked_tls.map(|value| value.0),
        revoked_tls_not_after: decision.revoked_tls.map(|value| value.1),
        revoked_pq_fingerprint: decision.revoked_pq.map(|value| value.0),
        revoked_pq_not_after: decision.revoked_pq.map(|value| value.1),
        effective_at: decision.effective_at,
        reason: decision.reason,
        replacement_transition_fingerprint: decision.replacement_transition_fingerprint,
        ca_signature: MlDsa87Signature::placeholder(),
    }
    .sign(private_key)?;
    revocation.verify(
        public_key,
        &identity.trust_domain_id,
        ca_epoch,
        current_revocation_epoch,
    )?;
    Ok(revocation)
}
