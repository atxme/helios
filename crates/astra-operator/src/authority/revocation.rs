//! Signing an emergency revocation under `CA-PQ`.

use super::*;

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

/// Signs an emergency revocation with the master `CA-PQ` key.
///
/// A delegated online issuer may renew an admitted identity, but it may never
/// withdraw one. Requiring an already-opened vault here keeps that boundary in
/// the function signature.
pub fn sign_revocation(
    vault: &AuthorityVault,
    opening: &crate::authenticator::Opened,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    decision: &RevocationDecision,
    current_revocation_epoch: u64,
) -> Result<EmergencyCertificateRevocation> {
    if decision.revoked_tls.is_none() && decision.revoked_pq.is_none() {
        return Err(GestureError::Anchors(
            "une révocation doit nommer au moins une feuille".into(),
        ));
    }
    with_anchors(vault, opening, |secrets| {
        let ca_pq_private_key = decode(&secrets.ca_pq_private_key, "clé privée CA-PQ")?;
        let revocation = EmergencyCertificateRevocation {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            ca_epoch: identity.ca_epoch,
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
        .sign(&ca_pq_private_key)?;
        revocation.verify(
            ca_pq_public_key,
            &identity.trust_domain_id,
            identity.ca_epoch,
            current_revocation_epoch,
        )?;
        Ok(revocation)
    })
}
