//! The trust ledger, and the base-state fingerprint a transaction binds.

use super::*;

/// What a trust holder knows that belongs to no single authority family.
///
/// Two things live here because they are cross-cutting: the revocations that
/// have been verified but not yet reached their instant, and the last status
/// ordering **per target**. The second is deliberately not one global pair —
/// Astra counts statuses per certificate, so a freshly rotated leaf starts at
/// epoch 1 and would be refused for good behind the high epoch of the leaf it
/// replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustLedger {
    /// Revocation counter of the **gateway** identity, on its own axis.
    #[serde(default)]
    pub gateway_revocation_epoch: u64,
    #[serde(default)]
    pub scheduled_revocations: Vec<ScheduledRevocation>,
    /// Fingerprints already withdrawn, kept so no later object reinstalls one.
    pub revoked: Vec<RevocationTombstone>,
    /// Keyed by the target's fingerprint in lowercase hex.
    #[serde(default)]
    pub last_statuses: BTreeMap<String, StatusOrdering>,
}

impl TrustLedger {
    /// Records a revocation whose object has already been verified.
    ///
    /// A revocation dated in the future is **kept**: its epoch is consumed the
    /// moment it verifies, so dropping it would discard a decision the
    /// authority already made and that can never be delivered again.
    pub fn schedule(
        &mut self,
        revocation: &EmergencyCertificateRevocation,
        gateway: &GatewayCertificateState,
        client: &ClientCertificateState,
    ) -> Result<(), CertificateError> {
        if self.scheduled_revocations.len() >= MAX_SCHEDULED_REVOCATIONS {
            return Err(CertificateError::InvalidTransaction(
                "too many pending revocations",
            ));
        }
        for (fingerprint, signed_expiry) in [
            (
                revocation.revoked_tls_fingerprint,
                revocation.revoked_tls_not_after,
            ),
            (
                revocation.revoked_pq_fingerprint,
                revocation.revoked_pq_not_after,
            ),
        ] {
            if let (Some(fingerprint), Some(signed_expiry)) = (fingerprint, signed_expiry) {
                if known_expiry(gateway, client, &fingerprint)
                    .is_some_and(|held_expiry| held_expiry != signed_expiry)
                {
                    return Err(CertificateError::InvalidTransaction(
                        "revocation expiry does not match the held certificate",
                    ));
                }
            }
        }
        if revocation.scope == RevocationScope::Gateway {
            self.gateway_revocation_epoch = revocation.revocation_epoch;
        }
        self.scheduled_revocations.push(ScheduledRevocation {
            scope: revocation.scope,
            revocation_epoch: revocation.revocation_epoch,
            effective_at: revocation.effective_at,
            revoked_tls_fingerprint: revocation.revoked_tls_fingerprint,
            revoked_tls_not_after: revocation.revoked_tls_not_after,
            revoked_pq_fingerprint: revocation.revoked_pq_fingerprint,
            revoked_pq_not_after: revocation.revoked_pq_not_after,
            revocation_fingerprint: Some(revocation.fingerprint()),
            replacement_transition_fingerprint: revocation.replacement_transition_fingerprint,
        });
        Ok(())
    }

    /// Applies every revocation that has reached its instant, to the state its
    /// scope names, and remembers the fingerprints it withdrew.
    ///
    /// The tombstone is written **before** the decision is applied: applying
    /// it clears the very slot the cryptographic expiry would have been read
    /// from. The signed expiry remains available when this holder never had
    /// the certificate at all.
    pub fn apply_due(
        &mut self,
        gateway: &mut GatewayCertificateState,
        client: &mut ClientCertificateState,
        now_unix: u64,
    ) -> Result<bool, CertificateError> {
        let mut moved = false;
        let mut remaining = Vec::with_capacity(self.scheduled_revocations.len());
        for revocation in std::mem::take(&mut self.scheduled_revocations) {
            if now_unix < revocation.effective_at {
                remaining.push(revocation);
                continue;
            }
            for (family, fingerprint, signed_expiry) in [
                (
                    RevokedFamily::Tls,
                    revocation.revoked_tls_fingerprint,
                    revocation.revoked_tls_not_after,
                ),
                (
                    RevokedFamily::Pq,
                    revocation.revoked_pq_fingerprint,
                    revocation.revoked_pq_not_after,
                ),
            ] {
                let (Some(fingerprint), Some(expires_at)) = (fingerprint, signed_expiry) else {
                    continue;
                };
                if known_expiry(gateway, client, &fingerprint)
                    .is_some_and(|held_expiry| held_expiry != expires_at)
                {
                    return Err(CertificateError::InvalidTransaction(
                        "revocation expiry does not match the held certificate",
                    ));
                }
                self.remember(
                    RevocationTombstone {
                        scope: revocation.scope,
                        family,
                        fingerprint,
                        revocation_epoch: revocation.revocation_epoch,
                        expires_at,
                        revocation_fingerprint: revocation.revocation_fingerprint,
                    },
                    now_unix,
                )?;
            }
            match revocation.scope {
                RevocationScope::Client => {
                    if revocation.hits_client(client) {
                        client.revoke(revocation.revocation_epoch);
                    }
                }
                RevocationScope::Gateway => {
                    // The client records the awaited replacement for the same
                    // reason the gateway does: without it, a client that
                    // received the revocation would refuse the transition
                    // that repairs the service, and stay refusing forever.
                    gateway.apply_revocation(
                        revocation.revoked_tls_fingerprint.as_ref(),
                        revocation.revoked_pq_fingerprint.as_ref(),
                        revocation.revocation_epoch,
                        revocation.replacement_transition_fingerprint.as_ref(),
                    )?;
                }
            }
            moved = true;
        }
        self.scheduled_revocations = remaining;
        Ok(moved)
    }

    /// Records a withdrawn fingerprint, or refuses rather than forgetting one.
    ///
    /// When the list is full, tombstones whose cryptographic validity has run
    /// out are dropped first — they can no longer protect anything. If that
    /// frees nothing, the operation is **refused**. Evicting a live tombstone
    /// to make room would silently restore the ability to reinstall a revoked
    /// leaf, and a refused trust update is recoverable in a way that is not.
    pub fn remember(
        &mut self,
        tombstone: RevocationTombstone,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        self.forget_expired(now_unix);
        if now_unix >= tombstone.expires_at {
            return Ok(());
        }
        if let Some(existing) = self.revoked.iter_mut().find(|held| {
            held.scope == tombstone.scope
                && held.family == tombstone.family
                && held.fingerprint.matches(&tombstone.fingerprint)
        }) {
            // Keep the whole newest decision together. Updating only the
            // counter would leave it pointing at the older signed document.
            if tombstone.revocation_epoch > existing.revocation_epoch {
                *existing = tombstone;
            }
            return Ok(());
        }
        if self.revoked.len() >= MAX_REVOCATION_TOMBSTONES {
            return Err(CertificateError::InvalidTransaction(
                "no room left for a revocation tombstone",
            ));
        }
        self.revoked.push(tombstone);
        Ok(())
    }

    /// Drops tombstones whose target could no longer be valid anyway.
    ///
    /// Remote expiry is part of the signed revocation, so a certificate the
    /// holder never saw is just as reclaimable as one it once installed.
    pub fn forget_expired(&mut self, now_unix: u64) -> bool {
        let before = self.revoked.len();
        self.revoked
            .retain(|tombstone| now_unix < tombstone.expires_at);
        self.revoked.len() != before
    }

    pub fn is_revoked(&self, fingerprint: &Fingerprint) -> bool {
        self.revoked
            .iter()
            .any(|tombstone| tombstone.fingerprint.matches(fingerprint))
    }

    /// Refuses an installation that would reintroduce a revoked fingerprint.
    ///
    /// Every install path calls this, which is why it is a parameter of each
    /// of them rather than a check a caller may remember to do: a revoked leaf
    /// coming back through a path nobody wired up is indistinguishable, from
    /// the outside, from a revocation that was never delivered.
    pub fn assert_not_revoked(&self, fingerprints: &[Fingerprint]) -> Result<(), CertificateError> {
        if fingerprints
            .iter()
            .any(|fingerprint| self.is_revoked(fingerprint))
        {
            return Err(CertificateError::Revoked);
        }
        Ok(())
    }

    pub fn last_status_for(&self, target: &Fingerprint) -> Option<(u64, u64)> {
        self.last_statuses
            .get(&target.to_hex())
            .map(|ordering| ordering.key())
    }

    /// Records the ordering of an accepted status for one target.
    pub fn record_status(
        &mut self,
        target: &Fingerprint,
        status: &AstraCertificateStatus,
    ) -> Result<(), CertificateError> {
        let key = target.to_hex();
        if !self.last_statuses.contains_key(&key)
            && self.last_statuses.len() >= MAX_TRACKED_STATUS_TARGETS
        {
            return Err(CertificateError::InvalidTransaction(
                "too many status targets",
            ));
        }
        self.last_statuses.insert(
            key,
            StatusOrdering {
                astra_service_key_epoch: status.astra_service_key_epoch,
                status_epoch: status.status_epoch,
            },
        );
        Ok(())
    }

    /// Forgets the ordering of targets the holder no longer has a slot for.
    ///
    /// A promoted generation is gone from the state, so keeping its counter
    /// would only ever consume room in a bounded map.
    pub fn prune_statuses(&mut self, held: &[Fingerprint]) {
        self.last_statuses
            .retain(|key, _| held.iter().any(|fingerprint| fingerprint.to_hex() == *key));
    }

    fn snapshot(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u64(self.gateway_revocation_epoch)
            .u16(self.scheduled_revocations.len() as u16);
        for revocation in &self.scheduled_revocations {
            bytes
                .u8(scope_byte(revocation.scope))
                .u64(revocation.revocation_epoch)
                .u64(revocation.effective_at)
                // The same one-flag-per-pair rule as the signed revocation
                // (spec §0.5): the base-state fingerprint must not be able to
                // describe a half-filled pair either.
                .optional_revoked_leaf(
                    revocation.revoked_tls_fingerprint.as_ref(),
                    revocation.revoked_tls_not_after,
                )
                .optional_revoked_leaf(
                    revocation.revoked_pq_fingerprint.as_ref(),
                    revocation.revoked_pq_not_after,
                )
                .optional_fingerprint(revocation.revocation_fingerprint.as_ref());
        }
        bytes.u16(self.revoked.len() as u16);
        for tombstone in &self.revoked {
            bytes
                .u8(scope_byte(tombstone.scope))
                .u8(match tombstone.family {
                    RevokedFamily::Tls => 0,
                    RevokedFamily::Pq => 1,
                })
                .fingerprint(&tombstone.fingerprint)
                .u64(tombstone.revocation_epoch)
                .u64(tombstone.expires_at)
                .optional_fingerprint(tombstone.revocation_fingerprint.as_ref());
        }
        bytes.u16(self.last_statuses.len() as u16);
        for (target, ordering) in &self.last_statuses {
            bytes
                .text(target)
                .u64(ordering.astra_service_key_epoch)
                .u64(ordering.status_epoch);
        }
    }
}

const fn scope_byte(scope: RevocationScope) -> u8 {
    match scope {
        RevocationScope::Gateway => 0,
        RevocationScope::Client => 1,
    }
}

/// The instant a fingerprint the holder currently has stops being valid.
///
/// Read from the slots, never from the revocation: the object names what to
/// withdraw, not how long the withdrawn thing would have lived. `None` when
/// this holder has no such certificate — the case the tombstone exists for,
/// and the one where an invented expiry would quietly drop the record.
fn known_expiry(
    gateway: &GatewayCertificateState,
    client: &ClientCertificateState,
    fingerprint: &Fingerprint,
) -> Option<u64> {
    for generation in [
        Some(&client.active),
        client.next.as_ref(),
        client.pending.as_ref().map(|pending| &pending.candidate),
    ]
    .into_iter()
    .flatten()
    {
        if generation.tls_certificate_fingerprint.matches(fingerprint)
            || generation.pq_certificate_fingerprint.matches(fingerprint)
        {
            return Some(generation.not_after);
        }
    }

    for (certificate, tls) in [
        (Some(&gateway.active_gateway_certificate), None),
        (gateway.next_gateway_certificate.as_ref(), None),
        (None, Some(&gateway.active_gateway_tls_certificate)),
        (None, gateway.next_gateway_tls_certificate.as_ref()),
    ] {
        if let Some(certificate) = certificate {
            if pq_certificate_fingerprint(certificate).is_ok_and(|held| held.matches(fingerprint)) {
                return Some(certificate.not_after_unix);
            }
        }
        if let Some(tls) = tls {
            if tls.fingerprint().matches(fingerprint) {
                return crate::certificates::x509::inspect(tls)
                    .ok()
                    .map(|facts| facts.not_after);
            }
        }
    }
    None
}

/// The complete state a transaction is computed against (spec §8.1).
///
/// Passed as one value rather than five arguments because the point is
/// exhaustiveness: adding a slot to the trust store and forgetting to bind it
/// here is what lets a manifest be built against a world that has since moved.
pub struct TrustSnapshot<'a> {
    pub gateway: &'a GatewayCertificateState,
    pub client_tls_ca: &'a ClientTlsCaState,
    pub astra: &'a AstraProfile,
    /// The anti-rollback counter, held **separately** from the delegation.
    ///
    /// A holder that has revoked its issuer, or never installed one, still
    /// carries a counter that only moves forward. Deriving this number from
    /// `issuer` would leave it out of the fingerprint in exactly that case,
    /// and a transaction built before the counter advanced would still match.
    pub issuer_epoch: u64,
    pub issuer: Option<&'a AstraIssuerState>,
    pub client: &'a ClientCertificateState,
    pub ledger: &'a TrustLedger,
}

/// SHA-256 of the receiver's complete trust state (spec §8.1).
///
/// A manifest is bound to this value, so a transaction built against a state
/// that has since moved is refused instead of being applied to a world it was
/// never computed for.
pub fn base_state_fingerprint(snapshot: &TrustSnapshot) -> Result<Fingerprint, CertificateError> {
    let mut bytes = CanonicalBytes::new(BASE_STATE_DOMAIN);
    snapshot.gateway.snapshot(&mut bytes)?;
    snapshot.client_tls_ca.snapshot(&mut bytes);
    snapshot.astra.snapshot(&mut bytes);
    bytes.u64(snapshot.issuer_epoch);
    match snapshot.issuer {
        // The whole delegation, not just its number: an issuer swapped at the
        // same epoch changes which key may certify the next client leaf.
        Some(issuer) => {
            bytes
                .u8(1)
                .u64(issuer.issuer_epoch)
                .fingerprint(&issuer.authorization.fingerprint())
                .u8(match issuer.state {
                    IssuerLifecycle::Active => 0,
                    IssuerLifecycle::Expiring => 1,
                    IssuerLifecycle::Revoked => 2,
                });
        }
        None => {
            bytes.u8(0);
        }
    }
    snapshot.client.snapshot(&mut bytes);
    snapshot.ledger.snapshot(&mut bytes);
    Ok(Fingerprint::of(&bytes.finish()))
}
