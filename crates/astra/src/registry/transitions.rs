//! The signed objects the companion produced, and the anchors they move.
//!
//! Every object is verified here, under the anchor and the epoch this registry
//! already holds, before a byte is written — the whole reason an online
//! authority may hold objects it could never forge. The store is bounded and
//! refuses rather than evicting; expiry, promotion of a due anchor and the
//! removal of the transition it consumes share one atomic write; and a gateway
//! decision is held back until §11.1 step 6 lets it leave.

use super::{
    AstraRegistry, AuditEvent, CaPqRotation, ClientTlsCaRotation, Fingerprint, RegistryError,
    StoredTransition, TransitionWindow, MAX_STORED_REVOCATIONS, MAX_STORED_TRANSITIONS,
};

impl AstraRegistry {
    /// Records the anchor transitions an approved campaign produced (§0.6).
    ///
    /// Every object is verified **here**, under the anchor and the epoch this
    /// registry already holds, before a byte is written. That is the whole
    /// reason the online authority may hold them at all: it re-derives the
    /// `CA-PQ` proof rather than trusting the channel that delivered it, and a
    /// forged object fails against a key no online process possesses.
    ///
    /// Depositing the same object twice is a **no-op**, not a second entry: a
    /// companion that retries after a lost response must not make the peer
    /// collect the same transition under two fingerprints.
    pub fn accept_transitions(
        &mut self,
        campaign: &aether::certificates::status::AstraRotationCampaign,
        objects: &[aether::certificates::transport::TrustUpdateObject],
        credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
        now_unix: u64,
    ) -> Result<usize, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        let campaign_id = campaign.campaign_id;

        let mut fresh = Vec::new();
        let mut withdrawn = Vec::new();
        let mut ca_rotation = self.state.ca_rotation.clone();
        let mut ca_tls_rotation = self.state.ca_tls_rotation.clone();
        for object in objects {
            let fingerprint = object.fingerprint()?;
            let held = self.state.transitions.iter().try_fold(
                false,
                |found, stored| -> Result<bool, RegistryError> {
                    Ok(found || stored.object.fingerprint()?.matches(&fingerprint))
                },
            )?;
            let repeated_in_batch = fresh.iter().try_fold(
                false,
                |found, pending: &TrustUpdateObject| -> Result<bool, RegistryError> {
                    Ok(found || pending.fingerprint()?.matches(&fingerprint))
                },
            )?;
            // An identical retry names an object this registry has already
            // verified and applied. In particular, checking its old counter
            // against the now-advanced revocation counter would turn the
            // idempotent retry into a rollback error.
            if held || repeated_in_batch {
                continue;
            }
            match object {
                TrustUpdateObject::CaTransition(transition) => {
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                    )?;
                    if ca_rotation.is_some() {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "a CA-PQ rotation is already in flight",
                            ),
                        ));
                    }
                    ca_rotation = Some(CaPqRotation::from_transition(transition));
                }
                TrustUpdateObject::CertificateRevocation(revocation) => {
                    use aether::certificates::revocation::RevocationScope;

                    if revocation.effective_at > now_unix {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IssuerScopeViolation(
                                "this authority accepts only immediately effective revocations",
                            ),
                        ));
                    }
                    if revocation.scope == RevocationScope::Gateway {
                        // The gateway's own leaves were never recorded here,
                        // so the approved campaign is the only place their
                        // state is pinned — the same asymmetry as a gateway
                        // transition. `covers_revocation` ties identity,
                        // fingerprints and counter to the text an operator
                        // read at a security key; only then may the counter be
                        // read back from the object to verify its signature.
                        campaign.covers_revocation(revocation)?;
                        let current_epoch = revocation.revocation_epoch.checked_sub(1).ok_or(
                            RegistryError::Transition(
                                aether::certificates::CertificateError::CampaignMismatch,
                            ),
                        )?;
                        revocation.verify(
                            &self.state.ca_public_key,
                            &self.state.trust_domain_id,
                            self.state.ca_epoch,
                            current_epoch,
                        )?;
                        fresh.push(object.clone());
                        continue;
                    }
                    let key = revocation.identity_key.to_base64();
                    let peer = self
                        .state
                        .peers
                        .get(&key)
                        .ok_or(RegistryError::UnknownPeer)?;
                    revocation.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        peer.revocation_epoch,
                    )?;
                    let tls_matches = revocation
                        .revoked_tls_fingerprint
                        .zip(revocation.revoked_tls_not_after)
                        .is_none_or(|(fingerprint, not_after)| {
                            peer.active
                                .tls_certificate_fingerprint
                                .matches(&fingerprint)
                                && peer.active.not_after == not_after
                        });
                    let pq_matches = revocation
                        .revoked_pq_fingerprint
                        .zip(revocation.revoked_pq_not_after)
                        .is_none_or(|(fingerprint, not_after)| {
                            peer.active.pq_certificate_fingerprint.matches(&fingerprint)
                                && peer.active.not_after == not_after
                        });
                    if !tls_matches || !pq_matches {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::CampaignMismatch,
                        ));
                    }
                    withdrawn.push((key, revocation.revocation_epoch));
                }
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    // The campaign first, and it is not a formality here: this
                    // authority holds no gateway leaf, so the approved text is
                    // the only place the state this decision was taken against
                    // is pinned. Verifying the object against fingerprints it
                    // carries itself would be verifying nothing — it is
                    // `covers_gateway_transition` that ties them to what an
                    // operator read at a security key.
                    campaign.covers_gateway_transition(transition)?;
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        transition.gateway_identity_epoch.checked_sub(1).ok_or(
                            RegistryError::Transition(
                                aether::certificates::CertificateError::CampaignMismatch,
                            ),
                        )?,
                        &self.state.gateway_wg_public_key,
                        &self.state.server_name,
                        &transition.active_gateway_tls_certificate_fingerprint,
                        &transition.active_gateway_certificate_fingerprint,
                    )?;
                }
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    campaign.covers_gateway_abort(abort)?;
                    // An abort is verified against the exact document it
                    // cancels, so that document must already be here. It is
                    // the same rule the gateway applies, and it is why an
                    // abort deposited before its transition is refused rather
                    // than stored for a transition that may never arrive.
                    let cancelled = self
                        .state
                        .transitions
                        .iter()
                        .filter_map(|stored| match &stored.object {
                            TrustUpdateObject::GatewayIdentityTransition(held) => {
                                Some((held, stored.published))
                            }
                            _ => None,
                        })
                        .find(|(held, _)| {
                            held.fingerprint().is_ok_and(|held_fingerprint| {
                                held_fingerprint.matches(&abort.gateway_transition_fingerprint)
                            })
                        })
                        .ok_or(RegistryError::Transition(
                            aether::certificates::CertificateError::CampaignMismatch,
                        ))?;
                    // The publication marker this authority persisted, not a
                    // constant: past it a client may already hold the decision,
                    // and refusing the abort here is what keeps one fleet from
                    // holding two truths (spec §6.3).
                    abort.verify(
                        &self.state.ca_public_key,
                        cancelled.0,
                        cancelled.1,
                        now_unix,
                    )?;
                }
                TrustUpdateObject::ClientTlsCaTransition(transition) => {
                    // The anchor this registry pins, never one taken from the
                    // object: comparing a transition to the fingerprint it
                    // carries itself would be comparing a value to itself.
                    // A domain bootstrapped before that pin existed is refused
                    // by name rather than checked against nothing.
                    let active = self
                        .state
                        .ca_tls_fingerprint
                        .ok_or(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "no client CA-TLS anchor is pinned here: record it with \
                             `astra pin-ca-tls` before a rotation can be verified",
                            ),
                        ))?;
                    transition.verify(
                        &self.state.ca_public_key,
                        &self.state.trust_domain_id,
                        self.state.ca_epoch,
                        self.state.ca_tls_epoch,
                        &active,
                    )?;
                    if ca_tls_rotation.is_some() {
                        return Err(RegistryError::Transition(
                            aether::certificates::CertificateError::IllegalStateTransition(
                                "a client CA-TLS rotation is already in flight",
                            ),
                        ));
                    }
                    ca_tls_rotation = Some(ClientTlsCaRotation::from_transition(transition));
                }
                _ => {
                    return Err(RegistryError::Transition(
                        aether::certificates::CertificateError::IssuerScopeViolation(
                            "this authority stores only a CA-PQ transition, a gateway identity \
                             decision or a client revocation",
                        ),
                    ))
                }
            }
            fresh.push(object.clone());
        }
        if fresh.is_empty() {
            return Ok(0);
        }
        let held_revocations = self
            .state
            .transitions
            .iter()
            .filter(|stored| {
                matches!(stored.object, TrustUpdateObject::CertificateRevocation(_))
                    && retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
            })
            .count();
        let fresh_revocations = fresh
            .iter()
            .filter(|object| matches!(object, TrustUpdateObject::CertificateRevocation(_)))
            .count();
        if held_revocations + fresh_revocations > MAX_STORED_REVOCATIONS {
            return Err(RegistryError::RevocationStoreFull {
                held: held_revocations,
            });
        }
        let held_transitions = self
            .state
            .transitions
            .iter()
            .filter(|stored| {
                !matches!(stored.object, TrustUpdateObject::CertificateRevocation(_))
                    && retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
            })
            .count();
        let fresh_transitions = fresh.len() - fresh_revocations;
        if held_transitions + fresh_transitions > MAX_STORED_TRANSITIONS {
            return Err(RegistryError::TransitionStoreFull {
                held: held_transitions,
            });
        }

        // Capacity has been proven without mutation. Only now remove expired
        // objects and commit the fresh batch, so a refused deposit leaves the
        // in-memory state exactly as it was.
        self.state.transitions.retain(|stored| {
            retained_until(&stored.object).is_some_and(|not_after| now_unix < not_after)
        });
        self.state.ca_rotation = ca_rotation;
        self.state.ca_tls_rotation = ca_tls_rotation;
        let accepted = fresh.len();
        for object in fresh {
            // A gateway transition is held back until §11.1 step 6; every
            // other object is distributable the moment it is accepted.
            let published = !matches!(
                object,
                TrustUpdateObject::GatewayIdentityTransition(_)
                    | TrustUpdateObject::GatewayTransitionAbort(_)
            );
            self.state.transitions.push(StoredTransition {
                campaign_id,
                accepted_at: now_unix,
                object,
                published,
                credential_registry: credential_registry.clone(),
            });
        }
        // The authority stops issuing for the identity as part of accepting
        // the signed decision. Delivery to other clients may follow later;
        // it must never be a prerequisite for the local withdrawal.
        for (key, revocation_epoch) in withdrawn {
            if let Some(peer) = self.state.peers.get_mut(&key) {
                peer.revoked = true;
                peer.revocation_epoch = revocation_epoch;
                peer.pending = None;
                self.state.audit.append(
                    AuditEvent::CertificateRevoked {
                        target: peer.name.clone(),
                    },
                    now_unix,
                );
            }
        }
        if fresh_transitions > 0 {
            self.state.audit.append(
                AuditEvent::AnchorTransitionsAccepted {
                    campaign: campaign_id.to_hex(),
                    objects: fresh_transitions,
                },
                now_unix,
            );
        }
        self.save()?;
        Ok(accepted)
    }

    /// Adopts due `CA-PQ` and client TLS anchors, then drops transitions no
    /// peer can still be told about (spec §§4.1, 9.2 and 9.4).
    ///
    /// A transition past its `not_after` authorizes nothing: a client that
    /// received it would refuse it, and one that did not has to be repaired by
    /// an operator rather than by a delivery that arrives after the window it
    /// was signed for. Forgetting it is what keeps the bounded store from
    /// filling with objects that can no longer do anything. Promotion and the
    /// removal of the transition it consumes share this method and therefore
    /// one atomic registry write: after a restart Astra cannot observe one
    /// without the other.
    pub fn forget_expired_transitions(&mut self, now_unix: u64) -> Result<usize, RegistryError> {
        let before = self.state.transitions.len();
        // Read before the retain below drops the transition this promotion
        // consumes: the document it carries is what the daemon adopts.
        let rotation_credentials = self.state.ca_rotation.as_ref().and_then(|rotation| {
            if now_unix < rotation.retire_active_at {
                return None;
            }
            self.state
                .transitions
                .iter()
                .find_map(|stored| match &stored.object {
                    aether::certificates::transport::TrustUpdateObject::CaTransition(
                        transition,
                    ) if transition.next_ca_epoch == rotation.next_ca_epoch => {
                        stored.credential_registry.clone()
                    }
                    _ => None,
                })
        });
        self.state
            .transitions
            .retain(|stored| match retained_until(&stored.object) {
                Some(not_after) => now_unix < not_after,
                // Something with no window is something this store does not
                // hold; keeping it would be keeping an object nothing prunes.
                None => false,
            });
        let dropped = before - self.state.transitions.len();
        let due_ca_rotation = self
            .state
            .ca_rotation
            .as_ref()
            .filter(|rotation| now_unix >= rotation.retire_active_at)
            .cloned();
        let ca_promoted = if let Some(rotation) = due_ca_rotation {
            self.state.ca_epoch = rotation.next_ca_epoch;
            self.state.ca_public_key = rotation.next_ca_public_key;
            self.state.ca_rotation = None;
            // Only a CA-PQ promotion feeds it: a CA-TLS one re-signs nothing.
            if rotation_credentials.is_some() {
                self.state.promoted_credentials = rotation_credentials;
            }
            true
        } else {
            false
        };
        let due_tls_rotation = self
            .state
            .ca_tls_rotation
            .as_ref()
            .filter(|rotation| now_unix >= rotation.retire_active_at)
            .cloned();
        let ca_tls_promoted = if let Some(rotation) = due_tls_rotation {
            self.state.ca_tls_epoch = rotation.next_ca_tls_epoch;
            self.state.ca_tls_fingerprint = Some(rotation.next_ca_tls_fingerprint);
            self.state.ca_tls_rotation = None;
            true
        } else {
            false
        };
        if dropped > 0 || ca_promoted || ca_tls_promoted {
            self.save()?;
        }
        Ok(dropped)
    }

    /// Hands out the credential document a promotion left to adopt, and
    /// forgets it.
    ///
    /// Called last, once the file and the memory carry the document: replaying
    /// any earlier step after a restart is harmless, whereas clearing first
    /// would lose the document on a crash.
    pub fn take_promoted_credentials(
        &mut self,
    ) -> Result<Option<Box<aether::certificates::approval::CredentialRegistry>>, RegistryError>
    {
        let Some(document) = self.state.promoted_credentials.take() else {
            return Ok(None);
        };
        if let Err(error) = self.save() {
            // Still pending in memory as on disk: the next pass retries.
            self.state.promoted_credentials = Some(document);
            return Err(error);
        }
        Ok(Some(document))
    }

    /// Lets a stored gateway decision leave the authority (spec §11.1 step 6).
    ///
    /// Persisted **before** the first byte, and irreversible. A gateway
    /// transition that has been distributed can no longer be aborted: a client
    /// may hold it, go offline, and promote on its own at `not_after`.
    ///
    /// The publication names the exact document: several transitions may be
    /// stored at one epoch, and publishing "the first at this epoch" could
    /// close the abort window on one the gateway never installed.
    ///
    /// Idempotent, because the relay to the gateway that follows may fail
    /// after this write. Re-running the step must be able to finish the relay
    /// without asking `CA-PQ` to sign anything again.
    pub fn publish_gateway_transition(
        &mut self,
        gateway_identity_epoch: u64,
        transition_fingerprint: &Fingerprint,
        now_unix: u64,
    ) -> Result<aether::certificates::gateway::GatewayIdentityTransition, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        let position = self
            .state
            .transitions
            .iter()
            .position(|stored| match &stored.object {
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    transition.gateway_identity_epoch == gateway_identity_epoch
                        && transition
                            .fingerprint()
                            .is_ok_and(|held| held.matches(transition_fingerprint))
                }
                _ => false,
            })
            .ok_or(RegistryError::UnknownPeer)?;
        let TrustUpdateObject::GatewayIdentityTransition(transition) =
            self.state.transitions[position].object.clone()
        else {
            return Err(RegistryError::UnknownPeer);
        };
        if self.state.transitions[position].published {
            // Saved again rather than trusted: the relay that follows closes
            // the gateway's abort window, so it may only ever follow a mark
            // the file holds.
            self.save()?;
            return Ok(*transition);
        }
        // An aborted decision never becomes publishable: the tombstone that
        // cancelled it is itself a stored object at the same epoch.
        let cancelled = self
            .state
            .transitions
            .iter()
            .any(|stored| match &stored.object {
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    abort.gateway_identity_epoch == gateway_identity_epoch
                }
                _ => false,
            });
        if cancelled {
            return Err(RegistryError::Transition(
                aether::certificates::CertificateError::IllegalStateTransition(
                    "this transition was aborted; the epoch stays consumed",
                ),
            ));
        }
        self.state.transitions[position].published = true;
        self.state.audit.append(
            AuditEvent::GatewayTransitionPublished {
                gateway_identity_epoch,
            },
            now_unix,
        );
        self.save()?;
        Ok(*transition)
    }

    /// Records the client `CA-TLS` this domain serves, once (spec §9.4).
    ///
    /// Refuses to replace one already pinned: an anchor that a command can
    /// overwrite is an anchor an operator error can move, and §9.4 makes that
    /// move a signed transition instead.
    pub fn pin_client_tls_ca(
        &mut self,
        fingerprint: Fingerprint,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        if let Some(held) = self.state.ca_tls_fingerprint {
            if !held.matches(&fingerprint) {
                return Err(RegistryError::Transition(
                    aether::certificates::CertificateError::IllegalStateTransition(
                        "a client CA-TLS anchor is already pinned; replacing it is a rotation",
                    ),
                ));
            }
            return Ok(());
        }
        let mut state = self.state.clone();
        state.ca_tls_fingerprint = Some(fingerprint);
        state.audit.append(
            AuditEvent::ClientTlsCaPinned {
                ca_tls_epoch: state.ca_tls_epoch,
            },
            now_unix,
        );
        self.state = state;
        self.save()
    }
}

/// The window an anchor transition is in force for, when it carries one.
///
/// Read from the object rather than recorded beside it: two copies of a
/// deadline drift, and the one that decides must be the one the signature
/// covers.
fn transition_window(
    object: &aether::certificates::transport::TrustUpdateObject,
) -> Option<&TransitionWindow> {
    use aether::certificates::transport::TrustUpdateObject;
    match object {
        TrustUpdateObject::CaTransition(transition) => Some(&transition.window),
        TrustUpdateObject::ClientTlsCaTransition(transition) => Some(&transition.window),
        TrustUpdateObject::GatewayIdentityTransition(transition) => Some(&transition.window),
        _ => None,
    }
}

/// Last instant at which a stored object can still affect a recipient.
fn retained_until(object: &aether::certificates::transport::TrustUpdateObject) -> Option<u64> {
    use aether::certificates::transport::TrustUpdateObject;

    if let TrustUpdateObject::CertificateRevocation(revocation) = object {
        return revocation
            .revoked_tls_not_after
            .into_iter()
            .chain(revocation.revoked_pq_not_after)
            .max();
    }
    transition_window(object).map(|window| window.not_after)
}
