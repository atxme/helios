//! One admitted identity, from transcription to terminal revocation.
//!
//! Astra does not decide admission — the gateway does — so everything here
//! either transcribes what the gateway serves or moves the rotation this
//! authority is itself staging: opened, granted, completed, abandoned or
//! purged. `revoked` is terminal, and the status counter of §4.2 only ever
//! increases.

use super::{
    AstraRegistry, AuditEvent, Fingerprint, Id16, PeerRecord, PendingRotation, RegistryError,
    WireGuardKey,
};

impl AstraRegistry {
    pub fn peer(&self, key: &WireGuardKey) -> Option<&PeerRecord> {
        self.state.peers.get(&key.to_base64())
    }

    /// Records a peer's first generation.
    ///
    /// Astra does not decide admission — the gateway does — so this is a
    /// **transcription**: the record is built from what the gateway answers on
    /// the private channel, and it exists so a renewal can be checked against
    /// the generation the domain actually holds rather than the one a request
    /// claims. Re-transcribing an unchanged peer is a no-op, which is what
    /// makes the lazy path of [`crate::renewal`] safe to retry.
    pub fn admit(&mut self, record: PeerRecord, now_unix: u64) -> Result<(), RegistryError> {
        let key = record.client_wg_public_key.to_base64();
        if self.state.peers.get(&key) == Some(&record) {
            return Ok(());
        }
        let generation = record.active.generation;
        let name = record.name.clone();
        self.state.peers.insert(key, record);
        self.state.audit.append(
            AuditEvent::PeerAdmitted {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Adopts the gateway's view of a peer without ever moving it backwards.
    ///
    /// # Why this is not `admit`
    ///
    /// [`Self::admit`] writes a whole `PeerRecord`. Calling it to refresh a
    /// peer would drop `pending` — a rotation whose grant may already be in a
    /// client's hands — and would happily accept a generation lower than the
    /// one already recorded, which is how a stale or rolled-back gateway view
    /// would rewrite this authority's idea of who is current.
    ///
    /// So the rules are stated rather than implied:
    ///
    /// * a generation below the recorded one is refused, never adopted;
    /// * the same generation must describe the same leaf, or it is two
    ///   histories wearing one number and it is refused;
    /// * terminal revocation state must agree, and an admission anchor already
    ///   pinned here cannot be replaced by a later gateway view;
    /// * a rotation in flight survives an adoption it is still ahead of, and
    ///   is dropped only when the adopted generation has caught up with or
    ///   passed the candidate it was staging;
    /// * an unchanged record writes nothing and appends nothing.
    ///
    /// Returns whether anything moved. Idempotent by construction, which is
    /// what makes it safe to replay after a crash: the gateway is the one that
    /// promotes, and this only ever copies what it already serves.
    pub fn reconcile_peer(
        &mut self,
        record: PeerRecord,
        now_unix: u64,
    ) -> Result<bool, RegistryError> {
        let key = record.client_wg_public_key.to_base64();
        let Some(held) = self.state.peers.get(&key) else {
            self.admit(record, now_unix)?;
            return Ok(true);
        };
        if held.revoked != record.revoked || held.revocation_epoch != record.revocation_epoch {
            return Err(RegistryError::RevocationDisagrees);
        }
        if held
            .admission_pq_ca
            .as_ref()
            .is_some_and(|anchor| record.admission_pq_ca.as_ref() != Some(anchor))
        {
            return Err(RegistryError::AdmissionAnchorDisagrees);
        }
        let (held_generation, adopted) = (held.active.generation, record.active.generation);
        if adopted < held_generation {
            return Err(RegistryError::GenerationRegression {
                held: held_generation,
                offered: adopted,
            });
        }
        if adopted == held_generation
            && (held.active != record.active
                || held.active_pq_certificate != record.active_pq_certificate)
        {
            return Err(RegistryError::GenerationDisagrees {
                generation: adopted,
            });
        }

        // The rotation in flight is this authority's own, and the gateway view
        // knows nothing of it. It is kept while it still names a generation
        // ahead of what is served, and dropped once it no longer can: a
        // candidate at or below the adopted generation has either landed or
        // been overtaken, and either way nothing is left to grant.
        let pending = held
            .pending
            .clone()
            .filter(|rotation| rotation.candidate.generation > adopted);
        let dropped_stage = held.pending.is_some() && pending.is_none();
        let name = record.name.clone();
        let admission_pq_ca = held
            .admission_pq_ca
            .clone()
            .or(record.admission_pq_ca.clone());
        let refreshed = PeerRecord {
            pending,
            admission_pq_ca,
            ..record
        };
        if self.state.peers.get(&key) == Some(&refreshed) {
            return Ok(false);
        }
        self.state.peers.insert(key, refreshed);
        if dropped_stage {
            self.state.audit.append(
                AuditEvent::ClientStagePurged {
                    peer: name.clone(),
                    generation: adopted,
                },
                now_unix,
            );
        }
        if adopted > held_generation {
            self.state.audit.append(
                AuditEvent::PeerGenerationAdopted {
                    peer: name,
                    generation: adopted,
                },
                now_unix,
            );
        }
        self.save()?;
        Ok(true)
    }

    /// Opens a rotation, refusing a second one for the same peer.
    ///
    /// One in flight at a time is the same bound the gateway enforces: two
    /// candidates for one identity would make `active + 1` ambiguous.
    pub fn open_rotation(
        &mut self,
        key: &WireGuardKey,
        rotation: PendingRotation,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        if peer.revoked {
            return Err(RegistryError::Revoked);
        }
        if let Some(existing) = &peer.pending {
            if existing == &rotation {
                return Ok(());
            }
            // An expired stage is not "in flight": it is debris, and it must
            // not block the renewal it was supposed to perform.
            if now_unix < existing.stage_expires_at {
                return Err(RegistryError::RotationInFlight);
            }
        }
        let generation = rotation.candidate.generation;
        let name = peer.name.clone();
        peer.pending = Some(rotation);
        self.state.audit.append(
            AuditEvent::ClientStageAuthorized {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Un-reserves a rotation the gateway refused, before its lease runs out.
    ///
    /// A staging that fails must not leave the peer holding a reservation
    /// nobody can clear: `active + 1` would stay unavailable until the lease
    /// expired, for a renewal that never happened. It names the stage it is
    /// clearing and clears nothing else — a refusal arriving after a later
    /// rotation opened would otherwise cancel that one instead.
    ///
    /// A rotation already `granted` is **not** cleared. Past that point Astra
    /// has released the leaves and the client may commit at any moment; taking
    /// the reservation back would let a second candidate be issued for a
    /// generation the gateway is about to promote.
    pub fn abandon_rotation(
        &mut self,
        key: &WireGuardKey,
        stage_id: &Id16,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let rotation = peer.pending.as_ref().ok_or(RegistryError::NoRotation)?;
        if rotation.stage_id != *stage_id || rotation.granted {
            return Err(RegistryError::NoRotation);
        }
        let rotation = peer.pending.take().expect("checked immediately above");
        let name = peer.name.clone();
        self.state.audit.append(
            AuditEvent::ClientStagePurged {
                peer: name,
                generation: rotation.candidate.generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Marks a rotation as granted — the point past which Astra has released
    /// the leaves and can no longer withhold them.
    pub fn mark_granted(&mut self, key: &WireGuardKey, now_unix: u64) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let name = peer.name.clone();
        let rotation = peer.pending.as_mut().ok_or(RegistryError::NoRotation)?;
        if rotation.granted {
            return Ok(());
        }
        rotation.granted = true;
        let generation = rotation.candidate.generation;
        self.state.audit.append(
            AuditEvent::ClientGrantReleased {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Promotes the candidate once the client has committed it.
    pub fn complete_rotation(
        &mut self,
        key: &WireGuardKey,
        pq_certificate: aether::key_negotiation::PqCertificate,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let rotation = peer.pending.take().ok_or(RegistryError::NoRotation)?;
        peer.active = rotation.candidate;
        peer.active_pq_certificate = pq_certificate;
        let name = peer.name.clone();
        let generation = peer.active.generation;
        self.state.audit.append(
            AuditEvent::ClientGrantReleased {
                peer: name,
                generation,
            },
            now_unix,
        );
        self.save()
    }

    /// Drops every rotation whose lease has run out.
    pub fn purge_expired(&mut self, now_unix: u64) -> Result<Vec<String>, RegistryError> {
        let mut purged = Vec::new();
        for peer in self.state.peers.values_mut() {
            let expired = peer
                .pending
                .as_ref()
                .is_some_and(|rotation| now_unix >= rotation.stage_expires_at);
            if expired {
                let rotation = peer.pending.take().expect("checked");
                purged.push(peer.name.clone());
                self.state.audit.append(
                    AuditEvent::ClientStagePurged {
                        peer: peer.name.clone(),
                        generation: rotation.candidate.generation,
                    },
                    now_unix,
                );
            }
        }
        if !purged.is_empty() {
            self.save()?;
        }
        Ok(purged)
    }

    /// Terminal revocation. Dominates a rotation already in flight.
    pub fn revoke(
        &mut self,
        key: &WireGuardKey,
        revocation_epoch: u64,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let peer = self
            .state
            .peers
            .get_mut(&key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.revoked = true;
        peer.revocation_epoch = revocation_epoch;
        peer.pending = None;
        let name = peer.name.clone();
        self.state
            .audit
            .append(AuditEvent::CertificateRevoked { target: name }, now_unix);
        self.save()
    }

    /// Next status counter for a target, strictly increasing (spec §4.2).
    pub fn next_status_epoch(&mut self, fingerprint: &Fingerprint) -> u64 {
        let entry = self
            .state
            .status_epochs
            .entry(fingerprint.to_hex())
            .or_insert(0);
        *entry += 1;
        *entry
    }
}
