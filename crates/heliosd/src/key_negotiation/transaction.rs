//! Per-peer PSK slots: ownership, generations and the handler state they live in.

use super::*;

pub(super) struct Transaction {
    pub(super) public_key: String,
    pub(super) address: String,
    pub(super) client_pq_public_key: String,
    pub(super) mode: ProtectionMode,
    pub(super) server_challenge: [u8; SERVER_CHALLENGE_LEN],
    /// Slot generation this transaction **reserved**, not merely observed.
    ///
    /// Anything that acts on the slot later must present it. A rollback whose
    /// generation no longer matches is a no-op, because something newer has
    /// happened to that peer in the meantime.
    pub(super) generation: u64,
    /// Last handshake the data plane reported **immediately before** the
    /// candidate PSK was posed.
    ///
    /// The commit demands a strictly later value. This is the only thing in
    /// the protocol that proves the peer holds the WireGuard private key: the
    /// QUIC and ML-DSA layers prove possession of the TLS and PQ identities,
    /// which are three separate keys. Without it, an attacker holding a
    /// stolen client identity — but not its WireGuard key — can have the
    /// gateway install a PSK of their choosing and cut the real client off.
    pub(super) handshake_before_install: Option<std::time::SystemTime>,
}

/// What the gateway currently holds in a peer's WireGuard PSK slot.
///
/// v4 needed nothing like this: the QUIC link was the ownership record, and
/// it vanished with the client. v5 has no link, so the slot's meaning is
/// written down — and the two kinds of PSK a slot can hold are **not**
/// interchangeable, which is the distinction v4 never had to make.
pub(super) enum SlotState {
    /// Nothing posed, or a candidate that never committed.
    Empty,
    /// A `static_psk` negotiation committed.
    ///
    /// The value in the slot is configuration, belonging to both peers before
    /// the transaction started and after it ended. It has no transactional
    /// owner, so nothing may release it, no deadline expires it, and data-plane
    /// reclamation must leave it alone: clearing it would delete an operator's
    /// configured secret because a laptop was closed for five minutes, and no
    /// renegotiation would put it back — only the operator could.
    ConfiguredStatic,
    /// A fresh `ml_kem` PSK, owned by the transaction that derived it.
    Committed(InstalledPsk),
    /// A candidate is posed and its transaction has not resolved yet.
    ///
    /// From the moment the candidate reaches the data plane it is the slot's
    /// logical owner (spec §11.1), which is the whole point of naming this
    /// state: without it the table still described the *displaced* PSK while
    /// the wire already carried the new one, so a `release` naming the old
    /// transaction — or a reclamation decided on an old, stale handshake —
    /// matched, cleared the data plane, and wiped a candidate that was about
    /// to commit. The gateway would then have signed a commit for a PSK no
    /// longer posed.
    ///
    /// Everything after `transaction_id` is rollback data. Nothing may act on
    /// it, and it lives **here** rather than only in the transaction record
    /// so that undoing a candidate needs no transaction record at all: a
    /// `prepare` destroyed between installing the candidate and recording it
    /// is still fully undoable, because the slot itself says what to put
    /// back.
    Preparing {
        transaction_id: [u8; 16],
        previous: Box<SlotState>,
        address: String,
        previous_psk: Option<SecretString>,
        /// Whether the candidate's installation has been **begun**.
        ///
        /// Set before the call, not after it, so that it is true even when
        /// the call is cancelled or fails: at that point the gateway does not
        /// know what the data plane holds, and §11.3's rest period is owed
        /// either way. Deriving this from the transaction record instead
        /// would lose it, because an interrupted preparation can have no
        /// transaction record yet and the slot is the only state guaranteed
        /// to survive the task that began the write.
        install_attempted: bool,
    },
    /// The peer left admission (spec §11.1, priority 1).
    ///
    /// Terminal until the key is admitted again. Entering it destroys the
    /// candidate and the rollback data, and drops every transaction of the
    /// peer, so no rollback, `release` or reclamation decided earlier can put
    /// anything back: they all find a generation they do not hold and a slot
    /// that is not theirs.
    Revoked,
}

impl SlotState {
    /// A named copy, because a slot can hold a secret and [`SecretString`]
    /// deliberately has no `Clone`.
    ///
    /// `Preparing` carries the PSK to put back on rollback, which makes the
    /// whole slot a secret-bearing type. ADR-006 §5 asks that the copies such
    /// a type needs be operations a reviewer can grep for rather than ones
    /// the compiler performs silently, so the derive is replaced by this.
    fn duplicate(&self) -> Self {
        match self {
            Self::Empty => Self::Empty,
            Self::ConfiguredStatic => Self::ConfiguredStatic,
            Self::Committed(installed) => Self::Committed(installed.clone()),
            Self::Preparing {
                transaction_id,
                previous,
                address,
                previous_psk,
                install_attempted,
            } => Self::Preparing {
                transaction_id: *transaction_id,
                previous: Box::new(previous.duplicate()),
                address: address.clone(),
                previous_psk: previous_psk.as_ref().map(SecretString::duplicate),
                install_attempted: *install_attempted,
            },
            Self::Revoked => Self::Revoked,
        }
    }
}

/// A PSK the gateway holds for a peer, and when it started holding it.
///
/// Ownership is what lets a delayed `release` be told from a current one, and
/// `installed_at` is what gives the 24-hour deadline something to measure.
#[derive(Clone)]
pub struct InstalledPsk {
    pub transaction_id: [u8; 16],
    pub public_key: String,
    pub address: String,
    pub installed_at: std::time::Instant,
    /// `rx + tx` of the peer at the first snapshot after the commit.
    ///
    /// The gateway never re-registers a peer for a new PSK, so its counters
    /// run on across PSKs: what this one carried is the difference. Set by the
    /// reclaimer, whose snapshot is at most ten seconds old — negligible next
    /// to the ceiling.
    pub bytes_baseline: Option<u64>,
}

impl InstalledPsk {
    /// Counts what this PSK has carried and names the ceiling once reached.
    ///
    /// A counter below the baseline means the peer was re-created (hot
    /// reload): counting restarts from it rather than reading a wrap-around
    /// as a huge transfer. The lifetime still bounds the slot meanwhile.
    pub(super) fn charge_transfer(&mut self, total: u64) -> Option<String> {
        let baseline = match self.bytes_baseline {
            Some(baseline) if total >= baseline => baseline,
            _ => {
                self.bytes_baseline = Some(total);
                return None;
            }
        };
        let carried = total - baseline;
        (carried >= aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT).then(|| {
            format!(
                "PSK carried {} GiB, its {} GiB ceiling, without a renewal",
                carried >> 30,
                aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT >> 30
            )
        })
    }
}

/// A peer's slot, and a counter that orders every change to it.
///
/// The generation is what makes late actors safe. Three of them can arrive
/// after the fact — a rollback for a transaction that already ended, a
/// `release` delayed on the network, a reclamation decided from a snapshot
/// taken seconds ago — and each would otherwise clear a slot a *newer*
/// negotiation had just filled, tearing down a tunnel that was working.
pub(super) struct PeerSlot {
    pub(super) generation: u64,
    pub(super) state: SlotState,
    /// End of the rest period a post-installation rollback arms (spec §4.5).
    ///
    /// Ten seconds during which this peer poses nothing new. A negotiation
    /// identity that has been stolen but is not backed by the peer's
    /// WireGuard key can never commit — the handshake proof stops it — but
    /// without this it can pose and roll back a candidate as fast as the
    /// round-trip allows, keeping a working slot in permanent oscillation.
    pub(super) resting_until: Option<std::time::Instant>,
}

impl Default for PeerSlot {
    fn default() -> Self {
        Self {
            generation: 0,
            state: SlotState::Empty,
            resting_until: None,
        }
    }
}

/// Rest imposed on a peer by a rollback that had already posed a candidate.
const POST_INSTALL_REST: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Default)]
pub(super) struct TransactionState {
    pub(super) active: HashMap<[u8; 16], Transaction>,
    /// Slot state per peer, by WireGuard public key.
    slots: HashMap<String, PeerSlot>,
    pub(super) peers: HashSet<String>,
    pub(super) replay_order: VecDeque<[u8; 16]>,
    pub(super) replay_set: HashSet<[u8; 16]>,
}

impl TransactionState {
    pub(super) fn slot(&mut self, public_key: &str) -> &mut PeerSlot {
        self.slots.entry(public_key.to_string()).or_default()
    }

    /// Aligns a peer's slot with whether admission still holds its key.
    ///
    /// A peer that left admission is revoked: generation incremented, every
    /// transaction and reservation of the peer dropped, candidate and
    /// rollback data destroyed. A revoked peer whose key is admitted again
    /// starts over from an empty slot, under a new generation. Returns
    /// whether this call revoked the slot.
    ///
    /// Removal reaches the gateway as a new `network.toml`, applied by the
    /// orchestrator, which drops the peer from the data plane and refuses any
    /// later PSK write for it. The slot learns it here, under the lock every
    /// slot transition holds, so that no actor decides on a slot that still
    /// describes a peer nobody admits.
    pub(super) fn settle_admission(&mut self, public_key: &str, admitted: bool) -> bool {
        let slot = self.slot(public_key);
        match (admitted, matches!(slot.state, SlotState::Revoked)) {
            (false, false) => {
                slot.generation += 1;
                slot.state = SlotState::Revoked;
                slot.resting_until = None;
                self.peers.remove(public_key);
                self.active
                    .retain(|_, transaction| transaction.public_key != public_key);
                true
            }
            (true, true) => {
                slot.generation += 1;
                slot.state = SlotState::Empty;
                false
            }
            _ => false,
        }
    }
}

pub struct GatewayHandler {
    pub(super) network: Arc<RwLock<NetworkConfig>>,
    pub(super) psk_tx: mpsc::Sender<InstallPskRequest>,
    /// Fresh reads of the data plane, for the handshake proof at the commit.
    pub(super) handshake_tx: mpsc::Sender<aether::ObserveHandshakeRequest>,
    pub(super) gateway_public_key: String,
    pub(super) client_pq_ca_public_key: Vec<u8>,
    /// The certificate registry, when this gateway has a trust domain.
    ///
    /// Read-only here, and read for one reason: a client that has renewed
    /// presents a leaf `network.toml` has never heard of. That file is written
    /// once, at admission, and nothing updates it afterwards — so a gateway
    /// resolving callers only from it refuses every peer it has itself just
    /// renewed, at the end of the overlap, on a machine whose only channel for
    /// asking about it was the tunnel it can no longer open.
    ///
    /// `None` is the ordinary state of a gateway with no trust domain, and
    /// there the behaviour is exactly what it was: the pins of `network.toml`
    /// and the single client PQ CA on disk.
    pub(super) registry: Option<crate::certificates::SharedRegistry>,
    pub(super) gateway_pq_certificate: PqCertificate,
    /// Fingerprint of the certificate this daemon actually serves.
    ///
    /// Computed once at startup from the loaded certificate, not read from a
    /// file at request time: a rotation the daemon has not restarted for must
    /// make requests fail against what is *served*, which is exactly the
    /// discrepancy the startup log names.
    pub(super) served_certificate_fingerprint: String,
    pub(super) gateway_pq_private_key: Zeroizing<Vec<u8>>,
    pub(super) dry_run: bool,
    pub(super) static_psks: RwLock<HashMap<String, SecretString>>,
    pub(super) transactions: Mutex<TransactionState>,
}

pub(super) fn elevate_security_floor(
    network: &mut NetworkConfig,
    public_key: &str,
    mode: ProtectionMode,
) -> Result<Option<ProtectionMode>, PublicError> {
    let peer = network
        .peers
        .iter_mut()
        .find(|peer| peer.public_key == public_key)
        .ok_or(PublicError::Rejected)?;
    // A plain WireGuard peer never negotiates: the protocol refuses it before
    // a mode is committed. Reaching here without a floor is an inconsistent
    // state, refused rather than given a floor it was never admitted with.
    let current = peer
        .minimum_key_negotiation_mode
        .ok_or(PublicError::Rejected)?;
    if mode == current || !mode.satisfies(current) {
        return Ok(None);
    }
    peer.minimum_key_negotiation_mode = Some(mode);
    Ok(Some(current))
}

impl GatewayHandler {
    /// The identity behind the fingerprint mTLS proved, from the registry.
    ///
    /// `None` when this gateway holds no registry, or when the registry knows
    /// nothing about that fingerprint — the caller then falls back to the pins
    /// of `network.toml`, which is what an un-bootstrapped gateway has always
    /// used and what a peer admitted before the trust domain existed still
    /// answers to.
    ///
    /// The PQ half that comes back is the **partner** of the TLS half, not the
    /// union of what the peer may hold: accepting the union would accept the
    /// mixed pair of spec §3.3, where each half is valid under a different
    /// generation and the assembled identity was never issued.
    pub(super) async fn registered_identity(
        &self,
        certificate_sha256: &str,
        now_unix: u64,
    ) -> Option<helios_provisioning::certificates::NegotiationIdentity> {
        let registry = self.registry.as_ref()?;
        let fingerprint =
            aether::certificates::encoding::Fingerprint::parse_hex(certificate_sha256).ok()?;
        registry
            .lock()
            .await
            .state()
            .resolve_negotiation_identity(&fingerprint, now_unix)
    }

    /// PQ leaves an already-authenticated peer may present, from the registry.
    ///
    /// Keyed by the WireGuard identity rather than by a fingerprint, because
    /// this serves the in-tunnel routes: there the tunnel is the proof and
    /// `require_peer` has already resolved the caller from its source VIP.
    /// Empty when the gateway holds no registry, or knows nothing about this
    /// peer — the caller then falls back to the pin of `network.toml`.
    pub(super) async fn registered_pq_fingerprints(
        &self,
        wg_public_key: &str,
        now_unix: u64,
    ) -> Vec<String> {
        let Some(registry) = self.registry.as_ref() else {
            return Vec::new();
        };
        let Ok(key) = aether::certificates::encoding::WireGuardKey::parse(wg_public_key) else {
            return Vec::new();
        };
        registry
            .lock()
            .await
            .acceptable_pq_fingerprints(&key, now_unix)
            .into_iter()
            .map(|fingerprint| fingerprint.to_hex())
            .collect()
    }

    /// Every ML-DSA-87 key that may legitimately have signed a client leaf.
    ///
    /// The one on disk is always in the set, and that is not belt and braces:
    /// a peer's **first** generation was issued by the operator CA that
    /// `init-key-negotiation` installed, and the registry does not necessarily
    /// hold that key at all — `init-trust-domain` receives the domain anchor
    /// from Astra, which is a different key. Dropping it would refuse every
    /// client that has never renewed, which is all of them on a fresh domain.
    ///
    /// The registry adds the anchor, its successor during a CA overlap, and
    /// the delegated issuer an ordinary renewal is actually issued under.
    pub(super) async fn client_leaf_issuers(&self, now_unix: u64) -> Vec<Vec<u8>> {
        let mut issuers = vec![self.client_pq_ca_public_key.clone()];
        if let Some(registry) = self.registry.as_ref() {
            for key in registry.lock().await.state().client_leaf_issuers(now_unix) {
                let bytes = key.as_bytes().to_vec();
                if !issuers.contains(&bytes) {
                    issuers.push(bytes);
                }
            }
        }
        issuers
    }

    /// [`TransactionState::settle_admission`] against the live configuration.
    ///
    /// Called with the transaction lock held, first thing in every section
    /// that acts on a slot. The configuration guard is released before this
    /// returns: callers go on to the data plane, whose writer takes it.
    pub(super) async fn settle_admission(&self, state: &mut TransactionState, public_key: &str) {
        let admitted = self
            .network
            .read()
            .await
            .peers
            .iter()
            .any(|peer| peer.public_key == public_key);
        if state.settle_admission(public_key, admitted) {
            self.forget_revoked(public_key).await;
        }
    }

    /// What a revocation drops beyond the slot.
    ///
    /// The static PSK baseline would otherwise slide back onto the key if it
    /// were ever admitted again — the reason `peer remove` also drops it from
    /// the table on disk.
    async fn forget_revoked(&self, public_key: &str) {
        self.static_psks.write().await.remove(public_key);
        tracing::warn!(
            peer = %public_key,
            "peer no longer admitted: its PSK slot is revoked and nothing decided earlier \
             may write to it"
        );
    }

    async fn install(
        &self,
        public_key: String,
        address: String,
        psk: Option<SecretString>,
    ) -> Result<(), PublicError> {
        let (reply, response) = oneshot::channel();
        self.psk_tx
            .send(InstallPskRequest {
                public_key,
                address,
                psk,
                reply,
            })
            .await
            .map_err(|_| PublicError::Internal)?;
        response
            .await
            .map_err(|_| PublicError::Internal)?
            .map_err(|_| PublicError::Internal)
    }

    /// Last handshake the data plane reports for this peer, read **now**.
    ///
    /// A backend that cannot be read is an error, never `Ok(None)`: the
    /// commit turns this value into proof, and proof that a read failed is
    /// not proof that a handshake did not happen.
    pub(super) async fn observe_handshake(
        &self,
        public_key: &str,
    ) -> Result<Option<std::time::SystemTime>, PublicError> {
        let (reply, response) = oneshot::channel();
        self.handshake_tx
            .send(aether::ObserveHandshakeRequest {
                public_key: public_key.to_string(),
                reply,
            })
            .await
            .map_err(|_| PublicError::Internal)?;
        response
            .await
            .map_err(|_| PublicError::Internal)?
            .map_err(|_| PublicError::Internal)
    }

    /// Undoes everything a transaction that did not commit left behind.
    ///
    /// # Why it is keyed by transaction identifier
    ///
    /// Because it has to work in the one case where no generation was ever
    /// handed back to a caller: a `prepare` destroyed part-way through, after
    /// it reserved the slot — possibly after it posed the candidate — and
    /// before it recorded anything. The slot names its own owner, so
    /// ownership is checked against that and nothing else. A transaction that
    /// no longer owns the slot undoes nothing, which is the whole point of
    /// the state.
    ///
    /// # Ordering
    ///
    /// The data plane is restored first and the table follows, under one
    /// lock, exactly as in [`Self::clear_slot`] and for the same reason. If
    /// the restore fails the slot stays `preparing` **and** the peer stays
    /// reserved: the gateway could not put back what it displaced, so it
    /// refuses to let anything else pose on top of a data plane it no longer
    /// describes. That peer is fail-closed until an operator acts, which is
    /// the honest outcome — the alternative is a slot nothing points at.
    pub(super) async fn abandon(&self, transaction_id: [u8; 16], public_key: &str) {
        let mut state = self.transactions.lock().await;
        // A revoked peer has nothing to put back: its rollback data died with
        // the revocation, and the data plane no longer holds the peer.
        self.settle_admission(&mut state, public_key).await;
        let (previous, address, previous_psk, install_attempted) =
            match &state.slot(public_key).state {
                SlotState::Preparing {
                    transaction_id: owner,
                    previous,
                    address,
                    previous_psk,
                    install_attempted,
                } if *owner == transaction_id => (
                    (**previous).duplicate(),
                    address.clone(),
                    previous_psk.as_ref().map(SecretString::duplicate),
                    *install_attempted,
                ),
                // Someone else owns the slot, or this transaction already
                // resolved. Either way there is nothing of ours to undo. Drop
                // only this stale record: the peer reservation may already
                // belong to the newer transaction and must not be removed by
                // an actor that cannot prove it owns the slot.
                _ => {
                    state.active.remove(&transaction_id);
                    return;
                }
            };
        if let Err(error) = self
            .install(public_key.to_string(), address, previous_psk)
            .await
        {
            tracing::error!(
                peer = %public_key,
                ?error,
                "key-negotiation rollback failed; peer remains fail-closed until operator action"
            );
            return;
        }
        state.active.remove(&transaction_id);
        state.peers.remove(public_key);
        let slot = state.slot(public_key);
        slot.state = previous;
        slot.generation += 1;
        // Read from the slot, never from the presence of a transaction
        // record. A destroyed rollback may be retried, and the slot is the
        // ownership record that outlives every attempt to undo it.
        if install_attempted {
            slot.resting_until = Some(std::time::Instant::now() + POST_INSTALL_REST);
        }
    }

    /// Installs a prepared candidate only while the reservation still owns it.
    ///
    /// The ownership check, the backend write and the `active` insertion are
    /// one serialized operation. Connection cancellation can roll the
    /// reservation back while material is being derived; without this final
    /// check that cancelled task would resume, install its candidate, and
    /// record a transaction for a slot it no longer owned.
    pub(super) async fn install_candidate(
        &self,
        transaction_id: [u8; 16],
        public_key: &str,
        generation: u64,
        address: String,
        psk: Option<SecretString>,
        transaction: Transaction,
    ) -> Result<(), PublicError> {
        let mut state = self.transactions.lock().await;
        self.settle_admission(&mut state, public_key).await;
        let slot = state.slot(public_key);
        let still_ours = slot.generation == generation
            && matches!(
                &slot.state,
                SlotState::Preparing {
                    transaction_id: owner,
                    ..
                } if *owner == transaction_id
            );
        if !still_ours {
            tracing::warn!(
                transaction = %hex_prefix(&transaction_id),
                peer = %public_key,
                reserved = generation,
                current = slot.generation,
                "key negotiation cancelled before the candidate reached the data plane"
            );
            return Err(PublicError::Rejected);
        }
        let SlotState::Preparing {
            install_attempted, ..
        } = &mut slot.state
        else {
            return Err(PublicError::Internal);
        };
        *install_attempted = true;

        // Keep the state lock across the backend write. `release`, rollback,
        // reclamation and another preparation all use the same lock, so none
        // can observe ownership and then act on a different physical slot.
        self.install(public_key.to_string(), address, psk).await?;
        state.active.insert(transaction_id, transaction);
        Ok(())
    }

    /// Applies a signed release as one linearizable slot transition.
    ///
    /// Classification and action share the lock. If confirmation commits
    /// before it is acquired, this clears that committed PSK; if the release
    /// acquires it first, the slot is not yet `Committed` and this is a no-op.
    /// Splitting observation from the write let both sides believe they had
    /// won.
    ///
    /// # Why `preparing` is untouched
    ///
    /// §11.1 priority 2: a release only withdraws a `committed` state whose
    /// owner it names exactly. A candidate belongs to the connection
    /// preparing it, and that connection already has an exit path for every
    /// way it can end — its rollback guard, which survives even the
    /// destruction of its task. Letting a second message cancel a candidate
    /// gave the same slot two writers with no ordering between them, and the
    /// v5 client sends no release before its commit anyway: the only callers
    /// left would be a stale command or a forged one.
    ///
    /// Returns whether the slot was actually cleared. The caller logs it; it
    /// never reaches the wire, where a cleared slot and a no-op are the same
    /// `204`.
    pub(super) async fn release_owned_slot(
        &self,
        transaction_id: [u8; 16],
        public_key: &str,
    ) -> Result<bool, PublicError> {
        let mut state = self.transactions.lock().await;
        self.settle_admission(&mut state, public_key).await;
        let address = match &state.slot(public_key).state {
            SlotState::Committed(installed) if installed.transaction_id == transaction_id => {
                installed.address.clone()
            }
            _ => return Ok(false),
        };
        self.install(public_key.to_string(), address, None).await?;
        let slot = state.slot(public_key);
        slot.state = SlotState::Empty;
        slot.generation += 1;
        Ok(true)
    }

    /// Clears a peer's slot on the data plane, then in the table.
    ///
    /// # Why the lock is held across the backend write
    ///
    /// Every install already funnels through a single mpsc consumer, so
    /// serialising here costs nothing the channel was not already costing. It
    /// buys the property the state machine needs: between deciding that this
    /// slot may be cleared and both the data plane and the table agreeing on
    /// it, no other actor can slip a newer PSK in and have it silently wiped.
    ///
    /// # Why the table is updated last
    ///
    /// The earlier order — drop the record, then ask the backend — lost the
    /// record whenever the backend write failed. The PSK stayed posed with
    /// nothing left pointing at it: a retried `release` answered "released"
    /// without clearing anything, and reclamation no longer knew the slot
    /// existed. An orphaned secret is exactly what neither end can repair.
    ///
    /// `expected` is the generation the caller observed. A mismatch means
    /// something newer owns the slot, and this is a deliberate no-op.
    pub(super) async fn clear_slot(
        &self,
        public_key: &str,
        expected: u64,
    ) -> Result<(), PublicError> {
        let mut state = self.transactions.lock().await;
        self.settle_admission(&mut state, public_key).await;
        let slot = state.slot(public_key);
        if slot.generation != expected {
            tracing::debug!(
                peer = %public_key,
                observed = expected,
                current = slot.generation,
                "not clearing a slot a newer transaction owns"
            );
            return Ok(());
        }
        let address = match &slot.state {
            SlotState::Committed(installed) => installed.address.clone(),
            // Configuration data, not a transactional secret: §12.2 of the
            // spec puts it outside this lifecycle entirely.
            SlotState::ConfiguredStatic | SlotState::Empty => return Ok(()),
            // A candidate belongs to its transaction, and clearing it here
            // would be exactly the erase the generation exists to prevent: a
            // reclamation or a delayed release matching a slot that has moved
            // on. Undoing a candidate has one entry point — the rollback guard
            // of the connection preparing it, which puts back what the
            // candidate displaced.
            SlotState::Preparing { .. } => return Ok(()),
            // Revocation already took the peer off the data plane.
            SlotState::Revoked => return Ok(()),
        };
        self.install(public_key.to_string(), address, None).await?;
        let slot = state.slot(public_key);
        slot.state = SlotState::Empty;
        slot.generation += 1;
        Ok(())
    }

    /// Revokes every slot whose peer left admission (spec §11.1, priority 1).
    ///
    /// Each slot section already settles its own peer before acting. This
    /// sweep covers the slots nothing touches, so that a removed peer's
    /// rollback data and static PSK outlive its removal by one reclaimer
    /// period at most.
    pub(super) async fn revoke_unadmitted(&self) {
        let mut state = self.transactions.lock().await;
        let admitted: HashSet<String> = self
            .network
            .read()
            .await
            .peers
            .iter()
            .map(|peer| peer.public_key.clone())
            .collect();
        let removed: Vec<String> = state
            .slots
            .keys()
            .filter(|key| !admitted.contains(*key))
            .cloned()
            .collect();
        for public_key in removed {
            if state.settle_admission(&public_key, false) {
                self.forget_revoked(&public_key).await;
            }
        }
    }

    /// PSKs that should be dropped, with the generation and reason.
    ///
    /// Read-only: it decides, the caller acts. Splitting the two keeps the
    /// lock on the transaction table short and out of the data-plane call —
    /// and the generation returned here is what makes acting later safe.
    ///
    /// Only [`SlotState::Committed`] slots are candidates. A
    /// [`SlotState::ConfiguredStatic`] one holds an operator's configured
    /// secret with no transactional owner: neither the handshake threshold
    /// nor the 24-hour deadline applies to it, and clearing it would destroy
    /// configuration that no renegotiation could restore.
    pub(super) async fn reclaimable(
        &self,
        observed: &[helios_wireguard::PeerStatus],
    ) -> Vec<(String, u64, String)> {
        let now = std::time::Instant::now();
        let mut state = self.transactions.lock().await;
        state
            .slots
            .values_mut()
            .filter_map(|slot| {
                let SlotState::Committed(installed) = &mut slot.state else {
                    return None;
                };
                let generation = slot.generation;
                let age = now.saturating_duration_since(installed.installed_at);
                if age >= MAX_PSK_LIFETIME {
                    return Some((
                        installed.public_key.clone(),
                        generation,
                        format!(
                            "PSK reached its {} h lifetime without a renewal",
                            MAX_PSK_LIFETIME.as_secs() / 3600
                        ),
                    ));
                }
                // A peer the data plane has never reported is not stale — it
                // is one the snapshot has not caught up with, typically right
                // after the commit. Only an observed, aged handshake counts.
                let peer = observed
                    .iter()
                    .find(|peer| peer.public_key_b64() == installed.public_key)?;
                if let Some(reason) =
                    installed.charge_transfer(peer.rx_bytes.saturating_add(peer.tx_bytes))
                {
                    return Some((installed.public_key.clone(), generation, reason));
                }
                // Silence is counted from the commit at the earliest. The
                // snapshot is up to ten seconds old and may still carry the
                // handshake of a previous session, while the commit itself
                // proved a fresh one: without this bound a slot committed
                // seconds ago reads as abandoned for an hour.
                let handshake_age = peer
                    .last_handshake
                    .and_then(|at| std::time::SystemTime::now().duration_since(at).ok())?
                    .min(age);
                (handshake_age.as_secs() >= helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS).then(
                    || {
                        (
                            installed.public_key.clone(),
                            generation,
                            format!(
                                "no WireGuard handshake for {} s, past the {} s reclamation \
                                 threshold",
                                handshake_age.as_secs(),
                                helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS
                            ),
                        )
                    },
                )
            })
            .collect()
    }

    pub(super) async fn raise_security_floor(
        &self,
        public_key: &str,
        mode: ProtectionMode,
    ) -> Result<(), PublicError> {
        let mut network = self.network.write().await;
        let Some(previous) = elevate_security_floor(&mut network, public_key, mode)? else {
            return Ok(());
        };

        let persisted = if self.dry_run {
            network.save_for_development()
        } else {
            network.save_redacted()
        };
        if persisted.is_err() {
            if let Some(peer) = network
                .peers
                .iter_mut()
                .find(|peer| peer.public_key == public_key)
            {
                peer.minimum_key_negotiation_mode = Some(previous);
            }
            return Err(PublicError::Internal);
        }
        Ok(())
    }
}
