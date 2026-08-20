//! Gateway integration of the public key-negotiation service.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use aether::{
    key_negotiation::{
        authenticate_commit, authenticate_response, generate_ml_dsa_87_keypair,
        issue_pq_certificate, AuthenticatedKeyNegotiationCommit,
        AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest,
        AuthenticatedPskRelease, PqCertificate, PqCertificateRole, ProtectionMode,
        KEY_NEGOTIATION_VERSION, PQ_CERTIFICATE_VERSION, SERVER_CHALLENGE_LEN,
    },
    InstallPskRequest, NetworkConfig, SecretString,
};
use anyhow::{Context, Result};
use base64::Engine as _;
use helio_tpm::{BootDecision, SealedKeystore};
use helios_api::key_negotiation::PskReleaseRefusal;
use helios_key_negotiation::{
    prepare_key_material, server_endpoint, GatewayIdentity, NegotiationHandler,
    PreparedNegotiation, PublicError, TlsIdentity, DEFAULT_CONFIRMATION_TIMEOUT,
};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use zeroize::Zeroizing;

/// Longest a negotiated PSK may stay posed without being renewed.
///
/// WireGuard rekeys its session keys on its own, but the PSK entering every
/// one of those derivations does not change while it is installed. A tunnel
/// left up for months would protect all of it with a single ML-KEM secret.
///
/// Orion renegotiates well before this — the deadline is the backstop, not
/// the mechanism — so a slot actually reaching it means the renewal failed,
/// which is why the reclamation names it in the journal instead of quietly
/// extending.
const MAX_PSK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

const CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-cert.der";
const CLIENT_CA_PATH: &str = "/var/lib/helios/key-negotiation-client-ca.der";
const PQ_CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-pq-cert.json";
/// The one ML-DSA-87 authority a client leaf is authenticated under, on the
/// public port.
///
/// `pub(crate)` because the certificate lifecycle has to ask the same question
/// before it stages a candidate: see
/// [`crate::certificates::assert_candidate_is_presentable`].
pub(crate) const CLIENT_PQ_CA_PATH: &str =
    "/var/lib/helios/key-negotiation-client-pq-ca-public.bin";
const PRIVATE_KEYSTORE_PATH: &str = "/var/lib/helios/key-negotiation-key.sealed";
const MAX_REPLAY_IDENTIFIERS: usize = 4096;

pub struct InitializedIdentity {
    pub certificate_path: std::path::PathBuf,
    pub certificate_sha256: String,
    pub pq_certificate_path: std::path::PathBuf,
    pub pq_certificate_sha256: String,
}

struct Transaction {
    public_key: String,
    address: String,
    client_pq_public_key: String,
    mode: ProtectionMode,
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    /// Slot generation this transaction **reserved**, not merely observed.
    ///
    /// Anything that acts on the slot later must present it. A rollback whose
    /// generation no longer matches is a no-op, because something newer has
    /// happened to that peer in the meantime.
    generation: u64,
    /// Last handshake the data plane reported **immediately before** the
    /// candidate PSK was posed.
    ///
    /// The commit demands a strictly later value. This is the only thing in
    /// the protocol that proves the peer holds the WireGuard private key: the
    /// QUIC and ML-DSA layers prove possession of the TLS and PQ identities,
    /// which are three separate keys. Without it, an attacker holding a
    /// stolen client identity — but not its WireGuard key — can have the
    /// gateway install a PSK of their choosing and cut the real client off.
    handshake_before_install: Option<std::time::SystemTime>,
}

/// What the gateway currently holds in a peer's WireGuard PSK slot.
///
/// v4 needed nothing like this: the QUIC link was the ownership record, and
/// it vanished with the client. v5 has no link, so the slot's meaning is
/// written down — and the two kinds of PSK a slot can hold are **not**
/// interchangeable, which is the distinction v4 never had to make.
#[derive(Clone)]
enum SlotState {
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
        previous_psk: Option<String>,
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
}

/// A peer's slot, and a counter that orders every change to it.
///
/// The generation is what makes late actors safe. Three of them can arrive
/// after the fact — a rollback for a transaction that already ended, a
/// `release` delayed on the network, a reclamation decided from a snapshot
/// taken seconds ago — and each would otherwise clear a slot a *newer*
/// negotiation had just filled, tearing down a tunnel that was working.
struct PeerSlot {
    generation: u64,
    state: SlotState,
    /// End of the rest period a post-installation rollback arms (spec §4.5).
    ///
    /// Ten seconds during which this peer poses nothing new. A negotiation
    /// identity that has been stolen but is not backed by the peer's
    /// WireGuard key can never commit — the handshake proof stops it — but
    /// without this it can pose and roll back a candidate as fast as the
    /// round-trip allows, keeping a working slot in permanent oscillation.
    resting_until: Option<std::time::Instant>,
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
struct TransactionState {
    active: HashMap<[u8; 16], Transaction>,
    /// Slot state per peer, by WireGuard public key.
    slots: HashMap<String, PeerSlot>,
    peers: HashSet<String>,
    replay_order: VecDeque<[u8; 16]>,
    replay_set: HashSet<[u8; 16]>,
}

impl TransactionState {
    fn slot(&mut self, public_key: &str) -> &mut PeerSlot {
        self.slots.entry(public_key.to_string()).or_default()
    }
}

pub struct GatewayHandler {
    network: Arc<RwLock<NetworkConfig>>,
    psk_tx: mpsc::Sender<InstallPskRequest>,
    /// Fresh reads of the data plane, for the handshake proof at the commit.
    handshake_tx: mpsc::Sender<aether::ObserveHandshakeRequest>,
    gateway_public_key: String,
    client_pq_ca_public_key: Vec<u8>,
    gateway_pq_certificate: PqCertificate,
    /// Fingerprint of the certificate this daemon actually serves.
    ///
    /// Computed once at startup from the loaded certificate, not read from a
    /// file at request time: a rotation the daemon has not restarted for must
    /// make requests fail against what is *served*, which is exactly the
    /// discrepancy the startup log names.
    served_certificate_fingerprint: String,
    gateway_pq_private_key: Zeroizing<Vec<u8>>,
    dry_run: bool,
    static_psks: RwLock<HashMap<String, String>>,
    transactions: Mutex<TransactionState>,
}

fn elevate_security_floor(
    network: &mut NetworkConfig,
    public_key: &str,
    mode: ProtectionMode,
) -> Result<Option<ProtectionMode>, PublicError> {
    let peer = network
        .peers
        .iter_mut()
        .find(|peer| peer.public_key == public_key)
        .ok_or(PublicError::Rejected)?;
    if mode == peer.minimum_key_negotiation_mode
        || !mode.satisfies(peer.minimum_key_negotiation_mode)
    {
        return Ok(None);
    }
    let previous = peer.minimum_key_negotiation_mode;
    peer.minimum_key_negotiation_mode = mode;
    Ok(Some(previous))
}

impl GatewayHandler {
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
    async fn observe_handshake(
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
    async fn abandon(&self, transaction_id: [u8; 16], public_key: &str) {
        let mut state = self.transactions.lock().await;
        let (previous, address, previous_psk, install_attempted) =
            match &state.slot(public_key).state {
                SlotState::Preparing {
                    transaction_id: owner,
                    previous,
                    address,
                    previous_psk,
                    install_attempted,
                } if *owner == transaction_id => (
                    (**previous).clone(),
                    address.clone(),
                    previous_psk.clone(),
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
            .install(
                public_key.to_string(),
                address,
                previous_psk.map(SecretString::new),
            )
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
    async fn install_candidate(
        &self,
        transaction_id: [u8; 16],
        public_key: &str,
        generation: u64,
        address: String,
        psk: Option<SecretString>,
        transaction: Transaction,
    ) -> Result<(), PublicError> {
        let mut state = self.transactions.lock().await;
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
    async fn release_owned_slot(
        &self,
        transaction_id: [u8; 16],
        public_key: &str,
    ) -> Result<bool, PublicError> {
        let mut state = self.transactions.lock().await;
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
    async fn clear_slot(&self, public_key: &str, expected: u64) -> Result<(), PublicError> {
        let mut state = self.transactions.lock().await;
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
        };
        self.install(public_key.to_string(), address, None).await?;
        let slot = state.slot(public_key);
        slot.state = SlotState::Empty;
        slot.generation += 1;
        Ok(())
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
    async fn reclaimable(
        &self,
        observed: &[helios_wireguard::PeerStatus],
    ) -> Vec<(String, u64, String)> {
        let now = std::time::Instant::now();
        let state = self.transactions.lock().await;
        state
            .slots
            .values()
            .filter_map(|slot| {
                let SlotState::Committed(installed) = &slot.state else {
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
                let handshake_age = peer
                    .last_handshake
                    .and_then(|at| std::time::SystemTime::now().duration_since(at).ok())?;
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

    async fn raise_security_floor(
        &self,
        public_key: &str,
        mode: ProtectionMode,
    ) -> Result<(), PublicError> {
        let mut network = self.network.write().await;
        let Some(previous) = elevate_security_floor(&mut network, public_key, mode)? else {
            return Ok(());
        };

        let mut on_disk = network.clone();
        if !self.dry_run {
            on_disk.wg_private_key.clear();
        }
        for peer in &mut on_disk.peers {
            peer.preshared_key = None;
        }
        if on_disk.save().is_err() {
            if let Some(peer) = network
                .peers
                .iter_mut()
                .find(|peer| peer.public_key == public_key)
            {
                peer.minimum_key_negotiation_mode = previous;
            }
            return Err(PublicError::Internal);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NegotiationHandler for GatewayHandler {
    fn announced_identity(&self) -> GatewayIdentity {
        // What is actually served, read from the loaded identity rather than
        // from the configuration file: after a rotation the daemon has not
        // restarted for, those two disagree, and the client must be told the
        // truth so it can name the discrepancy.
        GatewayIdentity {
            wg_public_key: self.gateway_public_key.clone(),
            server_name: self.gateway_pq_certificate.subject.clone(),
        }
    }

    async fn resolve_admitted_peer(&self, certificate_sha256: &str) -> Option<String> {
        self.network
            .read()
            .await
            .peers
            .iter()
            .find(|peer| {
                peer.key_negotiation_certificate_sha256.as_deref() == Some(certificate_sha256)
            })
            .map(|peer| peer.public_key.clone())
    }

    async fn prepare(
        &self,
        certificate_sha256: String,
        authenticated: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError> {
        let request = &authenticated.request;
        // The gateway used to refuse in silence: the client received a code,
        // the operator saw nothing at all, and the two halves of the same
        // failure could not be put side by side. Every refusal below now says
        // which peer, which transaction and — above all — why.
        let transaction = hex_prefix(&request.transaction_id);
        let peer_key = request.client_wg_public_key.clone();
        request.validate().map_err(|_| {
            tracing::warn!(%transaction, peer = %peer_key, "key negotiation refused: malformed request");
            PublicError::Protocol
        })?;
        // Checked before the peer table is even consulted: an authentic
        // request meant for another gateway must not reach a slot here. In a
        // shared infrastructure two gateways trust the same operator CA, so
        // without this the transcript is portable between them.
        request
            .assert_addressed_to(
                &self.gateway_public_key,
                &self.gateway_pq_certificate.subject,
                &self.served_certificate_fingerprint,
            )
            .map_err(|_| {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    named_gateway = %request.gateway_wg_public_key,
                    named_server = %request.server_name,
                    served_gateway = %self.gateway_public_key,
                    served_server = %self.gateway_pq_certificate.subject,
                    "key negotiation refused: this request names another gateway"
                );
                PublicError::Rejected
            })?;
        let (address, previous_psk, pq_fingerprint, minimum_mode) = {
            let network = self.network.read().await;
            // Found by the **TLS fingerprint**, never by the key the request
            // carries (spec §7.3). Searching on the request's field and then
            // comparing the fingerprint refuses the same messages, but it
            // makes a client-chosen value the index into the peer table; a
            // single missing comparison anywhere downstream would then let an
            // admitted identity aim a negotiation at another peer.
            let peer = network
                .peers
                .iter()
                .find(|peer| {
                    peer.key_negotiation_certificate_sha256.as_deref()
                        == Some(certificate_sha256.as_str())
                })
                .ok_or_else(|| {
                    tracing::warn!(
                        %transaction,
                        peer = %peer_key,
                        presented = %certificate_sha256,
                        "key negotiation refused: this client certificate is not admitted"
                    );
                    PublicError::Rejected
                })?;
            if peer.public_key != request.client_wg_public_key {
                tracing::warn!(
                    %transaction,
                    peer = %peer.name,
                    named = %request.client_wg_public_key,
                    admitted = %peer.public_key,
                    "key negotiation refused: the request names a WireGuard key other than the \
                     one this certificate is admitted for"
                );
                return Err(PublicError::Rejected);
            }
            (
                peer.address.clone(),
                peer.preshared_key.clone(),
                peer.key_negotiation_pq_certificate_sha256
                    .clone()
                    .ok_or(PublicError::Rejected)?,
                peer.minimum_key_negotiation_mode,
            )
        };
        if !request.mode.satisfies(minimum_mode) {
            tracing::warn!(
                %transaction,
                peer = %peer_key,
                requested = ?request.mode,
                floor = ?minimum_mode,
                "key negotiation refused: mode below this peer's floor"
            );
            // `Rejected`, not a dedicated code. v4 answered `downgrade` here,
            // which let anyone read a peer's security floor off the public
            // port by trying one mode after another.
            return Err(PublicError::Rejected);
        }
        authenticated
            .verify(
                &self.client_pq_ca_public_key,
                &pq_fingerprint,
                unix_time_now().map_err(|_| PublicError::Protocol)?,
            )
            .map_err(|error| {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    %error,
                    "key negotiation refused: ML-DSA-87 authentication failed \
                     (signature, PQ certificate, or a clock too far off)"
                );
                PublicError::Rejected
            })?;
        let baseline_static_psk = self
            .static_psks
            .read()
            .await
            .get(&request.client_wg_public_key)
            .cloned();
        // Recomputed against this transaction's context, so a match proves
        // possession now rather than agreeing with a stable identifier.
        let current_matches_static_request = request
            .static_psk_commitment
            .as_deref()
            .zip(previous_psk.as_deref())
            .is_some_and(|(presented, current)| {
                aether::key_negotiation::static_psk_commitment(
                    current,
                    &request.transaction_id,
                    &request.client_nonce,
                    &request.server_challenge,
                    &request.client_wg_public_key,
                    &self.gateway_public_key,
                )
                .is_ok_and(|expected| {
                    aether::key_negotiation::commitments_match(&expected, presented)
                })
            });
        let configured_static_psk = if current_matches_static_request {
            previous_psk.as_deref()
        } else {
            baseline_static_psk.as_deref()
        };

        let generation = {
            let mut state = self.transactions.lock().await;
            if state.replay_set.contains(&request.transaction_id) {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: transaction identifier already seen (replay)"
                );
                return Err(PublicError::Rejected);
            }
            if !state.peers.insert(request.client_wg_public_key.clone()) {
                // The case that leaves a client stuck without either end
                // saying so: a previous session died without closing, its
                // transaction still holds the peer, and every new attempt is
                // refused until that one is released.
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    "key negotiation refused: a transaction is already in flight for this peer — \
                     the previous session has not been released yet"
                );
                return Err(PublicError::Rejected);
            }
            if let Some(until) = state.slot(&request.client_wg_public_key).resting_until {
                if std::time::Instant::now() < until {
                    state.peers.remove(&request.client_wg_public_key);
                    tracing::warn!(
                        %transaction,
                        peer = %peer_key,
                        "key negotiation refused: this peer is in the rest period a rolled-back \
                         candidate armed"
                    );
                    return Err(PublicError::Rejected);
                }
            }
            state.replay_set.insert(request.transaction_id);
            state.replay_order.push_back(request.transaction_id);
            while state.replay_order.len() > MAX_REPLAY_IDENTIFIERS {
                if let Some(expired) = state.replay_order.pop_front() {
                    state.replay_set.remove(&expired);
                }
            }
            // Reserved, not merely observed. Incrementing the generation and
            // claiming the slot happen under the **same** lock that reserved
            // the peer, so from here on every other actor — a delayed
            // `release`, the reclaimer, a rollback from an earlier
            // transaction — sees a generation it does not hold and a slot it
            // does not own, and is a no-op instead of a write.
            //
            // Reading the generation without taking it, as this did before,
            // left a window in which those actors still matched: they cleared
            // the data plane under a candidate that then committed.
            let slot = state.slot(&request.client_wg_public_key);
            slot.generation += 1;
            slot.resting_until = None;
            let previous_state = std::mem::replace(&mut slot.state, SlotState::Empty);
            slot.state = SlotState::Preparing {
                transaction_id: request.transaction_id,
                previous: Box::new(previous_state),
                address: address.clone(),
                previous_psk: previous_psk.clone(),
                install_attempted: false,
            };
            slot.generation
        };

        // Read **before** the candidate is posed, because the commit compares
        // against it. Reading it after would let the very handshake the
        // attacker is trying to skip count as the proof.
        let handshake_before_install =
            match self.observe_handshake(&request.client_wg_public_key).await {
                Ok(observed) => observed,
                Err(error) => {
                    tracing::warn!(
                        %transaction,
                        peer = %peer_key,
                        "key negotiation refused: the data plane could not be read before posing \
                         the candidate PSK, so no commit could be proven afterwards"
                    );
                    self.abandon(request.transaction_id, &request.client_wg_public_key)
                        .await;
                    return Err(error);
                }
            };

        let gateway_nonce = match random_nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(PublicError::Protocol);
            }
        };
        let material = match prepare_key_material(
            request,
            &self.gateway_public_key,
            gateway_nonce,
            configured_static_psk,
            DEFAULT_CONFIRMATION_TIMEOUT,
        ) {
            Ok(material) => material,
            Err(error) => {
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    ?error,
                    "key negotiation refused: preparing the key material failed"
                );
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(error);
            }
        };

        let response = match authenticate_response(
            material.response,
            self.gateway_pq_certificate.clone(),
            self.gateway_pq_private_key.as_slice(),
        ) {
            Ok(response) => response,
            Err(_) => {
                self.abandon(request.transaction_id, &request.client_wg_public_key)
                    .await;
                return Err(PublicError::Protocol);
            }
        };

        let transaction_record = Transaction {
            public_key: request.client_wg_public_key.clone(),
            address: address.clone(),
            client_pq_public_key: authenticated.certificate.ml_dsa_87_public_key.clone(),
            mode: request.mode,
            server_challenge: request.server_challenge,
            generation,
            handshake_before_install,
        };
        if let Err(error) = self
            .install_candidate(
                request.transaction_id,
                &request.client_wg_public_key,
                generation,
                address.clone(),
                material.psk,
                transaction_record,
            )
            .await
        {
            // Posed **before** answering, always: a client that received a PSK
            // the data plane refused would handshake with nobody.
            tracing::warn!(
                %transaction,
                peer = %peer_key,
                ?error,
                "key negotiation refused: installing the PSK on the data plane failed"
            );
            self.abandon(request.transaction_id, &request.client_wg_public_key)
                .await;
            return Err(error);
        }
        tracing::info!(
            %transaction,
            peer = %peer_key,
            mode = ?request.mode,
            confirmation_timeout_s = DEFAULT_CONFIRMATION_TIMEOUT.as_secs(),
            "key negotiation prepared: PSK installed, awaiting the client's confirmation"
        );
        if request.mode == ProtectionMode::StaticPsk && current_matches_static_request {
            if let Some(static_psk) = previous_psk.clone() {
                self.static_psks
                    .write()
                    .await
                    .insert(request.client_wg_public_key.clone(), static_psk);
            }
        }

        Ok(PreparedNegotiation {
            response,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
        })
    }

    /// Point of no return.
    ///
    /// The order below is normative (spec §11.2): verify the signature,
    /// **prove a WireGuard handshake**, persist the floor, sign, and only
    /// then record what the slot now holds. Persisting the floor before
    /// signing is deliberate — a floor that rises for a session the client
    /// never saw committed is still correct, because the peer just proved a
    /// WireGuard handshake at that level, whereas a floor lost to a crash
    /// between signing and writing is a security property gone. Of the two
    /// possible mistakes, one is not a mistake.
    ///
    /// Once this returns `Ok`, no caller may roll back. A commit that cannot
    /// be delivered leaves the slot armed and the client renegotiates, which
    /// converges; undoing it would hand a client a valid commit against a
    /// gateway that had restored the previous state.
    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
        let transaction_id = confirmation.confirmation.transaction_id;
        let (client_pq_public_key, public_key, mode, server_challenge, before, generation) = self
            .transactions
            .lock()
            .await
            .active
            .get(&transaction_id)
            .map(|transaction| {
                (
                    transaction.client_pq_public_key.clone(),
                    transaction.public_key.clone(),
                    transaction.mode,
                    transaction.server_challenge,
                    transaction.handshake_before_install,
                    transaction.generation,
                )
            })
            .ok_or(PublicError::Rejected)?;
        if confirmation.confirmation.server_challenge != server_challenge {
            tracing::warn!(
                transaction = %hex_prefix(&transaction_id),
                peer = %public_key,
                "confirmation refused: it carries another transaction's challenge"
            );
            return Err(PublicError::Rejected);
        }
        confirmation
            .verify(&client_pq_public_key)
            .map_err(|_| PublicError::Rejected)?;

        // The gateway's own proof, and the only one that involves the peer's
        // **WireGuard** private key.
        //
        // Everything verified above proves possession of the client's TLS and
        // ML-DSA-87 identities. Those are two keys; the tunnel rests on a
        // third. An attacker who stole a client's negotiation identity but
        // not its WireGuard key could, without this check, present a
        // well-formed confirmation and have the gateway commit a PSK of their
        // choosing into that peer's slot — which cuts the genuine client off,
        // since a slot filled on one side only fails every handshake.
        //
        // The client is told to confirm *after* it observes a handshake, so
        // by the time this runs the data plane has the evidence. Comparing
        // raw observations rather than clocks keeps the check independent of
        // system time: only the backend's own notion of "later" matters.
        let after = self.observe_handshake(&public_key).await?;
        let handshake_proven = match (before, after) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(before), Some(after)) => after > before,
        };
        if !handshake_proven {
            tracing::warn!(
                transaction = %hex_prefix(&transaction_id),
                peer = %public_key,
                "confirmation refused: no WireGuard handshake observed since the candidate PSK \
                 was posed, so the confirming party has not proven it holds the peer's WireGuard \
                 private key"
            );
            return Err(PublicError::Rejected);
        }

        // Compare-and-swap before anything durable happens. The candidate
        // this confirmation speaks for must still be the one the slot holds:
        // if the generation has moved, or the slot is no longer `preparing`
        // for this transaction, then the PSK about to be committed is not the
        // PSK on the data plane, and signing a commit for it would hand the
        // client a receipt for a secret the gateway does not have.
        {
            let mut state = self.transactions.lock().await;
            let slot = state.slot(&public_key);
            let still_ours = slot.generation == generation
                && matches!(
                    &slot.state,
                    SlotState::Preparing { transaction_id: owner, .. } if *owner == transaction_id
                );
            if !still_ours {
                tracing::warn!(
                    transaction = %hex_prefix(&transaction_id),
                    peer = %public_key,
                    reserved = generation,
                    current = slot.generation,
                    "confirmation refused: this peer's slot moved on since the candidate was posed"
                );
                return Err(PublicError::Rejected);
            }
        }

        self.raise_security_floor(&public_key, mode).await?;
        let commit = authenticate_commit(
            server_challenge,
            transaction_id,
            self.gateway_pq_private_key.as_slice(),
        )
        .map_err(|_| PublicError::Internal)?;

        // Past this line the transaction is irreversible: its rollback data
        // is dropped rather than moved to a second map.
        //
        // Dropping the reservation and recording what the slot now holds are
        // one locked step. Two steps left a window between them in which the
        // next request could reserve the freed peer and pose its own
        // candidate, only for this transaction's tail to overwrite the slot
        // record with its own — describing a PSK the data plane no longer
        // carried.
        let transaction = {
            let mut state = self.transactions.lock().await;
            let transaction = state
                .active
                .remove(&transaction_id)
                .ok_or(PublicError::Internal)?;
            state.peers.remove(&transaction.public_key);
            let slot = state.slot(&transaction.public_key);
            if slot.generation != generation {
                return Err(PublicError::Internal);
            }
            // Two committed states, because the two modes leave two different
            // things in the slot. `ml_kem` leaves a fresh secret this
            // transaction owns, expires and may release. `static_psk` leaves
            // the value the operator configured on both peers: the
            // transaction proved possession of it and ends, but the secret
            // was there before and stays after, owned by nobody.
            slot.state = match mode {
                ProtectionMode::StaticPsk => SlotState::ConfiguredStatic,
                _ => SlotState::Committed(InstalledPsk {
                    transaction_id,
                    public_key: transaction.public_key.clone(),
                    address: transaction.address.clone(),
                    installed_at: std::time::Instant::now(),
                }),
            };
            slot.generation += 1;
            transaction
        };
        tracing::info!(
            transaction = %hex_prefix(&transaction_id),
            peer = %transaction.public_key,
            mode = ?mode,
            generation = generation + 1,
            "key negotiation committed: the floor is persisted and the slot is final"
        );
        Ok(commit)
    }

    async fn rollback(&self, transaction_id: [u8; 16], client_wg_public_key: &str) {
        tracing::info!(
            transaction = %hex_prefix(&transaction_id),
            peer = %client_wg_public_key,
            "key negotiation rolled back: the peer's previous PSK slot is restored"
        );
        // Ownership-guarded: if anything has touched this peer's slot since
        // the transaction reserved it, the restore is a no-op rather than a
        // write that would undo a newer negotiation.
        self.abandon(transaction_id, client_wg_public_key).await;
    }
}

/// Explicit teardown, arriving **inside the WireGuard tunnel**.
///
/// The gateway learns the caller's identity from the source VIP, which
/// `helios_api::auth::require_peer` has already resolved against the peer
/// table; this only ever *compares* the keys the body carries. So a release
/// engages the peer's WireGuard key — proved by the packet having crossed the
/// tunnel at all — on top of its ML-DSA-87 identity.
///
/// Idempotent and deliberately uninformative: cleared, already empty, owned by
/// another transaction, still `preparing` and holding a configured static PSK
/// are one and the same answer. Telling them apart would be an oracle on a
/// peer's state.
#[async_trait::async_trait]
impl helios_api::key_negotiation::PskReleaseHandler for GatewayHandler {
    async fn release(
        &self,
        caller_wg_public_key: &str,
        authenticated: AuthenticatedPskRelease,
    ) -> Result<(), PskReleaseRefusal> {
        let release = &authenticated.release;
        if release.protocol_version != KEY_NEGOTIATION_VERSION {
            return Err(PskReleaseRefusal::Protocol);
        }
        // The body's own copy of the client key is checked against the one the
        // transport proved, never used to find a peer. A negotiation identity
        // stolen from one client therefore cannot aim a release at another.
        if release.client_wg_public_key != caller_wg_public_key {
            tracing::warn!(
                peer = %caller_wg_public_key,
                "release refused: the body names another peer than the source VIP"
            );
            return Err(PskReleaseRefusal::Rejected);
        }
        if release.gateway_wg_public_key != self.gateway_public_key {
            tracing::warn!(
                peer = %caller_wg_public_key,
                "release refused: it names another gateway"
            );
            return Err(PskReleaseRefusal::Rejected);
        }
        let pq_fingerprint = {
            let network = self.network.read().await;
            let peer = network
                .peers
                .iter()
                .find(|peer| peer.public_key == caller_wg_public_key)
                .ok_or(PskReleaseRefusal::Rejected)?;
            peer.key_negotiation_pq_certificate_sha256
                .clone()
                .ok_or(PskReleaseRefusal::Rejected)?
        };
        authenticated
            .verify(
                &self.client_pq_ca_public_key,
                &pq_fingerprint,
                unix_time_now().map_err(|_| PskReleaseRefusal::Internal)?,
            )
            .map_err(|error| {
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    %error,
                    "release refused: authentication failed"
                );
                PskReleaseRefusal::Rejected
            })?;

        // Classification and action share one lock inside
        // `release_owned_slot`. If confirmation wins that lock first this
        // clears the PSK it just committed; if the release wins, the slot is
        // not committed yet and nothing is touched.
        match self
            .release_owned_slot(release.installed_transaction_id, caller_wg_public_key)
            .await
        {
            Ok(true) => {
                tracing::info!(
                    peer = %caller_wg_public_key,
                    transaction = %hex_prefix(&release.installed_transaction_id),
                    "signed release accepted: clearing the PSK slot"
                );
                Ok(())
            }
            Ok(false) => {
                tracing::info!(
                    peer = %caller_wg_public_key,
                    "release does not name the committed transaction that owns this peer's \
                     slot; answering without touching anything"
                );
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    ?error,
                    "could not apply the signed release to the PSK slot"
                );
                Err(PskReleaseRefusal::Internal)
            }
        }
    }
}

/// Starts the negotiation service, and hands back what the internal API needs.
///
/// The returned handler is the **same** object the QUIC listener serves, not a
/// copy: the in-tunnel `release` and the negotiation itself must contend for
/// one per-peer serializer, or two writers would race on the same slot.
/// `None` means no `key_negotiation_port`, so no service and nothing to
/// release.
pub async fn start(
    network: Arc<RwLock<NetworkConfig>>,
    psk_tx: mpsc::Sender<InstallPskRequest>,
    handshake_tx: mpsc::Sender<aether::ObserveHandshakeRequest>,
    peer_runtime: Arc<RwLock<Vec<helios_wireguard::PeerStatus>>>,
    boot: &BootDecision,
    dry_run: bool,
) -> Result<Option<Arc<GatewayHandler>>> {
    let (port, gateway_private_key, static_psks) = {
        let network = network.read().await;
        // No port declared, no service. This used to be an error, back when
        // the negotiation was a build flag: a binary carrying the feature and
        // a configuration ignoring it looked like a contradiction worth
        // refusing to start over. Every binary carries it now, so the absence
        // of a port is simply the ordinary state of a gateway that has not
        // opened it — and refusing to start would take down every gateway
        // that upgrades.
        let Some(port) = network.key_negotiation_port else {
            tracing::info!(
                "key_negotiation_port absent: the pre-WireGuard negotiation stays closed"
            );
            return Ok(None);
        };
        let static_psks = network
            .peers
            .iter()
            .filter_map(|peer| {
                peer.preshared_key
                    .clone()
                    .map(|psk| (peer.public_key.clone(), psk))
            })
            .collect();
        (port, network.wg_private_key.clone(), static_psks)
    };
    let gateway_public_key = aether::wg::public_from_private(&gateway_private_key)
        .context("gateway WireGuard identity is unavailable for key negotiation")?;
    let identity = load_identity(boot, dry_run, &gateway_public_key)?;
    let client_ca =
        std::fs::read(CLIENT_CA_PATH).context("reading key-negotiation client CA certificate")?;
    // The identity is read **once**, here, and served for the lifetime of the
    // process — unlike `network.toml`, which is watched and re-read.
    //
    // # Limite connue
    //
    // `heliosd init-key-negotiation --rotate` on a running daemon therefore
    // changes the files without changing what is served: the daemon keeps
    // presenting the previous certificate while every profile issued after the
    // rotation pins the new one. Clients then fail the QUIC handshake with
    // `invalid peer certificate: BadSignature`, which names a signature and
    // not the mismatch behind it. Restarting the daemon is what applies a
    // rotation. Reloading it under a live data plane would mean rebuilding the
    // QUIC endpoint while sessions hold PSK slots on it, and the closure of
    // those sessions is what releases the slots — so the rebuild would drop
    // every tunnel it was meant to spare.
    //
    // Until then this line is the diagnosis: the fingerprint served, next to
    // the age of the file it was read from. A certificate written after the
    // daemon started is the whole answer.
    tracing::info!(
        certificate_sha256 = %helios_key_negotiation::certificate_fingerprint_der(
            &std::fs::read(CERTIFICATE_PATH).unwrap_or_default()
        ),
        certificate_written = ?std::fs::metadata(CERTIFICATE_PATH)
            .and_then(|meta| meta.modified())
            .ok(),
        client_ca_sha256 = %helios_key_negotiation::certificate_fingerprint_der(&client_ca),
        "key-negotiation identity read from disk — served until this daemon restarts; \
         a rotation performed later takes effect only on restart"
    );
    let endpoint = server_endpoint(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        &identity.tls,
        client_ca,
    )
    .context("binding the key-negotiation QUIC listener")?;
    let handler = Arc::new(GatewayHandler {
        network,
        psk_tx,
        handshake_tx,
        gateway_public_key,
        client_pq_ca_public_key: std::fs::read(CLIENT_PQ_CA_PATH)
            .context("reading key-negotiation client PQ CA public key")?,
        served_certificate_fingerprint: identity
            .pq_certificate
            .fingerprint()
            .context("computing the fingerprint of the served PQ certificate")?,
        gateway_pq_certificate: identity.pq_certificate,
        gateway_pq_private_key: identity.pq_private_key,
        dry_run,
        static_psks: RwLock::new(static_psks),
        transactions: Mutex::new(TransactionState::default()),
    });
    tracing::info!("key-negotiation listening on UDP {port}");
    spawn_psk_reclaimer(Arc::clone(&handler), peer_runtime);
    tokio::spawn(helios_key_negotiation::serve(
        endpoint,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));
    Ok(Some(handler))
}

/// How often the reclaimer looks at the data plane.
///
/// Matches the orchestrator's own poll: it reads that poll's snapshot, so a
/// shorter period would only re-examine unchanged data.
const RECLAIM_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Reclaims PSKs whose peer has gone quiet, and PSKs that have aged out.
///
/// This is what replaces v4's closing QUIC link, and it reads the only source
/// that actually knows whether a peer is there: the data plane. A peer whose
/// last handshake is older than
/// [`PSK_RECLAIM_AFTER_STALE_SECS`](helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS)
/// has already been abandoned by WireGuard itself — that threshold sits above
/// the 180 s after which a session is dead — so clearing its slot destroys
/// nothing that still worked.
///
/// Two clocks, two questions. Handshake age answers «is this peer still
/// there»; [`MAX_PSK_LIFETIME`] answers «has this secret protected traffic for
/// long enough», and it fires even on a perfectly healthy tunnel. Orion is
/// expected to renegotiate well before, so reaching the deadline means the
/// renewal did not happen and the journal says so.
///
/// The whole loop depends on gateway-sent keep-alives, which
/// `NetworkConfig::validate` makes mandatory for every negotiated peer: an
/// idle tunnel without them produces no handshake, and a peer that is fine
/// would look long gone.
fn spawn_psk_reclaimer(
    handler: Arc<GatewayHandler>,
    peer_runtime: Arc<RwLock<Vec<helios_wireguard::PeerStatus>>>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RECLAIM_POLL);
        loop {
            ticker.tick().await;
            let observed = peer_runtime.read().await.clone();
            for (public_key, generation, reason) in handler.reclaimable(&observed).await {
                tracing::warn!(
                    peer = %public_key,
                    %reason,
                    "reclaiming a negotiated PSK"
                );
                // The snapshot this decision came from is up to ten seconds
                // old, so a negotiation may have committed in between. The
                // generation is what makes that harmless: a slot that moved
                // on is left alone rather than cleared under a client that
                // has just finished handshaking.
                if handler.clear_slot(&public_key, generation).await.is_err() {
                    tracing::error!("could not clear a reclaimed PSK slot");
                }
            }
        }
    });
}

/// The public identity material a trust-domain bootstrap needs.
///
/// Three files, all public by construction: the TLS leaf this gateway serves,
/// its PQ leaf, and the client TLS anchor it was told to trust. Reading them
/// opens no vault — which is why `init-trust-domain` needs no TPM, and can be
/// run on a gateway whose boot chain has moved.
///
/// The PQ leaf is where the server name and the WireGuard identity come from,
/// rather than from arguments an operator retypes: the registry must describe
/// the identity actually being served, and two fields that must agree are two
/// fields that can disagree.
pub struct ServedIdentity {
    pub tls_certificate: aether::certificates::encoding::DerCertificate,
    pub pq_certificate: PqCertificate,
    pub client_tls_ca: aether::certificates::encoding::DerCertificate,
}

pub fn served_identity() -> Result<Option<ServedIdentity>> {
    use aether::certificates::encoding::DerCertificate;

    let (Ok(tls_der), Ok(pq_json), Ok(client_ca_der)) = (
        std::fs::read(CERTIFICATE_PATH),
        std::fs::read(PQ_CERTIFICATE_PATH),
        std::fs::read(CLIENT_CA_PATH),
    ) else {
        return Ok(None);
    };
    let pq_certificate: PqCertificate = serde_json::from_slice(&pq_json)
        .with_context(|| format!("reading {PQ_CERTIFICATE_PATH}"))?;
    Ok(Some(ServedIdentity {
        tls_certificate: DerCertificate::new(tls_der)
            .with_context(|| format!("reading {CERTIFICATE_PATH}"))?,
        pq_certificate,
        client_tls_ca: DerCertificate::new(client_ca_der)
            .with_context(|| format!("reading {CLIENT_CA_PATH}"))?,
    }))
}

/// Reads the public certificates the API republishes to the operator tooling.
///
/// Deliberately independent from [`start`]: it opens neither the TPM nor the
/// sealed keystore, and only touches files that are public by construction.
/// A gateway whose identity has not been created yet simply has nothing to
/// publish — that is `None`, not an error, because it is the ordinary state
/// before `heliosd init-key-negotiation`.
pub fn public_material() -> Result<Option<helios_api::KeyNegotiationMaterial>> {
    let (Ok(certificate_der), Ok(pq_certificate_json)) = (
        std::fs::read(CERTIFICATE_PATH),
        std::fs::read(PQ_CERTIFICATE_PATH),
    ) else {
        return Ok(None);
    };
    Ok(Some(helios_api::KeyNegotiationMaterial {
        certificate_der,
        pq_certificate_json,
    }))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPrivateIdentity {
    tls_private_key: String,
    pq_private_key: String,
}

struct LoadedIdentity {
    tls: TlsIdentity,
    pq_certificate: PqCertificate,
    pq_private_key: Zeroizing<Vec<u8>>,
}

/// The gateway signs staging receipts with the leaf it already serves.
///
/// Not a second copy of the sealed key: the certificate lifecycle asks the
/// negotiation handler, which unsealed it once at startup and is the only
/// holder for the life of the process.
impl crate::certificates::StageReceiptSigner for GatewayHandler {
    fn sign_stage_receipt(
        &self,
        receipt: aether::certificates::client::GatewayCertificateStageReceipt,
    ) -> Result<
        aether::certificates::client::GatewayCertificateStageReceipt,
        aether::certificates::CertificateError,
    > {
        receipt.sign(&self.gateway_pq_private_key)
    }

    fn served_pq_certificate(&self) -> PqCertificate {
        self.gateway_pq_certificate.clone()
    }
}

/// Object context of the negotiation identity: the gateway WireGuard public
/// key it serves.
///
/// **Limite connue** : ADR-006 §2 demande d'y joindre l'époque du certificat.
/// Aucune époque n'est modelée aujourd'hui — l'ajouter suppose de versionner le
/// certificat de négociation, ce qui relève du lot gateway. La liaison au pair
/// est en place ; la fraîcheur du certificat ne l'est pas encore.
fn negotiation_identity_context(gateway_wg_public_key: &str) -> helio_tpm::Context {
    helio_tpm::Context::new().field("gateway_wg_public_key", gateway_wg_public_key.as_bytes())
}

fn load_identity(
    boot: &BootDecision,
    dry_run: bool,
    gateway_wg_public_key: &str,
) -> Result<LoadedIdentity> {
    let certificate =
        std::fs::read(CERTIFICATE_PATH).context("reading key-negotiation certificate")?;
    let private_identity = match boot.secret() {
        Some(secret) => SealedKeystore::new(
            PRIVATE_KEYSTORE_PATH,
            helio_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
        )
        .load(secret, &negotiation_identity_context(gateway_wg_public_key))
        .context("unsealing key-negotiation private key")?
        .to_vec(),
        None if dry_run => {
            let path = std::env::var("HELIOS_KEY_NEGO_DEV_KEY_DER")
                .context("HELIOS_KEY_NEGO_DEV_KEY_DER is required in dev mode")?;
            check_private_permissions(Path::new(&path))?;
            std::fs::read(path).context("reading development key-negotiation private key")?
        }
        None => anyhow::bail!("TPM secret unavailable: key-negotiation identity stays sealed"),
    };
    let private_identity: StoredPrivateIdentity = serde_json::from_slice(&private_identity)
        .context("decoding the sealed key-negotiation identity")?;
    let tls_private_key = base64::engine::general_purpose::STANDARD
        .decode(private_identity.tls_private_key)
        .context("decoding the sealed TLS private key")?;
    let pq_private_key = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(private_identity.pq_private_key)
            .context("decoding the sealed PQ private key")?,
    );
    let pq_certificate: PqCertificate = serde_json::from_slice(
        &std::fs::read(PQ_CERTIFICATE_PATH).context("reading key-negotiation PQ certificate")?,
    )
    .context("decoding the key-negotiation PQ certificate")?;
    pq_certificate
        .verify_self_signed(
            PqCertificateRole::Gateway,
            None,
            &pq_certificate.wireguard_public_key,
            unix_time_now()?,
        )
        .context("verifying the gateway PQ certificate")?;
    Ok(LoadedIdentity {
        tls: TlsIdentity {
            certificate_chain: vec![certificate],
            private_key: tls_private_key,
        },
        pq_certificate,
        pq_private_key,
    })
}

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "development private key permissions are {mode:o}; expected 0600 or stricter"
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// First bytes of a transaction identifier.
///
/// The client prints the same prefix: it is what lets an operator put the two
/// halves of one negotiation side by side, on two machines whose clocks are
/// never quite aligned.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_nonce() -> Result<[u8; 16]> {
    let mut nonce = [0u8; 16];
    aether::random::fill_public(&mut nonce)
        .map_err(|error| anyhow::anyhow!("the approved DRBG refused: {error}"))?;
    Ok(nonce)
}

fn unix_time_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

/// Creates the gateway TLS key locally, seals it, and installs public trust
/// material. The private key never exists as a plaintext filesystem object.
pub fn initialize(
    server_name: &str,
    gateway_wg_public_key: &str,
    client_ca_path: &Path,
    client_pq_ca_path: &Path,
    boot: &BootDecision,
    rotate: bool,
) -> Result<InitializedIdentity> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let certificate_path = std::path::PathBuf::from(CERTIFICATE_PATH);
    let client_ca_destination = std::path::PathBuf::from(CLIENT_CA_PATH);
    let pq_certificate_path = std::path::PathBuf::from(PQ_CERTIFICATE_PATH);
    let client_pq_ca_destination = std::path::PathBuf::from(CLIENT_PQ_CA_PATH);
    let keystore = SealedKeystore::new(
        PRIVATE_KEYSTORE_PATH,
        helio_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    );
    let already_initialized = keystore.exists()
        || certificate_path.exists()
        || client_ca_destination.exists()
        || pq_certificate_path.exists()
        || client_pq_ca_destination.exists();
    anyhow::ensure!(
        rotate || !already_initialized,
        "a key-negotiation identity already exists; use --rotate to replace it explicitly"
    );
    let secret = boot
        .secret()
        .context("TPM secret unavailable: cannot seal the key-negotiation identity")?;
    let client_ca = std::fs::read(client_ca_path)
        .with_context(|| format!("reading client CA {}", client_ca_path.display()))?;
    let client_pq_ca = std::fs::read(client_pq_ca_path)
        .with_context(|| format!("reading client PQ CA {}", client_pq_ca_path.display()))?;
    anyhow::ensure!(
        client_pq_ca.len() == aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN,
        "client PQ CA public key is {} bytes; an ML-DSA-87 public key is {}",
        client_pq_ca.len(),
        aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN
    );
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(client_ca.clone()))
        .context("client CA is not a valid DER certificate")?;

    let mut params = CertificateParams::new(vec![server_name.trim().to_string()])
        .context("server name is not valid for an X.509 certificate")?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(825);
    let key_pair = KeyPair::generate().context("generating the gateway TLS key")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("creating the gateway TLS certificate")?;
    let tls_private_key = Zeroizing::new(key_pair.serialize_der());
    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the gateway PQ identity")?;
    let now = unix_time_now()?;
    aether::wg::validate_key(gateway_wg_public_key)
        .context("gateway WireGuard identity is unavailable")?;
    let pq_certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: random_nonce()?,
            subject: server_name.trim().to_string(),
            issuer: server_name.trim().to_string(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_wg_public_key.to_string(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(pq_public_key),
            not_before_unix: now.saturating_sub(300),
            not_after_unix: now + 825 * 24 * 60 * 60,
            ml_dsa_87_signature: String::new(),
        },
        pq_private_key.as_slice(),
    )
    .context("creating the gateway PQ certificate")?;
    let private_identity = Zeroizing::new(
        serde_json::to_vec(&StoredPrivateIdentity {
            tls_private_key: base64::engine::general_purpose::STANDARD
                .encode(tls_private_key.as_slice()),
            pq_private_key: base64::engine::general_purpose::STANDARD
                .encode(pq_private_key.as_slice()),
        })
        .context("encoding the private key-negotiation identity")?,
    );
    keystore
        .store(
            secret,
            &negotiation_identity_context(gateway_wg_public_key),
            private_identity.as_slice(),
        )
        .context("sealing the gateway TLS and PQ keys")?;

    write_public_atomic(&certificate_path, certificate.der().as_ref())
        .context("installing the gateway TLS certificate")?;
    write_public_atomic(&client_ca_destination, &client_ca)
        .context("installing the Orion client CA")?;
    write_public_atomic(
        &pq_certificate_path,
        &serde_json::to_vec_pretty(&pq_certificate)
            .context("encoding the gateway PQ certificate")?,
    )
    .context("installing the gateway PQ certificate")?;
    write_public_atomic(&client_pq_ca_destination, &client_pq_ca)
        .context("installing the Orion client PQ CA")?;

    if rotate {
        tracing::warn!(
            "key-negotiation identity rotated; Orion profiles must trust the new certificate"
        );
    }
    Ok(InitializedIdentity {
        certificate_sha256: helios_key_negotiation::certificate_fingerprint_der(
            certificate.der().as_ref(),
        ),
        certificate_path,
        pq_certificate_sha256: pq_certificate.fingerprint()?,
        pq_certificate_path,
    })
}

fn write_public_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replacing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Horloge des tests : les requêtes doivent être fraîches pour passer la
    /// fenêtre anti-rejeu.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    use aether::key_negotiation::{
        authenticate_confirmation, authenticate_request, generate_ml_dsa_87_keypair,
        issue_pq_certificate, AuthenticatedKeyNegotiationRequest, KeyNegotiationRequest,
        PqCertificate, PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_VERSION,
        PQ_CERTIFICATE_VERSION,
    };
    const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const CERTIFICATE_FINGERPRINT: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct PqFixture {
        client_ca_public_key: Vec<u8>,
        client_certificate: PqCertificate,
        client_private_key: Vec<u8>,
        gateway_certificate: PqCertificate,
        gateway_private_key: Vec<u8>,
    }

    fn certificate(
        subject: &str,
        role: PqCertificateRole,
        wireguard_key: &str,
        public_key: &[u8],
        issuer_private_key: &[u8],
    ) -> PqCertificate {
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [8; 16],
                subject: subject.into(),
                issuer: "test-ca".into(),
                role,
                wireguard_public_key: wireguard_key.into(),
                ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            issuer_private_key,
        )
        .unwrap()
    }

    fn pq_fixture() -> PqFixture {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
        let client_certificate = certificate(
            "orion",
            PqCertificateRole::Client,
            CLIENT_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
        let gateway_certificate = certificate(
            "gateway",
            PqCertificateRole::Gateway,
            GATEWAY_KEY,
            &gateway_public,
            gateway_private.as_slice(),
        );
        PqFixture {
            client_ca_public_key: ca_public,
            client_certificate,
            client_private_key: client_private.to_vec(),
            gateway_certificate,
            gateway_private_key: gateway_private.to_vec(),
        }
    }

    const TEST_CHALLENGE: [u8; SERVER_CHALLENGE_LEN] = [5; SERVER_CHALLENGE_LEN];

    fn request(
        transaction_id: [u8; 16],
        fixture: &PqFixture,
    ) -> AuthenticatedKeyNegotiationRequest {
        // `ml_kem`: the mode that leaves an owned slot, which is what most of
        // these tests are about. `classic` used to serve here and no longer
        // decodes at all.
        request_in_mode(transaction_id, fixture, ProtectionMode::MlKem, None)
    }

    /// Sends a signed `release` the way Orion does: through the internal API.
    ///
    /// The caller key is passed separately, exactly as `require_peer` supplies
    /// it after resolving the source VIP — the body's copy is only ever
    /// compared against it.
    async fn release_in_tunnel(
        handler: &GatewayHandler,
        fixture: &PqFixture,
        installed_transaction_id: [u8; 16],
    ) -> Result<(), PskReleaseRefusal> {
        use helios_api::key_negotiation::PskReleaseHandler as _;

        let release = aether::key_negotiation::authenticate_release(
            aether::key_negotiation::PskRelease {
                protocol_version: KEY_NEGOTIATION_VERSION,
                installed_transaction_id,
                client_wg_public_key: CLIENT_KEY.into(),
                gateway_wg_public_key: GATEWAY_KEY.into(),
            },
            fixture.client_certificate.clone(),
            &fixture.client_private_key,
        )
        .unwrap();
        handler.release(CLIENT_KEY, release).await
    }

    /// The same request in a chosen mode, with the static commitment when one
    /// is needed.
    fn request_in_mode(
        transaction_id: [u8; 16],
        fixture: &PqFixture,
        mode: ProtectionMode,
        static_psk: Option<&str>,
    ) -> AuthenticatedKeyNegotiationRequest {
        let client_nonce = [2; 16];
        let static_psk_commitment = static_psk.map(|psk| {
            aether::key_negotiation::static_psk_commitment(
                psk,
                &transaction_id,
                &client_nonce,
                &TEST_CHALLENGE,
                CLIENT_KEY,
                GATEWAY_KEY,
            )
            .unwrap()
        });
        let kem_public_key = (mode == ProtectionMode::MlKem).then(|| {
            use aether::Kem as _;
            aether::MlKem1024Kem::generate().unwrap().1
        });
        let request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            server_challenge: TEST_CHALLENGE,
            transaction_id,
            mode,
            client_wg_public_key: CLIENT_KEY.to_string(),
            // Named, and checked against what the handler actually serves.
            gateway_wg_public_key: GATEWAY_KEY.to_string(),
            server_name: fixture.gateway_certificate.subject.clone(),
            gateway_certificate_fingerprint: fixture.gateway_certificate.fingerprint().unwrap(),
            client_nonce,
            timestamp_unix: test_now(),
            kem_public_key,
            static_psk_commitment,
        };
        authenticate_request(
            request,
            fixture.client_certificate.clone(),
            &fixture.client_private_key,
        )
        .unwrap()
    }

    /// A data plane the test drives, answering both gateway channels.
    ///
    /// The handshake it reports is the pivot of every commit: since v5 the
    /// gateway refuses to sign unless it observes one strictly newer than the
    /// value read before the candidate PSK was posed. A test that wants a
    /// commit must therefore say so — which is the point, because the absence
    /// of that call is exactly the attack the check exists to stop.
    struct TestDataPlane {
        /// Every PSK write the data plane received, in order.
        applied: Arc<Mutex<Vec<Option<String>>>>,
        /// When set, every write is acknowledged as a failure.
        failing: Arc<Mutex<bool>>,
        handshake: Arc<Mutex<Option<std::time::SystemTime>>>,
        /// Fed from a counter rather than the wall clock: two calls to
        /// `SystemTime::now()` can return the same instant on a coarse clock,
        /// and "strictly newer" would then be false for a handshake that did
        /// happen.
        tick: Arc<Mutex<u64>>,
    }

    impl TestDataPlane {
        fn spawn() -> (
            Self,
            mpsc::Sender<InstallPskRequest>,
            mpsc::Sender<aether::ObserveHandshakeRequest>,
        ) {
            let applied = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
            let failing = Arc::new(Mutex::new(false));
            let handshake = Arc::new(Mutex::new(None));
            let (psk_tx, mut psk_rx) = mpsc::channel::<InstallPskRequest>(8);
            let writes = Arc::clone(&applied);
            let refuse = Arc::clone(&failing);
            tokio::spawn(async move {
                while let Some(request) = psk_rx.recv().await {
                    writes
                        .lock()
                        .await
                        .push(request.psk.map(|secret| secret.expose().to_string()));
                    let answer = if *refuse.lock().await {
                        Err("data plane refused".to_string())
                    } else {
                        Ok(())
                    };
                    let _ = request.reply.send(answer);
                }
            });
            let (handshake_tx, mut handshake_rx) =
                mpsc::channel::<aether::ObserveHandshakeRequest>(8);
            let reported = Arc::clone(&handshake);
            tokio::spawn(async move {
                while let Some(request) = handshake_rx.recv().await {
                    let answer = *reported.lock().await;
                    let _ = request.reply.send(Ok(answer));
                }
            });
            (
                Self {
                    applied,
                    failing,
                    handshake,
                    tick: Arc::new(Mutex::new(0)),
                },
                psk_tx,
                handshake_tx,
            )
        }

        async fn start_failing(&self) {
            *self.failing.lock().await = true;
        }

        /// Reports a handshake strictly newer than any reported before.
        async fn handshake_happens(&self) {
            let mut tick = self.tick.lock().await;
            *tick += 1;
            *self.handshake.lock().await =
                Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(*tick));
        }

        async fn writes(&self) -> Vec<Option<String>> {
            self.applied.lock().await.clone()
        }
    }

    fn network(previous_psk: &str, pq_fingerprint: &str) -> NetworkConfig {
        let mut network = NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "orion".into(),
            public_key: CLIENT_KEY.into(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: Some(previous_psk.into()),
            key_negotiation_certificate_sha256: Some(CERTIFICATE_FINGERPRINT.into()),
            key_negotiation_pq_certificate_sha256: Some(pq_fingerprint.into()),
            minimum_key_negotiation_mode: ProtectionMode::Classic,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });
        network
    }

    #[tokio::test]
    async fn unconfirmed_transaction_restores_the_previous_slot() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([1; 16], &fixture))
            .await
            .unwrap();
        handler.rollback([1; 16], CLIENT_KEY).await;

        let writes = plane.writes().await;
        assert_eq!(writes.len(), 2, "one candidate posed, one restore");
        assert!(
            writes[0].as_deref().is_some_and(|psk| psk != previous_psk),
            "preparation posts the freshly derived candidate"
        );
        assert_eq!(
            writes[1],
            Some(previous_psk),
            "rollback must put the peer's previous PSK back"
        );
    }

    #[tokio::test]
    async fn undelivered_commit_restores_the_previous_slot() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([2; 16], &fixture))
            .await
            .unwrap();
        // The client handshakes with the candidate PSK before confirming; the
        // gateway will refuse to sign without seeing it.
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [2; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .unwrap();
        // A rollback attempted after the commit must find nothing. This test
        // asserted the exact opposite in v4, where a commit that failed to
        // reach the client restored the previous slot — leaving that client
        // holding a valid, verifiable commit against a gateway that had undone
        // everything. Choosing one semantics is the whole point of v5's point
        // of no return.
        handler.rollback([2; 16], CLIENT_KEY).await;

        assert_eq!(
            plane.writes().await.len(),
            1,
            "nothing may touch the slot after the commit is signed"
        );
        let mut state = handler.transactions.lock().await;
        assert!(state.active.is_empty());
        let slot = state.slot(CLIENT_KEY);
        assert_eq!(
            slot.generation, 2,
            "two transitions are recorded: reserving the slot for the candidate, then committing \
             it. The reservation counts — it is what makes every actor holding the previous \
             generation a no-op from the moment the candidate is posed."
        );
        let SlotState::Committed(installed) = &slot.state else {
            panic!("a committed ml_kem negotiation must leave an owned slot");
        };
        assert_eq!(
            installed.transaction_id, [2; 16],
            "the receipt names the transaction a release will have to quote"
        );
    }

    #[tokio::test]
    async fn certificate_mismatch_never_reaches_the_data_plane() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        assert!(matches!(
            handler
                .prepare("b".repeat(64), request([3; 16], &fixture))
                .await,
            // Coarse on purpose: an unknown peer and a mismatched certificate
            // must be indistinguishable from the public boundary.
            Err(PublicError::Rejected)
        ));
        assert!(plane.writes().await.is_empty());
    }

    #[tokio::test]
    async fn a_mode_below_the_peer_floor_is_refused() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        // `static_psk` under an `ml_kem` floor. This test used to present a
        // `classic` request; that mode is now refused at the decoder, one
        // layer earlier, which would have made the floor itself untested.
        assert!(matches!(
            handler
                .prepare(
                    CERTIFICATE_FINGERPRINT.into(),
                    request_in_mode(
                        [4; 16],
                        &fixture,
                        ProtectionMode::StaticPsk,
                        Some(&previous_psk),
                    ),
                )
                .await,
            // v4 answered `downgrade` here, which let anyone read a peer's
            // security floor off the public port.
            Err(PublicError::Rejected)
        ));
        assert!(plane.writes().await.is_empty());
    }

    #[test]
    fn committed_modes_only_raise_the_persistent_floor() {
        let mut configured = network("static", &"a".repeat(64));
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::StaticPsk).unwrap(),
            Some(ProtectionMode::Classic)
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::Classic).unwrap(),
            None
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::MlKem).unwrap(),
            Some(ProtectionMode::StaticPsk)
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::MlKem
        );
    }

    /// Builds a handler over a fresh fake data plane, with one admitted peer.
    fn gateway_with(
        fixture: &PqFixture,
        previous_psk: &str,
        floor: ProtectionMode,
    ) -> (GatewayHandler, TestDataPlane) {
        let mut configured = network(
            previous_psk,
            &fixture.client_certificate.fingerprint().unwrap(),
        );
        configured.peers[0].minimum_key_negotiation_mode = floor;
        let (plane, psk_tx, handshake_tx) = TestDataPlane::spawn();
        let handler = GatewayHandler {
            network: Arc::new(RwLock::new(configured)),
            psk_tx,
            handshake_tx,
            gateway_public_key: GATEWAY_KEY.into(),
            client_pq_ca_public_key: fixture.client_ca_public_key.clone(),
            gateway_pq_certificate: fixture.gateway_certificate.clone(),
            served_certificate_fingerprint: fixture.gateway_certificate.fingerprint().unwrap(),
            gateway_pq_private_key: Zeroizing::new(fixture.gateway_private_key.clone()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::from([(
                CLIENT_KEY.into(),
                previous_psk.to_string(),
            )])),
            transactions: Mutex::new(TransactionState::default()),
        };
        (handler, plane)
    }

    #[tokio::test]
    async fn a_confirmation_without_a_fresh_handshake_is_refused() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, _plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([9; 16], &fixture))
            .await
            .unwrap();
        // Everything a stolen TLS + ML-DSA identity can produce, and nothing
        // more: the confirmation verifies, but the peer's WireGuard key was
        // never used, so the data plane reports no handshake.
        let refusal = handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [9; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await;

        assert!(
            matches!(refusal, Err(PublicError::Rejected)),
            "a confirmation the data plane cannot corroborate must not be signed"
        );
    }

    #[tokio::test]
    async fn a_committed_static_psk_is_configuration_not_an_owned_slot() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        // Floor already at `static_psk`, so the commit raises nothing: this
        // test is about what the slot holds, not about persisting a floor.
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::StaticPsk);

        handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                request_in_mode(
                    [10; 16],
                    &fixture,
                    ProtectionMode::StaticPsk,
                    Some(&previous_psk),
                ),
            )
            .await
            .unwrap();
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [10; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .unwrap();

        {
            let mut state = handler.transactions.lock().await;
            assert!(
                matches!(state.slot(CLIENT_KEY).state, SlotState::ConfiguredStatic),
                "a static PSK belongs to the configuration, not to the transaction"
            );
        }

        // A peer that has been silent for far longer than the reclamation
        // threshold. An ml_kem slot would be cleared; this one must not be,
        // because nothing would ever put the operator's value back.
        let ancient = helios_wireguard::PeerStatus {
            public_key: base64::engine::general_purpose::STANDARD
                .decode(CLIENT_KEY)
                .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(
                std::time::SystemTime::now()
                    - std::time::Duration::from_secs(
                        helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS * 10,
                    ),
            ),
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        assert!(
            handler.reclaimable(&[ancient]).await.is_empty(),
            "reclamation must never destroy a configured static PSK"
        );
    }

    #[tokio::test]
    async fn a_stale_actor_cannot_clear_a_slot_that_moved_on() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([11; 16], &fixture))
            .await
            .unwrap();
        let stale = handler
            .transactions
            .lock()
            .await
            .slot(CLIENT_KEY)
            .generation;
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [11; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .unwrap();

        let before = plane.writes().await.len();
        // A release or a reclamation decided from the pre-commit view. It must
        // not reach the data plane: the slot it saw no longer exists.
        handler.clear_slot(CLIENT_KEY, stale).await.unwrap();

        assert_eq!(
            plane.writes().await.len(),
            before,
            "an actor holding an old generation must not touch the data plane"
        );
        let mut state = handler.transactions.lock().await;
        assert!(matches!(
            state.slot(CLIENT_KEY).state,
            SlotState::Committed(_)
        ));
    }

    #[tokio::test]
    async fn a_failed_clear_leaves_the_slot_owned_rather_than_orphaned() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                request_in_mode([12; 16], &fixture, ProtectionMode::MlKem, None),
            )
            .await
            .unwrap();
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [12; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .unwrap();

        let generation = handler
            .transactions
            .lock()
            .await
            .slot(CLIENT_KEY)
            .generation;
        plane.start_failing().await;
        assert!(
            handler.clear_slot(CLIENT_KEY, generation).await.is_err(),
            "a data plane that refuses the write must be reported, not ignored"
        );

        // The record survives the failure. Dropping it first — the earlier
        // order — left the PSK posed with nothing pointing at it: a retried
        // release answered "released" without clearing anything, and
        // reclamation no longer knew the slot existed.
        let mut state = handler.transactions.lock().await;
        let slot = state.slot(CLIENT_KEY);
        assert_eq!(
            slot.generation, generation,
            "a failed write is not a transition"
        );
        assert!(
            matches!(slot.state, SlotState::Committed(_)),
            "the slot must stay owned so the next attempt can still clear it"
        );
    }

    /// The interleaving the generation was introduced for, but which reading
    /// it without taking it never stopped.
    ///
    /// A peer whose handshake has aged past the reclamation threshold
    /// renegotiates. The reclaimer's ten-second snapshot still shows the old,
    /// stale handshake, and the slot record still described the *displaced*
    /// PSK — so the reclamation matched the current generation, cleared the
    /// data plane, and wiped a candidate that was about to commit. Naming the
    /// slot `preparing` from the moment it is reserved is what removes the
    /// match.
    #[tokio::test]
    async fn a_candidate_being_prepared_is_not_reclaimable() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([20; 16], &fixture))
            .await
            .unwrap();

        let ancient = helios_wireguard::PeerStatus {
            public_key: base64::engine::general_purpose::STANDARD
                .decode(CLIENT_KEY)
                .unwrap(),
            endpoint: None,
            last_handshake: Some(
                std::time::SystemTime::now()
                    - std::time::Duration::from_secs(
                        helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS * 10,
                    ),
            ),
            allowed_ips: Vec::new(),
            rx_bytes: 0,
            tx_bytes: 0,
        };
        assert!(
            handler.reclaimable(&[ancient]).await.is_empty(),
            "a slot a transaction is preparing has an owner and a deadline of its own; the \
             reclaimer must leave it to them"
        );

        // And the candidate is still the only thing the data plane was told.
        assert_eq!(plane.writes().await.len(), 1);
    }

    /// The other stale actor: a `release` naming the PSK the candidate
    /// displaced.
    ///
    /// It authenticates, it names a transaction the gateway really did commit,
    /// and it arrives while the next negotiation is in flight. Honouring it
    /// clears the data plane under a candidate whose handshake proof may
    /// already be in — leaving the gateway free to sign a commit for a PSK it
    /// no longer holds.
    #[tokio::test]
    async fn a_release_naming_the_displaced_psk_cannot_wipe_the_candidate() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        // First negotiation, committed: it owns the slot.
        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([21; 16], &fixture))
            .await
            .unwrap();
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [21; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .unwrap();

        // Second negotiation, in flight: its candidate is on the data plane.
        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([22; 16], &fixture))
            .await
            .unwrap();
        let candidate = plane.writes().await.last().cloned().flatten();
        let generation = handler
            .transactions
            .lock()
            .await
            .slot(CLIENT_KEY)
            .generation;

        // The delayed release for the first transaction lands now.
        handler.clear_slot(CLIENT_KEY, generation).await.unwrap();

        assert_eq!(
            plane.writes().await.last().cloned().flatten(),
            candidate,
            "the candidate must still be the last thing the data plane was told"
        );
        let mut state = handler.transactions.lock().await;
        assert!(
            matches!(
                state.slot(CLIENT_KEY).state,
                SlotState::Preparing { transaction_id, .. } if transaction_id == [22; 16]
            ),
            "the slot belongs to the transaction preparing it, not to the one it displaced"
        );
    }

    /// A `prepare` destroyed after it posed its candidate and before it
    /// recorded anything.
    ///
    /// This is what the absolute connection deadline used to do — it dropped
    /// the future, and dropping a future runs nothing. The undo therefore
    /// cannot depend on the transaction record: it is driven off the slot,
    /// which names its own owner.
    #[tokio::test]
    async fn a_transaction_that_was_never_recorded_is_still_undone() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([23; 16], &fixture))
            .await
            .unwrap();
        // Exactly what a cancellation between `install` and the insert leaves
        // behind: a posed candidate and no record of it.
        handler.transactions.lock().await.active.remove(&[23; 16]);

        handler.rollback([23; 16], CLIENT_KEY).await;

        assert_eq!(
            plane.writes().await.last().cloned().flatten(),
            Some(previous_psk),
            "the displaced PSK must come back even with no transaction to read it from"
        );
        let mut state = handler.transactions.lock().await;
        assert!(
            !state.peers.contains(CLIENT_KEY),
            "the reservation must go too, or that peer never negotiates again"
        );
        let slot = state.slot(CLIENT_KEY);
        assert!(matches!(
            slot.state,
            SlotState::ConfiguredStatic | SlotState::Empty
        ));
        // The rest period is owed by the *slot*, not by the transaction
        // record. A destroyed preparation may not have inserted that record
        // yet, so the slot is the only reliable witness that a backend write
        // was attempted and that §11.3 therefore requires a rest.
        assert!(
            slot.resting_until.is_some(),
            "a candidate that reached the data plane rests the peer, whatever is left of its \
             transaction record"
        );
    }

    /// §11.1, priority 2: a `release` arriving during `preparing` is a no-op.
    ///
    /// Only a `committed` state whose owner the release names exactly is
    /// withdrawn. A candidate belongs to the connection preparing it, and that
    /// connection already has an exit path for every way it can end — its
    /// rollback guard, which survives even the destruction of its task.
    /// Letting a second message cancel a candidate gave one slot two writers
    /// with no ordering between them; the client sends no release before its
    /// own commit, so the only callers left would be stale or forged.
    #[tokio::test]
    async fn a_release_arriving_during_preparation_touches_nothing() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([26; 16], &fixture))
            .await
            .unwrap();
        let candidate = plane.writes().await.last().cloned().flatten();

        release_in_tunnel(&handler, &fixture, [26; 16])
            .await
            .unwrap();

        assert_eq!(
            plane.writes().await.last().cloned().flatten(),
            candidate,
            "the candidate must still be the last thing the data plane was told"
        );

        // And the connection that posed it can still confirm: nothing took
        // its slot away.
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(TEST_CHALLENGE, [26; 16], &fixture.client_private_key)
                    .unwrap(),
            )
            .await
            .expect("a no-op release must not cost the transaction its commit");
    }

    /// A connection may be cancelled while `prepare` is still deriving
    /// material, before the candidate reaches the backend.
    ///
    /// Cancelling the slot is not enough by itself: the suspended preparation
    /// must re-check ownership immediately before its write, otherwise it
    /// resumes after rollback and installs a candidate for a transaction that
    /// no longer exists.
    #[tokio::test]
    async fn a_rolled_back_preparation_cannot_install_its_candidate_late() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let candidate = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
        let transaction_id = [27; 16];
        let generation = {
            let mut state = handler.transactions.lock().await;
            state.peers.insert(CLIENT_KEY.into());
            let slot = state.slot(CLIENT_KEY);
            slot.generation += 1;
            slot.state = SlotState::Preparing {
                transaction_id,
                previous: Box::new(SlotState::Empty),
                address: "100.64.1.2/32".into(),
                previous_psk: Some(previous_psk.clone()),
                install_attempted: false,
            };
            slot.generation
        };

        // The rollback wins while the original preparation is suspended.
        handler.abandon(transaction_id, CLIENT_KEY).await;
        let writes_after_rollback = plane.writes().await.len();

        let result = handler
            .install_candidate(
                transaction_id,
                CLIENT_KEY,
                generation,
                "100.64.1.2/32".into(),
                Some(SecretString::new(candidate)),
                Transaction {
                    public_key: CLIENT_KEY.into(),
                    address: "100.64.1.2/32".into(),
                    client_pq_public_key: fixture.client_certificate.ml_dsa_87_public_key.clone(),
                    mode: ProtectionMode::MlKem,
                    server_challenge: TEST_CHALLENGE,
                    generation,
                    handshake_before_install: None,
                },
            )
            .await;

        assert!(matches!(result, Err(PublicError::Rejected)));
        assert_eq!(
            plane.writes().await.len(),
            writes_after_rollback,
            "a preparation that lost its slot must never reach the backend"
        );
        assert!(
            !handler
                .transactions
                .lock()
                .await
                .active
                .contains_key(&transaction_id),
            "a cancelled preparation must not recreate its transaction record"
        );
    }

    /// If confirmation wins before the release is serialized, the release
    /// must act on the now-committed owner rather than on an obsolete snapshot
    /// that still called it a candidate.
    #[tokio::test]
    async fn a_release_after_commit_clears_the_same_transaction() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
        let transaction_id = [28; 16];

        handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                request(transaction_id, &fixture),
            )
            .await
            .unwrap();
        plane.handshake_happens().await;
        handler
            .confirm(
                authenticate_confirmation(
                    TEST_CHALLENGE,
                    transaction_id,
                    &fixture.client_private_key,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        release_in_tunnel(&handler, &fixture, transaction_id)
            .await
            .unwrap();

        assert_eq!(
            plane.writes().await.last().cloned().flatten(),
            None,
            "a release serialized after commit must clear that committed PSK"
        );
        let mut state = handler.transactions.lock().await;
        assert!(matches!(state.slot(CLIENT_KEY).state, SlotState::Empty));
    }

    /// §4.5: a rollback that had already posed a candidate rests the peer.
    ///
    /// A stolen negotiation identity without the peer's WireGuard key can
    /// never commit, but nothing stopped it posing and rolling back a
    /// candidate as fast as the round-trip allowed — which keeps a working
    /// slot in permanent oscillation.
    #[tokio::test]
    async fn a_rolled_back_candidate_rests_the_peer() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let (handler, _plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([24; 16], &fixture))
            .await
            .unwrap();
        handler.rollback([24; 16], CLIENT_KEY).await;

        let refusal = handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([25; 16], &fixture))
            .await;
        assert!(
            matches!(refusal, Err(PublicError::Rejected)),
            "the next attempt waits out the rest period"
        );
        assert!(
            !handler.transactions.lock().await.peers.contains(CLIENT_KEY),
            "a refusal during the rest period must not leave the peer reserved"
        );
    }

    /// TLS material for the interoperability test.
    ///
    /// One CA signs both leaves, exactly as the operator's does: the gateway
    /// authenticates the client against it, and Orion pins the server
    /// certificate as its trust anchor.
    struct TestTls {
        ca_der: Vec<u8>,
        server: helios_key_negotiation::TlsIdentity,
        client_certificate: Vec<u8>,
        client_key: Vec<u8>,
    }

    fn test_tls() -> TestTls {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_certificate = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_certificate = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

        TestTls {
            ca_der: ca.der().to_vec(),
            server: helios_key_negotiation::TlsIdentity {
                certificate_chain: vec![server_certificate.der().to_vec(), ca.der().to_vec()],
                private_key: server_key.serialize_der(),
            },
            client_certificate: client_certificate.der().to_vec(),
            client_key: client_key.serialize_der(),
        }
    }

    /// Provides the client identity from memory, as the Windows store would.
    struct TestIdentities(orion_core::key_negotiation::ClientIdentity);

    #[async_trait::async_trait]
    impl orion_core::key_negotiation::IdentityProvider for TestIdentities {
        async fn load(
            &self,
            _identity: &str,
        ) -> anyhow::Result<orion_core::key_negotiation::ClientIdentity> {
            Ok(orion_core::key_negotiation::ClientIdentity {
                certificate_chain: self.0.certificate_chain.clone(),
                private_key: self.0.private_key.clone(),
                pq_certificate: self.0.pq_certificate.clone(),
                pq_private_key: self.0.pq_private_key.clone(),
            })
        }
    }

    /// **The interoperability test**: the real gateway handler against the
    /// real Orion client, over a real QUIC socket.
    ///
    /// Unit tests on either side cannot show what matters here. The gateway
    /// derives the PSK from the shared secret it encapsulated; Orion derives
    /// it from the secret it decapsulated. Both call `derive_negotiated_psk`
    /// with what they believe the transcript to be — and if those two beliefs
    /// diverge by one field, both sides still succeed, install *different*
    /// PSKs, and every WireGuard handshake fails afterwards with no error
    /// pointing at the cause. Comparing the two values is the only way to
    /// know they agree.
    #[tokio::test]
    async fn the_gateway_and_orion_derive_the_same_psk() {
        use aether::key_negotiation::PqCertificateRole;

        let gateway_wg = aether::wg::generate_keypair().unwrap();
        let client_wg = aether::wg::generate_keypair().unwrap();

        // PQ identities bound to those WireGuard keys, as the operator CA
        // issues them.
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let (client_pq_private, client_pq_public) = generate_ml_dsa_87_keypair().unwrap();
        let client_pq_certificate = certificate(
            "orion",
            PqCertificateRole::Client,
            &client_wg.public_key,
            &client_pq_public,
            ca_private.as_slice(),
        );
        let (gateway_pq_private, gateway_pq_public) = generate_ml_dsa_87_keypair().unwrap();
        let gateway_pq_certificate = certificate(
            "localhost",
            PqCertificateRole::Gateway,
            &gateway_wg.public_key,
            &gateway_pq_public,
            gateway_pq_private.as_slice(),
        );

        let tls = test_tls();
        let mut network = NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "orion".into(),
            public_key: client_wg.public_key.clone(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: Some(
                helios_key_negotiation::certificate_fingerprint_der(&tls.client_certificate),
            ),
            key_negotiation_pq_certificate_sha256: Some(
                client_pq_certificate.fingerprint().unwrap(),
            ),
            minimum_key_negotiation_mode: ProtectionMode::MlKem,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });

        // Captures what the gateway actually installs on its data plane, and
        // lets the test say when the peer handshakes.
        let (plane, psk_tx, handshake_tx) = TestDataPlane::spawn();

        let handler = Arc::new(GatewayHandler {
            network: Arc::new(RwLock::new(network)),
            psk_tx,
            handshake_tx,
            gateway_public_key: gateway_wg.public_key.clone(),
            client_pq_ca_public_key: ca_public,
            gateway_pq_certificate: gateway_pq_certificate.clone(),
            served_certificate_fingerprint: gateway_pq_certificate.fingerprint().unwrap(),
            gateway_pq_private_key: Zeroizing::new(gateway_pq_private.to_vec()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::new()),
            transactions: Mutex::new(TransactionState::default()),
        });

        let server = helios_key_negotiation::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &tls.server,
            tls.ca_der.clone(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let served = tokio::spawn(helios_key_negotiation::serve(server, handler));

        // From here on, everything runs through the client Orion actually
        // ships — same module, same code path as a real connection.
        let identities = TestIdentities(orion_core::key_negotiation::ClientIdentity {
            certificate_chain: vec![tls.client_certificate.clone()],
            private_key: tls.client_key.clone(),
            pq_certificate: serde_json::to_vec(&client_pq_certificate).unwrap(),
            pq_private_key: client_pq_private.to_vec(),
        });
        let profile = orion_core::ClientProfile {
            name: "orion".into(),
            endpoint: format!("127.0.0.1:{}", address.port()),
            private_key: client_wg.private_key.expose().to_string(),
            peer_public_key: gateway_wg.public_key.clone(),
            address: Some("100.64.1.2/32".into()),
            key_negotiation: Some(orion_core::KeyNegotiationSettings {
                mode: ProtectionMode::MlKem,
                minimum_mode: ProtectionMode::MlKem,
                endpoint: format!("127.0.0.1:{}", address.port()),
                server_name: "localhost".into(),
                gateway_ca_der: base64::engine::general_purpose::STANDARD.encode(&tls.ca_der),
                gateway_pq_certificate: base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&gateway_pq_certificate).unwrap()),
                identity: "orion".into(),
                trust: None,
            }),
            ..orion_core::ClientProfile::default()
        };

        let negotiated = orion_core::key_negotiation::prepare_for_profile(&profile, &identities)
            .await
            .expect("Orion negotiates with the real gateway handler");

        let client_psk = negotiated
            .psk
            .as_ref()
            .map(|secret| secret.expose().to_string())
            .expect("ML-KEM yields a PSK");

        // The gateway installs before answering: its value is already here.
        let gateway_psk = plane
            .writes()
            .await
            .last()
            .cloned()
            .flatten()
            .expect("the gateway installed a PSK before replying");

        assert_eq!(
            client_psk, gateway_psk,
            "both ends must derive the same PSK — differing values would fail every \
             WireGuard handshake with nothing to point at the cause"
        );
        // A 32-byte secret, base64: anything shorter would mean a truncated
        // derivation that still compares equal on both sides.
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&client_psk)
                .unwrap()
                .len(),
            32
        );

        // What a real client does between the response and the confirmation:
        // mount the tunnel with the candidate PSK and handshake. The gateway
        // reads that handshake back and it is the only proof in the exchange
        // that involves the peer's WireGuard private key.
        plane.handshake_happens().await;

        negotiated
            .confirm()
            .await
            .expect("the gateway commits the transaction Orion confirms");
        served.abort();
    }
}
