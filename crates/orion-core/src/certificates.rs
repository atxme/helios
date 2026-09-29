//! Orion's trust store: anchors, slots, the 80 % planner and atomic apply.
//!
//! This is the client half of spec §4.3 and §8. It holds what a profile pins —
//! `CA-PQ`, the trust domain, the gateway's active and next leaves, the Astra
//! service key, and its own certificate generations — and it applies trust
//! updates in **one** local write.
//!
//! # Renewal starts at the fixed safety threshold
//!
//! The ordinary path opens at 80 % of the active leaf's life. It does not
//! disperse a client anywhere in the remaining 20 %: doing so could postpone
//! the only automatic attempt until immediately before expiry.
//!
//! # Why nothing is applied halfway
//!
//! A trust update can move the CA, the TLS CA, the Astra service key, the
//! gateway identity and the client's own candidate. Applying them as they
//! arrive would produce a store that trusts the new anchor and still pins the
//! old gateway — a state no participant ever intended. [`TrustStore::apply`]
//! verifies the whole ordered set first and commits it with a single write;
//! a failure anywhere leaves the live state untouched.
//!
//! # Limite connue : pas de migration de format
//!
//! [`TrustState`] carries `deny_unknown_fields`, and the shape of its bounded
//! state has changed inside this lot — `ledger` replaced two flat fields, and
//! the committed-stage record grew. There is deliberately **no** migration
//! path, for one reason: nothing outside tests has ever written this file.
//! `TrustStore` is constructed by the tests and by nothing that ships, so no
//! instance of an earlier shape can exist on any disk.
//!
//! That is a fact about today, not a design choice to keep. Once a released
//! Orion writes a trust store, the format is frozen and any later change needs
//! an explicit migration with fixtures of the previous version. Until then the
//! behaviour is the correct one for a bounded security state: an unreadable
//! document fails loudly as [`TrustError::Corrupt`] rather than deserializing
//! into a store that silently dropped the revocations it could not parse.

use std::path::{Path, PathBuf};

use aether::certificates::{
    client::{ClientCertificateGeneration, ClientCertificateRotationGrant},
    encoding::{Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey},
    gateway::{pq_certificate_fingerprint, GatewayIdentityTransition},
    revocation::RevocationScope,
    state::{
        base_state_fingerprint, AstraProfile, ClientCertificateState, ClientTlsCaState,
        GatewayCertificateState, InstallOutcome, PendingStageState, TrustLedger, TrustSnapshot,
    },
    status::{AstraCertificateStatus, CertificateKind},
    transport::{
        OrionTrustUpdateDocument, PendingTrustTransaction, TrustUpdateChunk, TrustUpdateObject,
        TrustUpdateTransactionManifest,
    },
    CertificateError,
};
use serde::{Deserialize, Serialize};

/// Everything a `helios_key_negotiation` profile pins, in one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    pub trust_domain_id: TrustDomainId,
    pub client_wg_public_key: WireGuardKey,
    pub gateway: GatewayCertificateState,
    pub client_tls_ca: ClientTlsCaState,
    pub astra: AstraProfile,
    pub issuer_epoch: u64,
    /// The delegated issuer this client accepts leaves from, when one has been
    /// installed. Absent, only `CA-PQ` may have issued a client leaf.
    #[serde(default)]
    pub issuer: Option<aether::certificates::state::AstraIssuerState>,
    pub certificates: ClientCertificateState,
    /// The staged gateway transition itself, not just its slots.
    ///
    /// An abort names the exact document it cancels, and verifying it needs
    /// that document. Keeping only the certificates would make a tombstone
    /// unverifiable, and a client that cannot apply an abort refuses the next
    /// epoch for good — the sequential counter would never advance again.
    pub staged_gateway_transition: Option<GatewayIdentityTransition>,
    /// Revocations in flight, gateway counter, and status ordering per target.
    ///
    /// Held together because they are the cross-cutting part of the state:
    /// a revocation may name either identity, and the status counters are per
    /// certificate rather than global.
    pub ledger: TrustLedger,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("trust object refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust store is unreadable: {0}")]
    Corrupt(String),
}

/// The store and its file.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    state: TrustState,
}

impl TrustStore {
    pub fn new(path: PathBuf, state: TrustState) -> Self {
        Self { path, state }
    }

    pub fn load(path: &Path) -> Result<Option<Self>, TrustError> {
        match std::fs::read(path) {
            Ok(raw) => {
                let state: TrustState = serde_json::from_slice(&raw)
                    .map_err(|error| TrustError::Corrupt(error.to_string()))?;
                Ok(Some(Self {
                    path: path.to_path_buf(),
                    state,
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(TrustError::Io(error)),
        }
    }

    pub fn state(&self) -> &TrustState {
        &self.state
    }

    pub fn save(&self) -> Result<(), TrustError> {
        self.write(&self.state)
    }

    /// Writes a state without adopting it.
    ///
    /// The order matters: a transaction is written to disk **first**, and the
    /// in-memory state is replaced only once that write succeeded. Swapping
    /// first and returning the write error afterwards would leave a running
    /// client trusting objects that no restart would ever reload — the live
    /// state and the persisted one would disagree for as long as the process
    /// lived.
    fn write(&self, state: &TrustState) -> Result<(), TrustError> {
        let encoded = serde_json::to_vec_pretty(state)
            .map_err(|error| TrustError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
        Ok(())
    }

    /// Authorities that may have issued a client leaf of this domain.
    ///
    /// `CA-PQ` first, then the delegated Astra issuer if one is installed: an
    /// ordinary renewal produces a leaf chaining to the second.
    pub fn client_leaf_issuers(&self) -> Vec<&MlDsa87PublicKey> {
        let mut issuers = vec![&self.state.gateway.current_ca_public_key];
        if let Some(next) = &self.state.gateway.next_ca_public_key {
            issuers.push(next);
        }
        if let Some(issuer) = &self.state.issuer {
            issuers.push(&issuer.authorization.pq_issuer_public_key);
        }
        issuers
    }

    /// SHA-256 of the complete live state, as a manifest binds it (spec §8.1).
    pub fn base_state_fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        base_state_fingerprint(&TrustSnapshot {
            gateway: &self.state.gateway,
            client_tls_ca: &self.state.client_tls_ca,
            astra: &self.state.astra,
            issuer_epoch: self.state.issuer_epoch,
            issuer: self.state.issuer.as_ref(),
            client: &self.state.certificates,
            ledger: &self.state.ledger,
        })
    }

    /// The gateway PQ leaf this client may accept right now.
    pub fn acceptable_gateway_fingerprints(
        &self,
        now_unix: u64,
    ) -> Result<Vec<Fingerprint>, CertificateError> {
        self.state.gateway.acceptable_pq_fingerprints(now_unix)
    }

    /// Instant at which this client should open its own renewal.
    pub fn renewal_at(&self) -> Result<u64, CertificateError> {
        renewal_instant(
            &self.state.certificates.active,
            &self.state.client_wg_public_key,
        )
    }

    /// Verifies a whole chunked transaction, then applies it (spec §8.1).
    ///
    /// This is the entry point production code uses. It is what makes the
    /// transaction a *decision* rather than a delivery: the manifest is
    /// verified under an authority this store already trusts, its snapshot is
    /// compared against the live state, every fragment is attributed to it,
    /// and only a complete set is applied — by a single write.
    ///
    /// [`Self::apply`] stays public for the offline document and for tests,
    /// but it takes an already-attributed object list; it is not a shortcut
    /// around this.
    pub fn verify_and_apply_transaction(
        &mut self,
        manifest: &TrustUpdateTransactionManifest,
        chunks: &[TrustUpdateChunk],
        now_unix: u64,
    ) -> Result<usize, TrustError> {
        // The authority is resolved from the local state, never from the
        // manifest: a transaction that named the key which verifies it would
        // authorize itself.
        let (authority_key, authority_epoch) = match manifest.manifest_authority_kind {
            // `CA-PQ` authorizes objects and the offline document, never an
            // online per-client envelope (spec §0.6, §8.1.1).
            aether::certificates::transport::ManifestAuthority::CaPq => {
                return Err(TrustError::Certificate(
                    CertificateError::UnauthorizedIssuer,
                ))
            }
            aether::certificates::transport::ManifestAuthority::AstraServiceKey => (
                &self.state.astra.active_astra_service_public_key,
                self.state.astra.astra_service_key_epoch,
            ),
        };
        manifest.verify(
            authority_key,
            authority_epoch,
            &self.state.trust_domain_id,
            &self.state.gateway.gateway_wg_public_key,
            &self.state.client_wg_public_key,
            &self.base_state_fingerprint()?,
            now_unix,
        )?;

        let mut pending = PendingTrustTransaction::new(manifest.clone());
        for chunk in chunks {
            pending.accept(chunk)?;
        }
        let objects = pending.complete().ok_or(TrustError::Certificate(
            CertificateError::InvalidTransaction("incomplete transaction"),
        ))?;
        if !pending.is_usable_at(now_unix) {
            return Err(TrustError::Certificate(
                CertificateError::InvalidTransaction("transaction expired before commit"),
            ));
        }
        self.apply(&objects, now_unix)
    }

    /// Applies an attributed, complete set of trust objects in one write.
    ///
    /// Each object is verified against the anchors the store **already** holds,
    /// in a temporary copy. Only if every one of them lands is the copy written
    /// and adopted. A partial success is not exposed, because there is no
    /// instant at which it exists.
    pub fn apply(
        &mut self,
        objects: &[TrustUpdateObject],
        now_unix: u64,
    ) -> Result<usize, TrustError> {
        let mut candidate = self.state.clone();
        let mut applied = 0usize;

        for object in objects {
            match object {
                TrustUpdateObject::CaTransition(transition) => {
                    if candidate.gateway.apply_ca_transition(
                        transition,
                        &candidate.ledger,
                        now_unix,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::ClientTlsCaTransition(transition) => {
                    if candidate.client_tls_ca.apply_transition(
                        transition,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        &candidate.ledger,
                        now_unix,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::AstraServiceKeyTransition(transition) => {
                    if candidate.astra.apply_service_key_transition(
                        transition,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        &candidate.ledger,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::AstraServiceKeyEmergencyReplacement(replacement) => {
                    // The counter is the profile's own: this is a domain-wide
                    // decision, and reading it against a per-peer axis would
                    // make two clients of one fleet answer differently.
                    if candidate.astra.apply_emergency_replacement(
                        replacement,
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        &candidate.ledger,
                        now_unix,
                    )? == InstallOutcome::Installed
                    {
                        applied += 1;
                    }
                }
                TrustUpdateObject::AstraIssuerAuthorization(delegation) => {
                    // A delegation is not an anchor, but it decides which key
                    // may have issued the client's own next leaf. Ignoring it
                    // would make every renewed identity unverifiable here.
                    candidate
                        .astra
                        .astra_policy_fingerprint
                        .assert_authorizes(delegation)?;
                    delegation.verify(
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        candidate.client_tls_ca.ca_tls_epoch,
                        &candidate.gateway.gateway_wg_public_key,
                        &candidate.gateway.server_name,
                        now_unix,
                    )?;
                    if delegation.issuer_epoch < candidate.issuer_epoch {
                        return Err(TrustError::Certificate(
                            CertificateError::GenerationRollback {
                                current: candidate.issuer_epoch,
                                proposed: delegation.issuer_epoch,
                            },
                        ));
                    }
                    if delegation.issuer_epoch > candidate.issuer_epoch {
                        candidate.issuer_epoch = delegation.issuer_epoch;
                        candidate.issuer = Some(aether::certificates::state::AstraIssuerState {
                            issuer_epoch: delegation.issuer_epoch,
                            authorization: (**delegation).clone(),
                            state: aether::certificates::state::IssuerLifecycle::Active,
                        });
                        applied += 1;
                    }
                }
                TrustUpdateObject::GatewayIdentityTransition(transition) => {
                    if candidate.gateway.install_transition(
                        transition,
                        &candidate.ledger,
                        now_unix,
                    )? == InstallOutcome::Installed
                    {
                        candidate.staged_gateway_transition = Some((**transition).clone());
                        applied += 1;
                    }
                }
                TrustUpdateObject::GatewayTransitionAbort(abort) => {
                    // The store holds one staged transition at a time, so the
                    // document an abort must name is that one. Without it the
                    // abort is unverifiable, and refusing is the only safe
                    // answer: applying a cancellation on trust would let a
                    // forged tombstone remove a legitimate decision.
                    let staged = candidate.staged_gateway_transition.clone().ok_or(
                        CertificateError::IllegalStateTransition("no staged transition to abort"),
                    )?;
                    if candidate.gateway.apply_abort(abort, &staged, now_unix)?
                        == InstallOutcome::Installed
                    {
                        candidate.staged_gateway_transition = None;
                        applied += 1;
                    }
                }
                TrustUpdateObject::CertificateRevocation(revocation) => {
                    // Which identity this object names decides everything that
                    // follows: which counter it advances, and which state it
                    // will eventually remove something from. Reading a gateway
                    // revocation against the client counter consumes a number
                    // the client then needs, and revokes nothing.
                    let current_epoch = match revocation.scope {
                        RevocationScope::Gateway => {
                            if revocation.identity_key != candidate.gateway.gateway_wg_public_key
                                || revocation.server_name.as_deref()
                                    != Some(candidate.gateway.server_name.as_str())
                            {
                                return Err(TrustError::Certificate(
                                    CertificateError::GatewayIdentityMismatch,
                                ));
                            }
                            candidate.ledger.gateway_revocation_epoch
                        }
                        RevocationScope::Client => {
                            if revocation.identity_key != candidate.client_wg_public_key {
                                return Err(TrustError::Certificate(
                                    CertificateError::ClientIdentityMismatch,
                                ));
                            }
                            candidate.certificates.revocation_epoch
                        }
                    };
                    revocation.verify(
                        &candidate.gateway.current_ca_public_key,
                        &candidate.trust_domain_id,
                        candidate.gateway.ca_epoch,
                        current_epoch,
                    )?;
                    // The epoch is consumed the moment the object verifies —
                    // it will never be delivered again — so a revocation dated
                    // in the future is **kept**, not dropped.
                    if revocation.scope == RevocationScope::Client {
                        candidate.certificates.revocation_epoch = revocation.revocation_epoch;
                    }
                    candidate.ledger.schedule(
                        revocation,
                        &candidate.gateway,
                        &candidate.certificates,
                    )?;
                    applied += 1;
                }
                TrustUpdateObject::ClientCertificateStageAuthorization(_)
                | TrustUpdateObject::ClientCertificateRotationGrant(_) => {
                    // The rotation flow owns these: it holds the private keys
                    // they refer to, and installing a candidate here would
                    // bypass the commit that makes it activable.
                }
                TrustUpdateObject::CertificateStatus(status) => {
                    absorb_status(&mut candidate, status, now_unix)?;
                    applied += 1;
                }
            }
        }

        // Every revocation that is already due takes effect inside the same
        // transaction, so a client never adopts a trust update and only then
        // notices it was revoked by it.
        candidate.ledger.apply_due(
            &mut candidate.gateway,
            &mut candidate.certificates,
            now_unix,
        )?;

        // Written first, adopted second.
        self.write(&candidate)?;
        self.state = candidate;
        Ok(applied)
    }

    /// Persists a candidate whose grant the caller has already verified.
    ///
    /// **Orion stages from the grant**, not from the staging authorization:
    /// the §0.5 amendment keeps `ClientCertificateStageAuthorization` on the
    /// Astra–Helios veth, and a client never carries one. What the grant
    /// embeds is the receipt the gateway signed over that authorization, so
    /// the stage identifier, its fingerprint and its lease are attested rather
    /// than asserted.
    ///
    /// The verification is deliberately the caller's: it needs the rotation
    /// request, which only the session that signed it holds, and this store
    /// has no business keeping a copy of a signed object it did not produce.
    /// See [`crate::certificate_renewal`].
    pub fn stage_verified_grant(
        &mut self,
        grant: &ClientCertificateRotationGrant,
        now_unix: u64,
    ) -> Result<InstallOutcome, TrustError> {
        let mut candidate = self.state.clone();
        let outcome =
            candidate
                .certificates
                .stage_from_grant(grant, &candidate.ledger, now_unix)?;
        self.write(&candidate)?;
        self.state = candidate;
        Ok(outcome)
    }

    /// Turns the pending candidate into `next`, once the gateway confirmed.
    ///
    /// `PendingCommit` is passed explicitly rather than accepted from whatever
    /// the slot holds: the two ends commit from different states, and a client
    /// that adopted the gateway's rule would commit a candidate before the
    /// grant that releases it ever arrived.
    pub fn commit_staged_candidate(
        &mut self,
        stage_id: &Id16,
        commit_fingerprint: &Fingerprint,
        now_unix: u64,
    ) -> Result<InstallOutcome, TrustError> {
        let mut candidate = self.state.clone();
        let outcome = candidate.certificates.commit(
            stage_id,
            commit_fingerprint,
            PendingStageState::PendingCommit,
            now_unix,
        )?;
        self.write(&candidate)?;
        self.state = candidate;
        Ok(outcome)
    }

    /// Applies an offline `orion-trust-update` document (spec §8.4).
    ///
    /// The signature is checked under the CA active at the **start** of the
    /// import, taken from this store and never from the document.
    pub fn apply_document(
        &mut self,
        document: &OrionTrustUpdateDocument,
        now_unix: u64,
    ) -> Result<usize, TrustError> {
        document.verify(
            &self.state.gateway.current_ca_public_key,
            &self.state.trust_domain_id,
        )?;
        self.apply(&document.objects, now_unix)
    }

    /// Brings the store up to date with the clock.
    ///
    /// Promotes every slot whose overlap has ended, and applies every
    /// revocation that has reached its instant. Callers run it before reading
    /// the store, so a revocation dated for this morning is in force this
    /// morning rather than at the next trust update.
    pub fn refresh(&mut self, now_unix: u64) -> Result<bool, TrustError> {
        let mut candidate = self.state.clone();
        let mut moved = candidate.gateway.promote_if_due(now_unix)?;
        if moved {
            // The staged document has done its job: keeping it would let a
            // late abort name a transition that is already the active one.
            candidate.staged_gateway_transition = None;
        }
        moved |= candidate.gateway.promote_ca_if_due(now_unix);
        moved |= candidate.client_tls_ca.promote_if_due(now_unix);
        moved |= candidate.astra.promote_service_key_if_due(now_unix);
        moved |= candidate.certificates.promote_if_due(now_unix);
        moved |= candidate.ledger.apply_due(
            &mut candidate.gateway,
            &mut candidate.certificates,
            now_unix,
        )?;
        // A tombstone whose target could no longer be valid anyway protects
        // nothing, and the list is bounded: keeping it costs a slot a live
        // revocation may need. Only known expiries are pruned.
        moved |= candidate.ledger.forget_expired(now_unix);
        // A promoted generation is gone from the state, so its status counter
        // is only occupying room in a bounded map.
        let held: Vec<Fingerprint> = status_targets(&candidate)
            .into_iter()
            .map(|target| target.fingerprint)
            .collect();
        let before = candidate.ledger.last_statuses.len();
        candidate.ledger.prune_statuses(&held);
        moved |= candidate.ledger.last_statuses.len() != before;
        if moved {
            self.write(&candidate)?;
            self.state = candidate;
        }
        Ok(moved)
    }
}

/// One certified object this store currently holds, as a status names it.
struct StatusTarget {
    kind: CertificateKind,
    generation: u64,
    fingerprint: Fingerprint,
}

/// Every target a signed status may legitimately be about.
///
/// A status is not indexed by the fingerprint it carries: it has to name a
/// slot this store actually holds, of the right family, at the right
/// generation. Passing the status's own fingerprint in as the expected one —
/// which is what an implementation reaches for first — makes the binding check
/// tautological, and a correctly signed status about another identity is then
/// absorbed as if it described this one.
fn status_targets(state: &TrustState) -> Vec<StatusTarget> {
    let mut targets = Vec::new();
    let mut push = |kind, generation, fingerprint| {
        targets.push(StatusTarget {
            kind,
            generation,
            fingerprint,
        });
    };

    for generation in [
        Some(&state.certificates.active),
        state.certificates.next.as_ref(),
        state.certificates.pending.as_ref().map(|p| &p.candidate),
    ]
    .into_iter()
    .flatten()
    {
        push(
            CertificateKind::ClientTls,
            generation.generation,
            generation.tls_certificate_fingerprint,
        );
        push(
            CertificateKind::ClientPq,
            generation.generation,
            generation.pq_certificate_fingerprint,
        );
    }

    let gateway = &state.gateway;
    push(
        CertificateKind::GatewayTls,
        gateway.active_gateway_identity_epoch,
        gateway.active_tls_fingerprint(),
    );
    if let Ok(fingerprint) = gateway.active_pq_fingerprint() {
        push(
            CertificateKind::GatewayPq,
            gateway.active_gateway_identity_epoch,
            fingerprint,
        );
    }
    if let Some(epoch) = gateway.next_gateway_identity_epoch {
        if let Some(certificate) = &gateway.next_gateway_tls_certificate {
            push(
                CertificateKind::GatewayTls,
                epoch,
                certificate.fingerprint(),
            );
        }
        if let Some(Ok(fingerprint)) = gateway
            .next_gateway_certificate
            .as_ref()
            .map(pq_certificate_fingerprint)
        {
            push(CertificateKind::GatewayPq, epoch, fingerprint);
        }
    }

    push(
        CertificateKind::CaPq,
        gateway.ca_epoch,
        gateway.current_ca_public_key.authority_fingerprint(),
    );
    if let Some(next) = &gateway.next_ca_public_key {
        push(
            CertificateKind::CaPq,
            gateway.ca_epoch + 1,
            next.authority_fingerprint(),
        );
    }
    push(
        CertificateKind::CaTls,
        state.client_tls_ca.ca_tls_epoch,
        state
            .client_tls_ca
            .active_client_tls_ca_certificate
            .fingerprint(),
    );
    if let Some(next) = &state.client_tls_ca.next_client_tls_ca_certificate {
        push(
            CertificateKind::CaTls,
            state.client_tls_ca.ca_tls_epoch + 1,
            next.fingerprint(),
        );
    }
    push(
        CertificateKind::AstraServiceKey,
        state.astra.astra_service_key_epoch,
        state
            .astra
            .active_astra_service_public_key
            .authority_fingerprint(),
    );
    if let Some(next) = &state.astra.next_astra_service_public_key {
        push(
            CertificateKind::AstraServiceKey,
            state.astra.astra_service_key_epoch + 1,
            next.authority_fingerprint(),
        );
    }
    if let Some(issuer) = &state.issuer {
        push(
            CertificateKind::AstraIssuer,
            issuer.issuer_epoch,
            issuer.authorization.fingerprint(),
        );
    }
    targets
}

/// Verifies a signed status against the slot it claims to describe.
///
/// The status never widens validity: it moves an ordering counter and nothing
/// else. What it is checked for is that it names something this store holds,
/// and that it is not older than the last one accepted **for that same
/// target** — Astra counts per certificate, so a global counter would leave a
/// freshly rotated leaf refused for good behind the epoch of the leaf it
/// replaced.
fn absorb_status(
    candidate: &mut TrustState,
    status: &AstraCertificateStatus,
    now_unix: u64,
) -> Result<(), TrustError> {
    let target = status_targets(candidate)
        .into_iter()
        .find(|target| {
            target.kind == status.certificate_kind
                && target.generation == status.generation
                && target.fingerprint.matches(&status.certificate_fingerprint)
        })
        .ok_or(CertificateError::FingerprintMismatch("status target"))?;
    let service_key = candidate
        .astra
        .service_key_for(status.astra_service_key_epoch, now_unix)
        .ok_or(CertificateError::UnauthorizedIssuer)?;
    status.verify(
        service_key,
        status.astra_service_key_epoch,
        &candidate.trust_domain_id,
        &target.fingerprint,
        candidate.ledger.last_status_for(&target.fingerprint),
    )?;
    candidate
        .ledger
        .record_status(&target.fingerprint, status)?;
    Ok(())
}

/// The instant this client opens its renewal window (spec §4.3).
///
/// The fixed 80 % threshold. The key remains an argument because callers
/// identify the generation and its owner together.
pub fn renewal_instant(
    generation: &ClientCertificateGeneration,
    _client_wg_public_key: &WireGuardKey,
) -> Result<u64, CertificateError> {
    generation.validity()?.renewal_at()
}

/// Whether a renewal is due at `now_unix`.
pub fn renewal_is_due(
    generation: &ClientCertificateGeneration,
    client_wg_public_key: &WireGuardKey,
    now_unix: u64,
) -> Result<bool, CertificateError> {
    Ok(now_unix >= renewal_instant(generation, client_wg_public_key)?)
}

#[cfg(test)]
mod tests;
