//! Orion's trust store: anchors, slots, the 80 % planner and atomic apply.
//!
//! This is the client half of spec §4.3 and §8. It holds what a profile pins —
//! `CA-PQ`, the trust domain, the gateway's active and next leaves, the Astra
//! service key, and its own certificate generations — and it applies trust
//! updates in **one** local write.
//!
//! # Why the renewal instant is derived, not drawn
//!
//! The window opens at 80 % of the leaf's life, and every client in a fleet
//! reaches it at nearly the same moment. Drawing a random instant inside it
//! would disperse them — until the first restart, when a fresh draw would
//! bunch them up again or move a renewal that was about to happen.
//!
//! [`renewal_instant`] instead derives the instant from values that do not
//! change: the client's WireGuard key, the generation and the certificate's
//! own period. It is stable across restarts by construction — there is nothing
//! to persist, and therefore nothing that can be lost — and it is uniform
//! across the fleet because the keys are.
//!
//! # Why nothing is applied halfway
//!
//! A trust update can move the CA, the TLS CA, the Astra service key, the
//! gateway identity and the client's own candidate. Applying them as they
//! arrive would produce a store that trusts the new anchor and still pins the
//! old gateway — a state no participant ever intended. [`TrustStore::apply`]
//! verifies the whole ordered set first and commits it with a single write;
//! a failure anywhere leaves the live state untouched.

use std::path::{Path, PathBuf};

use aether::certificates::{
    client::ClientCertificateGeneration,
    encoding::{Fingerprint, MlDsa87PublicKey, TrustDomainId, WireGuardKey},
    gateway::{pq_certificate_fingerprint, GatewayIdentityTransition},
    revocation::RevocationScope,
    state::{
        base_state_fingerprint, AstraProfile, ClientCertificateState, ClientTlsCaState,
        GatewayCertificateState, InstallOutcome, TrustLedger, TrustSnapshot,
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
    #[serde(default)]
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
            aether::certificates::transport::ManifestAuthority::CaPq => (
                &self.state.gateway.current_ca_public_key,
                self.state.gateway.ca_epoch,
            ),
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
                    if candidate
                        .gateway
                        .apply_ca_transition(transition, now_unix)?
                        == InstallOutcome::Installed
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
                    if candidate.gateway.install_transition(transition, now_unix)?
                        == InstallOutcome::Installed
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
                    candidate.ledger.schedule(revocation)?;
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
/// Derived, never drawn: the offset inside `[renewal_at, not_after)` comes
/// from the client's WireGuard key, the generation and the certificate period.
/// Restarting recomputes the same value, so a renewal that was about to happen
/// still happens, and the fleet stays spread out.
pub fn renewal_instant(
    generation: &ClientCertificateGeneration,
    client_wg_public_key: &WireGuardKey,
) -> Result<u64, CertificateError> {
    let validity = generation.validity()?;
    let renewal_at = validity.renewal_at()?;
    let span = validity
        .not_after
        .checked_sub(renewal_at)
        .filter(|span| *span > 0)
        .ok_or(CertificateError::ArithmeticOverflow)?;

    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(b"helios-client-renewal-dispersion-v5");
    input.extend_from_slice(client_wg_public_key.as_bytes());
    input.extend_from_slice(&generation.generation.to_be_bytes());
    input.extend_from_slice(&validity.not_before.to_be_bytes());
    input.extend_from_slice(&validity.not_after.to_be_bytes());
    let digest = Fingerprint::of(&input);
    let offset = u64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("a fingerprint is 32 bytes"),
    ) % span;

    renewal_at
        .checked_add(offset)
        .ok_or(CertificateError::ArithmeticOverflow)
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
mod tests {
    use super::*;
    #[cfg(feature = "certificate-signing")]
    use aether::certificates::encoding::DerCertificate;
    #[cfg(feature = "certificate-signing")]
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    fn generation(index: u64) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: index,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(&[index as u8, 1]),
            pq_certificate_fingerprint: Fingerprint::of(&[index as u8, 2]),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    /// Derived, not drawn: the same inputs always give the same instant, so a
    /// restart never moves a renewal that was about to happen.
    #[test]
    fn the_renewal_instant_is_stable_across_restarts() {
        let generation = generation(4);
        let first = renewal_instant(&generation, &key(1)).expect("instant");
        let second = renewal_instant(&generation, &key(1)).expect("instant");
        assert_eq!(first, second);
    }

    /// And it is inside the window it belongs to — never before 80 %, never at
    /// or after the expiry.
    #[test]
    fn the_renewal_instant_stays_inside_the_window() {
        let generation = generation(4);
        let validity = generation.validity().expect("validity");
        let renewal_at = validity.renewal_at().expect("renewal");
        for seed in 0..64u8 {
            let instant = renewal_instant(&generation, &key(seed)).expect("instant");
            assert!(instant >= renewal_at, "seed {seed}");
            assert!(instant < validity.not_after, "seed {seed}");
        }
    }

    /// Different clients land on different instants: that dispersion is the
    /// whole point, and a fleet arriving together is what it prevents.
    #[test]
    fn two_clients_do_not_renew_at_the_same_instant() {
        let generation = generation(4);
        let instants: std::collections::BTreeSet<_> = (0..32u8)
            .map(|seed| renewal_instant(&generation, &key(seed)).expect("instant"))
            .collect();
        assert!(
            instants.len() > 24,
            "expected a spread, got {} distinct instants",
            instants.len()
        );
    }

    /// A new generation moves the instant even for the same client, so two
    /// consecutive renewals do not fall on the same offset.
    #[test]
    fn a_new_generation_moves_the_instant() {
        assert_ne!(
            renewal_instant(&generation(4), &key(1)).expect("instant"),
            renewal_instant(&generation(5), &key(1)).expect("instant")
        );
    }

    #[test]
    fn a_renewal_is_due_only_from_its_own_instant() {
        let generation = generation(4);
        let instant = renewal_instant(&generation, &key(1)).expect("instant");
        assert!(!renewal_is_due(&generation, &key(1), instant - 1).expect("due"));
        assert!(renewal_is_due(&generation, &key(1), instant).expect("due"));
    }

    /// A signed gateway leaf: a PQ certificate's fingerprint covers its own
    /// signature, so an unsigned placeholder has no fingerprint at all.
    #[cfg(feature = "certificate-signing")]
    fn gateway_leaf() -> PqCertificate {
        use aether::certificates::encoding::generate_ml_dsa_87_keypair;
        use aether::key_negotiation::issue_pq_certificate;
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: "gateway.example".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: key(9).to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    #[cfg(feature = "certificate-signing")]
    fn store(
        path: PathBuf,
        anchor: aether::certificates::encoding::MlDsa87PublicKey,
        service: aether::certificates::encoding::MlDsa87PublicKey,
    ) -> TrustStore {
        TrustStore::new(
            path,
            TrustState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                client_wg_public_key: key(2),
                gateway: GatewayCertificateState {
                    trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                    gateway_wg_public_key: key(9),
                    server_name: "gateway.example".into(),
                    ca_epoch: 1,
                    current_ca_public_key: anchor,
                    next_ca_public_key: None,
                    next_ca_transition_fingerprint: None,
                    ca_activation_at: None,
                    ca_retire_active_at: None,
                    active_gateway_identity_epoch: 1,
                    gateway_decision_epoch: 1,
                    next_gateway_identity_epoch: None,
                    next_transition_fingerprint: None,
                    last_aborted_transition: None,
                    active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                    next_gateway_tls_certificate: None,
                    active_gateway_certificate: gateway_leaf(),
                    next_gateway_certificate: None,
                    activation_at: None,
                    retire_active_at: None,
                    published: false,
                    revoked: false,
                    revocation_epoch: 0,
                },
                client_tls_ca: ClientTlsCaState {
                    ca_tls_epoch: 1,
                    active_client_tls_ca_certificate: DerCertificate::new(vec![2; 64])
                        .expect("der"),
                    next_client_tls_ca_certificate: None,
                    next_transition_fingerprint: None,
                    activation_at: None,
                    retire_active_at: None,
                },
                astra: AstraProfile {
                    authority_url: "https://astra.example".into(),
                    webauthn_rp_id: "astra.example".into(),
                    active_astra_service_public_key: service,
                    next_astra_service_public_key: None,
                    next_service_key_transition_fingerprint: None,
                    astra_service_key_epoch: 1,
                    service_key_activation_at: None,
                    service_key_retire_active_at: None,
                    service_key_revocation_epoch: 0,
                    last_emergency_replacement_fingerprint: None,
                },
                issuer_epoch: 1,
                issuer: None,
                certificates: ClientCertificateState::new(generation(4)),
                staged_gateway_transition: None,
                ledger: TrustLedger::default(),
            },
        )
    }

    /// A revocation dated for later is kept, not dropped: its epoch is already
    /// consumed, so it would never be delivered again.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_future_revocation_is_held_and_applied_at_its_own_instant() {
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::revocation::{
            EmergencyCertificateRevocation, RevocationReason, RevocationScope,
        };

        let directory = tempfile::tempdir().expect("temp dir");
        let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public,
            service_public,
        );
        let active = generation(4);

        let revocation = EmergencyCertificateRevocation {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            scope: RevocationScope::Client,
            identity_key: key(2),
            server_name: None,
            revocation_epoch: 1,
            // Only the TLS half is named, and that is still a revocation: the
            // generation is indivisible.
            revoked_tls_fingerprint: Some(active.tls_certificate_fingerprint),
            revoked_pq_fingerprint: None,
            effective_at: 9_000,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private)
        .expect("sign");

        store
            .apply(
                &[TrustUpdateObject::CertificateRevocation(Box::new(
                    revocation,
                ))],
                1_000,
            )
            .expect("revocation accepted");

        assert!(
            !store.state().certificates.revoked,
            "a revocation dated for later is not in force yet"
        );
        assert_eq!(
            store.state().ledger.scheduled_revocations.len(),
            1,
            "and it is kept: its epoch has already been consumed"
        );
        assert_eq!(store.state().certificates.revocation_epoch, 1);

        store.refresh(8_999).expect("refresh");
        assert!(
            !store.state().certificates.revoked,
            "one second before its instant it is still not in force"
        );

        store.refresh(9_000).expect("refresh");
        assert!(
            store.state().certificates.revoked,
            "at its instant it takes effect, even though only the TLS half was named"
        );
        assert!(store.state().ledger.scheduled_revocations.is_empty());
    }

    /// A gateway revocation must remove the **gateway**, and it must spend the
    /// gateway's counter. Reading it against the client's consumes a number
    /// the client then needs, and revokes nothing at all.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_gateway_revocation_retires_the_gateway_and_not_the_client() {
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::revocation::{
            EmergencyCertificateRevocation, RevocationReason, RevocationScope,
        };

        let directory = tempfile::tempdir().expect("temp dir");
        let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public,
            service_public,
        );
        let served = store
            .state()
            .gateway
            .active_pq_fingerprint()
            .expect("fingerprint");

        let revocation = EmergencyCertificateRevocation {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            scope: RevocationScope::Gateway,
            identity_key: key(9),
            server_name: Some("gateway.example".into()),
            revocation_epoch: 1,
            revoked_tls_fingerprint: None,
            revoked_pq_fingerprint: Some(served),
            effective_at: 2_000,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private)
        .expect("sign");

        store
            .apply(
                &[TrustUpdateObject::CertificateRevocation(Box::new(
                    revocation.clone(),
                ))],
                1_000,
            )
            .expect("revocation accepted");

        assert_eq!(store.state().ledger.gateway_revocation_epoch, 1);
        assert_eq!(
            store.state().certificates.revocation_epoch,
            0,
            "a gateway decision must not spend the client's counter"
        );

        store.refresh(2_000).expect("refresh");
        assert!(
            store.state().gateway.revoked,
            "the compromised gateway is retired at its instant"
        );
        assert!(
            store
                .acceptable_gateway_fingerprints(2_000)
                .expect("fingerprints")
                .is_empty(),
            "and no leaf of it is acceptable any more"
        );
        assert!(
            !store.state().certificates.revoked,
            "the client identity is untouched: it was not the one revoked"
        );

        // The client's own counter is still at zero, so its first revocation
        // is still deliverable — which is exactly what a shared counter would
        // have destroyed.
        let client_revocation = EmergencyCertificateRevocation {
            scope: RevocationScope::Client,
            identity_key: key(2),
            server_name: None,
            revoked_pq_fingerprint: Some(generation(4).pq_certificate_fingerprint),
            effective_at: 2_500,
            ca_signature: MlDsa87Signature::placeholder(),
            ..revocation
        }
        .sign(&anchor_private)
        .expect("sign");
        store
            .apply(
                &[TrustUpdateObject::CertificateRevocation(Box::new(
                    client_revocation,
                ))],
                2_100,
            )
            .expect("the client's own first revocation still verifies");
        store.refresh(2_500).expect("refresh");
        assert!(store.state().certificates.revoked);
    }

    /// A revocation naming another machine is refused before its counter is
    /// spent: the object is signed, but it is not about this store.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_revocation_naming_another_identity_is_refused() {
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::revocation::{
            EmergencyCertificateRevocation, RevocationReason, RevocationScope,
        };

        let directory = tempfile::tempdir().expect("temp dir");
        let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public,
            service_public,
        );

        let stranger = EmergencyCertificateRevocation {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            scope: RevocationScope::Client,
            identity_key: key(77),
            server_name: None,
            revocation_epoch: 1,
            revoked_tls_fingerprint: Some(generation(4).tls_certificate_fingerprint),
            revoked_pq_fingerprint: None,
            effective_at: 1_000,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private)
        .expect("sign");

        assert!(store
            .apply(
                &[TrustUpdateObject::CertificateRevocation(Box::new(stranger))],
                1_000
            )
            .is_err());
        assert_eq!(store.state().certificates.revocation_epoch, 0);
        assert!(!store.state().certificates.revoked);
    }

    /// A status must name a slot this store actually holds, of the right
    /// family and generation. Taking the expected fingerprint from the status
    /// itself makes the binding tautological, and a correctly signed status
    /// about another identity is then absorbed as if it were about this one.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_status_about_something_this_store_does_not_hold_is_refused() {
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::status::{
            AstraCertificateStatus, CertificateKind, CertificateStatus,
        };

        let directory = tempfile::tempdir().expect("temp dir");
        let (_, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public,
            service_public,
        );
        let active = generation(4);

        let status = |fingerprint, kind, generation, status_epoch| {
            AstraCertificateStatus {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                certificate_fingerprint: fingerprint,
                certificate_kind: kind,
                generation,
                status: CertificateStatus::Active,
                suggested_window_start: 800_000,
                suggested_window_end: 1_000_000,
                produced_at: 1_000,
                next_update: 4_600,
                status_epoch,
                astra_service_key_epoch: 1,
                astra_signature: MlDsa87Signature::placeholder(),
            }
            .sign(&service_private)
            .expect("sign")
        };

        // Perfectly signed, and about a certificate this store never held.
        let stranger = status(
            Fingerprint::of(b"someone else's leaf"),
            CertificateKind::ClientPq,
            4,
            1,
        );
        assert!(store
            .apply(
                &[TrustUpdateObject::CertificateStatus(Box::new(stranger))],
                1_000
            )
            .is_err());

        // The right fingerprint under the wrong family is refused too: the
        // three fields together name a slot, and any one of them alone does
        // not.
        let mislabelled = status(
            active.pq_certificate_fingerprint,
            CertificateKind::GatewayPq,
            4,
            1,
        );
        assert!(store
            .apply(
                &[TrustUpdateObject::CertificateStatus(Box::new(mislabelled))],
                1_000
            )
            .is_err());

        // The genuine one lands, and moves the counter of that target only.
        let genuine = status(
            active.pq_certificate_fingerprint,
            CertificateKind::ClientPq,
            4,
            7,
        );
        store
            .apply(
                &[TrustUpdateObject::CertificateStatus(Box::new(genuine))],
                1_000,
            )
            .expect("a status about a slot this store holds");
        assert_eq!(
            store
                .state()
                .ledger
                .last_status_for(&active.pq_certificate_fingerprint),
            Some((1, 7))
        );
        // …and the TLS half of the same generation is a different target, so
        // it still starts at its own epoch instead of being held back behind
        // the counter of a certificate it has nothing to do with.
        let tls = status(
            active.tls_certificate_fingerprint,
            CertificateKind::ClientTls,
            4,
            1,
        );
        store
            .apply(
                &[TrustUpdateObject::CertificateStatus(Box::new(tls))],
                1_000,
            )
            .expect("counters are per target");
    }

    /// A transaction that fails anywhere leaves the live state untouched —
    /// the property that keeps a mixed trust store from ever existing.
    #[cfg(feature = "certificate-signing")]
    #[test]
    fn a_transaction_that_fails_leaves_the_live_state_untouched() {
        use aether::certificates::authority::CaTransition;
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87Signature};
        use aether::certificates::window::TransitionWindow;

        let directory = tempfile::tempdir().expect("temp dir");
        let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (next_private, next_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut store = store(
            directory.path().join("trust.json"),
            anchor_public.clone(),
            service_public,
        );
        let before = store.state().clone();

        let valid = CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: anchor_public.authority_fingerprint(),
            next_ca_public_key: next_public.clone(),
            next_ca_fingerprint: next_public.authority_fingerprint(),
            window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&anchor_private, &next_private)
        .expect("sign");

        // A **different** second CA transition cannot install: the store
        // already holds a rotation in flight after the first one, and it never
        // holds three anchors. (An identical replay would be idempotent — that
        // is the rule of spec §4.2, and a different one is the conflict.)
        let (other_private, other_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let conflicting = CaTransition {
            next_ca_public_key: other_public.clone(),
            next_ca_fingerprint: other_public.authority_fingerprint(),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
            ..valid.clone()
        }
        .sign(&anchor_private, &other_private)
        .expect("sign");
        let objects = vec![
            TrustUpdateObject::CaTransition(Box::new(valid)),
            TrustUpdateObject::CaTransition(Box::new(conflicting)),
        ];
        assert!(store.apply(&objects, 500).is_err());
        assert_eq!(
            store.state(),
            &before,
            "a failed transaction must not move the live state"
        );
        assert!(
            TrustStore::load(&directory.path().join("trust.json"))
                .expect("load")
                .is_none(),
            "and it must not have written anything at all"
        );
    }
}
