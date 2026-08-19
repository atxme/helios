//! Renewal operations: what the 80 % threshold prepares, and what it refuses
//! to finish on its own — spec §7.2, §8.1.2 and the amendment of 15 August
//! 2026.
//!
//! # Why an operation exists at all
//!
//! Before that amendment there was nothing to hold: Astra received a request,
//! signed two leaves and staged them, all in one call. The amendment inserts a
//! human, and a human is not a function call. So the request has to survive
//! between the moment the threshold notices it and the moment a YubiKey
//! answers it — under one identifier, bound to one peer, with one deadline.
//! That is this module.
//!
//! # The states, and the one that is the point
//!
//! [`ClientRenewalOperationState::AwaitingOperator`] is the state the
//! threshold creates and the only state an operation is born in. No
//! certificate exists in it, nothing has been signed by the delegated issuer,
//! and no amount of polling moves it: only an assertion that answers the exact
//! challenge of this operation's approval request does. That is the whole
//! difference between "the planner decided" and "the planner may act".
//!
//! From there an operation reaches `pending_commit` — the gateway persisted
//! the candidate, signed a receipt, and the grant is available — or `failed`.
//! There is no state in between that a client could mistake for permission.
//!
//! # Why the order is enforced here as well as in the issuer
//!
//! [`crate::DelegatedIssuer::release_grant`] already refuses to build a grant
//! without a receipt that verifies against the authorization. This module
//! refuses a second time, structurally: [`Operation::record_grant`] cannot be
//! reached before [`Operation::record_receipt`]. Two controls because they fail
//! differently — the issuer's is cryptographic and this one is a state
//! machine, and a refactor that lost one would almost certainly keep the other.
//!
//! # Limite connue
//!
//! One approval attempt per operation. The single-use capability token of
//! [`aether::certificates::capability`] is consumed by `operation_id`, on
//! successful authentication, before this module sees the result — so a
//! staging that fails **after** a valid assertion ends the operation rather
//! than asking for a second one, which is what §8.1.2 would otherwise allow
//! ("une assertion expirée peut être redemandée pour la même demande non
//! expirée"). The client opens a new operation for the same generation once
//! the previous stage lease has been purged. Consuming the token on the
//! accepted *result* instead of on the authenticated *token* — a change to
//! `CapabilityTokens`, in `aether` — is what would close it.

use std::collections::BTreeMap;

use aether::certificates::{
    approval::AstraCredentialApprovalRequest,
    client::{
        ClientCertificateRotationGrant, ClientCertificateRotationRequest,
        GatewayCertificateStageReceipt,
    },
    encoding::{Fingerprint, Id16, WireGuardKey},
};
use helios_api::internal::{ClientRenewalOperationState, ClientRenewalOperationView};

/// Largest number of operations held at once.
///
/// One per admitted peer is the shape of the traffic — a fleet renews over
/// weeks, not at once — and the map is bounded for the same reason the source
/// budget is: an unbounded one turns "open an operation" into a memory
/// exhaustion primitive against a service that has to stay up to finish the
/// rotations already in flight.
pub const MAX_LIVE_OPERATIONS: usize = 4_096;

/// Why an operation refused a transition.
///
/// Every variant is a refusal the caller may legitimately hit, and none of
/// them reaches a client unchanged: [`crate::service`] and the private router
/// map them to their coarse class before answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    #[error("no operation holds this identifier")]
    Unknown,
    #[error("this operation belongs to another peer")]
    NotYours,
    #[error("this operation has expired")]
    Expired,
    #[error(
        "this operation no longer awaits an operator: it has already been approved, or it failed"
    )]
    NotAwaitingOperator,
    #[error("an operation is already in flight for this peer")]
    AlreadyInFlight,
    #[error("this operation identifier already names another operation")]
    IdentifierConflict,
    #[error(
        "the authority is holding as many operations as it will: the oldest have to expire before \
         a new renewal can be opened"
    )]
    Saturated,
    #[error(
        "a grant cannot exist before the gateway's receipt: the authority would be releasing an \
         identity the gateway has not admitted"
    )]
    ReceiptRequired,
    #[error("this operation already carries a receipt for another staging")]
    ReceiptConflict,
    #[error(
        "this operation's approval has already been spent: one assertion opens one issuance, and \
         a second would renew twice under one touch"
    )]
    ApprovalAlreadySpent,
}

/// One renewal, from the threshold that prepared it to the grant that ends it.
#[derive(Debug, Clone)]
pub struct Operation {
    pub operation_id: Id16,
    pub client_wg_public_key: WireGuardKey,
    /// The client's own request, kept whole: the approval binds to its exact
    /// fingerprint, and recomputing that from a summary would bind to
    /// something else.
    pub request: Box<ClientCertificateRotationRequest>,
    pub request_fingerprint: Fingerprint,
    /// The signed request an operator is shown. Re-minted while the operation
    /// lives, because it is bounded to five minutes and the operation is not.
    pub approval_request: Box<AstraCredentialApprovalRequest>,
    pub state: ClientRenewalOperationState,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set when the approval is consumed, so a replay of the same assertion is
    /// a refusal rather than a second issuance.
    approved_with: Option<Fingerprint>,
    /// Identifier of the staging sent to the gateway, once one was.
    stage_id: Option<Id16>,
    /// The gateway's signed receipt. The only door to a grant.
    receipt: Option<Box<GatewayCertificateStageReceipt>>,
    grant: Option<Box<ClientCertificateRotationGrant>>,
}

impl Operation {
    /// Opens an operation in `awaiting_operator` and nothing else.
    pub fn awaiting_operator(
        operation_id: Id16,
        client_wg_public_key: WireGuardKey,
        request: Box<ClientCertificateRotationRequest>,
        approval_request: Box<AstraCredentialApprovalRequest>,
        created_at: u64,
    ) -> Self {
        let request_fingerprint = request.fingerprint();
        let expires_at = request.expires_at;
        Self {
            operation_id,
            client_wg_public_key,
            request,
            request_fingerprint,
            approval_request,
            state: ClientRenewalOperationState::AwaitingOperator,
            created_at,
            expires_at,
            approved_with: None,
            stage_id: None,
            receipt: None,
            grant: None,
        }
    }

    /// The manifest the capability tokens of §8.2 are bound to.
    ///
    /// The fingerprint of the signed approval request — the exact document the
    /// operator is shown. Re-minting the approval request therefore invalidates
    /// every token issued against the previous one, which is the correct
    /// outcome: they authorized a fetch of a manifest that no longer describes
    /// what will be asked.
    pub fn manifest_fingerprint(&self) -> Fingerprint {
        self.approval_request.fingerprint()
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    /// Refuses a caller that does not own this operation.
    ///
    /// On the private link the authenticated party is the gateway, so this is
    /// the only place the peer is checked on Astra's side. The gateway checks
    /// it too, against the source VIP; neither check makes the other
    /// redundant, because they are proofs of different things.
    pub fn assert_owner(&self, caller: &WireGuardKey) -> Result<(), OperationError> {
        if self.client_wg_public_key != *caller {
            return Err(OperationError::NotYours);
        }
        Ok(())
    }

    /// Replaces the approval request when the current one can no longer be
    /// answered inside its own window.
    ///
    /// Refused once the operation has left `awaiting_operator`: a fresh
    /// challenge on an approved operation would be an invitation to approve
    /// the same renewal twice.
    pub fn refresh_approval_request(
        &mut self,
        approval_request: Box<AstraCredentialApprovalRequest>,
    ) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::AwaitingOperator {
            return Err(OperationError::NotAwaitingOperator);
        }
        self.approval_request = approval_request;
        Ok(())
    }

    /// Spends the operator's approval.
    ///
    /// The evidence must already have been verified by the caller against this
    /// operation's own approval request — this records the decision and makes
    /// it unrepeatable. A second call, with the same assertion or another,
    /// refuses: one approval opens one issuance.
    pub fn consume_approval(
        &mut self,
        approval_fingerprint: Fingerprint,
    ) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::AwaitingOperator {
            return Err(OperationError::NotAwaitingOperator);
        }
        if self.approved_with.is_some() {
            return Err(OperationError::ApprovalAlreadySpent);
        }
        self.approved_with = Some(approval_fingerprint);
        Ok(())
    }

    /// The approval this operation was opened by, once one was spent.
    pub fn approved_with(&self) -> Option<Fingerprint> {
        self.approved_with
    }

    /// Records which staging was sent to the gateway.
    pub fn record_stage(&mut self, stage_id: Id16) {
        self.stage_id = Some(stage_id);
    }

    pub fn stage_id(&self) -> Option<Id16> {
        self.stage_id
    }

    /// Records the receipt the gateway signed after persisting the candidate.
    ///
    /// The caller has verified it against the authorization; this stores it and
    /// refuses a second, different one under the same operation.
    pub fn record_receipt(
        &mut self,
        receipt: Box<GatewayCertificateStageReceipt>,
    ) -> Result<(), OperationError> {
        if let Some(existing) = &self.receipt {
            if existing.fingerprint().matches(&receipt.fingerprint()) {
                return Ok(());
            }
            return Err(OperationError::ReceiptConflict);
        }
        self.receipt = Some(receipt);
        Ok(())
    }

    pub fn receipt(&self) -> Option<&GatewayCertificateStageReceipt> {
        self.receipt.as_deref()
    }

    /// Attaches the grant, and only against a receipt already recorded.
    ///
    /// This is the structural half of "no grant before the receipt". The
    /// cryptographic half lives in [`crate::DelegatedIssuer::release_grant`],
    /// which refuses to sign one at all without a receipt that verifies.
    pub fn record_grant(
        &mut self,
        grant: Box<ClientCertificateRotationGrant>,
    ) -> Result<(), OperationError> {
        if self.receipt.is_none() {
            return Err(OperationError::ReceiptRequired);
        }
        self.grant = Some(grant);
        self.state = ClientRenewalOperationState::PendingCommit;
        Ok(())
    }

    /// Ends the operation without a grant.
    ///
    /// Named rather than silent: a client that keeps polling an operation that
    /// will never produce anything is a client that never renews.
    pub fn fail(&mut self) {
        self.state = ClientRenewalOperationState::Failed;
        self.grant = None;
    }

    /// The answer a client receives, tokens included.
    ///
    /// Tokens are minted per read and belong to the caller that owns the
    /// operation; a failed or granted operation gets none, because there is
    /// nothing left for a companion to do.
    pub fn view(
        &self,
        signer_request_token: Option<String>,
        signer_result_token: Option<String>,
    ) -> ClientRenewalOperationView {
        let awaiting = self.state == ClientRenewalOperationState::AwaitingOperator;
        ClientRenewalOperationView {
            operation_id: self.operation_id,
            state: self.state,
            client_wg_public_key: self.client_wg_public_key,
            request_fingerprint: self.request_fingerprint,
            operation_manifest_fingerprint: self.manifest_fingerprint(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            signer_request_token: awaiting.then_some(signer_request_token).flatten(),
            signer_result_token: awaiting.then_some(signer_result_token).flatten(),
            grant: self.grant.clone(),
        }
    }
}

/// Every live operation, indexed by identifier and by peer.
///
/// Two indexes because two questions are asked: "what is operation *x*" on
/// every poll, and "does this peer already have one" on every request. One
/// operation per peer at a time is the same bound the registry enforces on
/// rotations — two candidates for one identity make `active + 1` ambiguous.
#[derive(Debug, Default)]
pub struct OperationStore {
    operations: BTreeMap<[u8; 16], Operation>,
    by_peer: BTreeMap<[u8; 32], [u8; 16]>,
}

impl OperationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Inserts a fresh operation, refusing a second one for the same peer.
    ///
    /// Expired operations are swept first: debris must not block the renewal it
    /// was supposed to perform, exactly as an expired staging does not block
    /// the next one in the registry.
    pub fn open(&mut self, operation: Operation, now_unix: u64) -> Result<(), OperationError> {
        self.purge_expired(now_unix);
        if self.operations.len() >= MAX_LIVE_OPERATIONS {
            return Err(OperationError::Saturated);
        }
        let peer = *operation.client_wg_public_key.as_bytes();
        if self.by_peer.contains_key(&peer) {
            return Err(OperationError::AlreadyInFlight);
        }
        let id = *operation.operation_id.as_bytes();
        if self.operations.contains_key(&id) {
            return Err(OperationError::IdentifierConflict);
        }
        self.by_peer.insert(peer, id);
        self.operations.insert(id, operation);
        Ok(())
    }

    /// Reads one operation, checking ownership and the clock in that order.
    pub fn get(
        &self,
        operation_id: &Id16,
        caller: &WireGuardKey,
        now_unix: u64,
    ) -> Result<&Operation, OperationError> {
        let operation = self
            .operations
            .get(operation_id.as_bytes())
            .ok_or(OperationError::Unknown)?;
        operation.assert_owner(caller)?;
        if operation.is_expired(now_unix) {
            return Err(OperationError::Expired);
        }
        Ok(operation)
    }

    /// The mutable form of [`Self::get`], with the same two checks.
    pub fn get_mut(
        &mut self,
        operation_id: &Id16,
        caller: &WireGuardKey,
        now_unix: u64,
    ) -> Result<&mut Operation, OperationError> {
        let operation = self
            .operations
            .get_mut(operation_id.as_bytes())
            .ok_or(OperationError::Unknown)?;
        operation.assert_owner(caller)?;
        if operation.is_expired(now_unix) {
            return Err(OperationError::Expired);
        }
        Ok(operation)
    }

    /// Drops every operation past its deadline, and returns their peers.
    pub fn purge_expired(&mut self, now_unix: u64) -> Vec<WireGuardKey> {
        let mut purged = Vec::new();
        self.operations.retain(|_, operation| {
            if operation.is_expired(now_unix) {
                purged.push(operation.client_wg_public_key);
                false
            } else {
                true
            }
        });
        for peer in &purged {
            self.by_peer.remove(peer.as_bytes());
        }
        purged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::{
        approval::MAX_APPROVAL_LIFETIME_SECS,
        encoding::{DerCertificate, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId},
        CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
    };

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    fn request(client: WireGuardKey) -> Box<ClientCertificateRotationRequest> {
        let (_, public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
        Box::new(ClientCertificateRotationRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([3; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: key(9),
            server_name: "gateway.example".into(),
            client_wg_public_key: client,
            active_generation: 4,
            requested_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            tls_csr: DerCertificate::new(vec![7; 64]).expect("der"),
            new_ml_dsa_87_public_key: public,
            created_at: 1_000,
            expires_at: 5_000,
            active_pq_signature: MlDsa87Signature::placeholder(),
            new_pq_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn approval_request(client: WireGuardKey) -> Box<AstraCredentialApprovalRequest> {
        Box::new(AstraCredentialApprovalRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: Id16::new([2; 16]).expect("id"),
            request_fingerprint: Fingerprint::of(b"request"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: key(9),
            client_wg_public_key: client,
            active_generation: 4,
            requested_generation: 5,
            credential_registry_epoch: 1,
            webauthn_rp_id: "astra.example".into(),
            webauthn_origin: "https://astra.example".into(),
            allowed_credential_ids: vec![vec![1, 2, 3]],
            required_credentials: 1,
            created_at: 1_000,
            expires_at: 1_000 + MAX_APPROVAL_LIFETIME_SECS,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn operation(seed: u8, client: WireGuardKey) -> Operation {
        Operation::awaiting_operator(
            Id16::new([seed; 16]).expect("id"),
            client,
            request(client),
            approval_request(client),
            1_000,
        )
    }

    fn receipt() -> Box<GatewayCertificateStageReceipt> {
        Box::new(GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            stage_id: Id16::new([8; 16]).expect("id"),
            stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
            request_fingerprint: Fingerprint::of(b"request"),
            operator_approval_fingerprint: Fingerprint::of(b"approval"),
            gateway_wg_public_key: key(9),
            client_wg_public_key: key(2),
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: Fingerprint::of(b"staged tls"),
            staged_pq_certificate_fingerprint: Fingerprint::of(b"staged pq"),
            persisted_at: 1_100,
            stage_expires_at: 4_000,
            active_gateway_identity_epoch: 3,
            gateway_decision_epoch: 3,
            gateway_certificate_fingerprint: Fingerprint::of(b"gateway leaf"),
            gateway_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn grant() -> Box<ClientCertificateRotationGrant> {
        Box::new(ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            issuer_kind: aether::certificates::client::IssuerKind::Astra,
            issuer_epoch: 1,
            issuer_authorization_fingerprint: Fingerprint::of(b"delegation"),
            issuer_authorization: None,
            request_fingerprint: Fingerprint::of(b"request"),
            operator_approval_fingerprint: Fingerprint::of(b"approval"),
            renewal_approval: None,
            stage_receipt_fingerprint: receipt().fingerprint(),
            stage_receipt: *receipt(),
            gateway_wg_public_key: key(9),
            server_name: "gateway.example".into(),
            client_wg_public_key: key(2),
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            next_tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            next_tls_certificate: DerCertificate::new(vec![5; 64]).expect("der"),
            next_pq_certificate: aether::key_negotiation::PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [4; 16],
                subject: "workstation".into(),
                issuer: "astra-delegated-issuer".into(),
                role: aether::key_negotiation::PqCertificateRole::Client,
                wireguard_public_key: key(2).to_base64(),
                ml_dsa_87_public_key: MlDsa87PublicKey::parse(
                    &aether::certificates::encoding::generate_ml_dsa_87_keypair()
                        .expect("keygen")
                        .1
                        .to_base64(),
                )
                .expect("key")
                .to_base64(),
                not_before_unix: 0,
                not_after_unix: 100_000,
                ml_dsa_87_signature: String::new(),
            },
            stage_expires_at: 4_000,
            window: aether::certificates::window::TransitionWindow::new(1_000, 2_000, 90_000)
                .expect("window"),
            reason: aether::certificates::authority::RotationReason::Scheduled,
            signature: MlDsa87Signature::placeholder(),
        })
    }

    /// The point of the amendment of 15 August 2026: the threshold prepares,
    /// and nothing else moves without an operator.
    #[test]
    fn an_operation_is_born_awaiting_an_operator_and_carries_no_grant() {
        let operation = operation(1, key(2));
        assert_eq!(
            operation.state,
            ClientRenewalOperationState::AwaitingOperator
        );
        let view = operation.view(Some("read".into()), Some("submit".into()));
        assert!(view.grant.is_none());
        assert_eq!(view.signer_request_token.as_deref(), Some("read"));
        assert_eq!(view.signer_result_token.as_deref(), Some("submit"));
    }

    /// A grant before the receipt would be the authority releasing an identity
    /// the gateway has not admitted.
    #[test]
    fn a_grant_before_the_receipt_is_refused() {
        let mut operation = operation(1, key(2));
        assert_eq!(
            operation.record_grant(grant()),
            Err(OperationError::ReceiptRequired)
        );
        assert_eq!(
            operation.state,
            ClientRenewalOperationState::AwaitingOperator
        );

        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        assert_eq!(operation.state, ClientRenewalOperationState::PendingCommit);
        assert!(operation
            .view(Some("read".into()), Some("submit".into()))
            .grant
            .is_some());
    }

    /// Once the grant exists the companion has nothing left to do, so it is
    /// handed no token to do it with.
    #[test]
    fn a_granted_operation_hands_out_no_capability_token() {
        let mut operation = operation(1, key(2));
        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        let view = operation.view(Some("read".into()), Some("submit".into()));
        assert!(view.signer_request_token.is_none());
        assert!(view.signer_result_token.is_none());
    }

    /// A receipt is idempotent when identical and a conflict otherwise: the
    /// same `stage_id` with other bytes describes another fact.
    #[test]
    fn a_second_receipt_is_idempotent_only_if_it_is_the_same_one() {
        let mut operation = operation(1, key(2));
        operation.record_receipt(receipt()).expect("receipt");
        operation.record_receipt(receipt()).expect("replay");

        let mut other = receipt();
        other.staged_generation = 6;
        assert_eq!(
            operation.record_receipt(other),
            Err(OperationError::ReceiptConflict)
        );
    }

    /// The challenge may be re-minted while an operator is still expected, and
    /// never afterwards: a fresh challenge on an approved operation invites a
    /// second approval of one renewal.
    #[test]
    fn the_challenge_is_re_minted_only_while_an_operator_is_expected() {
        let mut operation = operation(1, key(2));
        operation
            .refresh_approval_request(approval_request(key(2)))
            .expect("refresh");

        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        assert_eq!(
            operation.refresh_approval_request(approval_request(key(2))),
            Err(OperationError::NotAwaitingOperator)
        );
    }

    /// An operation belongs to the peer that opened it, and to nobody else.
    #[test]
    fn another_peer_cannot_read_an_operation() {
        let mut store = OperationStore::new();
        store.open(operation(1, key(2)), 1_000).expect("open");
        let id = Id16::new([1; 16]).expect("id");

        store.get(&id, &key(2), 1_100).expect("its owner");
        assert_eq!(
            store.get(&id, &key(3), 1_100).map(|_| ()),
            Err(OperationError::NotYours)
        );
    }

    /// One in flight per peer, and expired debris blocks nothing.
    #[test]
    fn one_operation_per_peer_and_expired_ones_free_the_slot() {
        let mut store = OperationStore::new();
        store.open(operation(1, key(2)), 1_000).expect("open");
        assert_eq!(
            store.open(operation(4, key(2)), 1_100),
            Err(OperationError::AlreadyInFlight)
        );
        // Another peer is unaffected: the bound is per peer, not global.
        store.open(operation(5, key(3)), 1_100).expect("other peer");
        assert_eq!(store.len(), 2);
        store
            .get(&Id16::new([5; 16]).expect("id"), &key(3), 1_100)
            .expect("and it is readable while it lives");

        // Past the request's own deadline the slot is free again. Every
        // operation here expires with the same request, so the sweep at 5_000
        // takes both of the older ones and only the fresh one is left — which
        // is the property: debris blocks nothing, and it does not linger.
        store
            .open(operation(6, key(2)), 5_000)
            .expect("after expiry");
        assert_eq!(store.len(), 1, "the expired ones were swept");
    }

    /// An expired operation is refused rather than read: a client polling one
    /// must learn it has to start again.
    #[test]
    fn an_expired_operation_is_refused_on_read() {
        let mut store = OperationStore::new();
        store.open(operation(1, key(2)), 1_000).expect("open");
        let id = Id16::new([1; 16]).expect("id");
        assert_eq!(
            store.get(&id, &key(2), 5_000).map(|_| ()),
            Err(OperationError::Expired)
        );
    }

    /// One approval opens one issuance. A second consumption — the same
    /// assertion replayed, or another one — is refused.
    #[test]
    fn an_approval_is_spent_once() {
        let mut operation = operation(1, key(2));
        let approval = Fingerprint::of(b"an approval");
        operation.consume_approval(approval).expect("first");
        assert_eq!(operation.approved_with(), Some(approval));
        assert_eq!(
            operation.consume_approval(approval),
            Err(OperationError::ApprovalAlreadySpent)
        );
        assert_eq!(
            operation.consume_approval(Fingerprint::of(b"another approval")),
            Err(OperationError::ApprovalAlreadySpent)
        );

        // And past `awaiting_operator` no approval is accepted at all.
        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        assert_eq!(
            operation.consume_approval(Fingerprint::of(b"late")),
            Err(OperationError::NotAwaitingOperator)
        );
    }

    /// A failed operation carries no grant and no token: polling it forever is
    /// how a client never renews.
    #[test]
    fn a_failed_operation_carries_nothing() {
        let mut operation = operation(1, key(2));
        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        operation.fail();
        let view = operation.view(Some("read".into()), Some("submit".into()));
        assert_eq!(view.state, ClientRenewalOperationState::Failed);
        assert!(view.grant.is_none());
        assert!(view.signer_request_token.is_none());
    }
}
