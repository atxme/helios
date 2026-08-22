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
//! From there an operation reaches `pending_grant` once the approval has been
//! consumed.  That internal, non-activable state durably holds the exact
//! evidence and staging bytes while Astra obtains the gateway receipt.  Only
//! then does it reach `pending_commit`, where the grant is available to the
//! client, or `failed`.  Neither intermediate state is permission to activate.
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
//! # Persistence and retries
//!
//! The table is an atomically replaced private file. A restart discards only
//! capability tokens (their key is process-local); polling the same operation
//! mints fresh ones. The exact companion submission fingerprint is persisted
//! before issuance, an identical retry returns the same completed operation,
//! and different bytes under the same identifier conflict.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aether::certificates::{
    approval::{
        AstraCampaignApprovalEvidence, AstraCredentialApprovalRequest,
        AstraRenewalApprovalEvidence, DelegatedApproval,
    },
    client::{
        ClientCertificateRotationGrant, ClientCertificateRotationRequest,
        ClientCertificateStageAuthorization, GatewayCertificateStageReceipt,
    },
    encoding::{Fingerprint, Id16, WireGuardKey},
};
use helios_api::internal::{ClientRenewalOperationState, ClientRenewalOperationView};
use serde::{Deserialize, Serialize};

/// Largest number of operations held at once.
///
/// One per admitted peer is the shape of the traffic — a fleet renews over
/// weeks, not at once — and the map is bounded for the same reason the source
/// budget is: an unbounded one turns "open an operation" into a memory
/// exhaustion primitive against a service that has to stay up to finish the
/// rotations already in flight.
pub const MAX_LIVE_OPERATIONS: usize = 4_096;

/// Disk bound checked before parsing the operation journal.
pub const MAX_OPERATION_STORE_BYTES: u64 = 256 * 1024 * 1024;

const OPERATION_STORE_FORMAT_VERSION: u16 = 1;

/// Why an operation refused a transition.
///
/// Every variant is a refusal the caller may legitimately hit, and none of
/// them reaches a client unchanged: [`crate::service`] and the private router
/// map them to their coarse class before answering.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
    #[error("this operation already carries another staging authorization")]
    StageConflict,
    #[error("this operation already carries another grant")]
    GrantConflict,
    #[error(
        "this operation's approval has already been spent: one assertion opens one issuance, and \
         a second would renew twice under one touch"
    )]
    ApprovalAlreadySpent,
    #[error("this operation already accepted a different approval result")]
    ApprovalConflict,
    #[error("operation store input/output: {0}")]
    Persistence(String),
    #[error("operation store is inconsistent: {0}")]
    Corrupt(&'static str),
}

/// One renewal, from the threshold that prepared it to the grant that ends it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Fingerprint of the exact companion result accepted for this operation.
    /// An identical upload is idempotent; different bytes conflict.
    approved_with: Option<Fingerprint>,
    /// Fully verified and Astra-countersigned evidence. Persisted before any
    /// certificate is issued so a restart never asks for a second touch.
    approval_evidence: Option<Box<AstraRenewalApprovalEvidence>>,
    /// The other approval family of §7.2, when a manual campaign authorized
    /// this rotation instead of a per-peer ceremony.
    ///
    /// Additive and defaulted rather than folded into `approval_evidence` as
    /// an enum: this journal is on disk, a version bump refuses the whole file,
    /// and refusing it would abandon every renewal already past its operator
    /// touch. At most one of the two is ever set — `validate_persisted`
    /// refuses a record carrying both, and [`Operation::approval`] is the only
    /// way the rest of the code reads either.
    #[serde(default)]
    campaign_evidence: Option<Box<AstraCampaignApprovalEvidence>>,
    /// Identifier of the staging sent to the gateway, once one was.
    stage_id: Option<Id16>,
    /// Exact authorization replayed after a cut; random leaf material is never
    /// regenerated under the same operation.
    stage_authorization: Option<Box<ClientCertificateStageAuthorization>>,
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
            approval_evidence: None,
            campaign_evidence: None,
            stage_id: None,
            stage_authorization: None,
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

    fn validate_persisted(&self) -> Result<(), OperationError> {
        if self.client_wg_public_key != self.request.client_wg_public_key
            || self.request_fingerprint != self.request.fingerprint()
            || self.operation_id != self.approval_request.operation_id
            || self.request_fingerprint != self.approval_request.request_fingerprint
            || self.expires_at != self.request.expires_at
            || self.created_at >= self.expires_at
        {
            return Err(OperationError::Corrupt("identity or request binding"));
        }
        // One approval, one rotation. A record carrying both families would
        // leave "which one authorized this" to whoever read it first.
        if self.approval_evidence.is_some() && self.campaign_evidence.is_some() {
            return Err(OperationError::Corrupt("two approval families"));
        }
        if let Some(evidence) = &self.approval_evidence {
            if evidence.approval_request != *self.approval_request
                || evidence.approval.operation_id != self.operation_id
                || !evidence
                    .approval
                    .request_fingerprint
                    .matches(&self.request_fingerprint)
            {
                return Err(OperationError::Corrupt("approval evidence binding"));
            }
        }
        if let Some(evidence) = &self.campaign_evidence {
            // The campaign binds to the target's state, not to this request,
            // so what has to hold on reload is that it still covers the peer
            // and generation this operation is about.
            if evidence
                .campaign
                .covers_client(
                    &self.client_wg_public_key,
                    self.request.active_generation,
                    &self.request.active_tls_certificate_fingerprint,
                    &self.request.active_pq_certificate_fingerprint,
                )
                .is_err()
            {
                return Err(OperationError::Corrupt("campaign evidence binding"));
            }
        }
        if let Some(authorization) = &self.stage_authorization {
            if self.stage_id != Some(authorization.stage_id)
                || authorization.client_wg_public_key != self.client_wg_public_key
                || !authorization
                    .request_fingerprint
                    .matches(&self.request_fingerprint)
                || authorization.renewal_approval.as_ref() != self.approval_evidence.as_deref()
                || authorization.campaign_approval.as_deref() != self.campaign_evidence.as_deref()
            {
                return Err(OperationError::Corrupt("stage authorization binding"));
            }
        }
        if let Some(receipt) = &self.receipt {
            let authorization = self
                .stage_authorization
                .as_ref()
                .ok_or(OperationError::Corrupt("receipt without authorization"))?;
            let authorization_fingerprint = authorization
                .fingerprint()
                .map_err(|_| OperationError::Corrupt("invalid authorization"))?;
            if receipt.stage_id != authorization.stage_id
                || !receipt
                    .stage_authorization_fingerprint
                    .matches(&authorization_fingerprint)
                || !receipt
                    .request_fingerprint
                    .matches(&authorization.request_fingerprint)
                || !receipt
                    .operator_approval_fingerprint
                    .matches(&authorization.operator_approval_fingerprint)
                || receipt.client_wg_public_key != self.client_wg_public_key
                || receipt.staged_generation != authorization.next_generation
            {
                return Err(OperationError::Corrupt("receipt binding"));
            }
        }
        if let Some(grant) = &self.grant {
            let authorization = self
                .stage_authorization
                .as_ref()
                .ok_or(OperationError::Corrupt("grant without authorization"))?;
            let receipt = self
                .receipt
                .as_ref()
                .ok_or(OperationError::Corrupt("grant without receipt"))?;
            if grant.stage_receipt != **receipt
                || !grant
                    .request_fingerprint
                    .matches(&authorization.request_fingerprint)
                || !grant
                    .operator_approval_fingerprint
                    .matches(&authorization.operator_approval_fingerprint)
                || grant.client_wg_public_key != self.client_wg_public_key
                || grant.active_generation != authorization.active_generation
                || grant.next_generation != authorization.next_generation
                || grant.stage_expires_at != authorization.stage_expires_at
                || grant.renewal_approval.as_ref() != self.approval_evidence.as_deref()
                || grant.campaign_approval.as_deref() != self.campaign_evidence.as_deref()
            {
                return Err(OperationError::Corrupt("grant binding"));
            }
        }
        match self.state {
            ClientRenewalOperationState::AwaitingOperator
                if self.approved_with.is_some()
                    || self.approval_evidence.is_some()
                    || self.stage_id.is_some()
                    || self.stage_authorization.is_some()
                    || self.receipt.is_some()
                    || self.grant.is_some() =>
            {
                Err(OperationError::Corrupt(
                    "awaiting operation carries approval state",
                ))
            }
            ClientRenewalOperationState::PendingGrant
                if self.approved_with.is_none()
                    || self.approval_evidence.is_none()
                    || self.grant.is_some() =>
            {
                Err(OperationError::Corrupt(
                    "incomplete pending-grant operation",
                ))
            }
            ClientRenewalOperationState::PendingCommit
                if self.approved_with.is_none()
                    || self.approval_evidence.is_none()
                    || self.stage_id.is_none()
                    || self.stage_authorization.is_none()
                    || self.receipt.is_none()
                    || self.grant.is_none() =>
            {
                Err(OperationError::Corrupt(
                    "incomplete pending-commit operation",
                ))
            }
            ClientRenewalOperationState::Failed if self.grant.is_some() => {
                Err(OperationError::Corrupt("failed operation carries a grant"))
            }
            _ => Ok(()),
        }
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
        evidence: Box<AstraRenewalApprovalEvidence>,
    ) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::AwaitingOperator {
            return Err(OperationError::NotAwaitingOperator);
        }
        if self.approved_with.is_some() {
            return Err(OperationError::ApprovalAlreadySpent);
        }
        if evidence.approval_request != *self.approval_request
            || evidence.approval.operation_id != self.operation_id
            || !evidence
                .approval
                .request_fingerprint
                .matches(&self.request_fingerprint)
        {
            return Err(OperationError::Corrupt("approval evidence binding"));
        }
        self.approved_with = Some(approval_fingerprint);
        self.approval_evidence = Some(evidence);
        self.state = ClientRenewalOperationState::PendingGrant;
        Ok(())
    }

    /// The approval this operation was opened by, once one was spent.
    pub fn approved_with(&self) -> Option<Fingerprint> {
        self.approved_with
    }

    pub fn approval_evidence(&self) -> Option<&AstraRenewalApprovalEvidence> {
        self.approval_evidence.as_deref()
    }

    /// The operator authorization this rotation stands on, whichever family.
    ///
    /// The single reader of the two fields. Returning
    /// [`DelegatedApproval`] rather than either half is what keeps the reason
    /// derived from the evidence all the way to the issuer: nothing between
    /// here and `authorize_stage` gets to name a reason of its own.
    pub fn approval(&self) -> Option<DelegatedApproval> {
        match (&self.approval_evidence, &self.campaign_evidence) {
            (Some(renewal), None) => Some(DelegatedApproval::Renewal(renewal.clone())),
            (None, Some(campaign)) => Some(DelegatedApproval::Campaign(campaign.clone())),
            // Both, or neither. `validate_persisted` refuses the first on
            // reload and `consume_*` never creates it; treating it as "no
            // approval" here is the refusal that costs nothing.
            _ => None,
        }
    }

    /// Records a campaign that already authorized this target (spec §7.6).
    ///
    /// No operator is asked anything: the touch happened once, for a set of
    /// targets, before this request existed. The operation therefore skips
    /// `awaiting_operator` — the state exists to hold a request while a human
    /// is asked, and here nobody is.
    ///
    /// The campaign is still required to cover *this* peer at *this* state,
    /// here as well as at the gateway: this is the point where a lookup could
    /// hand over a campaign that has drifted from the request it is about to
    /// authorize.
    pub fn consume_campaign_approval(
        &mut self,
        approval_fingerprint: Fingerprint,
        evidence: Box<AstraCampaignApprovalEvidence>,
    ) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::AwaitingOperator {
            return Err(OperationError::NotAwaitingOperator);
        }
        if self.approved_with.is_some() {
            return Err(OperationError::ApprovalAlreadySpent);
        }
        if evidence
            .campaign
            .covers_client(
                &self.client_wg_public_key,
                self.request.active_generation,
                &self.request.active_tls_certificate_fingerprint,
                &self.request.active_pq_certificate_fingerprint,
            )
            .is_err()
        {
            return Err(OperationError::Corrupt("campaign evidence binding"));
        }
        self.approved_with = Some(approval_fingerprint);
        self.campaign_evidence = Some(evidence);
        self.state = ClientRenewalOperationState::PendingGrant;
        Ok(())
    }

    /// Whether this is the result that already completed the operation.
    pub fn is_idempotent_submission(
        &self,
        submission_fingerprint: &Fingerprint,
    ) -> Result<bool, OperationError> {
        match self.approved_with {
            None => Ok(false),
            Some(previous) if previous.matches(submission_fingerprint) => Ok(true),
            Some(previous) if !previous.matches(submission_fingerprint) => {
                Err(OperationError::ApprovalConflict)
            }
            Some(_) => Err(OperationError::NotAwaitingOperator),
        }
    }

    /// Records which staging was sent to the gateway.
    pub fn record_stage(
        &mut self,
        authorization: Box<ClientCertificateStageAuthorization>,
    ) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::PendingGrant {
            return Err(OperationError::NotAwaitingOperator);
        }
        if let Some(existing) = &self.stage_authorization {
            if matches!(
                (existing.fingerprint(), authorization.fingerprint()),
                (Ok(left), Ok(right)) if left.matches(&right)
            ) {
                return Ok(());
            }
            return Err(OperationError::StageConflict);
        }
        self.stage_id = Some(authorization.stage_id);
        self.stage_authorization = Some(authorization);
        Ok(())
    }

    pub fn stage_id(&self) -> Option<Id16> {
        self.stage_id
    }

    pub fn stage_authorization(&self) -> Option<&ClientCertificateStageAuthorization> {
        self.stage_authorization.as_deref()
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
        if let Some(existing) = &self.grant {
            if matches!(
                (existing.fingerprint(), grant.fingerprint()),
                (Ok(left), Ok(right)) if left.matches(&right)
            ) {
                return Ok(());
            }
            return Err(OperationError::GrantConflict);
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedOperations {
    format_version: u16,
    operations: Vec<Operation>,
}

#[derive(Debug, Default)]
pub struct OperationStore {
    operations: BTreeMap<[u8; 16], Operation>,
    by_peer: BTreeMap<[u8; 32], [u8; 16]>,
    path: Option<PathBuf>,
}

impl OperationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads the durable operation journal, or creates an empty one.
    ///
    /// Capability tokens are intentionally absent: their process-lifetime key
    /// is redrawn at restart, and polling the surviving operation mints fresh
    /// tokens as §8.2 requires.
    pub fn load(path: &Path, now_unix: u64) -> Result<Self, OperationError> {
        let bytes = match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.len() > MAX_OPERATION_STORE_BYTES {
                    return Err(OperationError::Corrupt("file too large"));
                }
                std::fs::read(path)
                    .map_err(|error| OperationError::Persistence(error.to_string()))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let store = Self {
                    path: Some(path.to_path_buf()),
                    ..Self::default()
                };
                store.persist()?;
                return Ok(store);
            }
            Err(error) => return Err(OperationError::Persistence(error.to_string())),
        };
        let persisted: PersistedOperations =
            serde_json::from_slice(&bytes).map_err(|_| OperationError::Corrupt("invalid JSON"))?;
        if persisted.format_version != OPERATION_STORE_FORMAT_VERSION {
            return Err(OperationError::Corrupt("unsupported format version"));
        }
        if persisted.operations.len() > MAX_LIVE_OPERATIONS {
            return Err(OperationError::Corrupt("too many operations"));
        }
        let mut store = Self {
            path: Some(path.to_path_buf()),
            ..Self::default()
        };
        for operation in persisted.operations {
            operation.validate_persisted()?;
            if operation.is_expired(now_unix) {
                continue;
            }
            store.open(operation, now_unix)?;
        }
        // Also removes expired entries from the on-disk representation.
        store.persist()?;
        Ok(store)
    }

    /// Atomically publishes the complete operation journal.
    pub fn persist(&self) -> Result<(), OperationError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = PersistedOperations {
            format_version: OPERATION_STORE_FORMAT_VERSION,
            operations: self.operations.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&persisted)
            .map_err(|_| OperationError::Corrupt("cannot encode operation"))?;
        if bytes.len() as u64 > MAX_OPERATION_STORE_BYTES {
            return Err(OperationError::Corrupt("file too large"));
        }
        aether::private_file::write_private_atomic(path, &bytes)
            .map_err(|error| OperationError::Persistence(error.to_string()))
    }

    /// Removes an operation whose surrounding durable transaction failed.
    pub fn remove(&mut self, operation_id: &Id16) {
        if let Some(operation) = self.operations.remove(operation_id.as_bytes()) {
            self.by_peer
                .remove(operation.client_wg_public_key.as_bytes());
        }
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

    /// Whether this peer has a live renewal that no operator has answered.
    ///
    /// It answers the one question the registry cannot: §8.2 separates
    /// `awaiting_operator` — an operation is open and no candidate exists —
    /// from `pending_grant`, which describes a candidate the registry already
    /// records. Only the operation store knows the first.
    ///
    /// `AwaitingOperator` and nothing else: past that state the operation has
    /// produced a staging, and the registry's own record is what decides.
    pub fn awaits_operator(&self, peer: &WireGuardKey, now_unix: u64) -> bool {
        self.operations.values().any(|operation| {
            operation.client_wg_public_key == *peer
                && !operation.is_expired(now_unix)
                && operation.state == ClientRenewalOperationState::AwaitingOperator
        })
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
        approval::{
            AstraCredentialBinding, AstraRenewalApproval, CredentialState,
            MAX_APPROVAL_LIFETIME_SECS,
        },
        encoding::{DerCertificate, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId},
        webauthn::WebAuthnAssertion,
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
        let operation_id = Id16::new([seed; 16]).expect("id");
        let request = request(client);
        let mut approval_request = approval_request(client);
        approval_request.operation_id = operation_id;
        approval_request.request_fingerprint = request.fingerprint();
        Operation::awaiting_operator(operation_id, client, request, approval_request, 1_000)
    }

    fn campaign_evidence(
        client: WireGuardKey,
        generation: u64,
    ) -> Box<AstraCampaignApprovalEvidence> {
        use aether::certificates::approval::CredentialRegistry;
        use aether::certificates::status::{
            AstraRotationCampaign, CampaignApproval, CampaignScope, CampaignTarget, CertificateKind,
        };
        let campaign = AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: key(9),
            server_name: "gateway.example".into(),
            created_at: 1_000,
            expires_at: 1_300,
            scope: CampaignScope::FleetLeafs,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientPq,
                identity_key: client,
                epoch: 1,
                generation,
                active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            }],
            reason: "rotation".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: 1,
        };
        let approval = CampaignApproval {
            campaign_id: campaign.campaign_id,
            campaign_fingerprint: campaign.fingerprint(),
            required_credentials: 1,
            approved_at: 1_050,
            approvals: Vec::new(),
        };
        Box::new(AstraCampaignApprovalEvidence {
            campaign,
            approval,
            credential_registry: CredentialRegistry {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: key(9),
                ca_epoch: 1,
                credential_registry_epoch: 1,
                bindings: Vec::new(),
            },
            webauthn_origin: "https://astra.example".into(),
        })
    }

    fn evidence(operation: &Operation) -> Box<AstraRenewalApprovalEvidence> {
        let request = operation.approval_request.clone();
        let binding = AstraCredentialBinding {
            format_version: CERTIFICATE_FORMAT_VERSION,
            credential_id: vec![1, 2, 3],
            credential_public_key: vec![0xa5, 0x01],
            aaguid: [0; 16],
            trust_domain_id: request.trust_domain_id,
            gateway_wg_public_key: request.gateway_wg_public_key,
            state: CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: 1_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        };
        let assertion = WebAuthnAssertion {
            authenticator_data: vec![1],
            client_data_json: vec![2],
            signature: vec![3],
        };
        Box::new(AstraRenewalApprovalEvidence {
            approval_request: (*request).clone(),
            approval: AstraRenewalApproval {
                format_version: CERTIFICATE_FORMAT_VERSION,
                operation_id: request.operation_id,
                request_fingerprint: request.request_fingerprint,
                approval_request_fingerprint: request.fingerprint(),
                credential_fingerprint: binding.fingerprint(),
                credential_binding: binding,
                assertion_fingerprint: assertion.fingerprint(),
                webauthn_assertion: assertion,
                approved_at: 1_001,
                expires_at: 1_200,
                astra_service_key_epoch: 1,
                astra_signature: MlDsa87Signature::placeholder(),
            },
        })
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
            campaign_approval: None,
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

    #[test]
    fn an_operation_survives_restart_but_an_expired_one_does_not() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("operations.json");
        let id = Id16::new([1; 16]).expect("id");
        let mut store = OperationStore::load(&path, 1_000).expect("new store");
        store.open(operation(1, key(2)), 1_000).expect("open");
        store.persist().expect("persist");

        let restarted = OperationStore::load(&path, 1_001).expect("restart");
        restarted.get(&id, &key(2), 1_001).expect("survives");

        let expired = OperationStore::load(&path, 5_000).expect("purges expired");
        assert!(expired.is_empty());
        assert!(matches!(
            expired.get(&id, &key(2), 5_000),
            Err(OperationError::Unknown)
        ));
    }

    #[test]
    fn an_approved_operation_resumes_without_a_second_touch() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("operations.json");
        let id = Id16::new([1; 16]).expect("id");
        let mut operation = operation(1, key(2));
        let approval = Fingerprint::of(b"an approval");
        let accepted_evidence = evidence(&operation);
        operation
            .consume_approval(approval, accepted_evidence)
            .expect("approval");

        let mut store = OperationStore::load(&path, 1_000).expect("new store");
        store.open(operation, 1_000).expect("open");
        store.persist().expect("persist");

        let restarted = OperationStore::load(&path, 1_001).expect("restart");
        let resumed = restarted.get(&id, &key(2), 1_001).expect("operation");
        assert_eq!(resumed.state, ClientRenewalOperationState::PendingGrant);
        assert_eq!(resumed.approved_with(), Some(approval));
        assert!(resumed.approval_evidence().is_some());
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
        let accepted_evidence = evidence(&operation);
        operation
            .consume_approval(approval, accepted_evidence)
            .expect("first");
        assert_eq!(operation.approved_with(), Some(approval));
        let replayed_evidence = evidence(&operation);
        assert_eq!(
            operation.consume_approval(approval, replayed_evidence),
            Err(OperationError::NotAwaitingOperator)
        );
        let conflicting_evidence = evidence(&operation);
        assert_eq!(
            operation.consume_approval(Fingerprint::of(b"another approval"), conflicting_evidence),
            Err(OperationError::NotAwaitingOperator)
        );

        // And past `awaiting_operator` no approval is accepted at all.
        operation.record_receipt(receipt()).expect("receipt");
        operation.record_grant(grant()).expect("grant");
        let late_evidence = evidence(&operation);
        assert_eq!(
            operation.consume_approval(Fingerprint::of(b"late"), late_evidence),
            Err(OperationError::NotAwaitingOperator)
        );
    }

    #[test]
    fn an_accepted_submission_is_idempotent_only_for_identical_bytes() {
        let mut operation = operation(1, key(2));
        let submitted = Fingerprint::of(b"companion result");
        let accepted_evidence = evidence(&operation);
        operation
            .consume_approval(submitted, accepted_evidence)
            .expect("first submission");

        assert!(operation
            .is_idempotent_submission(&submitted)
            .expect("same result"));
        assert_eq!(
            operation.is_idempotent_submission(&Fingerprint::of(b"different result")),
            Err(OperationError::ApprovalConflict)
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

    /// A campaign approved before this request existed: nobody is asked
    /// anything, so the operation never rests in `awaiting_operator`.
    #[test]
    fn a_covering_campaign_opens_an_operation_that_asks_no_one() {
        let client = key(1);
        let mut operation = operation(2, client);
        let evidence = campaign_evidence(client, 4);
        operation
            .consume_campaign_approval(Fingerprint::of(b"campaign"), evidence)
            .expect("covered");

        assert_eq!(operation.state, ClientRenewalOperationState::PendingGrant);
        assert!(matches!(
            operation.approval(),
            Some(DelegatedApproval::Campaign(_))
        ));
        // The reason travels with the family, all the way to the issuer.
        assert_eq!(
            operation.approval().expect("approval").reason(),
            aether::certificates::authority::RotationReason::ManualGlobal
        );
    }

    /// The lookup is not the last word: the campaign has to cover the request
    /// this operation actually carries.
    #[test]
    fn a_campaign_describing_another_generation_authorizes_nothing_here() {
        let client = key(1);
        let mut operation = operation(2, client);
        // The request is generation 4 -> 5; this campaign was approved for 3.
        let evidence = campaign_evidence(client, 3);
        assert!(matches!(
            operation.consume_campaign_approval(Fingerprint::of(b"campaign"), evidence),
            Err(OperationError::Corrupt("campaign evidence binding"))
        ));
        assert_eq!(
            operation.state,
            ClientRenewalOperationState::AwaitingOperator
        );
    }

    /// One approval, one issuance — whichever family it came from.
    #[test]
    fn a_campaign_approval_is_spent_once() {
        let client = key(1);
        let mut operation = operation(2, client);
        operation
            .consume_campaign_approval(Fingerprint::of(b"campaign"), campaign_evidence(client, 4))
            .expect("covered");
        assert!(matches!(
            operation.consume_campaign_approval(
                Fingerprint::of(b"campaign"),
                campaign_evidence(client, 4)
            ),
            Err(OperationError::NotAwaitingOperator)
        ));
        // And the ordinary ceremony cannot approve it a second time either.
        let ordinary = evidence(&operation);
        assert!(matches!(
            operation.consume_approval(Fingerprint::of(b"other"), ordinary),
            Err(OperationError::NotAwaitingOperator)
        ));
    }

    /// A record carrying both families leaves «which one authorized this» to
    /// whoever reads it first. It is refused on reload, and read as nothing.
    #[test]
    fn a_record_carrying_two_approval_families_is_refused() {
        let client = key(1);
        let mut operation = operation(2, client);
        operation
            .consume_campaign_approval(Fingerprint::of(b"campaign"), campaign_evidence(client, 4))
            .expect("covered");
        // Only a corrupted journal can reach this shape; construct it here so
        // the refusal is exercised rather than assumed.
        operation.approval_evidence = Some(evidence(&operation));

        assert!(operation.approval().is_none());
        assert!(matches!(
            operation.validate_persisted(),
            Err(OperationError::Corrupt("two approval families"))
        ));
    }
}
