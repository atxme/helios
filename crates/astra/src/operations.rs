//! Renewal journal for automatic decisions, campaigns and legacy companions.
//!
//! Current scheduled requests are authorized automatically under the pinned
//! policy. Manual campaigns carry their own earlier approval. The constructor
//! starts at `AwaitingOperator`, but these two paths leave that state before
//! their first durable write; per-request operator records remain loadable for
//! operations created by an older Astra, without restoring their obsolete
//! permission to stage a scheduled renewal.
//!
//! `PendingGrant` durably holds the exact evidence and random issuance bytes
//! while Astra obtains the gateway receipt. Only `PendingCommit` releases a
//! grant. Neither state activates a candidate on the data plane.
//!
//! The incoming companion submission fingerprint is the idempotency key.
//! Astra's countersigned evidence has a different fingerprint, used by the
//! stage authorization. Reload must check the right binding for each role.
//! Capability keys are process-local; polling mints new tokens for the stored
//! approval-request manifest after restart.
//!
//! Updates prepare one public operation and restore memory on persistence
//! failure. The atomic writer can fail during directory sync after rename:
//! in that case disk may already contain the new complete record while memory
//! remains at the previous record. No successful response is released on that
//! error; retry or restart must use a structurally valid journal. Tests that
//! obstruct publication cover pre-rename failures; post-rename sync faults
//! require a filesystem fault harness to validate power-loss durability.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aether::certificates::transport::{ClientRenewalOperationState, ClientRenewalOperationView};
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

    /// Authorizes a due ordinary renewal from the pinned delegated policy.
    ///
    /// The active client's signed request is the authorization boundary: it
    /// proves continuity, proves possession of the candidate key, names only
    /// `active + 1`, and has already passed the 80 % gate. Persisting its
    /// fingerprint before issuance gives retries the same one-shot property
    /// that operator evidence provides to manual campaigns.
    pub fn authorize_automatic(&mut self) -> Result<(), OperationError> {
        if self.state != ClientRenewalOperationState::AwaitingOperator {
            return Err(OperationError::NotAwaitingOperator);
        }
        if self.approved_with.is_some() {
            return Err(OperationError::ApprovalAlreadySpent);
        }
        self.approved_with = Some(self.request_fingerprint);
        self.state = ClientRenewalOperationState::PendingGrant;
        Ok(())
    }

    fn is_automatic(&self) -> bool {
        self.approval_evidence.is_none()
            && self.campaign_evidence.is_none()
            && self
                .approved_with
                .is_some_and(|fingerprint| fingerprint.matches(&self.request_fingerprint))
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
            // The received submission remains the idempotency key, while the
            // issuer binds the stage to the countersigned evidence. Automatic
            // and campaign records retain their original fingerprint rule.
            let authorization_fingerprint = self
                .approval_evidence
                .as_ref()
                .map(|evidence| evidence.fingerprint())
                .or(self.approved_with);
            if self.stage_id != Some(authorization.stage_id)
                || authorization.client_wg_public_key != self.client_wg_public_key
                || !authorization
                    .request_fingerprint
                    .matches(&self.request_fingerprint)
                || authorization.renewal_approval.as_ref() != self.approval_evidence.as_deref()
                || authorization.campaign_approval.as_deref() != self.campaign_evidence.as_deref()
                || !authorization_fingerprint.is_some_and(|fingerprint| {
                    fingerprint.matches(&authorization.renewal_authorization_fingerprint)
                })
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
                    .renewal_authorization_fingerprint
                    .matches(&authorization.renewal_authorization_fingerprint)
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
                    .renewal_authorization_fingerprint
                    .matches(&authorization.renewal_authorization_fingerprint)
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
                    || (self.approval_evidence.is_none()
                        && self.campaign_evidence.is_none()
                        && !self.is_automatic())
                    || self.grant.is_some() =>
            {
                Err(OperationError::Corrupt(
                    "incomplete pending-grant operation",
                ))
            }
            ClientRenewalOperationState::PendingCommit
                if self.approved_with.is_none()
                    || (self.approval_evidence.is_none()
                        && self.campaign_evidence.is_none()
                        && !self.is_automatic())
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
            (None, None) if self.is_automatic() => {
                Some(DelegatedApproval::Automatic(self.request_fingerprint))
            }
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

    /// Publishes one structurally valid update under the caller's store lock.
    ///
    /// The synchronous closure only touches a candidate. No operation, token,
    /// or external effect is released between replacement and persistence.
    /// On an error memory retains the previous operation; a post-rename sync
    /// error can still leave the complete candidate file on disk.
    pub(crate) fn update_persisted(
        &mut self,
        operation_id: &Id16,
        caller: &WireGuardKey,
        now_unix: u64,
        update: impl FnOnce(&mut Operation) -> Result<(), OperationError>,
    ) -> Result<(), OperationError> {
        let mut candidate = self.get(operation_id, caller, now_unix)?.clone();
        let request_fingerprint = candidate.request_fingerprint;
        update(&mut candidate)?;
        candidate.validate_persisted()?;
        if candidate.operation_id != *operation_id
            || candidate.client_wg_public_key != *caller
            || candidate.request_fingerprint != request_fingerprint
        {
            return Err(OperationError::Corrupt("operation update changed identity"));
        }
        let previous = std::mem::replace(self.get_mut(operation_id, caller, now_unix)?, candidate);
        if let Err(error) = self.persist() {
            *self.get_mut(operation_id, caller, now_unix)? = previous;
            return Err(error);
        }
        Ok(())
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
mod tests;
