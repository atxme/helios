//! Operator signing operations, out of tunnel — spec §7.6 and §8.2.
//!
//! # What this is, and what it deliberately is not
//!
//! [`crate::operations`] holds the *client* renewals: one peer, one rotation
//! request, a staging and a grant, all of it reached through the gateway's
//! tunnel because the source VIP is what proves the caller. This module holds
//! the other half — a manual campaign approved by an operator who has no
//! tunnel, on a workstation, through the public HTTPS origin.
//!
//! They are separate stores rather than one enum, and that separation carries
//! a rule of §8.2 for free: «un `operation_id` de renouvellement ordinaire y
//! reçoit le même refus grossier qu'un identifiant inconnu». The public
//! companion routes look only here, so an ordinary renewal identifier is
//! simply absent — not filtered out by a comparison somebody could forget to
//! write.
//!
//! # Why nothing here is persisted
//!
//! Same reason the client operations are not: an operation holds no
//! certificate, and the campaign inside it carries a five-minute window
//! (§7.6). Persisting one would outlive the window it exists to bound, and a
//! restart would resurrect a challenge an operator answered — or worse, one
//! they declined to. A restart loses nothing but a ceremony that has to be
//! restarted anyway.
//!
//! # What the operator's touch authorizes
//!
//! Exactly the campaign whose fingerprint was displayed. That fingerprint
//! covers every target, its epoch, its generation, its current fingerprints
//! **and their order**, so an approval cannot be replayed against the same set
//! applied differently, and a target that moved in the meantime is refused
//! rather than silently recomputed.

use std::collections::BTreeMap;

use aether::certificates::{
    approval::CredentialRegistry,
    encoding::{Fingerprint, Id16, WireGuardKey},
    status::{
        AstraRotationCampaign, AstraSignerRequest, AstraSignerResult, CampaignFamily,
        CampaignScope, CampaignTarget,
    },
    transport::TrustUpdateObject,
    CertificateError,
};

/// Largest number of operator operations alive at once.
///
/// A ceiling rather than an unbounded map: each one is opened by a local
/// operator command, so more than a handful in flight means something is
/// looping, and growing memory on that is how a bound stops being one.
pub const MAX_LIVE_SIGNING_OPERATIONS: usize = 64;

/// How much of a campaign's free text the pending list carries.
const PENDING_TEXT_CHARS: usize = 128;

/// The first [`PENDING_TEXT_CHARS`] characters, with an ellipsis if cut.
///
/// Cut on `char` boundaries, never bytes: the text is operator-written and
/// may be multi-byte.
fn shorten(text: &str) -> String {
    match text.char_indices().nth(PENDING_TEXT_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("no such operator operation")]
    Unknown,
    #[error("this operator operation has expired")]
    Expired,
    #[error("too many operator operations are already in flight")]
    Full,
    #[error("this operation already accepted a different operator result")]
    Conflict,
    #[error(
        "this operation's approval has already been spent: one campaign is approved once, and a \
         second result would apply it twice"
    )]
    AlreadyApproved,
    #[error("operator approval refused: {0}")]
    Approval(#[from] CertificateError),
}

/// The two shapes an operator operation is read as, defined in `aether`.
///
/// They live there rather than here because the in-tunnel operator relay of
/// spec §8.5 has to name them, and `helios-api` cannot depend on this crate —
/// this crate depends on it. Same reason
/// [`aether::certificates::transport::ClientRenewalOperationView`] is there.
pub use aether::certificates::transport::{SigningOperationState, SigningOperationView};

/// One manual campaign, from the command that opened it to its approval.
#[derive(Debug, Clone)]
pub struct SigningOperation {
    pub operation_id: Id16,
    /// The frozen campaign. Its fingerprint is the WebAuthn challenge and the
    /// manifest every capability token for this operation is bound to.
    pub campaign: Box<AstraRotationCampaign>,
    /// What the companion fetches and verifies under the pinned service key.
    pub signer_request: Box<AstraSignerRequest>,
    pub state: SigningOperationState,
    pub created_at: u64,
    pub expires_at: u64,
    /// The exact result accepted, by fingerprint. An identical upload is
    /// idempotent; different bytes under the same identifier are a conflict.
    accepted: Option<Fingerprint>,
    approval: Option<Box<aether::certificates::status::CampaignApproval>>,
}

impl SigningOperation {
    /// Opens an operation around a campaign and the request that names it.
    ///
    /// The two are checked against each other here rather than trusted: the
    /// request's `campaign_fingerprint` is what the companion binds its
    /// assertion to, and a request naming another campaign would have an
    /// operator approve one text while another was applied.
    pub fn new(
        campaign: Box<AstraRotationCampaign>,
        signer_request: Box<AstraSignerRequest>,
        now_unix: u64,
    ) -> Result<Self, SigningError> {
        campaign.validate(now_unix)?;
        if signer_request.operation_id == campaign.campaign_id {
            // Not a security property, a diagnosis: the two identifiers are
            // drawn separately and colliding means one was copied from the
            // other, which is the bug that makes a replay look legitimate.
            return Err(SigningError::Approval(CertificateError::CampaignMismatch));
        }
        campaign.assert_unchanged(&signer_request.campaign_fingerprint)?;
        if signer_request.required_credentials != campaign.required_credentials {
            return Err(SigningError::Approval(
                CertificateError::InsufficientApprovals {
                    required: campaign.required_credentials,
                    provided: signer_request.required_credentials,
                },
            ));
        }
        // The operation cannot outlive the campaign it carries: past that
        // instant the approval would be answering a text nobody may still act
        // on.
        let expires_at = signer_request.expires_at.min(campaign.expires_at);
        if expires_at <= now_unix {
            return Err(SigningError::Expired);
        }
        Ok(Self {
            operation_id: signer_request.operation_id,
            campaign,
            signer_request,
            state: SigningOperationState::AwaitingOperator,
            created_at: now_unix,
            expires_at,
            accepted: None,
            approval: None,
        })
    }

    /// The manifest the capability tokens of §8.2 are bound to.
    ///
    /// The campaign fingerprint, which is also the challenge the operator's
    /// key answers. A token therefore stops authorizing anything the moment
    /// the campaign it was minted for changes — which is the correct outcome:
    /// it authorized a fetch of a text that no longer describes what will be
    /// asked.
    pub fn manifest_fingerprint(&self) -> Fingerprint {
        self.campaign.fingerprint()
    }

    /// The encrypted vault this operation may read, if its scope needs one.
    ///
    /// Only a scope that makes a master key sign — an anchor rotation or an
    /// emergency revocation — has the companion open the vault. Returning
    /// `None` otherwise is what stops an ordinary campaign's token from being
    /// a vault-download token.
    pub fn vault_fingerprint(&self) -> Option<Fingerprint> {
        self.campaign
            .scope
            .opens_vault()
            .then_some(self.signer_request.encrypted_vault_fingerprint)
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    pub fn approval(&self) -> Option<&aether::certificates::status::CampaignApproval> {
        self.approval.as_deref()
    }

    /// Whether this exact result has already been accepted (spec §8.2).
    fn is_idempotent(&self, submitted: &Fingerprint) -> Result<bool, SigningError> {
        match &self.accepted {
            Some(accepted) if accepted.matches(submitted) => Ok(true),
            Some(_) => Err(SigningError::Conflict),
            None => Ok(false),
        }
    }

    /// Marks the operation approved without a ceremony.
    ///
    /// Test-only, and deliberately not a shortcut anything else can take: the
    /// real path is [`SigningOperationStore::submit`], which re-derives the
    /// challenge and resolves every credential against the `CA-PQ`-signed
    /// registry. Verifying an assertion here would need a WebAuthn credential
    /// fixture that lives inside `aether`.
    #[cfg(test)]
    pub(crate) fn approve_without_ceremony(&mut self) {
        self.accepted = Some(Fingerprint::of(b"test approval"));
        self.state = SigningOperationState::Approved;
    }

    /// Records a verified approval, once.
    fn accept(
        &mut self,
        submitted: Fingerprint,
        approval: Box<aether::certificates::status::CampaignApproval>,
    ) {
        self.accepted = Some(submitted);
        self.approval = Some(approval);
        self.state = SigningOperationState::Approved;
    }
}

/// Every operator operation this process holds.
#[derive(Debug, Default)]
pub struct SigningOperationStore {
    operations: BTreeMap<[u8; 16], SigningOperation>,
}

impl SigningOperationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Everything still waiting for an operator, oldest first.
    ///
    /// Expired entries are skipped rather than returned and filtered later: an
    /// operation whose window closed is not «pending», it is over, and offering
    /// it would send an operator to a ceremony that refuses at the first step.
    ///
    /// Carries no capability token. Tokens are minted for the caller about to
    /// act on the operation they named; a list that carried them would hand
    /// every reader a credential for every operation on it.
    ///
    /// `reason` and `requested_by` are cut at [`PENDING_TEXT_CHARS`]: the list
    /// only tells operations apart, and the full text is read on the one the
    /// operator opens. Without the cut, [`MAX_LIVE_SIGNING_OPERATIONS`] entries
    /// of the longest accepted text would outgrow the answer bound the client
    /// enforces.
    pub fn pending(
        &self,
        now_unix: u64,
    ) -> Vec<aether::certificates::transport::OperatorPendingOperation> {
        let mut pending: Vec<_> = self
            .operations
            .values()
            .filter(|operation| {
                !operation.is_expired(now_unix)
                    && operation.state
                        == aether::certificates::transport::SigningOperationState::AwaitingOperator
            })
            .map(
                |operation| aether::certificates::transport::OperatorPendingOperation {
                    operation_id: operation.operation_id,
                    scope: operation.campaign.scope,
                    reason: shorten(&operation.campaign.reason),
                    requested_by: shorten(&operation.campaign.requested_by),
                    target_count: operation.campaign.targets.len(),
                    required_credentials: operation.campaign.required_credentials,
                    campaign_fingerprint: operation.campaign.fingerprint(),
                    created_at: operation.created_at,
                    expires_at: operation.expires_at,
                },
            )
            .collect();
        // Oldest first: the one closest to its deadline is the one an operator
        // has least time to reach.
        pending.sort_by_key(|operation| operation.expires_at);
        pending
    }

    /// The live operation a new opening over these targets would duplicate.
    ///
    /// «Live» is what [`Self::pending`] lists: waiting for its operator and
    /// not expired. A ceremony that failed or finished does not block the
    /// next attempt, and one whose window closed is over.
    ///
    /// One per [`CampaignFamily`], so a chain step and an isolated
    /// `fleet_leafs` campaign block each other, on purpose. A revocation is
    /// the exception: one per identity it names, so that two stolen
    /// workstations can be revoked within the same minute.
    pub fn live_conflict(
        &self,
        scope: CampaignScope,
        targets: &[CampaignTarget],
        now_unix: u64,
    ) -> Option<Id16> {
        let family = scope.family();
        self.operations
            .values()
            .filter(|operation| {
                !operation.is_expired(now_unix)
                    && operation.state == SigningOperationState::AwaitingOperator
                    && operation.campaign.scope.family() == family
            })
            .find(|operation| match family {
                CampaignFamily::Revocation => operation.campaign.targets.iter().any(|held| {
                    targets
                        .iter()
                        .any(|asked| asked.identity_key == held.identity_key)
                }),
                CampaignFamily::ClientLeaves
                | CampaignFamily::Authorities
                | CampaignFamily::GatewayIdentity
                | CampaignFamily::IssuerDelegation
                | CampaignFamily::GatewayBootstrap => true,
            })
            .map(|operation| operation.operation_id)
    }

    /// Admits a new operation, dropping the ones the clock has ended.
    ///
    /// Expired entries are collected before the ceiling is applied, so a burst
    /// of abandoned ceremonies does not permanently deny the next honest one.
    pub fn open(&mut self, operation: SigningOperation, now_unix: u64) -> Result<(), SigningError> {
        self.operations
            .retain(|_, existing| !existing.is_expired(now_unix));
        if self.operations.len() >= MAX_LIVE_SIGNING_OPERATIONS {
            return Err(SigningError::Full);
        }
        if self
            .operations
            .contains_key(operation.operation_id.as_bytes())
        {
            return Err(SigningError::Conflict);
        }
        self.operations
            .insert(*operation.operation_id.as_bytes(), operation);
        Ok(())
    }

    /// One operation, if it exists and the clock has not ended it.
    ///
    /// Expiry is answered as [`SigningError::Expired`] rather than folded into
    /// [`SigningError::Unknown`]: the public endpoint collapses both into one
    /// refusal, and keeping them apart here is what lets the local operator
    /// command say which of the two happened.
    pub fn get(
        &self,
        operation_id: &Id16,
        now_unix: u64,
    ) -> Result<&SigningOperation, SigningError> {
        let operation = self
            .operations
            .get(operation_id.as_bytes())
            .ok_or(SigningError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(SigningError::Expired);
        }
        Ok(operation)
    }

    /// Live operations whose scope makes an anchor sign this exact vault.
    ///
    /// The vault route has no operation identifier in its path — §8.2 keys it
    /// by the vault's fingerprint — so the operation has to be found from the
    /// token instead. Returning the candidates lets the caller ask the token
    /// which one it is for, rather than letting the *path* select an
    /// operation: a fingerprint is not a secret, and choosing the record to
    /// check a credential against by a value the caller supplied is the shape
    /// of every confused-deputy bug.
    ///
    /// Bounded by [`MAX_LIVE_SIGNING_OPERATIONS`], and in practice one.
    pub fn awaiting_vault(&self, vault: &Fingerprint, now_unix: u64) -> Vec<&SigningOperation> {
        self.operations
            .values()
            .filter(|operation| {
                !operation.is_expired(now_unix)
                    && operation
                        .vault_fingerprint()
                        .is_some_and(|held| held.matches(vault))
            })
            .collect()
    }

    /// The approved campaign that authorizes rotating one client's generation.
    ///
    /// # Why this is a lookup and not a flag on the peer
    ///
    /// A campaign authorizes *the rotation it described*: §7.6 freezes the
    /// targets and their current fingerprints at approval, so the row only
    /// covers the identity in the exact state the operator read. Marking the
    /// peer instead would survive the generation it was approved for, and one
    /// touch would then renew that peer once per generation, indefinitely.
    /// [`AstraRotationCampaign::covers_client`] is the whole test, and it is
    /// the same one the gateway re-runs on the staging it receives.
    ///
    /// Bounded by [`MAX_LIVE_SIGNING_OPERATIONS`], and in practice one.
    pub fn approved_for_client(
        &self,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        active_tls_certificate_fingerprint: &Fingerprint,
        active_pq_certificate_fingerprint: &Fingerprint,
        now_unix: u64,
    ) -> Option<&SigningOperation> {
        self.operations.values().find(|operation| {
            operation.state == SigningOperationState::Approved
                && !operation.is_expired(now_unix)
                && operation
                    .campaign
                    .covers_client(
                        client_wg_public_key,
                        active_generation,
                        active_tls_certificate_fingerprint,
                        active_pq_certificate_fingerprint,
                    )
                    .is_ok()
        })
    }

    /// Checks an operator result, and decides nothing.
    ///
    /// Nothing in the submitted document decides anything: the challenge is
    /// recomputed from **this operation's** campaign, each credential's public
    /// key comes from the registry `CA-PQ` signed, and the relying party and
    /// origin come from the domain.
    ///
    /// # Why checking and recording are two calls
    ///
    /// An authority campaign carries transition objects that have to reach the
    /// **registry**, behind another lock, before the approval that authorized
    /// them is marked spent. Recording first would let a failed persistence
    /// leave an approval that is already idempotent — the companion's retry
    /// would return «already approved» and the objects would be gone with no
    /// second chance to deliver them. So this call verifies, the caller
    /// persists, and [`Self::accept_result`] records.
    pub fn verify_result(
        &self,
        operation_id: &Id16,
        result: &AstraSignerResult,
        registry: &CredentialRegistry,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<VerifiedResult, SigningError> {
        let operation = self
            .operations
            .get(operation_id.as_bytes())
            .ok_or(SigningError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(SigningError::Expired);
        }
        let submitted = result.fingerprint()?;
        if operation.is_idempotent(&submitted)? {
            return Ok(VerifiedResult {
                fingerprint: submitted,
                campaign_id: operation.campaign.campaign_id,
                campaign: Box::new(operation.campaign.as_ref().clone()),
                // Exact bytes were accepted before, so replaying their
                // objects is safe. The registry deduplicates persistence and
                // the service may need the object again to retry an external
                // side effect such as the private-channel revocation relay.
                objects: result.objects.clone(),
                credential_registry: result.credential_registry.clone(),
                issuer_authorization: result.issuer_authorization.clone(),
                already_accepted: true,
            });
        }
        if operation.state == SigningOperationState::Approved {
            return Err(SigningError::AlreadyApproved);
        }
        // Shape first, signatures second. `validate` is what ties each object
        // to a target the operator was shown; without it a valid `CA-PQ`
        // signature over an object nobody read would pass every later check.
        result.validate(&operation.campaign)?;
        result.approval.verify(
            &operation.campaign,
            registry,
            webauthn_rp_id,
            webauthn_origin,
            now_unix,
        )?;
        Ok(VerifiedResult {
            fingerprint: submitted,
            campaign_id: operation.campaign.campaign_id,
            campaign: Box::new(operation.campaign.as_ref().clone()),
            objects: result.objects.clone(),
            credential_registry: result.credential_registry.clone(),
            issuer_authorization: result.issuer_authorization.clone(),
            already_accepted: false,
        })
    }

    /// Records a result [`Self::verify_result`] accepted, once.
    ///
    /// Takes the same `now_unix` as the verification that preceded it, so an
    /// operation cannot expire between the two and leave the caller having
    /// persisted objects for an approval that was then refused.
    pub fn accept_result(
        &mut self,
        operation_id: &Id16,
        result: AstraSignerResult,
        verified: &VerifiedResult,
        now_unix: u64,
    ) -> Result<&SigningOperation, SigningError> {
        let operation = self
            .operations
            .get_mut(operation_id.as_bytes())
            .ok_or(SigningError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(SigningError::Expired);
        }
        if operation.is_idempotent(&verified.fingerprint)? {
            return Ok(operation);
        }
        if operation.state == SigningOperationState::Approved {
            return Err(SigningError::AlreadyApproved);
        }
        operation.accept(verified.fingerprint, result.approval);
        Ok(operation)
    }
}

/// What an operator result was found to contain, before anything records it.
#[derive(Debug, Clone)]
pub struct VerifiedResult {
    /// The exact bytes accepted, for the idempotency rule of §8.2.
    pub fingerprint: Fingerprint,
    pub campaign_id: Id16,
    /// The exact text the operator approved.
    ///
    /// Carried rather than looked up again: it is the only place the state a
    /// decision was taken against is pinned — for the gateway identity, whose
    /// leaves this authority does not hold, it is the *only* place. A second
    /// lookup would be a second value that can disagree with the one the
    /// approval was checked against.
    pub campaign: Box<AstraRotationCampaign>,
    /// Anchor transitions to persist before the approval is marked spent.
    ///
    /// Repeated on an idempotent replay. Registry persistence deduplicates
    /// them, while external relays may need another attempt.
    pub objects: Vec<TrustUpdateObject>,
    pub credential_registry: Option<Box<CredentialRegistry>>,
    /// The bounded delegation an issuer campaign authorized (spec §9.5).
    ///
    /// Beside `objects` rather than among them: no holder receives it, so it
    /// is recorded here and never distributed. Repeated on an idempotent
    /// replay for the same reason the objects are — the registry deduplicates
    /// on the epoch, and a lost response must be retryable.
    pub issuer_authorization:
        Option<Box<aether::certificates::authority::AstraIssuerAuthorization>>,
    /// `true` when these exact bytes were already accepted.
    pub already_accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::MlDsa87Signature;
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};
    use aether::certificates::{
        encoding::{TrustDomainId, WireGuardKey},
        CERTIFICATE_FORMAT_VERSION,
    };

    fn campaign(scope: CampaignScope) -> Box<AstraRotationCampaign> {
        Box::new(AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            created_at: 1_000,
            expires_at: 1_300,
            scope,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientPq,
                identity_key: WireGuardKey::from_bytes([3; 32]),
                epoch: 1,
                generation: 3,
                active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            }],
            reason: "rotation".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: scope.required_credentials(),
        })
    }

    fn request(campaign: &AstraRotationCampaign, vault: Fingerprint) -> Box<AstraSignerRequest> {
        Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: Id16::new([8; 16]).expect("id"),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: vault,
            required_credentials: campaign.required_credentials,
            created_at: 1_000,
            expires_at: 1_300,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn client_key() -> WireGuardKey {
        WireGuardKey::from_bytes([3; 32])
    }

    fn approved_store(scope: CampaignScope) -> SigningOperationStore {
        let campaign = campaign(scope);
        let request = request(&campaign, Fingerprint::of(b"vault"));
        let mut operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        operation.approve_without_ceremony();
        let mut store = SigningOperationStore::new();
        store.open(operation, 1_050).expect("store");
        store
    }

    /// Inserts one live operation whose campaign carries this text, under an
    /// operation identifier of its own. Identifiers are drawn from `index`.
    fn open_with_text(
        store: &mut SigningOperationStore,
        index: u8,
        reason: String,
        requested_by: String,
    ) {
        let mut campaign = campaign(CampaignScope::FleetLeafs);
        // Distinct from every operation identifier drawn from `index`.
        campaign.campaign_id = Id16::new([200; 16]).expect("id");
        campaign.reason = reason;
        campaign.requested_by = requested_by;
        let mut request = request(&campaign, Fingerprint::of(b"vault"));
        request.operation_id = Id16::new([index; 16]).expect("id");
        let operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        store.operations.insert([index; 16], operation);
    }

    #[test]
    fn pending_list_of_64_longest_operations_fits_the_answer_bound() {
        use crate::door::{MAX_REASON_CHARS, MAX_REQUESTED_BY_CHARS};
        // Multi-byte on purpose: the bound is in bytes, the limits in chars.
        let reason: String = "é€😀".chars().cycle().take(MAX_REASON_CHARS).collect();
        let requested_by: String = "😀é€"
            .chars()
            .cycle()
            .take(MAX_REQUESTED_BY_CHARS)
            .collect();
        let mut store = SigningOperationStore::new();
        for index in 1..=MAX_LIVE_SIGNING_OPERATIONS as u8 {
            open_with_text(&mut store, index, reason.clone(), requested_by.clone());
        }
        let list = aether::certificates::transport::OperatorPendingList {
            operations: store.pending(1_100),
        };
        assert_eq!(list.operations.len(), MAX_LIVE_SIGNING_OPERATIONS);
        let body = serde_json::to_vec(&list).unwrap();
        assert!(
            body.len() <= astra_channel::MAX_OPERATOR_ANSWER_BYTES,
            "{} bytes",
            body.len()
        );
    }

    #[test]
    fn pending_cuts_reason_and_requester_at_128_chars_with_an_ellipsis() {
        let mut store = SigningOperationStore::new();
        open_with_text(&mut store, 1, "é".repeat(300), "😀".repeat(200));
        open_with_text(&mut store, 2, "motif court".into(), "a".repeat(128));
        let pending = store.pending(1_100);
        let long = pending
            .iter()
            .find(|op| op.operation_id.as_bytes()[0] == 1)
            .unwrap();
        assert_eq!(long.reason.chars().count(), 129);
        assert!(long.reason.ends_with('…'));
        assert_eq!(long.requested_by.chars().count(), 129);
        assert!(long.requested_by.ends_with('…'));
        let short = pending
            .iter()
            .find(|op| op.operation_id.as_bytes()[0] == 2)
            .unwrap();
        assert_eq!(short.reason, "motif court");
        // Exactly at the limit is not cut.
        assert_eq!(short.requested_by, "a".repeat(128));
    }

    /// The lookup the delegated renewal path runs before asking anyone for a
    /// touch: an approved campaign covering this identity, in this state.
    #[test]
    fn an_approved_campaign_is_found_for_the_target_it_named() {
        let store = approved_store(CampaignScope::FleetLeafs);
        assert!(store
            .approved_for_client(
                &client_key(),
                3,
                &Fingerprint::of(b"tls"),
                &Fingerprint::of(b"pq"),
                1_100,
            )
            .is_some());
    }

    /// A campaign nobody has approved yet authorizes nothing. Without this the
    /// mere act of opening a campaign would renew the fleet.
    #[test]
    fn a_campaign_still_awaiting_its_operator_authorizes_nothing() {
        let campaign = campaign(CampaignScope::FleetLeafs);
        let request = request(&campaign, Fingerprint::of(b"vault"));
        let operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        let mut store = SigningOperationStore::new();
        store.open(operation, 1_050).expect("store");

        assert!(store
            .approved_for_client(
                &client_key(),
                3,
                &Fingerprint::of(b"tls"),
                &Fingerprint::of(b"pq"),
                1_100,
            )
            .is_none());
    }

    /// The approval covers the generation the operator read, and stops there.
    /// A peer that rotated in the meantime is a different rotation.
    #[test]
    fn an_approved_campaign_does_not_follow_its_target_to_the_next_generation() {
        let store = approved_store(CampaignScope::FleetLeafs);
        for (generation, tls, pq) in [
            (4, Fingerprint::of(b"tls"), Fingerprint::of(b"pq")),
            (3, Fingerprint::of(b"other"), Fingerprint::of(b"pq")),
            (3, Fingerprint::of(b"tls"), Fingerprint::of(b"other")),
        ] {
            assert!(
                store
                    .approved_for_client(&client_key(), generation, &tls, &pq, 1_100)
                    .is_none(),
                "generation {generation} was covered by an approval that never described it"
            );
        }
        // And an identity the campaign never named at all.
        assert!(store
            .approved_for_client(
                &WireGuardKey::from_bytes([9; 32]),
                3,
                &Fingerprint::of(b"tls"),
                &Fingerprint::of(b"pq"),
                1_100,
            )
            .is_none());
    }

    /// The window is the approval's, and it ends. An expired operation is not
    /// an authorization the next request may still spend.
    #[test]
    fn an_expired_approval_authorizes_nothing() {
        let store = approved_store(CampaignScope::FleetLeafs);
        assert!(store
            .approved_for_client(
                &client_key(),
                3,
                &Fingerprint::of(b"tls"),
                &Fingerprint::of(b"pq"),
                1_300,
            )
            .is_none());
    }

    /// Two credentials approved a decision about `CA-PQ`; spending it on a
    /// client leaf would apply a text the operator was never shown.
    #[test]
    fn an_authority_campaign_is_never_found_for_a_client() {
        let store = approved_store(CampaignScope::TrustAuthorities);
        assert!(store
            .approved_for_client(
                &client_key(),
                3,
                &Fingerprint::of(b"tls"),
                &Fingerprint::of(b"pq"),
                1_100,
            )
            .is_none());
    }

    /// The request the companion verifies must name the campaign it will be
    /// shown, or an operator approves one text while another is applied.
    #[test]
    fn a_request_naming_another_campaign_opens_nothing() {
        let approved = campaign(CampaignScope::FleetLeafs);
        let other = campaign(CampaignScope::FullCertificateChain);
        let request = request(&other, Fingerprint::of(b"vault"));

        assert!(matches!(
            SigningOperation::new(approved, request, 1_050),
            Err(SigningError::Approval(
                aether::certificates::CertificateError::CampaignMismatch
            ))
        ));
    }

    /// A token is minted for a vault only when the scope makes a master key sign.
    ///
    /// Otherwise an ordinary campaign's grant would carry a vault fingerprint,
    /// and a vault-download token would exist for a ceremony that opens
    /// nothing.
    #[test]
    fn only_a_master_key_scope_names_a_vault() {
        let vault = Fingerprint::of(b"vault");
        let ordinary = campaign(CampaignScope::FleetLeafs);
        let ordinary_request = request(&ordinary, vault);
        let operation = SigningOperation::new(ordinary, ordinary_request, 1_050).expect("open");
        assert_eq!(operation.vault_fingerprint(), None);

        let authorities = campaign(CampaignScope::TrustAuthorities);
        let authority_request = request(&authorities, vault);
        let operation = SigningOperation::new(authorities, authority_request, 1_050).expect("open");
        assert_eq!(operation.vault_fingerprint(), Some(vault));

        let revocation = campaign(CampaignScope::EmergencyRevocation);
        let revocation_request = request(&revocation, vault);
        let operation = SigningOperation::new(revocation, revocation_request, 1_050).expect("open");
        assert_eq!(operation.vault_fingerprint(), Some(vault));
    }

    /// The operation cannot outlive the campaign it carries.
    #[test]
    fn the_window_is_the_narrower_of_the_two() {
        let campaign = campaign(CampaignScope::FleetLeafs);
        let mut request = request(&campaign, Fingerprint::of(b"vault"));
        request.expires_at = 9_000;
        let operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        assert_eq!(operation.expires_at, 1_300, "the campaign ends first");
        assert!(!operation.is_expired(1_299));
        assert!(operation.is_expired(1_300));
    }

    /// The capability tokens are bound to the campaign, so they stop meaning
    /// anything the moment the campaign would change.
    #[test]
    fn the_manifest_is_the_campaign_fingerprint() {
        let campaign = campaign(CampaignScope::FleetLeafs);
        let expected = campaign.fingerprint();
        let request = request(&campaign, Fingerprint::of(b"vault"));
        let operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        assert_eq!(operation.manifest_fingerprint(), expected);
    }

    /// The shape of a result is decided before its assertions are, so an
    /// object nobody was shown is refused without a signature being checked —
    /// and without the operator's approval being marked spent.
    #[test]
    fn an_object_the_campaign_never_named_is_refused_before_any_assertion() {
        use aether::certificates::authority::CaTransition;
        use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87PublicKey};
        use aether::certificates::transport::TrustUpdateObject;
        use aether::certificates::window::TransitionWindow;

        let campaign = campaign(CampaignScope::FleetLeafs);
        let request = request(&campaign, Fingerprint::of(b"vault"));
        let campaign_fingerprint = campaign.fingerprint();
        let campaign_id = campaign.campaign_id;
        let trust_domain_id = campaign.trust_domain_id;
        let operation = SigningOperation::new(campaign, request, 1_050).expect("open");
        let operation_id = operation.operation_id;
        let mut store = SigningOperationStore::new();
        store.open(operation, 1_050).expect("opened");

        let (_, next) = generate_ml_dsa_87_keypair().expect("keygen");
        let smuggled = TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id,
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: Fingerprint::of(b"anchor"),
            next_ca_fingerprint: next.authority_fingerprint(),
            next_ca_public_key: MlDsa87PublicKey::clone(&next),
            window: TransitionWindow::new(1_000, 90_000, 200_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }));
        let result = AstraSignerResult {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(aether::certificates::status::CampaignApproval {
                campaign_id,
                campaign_fingerprint,
                required_credentials: 1,
                approved_at: 1_100,
                approvals: Vec::new(),
            }),
            objects: vec![smuggled],
            credential_registry: None,
            issuer_authorization: None,
        };
        let registry = CredentialRegistry {
            trust_domain_id,
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        };
        assert!(store
            .verify_result(
                &operation_id,
                &result,
                &registry,
                "astra.example",
                "https://astra.example",
                1_100,
            )
            .is_err());
        assert_eq!(
            store.get(&operation_id, 1_100).expect("still open").state,
            SigningOperationState::AwaitingOperator,
            "a refused result must not spend the approval"
        );
    }

    fn awaiting(scope: CampaignScope, identity: u8, operation: u8) -> SigningOperation {
        let mut campaign = campaign(scope);
        campaign.targets[0].identity_key = WireGuardKey::from_bytes([identity; 32]);
        let mut request = request(&campaign, Fingerprint::of(b"vault"));
        request.operation_id = Id16::new([operation; 16]).expect("id");
        SigningOperation::new(campaign, request, 1_050).expect("open")
    }

    /// One live operation per family: what is waiting blocks, what was
    /// approved or has expired does not.
    #[test]
    fn a_live_operation_blocks_its_family_and_only_while_it_waits() {
        let mut store = SigningOperationStore::new();
        store
            .open(awaiting(CampaignScope::FleetLeafs, 3, 8), 1_050)
            .expect("opened");
        let targets = campaign(CampaignScope::FleetLeafs).targets;

        assert_eq!(
            store.live_conflict(CampaignScope::FleetLeafs, &targets, 1_100),
            Some(Id16::new([8; 16]).expect("id"))
        );
        // Same family, another scope: a chain step and an isolated
        // `fleet_leafs` campaign block each other.
        assert!(store
            .live_conflict(CampaignScope::OrionDevice, &targets, 1_100)
            .is_some());
        assert!(store
            .live_conflict(CampaignScope::TrustAuthorities, &targets, 1_100)
            .is_none());
        assert!(store
            .live_conflict(CampaignScope::FleetLeafs, &targets, 1_300)
            .is_none());

        let approved = approved_store(CampaignScope::FleetLeafs);
        assert!(approved
            .live_conflict(CampaignScope::FleetLeafs, &targets, 1_100)
            .is_none());
    }

    /// Two stolen workstations can be revoked within the same minute.
    #[test]
    fn a_revocation_blocks_only_the_identity_it_names() {
        let mut store = SigningOperationStore::new();
        store
            .open(awaiting(CampaignScope::EmergencyRevocation, 3, 8), 1_050)
            .expect("opened");
        let same = campaign(CampaignScope::EmergencyRevocation).targets;
        let mut other = same.clone();
        other[0].identity_key = WireGuardKey::from_bytes([4; 32]);

        assert_eq!(
            store.live_conflict(CampaignScope::EmergencyRevocation, &same, 1_100),
            Some(Id16::new([8; 16]).expect("id"))
        );
        assert!(store
            .live_conflict(CampaignScope::EmergencyRevocation, &other, 1_100)
            .is_none());
    }

    /// A store that never dropped an abandoned ceremony would let a burst of
    /// them deny every honest one afterwards.
    #[test]
    fn an_expired_operation_frees_its_place() {
        let mut store = SigningOperationStore::new();
        let first = campaign(CampaignScope::FleetLeafs);
        let first_request = request(&first, Fingerprint::of(b"vault"));
        let operation = SigningOperation::new(first, first_request, 1_050).expect("open");
        let operation_id = operation.operation_id;
        store.open(operation, 1_050).expect("opened");
        assert_eq!(store.len(), 1);
        assert!(store.get(&operation_id, 1_100).is_ok());

        // Past the window it is refused, and the next `open` collects it.
        assert!(matches!(
            store.get(&operation_id, 1_300),
            Err(SigningError::Expired)
        ));

        let mut later = *campaign(CampaignScope::FleetLeafs);
        later.created_at = 2_000;
        later.expires_at = 2_300;
        let later = Box::new(later);
        let mut next_request = request(&later, Fingerprint::of(b"vault"));
        next_request.operation_id = Id16::new([9; 16]).expect("id");
        next_request.created_at = 2_000;
        next_request.expires_at = 2_300;
        let next = SigningOperation::new(later, next_request, 2_050).expect("open");
        store.open(next, 2_050).expect("opened");
        assert_eq!(store.len(), 1, "the expired one was collected");
    }

    /// A refused submission must not consume the ceremony.
    ///
    /// The operator is standing there with a key. If a malformed or hostile
    /// body could put the operation into a state that accepts nothing more,
    /// anybody who learned the identifier could burn every campaign at the one
    /// moment there is nobody to ask twice.
    #[test]
    fn a_refused_result_leaves_the_operation_open() {
        use aether::certificates::approval::CredentialRegistry;
        use aether::certificates::status::{CampaignApproval, CredentialAssertion};
        use aether::certificates::webauthn::WebAuthnAssertion;

        let mut store = SigningOperationStore::new();
        let opened = campaign(CampaignScope::FleetLeafs);
        let fingerprint = opened.fingerprint();
        let campaign_id = opened.campaign_id;
        let opened_request = request(&opened, Fingerprint::of(b"vault"));
        let operation = SigningOperation::new(opened, opened_request, 1_050).expect("open");
        let operation_id = operation.operation_id;
        store.open(operation, 1_050).expect("opened");

        let registry = CredentialRegistry {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        };
        let nonsense = CampaignApproval {
            campaign_id,
            campaign_fingerprint: fingerprint,
            required_credentials: 1,
            approved_at: 1_100,
            approvals: vec![CredentialAssertion {
                credential_id: b"nobody".to_vec(),
                credential_fingerprint: Fingerprint::of(b"nobody"),
                assertion_fingerprint: Fingerprint::of(b"nothing"),
                assertion: WebAuthnAssertion {
                    authenticator_data: Vec::new(),
                    client_data_json: Vec::new(),
                    signature: Vec::new(),
                },
            }],
        };

        let result = AstraSignerResult {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(nonsense),
            objects: Vec::new(),
            credential_registry: None,
            issuer_authorization: None,
        };
        assert!(store
            .verify_result(
                &operation_id,
                &result,
                &registry,
                "astra.example",
                "https://astra.example",
                1_100,
            )
            .is_err());

        let operation = store.get(&operation_id, 1_100).expect("still open");
        assert_eq!(operation.state, SigningOperationState::AwaitingOperator);
        assert!(operation.approval().is_none());
    }
}
