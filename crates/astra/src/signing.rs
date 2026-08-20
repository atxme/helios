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
    encoding::{Fingerprint, Id16},
    status::{AstraRotationCampaign, AstraSignerRequest, CampaignScope},
    CertificateError,
};
use serde::{Deserialize, Serialize};

/// Directory a local operator command deposits a campaign into.
///
/// # Why an inbox and not a call
///
/// The store above lives in the process that serves the endpoint, in memory.
/// `astra campaign open` runs in a **different** process — it is a shell
/// command on the machine, deliberately, because opening a campaign from the
/// public origin would mean an unauthenticated route that resolves and returns
/// the fleet's inventory. So the command deposits, and the server drains.
///
/// It is the shape `heliosd peer add` already uses for admissions, and for the
/// same reason: one owner of the state, and a second process that may only
/// leave something for it.
pub const CAMPAIGN_INBOX_DIR: &str = "campaign-inbox";

/// Largest campaign file drained from the inbox, in bytes.
///
/// A campaign is bounded at 256 targets, each a handful of fixed-width fields.
/// Anything above this is not a campaign.
pub const MAX_INBOX_ENTRY_BYTES: u64 = 512 * 1024;

/// What a local command leaves for the running service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDeposit {
    pub campaign: Box<AstraRotationCampaign>,
    pub signer_request: Box<AstraSignerRequest>,
}

/// Largest number of operator operations alive at once.
///
/// A ceiling rather than an unbounded map: each one is opened by a local
/// operator command, so more than a handful in flight means something is
/// looping, and growing memory on that is how a bound stops being one.
pub const MAX_LIVE_SIGNING_OPERATIONS: usize = 64;

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

/// Where an operator operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOperationState {
    /// Open, and waiting for the companion's assertions.
    AwaitingOperator,
    /// The assertions arrived and verified.
    ///
    /// # Limite connue : rien n'applique encore une campagne approuvée
    ///
    /// The approval is recorded, and that is where it stops. Turning it into
    /// signed objects means Astra building a per-client manifest and depositing
    /// it on the veth, which is the lot after this one. Every surface that can
    /// reach this state says so out loud rather than letting an operator spend
    /// a ceremony and watch nothing happen.
    Approved,
}

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
    /// Only a scope that rotates an anchor makes `CA-PQ` or `CA-TLS` sign, and
    /// only then does the companion have to open the vault at all. Returning
    /// `None` otherwise is what stops an ordinary campaign's token from being
    /// a vault-download token.
    pub fn vault_fingerprint(&self) -> Option<Fingerprint> {
        self.campaign
            .scope
            .rotates_authority()
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

/// What a caller learns about an operation it holds the identifier of.
///
/// Unsigned, exactly like [`aether::certificates::transport::ClientRenewalOperationView`]
/// and for the same reason: everything here that decides anything is
/// re-derivable from the signed `AstraSignerRequest` the companion fetches and
/// verifies under the service key it already pins. A view is how an interface
/// follows progress, never how it concludes that a signature succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningOperationView {
    pub operation_id: Id16,
    pub state: SigningOperationState,
    pub scope: CampaignScope,
    pub target_count: usize,
    pub required_credentials: u8,
    /// SHA-256 of the canonical campaign — the value the operator reads on the
    /// companion's screen, and the challenge their key answers.
    pub campaign_fingerprint: Fingerprint,
    pub created_at: u64,
    pub expires_at: u64,
    /// Bearer token for the companion's read route, absent once the operation
    /// no longer accepts one.
    pub signer_request_token: Option<String>,
    /// Bearer token for the encrypted vault, present only for a scope that
    /// makes an anchor sign.
    pub vault_token: Option<String>,
    /// Bearer token for the companion's submission route.
    pub signer_result_token: Option<String>,
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

    /// Delivers the operator's result, verified against what Astra holds.
    ///
    /// Nothing in the submitted document decides anything: the challenge is
    /// recomputed from **this operation's** campaign, each credential's public
    /// key comes from the registry `CA-PQ` signed, and the relying party and
    /// origin come from the domain. An identical replay is a no-op; different
    /// bytes under the same identifier are a conflict.
    pub fn submit(
        &mut self,
        operation_id: &Id16,
        approval: Box<aether::certificates::status::CampaignApproval>,
        registry: &CredentialRegistry,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<&SigningOperation, SigningError> {
        let operation = self
            .operations
            .get_mut(operation_id.as_bytes())
            .ok_or(SigningError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(SigningError::Expired);
        }
        let submitted = approval.fingerprint()?;
        if operation.is_idempotent(&submitted)? {
            return Ok(operation);
        }
        if operation.state == SigningOperationState::Approved {
            return Err(SigningError::AlreadyApproved);
        }
        approval.verify(
            &operation.campaign,
            registry,
            webauthn_rp_id,
            webauthn_origin,
            now_unix,
        )?;
        operation.accept(submitted, approval);
        Ok(operation)
    }
}

/// Drains the campaign inbox into the running service's store.
///
/// Two seconds, like the gateway's admission drain: an operator who has just
/// run `astra campaign open` is looking at the terminal, and the campaign they
/// opened carries a five-minute window — a slower sweep would spend a
/// noticeable share of it doing nothing.
pub const INBOX_POLL_INTERVAL_SECS: u64 = 2;

/// Reads one deposit, checks it against the domain, and opens the operation.
///
/// The service key signature on the request is **re-verified** here even
/// though the same machine produced it: the file sat on disk between two
/// processes, and a check that trusts a path rather than a signature is a
/// check that trusts whoever can write to that path.
pub fn adopt_deposit(
    store: &mut SigningOperationStore,
    deposit: CampaignDeposit,
    service_public_key: &aether::certificates::encoding::MlDsa87PublicKey,
    service_key_epoch: u64,
    authority_url: &str,
    now_unix: u64,
) -> Result<Id16, SigningError> {
    deposit.signer_request.verify(
        service_public_key,
        service_key_epoch,
        authority_url,
        now_unix,
    )?;
    let operation = SigningOperation::new(deposit.campaign, deposit.signer_request, now_unix)?;
    let operation_id = operation.operation_id;
    store.open(operation, now_unix)?;
    Ok(operation_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::MlDsa87Signature;
    use aether::certificates::status::{CampaignTarget, CertificateKind};
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

    /// A token is minted for a vault only when the scope makes an anchor sign.
    ///
    /// Otherwise an ordinary campaign's grant would carry a vault fingerprint,
    /// and a vault-download token would exist for a ceremony that opens
    /// nothing.
    #[test]
    fn only_an_authority_scope_names_a_vault() {
        let vault = Fingerprint::of(b"vault");
        let ordinary = campaign(CampaignScope::FleetLeafs);
        let ordinary_request = request(&ordinary, vault);
        let operation = SigningOperation::new(ordinary, ordinary_request, 1_050).expect("open");
        assert_eq!(operation.vault_fingerprint(), None);

        let authorities = campaign(CampaignScope::TrustAuthorities);
        let authority_request = request(&authorities, vault);
        let operation = SigningOperation::new(authorities, authority_request, 1_050).expect("open");
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

        assert!(store
            .submit(
                &operation_id,
                Box::new(nonsense),
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
