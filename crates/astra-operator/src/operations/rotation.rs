//! Replacing a CA: validate each key, approve in any order, sign, then carry the
//! rotation to the gateway alone (spec §5.3, §5.4).
//!
//! # Why a key is validated before anything exists
//!
//! A campaign blocks its family for five minutes, so the two keys are proved
//! first and nothing is opened until both answered. What each one released is
//! kept in memory until the signature, or until the campaign expires: that replaces
//! the touch that would open the vault at the ceremony, and leaves one approval per
//! key to go, four touches in all. These openings never leave this process, and neither of the two types
//! holding them is `Debug` or `Serialize`.
//!
//! # Why the journal comes between the signature and the deposit
//!
//! See [`crate::rotation_journal`]. Signing here moves nothing on disk but the
//! journal. The vault in place moves in [`advance`], once Astra has accepted, and a
//! client TLS rotation leaves its prepared record with it: that record outlives the
//! journal, names the incoming certificate for « Terminer », and holds any other
//! rotation until then. `apply_local` does not check the acceptance for itself:
//! [`next_step`] is the only barrier, which is why [`advance`] is the only caller.
//!
//! # Ending a client TLS rotation
//!
//! [`CaTlsFinish`] is « Terminer »: one key, and the record [`advance`] left names the
//! incoming certificate. It holds out while a journal is in flight, since that
//! rotation has not reached the gateway and the outgoing key is all that still works.
//!
//! # What the words are
//!
//! This module decides and the caller shows. [`KeyStep`] is for a key that can be
//! tried again, [`ResumeStep`] for a rotation that stopped, and neither is a failure
//! of the rotation.

use std::marker::PhantomData;
use std::path::Path;

use aether::certificates::approval::CredentialRegistry;
use aether::certificates::authority::{CaTransition, ClientTlsCaTransition};
use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, MlDsa87PublicKey};
use aether::certificates::operator_session::{
    AffectedCa, AstraManifest, CaRotationManifest, CampaignManifest,
};
use aether::certificates::status::{AstraRotationCampaign, AstraSignerResult};
use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorOpenAction, OperatorOpenRequest, OperatorOpened,
    OperatorVaultCopy, SigningOperationState, TrustUpdateObject,
};
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::authenticator::{Authenticator, AuthenticatorError, Opened};
use crate::gestures::{self, GestureError};
use crate::handoff::{self, DomainHandoff};
use crate::origin::CampaignRequest;
use crate::rotation_journal::{
    self, next_step, GatewayAnchor, JournalDeposit, JournalStage, NextLocal, ResumeFacts,
    ResumeStep, RotationJournal, RotationKind, RotationTransition,
};
use crate::signing::{
    self, CampaignApprovalSession, DomainIdentity, ANCHOR_ROTATION_CREDENTIALS,
    MAX_CA_TLS_LIFETIME_SECS,
};
use crate::tunnel::{Tunnel, TunnelRefusal, VaultCopySent};
use crate::vault::{AuthorityVault, CaTlsAdvance};
use crate::{credentials, prepared, store};

/// Default of « Modifier » on the approval screen (spec §5.1).
pub const DEFAULT_PREPARE_DAYS: u64 = 7;
pub const DEFAULT_OVERLAP_DAYS: u64 = 30;
pub const DEFAULT_CA_TLS_VALIDITY_DAYS: u64 = 1825;

/// The gateway refuses a transition past `activation_at`, with no repair (§5.4),
/// so the installation gets at least a day.
const MIN_PREPARE_DAYS: u64 = 1;

const DAY_SECS: u64 = 86_400;

/// The longest a campaign may live (§7.6).
const CAMPAIGN_WINDOW_SECS: u64 = 300;

/// This ceremony has no way to ask for a PIN: the platform's dialog does, and the
/// value never crosses into this process. Orion refuses a transport that wants one
/// before reaching here.
const NO_PIN: &str = "";

/// Why a key was turned down. Nothing is lost: the operator can try again.
///
/// An error type so that [`OpenedRotation::sign_and_journal`] can also say
/// [`KeyStep::Expired`], which a caller reads with `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyStep {
    /// This key does not open the vault.
    #[error("clé absente du coffre")]
    NotEnrolled,
    /// This key opens the vault, and the credential document marks it lost or revoked:
    /// it approves nothing, and another key can take its place.
    #[error("clé marquée perdue ou révoquée")]
    NotApprovable,
    /// This key has already answered: two touches of one token are not two people.
    #[error("clé déjà utilisée")]
    Repeated,
    /// Not a key this step can take: outside the two validated, or one that has
    /// approved already, which the platform cannot tell apart once it is not offered.
    #[error("autre clé attendue")]
    NotValidated,
    /// No key answered, or the operator cancelled the gesture.
    #[error("geste de la clé annulé")]
    Declined,
    /// The campaign's window closed. Nothing was signed.
    #[error("campagne expirée")]
    Expired,
}

/// What [`open`] refuses of the domain before any campaign, by its cause. Anything else
/// it refuses is a call that failed, or files that do not describe this domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenRefusal {
    /// A validated key is no longer active in the credential document.
    #[error(
        "une clé validée n'est pas active dans le document de credentials. Rien n'a été signé."
    )]
    KeyNotApprovable,
    /// Astra has a CA rotation in flight, of either kind.
    #[error("une rotation de CA est en cours sur le domaine. Rien n'a été signé.")]
    RotationInFlight,
    /// The vault still holds a client TLS window, until « Terminer ».
    #[error("la rotation CA TLS en cours reste à terminer. Rien n'a été signé.")]
    CaTlsToFinish,
    /// Astra and this vault do not name the same anchors.
    #[error("Astra et ce coffre ne nomment pas la même ancre. Rien n'a été signé.")]
    AnchorsDisagree,
}

/// What the operator chose on the approval screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationTerms {
    /// A campaign already open, to be led here rather than opened again.
    pub existing_operation: Option<Id16>,
    pub reason: String,
    pub requested_by: String,
    pub prepare_days: u64,
    pub overlap_days: u64,
    /// Read for a client TLS rotation only: the `CA-PQ` key has no certificate.
    pub validity_days: u64,
}

/// What a rotation needs from the far side of the tunnel.
pub trait RotationRemote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened>;
    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest>;
    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState>;
    fn authority_status(&self) -> Result<OperatorAuthorityStatus>;
    fn send_vault_copy(&self, copy: &OperatorVaultCopy) -> Result<VaultCopySent>;
    fn install_ca_transition(&self, transition: &CaTransition) -> Result<()>;
    fn install_client_tls_ca_transition(&self, transition: &ClientTlsCaTransition) -> Result<()>;
    fn gateway_next_anchor(&self, kind: RotationKind) -> Result<Option<Fingerprint>>;
}

impl RotationRemote for Tunnel {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        Tunnel::open_campaign(self, request)
    }

    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        Tunnel::fetch_campaign(self, operation_id)
    }

    fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<SigningOperationState> {
        Tunnel::submit_campaign(self, operation_id, result_token, result)
    }

    fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        Tunnel::authority_status(self)
    }

    fn send_vault_copy(&self, copy: &OperatorVaultCopy) -> Result<VaultCopySent> {
        Tunnel::send_vault_copy(self, copy)
    }

    fn install_ca_transition(&self, transition: &CaTransition) -> Result<()> {
        Tunnel::install_ca_transition(self, transition)
    }

    fn install_client_tls_ca_transition(&self, transition: &ClientTlsCaTransition) -> Result<()> {
        Tunnel::install_client_tls_ca_transition(self, transition)
    }

    fn gateway_next_anchor(&self, kind: RotationKind) -> Result<Option<Fingerprint>> {
        Tunnel::gateway_next_anchor(self, kind)
    }
}

/// The keys proved so far, and what each one released.
///
/// Dropping it wipes the openings, which is what abandoning a ceremony comes to.
///
/// The marker removes `Send` and `Sync` from it and from whatever holds it, so these
/// openings stay on the thread of the ceremony that asked for them.
pub struct ValidatedKeys {
    vault: AuthorityVault,
    /// The credential document beside the vault, read as it is to turn a key marked lost
    /// down at its validation. Not trusted for anything else: [`open`] checks the keys
    /// again against the document it has verified under `CA-PQ`.
    registry: Option<Box<CredentialRegistry>>,
    openings: Vec<Opened>,
    _thread: PhantomData<*const ()>,
}

impl ValidatedKeys {
    pub fn new(vault_path: &Path) -> Result<Self> {
        Ok(Self {
            vault: store::load(vault_path)?,
            registry: credentials::load(&credentials::path_beside(vault_path))?.map(Box::new),
            openings: Vec::with_capacity(ANCHOR_ROTATION_CREDENTIALS),
            _thread: PhantomData,
        })
    }

    /// One touch: proves this key opens the anchors, and returns the label of its
    /// slot. Opens no campaign, and asks the remote nothing.
    pub fn validate(&mut self, key: &dyn Authenticator) -> Result<String, KeyStep> {
        if self.openings.len() >= ANCHOR_ROTATION_CREDENTIALS {
            return Err(KeyStep::NotValidated);
        }
        let opened = gestures::open_with_authorized_key(key, &self.vault, NO_PIN)
            .map_err(key_step_of_opening)?;
        if self.is_validated(&opened.credential_id) {
            return Err(KeyStep::Repeated);
        }
        gestures::prove_anchors_open(&self.vault, &opened).map_err(|_| KeyStep::NotEnrolled)?;
        // With no document, `open` refuses before any campaign, whatever the keys.
        if let Some(registry) = &self.registry {
            if !may_approve(registry, &opened.credential_id) {
                return Err(KeyStep::NotApprovable);
            }
        }
        let label = self
            .vault
            .slot_for_credential(&opened.credential_id)
            .map_err(|_| KeyStep::NotEnrolled)?
            .label
            .clone();
        self.openings.push(opened);
        Ok(label)
    }

    pub fn count(&self) -> usize {
        self.openings.len()
    }

    /// What [`open`] would refuse of the files beside this vault, asked before a key
    /// is touched for nothing.
    pub fn ensure_domain_readable(&self, vault_path: &Path, kind: RotationKind) -> Result<()> {
        LocalDomain::read(vault_path, &self.vault, kind).map(|_| ())
    }

    fn is_validated(&self, credential_id: &[u8]) -> bool {
        self.openings
            .iter()
            .any(|opening| opening.credential_id == credential_id)
    }
}

/// The token did not say which credential it holds: it holds none of those offered,
/// or something got in the way of the gesture.
fn key_step_of_opening(error: GestureError) -> KeyStep {
    match error {
        GestureError::Authenticator(AuthenticatorError::UnknownCredential)
        | GestureError::Vault(_) => KeyStep::NotEnrolled,
        _ => KeyStep::Declined,
    }
}

/// A verified campaign and the session its approvals go into.
pub struct OpenedRotation {
    kind: RotationKind,
    keys: ValidatedKeys,
    domain: LocalDomain,
    schedule: Schedule,
    request: Box<CampaignRequest>,
    manifest: AstraManifest,
    approval: CampaignApprovalSession,
}

/// What the files beside the vault say of the domain, checked with no key and
/// before any campaign.
struct LocalDomain {
    relay: DomainHandoff,
    identity: DomainIdentity,
    registry: CredentialRegistry,
    current_ca: MlDsa87PublicKey,
    /// The client TLS anchor in service, for a rotation that replaces it.
    active_certificate: Option<DerCertificate>,
    authority_url: String,
}

impl LocalDomain {
    fn read(vault_path: &Path, vault: &AuthorityVault, kind: RotationKind) -> Result<Self> {
        let relay = DomainHandoff::beside(vault_path, vault)?;
        let identity = handoff::identity_of(&relay)?;
        let current_ca = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
        let registry = credentials::load(&credentials::path_beside(vault_path))?
            .context("aucun document de credentials à côté du coffre")?;
        registry.verify(
            &current_ca,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            registry.credential_registry_epoch,
        )?;
        let active_certificate = match kind {
            RotationKind::CaPq => None,
            RotationKind::CaTls => Some(DerCertificate::parse(relay.require(
                relay.ca_tls_certificate.as_ref(),
                "le certificat CA-TLS en service",
                "--ca-tls-certificate",
            )?)?),
        };
        let authority_url = relay
            .require(
                relay.astra_authority_url.as_ref(),
                "l'origine déclarée par l'autorité",
                "--astra-authority-url",
            )?
            .clone();
        Ok(Self {
            relay,
            identity,
            registry,
            current_ca,
            active_certificate,
            authority_url,
        })
    }

    /// The object a campaign is compared to, before a key is asked to approve it.
    fn probe(&self, window: TransitionWindow) -> Result<TrustUpdateObject> {
        Ok(match &self.active_certificate {
            None => signing::anchor_probe(&self.identity, &self.current_ca, window)?,
            Some(active) => signing::client_tls_probe(&self.identity, active, window)?,
        })
    }
}

/// The dates the operator approves, and the ones signed.
#[derive(Clone, Copy)]
struct Schedule {
    window: TransitionWindow,
    /// The validity of an incoming client TLS anchor. Empty for a CA-PQ rotation.
    validity: (u64, u64),
}

impl Schedule {
    /// Everything `rotate_ca_tls` and `rotate_ca_pq` would refuse of these terms,
    /// refused here: they run after the four touches, and a campaign is open by then.
    fn of(kind: RotationKind, terms: &RotationTerms, now: u64) -> Result<Self> {
        if terms.prepare_days < MIN_PREPARE_DAYS {
            bail!("la préparation dure au moins {MIN_PREPARE_DAYS} jour");
        }
        let after = |from: u64, days: u64| {
            days.checked_mul(DAY_SECS)
                .and_then(|span| from.checked_add(span))
                .context("durée hors bornes")
        };
        let activation_at = after(now, terms.prepare_days)?;
        let not_after = after(activation_at, terms.overlap_days)?;
        let window = TransitionWindow::new(now, activation_at, not_after)?;
        let validity_end = match kind {
            RotationKind::CaPq => now,
            RotationKind::CaTls => {
                let end = after(now, terms.validity_days)?;
                if end <= not_after || end - now > MAX_CA_TLS_LIFETIME_SECS {
                    bail!(
                        "la validité de la CA TLS doit couvrir la rotation, et rester sous dix ans"
                    );
                }
                end
            }
        };
        Ok(Self {
            window,
            validity: (now, validity_end),
        })
    }
}

/// What [`open`] would refuse of these terms, so that they cost no validated key.
pub fn check_terms(kind: RotationKind, terms: &RotationTerms, now: u64) -> Result<()> {
    Schedule::of(kind, terms, now).map(|_| ())
}

/// Opens the campaign, or reads the one named, and verifies it before any approval.
///
/// Everything this machine can refuse by itself comes first, so that a campaign
/// never blocks its family for five minutes over a prerequisite (spec §4).
pub fn open(
    remote: &dyn RotationRemote,
    vault_path: &Path,
    kind: RotationKind,
    keys: ValidatedKeys,
    terms: &RotationTerms,
    now: u64,
) -> Result<OpenedRotation> {
    ensure_nothing_outstanding(vault_path)?;
    ensure_same_vault(vault_path, &keys.vault)?;
    if keys.count() != ANCHOR_ROTATION_CREDENTIALS {
        bail!(
            "une rotation de CA exige {ANCHOR_ROTATION_CREDENTIALS} clés validées, {} ici",
            keys.count()
        );
    }
    let schedule = Schedule::of(kind, terms, now)?;
    let domain = LocalDomain::read(vault_path, &keys.vault, kind)?;
    ensure_keys_may_approve(&keys, &domain.registry)?;
    ensure_no_window_open(&keys)?;
    let authority = remote.authority_status()?;
    ensure_no_overlap(&authority)?;
    ensure_same_anchors(&authority, &domain)?;

    let operation_id = match terms.existing_operation {
        Some(operation_id) => operation_id,
        None => {
            remote
                .open_campaign(&OperatorOpenRequest {
                    action: OperatorOpenAction::TrustAuthorities,
                    reason: terms.reason.clone(),
                    requested_by: terms.requested_by.clone(),
                    window_secs: CAMPAIGN_WINDOW_SECS,
                })?
                .operation_id
        }
    };
    let request = remote.fetch_campaign(&operation_id)?;
    handoff::verify_campaign_request(
        &domain.relay,
        &keys.vault,
        &request,
        &domain.authority_url,
        now,
    )?;
    let campaign = request.campaign.as_ref();
    if !campaign.scope.rotates_authority() {
        bail!("cette campagne ne fait tourner aucune ancre. Rien n'a été signé.");
    }
    // The status said so a moment ago, and this is the signed word on the same
    // question: what the keys approve must name the anchor this vault holds.
    campaign
        .covers_authority_object(&domain.probe(schedule.window)?)
        .context("la campagne ne nomme pas l'ancre de ce coffre")?;

    let approval = CampaignApprovalSession::new(
        campaign,
        &domain.registry,
        &domain.identity,
        &domain.current_ca,
        &keys.vault.rp_id,
        &format!("https://{}", keys.vault.rp_id),
        now,
    )?;
    let manifest = rotation_manifest(&domain, schedule.window, campaign);
    Ok(OpenedRotation {
        kind,
        keys,
        domain,
        schedule,
        request: Box::new(request),
        manifest,
        approval,
    })
}

/// What the touch does, with the whole campaign it signs: the authority replaced, and
/// every target that fingerprint covers. The incoming anchor does not exist before
/// the signature, which waits for the approvals, so it is absent here and the journal
/// gives it once signed.
fn rotation_manifest(
    domain: &LocalDomain,
    window: TransitionWindow,
    campaign: &AstraRotationCampaign,
) -> AstraManifest {
    let (affected_ca, current_epoch, outgoing_anchor_fingerprint) = match &domain.active_certificate
    {
        None => (
            AffectedCa::CaPq,
            domain.identity.ca_epoch,
            domain.current_ca.authority_fingerprint(),
        ),
        Some(active) => (
            AffectedCa::CaTls,
            domain.identity.ca_tls_epoch,
            active.fingerprint(),
        ),
    };
    AstraManifest::CaRotation(CaRotationManifest {
        trust_domain_id: domain.identity.trust_domain_id,
        affected_ca,
        current_epoch,
        next_epoch: current_epoch + 1,
        activation_at: window.activation_at,
        not_after: window.not_after,
        outgoing_anchor_fingerprint,
        next_anchor_fingerprint: None,
        campaign: Some(CampaignManifest {
            campaign: Box::new(campaign.clone()),
            fingerprint: campaign.fingerprint(),
        }),
    })
}

/// A journal, or what will become one: a second rotation over it would name its
/// outgoing anchor. The prepared record lasts until the promotion, and so does the
/// window it describes.
pub fn ensure_nothing_outstanding(vault_path: &Path) -> Result<()> {
    rotation_journal::ensure_none_in_flight(vault_path)?;
    if rotation_journal::legacy_ca_pq_path_beside(vault_path).exists() {
        bail!(
            "une rotation CA-PQ préparée par astra-signer reste à reprendre. Rien n'a été signé."
        );
    }
    if prepared::load(&prepared::path_beside(vault_path))?.is_some() {
        bail!("une rotation CA TLS préparée reste à terminer. Rien n'a été signé.");
    }
    Ok(())
}

/// What is shown must be what is signed, and the keys were proved against this
/// vault: one that moved since (a key added, another ceremony) is not it any more.
fn ensure_same_vault(vault_path: &Path, vault: &AuthorityVault) -> Result<()> {
    if store::load(vault_path)?.fingerprint()? != vault.fingerprint()? {
        bail!("le coffre a changé depuis la validation des clés. Rien n'a été signé.");
    }
    Ok(())
}

/// Whether the document lets this credential approve: `active`, and nothing else.
fn may_approve(registry: &CredentialRegistry, credential_id: &[u8]) -> bool {
    registry
        .approvable()
        .iter()
        .any(|binding| binding.credential_id == credential_id)
}

/// A key the document marks lost or revoked opens the vault and approves nothing.
fn ensure_keys_may_approve(keys: &ValidatedKeys, registry: &CredentialRegistry) -> Result<()> {
    if keys
        .openings
        .iter()
        .all(|opening| may_approve(registry, &opening.credential_id))
    {
        Ok(())
    } else {
        Err(OpenRefusal::KeyNotApprovable.into())
    }
}

/// A client TLS window Astra has already closed at `not_after` stays open in the
/// vault until « Terminer », and only the vault says so.
fn ensure_no_window_open(keys: &ValidatedKeys) -> Result<()> {
    let opening = &keys.openings[0];
    let secrets = keys.vault.open(&opening.credential_id, &opening.secret)?;
    if secrets.retained_ca_tls.is_some() {
        return Err(OpenRefusal::CaTlsToFinish.into());
    }
    Ok(())
}

/// One CA rotation at a time, whichever (spec §5.1). During a CA-PQ overlap the
/// vault is under the new anchor while Astra and the gateway verify under the old,
/// so a transition would be refused after the touches.
fn ensure_no_overlap(authority: &OperatorAuthorityStatus) -> Result<()> {
    if authority.next_ca_fingerprint.is_some() || authority.next_ca_tls_fingerprint.is_some() {
        return Err(OpenRefusal::RotationInFlight.into());
    }
    Ok(())
}

/// Astra and this vault must name the same anchors before a campaign exists: one
/// opened over a disagreement blocks its family for five minutes, and a rotation is
/// the last thing that should reconcile the two halves of a domain.
///
/// The client TLS anchor is compared only for the rotation that replaces it. A CA-PQ
/// rotation does not depend on it, and a domain may not have pinned one yet.
fn ensure_same_anchors(authority: &OperatorAuthorityStatus, domain: &LocalDomain) -> Result<()> {
    let ca_pq_agrees = authority.ca_epoch == domain.identity.ca_epoch
        && authority.ca_fingerprint == domain.current_ca.authority_fingerprint();
    let client_tls_agrees = domain.active_certificate.as_ref().is_none_or(|active| {
        authority.ca_tls_epoch == domain.identity.ca_tls_epoch
            && authority.ca_tls_fingerprint == Some(active.fingerprint())
    });
    if !(ca_pq_agrees && client_tls_agrees) {
        return Err(OpenRefusal::AnchorsDisagree.into());
    }
    Ok(())
}

impl OpenedRotation {
    /// What the operator approves. Shown before any approval.
    pub fn manifest(&self) -> &AstraManifest {
        &self.manifest
    }

    /// Which CA this rotation replaces.
    pub fn kind(&self) -> RotationKind {
        self.kind
    }

    /// The dates the transition will carry.
    pub fn window(&self) -> TransitionWindow {
        self.schedule.window
    }

    /// The operation the approvals answer.
    pub fn operation_id(&self) -> Id16 {
        self.request.operation_id
    }

    /// When the campaign dies, and [`Self::approve`] with it.
    pub fn campaign_expires_at(&self) -> u64 {
        self.request.campaign.expires_at
    }

    /// The credentials still to answer: validated, not yet approved.
    pub fn offered(&self) -> Vec<Vec<u8>> {
        self.approval
            .offered_credentials()
            .into_iter()
            .filter(|credential_id| self.keys.is_validated(credential_id))
            .collect()
    }

    /// One touch, by whichever validated key is present: under Windows WebAuthn
    /// the key that answers is the one plugged in, and not the one awaited.
    ///
    /// A refusal loses nothing, and the same or another key can try again.
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep> {
        if now >= self.request.campaign.expires_at {
            // A dead campaign has no use for them, and they must not wait on the
            // caller dropping this value.
            self.keys.openings.clear();
        }
        // Empty only once expired, whatever a clock that moved back says now.
        if self.keys.openings.is_empty() {
            return Err(KeyStep::Expired);
        }
        let offered = self.offered();
        if offered.is_empty() {
            return Err(KeyStep::Repeated);
        }
        let assertion = key
            .approve(
                self.approval.webauthn_rp_id(),
                &offered,
                self.approval.client_data_json(),
                NO_PIN,
            )
            .map_err(|error| match error {
                AuthenticatorError::UnknownCredential => KeyStep::NotValidated,
                _ => KeyStep::Declined,
            })?;
        let credential_id = assertion.credential_id.clone();
        if !self.keys.is_validated(&credential_id) {
            return Err(KeyStep::NotValidated);
        }
        if !offered.contains(&credential_id) {
            return Err(KeyStep::Repeated);
        }
        self.approval
            .accept_for(assertion, None, now)
            .map_err(|_| KeyStep::NotValidated)?;
        self.keys
            .vault
            .slot_for_credential(&credential_id)
            .map(|slot| slot.label.clone())
            .map_err(|_| KeyStep::NotEnrolled)
    }

    /// Signs on the vault in memory, and writes the journal. Moves nothing else.
    ///
    /// An expired campaign answers [`KeyStep::Expired`], for `downcast_ref`.
    pub fn sign_and_journal(self, vault_path: &Path, now: u64) -> Result<RotationJournal> {
        let Self {
            kind,
            keys,
            domain,
            schedule,
            request,
            approval,
            ..
        } = self;
        // No openings means `approve` already saw this campaign dead, whatever the
        // clock says now.
        if now >= request.campaign.expires_at || keys.openings.is_empty() {
            return Err(KeyStep::Expired.into());
        }
        // A rotation resumed or a vault changed while the keys were being touched.
        rotation_journal::ensure_none_in_flight(vault_path)?;
        ensure_same_vault(vault_path, &keys.vault)?;
        let approval = approval.finish(now)?;

        let ValidatedKeys {
            mut vault,
            openings,
            ..
        } = keys;
        let LocalDomain {
            mut relay,
            identity,
            registry,
            active_certificate,
            ..
        } = domain;
        let (transition, next_credentials) = match active_certificate {
            None => {
                let rotated = signing::rotate_ca_pq(
                    &mut vault,
                    &[&openings[0], &openings[1]],
                    &identity,
                    Some(&registry),
                    schedule.window,
                    now,
                )?;
                relay.ca_epoch = Some(rotated.transition.next_ca_epoch);
                (
                    RotationTransition::CaPq(Box::new(rotated.transition)),
                    Some(rotated.bindings),
                )
            }
            // The relay keeps its client TLS epoch and certificate: they move at
            // the promotion, where the gateway moves its own.
            Some(active) => {
                let rotated = signing::rotate_ca_tls(
                    &mut vault,
                    &openings[0],
                    &identity,
                    &active,
                    schedule.window,
                    schedule.validity,
                )?;
                (
                    RotationTransition::CaTls(Box::new(rotated.transition)),
                    None,
                )
            }
        };
        relay.adopt(&vault)?;

        let object = match &transition {
            RotationTransition::CaPq(signed) => TrustUpdateObject::CaTransition(signed.clone()),
            RotationTransition::CaTls(signed) => {
                TrustUpdateObject::ClientTlsCaTransition(signed.clone())
            }
        };
        request
            .campaign
            .covers_authority_object(&object)
            .context("la transition signée ne correspond pas à la campagne approuvée")?;
        let result = super::campaign_result(
            &approval,
            vec![object],
            next_credentials.clone().map(Box::new),
        );

        let journal = RotationJournal {
            format_version: rotation_journal::ROTATION_JOURNAL_VERSION,
            kind,
            stage: JournalStage::Signed,
            deposit: Some(JournalDeposit {
                operation_id: request.operation_id,
                result_token: request.result_token.clone(),
                result,
            }),
            next_anchor_fingerprint: transition.next_anchor_fingerprint(),
            transition,
            next: Some(NextLocal {
                vault,
                credentials: next_credentials,
                handoff: relay,
            }),
            campaign_expires_at: request.campaign.expires_at,
            activation_at: schedule.window.activation_at,
            not_after: schedule.window.not_after,
            signed_at: now,
        };
        rotation_journal::save(&rotation_journal::path_beside(vault_path), &journal)?;
        Ok(journal)
    }
}

/// The vault in place as Astra keeps it, with no credential document.
///
/// Its compact form, whose fingerprint is [`AuthorityVault::fingerprint`]: the file
/// is pretty-printed, and Astra fingerprints the bytes it receives, so the copy
/// would otherwise read as « Ancienne » beside the vault it was just taken from.
pub fn vault_copy(vault_path: &Path) -> Result<OperatorVaultCopy> {
    let vault = store::load(vault_path)?;
    let bytes = serde_json::to_vec(&vault).context("sérialisation du coffre")?;
    Ok(OperatorVaultCopy {
        vault_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        credentials: None,
    })
}

/// Carries a rotation as far as it goes, with no key, and says where it stopped.
///
/// - [`ResumeStep::Finished`]: the copy was attempted and the journal is gone. A
///   copy that failed does not undo anything: the prerequisite reads it and the
///   screen offers to send it (spec §5.9). A client TLS rotation still has its
///   prepared record, until « Terminer ».
/// - [`ResumeStep::SendVaultCopy`]: Astra holds the copy back. The same copy passes
///   later, so the journal stays and the next look retries it.
/// - [`ResumeStep::Discard`]: nothing was announced, and the journal is gone.
/// - [`ResumeStep::GatewayOutdated`], [`ResumeStep::DomainConflict`],
///   [`ResumeStep::InstallDeadlinePassed`]: stopped, with everything in place.
///
/// An `Err` is a call that failed, and the journal says what remains. The next look
/// resumes from it.
pub fn advance(
    remote: &dyn RotationRemote,
    vault_path: &Path,
    journal: &mut RotationJournal,
    now: u64,
) -> Result<ResumeStep> {
    let mut facts = ResumeFacts {
        now,
        deposit_refused: false,
        authority: None,
        gateway_next: GatewayAnchor::NotRead,
    };
    let mut install_sent = false;
    loop {
        match next_step(journal, &facts) {
            ResumeStep::Deposit => match deposit(remote, journal) {
                Ok(()) => rotation_journal::record_accepted(vault_path, journal)?,
                Err(error) if is_a_refusal_of_the_deposit(&error) => facts.deposit_refused = true,
                Err(error) => return Err(error),
            },
            ResumeStep::ReadAuthority => facts.authority = Some(remote.authority_status()?),
            ResumeStep::ApplyLocal => {
                rotation_journal::record_accepted(vault_path, journal)?;
                rotation_journal::apply_local(vault_path, journal)?;
            }
            // A failed read goes up as such. Read as « no anchor », it would make a
            // false dead end out of a gateway that was only out of reach.
            ResumeStep::ReadGateway => {
                facts.gateway_next = remote.gateway_next_anchor(journal.kind)?.into();
            }
            ResumeStep::Install => {
                // What the gateway accepted is what it now names (spec §5.5). One
                // that says otherwise would have this loop install forever.
                if install_sent {
                    bail!("la gateway a accepté la transition et ne la nomme pas");
                }
                install(remote, journal)?;
                install_sent = true;
                facts.gateway_next = GatewayAnchor::NotRead;
            }
            ResumeStep::SendVaultCopy => return finish_with_the_copy(remote, vault_path, journal),
            ResumeStep::Discard => {
                rotation_journal::clear(&rotation_journal::path_beside(vault_path))?;
                return Ok(ResumeStep::Discard);
            }
            stop @ (ResumeStep::GatewayOutdated
            | ResumeStep::DomainConflict
            | ResumeStep::InstallDeadlinePassed
            | ResumeStep::Finished) => return Ok(stop),
        }
    }
}

/// Replays the identical deposit, which Astra treats as the same one.
fn deposit(remote: &dyn RotationRemote, journal: &RotationJournal) -> Result<()> {
    let deposit = journal
        .deposit
        .as_ref()
        .context("le journal de rotation n'a aucun dépôt à rejouer")?;
    match remote.submit_campaign(
        &deposit.operation_id,
        &deposit.result_token,
        &deposit.result,
    )? {
        SigningOperationState::Approved => Ok(()),
        SigningOperationState::AwaitingOperator => {
            bail!("Astra n'a pas enregistré ce dépôt")
        }
    }
}

/// Whether Astra answered this deposit, rather than failing to.
///
/// 429, 500 or 503 say the gateway or the authority could not answer, and say
/// nothing of this rotation: reading them as a refusal, a status read that works
/// would then discard a live rotation.
fn is_a_refusal_of_the_deposit(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<TunnelRefusal>(),
        Some(TunnelRefusal {
            status: 403 | 409,
            ..
        })
    )
}

fn install(remote: &dyn RotationRemote, journal: &RotationJournal) -> Result<()> {
    match &journal.transition {
        RotationTransition::CaPq(transition) => remote.install_ca_transition(transition),
        RotationTransition::CaTls(transition) => {
            remote.install_client_tls_ca_transition(transition)
        }
    }
}

/// The last step. The stage is written first, so a stop here resumes with the copy
/// and never asks the gateway again.
fn finish_with_the_copy(
    remote: &dyn RotationRemote,
    vault_path: &Path,
    journal: &mut RotationJournal,
) -> Result<ResumeStep> {
    let journal_path = rotation_journal::path_beside(vault_path);
    if journal.stage != JournalStage::Installed {
        let installed = RotationJournal {
            stage: JournalStage::Installed,
            ..journal.clone()
        };
        rotation_journal::save(&journal_path, &installed)?;
        *journal = installed;
    }
    match vault_copy(vault_path).and_then(|copy| remote.send_vault_copy(&copy)) {
        Ok(VaultCopySent::HeldBack) => Ok(ResumeStep::SendVaultCopy),
        Ok(VaultCopySent::Copied(_)) | Err(_) => {
            rotation_journal::clear(&journal_path)?;
            Ok(ResumeStep::Finished)
        }
    }
}

/// Why « Terminer » did not go through. Nothing moved, and no key was asked unless
/// the refusal came after it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FinishRefusal {
    /// A journal is in flight, or a record has yet to be carried by one: that rotation
    /// has not reached the gateway, and promoting would destroy the outgoing key.
    #[error("une rotation reste à reprendre avant de terminer. Rien n'a été modifié.")]
    InFlight,
    /// The overlap still runs: the gateway requires the outgoing generation.
    #[error("le recouvrement court jusqu'à {at}. Rien n'a été modifié.")]
    NotYet { at: u64 },
    /// No rotation is waiting to end.
    #[error("aucune rotation CA TLS à terminer")]
    Nothing,
    /// The vault changed between the manifest and the signature.
    #[error("le coffre a changé depuis l'affichage. Rien n'a été modifié.")]
    Moved,
    /// The vault and the record do not describe one rotation.
    #[error(
        "le coffre ne détient pas l'ancre que nomme la rotation préparée. Rien n'a été modifié."
    )]
    Mismatch,
}

/// « Terminer », read with no key: the prepared record, and what it would do.
pub struct CaTlsFinish {
    vault: AuthorityVault,
    record: prepared::PreparedRotation,
    incoming: DerCertificate,
    manifest: AstraManifest,
}

impl CaTlsFinish {
    /// Everything refused here is refused before the key.
    ///
    /// The record is the same one whichever wrote it, and it names the certificate
    /// because the journal is gone by now. It must have been through a journal, which
    /// is what proves the gateway named the anchor. A record `astra-signer` left is
    /// adopted by the resumption first, and comes back here marked so.
    pub fn begin(vault_path: &Path, now: u64) -> Result<Self> {
        rotation_journal::ensure_none_in_flight(vault_path).context(FinishRefusal::InFlight)?;
        let record =
            prepared::load(&prepared::path_beside(vault_path))?.ok_or(FinishRefusal::Nothing)?;
        if !record.submitted || !record.adopted {
            return Err(FinishRefusal::InFlight.into());
        }
        if now < record.not_after {
            return Err(FinishRefusal::NotYet {
                at: record.not_after,
            }
            .into());
        }
        let vault = store::load(vault_path)?;
        let incoming = DerCertificate::parse(&record.next_ca_tls_certificate)
            .context(FinishRefusal::Mismatch)?;
        let manifest = finish_manifest(vault_path, &vault, &record, &incoming)?;
        Ok(Self {
            vault,
            record,
            incoming,
            manifest,
        })
    }

    /// What the touch does.
    pub fn manifest(&self) -> &AstraManifest {
        &self.manifest
    }

    /// One touch: this executes what two keys approved, and authorises nothing new.
    pub fn open(&self, key: &dyn Authenticator) -> Result<Opened, KeyStep> {
        gestures::open_with_authorized_key(key, &self.vault, NO_PIN).map_err(key_step_of_opening)
    }

    /// Moves the vault, then the relay, clears the record and sends the copy.
    ///
    /// Each write is atomic and this order survives a stop anywhere in it. A stop
    /// after the vault leaves [`CaTlsAdvance::Idle`] beside a record still there, so
    /// that state finishes the relay, once the vault proves it holds that certificate.
    /// As after a rotation, a copy that fails undoes nothing: the prerequisite reads
    /// what Astra holds, and the screen offers to send it (spec §5.9).
    ///
    /// Takes the opening so as to wipe it before the copy, a network call nothing in
    /// it is needed for.
    pub fn finish(
        self,
        remote: &dyn RotationRemote,
        vault_path: &Path,
        opening: Opened,
        now: u64,
    ) -> Result<()> {
        let Self {
            mut vault,
            record,
            incoming,
            ..
        } = self;
        // The operator may have stood at the prompt for a while.
        rotation_journal::ensure_none_in_flight(vault_path).context(FinishRefusal::InFlight)?;
        if store::load(vault_path)?.fingerprint()? != vault.fingerprint()? {
            return Err(FinishRefusal::Moved.into());
        }
        ensure_vault_holds(&vault, &opening, &incoming)?;
        match signing::advance_ca_tls(&mut vault, &opening, now)? {
            CaTlsAdvance::Rotated { .. } => store::save(vault_path, &vault)?,
            CaTlsAdvance::Idle => {}
            CaTlsAdvance::Awaiting { at } => return Err(FinishRefusal::NotYet { at }.into()),
        }
        let mut relay = DomainHandoff::beside(vault_path, &vault)?;
        relay.ca_tls_epoch = Some(record.next_ca_tls_epoch);
        relay.ca_tls_certificate = Some(record.next_ca_tls_certificate);
        handoff::save(&handoff::path_beside(vault_path), &relay)?;
        prepared::clear(&prepared::path_beside(vault_path))?;
        drop(opening);
        let _ = vault_copy(vault_path).and_then(|copy| remote.send_vault_copy(&copy));
        Ok(())
    }
}

/// The vault's window names `incoming`, or it has closed on it. Checked before the
/// vault moves: an advance destroys the outgoing key, and a relay naming another
/// certificate than the key would have nothing issue under it.
fn ensure_vault_holds(
    vault: &AuthorityVault,
    opening: &Opened,
    incoming: &DerCertificate,
) -> Result<()> {
    let holds = match vault.ca_tls_window(&opening.credential_id, &opening.secret)? {
        Some((fingerprint, _)) => fingerprint == incoming.fingerprint().to_hex(),
        None => signing::issues_under(vault, opening, incoming)?,
    };
    if holds {
        Ok(())
    } else {
        Err(FinishRefusal::Mismatch.into())
    }
}

fn finish_manifest(
    vault_path: &Path,
    vault: &AuthorityVault,
    record: &prepared::PreparedRotation,
    incoming: &DerCertificate,
) -> Result<AstraManifest> {
    let relay = DomainHandoff::beside(vault_path, vault)?;
    let outgoing = DerCertificate::parse(relay.require(
        relay.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS en service",
        "--ca-tls-certificate",
    )?)?;
    Ok(AstraManifest::CaRotation(CaRotationManifest {
        trust_domain_id: vault.trust_domain_id,
        affected_ca: AffectedCa::CaTls,
        current_epoch: record.next_ca_tls_epoch.saturating_sub(1),
        next_epoch: record.next_ca_tls_epoch,
        activation_at: record.activation_at,
        not_after: record.not_after,
        outgoing_anchor_fingerprint: outgoing.fingerprint(),
        next_anchor_fingerprint: Some(incoming.fingerprint()),
        campaign: None,
    }))
}

#[cfg(test)]
mod tests;
