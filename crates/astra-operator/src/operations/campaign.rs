//! §8.5, as a ceremony rather than as a command.
//!
//! # Two keys, and why they are asked for one at a time
//!
//! A campaign names how many distinct credentials must approve it. Two touches
//! of the same token is exactly what [`crate::signing::approve_campaign`]
//! refuses, and refusing it after both gestures would waste the operator's
//! window on a decision they cannot un-take. So the keys are collected one
//! after another, each connection its own, and the second one is asked for
//! only once the first has answered — which is also how an operator discovers,
//! at the second prompt, that they were about to use the same key twice.
//!
//! # What this ceremony refuses to be
//!
//! Only client-leaf campaigns are accepted here. Every other family produces
//! an object in the same ceremony as its approval, so submitting the empty
//! result used for client leaves would spend a gesture and then be refused.
//!
//! # Où sont les tests
//!
//! Ce module n'assemble que des entrées déjà vérifiées ailleurs : la campagne
//! est authentifiée par [`crate::handoff::verify_campaign_request`] et le geste
//! par [`crate::signing::approve_campaign`], tous deux éprouvés contre des
//! clés simulées dans `tests/signing.rs`. Y ajouter un test qui n'exerce ni
//! l'un ni l'autre donnerait l'apparence d'une couverture sans la substance.

use std::path::Path;

use aether::certificates::encoding::{Id16, MlDsa87PublicKey};
use aether::certificates::operator_session::{CampaignManifest, RemoteState};
use aether::certificates::status::{AstraRotationCampaign, CampaignApproval};
use anyhow::{bail, Context, Result};

use crate::authenticator::Authenticator;
use crate::vault::AuthorityVault;
use crate::{credentials, handoff, origin, signing, store};

/// A campaign whose every input has been verified, waiting on the keys.
pub struct Verified {
    vault: AuthorityVault,
    identity: signing::DomainIdentity,
    registry: credentials::CredentialRegistry,
    ca_pq_public_key: MlDsa87PublicKey,
    client: origin::Origin,
    request: Box<origin::CampaignRequest>,
    campaign: Box<AstraRotationCampaign>,
    webauthn_origin: String,
    manifest: CampaignManifest,
}

impl Verified {
    /// What the operator is approving. Rendered before any key is touched.
    pub fn manifest(&self) -> &CampaignManifest {
        &self.manifest
    }

    /// How many distinct credentials this campaign requires.
    pub fn required_credentials(&self) -> u8 {
        self.campaign.required_credentials
    }

    pub fn operation(&self) -> Id16 {
        self.request.operation_id
    }
}

/// Fetches the campaign, verifies it against the pinned hand-off, describes it.
///
/// Opens nothing and asks for nothing. The origin comes from the hand-off, for
/// the reason it does everywhere here: a process holding `CA-PQ` that learned
/// where to send its signatures from whoever asked would authenticate nothing.
pub fn begin(
    vault_path: &Path,
    operation: Id16,
    offered_authority_url: Option<&str>,
    offered_webauthn_origin: Option<&str>,
    now: u64,
) -> Result<Verified> {
    let vault = store::load(vault_path)?;
    let handoff = handoff::DomainHandoff::beside(vault_path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(vault_path))?.ok_or_else(|| {
        anyhow::anyhow!(
            "aucun document de credentials à côté du coffre : sans lui, aucune approbation ne \
             peut être rattachée à une clé enrôlée"
        )
    })?;

    let authority_url = super::resolve_authority_url(
        handoff.astra_authority_url.as_deref(),
        offered_authority_url,
    )?;
    let client = origin::Origin::new(&authority_url)?;
    let request = client.fetch(&operation)?;
    handoff::verify_campaign_request(&handoff, &vault, &request, &authority_url, now)?;
    let campaign = request.campaign.as_ref().clone();

    if !campaign.scope.authorizes_client_rotation() {
        bail!(
            "cette campagne ne renouvelle pas des certificats clients : sa décision et les \
             objets qu'elle produit doivent voyager dans une cérémonie dédiée. Rien n'a été \
             signé."
        );
    }

    let manifest = CampaignManifest {
        campaign: Box::new(campaign.clone()),
        fingerprint: campaign.fingerprint(),
    };

    Ok(Verified {
        vault,
        identity,
        registry,
        ca_pq_public_key,
        client,
        request: Box::new(request),
        campaign: Box::new(campaign),
        webauthn_origin: offered_webauthn_origin
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://{}", handoff.rp_id)),
        manifest,
    })
}

impl Verified {
    /// Starts the credential session without touching a key.
    pub fn start_approval(self, now: u64) -> Result<InProgressApproval> {
        let approval = signing::CampaignApprovalSession::new(
            &self.campaign,
            &self.registry,
            &self.identity,
            &self.ca_pq_public_key,
            &self.vault.rp_id,
            &self.webauthn_origin,
            now,
        )?;
        Ok(InProgressApproval {
            vault: self.vault,
            client: self.client,
            operation: self.request.operation_id,
            result_token: self.request.result_token.clone(),
            approval,
        })
    }
}

/// A campaign whose assertions are collected while each physical key is
/// still connected.
///
/// A Windows WebAuthn value is a platform selector, not a handle bound to the
/// token present when `connect` ran. Delaying all assertions until after the
/// key swaps therefore lets the last token answer every stored selector. This
/// type makes the assertion itself the per-key operation.
pub struct InProgressApproval {
    vault: AuthorityVault,
    client: origin::Origin,
    operation: Id16,
    result_token: String,
    approval: signing::CampaignApprovalSession,
}

impl InProgressApproval {
    pub fn required_credentials(&self) -> u8 {
        u8::try_from(self.approval.required()).unwrap_or(u8::MAX)
    }

    /// Obtains and validates one assertion now, before the caller asks for the
    /// next physical key.
    pub fn approve_key(&mut self, key: &dyn Authenticator, pin: &str, now: u64) -> Result<String> {
        let offered = self.approval.offered_credentials();
        let assertion = key.approve(
            self.approval.webauthn_rp_id(),
            &offered,
            self.approval.client_data_json(),
            pin,
        )?;
        let credential_id = assertion.credential_id.clone();
        self.approval.accept(assertion, now)?;
        Ok(self
            .vault
            .slot_for_credential(&credential_id)?
            .label
            .clone())
    }

    /// Finishes the already-collected decision and deposits it.
    pub fn finish(
        self,
        now: u64,
        progress: &mut dyn FnMut(RemoteState),
    ) -> Result<CampaignApproval> {
        let approval = self.approval.finish(now)?;
        progress(RemoteState::Prepared);

        let result = super::campaign_result(&approval, Vec::new(), None);
        self.client
            .submit(&self.operation, &self.result_token, &result)
            .context("dépôt de l'approbation")?;
        progress(RemoteState::Deposited);
        Ok(approval)
    }
}
