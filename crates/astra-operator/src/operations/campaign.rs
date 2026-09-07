//! §8.5, as a ceremony rather than as a command.
//!
//! # Two keys, and why they are asked for one at a time
//!
//! A campaign names how many distinct credentials must approve it. Two touches
//! of the same token is exactly what [`crate::authority::approve_campaign`]
//! refuses, and refusing it after both gestures would waste the operator's
//! window on a decision they cannot un-take. So the keys are collected one
//! after another, each connection its own, and the second one is asked for
//! only once the first has answered — which is also how an operator discovers,
//! at the second prompt, that they were about to use the same key twice.
//!
//! # What this ceremony refuses to be
//!
//! Two campaign families are declined here by name rather than run: one that
//! withdraws an identity, and one that rotates an anchor. Neither is an
//! approval followed by an application — the approval and the objects `CA-PQ`
//! signs travel in a single deposit (§0.6) — so taking the touch here would
//! spend the operator's window on a result that carries nothing.
//!
//! # Où sont les tests
//!
//! Ce module n'assemble que des entrées déjà vérifiées ailleurs : la campagne
//! est authentifiée par [`crate::handoff::verify_campaign_request`] et le geste
//! par [`crate::authority::approve_campaign`], tous deux éprouvés contre des
//! clés simulées dans `tests/authority.rs`. Y ajouter un test qui n'exerce ni
//! l'un ni l'autre donnerait l'apparence d'une couverture sans la substance.

use std::path::Path;

use aether::certificates::encoding::{Id16, MlDsa87PublicKey};
use aether::certificates::operator_session::{AffectedCa, CampaignManifest, RemoteState};
use aether::certificates::status::{AstraRotationCampaign, CampaignApproval};
use anyhow::{bail, Context, Result};

use crate::authenticator::Authenticator;
use crate::vault::AuthorityVault;
use crate::{authority, credentials, handoff, origin, store};

/// A campaign whose every input has been verified, waiting on the keys.
pub struct Verified {
    vault: AuthorityVault,
    identity: authority::DomainIdentity,
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

    if campaign.scope.revokes() {
        bail!(
            "cette campagne retire une identité : elle se dépose en un seul geste, avec la \
             décision signée. Rien n'a été signé."
        );
    }
    if campaign.scope.rotates_authority() {
        bail!(
            "cette campagne fait tourner une ancre : l'approbation et les objets que `CA-PQ` \
             signe voyagent dans un seul dépôt (§0.6). Rien n'a été signé."
        );
    }

    let manifest = CampaignManifest {
        trust_domain_id: identity.trust_domain_id,
        reason: campaign.reason.clone(),
        requested_by: campaign.requested_by.clone(),
        fingerprint: campaign.fingerprint(),
        // Client leaves are what an ordinary campaign moves; the two families
        // that touch an authority are refused above.
        affected_ca: AffectedCa::CaTls,
        current_epoch: identity.ca_tls_epoch,
        next_epoch: identity.ca_tls_epoch,
        activation_at: campaign.created_at,
        not_after: campaign.expires_at,
        outgoing_anchor_fingerprint: aether::certificates::encoding::Fingerprint::of(
            ca_pq_public_key.as_bytes(),
        ),
        target_count: campaign.targets.len(),
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
    /// Signs the approval with the keys collected and submits it.
    ///
    /// `keys` and `pins` are positional and must be as long as
    /// [`Self::required_credentials`]. They are collected by the caller, one
    /// gesture at a time, because that is the only order in which an operator
    /// finds out at the *second* prompt that they were about to reuse one
    /// token — rather than after both.
    pub fn approve(
        self,
        keys: &[&dyn Authenticator],
        pins: &[&str],
        now: u64,
        progress: &mut dyn FnMut(RemoteState),
    ) -> Result<CampaignApproval> {
        let required = usize::from(self.campaign.required_credentials);
        if keys.len() != required || pins.len() != required {
            bail!("cette campagne demande {required} clé(s) distincte(s)");
        }
        let approval = authority::approve_campaign(
            keys,
            &self.campaign,
            &self.registry,
            &self.identity,
            &self.ca_pq_public_key,
            &self.vault.rp_id,
            &self.webauthn_origin,
            pins,
            now,
        )?;
        progress(RemoteState::Prepared);

        let result = super::campaign_result(&approval, Vec::new(), None);
        self.client
            .submit(
                &self.request.operation_id,
                &self.request.result_token,
                &result,
            )
            .context("dépôt de l'approbation")?;
        progress(RemoteState::Deposited);
        Ok(approval)
    }
}
