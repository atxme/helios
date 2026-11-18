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
//! The ceremony tests use signed Astra requests, the real vault and simulated
//! authenticator assertions. The fetch and deposit are replaced at the transport
//! boundary so the tests can check the exact result and progress events.

use std::path::Path;

use aether::certificates::encoding::{Id16, MlDsa87PublicKey};
use aether::certificates::operator_session::{CampaignManifest, RemoteState};
use aether::certificates::status::{AstraRotationCampaign, AstraSignerResult, CampaignApproval};
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
    begin_with_fetch(
        vault_path,
        operation,
        offered_authority_url,
        offered_webauthn_origin,
        now,
        origin::Origin::fetch,
    )
}

fn begin_with_fetch(
    vault_path: &Path,
    operation: Id16,
    offered_authority_url: Option<&str>,
    offered_webauthn_origin: Option<&str>,
    now: u64,
    fetch: impl FnOnce(&origin::Origin, &Id16) -> Result<origin::CampaignRequest>,
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
    let request = fetch(&client, &operation)?;
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
        self.finish_with_submit(now, progress, |client, operation, token, result| {
            client.submit(operation, token, result).map(|_| ())
        })
    }

    fn finish_with_submit(
        self,
        now: u64,
        progress: &mut dyn FnMut(RemoteState),
        submit: impl FnOnce(&origin::Origin, &Id16, &str, &AstraSignerResult) -> Result<()>,
    ) -> Result<CampaignApproval> {
        let approval = self.approval.finish(now)?;
        progress(RemoteState::Prepared);

        let result = super::campaign_result(&approval, Vec::new(), None);
        submit(&self.client, &self.operation, &self.result_token, &result)
            .context("dépôt de l'approbation")?;
        progress(RemoteState::Deposited);
        Ok(approval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::fixtures::{domain, operation, Domain, EXPIRES, NOW};
    use aether::certificates::{
        encoding::{Fingerprint, WireGuardKey},
        status::{CampaignScope, CampaignTarget, CertificateKind},
    };
    use std::cell::RefCell;

    fn client_campaign(domain: &Domain) -> AstraRotationCampaign {
        domain.campaign(
            CampaignScope::OrionProfile,
            vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientTls,
                identity_key: WireGuardKey::from_bytes([7; 32]),
                epoch: 1,
                generation: 1,
                active_tls_certificate_fingerprint: Fingerprint::of(b"active TLS leaf"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"active PQ leaf"),
            }],
            EXPIRES,
        )
    }

    fn verify(domain: &Domain, request: origin::CampaignRequest) -> Result<Verified> {
        begin_with_fetch(&domain.path, operation(), None, None, NOW, |_, id| {
            assert_eq!(*id, operation());
            Ok(request)
        })
    }

    #[test]
    fn verified_client_campaign_deposits_only_the_approval_shown_to_the_operator() {
        let domain = domain();
        let campaign = client_campaign(&domain);
        let request = domain.request(campaign.clone());
        let token = request.result_token.clone();
        let verified = verify(&domain, request).expect("verify signed campaign");
        assert_eq!(verified.manifest().campaign.as_ref(), &campaign);
        assert_eq!(verified.manifest().fingerprint, campaign.fingerprint());
        assert_eq!(verified.required_credentials(), 1);
        assert_eq!(verified.operation(), operation());
        assert_eq!(domain.touches(), 0);

        let mut approval = verified.start_approval(NOW).expect("prepare assertion");
        assert_eq!(approval.required_credentials(), 1);
        let label = approval
            .approve_key(&domain.keys[0], "", NOW)
            .expect("approve");
        assert_eq!(label, "Clé 1");
        assert_eq!(domain.keys[0].touches.get(), 1);

        let events = RefCell::new(Vec::new());
        let mut deposited = None;
        let decision = approval
            .finish_with_submit(
                NOW,
                &mut |state| events.borrow_mut().push(state),
                |_, id, result_token, result| {
                    assert_eq!(*events.borrow(), [RemoteState::Prepared]);
                    assert_eq!(*id, operation());
                    assert_eq!(result_token, token);
                    assert!(result.objects.is_empty());
                    assert!(result.credential_registry.is_none());
                    assert!(result.issuer_authorization.is_none());
                    deposited = Some(result.approval.as_ref().clone());
                    Ok(())
                },
            )
            .expect("deposit the approval");
        assert_eq!(deposited, Some(decision.clone()));
        assert_eq!(decision.campaign_fingerprint, campaign.fingerprint());
        assert_eq!(
            *events.borrow(),
            [RemoteState::Prepared, RemoteState::Deposited]
        );
    }

    #[test]
    fn a_different_campaign_family_or_rp_id_is_refused_without_a_hardware_gesture() {
        let domain = domain();
        let request = domain.request(domain.authority_campaign(EXPIRES));
        let Err(error) = verify(&domain, request) else {
            panic!("an anchor campaign requires another ceremony");
        };
        assert!(error.to_string().contains("cérémonie dédiée"), "{error}");

        let mut request = domain.request(client_campaign(&domain));
        request.webauthn_rp_id = "other.example.test".into();
        let Err(error) = verify(&domain, request) else {
            panic!("the pinned relying party must match");
        };
        assert!(error.to_string().contains("RP ID"), "{error}");
        assert_eq!(domain.touches(), 0);
    }

    #[test]
    fn an_origin_that_conflicts_with_the_relay_is_refused_before_fetch() {
        let domain = domain();
        let Err(error) = begin_with_fetch(
            &domain.path,
            operation(),
            Some("https://other.example.test"),
            None,
            NOW,
            |_, _| panic!("a conflicting origin must never receive a request"),
        ) else {
            panic!("the caller cannot override the relay");
        };
        assert!(error.to_string().contains("origine"), "{error}");
        assert_eq!(domain.touches(), 0);
    }

    #[test]
    fn a_declined_key_does_not_allow_deposit_and_a_failed_deposit_stays_prepared() {
        let domain = domain();
        let start = || {
            verify(&domain, domain.request(client_campaign(&domain)))
                .expect("verify signed campaign")
                .start_approval(NOW)
                .expect("prepare assertion")
        };

        let mut refused = start();
        domain.keys[0].declines.set(true);
        assert!(refused.approve_key(&domain.keys[0], "", NOW).is_err());
        assert!(refused
            .finish_with_submit(
                NOW,
                &mut |_| panic!("no approval to report"),
                |_, _, _, _| panic!("a declined gesture authorizes nothing"),
            )
            .is_err());

        let mut approved = start();
        approved
            .approve_key(&domain.keys[1], "", NOW)
            .expect("approve with a recovery key");
        let mut events = Vec::new();
        let error = approved
            .finish_with_submit(NOW, &mut |state| events.push(state), |_, _, _, _| {
                bail!("fixture deposit error")
            })
            .expect_err("report a failed deposit");
        assert_eq!(error.to_string(), "dépôt de l'approbation");
        assert_eq!(events, [RemoteState::Prepared]);
    }
}
