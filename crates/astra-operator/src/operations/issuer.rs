//! §9.5, `authorize-issuer`, as a ceremony rather than as a command.
//!
//! # Plan, then gesture
//!
//! [`plan`] reads the domain and the delegation request and refuses, as an
//! [`IssuerRefusal`], everything predictable — a domain without a `CA-TLS`
//! able to back the whole delegation window, a file that is not a request, a
//! campaign of another family or that does not name this request, an offline
//! delegation for a domain that has an origin — before any key is asked
//! anything. It settles the bounds, the leaf lifetime
//! already capped by the pinned policy, and the [`IssuerManifest`] the
//! operator reads: the value shown is the value signed.
//!
//! The gesture settles the plan again from the domain as it is when the key
//! is pressed, and refuses one that moved ([`IssuerRefusal::PlanChanged`]). A
//! plan is engine state, not proof: the interface disabling a button
//! guarantees nothing.
//!
//! The manifest's `request_fingerprint` is the SHA-256 of the compact JSON
//! re-encoding of the parsed request, fields in declaration order — not the
//! hash of the file as read, which `settle_again` could not reproduce from
//! the plan. The values that bind what is certified are the two key
//! fingerprints beside it.
//!
//! # Two paths, and why the campaign is the ordinary one
//!
//! An [`IssuerDelegationRequest`] carries no signature. Read from a file, it
//! authorizes whoever handed the operator that file. The campaign, signed by
//! the authority's service key, pins the epoch and both public halves; the
//! request is checked against it before the key is touched.
//! [`CampaignDelegation::approve_and_sign`] asks for **one** key: its
//! assertion approves the campaign, and the vault then opens only for the
//! credential that answered ([`gestures::open_with_credential`]).
//!
//! [`sign_offline`] survives for a domain whose relay names no Astra origin,
//! and only for it: a domain that has an origin has a campaign path, and a
//! file is then the weaker of two options for no reason.
//!
//! Every [`Opened`] handled here is secret: none is logged, serialized nor
//! shown.
//!
//! # Where the tests are
//!
//! `tests/issuer_delegation.rs` exercises the plan, the offline signature,
//! the campaign verification ([`CampaignDelegation::from_request`]), the
//! one-key approval and restricted opening
//! ([`CampaignDelegation::sign_in_campaign`]) against simulated keys. What
//! remains untested is the network itself — [`CampaignDelegation::begin`]'s
//! fetch and the deposit in [`CampaignDelegation::approve_and_sign`] — as in
//! [`super::campaign`]: both only carry values verified by the functions
//! above.

use std::path::Path;

use aether::certificates::approval::AstraIssuancePolicy;
use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
use aether::certificates::encoding::{
    DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId,
};
use aether::certificates::operator_session::{CampaignManifest, IssuerManifest, RemoteState};
use aether::certificates::status::{AstraRotationCampaign, CampaignApproval, CampaignFamily};
use anyhow::{bail, Context, Result};
use base64::Engine as _;

use crate::authenticator::{Authenticator, Opened};
use crate::signing::{DelegationBounds, DomainIdentity, IssuerDelegationRequest};
use crate::vault::AuthorityVault;
use crate::vault_gestures::DAY_SECS;
use crate::{credentials, gestures, handoff, origin, signing, store};

/// Lifetime of one delegation, in days — `astra-signer`'s.
pub const DELEGATION_DAYS: u64 = 30;

/// Longest leaf the delegated issuer may sign, in days, before the pinned
/// policy's cap is applied.
pub const LEAF_DAYS: u64 = 90;

/// The largest request read, the bound the interface applies to the file it
/// reads.
pub const MAX_DELEGATION_REQUEST_BYTES: usize = 256 * 1024;

/// The name an offline authorization is handed over under.
pub const AUTHORIZATION_FILE: &str = "issuer-authorization.json";

const DELEGATION_SECS: u64 = DELEGATION_DAYS * DAY_SECS;
const LEAF_SECS: u64 = LEAF_DAYS * DAY_SECS;

/// What a delegation refuses before any key is asked anything.
///
/// Closed, so the ceremony maps each variant to a refusal of its own; the
/// sentence below is for logs. [`IssuerRefusal::Vault`] carries the error
/// chain of a vault or relay that could not be read, which names files and
/// fields, never their secret contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuerRefusal {
    #[error("ce fichier n'est pas une demande de délégation d'émetteur lisible")]
    RequestInvalid,
    #[error(
        "la demande de délégation n'est pas celle que la campagne nomme, ou vise un autre \
         domaine : époque ou clé substituée. Rien n'a été signé."
    )]
    RequestMismatch,
    #[error("cette opération n'autorise pas de délégation d'émetteur. Rien n'a été signé.")]
    NotADelegation,
    #[error(
        "le relais de domaine nomme une origine Astra : une délégation passe alors par une \
         campagne (`astra issuer request --reason --requested-by` sur l'hôte d'Astra)"
    )]
    OriginRecorded,
    #[error("ce domaine ne porte pas encore de CA-TLS : finaliser le domaine avant de déléguer")]
    CaTlsMissing,
    #[error(
        "la CA-TLS de ce domaine ne peut pas porter cette délégation : elle n'est pas une \
         autorité de certification, ou ne couvre pas toute la fenêtre de délégation"
    )]
    CaTlsUnusable,
    #[error(
        "le domaine ou la campagne a changé depuis l'affichage de ce qui allait être signé : \
         recommencer le geste. Rien n'a été signé."
    )]
    PlanChanged,
    #[error("coffre ou relais de domaine illisible : {0}")]
    Vault(String),
}

/// What a delegation will sign, settled before any key is asked anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerPlan {
    pub request: IssuerDelegationRequest,
    pub bounds: DelegationBounds,
    pub manifest: IssuerManifest,
}

/// The domain as a delegation reads it.
struct Domain {
    vault: AuthorityVault,
    relay: handoff::DomainHandoff,
    identity: DomainIdentity,
    ca_tls: DerCertificate,
    policy: AstraIssuancePolicy,
}

/// What the request asks to be certified, read without trusting it.
struct Material {
    trust_domain_id: TrustDomainId,
    pq_fingerprint: Fingerprint,
    spki_fingerprint: Fingerprint,
}

/// What delegating to the issuer of `request_json` will sign, or why it is
/// refused. Writes nothing and asks no key anything.
///
/// With `campaign`, the request must be the one it names. The campaign is not
/// authenticated here: [`CampaignDelegation::begin`] did that, and
/// [`CampaignDelegation::approve_and_sign`] settles this plan again against
/// the campaign it verified. Without one, the relay must name no origin.
pub fn plan(
    vault_path: &Path,
    request_json: &str,
    campaign: Option<&AstraRotationCampaign>,
    now_unix: u64,
) -> std::result::Result<IssuerPlan, IssuerRefusal> {
    let domain = read_domain(vault_path)?;
    if request_json.len() > MAX_DELEGATION_REQUEST_BYTES {
        return Err(IssuerRefusal::RequestInvalid);
    }
    let request: IssuerDelegationRequest =
        serde_json::from_str(request_json).map_err(|_| IssuerRefusal::RequestInvalid)?;
    plan_for(&domain, request, campaign, now_unix)
}

/// Signs the delegation of an offline plan, with an opening the ceremony
/// already holds.
///
/// The plan is settled again from the domain as it is now, at the instant it
/// was shown for, and must be the one shown: a relay that gained an origin in
/// between is refused as [`IssuerRefusal::OriginRecorded`], any other change
/// as [`IssuerRefusal::PlanChanged`].
pub fn sign_offline(
    vault_path: &Path,
    plan: &IssuerPlan,
    opened: &Opened,
    now_unix: u64,
) -> Result<AstraIssuerAuthorization> {
    if plan.manifest.campaign.is_some() {
        bail!(
            "ce plan nomme une campagne : sa délégation se signe dans la campagne, avec son \
             approbation. Rien n'a été signé."
        );
    }
    let domain = settle_again(vault_path, plan, None, now_unix)?;
    Ok(signing::authorize_issuer(
        &domain.vault,
        opened,
        &domain.identity,
        &domain.ca_tls,
        &plan.request,
        &plan.bounds,
        now_unix,
    )?)
}

/// A delegation campaign fetched from the relay's origin and verified,
/// waiting on the key.
pub struct CampaignDelegation {
    campaign: Box<AstraRotationCampaign>,
    client: origin::Origin,
    operation: Id16,
    result_token: String,
}

impl CampaignDelegation {
    /// Fetches the campaign from the relay's origin and verifies it, as
    /// [`Self::from_request`] does.
    ///
    /// The origin is the relay's and nobody else's: a process holding
    /// `CA-PQ` that learned where to send its signatures from whoever asked
    /// would authenticate nothing. Opens nothing and asks for nothing.
    pub fn begin(vault_path: &Path, operation: Id16, now_unix: u64) -> Result<CampaignDelegation> {
        let (_, _, authority_url) = relay_authority(vault_path)?;
        let request = origin::Origin::new(&authority_url)?.fetch(&operation)?;
        Self::from_request(vault_path, request, now_unix)
    }

    /// Verifies a campaign request against the pinned relay, and requires it
    /// to be a delegation.
    ///
    /// The request is authenticated by the service key the relay pins, not by
    /// the channel it came through: the signed request must name the relay's
    /// origin and this exact campaign. Both bindings [`origin::Origin::fetch`]
    /// checks are checked again here, so a request that did not come through
    /// it is held to the same rule. Opens nothing and asks for nothing.
    pub fn from_request(
        vault_path: &Path,
        request: origin::CampaignRequest,
        now_unix: u64,
    ) -> Result<CampaignDelegation> {
        let (vault, relay, authority_url) = relay_authority(vault_path)?;
        if request.signer_request.operation_id != request.operation_id {
            bail!(
                "la demande signée porte l'opération {} et non {}",
                request.signer_request.operation_id.to_hex(),
                request.operation_id.to_hex()
            );
        }
        request
            .campaign
            .assert_unchanged(&request.signer_request.campaign_fingerprint)
            .context("la campagne n'est pas celle que la demande signée nomme")?;
        handoff::verify_campaign_request(&relay, &vault, &request, &authority_url, now_unix)?;
        if !matches!(
            request.campaign.scope.family(),
            CampaignFamily::IssuerDelegation
        ) {
            return Err(IssuerRefusal::NotADelegation.into());
        }
        Ok(CampaignDelegation {
            campaign: request.campaign,
            client: origin::Origin::new(&authority_url)?,
            operation: request.operation_id,
            result_token: request.result_token,
        })
    }

    /// The verified campaign, for [`plan`] and for the manifest.
    pub fn campaign(&self) -> &AstraRotationCampaign {
        &self.campaign
    }

    /// [`Self::sign_in_campaign`], then the deposit of the approval and the
    /// delegation on the origin.
    pub fn approve_and_sign(
        self,
        vault_path: &Path,
        plan: &IssuerPlan,
        key: &dyn Authenticator,
        pin: &str,
        now_unix: u64,
        progress: &mut dyn FnMut(RemoteState),
    ) -> Result<()> {
        let (approval, authorization) =
            self.sign_in_campaign(vault_path, plan, key, pin, now_unix)?;
        progress(RemoteState::Prepared);

        let mut result = super::campaign_result(&approval, Vec::new(), None);
        result.issuer_authorization = Some(Box::new(authorization));
        self.client
            .submit(&self.operation, &self.result_token, &result)
            .context("dépôt de la délégation")?;
        progress(RemoteState::Deposited);
        Ok(())
    }

    /// Approves the campaign with one key, opens the vault with that same
    /// credential and signs the delegation. Deposits nothing.
    ///
    /// Everything that can be refused without the key is refused first: a
    /// campaign asking for more than one credential, a plan that does not
    /// settle again against this campaign, the credential document and the
    /// policy pin. Only credentials that hold a slot of this vault are
    /// offered, so a binding the vault no longer knows cannot spend a press
    /// on an approval that could never open it. The vault then opens only
    /// for the credential that approved: under a platform transport the two
    /// are two dialogs, and another key presented to the second cannot
    /// answer it.
    pub fn sign_in_campaign(
        &self,
        vault_path: &Path,
        plan: &IssuerPlan,
        key: &dyn Authenticator,
        pin: &str,
        now_unix: u64,
    ) -> Result<(CampaignApproval, AstraIssuerAuthorization)> {
        if self.campaign.required_credentials != 1 {
            bail!(
                "cette campagne exige {} credentials : une délégation d'émetteur s'approuve avec \
                 une seule clé, celle qui ouvre ensuite le coffre. Rien n'a été signé.",
                self.campaign.required_credentials
            );
        }
        let domain = settle_again(vault_path, plan, Some(&*self.campaign), now_unix)?;
        let registry =
            credentials::load(&credentials::path_beside(vault_path))?.ok_or_else(|| {
                anyhow::anyhow!(
                    "aucun document de credentials à côté du coffre : sans lui, aucune \
                     approbation ne peut être rattachée à une clé enrôlée"
                )
            })?;
        let ca_pq_public_key = MlDsa87PublicKey::parse(&domain.relay.ca_pq_public_key)?;
        let webauthn_origin = format!("https://{}", domain.relay.rp_id);
        let mut session = signing::CampaignApprovalSession::new(
            &self.campaign,
            &registry,
            &domain.identity,
            &ca_pq_public_key,
            &domain.vault.rp_id,
            &webauthn_origin,
            now_unix,
        )?;
        let offered: Vec<Vec<u8>> = session
            .offered_credentials()
            .into_iter()
            .filter(|credential_id| domain.vault.slot_for_credential(credential_id).is_ok())
            .collect();
        if offered.is_empty() {
            bail!(
                "aucune clé approuvable du document de credentials ne détient de place dans ce \
                 coffre : le document et le coffre ne décrivent plus les mêmes clés. Rien n'a \
                 été signé."
            );
        }

        let assertion = key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            pin,
        )?;
        let approving_credential_id = assertion.credential_id.clone();
        session.accept(assertion, now_unix)?;
        let approval = session.finish(now_unix)?;

        let opened =
            gestures::open_with_credential(key, &domain.vault, &approving_credential_id, pin)?;
        let authorization = signing::authorize_issuer(
            &domain.vault,
            &opened,
            &domain.identity,
            &domain.ca_tls,
            &plan.request,
            &plan.bounds,
            now_unix,
        )?;
        drop(opened);
        Ok((approval, authorization))
    }
}

/// The vault, the relay, and the origin the relay pins.
fn relay_authority(vault_path: &Path) -> Result<(AuthorityVault, handoff::DomainHandoff, String)> {
    let vault = store::load(vault_path)?;
    let relay = handoff::DomainHandoff::beside(vault_path, &vault)?;
    let authority_url = super::resolve_authority_url(relay.astra_authority_url.as_deref(), None)?;
    Ok((vault, relay, authority_url))
}

/// The vault, the relay, the identity, `CA-TLS` and the pinned policy.
fn read_domain(vault_path: &Path) -> std::result::Result<Domain, IssuerRefusal> {
    let vault = store::load(vault_path).map_err(unreadable)?;
    let relay = handoff::DomainHandoff::beside(vault_path, &vault).map_err(unreadable)?;
    let identity = handoff::identity_of(&relay).map_err(unreadable)?;
    let ca_tls = relay
        .ca_tls_certificate
        .as_deref()
        .ok_or(IssuerRefusal::CaTlsMissing)?;
    let ca_tls = DerCertificate::parse(ca_tls).map_err(unreadable)?;
    let policy = identity.policy().map_err(unreadable)?;
    Ok(Domain {
        vault,
        relay,
        identity,
        ca_tls,
        policy,
    })
}

fn unreadable(error: impl std::fmt::Display) -> IssuerRefusal {
    IssuerRefusal::Vault(format!("{error:#}"))
}

/// Every check of [`plan`] after the request is parsed.
fn plan_for(
    domain: &Domain,
    request: IssuerDelegationRequest,
    campaign: Option<&AstraRotationCampaign>,
    now_unix: u64,
) -> std::result::Result<IssuerPlan, IssuerRefusal> {
    let material = material_of(&request)?;
    let campaign = match campaign {
        Some(campaign) => {
            if !matches!(campaign.scope.family(), CampaignFamily::IssuerDelegation) {
                return Err(IssuerRefusal::NotADelegation);
            }
            campaign
                .covers_issuer_delegation(
                    domain.identity.trust_domain_id,
                    request.issuer_epoch,
                    &material.pq_fingerprint,
                    &material.spki_fingerprint,
                )
                .map_err(|_| IssuerRefusal::RequestMismatch)?;
            Some(CampaignManifest {
                campaign: Box::new(campaign.clone()),
                fingerprint: campaign.fingerprint(),
            })
        }
        None => {
            // Fail closed: any value, even one that would not parse, is an
            // origin the domain was given.
            if domain.relay.astra_authority_url.is_some() {
                return Err(IssuerRefusal::OriginRecorded);
            }
            None
        }
    };
    if material.trust_domain_id != domain.identity.trust_domain_id {
        return Err(IssuerRefusal::RequestMismatch);
    }
    let plan = describe(request, &material, &domain.policy, campaign, now_unix)?;
    // `signing::authorize_issuer` runs both again once the vault is open;
    // here they refuse before the key, which is when they are predictable.
    aether::certificates::x509::assert_certificate_authority(&domain.ca_tls)
        .map_err(|_| IssuerRefusal::CaTlsUnusable)?;
    aether::certificates::x509::assert_covers(
        &domain.ca_tls,
        plan.bounds.not_before,
        plan.bounds.not_after,
    )
    .map_err(|_| IssuerRefusal::CaTlsUnusable)?;
    Ok(plan)
}

/// Reads what the request asks to be certified, the way the signature will.
///
/// The CSR is parsed by both readers that use it: the one that extracts the
/// `SubjectPublicKeyInfo` the campaign pins, and the one
/// [`signing::authorize_issuer`] issues the intermediate from, so a request
/// one of them rejects is refused here rather than after the press.
fn material_of(request: &IssuerDelegationRequest) -> std::result::Result<Material, IssuerRefusal> {
    let trust_domain_id = TrustDomainId::parse_hex(request.trust_domain_id.trim())
        .map_err(|_| IssuerRefusal::RequestInvalid)?;
    let csr_der = base64::engine::general_purpose::STANDARD
        .decode(request.tls_intermediate_csr.trim())
        .map_err(|_| IssuerRefusal::RequestInvalid)?;
    rcgen::CertificateSigningRequestParams::from_der(&csr_der.clone().into())
        .map_err(|_| IssuerRefusal::RequestInvalid)?;
    let csr = DerCertificate::new(csr_der).map_err(|_| IssuerRefusal::RequestInvalid)?;
    let spki = aether::certificates::x509::certification_request_public_key_info(&csr)
        .map_err(|_| IssuerRefusal::RequestInvalid)?;
    let pq = MlDsa87PublicKey::parse(request.pq_issuer_public_key.trim())
        .map_err(|_| IssuerRefusal::RequestInvalid)?;
    Ok(Material {
        trust_domain_id,
        pq_fingerprint: Fingerprint::of(pq.as_bytes()),
        spki_fingerprint: Fingerprint::of(&spki),
    })
}

/// The bounds and the manifest, under `policy`.
///
/// The leaf lifetime is [`LEAF_DAYS`] brought down to the policy's cap, so
/// the manifest shows the value [`signing::authorize_issuer`] signs and
/// compares with that same cap.
fn describe(
    request: IssuerDelegationRequest,
    material: &Material,
    policy: &AstraIssuancePolicy,
    campaign: Option<CampaignManifest>,
    now_unix: u64,
) -> std::result::Result<IssuerPlan, IssuerRefusal> {
    let bounds = DelegationBounds {
        maximum_leaf_lifetime_secs: LEAF_SECS.min(policy.maximum_leaf_lifetime_secs),
        not_before: now_unix,
        not_after: now_unix
            .checked_add(DELEGATION_SECS)
            .ok_or_else(|| IssuerRefusal::Vault("horloge hors bornes".into()))?,
    };
    let encoded = serde_json::to_vec(&request).map_err(|_| IssuerRefusal::RequestInvalid)?;
    let manifest = IssuerManifest {
        trust_domain_id: material.trust_domain_id,
        issuer_epoch: request.issuer_epoch,
        not_before: bounds.not_before,
        not_after: bounds.not_after,
        allowed_usages: vec![usage_name(AllowedUsage::AdmittedClientLeafRenewal).to_string()],
        policy_fingerprint: policy.fingerprint().map_err(unreadable)?,
        request_fingerprint: Fingerprint::of(&encoded),
        maximum_leaf_lifetime_secs: bounds.maximum_leaf_lifetime_secs,
        pq_public_key_fingerprint: material.pq_fingerprint,
        tls_public_key_info_fingerprint: material.spki_fingerprint,
        campaign,
    };
    Ok(IssuerPlan {
        request,
        bounds,
        manifest,
    })
}

/// The wire spelling of a usage, as the authorization carries it.
///
/// A match rather than a serialization, so a usage added to the protocol does
/// not compile until this manifest names it.
fn usage_name(usage: AllowedUsage) -> &'static str {
    match usage {
        AllowedUsage::AdmittedClientLeafRenewal => "admitted_client_leaf_renewal",
    }
}

/// Reads the domain again and requires it to produce `plan`, at the instant
/// `plan` was settled for.
fn settle_again(
    vault_path: &Path,
    plan: &IssuerPlan,
    campaign: Option<&AstraRotationCampaign>,
    now_unix: u64,
) -> Result<Domain> {
    // A plan settled for a later instant than the signature is not one this
    // domain produced.
    if plan.bounds.not_before > now_unix {
        return Err(IssuerRefusal::PlanChanged.into());
    }
    let domain = read_domain(vault_path)?;
    let current = plan_for(
        &domain,
        plan.request.clone(),
        campaign,
        plan.bounds.not_before,
    )?;
    if current != *plan {
        return Err(IssuerRefusal::PlanChanged.into());
    }
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::WireGuardKey;

    fn policy() -> AstraIssuancePolicy {
        AstraIssuancePolicy::standard(
            TrustDomainId::new([0x2A; 16]).expect("domain"),
            WireGuardKey::from_bytes([0x11; 32]),
            "gateway.helios.test".into(),
        )
    }

    fn material() -> Material {
        Material {
            trust_domain_id: TrustDomainId::new([0x2A; 16]).expect("domain"),
            pq_fingerprint: Fingerprint::of(b"pq"),
            spki_fingerprint: Fingerprint::of(b"spki"),
        }
    }

    fn request() -> IssuerDelegationRequest {
        IssuerDelegationRequest {
            trust_domain_id: TrustDomainId::new([0x2A; 16]).expect("domain").to_hex(),
            issuer_epoch: 1,
            pq_issuer_public_key: String::new(),
            tls_intermediate_csr: String::new(),
        }
    }

    /// The standard profile pins 90 days, so a stricter policy cannot be
    /// reached through a relay: it is checked here, on the function that
    /// settles the bounds.
    #[test]
    fn the_leaf_cap_follows_a_stricter_policy() {
        let standard = describe(request(), &material(), &policy(), None, 1_000).expect("plan");
        assert_eq!(standard.bounds.maximum_leaf_lifetime_secs, LEAF_SECS);

        let mut strict = policy();
        strict.maximum_leaf_lifetime_secs = 30 * DAY_SECS;
        let capped = describe(request(), &material(), &strict, None, 1_000).expect("plan");
        assert_eq!(capped.bounds.maximum_leaf_lifetime_secs, 30 * DAY_SECS);
        assert_eq!(capped.manifest.maximum_leaf_lifetime_secs, 30 * DAY_SECS);
        assert_eq!(
            capped.manifest.policy_fingerprint,
            strict.fingerprint().expect("fingerprint")
        );
        assert_eq!(
            capped.bounds.not_after - capped.bounds.not_before,
            DELEGATION_SECS
        );
    }

    /// The manifest spells the usage the way the authorization's wire form
    /// does.
    #[test]
    fn the_usage_is_spelled_as_on_the_wire() {
        assert_eq!(
            serde_json::to_value(AllowedUsage::AdmittedClientLeafRenewal).expect("usage"),
            serde_json::json!(usage_name(AllowedUsage::AdmittedClientLeafRenewal))
        );
    }
}
