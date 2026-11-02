//! What every opening does with a campaign, whatever its scope.
//!
//! Resolving the targets belongs to the action — each scope reads a different
//! source — but the bounds of §5.3, the vault the companion must be able to
//! open, the policy pin, the structural validation, the service-signed
//! companion request and the admission into the store are the same for all of
//! them, and live here so that a scope added later cannot acquire its own
//! version of any of it.

use aether::certificates::encoding::{Fingerprint, MlDsa87Signature};
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget, MAX_CAMPAIGN_TARGETS,
};
use aether::certificates::transport::OperatorOpened;

use super::{DoorConnector, DoorRefusal, OpeningText};
use crate::registry::AstraState;
use crate::service::AstraService;
use crate::signing::SigningOperation;

/// The longest window an opening may ask for, in seconds.
///
/// The specification bounds the campaign window at five minutes: the approval
/// is a challenge, and a challenge with a long life is a challenge worth
/// capturing.
pub const MAX_OPENING_WINDOW_SECS: u64 = 300;

/// What the signed companion request names when no vault is held.
///
/// Only a scope that makes a master key sign has the companion fetch the
/// vault, and such a scope is refused before it gets here without one. Every
/// other scope still carries the field, because the request format has it;
/// this value is the digest of no file, so it can never match a vault.
const NO_VAULT_FINGERPRINT_INPUT: &[u8] = b"no encrypted vault in this state volume";

/// What a campaign takes from the domain, read under the registry lock.
struct Domain {
    trust_domain_id: aether::certificates::encoding::TrustDomainId,
    gateway_wg_public_key: aether::certificates::encoding::WireGuardKey,
    server_name: String,
    authority_url: String,
    policy_fingerprint: Fingerprint,
    service_key_epoch: u64,
}

impl Domain {
    fn of(state: &AstraState) -> Self {
        Self {
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway_wg_public_key,
            server_name: state.server_name.clone(),
            authority_url: state.authority_url.clone(),
            // The pin the domain was bootstrapped with, not one computed
            // here: a campaign carrying a policy it derived itself would be a
            // campaign that chose the policy it is checked against (§2.4).
            policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
            service_key_epoch: state.astra_service_key_epoch,
        }
    }
}

/// Opens one campaign over the targets `resolve` reads from the registry.
///
/// The registry and the operation store are never held together: the targets
/// and the facts of the domain are copied out under the first lock, then the
/// uniqueness check, the signature and the admission happen under the second,
/// so that two openings of the same family cannot both pass the check.
pub(super) async fn open_campaign(
    service: &AstraService,
    connector: &DoorConnector,
    scope: CampaignScope,
    text: OpeningText,
    resolve: impl FnOnce(&AstraState) -> Result<Vec<CampaignTarget>, DoorRefusal>,
    now_unix: u64,
) -> Result<OperatorOpened, DoorRefusal> {
    if text.reason.trim().is_empty() || text.requested_by.trim().is_empty() {
        return Err(DoorRefusal::TextMissing);
    }
    if text.window_secs == 0 || text.window_secs > MAX_OPENING_WINDOW_SECS {
        return Err(DoorRefusal::WindowOutOfRange);
    }

    let (domain, targets) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        (Domain::of(state), resolve(state)?)
    };
    if targets.is_empty() {
        return Err(DoorRefusal::NoTarget);
    }
    if targets.len() > MAX_CAMPAIGN_TARGETS {
        return Err(DoorRefusal::TooManyTargets);
    }
    let vault_fingerprint = match &service.encrypted_vault {
        Some(bytes) => Fingerprint::of(bytes),
        // The companion needs the vault to open `CA-PQ`, and it fetches it
        // from here. Opening the campaign anyway would spend an operator's
        // window on a ceremony that cannot reach a private key.
        None if scope.opens_vault() => return Err(DoorRefusal::NoVault),
        None => Fingerprint::of(NO_VAULT_FINGERPRINT_INPUT),
    };

    let mut store = service.signing.lock().await;
    if let Some(operation_id) = store.live_conflict(scope, &targets, now_unix) {
        return Err(DoorRefusal::AlreadyOpen { operation_id });
    }

    let expires_at = now_unix
        .checked_add(text.window_secs)
        .ok_or(DoorRefusal::Internal)?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: domain.trust_domain_id,
        gateway_wg_public_key: domain.gateway_wg_public_key,
        server_name: domain.server_name,
        created_at: now_unix,
        expires_at,
        scope,
        targets,
        reason: text.reason.trim().to_string(),
        requested_by: requested_by(connector, &text.requested_by),
        policy_fingerprint: domain.policy_fingerprint,
        required_credentials: scope.required_credentials(),
    };
    // Checked before anything is signed: the service key signs only a text an
    // operator may be shown.
    campaign
        .validate(now_unix)
        .map_err(|error| DoorRefusal::Store(error.into()))?;

    let signer_request = AstraSignerRequest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        operation_id: fresh_id()?,
        campaign_fingerprint: campaign.fingerprint(),
        authority_url: domain.authority_url,
        encrypted_vault_fingerprint: vault_fingerprint,
        required_credentials: campaign.required_credentials,
        created_at: now_unix,
        expires_at,
        astra_service_key_epoch: domain.service_key_epoch,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&service.service_private_key)
    .map_err(|error| {
        tracing::error!(%error, "the door could not sign the companion request");
        DoorRefusal::Internal
    })?;

    // Straight into the store: the request was signed in this process a line
    // above, so there is no file and no second process whose signature would
    // need re-verifying. `SigningOperation::new` and `open` keep their
    // structural checks — the request names this campaign, the windows agree,
    // the global ceiling holds.
    let operation = SigningOperation::new(Box::new(campaign), Box::new(signer_request), now_unix)
        .map_err(DoorRefusal::Store)?;
    let opened = OperatorOpened {
        operation_id: operation.operation_id,
        campaign_id: operation.campaign.campaign_id,
        campaign_fingerprint: operation.campaign.fingerprint(),
        scope: operation.campaign.scope,
        target_count: operation.campaign.targets.len(),
        required_credentials: operation.campaign.required_credentials,
        expires_at: operation.expires_at,
        revocation_expiries: None,
    };
    store
        .open(operation, now_unix)
        .map_err(DoorRefusal::Store)?;
    Ok(opened)
}

/// The requester the operator reads, with the identity the tunnel resolved.
///
/// Through the tunnel, the door appends the administrator the gateway
/// resolved from its source VIP, so that a compromised administrator peer
/// cannot put another name in front of the touch. Whatever the caller wrote
/// stays, including a suffix that imitates this one: the real identity is
/// always the last. Through the console the text is the local user's own, and
/// the user goes to the log.
fn requested_by(connector: &DoorConnector, written: &str) -> String {
    let written = written.trim();
    match connector {
        DoorConnector::Console { .. } => written.to_string(),
        DoorConnector::Tunnel { operator } => format!("{written} — pair {operator}"),
    }
}

/// A non-zero identifier from the approved DRBG, or a refusal by name.
fn fresh_id() -> Result<aether::certificates::encoding::Id16, DoorRefusal> {
    crate::renewal::fresh_id().map_err(|error| {
        tracing::error!(%error, "the door could not draw an identifier");
        DoorRefusal::Internal
    })
}
