//! What every operator ceremony does with a campaign, whatever its scope.
//!
//! Resolving the targets belongs to the caller — each scope reads a different
//! source — but the window bound of §7.6, the vault the companion must be able
//! to open, the policy pin, the structural validation, the service-signed
//! companion request and the deposit itself are the same for all of them, and
//! live here so that a scope added later cannot acquire its own version of
//! any of it.

use std::path::Path;

use aether::certificates::encoding::Fingerprint;
use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::{now_unix, SERVICE_KEY_FILE};

/// The encrypted authority vault, as the companion wrote it.
///
/// Astra transports and backs it up; it does not open it, and nothing in this
/// container can — the key-slots unwrap under a FIDO2 `hmac-secret` output
/// that never leaves the operator's token. Copied in by an operator, exactly
/// like the credential document.
const VAULT_FILE: &str = "authority-vault.json";
/// Largest vault file read, in bytes.
///
/// The same ceiling the companion applies to its own copy: a file larger than
/// this is not a vault with more key-slots, it is a mistake or a wedge.
const MAX_VAULT_BYTES: u64 = 4 * 1024 * 1024;

/// Reads the encrypted vault, if an operator has copied one into the volume.
///
/// The bytes are kept exactly as written and never parsed: Astra serves them
/// to a companion that holds the key-slots, and a value it had opinions about
/// would be a value it could substitute. Its fingerprint is what the signed
/// `AstraSignerRequest` names, so a wrong file is refused by the companion —
/// not by this read.
///
/// Absent is a supported state, and the ordinary one: only a ceremony that
/// makes a master key sign needs it. Saying so at start-up beats discovering
/// it in the middle of a ceremony.
pub(crate) fn load_encrypted_vault(state_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = state_dir.join(VAULT_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::info!(
            path = %path.display(),
            "no encrypted vault in the state volume: anchor rotations and revocations are \
             refused by name; every other scope is unaffected"
        );
        return Ok(None);
    };
    if metadata.len() > MAX_VAULT_BYTES {
        anyhow::bail!(
            "{} is {} bytes, over the {MAX_VAULT_BYTES}-byte ceiling: this is not a vault",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let fingerprint = aether::certificates::encoding::Fingerprint::of(&bytes);
    tracing::info!(
        path = %path.display(),
        vault_sha256 = %fingerprint,
        bytes = bytes.len(),
        "encrypted vault held for the companion — this process cannot open it"
    );
    Ok(Some(bytes))
}

/// A non-zero 16-byte identifier from the approved DRBG (spec §2.3.2).
pub(crate) fn fresh_id() -> Result<aether::certificates::encoding::Id16> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|error| anyhow::anyhow!("drawing an identifier: {error}"))?;
    aether::certificates::encoding::Id16::new(bytes)
        .map_err(|error| anyhow::anyhow!("drawing an identifier: {error}"))
}

/// Writes a resolved campaign and its service-signed companion request into
/// the inbox consumed by the running Astra service.
pub(crate) fn deposit_campaign(
    state_dir: &Path,
    state: &astra::registry::AstraState,
    campaign: aether::certificates::status::AstraRotationCampaign,
    now: u64,
    expires_at: u64,
) -> Result<astra::signing::CampaignDeposit> {
    use aether::certificates::status::AstraSignerRequest;

    let service_private_key = Zeroizing::new(
        std::fs::read(state_dir.join(SERVICE_KEY_FILE)).context("reading the Astra service key")?,
    );
    let vault_fingerprint = load_encrypted_vault(state_dir)?
        .map(|bytes| Fingerprint::of(&bytes))
        .unwrap_or_else(|| Fingerprint::of(b"no encrypted vault in this state volume"));
    let signer_request = AstraSignerRequest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        operation_id: fresh_id()?,
        campaign_fingerprint: campaign.fingerprint(),
        authority_url: state.authority_url.clone(),
        encrypted_vault_fingerprint: vault_fingerprint,
        required_credentials: campaign.required_credentials,
        created_at: now,
        expires_at,
        astra_service_key_epoch: state.astra_service_key_epoch,
        astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&service_private_key)
    .map_err(|error| anyhow::anyhow!("signing the companion request: {error}"))?;

    let operation_id = signer_request.operation_id;
    let deposit = astra::signing::CampaignDeposit {
        campaign: Box::new(campaign),
        signer_request: Box::new(signer_request),
    };
    let directory = state_dir.join(astra::signing::CAMPAIGN_INBOX_DIR);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let path = directory.join(format!("{}.json", operation_id.to_hex()));
    let temporary = directory.join(format!("{}.tmp", operation_id.to_hex()));
    std::fs::write(
        &temporary,
        serde_json::to_vec(&deposit).context("encoding the campaign")?,
    )
    .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, &path).with_context(|| format!("publishing {}", path.display()))?;
    Ok(deposit)
}

/// What a resolved campaign left for the running service to adopt.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DepositedCampaign {
    pub(crate) operation_id: aether::certificates::encoding::Id16,
    pub(crate) campaign_id: aether::certificates::encoding::Id16,
    pub(crate) fingerprint: Fingerprint,
}

/// Builds one campaign over targets a caller resolved, and deposits it.
///
/// The targets are the caller's business, because each scope reads a different
/// source: the fleet from this registry, the gateway from the daemon that
/// serves it, the delegation from the request that was just produced. What is
/// the same for all of them — the window bound of §7.6, the vault the
/// companion must be able to open, the policy pin, the structural validation
/// and the deposit itself — lives here, so that a scope added later cannot
/// acquire its own version of any of it.
pub(crate) fn open_campaign(
    state_dir: &Path,
    state: &astra::registry::AstraState,
    scope: aether::certificates::status::CampaignScope,
    targets: Vec<aether::certificates::status::CampaignTarget>,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<DepositedCampaign> {
    use aether::certificates::status::{AstraRotationCampaign, MAX_CAMPAIGN_TARGETS};

    if reason.trim().is_empty() || requested_by.trim().is_empty() {
        anyhow::bail!("--reason and --requested-by are what the operator reads before the touch");
    }
    // The specification bounds the campaign window at five minutes: the
    // approval is a challenge, and a challenge with a long life is a challenge
    // worth capturing.
    if window_secs == 0 || window_secs > 300 {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }
    if targets.is_empty() {
        anyhow::bail!(
            "this campaign resolves to no target: there is nothing for an operator to approve"
        );
    }
    if targets.len() > MAX_CAMPAIGN_TARGETS {
        anyhow::bail!(
            "{} targets, over the {MAX_CAMPAIGN_TARGETS} ceiling of §8.2",
            targets.len()
        );
    }
    if scope.opens_vault() && load_encrypted_vault(state_dir)?.is_none() {
        // The companion needs the vault to open `CA-PQ`, and it fetches it
        // from here. Opening the campaign anyway would spend an operator's
        // window on a ceremony that cannot reach a private key.
        anyhow::bail!(
            "this state volume holds no encrypted vault: this campaign has nothing for the \
             companion to open, and `CA-PQ` would never sign"
        );
    }

    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope,
        targets,
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        // The pin the domain was bootstrapped with, not one computed here: a
        // campaign carrying a policy it derived itself would be a campaign
        // that chose the policy it is checked against (§2.4).
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: scope.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved campaign is not one an operator may be shown: {error}")
    })?;

    let campaign_id = campaign.campaign_id;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    Ok(DepositedCampaign {
        operation_id: deposit.signer_request.operation_id,
        campaign_id,
        fingerprint: deposit.campaign.fingerprint(),
    })
}
