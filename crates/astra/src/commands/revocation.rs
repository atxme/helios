//! `astra revocation open`, for a client identity or for the gateway's own.
//!
//! One command and two scopes, because the two resolve from different places:
//! a client revocation reads the generation this registry records, and the
//! gateway's reads the leaves — and above all the signed expiries — from the
//! daemon that serves them.

use std::net::SocketAddr;
use std::path::Path;

use aether::certificates::encoding::WireGuardKey;
use anyhow::{Context, Result};
use astra::registry::AstraRegistry;

use crate::campaign_deposit::{deposit_campaign, fresh_id, load_encrypted_vault};
use crate::private_channel::read_gateway_identity;
use crate::{now_unix, RevocationScopeArg, REGISTRY_FILE};

/// Freezes the gateway identity in service into a revocation campaign (§10.1).
///
/// # Why this one dials the gateway too
///
/// A client revocation resolves from this registry, which records every
/// admitted generation. The gateway's own leaves were never recorded here —
/// Astra transcribes admissions, it does not hold the identity every client
/// pins — so their fingerprints and, above all, their **signed expiries** come
/// from the daemon that serves them. §10.1 makes each expiry exact: a value
/// retyped or inferred produces an object every recipient refuses, during the
/// incident that motivated it.
fn gateway_revocation_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<()> {
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    if load_encrypted_vault(state_dir)?.is_none() {
        anyhow::bail!("this state volume has no encrypted vault for the companion to open");
    }
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();

    let identity = read_gateway_identity(state_dir, gateway_channel, gateway_certificate)?;
    let pq_not_after = identity.pq_certificate.not_after_unix;
    let tls_not_after = identity.tls_certificate_not_after;

    // The counter is the gateway's own axis (§4.2), and this registry does not
    // hold it either. It is the decision epoch the daemon reports, advanced by
    // one — the same rule a client revocation follows on its own axis.
    let target = CampaignTarget {
        certificate_kind: CertificateKind::GatewayPq,
        identity_key: state.gateway_wg_public_key,
        epoch: identity.gateway_decision_epoch,
        generation: identity.active_gateway_identity_epoch,
        active_tls_certificate_fingerprint: identity.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: identity.pq_certificate_fingerprint,
    };
    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("revocation campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::EmergencyRevocation,
        targets: vec![target],
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: CampaignScope::EmergencyRevocation.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved revocation cannot be shown to an operator: {error}")
    })?;

    let next_epoch = identity
        .gateway_decision_epoch
        .checked_add(1)
        .context("gateway revocation counter overflow")?;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    let operation_id = deposit.signer_request.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!("révocation gateway déposée : compteur {next_epoch}, fenêtre de {window_secs} s");
    eprintln!(
        "feuille PQ  : {} · expire {pq_not_after}",
        identity.pq_certificate_fingerprint
    );
    eprintln!(
        "feuille TLS : {} · expire {tls_not_after}",
        identity.tls_certificate_fingerprint
    );
    eprintln!("empreinte de campagne : {}", deposit.campaign.fingerprint());
    eprintln!(
        "terminal : la gateway ne négociera plus. Signer depuis le poste opérateur :\n  \
         astra-signer revoke --scope gateway --authority-url {} --operation-id {} \
         --pq-not-after {pq_not_after} --tls-not-after {tls_not_after}",
        deposit.signer_request.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}

/// Resolves one admitted client into an emergency revocation campaign.
#[allow(clippy::too_many_arguments)]
pub(crate) fn revocation_open(
    state_dir: &Path,
    scope: RevocationScopeArg,
    peer: Option<&str>,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
) -> Result<()> {
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    if reason.trim().is_empty() || requested_by.trim().is_empty() {
        anyhow::bail!("--reason and --requested-by are what the operator reads before the touch");
    }
    if window_secs == 0 || window_secs > 300 {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }
    if scope == RevocationScopeArg::Gateway {
        anyhow::ensure!(peer.is_none(), "--peer is refused for --scope gateway");
        return gateway_revocation_open(
            state_dir,
            reason,
            requested_by,
            window_secs,
            gateway_channel.context(
                "--gateway-channel is required for --scope gateway: this registry holds no \
                 gateway leaf, and §10.1 needs the exact expiry each one carries",
            )?,
            gateway_certificate.context("--gateway-certificate is required for --scope gateway")?,
        );
    }
    let peer = peer.context("--peer is required for --scope client")?;
    let client_wg_public_key =
        WireGuardKey::parse(peer).context("reading the client's WireGuard public key")?;

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();
    let record = state
        .peers
        .get(&client_wg_public_key.to_base64())
        .context("this registry has no admitted identity for --peer")?;
    if record.revoked {
        anyhow::bail!(
            "{} is already revoked at epoch {}; revoked is terminal",
            record.name,
            record.revocation_epoch
        );
    }
    if load_encrypted_vault(state_dir)?.is_none() {
        anyhow::bail!("this state volume has no encrypted vault for the companion to open");
    }

    let target = CampaignTarget {
        certificate_kind: CertificateKind::ClientPq,
        identity_key: record.client_wg_public_key,
        epoch: record.revocation_epoch,
        generation: record.active.generation,
        active_tls_certificate_fingerprint: record.active.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: record.active.pq_certificate_fingerprint,
    };
    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("revocation campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::EmergencyRevocation,
        targets: vec![target],
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: CampaignScope::EmergencyRevocation.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved revocation cannot be shown to an operator: {error}")
    })?;

    let peer_name = record.name.clone();
    let generation = record.active.generation;
    let not_after = record.active.not_after;
    let next_epoch = record
        .revocation_epoch
        .checked_add(1)
        .context("revocation counter overflow")?;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    let operation_id = deposit.signer_request.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!(
        "révocation déposée : {peer_name}, génération {generation}, compteur {next_epoch}, fenêtre de {window_secs} s"
    );
    eprintln!("empreinte de campagne : {}", deposit.campaign.fingerprint());
    eprintln!(
        "signer depuis le poste opérateur :\n  astra-signer revoke --authority-url {} \
         --operation-id {} --not-after {not_after}",
        deposit.signer_request.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}
