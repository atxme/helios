//! The gateway's own identity: freeze it, then let the signed transition go.
//!
//! Both commands read or write state this registry has never held — the leaves
//! the daemon actually serves — so both go over the private channel.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use astra::registry::AstraRegistry;

use crate::campaign_deposit::{open_campaign, DepositedCampaign};
use crate::private_channel::read_gateway_identity;
use crate::{now_unix, REGISTRY_FILE};

/// The gateway leaf in service, exported for the operator companion.
///
/// Public by construction, and rewritten on every campaign: the companion has
/// to verify the §5 request's continuity signature under the key that is
/// actually serving, and it holds no copy of it.
const GATEWAY_ACTIVE_CERTIFICATE_FILE: &str = "gateway-active-certificate.json";

/// Freezes the gateway identity in service into a signing campaign (§11.1 3).
pub(crate) fn gateway_identity_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<DepositedCampaign> {
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();

    let identity = read_gateway_identity(state_dir, gateway_channel, gateway_certificate)?;

    // The daemon answers with the leaf it actually presents. A campaign built
    // from anything else would freeze a state no client has ever pinned.
    let target = CampaignTarget {
        certificate_kind: CertificateKind::GatewayPq,
        identity_key: state.gateway_wg_public_key,
        epoch: identity.gateway_decision_epoch,
        generation: identity.active_gateway_identity_epoch,
        active_tls_certificate_fingerprint: identity.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: identity.pq_certificate_fingerprint,
    };

    // Exported because the companion cannot verify the §5 request's
    // continuity signature without the leaf in service, and it holds no copy
    // of it. Public material: the same leaf every admitted client pins.
    let served_path = state_dir.join(GATEWAY_ACTIVE_CERTIFICATE_FILE);
    std::fs::write(
        &served_path,
        serde_json::to_vec_pretty(&identity.pq_certificate)
            .context("encoding the gateway leaf in service")?,
    )
    .with_context(|| format!("writing {}", served_path.display()))?;

    let decision_epoch = identity.gateway_decision_epoch;
    let next_epoch = decision_epoch
        .checked_add(1)
        .context("gateway decision epoch overflow")?;
    let deposited = open_campaign(
        state_dir,
        state,
        CampaignScope::GatewayIdentity,
        vec![target],
        reason,
        requested_by,
        window_secs,
    )?;
    let operation_id = deposited.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!("campagne gateway déposée : décision {decision_epoch}, fenêtre de {window_secs} s");
    eprintln!(
        "feuille PQ en service : {}",
        identity.pq_certificate_fingerprint
    );
    eprintln!(
        "feuille TLS en service : {}",
        identity.tls_certificate_fingerprint
    );
    eprintln!("empreinte de campagne : {}", deposited.fingerprint);
    eprintln!("feuille en service exportée : {}", served_path.display());
    eprintln!(
        "renouveler depuis le poste opérateur (époque {next_epoch}) :\n  astra-signer \
         sign-gateway-transition --authority-url {} --operation-id {} --request <demande.json> \
         --active-certificate <{}> --out <transition.json>",
        state.authority_url,
        operation_id.to_hex(),
        GATEWAY_ACTIVE_CERTIFICATE_FILE
    );
    eprintln!(
        "ou annuler la transition déjà en attente :\n  astra-signer abort-gateway-transition \
         --authority-url {} --operation-id {} --transition <transition.json> \
         --out <avortement.json>",
        state.authority_url,
        operation_id.to_hex()
    );
    Ok(deposited)
}

/// Lets a signed transition leave the authority (spec §11.1 step 6).
pub(crate) fn gateway_identity_publish(
    state_dir: &Path,
    epoch: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<()> {
    let mut registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let pinned = aether::certificates::encoding::DerCertificate::parse(gateway_certificate)
        .map_err(|error| anyhow::anyhow!("--gateway-certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, gateway_channel, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;

    // Persisted first, and irreversibly. A marker written after the relay
    // would leave a gateway that has closed its abort window while this
    // authority still believes the decision cancellable — and §6.3 makes the
    // gateway's belief the one clients act on.
    let transition = registry
        .publish_gateway_transition(epoch, now_unix())
        .context("no unaborted gateway transition is stored at this epoch")?;
    let fingerprint = transition
        .fingerprint()
        .context("fingerprinting the published transition")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for the private channel")?;
    runtime
        .block_on(channel.gateway_transition_published(
            &helios_api::internal::GatewayTransitionPublished {
                gateway_identity_epoch: epoch,
                transition_fingerprint: fingerprint,
            },
        ))
        .context(
            "the publication is recorded here but the gateway did not confirm it; re-run this \
             command",
        )?;

    println!("{}", fingerprint);
    eprintln!(
        "transition publiée : époque {epoch}, activation {}",
        transition.window.activation_at
    );
    eprintln!("l'avortement n'est plus légitime ; la distribution aux clients est ouverte");
    Ok(())
}
