//! The gateway's own identity: freeze it, then let the signed transition go.
//!
//! Both read or write state the registry has never held — the leaves the
//! daemon actually serves — so both use the running service's own channel to
//! the gateway, through the door. With the service stopped, the publication
//! still runs here, under the volume lock, on the channel the service is
//! configured with.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use astra::door::{
    DoorOutcome, DoorRequest, OpenedSubject, Opening, GATEWAY_ACTIVE_CERTIFICATE_FILE,
};

use crate::{console, now_unix};

/// Freezes the gateway identity in service into a signing campaign (§11.1 3).
pub(crate) fn gateway_identity_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    let text = console::opening_text(reason, requested_by, window_secs);
    let opening = console::opened(console::open(
        state_dir,
        DoorRequest::GatewayIdentity { text },
    )?)?;
    print_gateway_identity(state_dir, &opening, window_secs)
}

/// What a gateway-identity campaign prints, alone or as a step of the chain.
pub(super) fn print_gateway_identity(
    state_dir: &Path,
    opening: &Opening,
    window_secs: u64,
) -> Result<()> {
    let OpenedSubject::Gateway {
        decision_epoch,
        tls_certificate_fingerprint,
        pq_certificate_fingerprint,
    } = &opening.subject
    else {
        return Err(console::unexpected(&DoorOutcome::Opened(opening.clone())));
    };
    let next_epoch = decision_epoch
        .checked_add(1)
        .context("gateway decision epoch overflow")?;
    let operation_id = opening.opened.operation_id;
    // The door exported the leaf in service beside the registry, at a name it
    // chose: this is the same volume, reached by the same socket.
    let served_path = state_dir.join(GATEWAY_ACTIVE_CERTIFICATE_FILE);
    println!("{}", operation_id.to_hex());
    eprintln!("campagne gateway déposée : décision {decision_epoch}, fenêtre de {window_secs} s");
    eprintln!("feuille PQ en service : {pq_certificate_fingerprint}");
    eprintln!("feuille TLS en service : {tls_certificate_fingerprint}");
    eprintln!(
        "empreinte de campagne : {}",
        opening.opened.campaign_fingerprint
    );
    eprintln!("feuille en service exportée : {}", served_path.display());
    eprintln!(
        "renouveler depuis le poste opérateur (époque {next_epoch}) :\n  astra-signer \
         sign-gateway-transition --authority-url {} --operation-id {} --request <demande.json> \
         --active-certificate <{}> --out <transition.json>",
        opening.authority_url,
        operation_id.to_hex(),
        GATEWAY_ACTIVE_CERTIFICATE_FILE
    );
    eprintln!(
        "ou annuler la transition déjà en attente :\n  astra-signer abort-gateway-transition \
         --authority-url {} --operation-id {} --transition <transition.json> \
         --out <avortement.json>",
        opening.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}

/// Lets a signed transition leave the authority (spec §11.1 step 6).
///
/// Replayable: the mark is persisted before the relay, and a second run
/// finishes a relay the first could not confirm.
pub(crate) fn gateway_identity_publish(
    state_dir: &Path,
    epoch: u64,
    transition: &str,
) -> Result<()> {
    let transition_fingerprint =
        super::trust_domain::parse_fingerprint(transition).context("--transition")?;
    let outcome = console::write(
        state_dir,
        DoorRequest::GatewayIdentityPublish {
            epoch,
            transition_fingerprint,
        },
        |registry| {
            let channel = configured_gateway_channel(state_dir)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting a runtime for the private channel")?;
            let (mark, confirmed) =
                runtime.block_on(astra::door::write::publish_gateway_transition(
                    registry,
                    &channel,
                    epoch,
                    &transition_fingerprint,
                    now_unix(),
                ))?;
            Ok(DoorOutcome::published(mark, confirmed))
        },
    )?;
    let DoorOutcome::Published {
        epoch,
        transition_fingerprint,
        activation_at,
        confirmed,
    } = outcome
    else {
        return Err(console::unexpected(&outcome));
    };
    if !confirmed {
        anyhow::bail!(
            "the publication is recorded here but the gateway did not confirm it; re-run this \
             command"
        );
    }
    println!("{transition_fingerprint}");
    eprintln!("transition publiée : époque {epoch}, activation {activation_at}");
    eprintln!("l'avortement n'est plus légitime ; la distribution aux clients est ouverte");
    Ok(())
}

/// The channel `astra run` is configured with, for a publication made while
/// it is stopped.
///
/// Read from the service's own variables (`ASTRA_GATEWAY_CHANNEL`,
/// `ASTRA_GATEWAY_CERTIFICATE`, as `astra run` reads them) rather than from a
/// flag: the gateway a publication reaches is the service's, whichever path
/// the write takes.
fn configured_gateway_channel(state_dir: &Path) -> Result<astra::gateway::GatewayChannel> {
    let (Ok(address), Ok(certificate)) = (
        std::env::var("ASTRA_GATEWAY_CHANNEL"),
        std::env::var("ASTRA_GATEWAY_CERTIFICATE"),
    ) else {
        return Err(astra::door::DoorRefusal::PublicationChannelUnavailable.into());
    };
    let address: SocketAddr = address
        .parse()
        .context("ASTRA_GATEWAY_CHANNEL n'est pas une adresse")?;
    let pinned = aether::certificates::encoding::DerCertificate::parse(&certificate)
        .map_err(|error| anyhow::anyhow!("ASTRA_GATEWAY_CERTIFICATE illisible : {error}"))?;
    astra::gateway::GatewayChannel::open(state_dir, address, &pinned)
        .map_err(|error| anyhow::anyhow!("ouvrir le canal privé vers la gateway : {error}"))
}
