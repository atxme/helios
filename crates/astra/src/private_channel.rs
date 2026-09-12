//! The private veth channel to `heliosd`, in both directions (spec §8.3).
//!
//! One identity pair and three ways to use it: `astra init-channel` creates
//! the pair and prints what the gateway must pin, `astra run` opens the
//! direction Astra dials and the listener the gateway dials, and the operator
//! commands that need the gateway's own leaves open a channel for that single
//! question. Nothing else in this binary builds a transport.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};

/// Creates Astra's end of the private channel, and prints its certificate.
///
/// One value per line, `clé=valeur`, because the consumer is `deploy.sh` over
/// SSH: a script that has to parse JSON parses it with `sed`, and a `sed`
/// pattern over a certificate is a defect waiting for a field to move.
pub(crate) fn init_channel(state_dir: &Path, rotate: bool) -> Result<()> {
    let identities = astra::gateway::initialize_pair(state_dir, rotate)
        .context("creating the Astra transport identities")?;
    println!(
        "astra_channel_certificate={}",
        identities.client.to_base64()
    );
    println!(
        "astra_channel_fingerprint={}",
        identities.client.fingerprint()
    );
    println!(
        "astra_authority_certificate={}",
        identities.authority.to_base64()
    );
    println!(
        "astra_authority_fingerprint={}",
        identities.authority.fingerprint()
    );
    println!();
    println!(
        "then, on the gateway: `heliosd init-astra-channel --bind <veth address:port> \
         --astra-certificate <astra_channel_certificate> --authority <astra veth address:port> \
         --astra-authority-certificate <astra_authority_certificate>`"
    );
    Ok(())
}

/// Opens the private channel to the gateway, when this deployment has one.
///
/// The pin is checked here, at startup, rather than at the first rotation: an
/// unusable pairing found at deployment costs a command, and the same pairing
/// found at 80 % of a leaf's life costs a night. It performs no network I/O —
/// the gateway may legitimately come up after the authority does.
pub(crate) fn open_gateway_channel(
    state_dir: &Path,
    address: Option<SocketAddr>,
    certificate: Option<&str>,
) -> Result<Option<astra::gateway::GatewayChannel>> {
    let (Some(address), Some(certificate)) = (address, certificate) else {
        if address.is_some() != certificate.is_some() {
            // Half a pairing is an operator error, not a deployment choice: it
            // means someone meant to have a channel and will not.
            anyhow::bail!(
                "the private gateway channel needs both its address and the gateway's pinned \
                 certificate; only one was given"
            );
        }
        tracing::info!(
            "no private gateway channel configured: Astra serves its public endpoint alone, and \
             stages nothing on the gateway"
        );
        return Ok(None);
    };
    let pinned = aether::certificates::encoding::DerCertificate::parse(certificate)
        .map_err(|error| anyhow::anyhow!("the pinned gateway certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, address, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;
    tracing::info!(
        gateway = %channel.address(),
        pinned_gateway_sha256 = %pinned.fingerprint(),
        "private gateway channel ready"
    );
    Ok(Some(channel))
}

/// Astra's own listener on the veth, when this deployment has one.
///
/// It pins the gateway's **client** certificate — a second identity from the
/// one Astra pins for dialling, because the two roles are pinned by different
/// peers under different names. Half a pairing is refused rather than served
/// one-sided: an address without a pin would accept any client that reached
/// the veth, which is precisely what the pin exists to prevent.
pub(crate) fn private_listener(
    state_dir: &Path,
    bind: Option<SocketAddr>,
    gateway_client_certificate: Option<&str>,
) -> Result<Option<(SocketAddr, rustls::ServerConfig)>> {
    let (Some(bind), Some(certificate)) = (bind, gateway_client_certificate) else {
        if bind.is_some() != gateway_client_certificate.is_some() {
            anyhow::bail!(
                "the private renewal listener needs both its bind address and the gateway's \
                 pinned client certificate; only one was given"
            );
        }
        tracing::info!(
            "no private renewal listener configured: the gateway relays no client renewal, and \
             answers 503 on its four renewal routes"
        );
        return Ok(None);
    };
    anyhow::ensure!(
        !bind.ip().is_unspecified(),
        "the private renewal listener is configured to bind {bind}, which publishes the authority \
         on every interface; name Astra's veth address"
    );
    let pinned = aether::certificates::encoding::DerCertificate::parse(certificate)
        .map_err(|error| anyhow::anyhow!("the pinned gateway client certificate: {error}"))?;
    let identity = astra::gateway::authority_identity(state_dir)
        .map_err(|error| anyhow::anyhow!("reading the authority transport identity: {error}"))?;
    let config = helios_api::internal::server_config(&identity, &pinned)
        .map_err(|error| anyhow::anyhow!("building the private renewal listener: {error}"))?;
    tracing::info!(
        %bind,
        pinned_gateway_client_sha256 = %pinned.fingerprint(),
        "private renewal listener ready"
    );
    Ok(Some((bind, config)))
}

/// Reads the identity the daemon **serves**, over the private channel.
pub(crate) fn read_gateway_identity(
    state_dir: &Path,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<helios_api::internal::GatewayIdentityView> {
    let pinned = aether::certificates::encoding::DerCertificate::parse(gateway_certificate)
        .map_err(|error| anyhow::anyhow!("--gateway-certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, gateway_channel, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for the private channel")?;
    runtime
        .block_on(channel.gateway_identity())
        .context("reading the identity the gateway serves")
}
