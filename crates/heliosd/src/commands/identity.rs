//! The identities this gateway creates and hands out.
//!
//! Its WireGuard identity, its key-negotiation TLS/PQ identity, and the
//! transport identity of the private Astra channel. All four gestures are
//! read over SSH by a deployment script, which is why three of them print
//! `key=value` and nothing else.

use aether::NetworkConfig;
use anyhow::Context;
use helios_tpm::TpmSettings;
use tracing::info;

use crate::commands::tpm::unlock_tpm_for_offline_command;
use crate::{astra_channel, gateway_key, key_negotiation};

pub(crate) fn init_key_negotiation(
    network: &NetworkConfig,
    server_name: &str,
    client_ca: &std::path::Path,
    client_pq_ca: &std::path::Path,
    rotate: bool,
) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(&TpmSettings::default())
        .context("unlocking the TPM vault for key-negotiation identity creation")?;
    let resolved = gateway_key::resolve(network, &boot);
    let gateway_wg_public_key = aether::wg::public_from_private(resolved.private_key.expose())
        .context("gateway WireGuard identity is unavailable")?;
    let result = key_negotiation::initialize(
        server_name,
        &gateway_wg_public_key,
        client_ca,
        client_pq_ca,
        &boot,
        rotate,
    )?;
    println!("certificate: {}", result.certificate_path.display());
    println!("sha256: {}", result.certificate_sha256);
    println!(
        "gateway bootstrap request: {}",
        result.bootstrap_request_path.display()
    );
    println!(
        "request fingerprint: {}",
        result.bootstrap_request_fingerprint
    );
    info!("key-negotiation TLS and PQ private keys generated on the gateway and sealed");
    Ok(())
}

/// Prints the served key-negotiation identity, for a deployment to read.
///
/// One value per line, `clé=valeur`, because the consumer is a shell script:
/// a script that has to parse JSON over SSH parses it with `sed`, and a `sed`
/// pattern over a certificate is a defect waiting for a field to move.
pub(crate) fn show_identity() -> anyhow::Result<()> {
    if let Some(served) = key_negotiation::served_identity()? {
        println!("server_name={}", served.pq_certificate.subject);
        println!(
            "wireguard_public_key={}",
            served.pq_certificate.wireguard_public_key
        );
        println!(
            "pq_certificate_not_after={}",
            served.pq_certificate.not_after_unix
        );
    } else if let Some(request) = key_negotiation::gateway_bootstrap_request()? {
        request
            .verify()
            .context("verifying the gateway bootstrap request")?;
        println!("server_name={}", request.server_name);
        println!(
            "wireguard_public_key={}",
            request.gateway_wg_public_key.to_base64()
        );
        println!("bootstrap_request_fingerprint={}", request.fingerprint());
    } else {
        anyhow::bail!(
            "this gateway has no key-negotiation identity: run `heliosd init-key-negotiation`"
        );
    }
    Ok(())
}

/// Creates the gateway's end of the private Astra channel (spec §8.3).
///
/// Prints its certificate in the same `clé=valeur` shape `show-identity` uses,
/// and for the same reason: the consumer is `deploy.sh` over SSH, and a script
/// that has to parse JSON parses it with `sed`.
pub(crate) fn init_astra_channel(
    bind: std::net::SocketAddr,
    astra_certificate: &std::path::Path,
    authority: Option<std::net::SocketAddr>,
    astra_authority_certificate: Option<&std::path::Path>,
    rotate: bool,
) -> anyhow::Result<()> {
    let identities = astra_channel::initialize(
        bind,
        astra_certificate,
        authority,
        astra_authority_certificate,
        rotate,
    )?;
    println!("bind={bind}");
    println!(
        "gateway_channel_certificate={}",
        identities.served.to_base64()
    );
    println!(
        "gateway_channel_fingerprint={}",
        identities.served.fingerprint()
    );
    if let Some(client) = &identities.client {
        println!("gateway_client_certificate={}", client.to_base64());
        println!("gateway_client_fingerprint={}", client.fingerprint());
    }
    println!();
    println!(
        "hand the certificates above to Astra: it pins these exact bytes and accepts no other \
         gateway — the served one to dial this listener, the client one to accept this gateway \
         on its own"
    );
    Ok(())
}

/// Creates and seals the gateway's WireGuard identity.
///
/// Unsealing goes through the same `BootController` as nominal startup: if
/// the boot chain's integrity is not confirmed, there is no secret, hence no
/// sealing — and no half-created identity.
pub(crate) fn init_identity(network: &NetworkConfig, rotate: bool) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    let boot = unlock_tpm_for_offline_command(&tpm).map_err(|e| {
        anyhow::anyhow!(
            "TPM unsealing failed: {e}. Provision the vault first \
             (`heliosd provision-tpm`)."
        )
    })?;

    let public_key = gateway_key::initialize(network, &boot, rotate)
        .map_err(|e| anyhow::anyhow!("could not initialize the identity: {e}"))?;

    println!("{public_key}");
    info!(
        "gateway's public key above — this is the `peer_public_key` value \
         for client profiles. The private key stays sealed and is never displayed."
    );
    Ok(())
}
