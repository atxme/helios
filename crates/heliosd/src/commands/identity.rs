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
    let tpm = TpmSettings::default();
    let boot = unlock_tpm_for_offline_command(&tpm)
        .context("unlocking the TPM vault for key-negotiation identity creation")?;
    let resolved = gateway_key::resolve(network, &boot, &tpm);
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
    let fields = if let Some(served) = key_negotiation::served_identity()? {
        identity_export_lines(Some(&served.pq_certificate), None)?
    } else {
        let request = key_negotiation::gateway_bootstrap_request()?;
        identity_export_lines(None, request.as_ref())?
    };
    for field in fields {
        println!("{field}");
    }
    Ok(())
}

/// Builds the stable key/value export consumed by the deployment script.
/// The file reads stay at the command boundary; this keeps formatting
/// testable with identities loaded from an isolated fixture directory.
pub(crate) fn identity_export_lines(
    served: Option<&aether::key_negotiation::PqCertificate>,
    request: Option<&aether::certificates::gateway::GatewayBootstrapRequest>,
) -> anyhow::Result<Vec<String>> {
    if let Some(served) = served {
        return Ok(vec![
            format!("server_name={}", served.subject),
            format!("wireguard_public_key={}", served.wireguard_public_key),
            format!("pq_certificate_not_after={}", served.not_after_unix),
        ]);
    }
    if let Some(request) = request {
        request
            .verify()
            .context("verifying the gateway bootstrap request")?;
        return Ok(vec![
            format!("server_name={}", request.server_name),
            format!(
                "wireguard_public_key={}",
                request.gateway_wg_public_key.to_base64()
            ),
            format!("bootstrap_request_fingerprint={}", request.fingerprint()),
        ]);
    }
    anyhow::bail!(
        "this gateway has no key-negotiation identity: run `heliosd init-key-negotiation`"
    )
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

    let public_key = gateway_key::initialize(network, &boot, rotate, &tpm)
        .map_err(|e| anyhow::anyhow!("could not initialize the identity: {e}"))?;

    println!("{public_key}");
    info!(
        "gateway's public key above — this is the `peer_public_key` value \
         for client profiles. The private key stays sealed and is never displayed."
    );
    Ok(())
}
