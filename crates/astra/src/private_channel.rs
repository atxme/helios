//! The private veth channel to `heliosd`, in both directions (spec §8.3).
//!
//! One identity pair and two ways to use it: `astra init-channel` creates the
//! pair and prints what the gateway must pin, and `astra run` opens the
//! direction Astra dials and the listener the gateway dials. The operator
//! commands that need the gateway's own leaves ask the running service, which
//! holds the channel; only `gateway-identity publish` with the service stopped
//! opens one of its own, from the service's configuration.

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
    let config = astra_channel::server_config(&identity, &pinned)
        .map_err(|error| anyhow::anyhow!("building the private renewal listener: {error}"))?;
    tracing::info!(
        %bind,
        pinned_gateway_client_sha256 = %pinned.fingerprint(),
        "private renewal listener ready"
    );
    Ok(Some((bind, config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        "192.0.2.10:9443".parse().expect("test address")
    }

    fn generated_pair(path: &Path) -> astra::gateway::TransportIdentities {
        astra::gateway::initialize_pair(path, false).expect("generate channel identities")
    }

    #[test]
    fn channel_open_is_optional_but_never_accepts_a_partial_pairing() {
        let directory = tempfile::tempdir().expect("temp dir");

        assert!(open_gateway_channel(directory.path(), None, None)
            .expect("channel is optional")
            .is_none());
        assert!(open_gateway_channel(directory.path(), Some(address()), None).is_err());
        assert!(open_gateway_channel(directory.path(), None, Some("pin")).is_err());
    }

    #[test]
    fn channel_open_validates_the_pin_and_builds_without_network_io() {
        let local = tempfile::tempdir().expect("local identity dir");
        let gateway_dir = tempfile::tempdir().expect("gateway identity dir");
        let local_pair = generated_pair(local.path());
        let gateway_pair = generated_pair(gateway_dir.path());

        assert!(open_gateway_channel(local.path(), Some(address()), Some("not DER")).is_err());
        // The authority certificate is server-auth; Astra's own client-auth
        // certificate is not interchangeable with the gateway pin.
        assert!(open_gateway_channel(
            local.path(),
            Some(address()),
            Some(&local_pair.client.to_base64())
        )
        .is_err());

        let channel = open_gateway_channel(
            local.path(),
            Some(address()),
            Some(&gateway_pair.authority.to_base64()),
        )
        .expect("construct pinned client without dialing")
        .expect("configured channel");
        assert_eq!(channel.address(), address());
    }

    #[test]
    fn private_listener_is_optional_and_refuses_half_or_public_bindings() {
        let directory = tempfile::tempdir().expect("state dir");

        assert!(private_listener(directory.path(), None, None)
            .expect("listener is optional")
            .is_none());
        assert!(private_listener(directory.path(), Some(address()), None).is_err());
        assert!(private_listener(directory.path(), None, Some("pin")).is_err());
        assert!(private_listener(
            directory.path(),
            Some("0.0.0.0:9443".parse().expect("wildcard")),
            Some("malformed pin"),
        )
        .is_err());
    }

    #[test]
    fn private_listener_builds_only_from_an_authority_and_client_pin() {
        let authority_dir = tempfile::tempdir().expect("authority identity dir");
        let gateway_dir = tempfile::tempdir().expect("gateway identity dir");
        let authority_pair = generated_pair(authority_dir.path());
        let gateway_pair = generated_pair(gateway_dir.path());

        assert!(private_listener(authority_dir.path(), Some(address()), Some("not DER"),).is_err());
        // The gateway's client-auth certificate is the listener's pin.
        let listener = private_listener(
            authority_dir.path(),
            Some(address()),
            Some(&gateway_pair.client.to_base64()),
        )
        .expect("build pinned TLS listener")
        .expect("configured listener");
        assert_eq!(listener.0, address());
        drop(listener.1);

        // A server-auth pin cannot authenticate the gateway's client role.
        assert!(private_listener(
            authority_dir.path(),
            Some(address()),
            Some(&authority_pair.authority.to_base64()),
        )
        .is_err());
    }

    #[test]
    fn init_channel_creates_an_idempotent_pair_and_explicit_rotation_replaces_it() {
        let directory = tempfile::tempdir().expect("state dir");
        init_channel(directory.path(), false).expect("initialize channel");
        let first = generated_pair(directory.path());

        init_channel(directory.path(), false).expect("reuse channel");
        let repeated = generated_pair(directory.path());
        assert_eq!(first.client, repeated.client);
        assert_eq!(first.authority, repeated.authority);

        init_channel(directory.path(), true).expect("rotate channel");
        let rotated = generated_pair(directory.path());
        assert_ne!(first.client, rotated.client);
        assert_ne!(first.authority, rotated.authority);
    }
}
