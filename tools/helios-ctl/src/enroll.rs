//! One-shot enrollment: everything a client needs, in a single command.
//!
//! Admitting a client used to take five commands and three copies between
//! machines — generate a WireGuard key, issue two certificates, read back two
//! fingerprints, admit the peer with them, then hand-assemble the profile
//! around a certificate copied out of `/var/lib/helios`. Every one of those
//! steps is a place to paste the wrong value, and the failure only shows up
//! later, as a negotiation the gateway refuses without saying why.
//!
//! So this command does the whole thing, and takes everything it can from the
//! gateway itself:
//!
//! 1. read the gateway's WireGuard identity and negotiation certificates;
//! 2. resolve the client's WireGuard key — supplied, or generated here;
//! 3. issue the client's TLS and ML-DSA-65 certificates from the operator CA;
//! 4. admit the peer with both fingerprints and the anti-downgrade floor;
//! 5. write one Orion document carrying the profile **and** the identity.
//!
//! # Why the result is a secret
//!
//! The identity's two private keys are in the file. That is what makes the
//! import a single gesture, and it is also what makes the document as
//! sensitive as `profile emit --with-private-key`: it is born at 0600, it
//! travels through a controlled channel, and it is destroyed on both ends
//! after import. `profile emit` remains the path that carries no secret.

use std::path::{Path, PathBuf};

use aether::key_negotiation::ProtectionMode;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use reqwest::Client;

use crate::{api, key_nego, peer, profile};

/// File names produced by `key-nego init-client-ca`, looked up in `--client-ca-dir`.
const CA_CERTIFICATE_FILE: &str = "orion-client-ca.der";
const CA_PRIVATE_KEY_FILE: &str = "orion-client-ca-key.der";
const PQ_CA_PRIVATE_KEY_FILE: &str = "orion-client-pq-ca-private.bin";

pub struct EnrollOptions {
    /// Profile name, also the peer name on the gateway.
    pub name: String,
    /// Gateway's public WireGuard endpoint (`IP:port` or `FQDN:port`).
    pub endpoint: String,
    /// Directory holding the operator client CA.
    pub client_ca_dir: PathBuf,
    /// Client public key, when the client already holds its own pair.
    pub public_key: Option<String>,
    /// Negotiation mode, which is also the peer's floor.
    pub mode: ProtectionMode,
    /// Negotiation endpoint. Defaults to the tunnel host with the port the
    /// gateway publishes.
    pub negotiation_endpoint: Option<String>,
    /// Name of the protected store entry. Defaults to `orion-<name>`.
    pub identity: Option<String>,
    /// Admit the peer as a control-plane administrator.
    pub admin: bool,
    /// Revoke an existing peer of the same name before admitting.
    pub replace: bool,
    pub output: PathBuf,
}

pub async fn run(client: &Client, base: &str, options: EnrollOptions) -> Result<()> {
    if options.mode == ProtectionMode::StaticPsk {
        bail!(
            "`enroll` does not set up a static PSK: that mode needs a secret shared out of band, \
             which this command deliberately never invents. Use --mode ml-kem (recommended) or \
             --mode classic, and configure a static PSK by hand if you really need one."
        );
    }

    let network = api::network(client, base).await?;
    let gateway_public_key = network
        .wg_public_key
        .clone()
        .filter(|key| !key.is_empty())
        .context(
            "the gateway has no WireGuard identity yet — run `heliosd init-identity` on the \
             gateway, with console access",
        )?;

    let negotiation = api::key_negotiation(client, base).await?.context(
        "this gateway serves no key-negotiation material — build heliosd with the \
         `key-negotiation` feature and run `heliosd init-key-negotiation`, or fall back to \
         `helios-ctl profile emit` for a profile without pre-WireGuard negotiation",
    )?;

    // The gateway certificate is pinned to a WireGuard key. If that is not
    // the identity the gateway actually runs on, every client built here
    // would fail its pinning check — and the message would blame the client.
    if negotiation.wireguard_public_key != gateway_public_key {
        bail!(
            "the gateway negotiation certificate is bound to another WireGuard identity: it \
             pins {}, while the gateway runs {}. Its identity was rotated without reissuing \
             the certificate — re-run `heliosd init-key-negotiation --rotate`.",
            negotiation.wireguard_public_key,
            gateway_public_key
        );
    }

    let identity_name = options
        .identity
        .clone()
        .unwrap_or_else(|| format!("orion-{}", options.name.trim()));
    let negotiation_endpoint = resolve_negotiation_endpoint(&options, negotiation.port)?;

    let (public_key, private_key) = resolve_keys(&options)?;
    let material = key_nego::issue_client_material(
        &options.name,
        &public_key,
        &options.client_ca_dir.join(CA_CERTIFICATE_FILE),
        &options.client_ca_dir.join(CA_PRIVATE_KEY_FILE),
        &options.client_ca_dir.join(PQ_CA_PRIVATE_KEY_FILE),
    )
    .with_context(|| {
        format!(
            "issuing the client certificates from {} — was the CA created with \
             `helios-ctl key-nego init-client-ca`?",
            options.client_ca_dir.display()
        )
    })?;

    let address = admit(client, base, &options, &public_key, &material).await?;

    let encoder = base64::engine::general_purpose::STANDARD;
    let json = profile::render(profile::Profile {
        name: &options.name,
        endpoint: &options.endpoint,
        private_key: private_key.as_deref(),
        peer_public_key: &gateway_public_key,
        address: &address,
        heliosd_url: crate::profile::heliosd_url(&network.wg_address),
        key_negotiation: Some(profile::KeyNegotiation {
            mode: options.mode,
            minimum_mode: options.mode,
            endpoint: negotiation_endpoint,
            server_name: negotiation.server_name.clone(),
            gateway_ca_der: negotiation.gateway_ca_der.clone(),
            gateway_pq_certificate: negotiation.gateway_pq_certificate.clone(),
            identity: identity_name.clone(),
        }),
        key_negotiation_identity: Some(orion_core::ClientIdentityBundle {
            identity: identity_name.clone(),
            certificate_chain: vec![encoder.encode(&material.certificate_der)],
            private_key: encoder.encode(&material.private_key_der),
            pq_certificate: encoder.encode(&material.pq_certificate_json),
            pq_private_key: encoder.encode(&material.pq_private_key),
        }),
    })?;

    crate::files::write_new(&options.output, json.as_bytes(), true)?;
    report(&options, &public_key, &material, &negotiation);
    Ok(())
}

/// Endpoint of the negotiation service, as the client will dial it.
///
/// Derived from the tunnel endpoint by default: the two services live on the
/// same host, and asking the operator to retype the address is one more place
/// to get it wrong. The port comes from the gateway, never from a guess — a
/// hardcoded 51821 would silently be wrong on a gateway that moved it.
fn resolve_negotiation_endpoint(options: &EnrollOptions, port: Option<u16>) -> Result<String> {
    if let Some(explicit) = &options.negotiation_endpoint {
        return Ok(explicit.trim().to_string());
    }
    let port = port.context(
        "the gateway publishes no key-negotiation port — set `key_negotiation_port` in \
         network.toml, or pass --negotiation-endpoint",
    )?;
    let host = options
        .endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&options.endpoint);
    Ok(format!("{host}:{port}"))
}

/// Picks the mode and returns `(public key, optional private key)`.
///
/// Unlike `profile emit`, generating the pair is the **default**: this
/// document already carries the identity's private keys, so withholding the
/// WireGuard one would protect nothing while forcing an extra round-trip.
/// Supplying `--public-key` stays possible and remains better whenever the
/// client can generate its own key.
fn resolve_keys(options: &EnrollOptions) -> Result<(String, Option<String>)> {
    match &options.public_key {
        Some(public_key) => {
            let public_key = public_key.trim().to_string();
            aether::wg::validate_key(&public_key).context("invalid client public key")?;
            Ok((public_key, None))
        }
        None => {
            let pair = aether::wg::generate_keypair()
                .map_err(|e| anyhow::anyhow!("generating the client key pair: {e}"))?;
            Ok((pair.public_key, Some(pair.private_key.expose().to_string())))
        }
    }
}

/// Admits the peer with both fingerprints and the floor.
///
/// A re-enrollment always carries **new** certificates, so reusing an
/// existing admission is not an option here: the gateway would keep matching
/// the old fingerprints and refuse the client this very command just issued.
/// Hence the explicit `--replace`, which says out loud that the peer holding
/// the previous identity is about to be cut off.
async fn admit(
    client: &Client,
    base: &str,
    options: &EnrollOptions,
    public_key: &str,
    material: &key_nego::ClientMaterial,
) -> Result<String> {
    let policy = peer::KeyNegotiationAdmission {
        tls_certificate_sha256: Some(&material.certificate_sha256),
        pq_certificate_sha256: Some(&material.pq_certificate_sha256),
        minimum_mode: options.mode,
    };

    if options.replace {
        // Ignored on purpose when there is nothing to revoke: `--replace` on
        // a first enrollment should succeed, not report a missing peer.
        let _ = peer::revoke(client, base, &options.name).await;
    }

    match peer::admit_with_policy(
        client,
        base,
        &options.name,
        public_key,
        options.admin,
        policy,
    )
    .await
    {
        Ok(peer) => Ok(peer.address),
        Err(error) => {
            let view = api::network(client, base).await?;
            if view
                .peers
                .iter()
                .any(|peer| peer.name.trim() == options.name.trim())
            {
                bail!(
                    "a peer named \"{}\" is already admitted, with the certificates of a \
                     previous enrollment. Re-run with --replace to revoke it and admit this \
                     new identity: the client still holding the old one will stop connecting.",
                    options.name
                );
            }
            Err(error)
        }
    }
}

fn report(
    options: &EnrollOptions,
    public_key: &str,
    material: &key_nego::ClientMaterial,
    negotiation: &api::KeyNegotiationView,
) {
    println!(
        "{} {} enrolled → {}",
        crate::ok(),
        options.name,
        options.output.display()
    );
    println!();
    println!("  \x1b[33mThis file contains the client's private keys.\x1b[0m Hand it over through");
    println!("  a controlled channel, then erase it from both workstations: Orion");
    println!("  seals the identity on import and no longer needs the file.");
    println!();
    println!("  \x1b[2mWireGuard public key : {public_key}\x1b[0m");
    println!(
        "  \x1b[2mclient PQ certificate: {}\x1b[0m",
        material.pq_certificate_sha256
    );
    println!(
        "  \x1b[2mgateway PQ certificate: {}\x1b[0m",
        negotiation.pq_certificate_sha256
    );
    println!();
    println!("  \x1b[2mOrion displays that gateway fingerprint on its Profiles screen:\x1b[0m");
    println!("  \x1b[2mcomparing the two is what ties the profile to this gateway.\x1b[0m");
}

/// Reads the CA files the enrollment needs, before anything is issued.
///
/// Checked up front so a missing CA is reported before the command has
/// admitted a peer it will not be able to hand a profile to.
pub fn check_client_ca(directory: &Path) -> Result<()> {
    for file in [
        CA_CERTIFICATE_FILE,
        CA_PRIVATE_KEY_FILE,
        PQ_CA_PRIVATE_KEY_FILE,
    ] {
        let path = directory.join(file);
        if !path.is_file() {
            bail!(
                "{} is missing — create the operator CA first:\n  \
                 helios-ctl key-nego init-client-ca --name <nom> --output-dir {}",
                path.display(),
                directory.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> EnrollOptions {
        EnrollOptions {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            client_ca_dir: PathBuf::from("./ca"),
            public_key: None,
            mode: ProtectionMode::MlKem,
            negotiation_endpoint: None,
            identity: None,
            admin: false,
            replace: false,
            output: PathBuf::from("portable.orionprofile"),
        }
    }

    /// The negotiation port is the gateway's to state: hardcoding 51821 would
    /// silently produce unreachable profiles on a gateway that moved it.
    #[test]
    fn the_negotiation_endpoint_keeps_the_host_and_takes_the_published_port() {
        assert_eq!(
            resolve_negotiation_endpoint(&options(), Some(51821)).unwrap(),
            "vpn.example.net:51821"
        );
        assert_eq!(
            resolve_negotiation_endpoint(
                &EnrollOptions {
                    endpoint: "[2001:db8::1]:51820".into(),
                    ..options()
                },
                Some(7777)
            )
            .unwrap(),
            "[2001:db8::1]:7777"
        );
        assert_eq!(
            resolve_negotiation_endpoint(
                &EnrollOptions {
                    negotiation_endpoint: Some("autre.example.net:51821".into()),
                    ..options()
                },
                None
            )
            .unwrap(),
            "autre.example.net:51821"
        );
        assert!(resolve_negotiation_endpoint(&options(), None).is_err());
    }

    /// Same property as `profile emit`: the operator must not be able to
    /// manufacture a client secret by accident.
    #[test]
    fn a_supplied_public_key_never_produces_a_private_one() {
        let pair = aether::wg::generate_keypair().unwrap();
        let (public_key, private_key) = resolve_keys(&EnrollOptions {
            public_key: Some(pair.public_key.clone()),
            ..options()
        })
        .unwrap();

        assert_eq!(public_key, pair.public_key);
        assert!(private_key.is_none());
    }

    #[test]
    fn a_generated_pair_is_consistent() {
        let (public_key, private_key) = resolve_keys(&options()).unwrap();
        let private_key = private_key.expect("generated key");
        assert_eq!(
            aether::wg::public_from_private(&private_key).unwrap(),
            public_key
        );
    }

    #[test]
    fn a_missing_client_ca_is_reported_before_anything_is_issued() {
        let error = check_client_ca(Path::new("/nonexistent-ca"))
            .expect_err("a missing CA must be refused")
            .to_string();
        assert!(error.contains("init-client-ca"), "message: {error}");
    }
}
