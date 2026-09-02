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
//! 3. issue the client's TLS and ML-DSA-87 certificates from the operator CA;
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
    /// File holding the client's WireGuard **private** key.
    ///
    /// A file rather than an argument: `ps` shows every process's argv, so a
    /// key passed on the command line is readable by any local user for as
    /// long as the command runs.
    pub private_key_file: Option<PathBuf>,
    /// Negotiation mode, which is also the peer's floor.
    pub mode: ProtectionMode,
    /// Negotiation endpoint. Defaults to the tunnel host with the port the
    /// gateway publishes.
    pub negotiation_endpoint: Option<String>,
    /// Name of the protected store entry. Defaults to `orion-<name>`.
    pub identity: Option<String>,
    /// Admit the peer as a control-plane administrator.
    pub admin: bool,
    /// Split tunnel to ship with the profile. Absent = full tunnel.
    ///
    /// Stated once by the operator and carried by the document, rather than
    /// retyped into each machine's Advanced panel — which is how a fleet ends
    /// up with as many routing tables as it has users.
    pub allowed_ips: Option<String>,
    /// SSH destination to ship with the profile. Absent = no terminal button.
    pub ssh_target: Option<String>,
    /// Revoke an existing peer of the same name before admitting.
    pub replace: bool,
    pub output: PathBuf,
    /// Reuse an identity already written by `key-nego issue-client`.
    ///
    /// Mandatory whenever admission happened in a separate step: the gateway
    /// holds the fingerprints of *those* certificates, and reissuing here
    /// would build a profile the gateway refuses.
    pub client_pki_dir: Option<PathBuf>,
    /// Enrollment without the control-plane API. See [`OfflineInputs`].
    pub offline: Option<OfflineInputs>,
}

/// Everything the API would have supplied, taken from the gateway by hand.
///
/// # Why this path exists
///
/// The API lives **behind the tunnel** (`admin_iface`), so reaching it means
/// already being connected. That is harmless for day-to-day operations and
/// absurd for the very first enrollment: it would make the negotiation that
/// protects the first handshake depend on a first handshake.
///
/// The protocol has no such dependency — Orion dials the public negotiation
/// port before mounting anything. Only the tooling did, and this is where it
/// stops: the operator already has an SSH session to the gateway, which is
/// enough to read two public certificates and to admit the peer with
/// `heliosd peer add`.
pub struct OfflineInputs {
    /// `/var/lib/helios/key-negotiation-cert.der`, fetched over SSH.
    pub gateway_certificate: PathBuf,
    /// `/var/lib/helios/key-negotiation-pq-cert.json`, fetched over SSH.
    pub gateway_pq_certificate: PathBuf,
    /// VIP printed by `heliosd peer add`, which performed the admission.
    pub address: String,
    /// Internal API URL, for telemetry only. Absent is fine.
    pub heliosd_url: Option<String>,
    /// The §19 trust block, as `heliosd show-trust-enrolment` printed it.
    ///
    /// Offline there is no API to ask, and the values are not guessable: they
    /// are the domain's anchors and this peer's generation. Absent, the
    /// profile omits the block and Orion says renewal is unavailable — which
    /// is true, and better than a button that fails at its last step.
    pub trust_material: Option<PathBuf>,
}

/// Reads a trust block printed by `heliosd show-trust-enrolment`.
///
/// Validated here rather than at import: an operator running this command has
/// the gateway in front of them, and a block that is wrong is one SSH call
/// away from being reprinted. The same block discovered as invalid on a user's
/// machine is a redeployment.
fn read_trust_material(path: &Path) -> Result<orion_core::TrustMaterial> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading the trust block from {}", path.display()))?;
    let material: orion_core::TrustMaterial = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "{} is not a trust block — it is what `heliosd show-trust-enrolment --public-key \
             <clé>` prints",
            path.display()
        )
    })?;
    material
        .validate()
        .with_context(|| format!("the trust block in {} is unusable", path.display()))?;
    Ok(material)
}

/// Gateway-side material a profile pins, however it was obtained.
struct GatewayMaterial {
    server_name: String,
    gateway_ca_der: String,
    gateway_pq_certificate: String,
    wireguard_public_key: String,
    pq_certificate_sha256: String,
    negotiation_port: Option<u16>,
}

/// Reads the material from the two public certificates on disk.
///
/// The PQ certificate carries the subject **and** the WireGuard key it is
/// pinned to, so the operator has nothing to retype: everything the profile
/// needs is inside the file, and verifying it here means a mistyped copy is
/// caught now rather than as a refused negotiation later.
fn offline_material(inputs: &OfflineInputs) -> Result<GatewayMaterial> {
    use aether::key_negotiation::PqCertificate;

    let certificate_der = std::fs::read(&inputs.gateway_certificate).with_context(|| {
        format!(
            "reading the gateway certificate {}",
            inputs.gateway_certificate.display()
        )
    })?;
    let pq_certificate_json = std::fs::read(&inputs.gateway_pq_certificate).with_context(|| {
        format!(
            "reading the gateway PQ certificate {}",
            inputs.gateway_pq_certificate.display()
        )
    })?;
    let certificate: PqCertificate = serde_json::from_slice(&pq_certificate_json)
        .context("the gateway PQ certificate is not a readable JSON document")?;

    // The signature is **not** checked here. Which authority signs this leaf
    // depends on whether the gateway has a trust domain — self-signed without
    // one, `CA-PQ` with one (ADR-008 §13.1) — and the anchor for the second
    // case lives in the trust block, which is only known once the peer is
    // admitted. Verifying here would therefore accept exactly one of the two
    // shapes. `run` checks the leaf once, for both paths, against the anchor
    // the profile is about to pin.
    let encoder = base64::engine::general_purpose::STANDARD;
    Ok(GatewayMaterial {
        server_name: certificate.subject.clone(),
        gateway_ca_der: encoder.encode(&certificate_der),
        gateway_pq_certificate: encoder.encode(&pq_certificate_json),
        wireguard_public_key: certificate.wireguard_public_key.clone(),
        pq_certificate_sha256: certificate.fingerprint()?,
        // Unknown offline: the port lives in the gateway's network.toml, not
        // in any certificate. `--negotiation-endpoint` states it.
        negotiation_port: None,
    })
}

pub async fn run(client: &Client, base: &str, options: EnrollOptions) -> Result<()> {
    if options.mode == ProtectionMode::StaticPsk {
        bail!(
            "`enroll` does not set up a static PSK: that mode needs a secret shared out of band, \
             which this command deliberately never invents. Use --mode ml-kem (recommended) or \
             --mode classic, and configure a static PSK by hand if you really need one."
        );
    }

    let (material, heliosd_url) = match &options.offline {
        Some(inputs) => (offline_material(inputs)?, inputs.heliosd_url.clone()),
        None => {
            let network = api::network(client, base).await?;
            let gateway_public_key = network
                .wg_public_key
                .clone()
                .filter(|key| !key.is_empty())
                .context(
                    "the gateway has no WireGuard identity yet — run `heliosd init-identity` on \
                     the gateway, with console access",
                )?;

            let negotiation = api::key_negotiation(client, base).await?.context(
                "this gateway serves no key-negotiation material — build heliosd with the \
                 `key-negotiation` feature and run `heliosd init-key-negotiation`, or fall back \
                 to `helios-ctl profile emit` for a profile without pre-WireGuard negotiation",
            )?;

            // The gateway certificate is pinned to a WireGuard key. If that is
            // not the identity the gateway actually runs on, every client
            // built here would fail its pinning check — and the message would
            // blame the client.
            if negotiation.wireguard_public_key != gateway_public_key {
                bail!(
                    "the gateway negotiation certificate is bound to another WireGuard identity: \
                     it pins {}, while the gateway runs {}. Its identity was rotated without \
                     reissuing the certificate — re-run `heliosd init-key-negotiation --rotate`.",
                    negotiation.wireguard_public_key,
                    gateway_public_key
                );
            }
            let url = crate::profile::heliosd_url(&network.wg_address);
            (
                GatewayMaterial {
                    server_name: negotiation.server_name,
                    gateway_ca_der: negotiation.gateway_ca_der,
                    gateway_pq_certificate: negotiation.gateway_pq_certificate,
                    wireguard_public_key: negotiation.wireguard_public_key,
                    pq_certificate_sha256: negotiation.pq_certificate_sha256,
                    negotiation_port: negotiation.port,
                },
                url,
            )
        }
    };

    let identity_name = options
        .identity
        .clone()
        .unwrap_or_else(|| format!("orion-{}", options.name.trim()));
    let negotiation_endpoint = resolve_negotiation_endpoint(&options, material.negotiation_port)?;

    let (public_key, private_key) = resolve_keys(&options)?;
    let client_material = match &options.client_pki_dir {
        Some(directory) => key_nego::load_client_material(directory).with_context(|| {
            format!("reloading the client identity from {}", directory.display())
        })?,
        None => key_nego::issue_client_material(
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
        })?,
    };

    // Offline, the admission has already happened through `heliosd peer add`
    // on the console: the VIP it printed is what the operator passes back.
    let address = match &options.offline {
        Some(inputs) => inputs.address.clone(),
        None => admit(client, base, &options, &public_key, &client_material).await?,
    };

    // The §19 trust block, read from the gateway once the peer is admitted —
    // the generation it carries is that peer's, so it cannot be fetched
    // earlier. Offline, there is nobody to ask: the document then omits it and
    // Orion says so rather than offering a renewal that would fail at its last
    // step.
    let trust = match &options.offline {
        Some(inputs) => match &inputs.trust_material {
            Some(path) => Some(read_trust_material(path)?),
            None => None,
        },
        None => api::trust_enrolment(client, base, &public_key).await?,
    };
    if trust.is_none() {
        eprintln!(
            "note : ce profil ne portera pas de matériel de confiance — cette gateway n'a pas de \
             domaine amorcé (`heliosd init-trust-domain`). Le client se connectera, mais ne \
             pourra pas renouveler son certificat."
        );
    }

    // The one place the pinned gateway leaf is verified, under whichever
    // authority actually issued it. It runs after the trust block is known
    // because a `CA-PQ`-issued leaf can only be checked against the anchor
    // that block carries — and it runs on the API path too, which until now
    // pinned whatever the gateway returned without checking a signature.
    {
        let certificate: aether::key_negotiation::PqCertificate = serde_json::from_slice(
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &material.gateway_pq_certificate,
            )
            .context("the gateway PQ certificate is not valid base64")?,
        )
        .context("the gateway PQ certificate is not a readable JSON document")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock predates the Unix epoch")?
            .as_secs();
        orion_core::verify_pinned_gateway_certificate(
            &certificate,
            &material.server_name,
            &material.wireguard_public_key,
            trust.as_ref(),
            now,
        )
        .context("the gateway PQ certificate does not verify — copied incompletely, or expired")?;
    }

    let encoder = base64::engine::general_purpose::STANDARD;
    let json = profile::render(profile::Profile {
        name: &options.name,
        endpoint: &options.endpoint,
        private_key: private_key.as_deref(),
        peer_public_key: &material.wireguard_public_key,
        address: &address,
        allowed_ips: options.allowed_ips.as_deref(),
        ssh_target: options.ssh_target.as_deref(),
        heliosd_url,
        key_negotiation: Some(profile::KeyNegotiation {
            mode: options.mode,
            minimum_mode: options.mode,
            endpoint: negotiation_endpoint,
            server_name: material.server_name.clone(),
            gateway_ca_der: material.gateway_ca_der.clone(),
            gateway_pq_certificate: material.gateway_pq_certificate.clone(),
            identity: identity_name.clone(),
            trust,
        }),
        key_negotiation_identity: Some(orion_core::ClientIdentityBundle {
            identity: identity_name.clone(),
            certificate_chain: vec![encoder.encode(&client_material.certificate_der)],
            private_key: encoder.encode(&client_material.private_key_der),
            pq_certificate: encoder.encode(&client_material.pq_certificate_json),
            pq_private_key: encoder.encode(&client_material.pq_private_key),
        }),
    })?;

    crate::files::write_new(&options.output, json.as_bytes(), true)?;
    report(&options, &public_key, &client_material, &material);
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
    // A supplied private key takes precedence: it means the caller generated
    // the pair beforehand — the offline path has to, because the peer must be
    // admitted (and its VIP known) before the profile can be assembled.
    if let Some(path) = &options.private_key_file {
        let private_key = std::fs::read_to_string(path)
            .with_context(|| format!("reading the client private key {}", path.display()))?
            .trim()
            .to_string();
        let public_key = aether::wg::public_from_private(&private_key)
            .map_err(|e| anyhow::anyhow!("unreadable client private key: {e}"))?;
        if let Some(declared) = &options.public_key {
            anyhow::ensure!(
                declared.trim() == public_key,
                "the supplied private key does not match --public-key: the peer would be \
                 admitted under one identity and the profile built on another"
            );
        }
        return Ok((public_key, Some(private_key)));
    }
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
    // The two leaves travel with the two fingerprints: the peer table pins the
    // digests, the certificate registry records the objects. One admission,
    // one pair of certificates — a peer whose registry row was written from
    // another enrollment would hold a generation nobody can renew.
    let encoder = base64::engine::general_purpose::STANDARD;
    let tls_certificate = encoder.encode(&material.certificate_der);
    let pq_certificate = encoder.encode(&material.pq_certificate_json);
    let policy = peer::KeyNegotiationAdmission {
        tls_certificate_sha256: Some(&material.certificate_sha256),
        pq_certificate_sha256: Some(&material.pq_certificate_sha256),
        tls_certificate: Some(&tls_certificate),
        pq_certificate: Some(&pq_certificate),
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
    negotiation: &GatewayMaterial,
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
/// # Le piège que ce message évite
///
/// Il disait « créer la CA opérateur d'abord », avec la commande toute faite.
/// Sur un poste où la CA existe mais n'a pas été trouvée — parce que le
/// répertoire par défaut était relatif au dossier courant — suivre ce conseil
/// **orphelinait toute la flotte** : `heliosd init-key-negotiation` épingle la
/// CA client dans `/var/lib/helios/key-negotiation-client-pq-ca-public.bin`, et
/// la gateway refuse tout certificat émis par une autre. Le remède proposé
/// cassait ce qui marchait encore.
///
/// Le message dit donc d'abord de **retrouver** la CA existante, et ne propose
/// d'en créer une qu'en nommant la conséquence.
pub fn check_client_ca(directory: &Path) -> Result<()> {
    for file in [
        CA_CERTIFICATE_FILE,
        CA_PRIVATE_KEY_FILE,
        PQ_CA_PRIVATE_KEY_FILE,
    ] {
        let path = directory.join(file);
        if !path.is_file() {
            bail!(
                "CA opérateur introuvable dans {} ({} manque).\n\n\
                 Si vous avez déjà enrôlé un client, cette CA **existe** et la gateway \
                 n'accepte qu'elle. La retrouver :\n  \
                 find ~ -name '{}' 2>/dev/null\n\
                 puis la désigner par --client-ca-dir, ou la déplacer à l'emplacement \
                 par défaut ci-dessus.\n\n\
                 N'en créer une neuve que s'il n'en existe aucune : la gateway épingle la \
                 CA cliente à `heliosd init-key-negotiation`, et une CA différente rend \
                 illisible tout certificat déjà émis — tous les clients admis cessent de \
                 négocier.\n  \
                 helios-ctl key-nego init-client-ca --name <nom>",
                directory.display(),
                path.display(),
                CA_CERTIFICATE_FILE,
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
            allowed_ips: None,
            ssh_target: None,
            private_key_file: None,
            client_pki_dir: None,
            mode: ProtectionMode::MlKem,
            negotiation_endpoint: None,
            identity: None,
            admin: false,
            replace: false,
            output: PathBuf::from("portable.orion"),
            offline: None,
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

    /// The offline path generates the pair before admitting, then hands the
    /// private half back for the profile. A mismatch between the two would
    /// admit one identity and build the profile on another — a tunnel that
    /// never comes up, for a reason nothing displays.
    #[test]
    fn a_private_key_file_must_match_the_admitted_public_key() {
        let pair = aether::wg::generate_keypair().unwrap();
        let other = aether::wg::generate_keypair().unwrap();
        let path = std::env::temp_dir().join(format!("orion-enroll-{}", std::process::id()));
        std::fs::write(&path, pair.private_key.expose()).unwrap();

        let (public_key, private_key) = resolve_keys(&EnrollOptions {
            private_key_file: Some(path.clone()),
            public_key: Some(pair.public_key.clone()),
            ..options()
        })
        .expect("consistent pair");
        assert_eq!(public_key, pair.public_key);
        assert_eq!(private_key.as_deref(), Some(pair.private_key.expose()));

        let error = resolve_keys(&EnrollOptions {
            private_key_file: Some(path.clone()),
            public_key: Some(other.public_key),
            ..options()
        })
        .expect_err("a mismatched pair must be refused");
        assert!(error.to_string().contains("does not match"), "{error}");

        let _ = std::fs::remove_file(&path);
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

    /// Offline, everything the profile pins comes out of the two public
    /// certificates — nothing is retyped, so nothing can be mistyped.
    #[test]
    fn the_offline_material_is_read_entirely_from_the_gateway_certificates() {
        use aether::key_negotiation::{
            generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
            PQ_CERTIFICATE_VERSION,
        };
        use base64::engine::general_purpose::STANDARD;

        let gateway_key = aether::wg::generate_keypair().unwrap();
        let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [5u8; 16],
                subject: "vpn.example.net".into(),
                issuer: "vpn.example.net".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key.public_key.clone(),
                ml_dsa_87_public_key: STANDARD.encode(&public_key),
                not_before_unix: now - 60,
                not_after_unix: now + 3600,
                ml_dsa_87_signature: String::new(),
            },
            &private_key,
        )
        .unwrap();

        let directory = std::env::temp_dir().join(format!("orion-offline-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let der = directory.join("cert.der");
        let json = directory.join("pq.json");
        std::fs::write(&der, [0x30, 0x82, 0x01, 0x00]).unwrap();
        std::fs::write(&json, serde_json::to_vec(&certificate).unwrap()).unwrap();

        let inputs = OfflineInputs {
            gateway_certificate: der.clone(),
            gateway_pq_certificate: json.clone(),
            address: "100.64.1.2/32".into(),
            heliosd_url: None,
            trust_material: None,
        };
        let material = offline_material(&inputs).expect("material read from the certificates");
        assert_eq!(material.server_name, "vpn.example.net");
        assert_eq!(material.wireguard_public_key, gateway_key.public_key);
        assert_eq!(
            material.pq_certificate_sha256,
            certificate.fingerprint().unwrap()
        );
        // No port in any certificate: it lives in the gateway's network.toml.
        assert_eq!(material.negotiation_port, None);

        // A truncated copy must be caught here, not as a refused negotiation
        // days later on the user's machine.
        std::fs::write(&json, b"{\"version\":1}").unwrap();
        assert!(offline_material(&inputs).is_err());

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_client_ca_is_reported_before_anything_is_issued() {
        let error = check_client_ca(Path::new("/nonexistent-ca"))
            .expect_err("a missing CA must be refused")
            .to_string();
        assert!(error.contains("init-client-ca"), "message: {error}");
    }
}
