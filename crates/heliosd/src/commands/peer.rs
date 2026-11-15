//! Local admission, with console access.
//!
//! Reads, modifies and rewrites `network.toml`, and leaves the console's half
//! of an admission in the certificate registry's inbox for the running daemon
//! to drain.

use std::path::Path;

use aether::NetworkConfig;
use anyhow::Context;
use tracing::{info, warn};

use crate::{certificates, static_psk};
use crate::{NegotiationMode, PeerCommand};

/// Local admission: reads, modifies and rewrites `network.toml`.
///
/// This command runs in its own process and only knows the file. A running
/// daemon picks the change up on its own — it watches `network.toml`
/// (`orchestrator::spawn_network_config_watcher`) and re-applies it without a
/// restart. Admitting a peer therefore no longer costs the connection of
/// every peer already admitted.
///
/// The secrets are not in the file, and must not be: the daemon restores its
/// sealed private key and its negotiated PSKs from memory when it reloads.
pub(crate) fn peer_command(mut network: NetworkConfig, command: PeerCommand) -> anyhow::Result<()> {
    match command {
        PeerCommand::List => {
            if network.peers.is_empty() {
                println!("no admitted peers");
                return Ok(());
            }
            for peer in &network.peers {
                let role = if peer.admin { " [admin]" } else { "" };
                let pq = if peer.preshared_key.is_some() {
                    " [PQ]"
                } else {
                    ""
                };
                println!(
                    "{}\t{}\t{}{role}{pq}",
                    peer.name, peer.address, peer.public_key
                );
            }
            Ok(())
        }
        PeerCommand::Add {
            name,
            public_key,
            admin,
            key_negotiation_certificate_sha256,
            key_negotiation_pq_certificate_sha256,
            certificate,
            pq_certificate,
            minimum_mode,
        } => {
            // Read and checked before `network.toml` moves: an admission whose
            // certificates cannot be queued must not leave a peer admitted
            // with no certificate generation.
            let queued = queue_console_admission(
                &helios_provisioning::certificates::CertificateRegistry::path(),
                &name,
                &public_key,
                certificate.as_deref(),
                pq_certificate.as_deref(),
            )?;
            // `None` only without a PQ identity, which admission refuses before
            // it reads the floor: the fallback names the floor that refusal
            // would have carried, and changes nothing else.
            let minimum_mode = admission_floor(
                minimum_mode,
                key_negotiation_pq_certificate_sha256.is_some(),
            )
            .unwrap_or(aether::key_negotiation::ProtectionMode::MlKem);
            // No live table here: this process only knows the file, and the
            // data plane belongs to the daemon. The collision view still
            // holds every declared peer, which is what the live table mirrors;
            // what it can miss is a peer just removed from the file that the
            // daemon has not dropped yet, and the daemon's reload of this
            // very file drops it before installing the new one.
            let admission = helios_provisioning::admit_with_key_negotiation(
                &mut network,
                &[],
                &name,
                &public_key,
                admin,
                key_negotiation_certificate_sha256.as_deref(),
                key_negotiation_pq_certificate_sha256.as_deref(),
                minimum_mode,
            )
            .map_err(|e| anyhow::anyhow!("admission refused: {e}"))?;
            let peer = &admission.peer;
            if admission.changed_config() {
                network
                    .save()
                    .context("writing the network configuration")?;
            }
            // Only a first admission queues a certificate generation: a
            // readmitted peer already has one, and queueing it again would
            // replace the registry's renewal state for that peer.
            if admission.outcome == helios_provisioning::AdmissionOutcome::Admitted {
                if let Some(queued) = queued {
                    certificates::queue_admission(
                        &helios_provisioning::certificates::CertificateRegistry::path(),
                        &queued,
                    )
                    .context("queueing the peer's first certificate generation")?;
                }
            }
            match peer.address_v6 {
                Some(v6) => println!("{}\t{}\t{v6}", peer.name, peer.address),
                None => println!("{}\t{}", peer.name, peer.address),
            }
            match admission.outcome {
                helios_provisioning::AdmissionOutcome::Admitted => info!(
                    "peer admitted — a running heliosd applies it within seconds, without restart"
                ),
                helios_provisioning::AdmissionOutcome::Ipv6Added => info!(
                    "peer already admitted — IPv6 VIP added, IPv4 VIP unchanged; a running \
                     heliosd applies it within seconds"
                ),
                helios_provisioning::AdmissionOutcome::Unchanged => {
                    info!("peer already admitted with this identity — nothing changed")
                }
            }
            Ok(())
        }
        PeerCommand::Remove { name } => {
            let peer = helios_provisioning::revoke(&mut network, &name)
                .map_err(|e| anyhow::anyhow!("revocation refused: {e}"))?;
            // The peer leaves the table too. Leaving its PSK behind would keep
            // a shared secret alive for an identity nobody admits any more —
            // and would make it slide back onto that public key if it were
            // ever re-admitted.
            let table = static_psk::default_path();
            let identity = network.wg_private_key.duplicate();
            if !identity.is_empty() {
                match static_psk::load(&table, identity.expose()) {
                    Ok(mut map) => {
                        if map.remove(&peer.public_key) {
                            static_psk::store(&table, identity.expose(), &map).map_err(|e| {
                                anyhow::anyhow!("writing the static PSK table: {e}")
                            })?;
                            info!("static PSK removed with the peer");
                        }
                    }
                    // Not fatal: the peer is revoked either way, and refusing
                    // here would leave it admitted because a table we cannot
                    // read might hold a secret for it.
                    Err(error) => warn!(%error, "static PSK table unreadable — entry not removed"),
                }
            }
            network
                .save()
                .context("writing the network configuration")?;
            println!("{} removed", peer.name);
            warn!(
                "the peer will drop at its next handshake; no cryptographic \
                 revocation exists (ADR-004)"
            );
            Ok(())
        }
    }
}

/// Prepares the console's half of an admission into the certificate registry.
///
/// Returns `None` when this gateway has no trust domain: there is nothing to
/// record, and admission keeps working exactly as it did before ADR-008.
///
/// When it does have one, both certificates are required. The registry needs
/// the objects — it verifies signatures made by them — and a peer admitted
/// without them holds no generation, therefore no trust block, therefore a
/// profile that connects and can never renew. That is refused here rather than
/// discovered months later.
fn queue_console_admission(
    registry_path: &Path,
    name: &str,
    public_key: &str,
    certificate: Option<&Path>,
    pq_certificate: Option<&Path>,
) -> anyhow::Result<Option<certificates::QueuedAdmission>> {
    use base64::Engine as _;

    if !registry_path.exists() {
        return Ok(None);
    }
    let (Some(certificate), Some(pq_certificate)) = (certificate, pq_certificate) else {
        anyhow::bail!(
            "this gateway holds a trust domain, so `peer add` also takes the client's two \
             certificates: --certificate <orion-client-cert.der> --pq-certificate \
             <orion-client-pq-cert.json>. Without them the peer connects but can never renew."
        );
    };
    let encoder = base64::engine::general_purpose::STANDARD;
    let tls =
        std::fs::read(certificate).with_context(|| format!("reading {}", certificate.display()))?;
    let pq = std::fs::read(pq_certificate)
        .with_context(|| format!("reading {}", pq_certificate.display()))?;
    Ok(Some(certificates::QueuedAdmission {
        name: name.to_string(),
        client_wg_public_key: public_key.trim().to_string(),
        tls_certificate: encoder.encode(tls),
        pq_certificate: encoder.encode(pq),
    }))
}

/// Derives the floor without hiding an explicit operator one.
///
/// `None` is a plain WireGuard peer: no explicit floor and no PQ identity to
/// negotiate with.
fn admission_floor(
    explicit: Option<NegotiationMode>,
    has_pq_certificate: bool,
) -> Option<aether::key_negotiation::ProtectionMode> {
    explicit
        .map(Into::into)
        .or(has_pq_certificate.then_some(aether::key_negotiation::ProtectionMode::MlKem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn admission_floor_defaults_to_the_strongest_available_identity() {
        use aether::key_negotiation::ProtectionMode;

        assert_eq!(admission_floor(None, false), None);
        assert_eq!(admission_floor(None, true), Some(ProtectionMode::MlKem));
        assert_eq!(
            admission_floor(Some(NegotiationMode::StaticPsk), true),
            Some(ProtectionMode::StaticPsk),
            "an explicit floor must not be replaced by inference"
        );
    }

    #[test]
    fn listing_peers_is_safe_for_empty_and_populated_configuration() {
        peer_command(NetworkConfig::default(), PeerCommand::List).unwrap();
        let network = NetworkConfig {
            peers: vec![aether::WgPeer {
                name: "portable".into(),
                public_key: "public".into(),
                address: "100.64.1.2/32".into(),
                address_v6: None,
                admin: true,
                preshared_key: Some("secret".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: None,
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..NetworkConfig::default()
        };
        peer_command(network, PeerCommand::List).unwrap();
    }

    #[test]
    fn admission_without_a_trust_domain_does_not_require_certificates() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = directory.path().join("missing-registry.json");

        let queued = queue_console_admission(&registry, "alice", " public ", None, None)
            .expect("admission without a trust domain");

        assert!(queued.is_none());
    }

    #[test]
    fn trust_domain_refuses_missing_client_certificates_before_admission() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = directory.path().join("registry.json");
        std::fs::write(&registry, b"registry present").expect("create registry marker");

        let error = queue_console_admission(&registry, "alice", "public", None, None)
            .expect_err("both certificate objects are required");

        assert!(error.to_string().contains("trust domain"));
        assert!(error.to_string().contains("--certificate"));
    }

    #[test]
    fn trust_domain_reads_and_encodes_both_client_certificates() {
        use base64::Engine as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = directory.path().join("registry.json");
        std::fs::write(&registry, b"registry present").expect("create registry marker");
        let tls_path = directory.path().join("client.der");
        let pq_path = directory.path().join("client-pq.json");
        std::fs::write(&tls_path, [0x30, 0x01, 0xff]).expect("write TLS certificate");
        std::fs::write(&pq_path, br#"{"leaf":"pq"}"#).expect("write PQ certificate");

        let queued = queue_console_admission(
            &registry,
            "alice",
            "  public-key  ",
            Some(&tls_path),
            Some(&pq_path),
        )
        .expect("queue certificate material")
        .expect("trust domain creates a queue entry");

        assert_eq!(queued.name, "alice");
        assert_eq!(queued.client_wg_public_key, "public-key");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(queued.tls_certificate)
                .expect("decode TLS bytes"),
            [0x30, 0x01, 0xff]
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(queued.pq_certificate)
                .expect("decode PQ bytes"),
            br#"{"leaf":"pq"}"#
        );
    }

    #[test]
    fn unreadable_tls_certificate_is_reported_with_its_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = directory.path().join("registry.json");
        std::fs::write(&registry, b"registry present").expect("create registry marker");
        let missing_tls = directory.path().join("missing-client.der");
        let pq_path = directory.path().join("client-pq.json");
        std::fs::write(&pq_path, b"pq").expect("write PQ certificate");

        let error = queue_console_admission(
            &registry,
            "alice",
            "public",
            Some(&missing_tls),
            Some(&pq_path),
        )
        .expect_err("missing TLS certificate is an admission error");

        assert!(error.to_string().contains("missing-client.der"));
    }

    const ISOLATED_PEER_SCENARIO: &str = "HELIOSD_PEER_COMMAND_SCENARIO";

    /// Runs command scenarios in a child process because all three production
    /// paths are process-wide environment overrides.
    fn run_isolated_scenario(name: &str) -> bool {
        if std::env::var(ISOLATED_PEER_SCENARIO).as_deref() == Ok(name) {
            return false;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                &format!("commands::peer::tests::{name}"),
                "--nocapture",
            ])
            .env(ISOLATED_PEER_SCENARIO, name)
            .env(
                "HELIOS_NETWORK_CONFIG",
                directory.path().join("network.toml"),
            )
            .env("HELIOS_IDENTITY_DIR", directory.path().join("identity"))
            .env(
                "HELIOS_CERTIFICATE_REGISTRY",
                directory.path().join("certificates.json"),
            )
            .output()
            .expect("isolated command scenario starts");
        assert!(
            output.status.success(),
            "isolated {name} failed:
{}
{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "isolated {name} must execute exactly one test:
{}",
            String::from_utf8_lossy(&output.stdout)
        );
        true
    }

    fn test_fingerprint(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn add_command(
        name: &str,
        public_key: &str,
        certificate: Option<std::path::PathBuf>,
        pq_certificate: Option<std::path::PathBuf>,
    ) -> PeerCommand {
        PeerCommand::Add {
            name: name.into(),
            public_key: public_key.into(),
            admin: false,
            key_negotiation_certificate_sha256: Some(test_fingerprint(0x11)),
            key_negotiation_pq_certificate_sha256: Some(test_fingerprint(0x22)),
            certificate,
            pq_certificate,
            minimum_mode: None,
        }
    }

    fn admitted_peer(name: &str, public_key: &str) -> aether::WgPeer {
        aether::WgPeer {
            name: name.into(),
            public_key: public_key.into(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: Some(test_fingerprint(0x11)),
            key_negotiation_pq_certificate_sha256: Some(test_fingerprint(0x22)),
            minimum_key_negotiation_mode: Some(aether::key_negotiation::ProtectionMode::MlKem),
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        }
    }

    #[test]
    fn peer_add_persists_ipam_admission_and_the_certificate_inbox_entry() {
        use aether::certificates::encoding::Fingerprint;
        use base64::Engine as _;

        if run_isolated_scenario("peer_add_persists_ipam_admission_and_the_certificate_inbox_entry")
        {
            return;
        }
        let config_path = NetworkConfig::path();
        let registry_path = helios_provisioning::certificates::CertificateRegistry::path();
        std::fs::write(&registry_path, b"registry marker").expect("trust domain marker");
        let directory = registry_path.parent().expect("test registry directory");
        let tls_path = directory.join("client.der");
        let pq_path = directory.join("client-pq.json");
        std::fs::write(&tls_path, [0x30, 0x01, 0xff]).expect("TLS certificate fixture");
        std::fs::write(&pq_path, br#"{"leaf":"pq"}"#).expect("PQ certificate fixture");
        let public_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);

        peer_command(
            NetworkConfig::default(),
            add_command(
                "alice",
                &public_key,
                Some(tls_path.clone()),
                Some(pq_path.clone()),
            ),
        )
        .expect("new peer is admitted");

        let initial_config = std::fs::read(&config_path).expect("first admission persists");
        std::fs::write(&tls_path, b"replacement TLS leaf").expect("replacement TLS fixture");
        std::fs::write(&pq_path, b"replacement PQ leaf").expect("replacement PQ fixture");
        peer_command(
            NetworkConfig::load().expect("readmitted config loads"),
            add_command("alice", &public_key, Some(tls_path), Some(pq_path)),
        )
        .expect("unchanged readmission succeeds");
        assert_eq!(
            std::fs::read(&config_path).expect("config after readmission"),
            initial_config,
            "unchanged readmission must not rewrite the persisted peer table"
        );

        let persisted = NetworkConfig::load().expect("persisted configuration loads");
        assert_eq!(persisted.peers.len(), 1);
        let peer = &persisted.peers[0];
        assert_eq!(peer.name, "alice");
        assert_eq!(peer.public_key, public_key);
        assert_eq!(
            peer.address,
            format!(
                "{}/32",
                helios_provisioning::ipam::derive_cgnat_ip(&[9u8; 32], 0)
            )
        );
        assert_eq!(peer.preshared_key, None, "admission never invents a PSK");
        assert_eq!(
            peer.minimum_key_negotiation_mode,
            Some(aether::key_negotiation::ProtectionMode::MlKem)
        );
        let serialized = std::fs::read_to_string(&config_path).expect("public config file");
        assert!(!serialized.contains("preshared_key"));
        assert!(serialized.contains("wg_private_key = \"\""));

        let admission_path = heliosd_admission_path(&registry_path, &public_key);
        let queued: certificates::QueuedAdmission =
            serde_json::from_slice(&std::fs::read(&admission_path).expect("queued admission"))
                .expect("queued admission is valid JSON");
        assert_eq!(queued.name, "alice");
        assert_eq!(queued.client_wg_public_key, public_key);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(queued.tls_certificate)
                .unwrap(),
            [0x30, 0x01, 0xff]
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(queued.pq_certificate)
                .unwrap(),
            br#"{"leaf":"pq"}"#
        );
        assert_eq!(
            Fingerprint::of(public_key.as_bytes()).to_hex(),
            admission_path.file_stem().unwrap().to_string_lossy()
        );
    }

    fn heliosd_admission_path(registry_path: &Path, public_key: &str) -> std::path::PathBuf {
        use aether::certificates::encoding::Fingerprint;
        registry_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("admissions")
            .join(format!(
                "{}.json",
                Fingerprint::of(public_key.as_bytes()).to_hex()
            ))
    }

    #[test]
    fn trust_domain_certificate_read_failure_precedes_admission_persistence() {
        if run_isolated_scenario(
            "trust_domain_certificate_read_failure_precedes_admission_persistence",
        ) {
            return;
        }
        let registry_path = helios_provisioning::certificates::CertificateRegistry::path();
        std::fs::write(&registry_path, b"registry marker").expect("trust domain marker");
        let directory = registry_path.parent().expect("test registry directory");
        let pq_path = directory.join("client-pq.json");
        std::fs::write(&pq_path, b"pq").expect("PQ certificate fixture");
        let public_key = base64::engine::general_purpose::STANDARD.encode([10u8; 32]);

        let error = peer_command(
            NetworkConfig::default(),
            add_command(
                "alice",
                &public_key,
                Some(directory.join("missing-client.der")),
                Some(pq_path),
            ),
        )
        .expect_err("missing trust certificate blocks admission");

        assert!(error.to_string().contains("missing-client.der"));
        assert!(
            !NetworkConfig::path().exists(),
            "a failed certificate read must not persist the peer"
        );
        assert!(
            !registry_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("admissions")
                .exists(),
            "no admission is queued when certificate reads fail"
        );
    }

    #[test]
    fn duplicate_name_refusal_leaves_the_persisted_peer_table_unchanged() {
        if run_isolated_scenario("duplicate_name_refusal_leaves_the_persisted_peer_table_unchanged")
        {
            return;
        }
        let first_key = base64::engine::general_purpose::STANDARD.encode([11u8; 32]);
        let second_key = base64::engine::general_purpose::STANDARD.encode([12u8; 32]);
        let network = NetworkConfig {
            peers: vec![admitted_peer("alice", &first_key)],
            ..NetworkConfig::default()
        };
        network.save().expect("initial peer table");
        let before = std::fs::read(NetworkConfig::path()).expect("saved table");

        let error = peer_command(network, add_command("alice", &second_key, None, None))
            .expect_err("a name cannot be rebound to another WireGuard key");

        assert!(error.to_string().contains("already admitted"), "{error:#}");
        assert_eq!(std::fs::read(NetworkConfig::path()).unwrap(), before);
        let persisted = NetworkConfig::load().expect("original table remains valid");
        assert_eq!(persisted.peers.len(), 1);
        assert_eq!(persisted.peers[0].public_key, first_key);
    }

    #[test]
    fn peer_remove_persists_revocation_and_unknown_names_are_noops() {
        if run_isolated_scenario("peer_remove_persists_revocation_and_unknown_names_are_noops") {
            return;
        }
        let public_key = base64::engine::general_purpose::STANDARD.encode([13u8; 32]);
        let network = NetworkConfig {
            peers: vec![admitted_peer("alice", &public_key)],
            ..NetworkConfig::default()
        };
        network.save().expect("initial peer table");

        peer_command(
            network,
            PeerCommand::Remove {
                name: "alice".into(),
            },
        )
        .expect("known peer is revoked");
        assert!(NetworkConfig::load().unwrap().peers.is_empty());
        let after_remove = std::fs::read(NetworkConfig::path()).unwrap();

        let error = peer_command(
            NetworkConfig::load().unwrap(),
            PeerCommand::Remove {
                name: "unknown".into(),
            },
        )
        .expect_err("unknown peer removal must be refused");
        assert!(error.to_string().contains("unknown"));
        assert_eq!(std::fs::read(NetworkConfig::path()).unwrap(), after_remove);
    }

    #[test]
    fn unreadable_pq_certificate_is_reported_with_its_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = directory.path().join("registry.json");
        std::fs::write(&registry, b"registry present").expect("create registry marker");
        let tls_path = directory.path().join("client.der");
        let missing_pq = directory.path().join("missing-client-pq.json");
        std::fs::write(&tls_path, b"tls").expect("write TLS certificate");

        let error = queue_console_admission(
            &registry,
            "alice",
            "public",
            Some(&tls_path),
            Some(&missing_pq),
        )
        .expect_err("missing PQ certificate is an admission error");

        assert!(error.to_string().contains("missing-client-pq.json"));
    }
}
