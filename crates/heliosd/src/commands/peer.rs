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
                &name,
                &public_key,
                certificate.as_deref(),
                pq_certificate.as_deref(),
            )?;
            let minimum_mode = admission_floor(
                minimum_mode,
                key_negotiation_pq_certificate_sha256.is_some(),
            );
            let peer = helios_provisioning::admit_with_key_negotiation(
                &mut network,
                &name,
                &public_key,
                admin,
                key_negotiation_certificate_sha256.as_deref(),
                key_negotiation_pq_certificate_sha256.as_deref(),
                minimum_mode,
            )
            .map_err(|e| anyhow::anyhow!("admission refused: {e}"))?;
            network
                .save()
                .context("writing the network configuration")?;
            if let Some(queued) = queued {
                certificates::queue_admission(
                    &helios_provisioning::certificates::CertificateRegistry::path(),
                    &queued,
                )
                .context("queueing the peer's first certificate generation")?;
            }
            println!("{}\t{}", peer.name, peer.address);
            info!("peer admitted — a running heliosd applies it within seconds, without restart");
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
    name: &str,
    public_key: &str,
    certificate: Option<&Path>,
    pq_certificate: Option<&Path>,
) -> anyhow::Result<Option<certificates::QueuedAdmission>> {
    use base64::Engine as _;

    if !helios_provisioning::certificates::CertificateRegistry::path().exists() {
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

/// Derives the safe default without hiding an explicit operator floor.
fn admission_floor(
    explicit: Option<NegotiationMode>,
    has_pq_certificate: bool,
) -> aether::key_negotiation::ProtectionMode {
    explicit.map(Into::into).unwrap_or_else(|| {
        if has_pq_certificate {
            aether::key_negotiation::ProtectionMode::MlKem
        } else {
            aether::key_negotiation::ProtectionMode::Classic
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_floor_defaults_to_the_strongest_available_identity() {
        use aether::key_negotiation::ProtectionMode;

        assert_eq!(admission_floor(None, false), ProtectionMode::Classic);
        assert_eq!(admission_floor(None, true), ProtectionMode::MlKem);
        assert_eq!(
            admission_floor(Some(NegotiationMode::StaticPsk), true),
            ProtectionMode::StaticPsk,
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
                admin: true,
                preshared_key: Some("secret".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..NetworkConfig::default()
        };
        peer_command(network, PeerCommand::List).unwrap();
    }
}
